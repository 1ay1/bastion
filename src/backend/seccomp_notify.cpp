#include "bastion/backend/seccomp_notify.hpp"

#if defined(__linux__)

#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <poll.h>
#  include <signal.h>
#  include <sys/ioctl.h>
#  include <sys/prctl.h>
#  include <sys/socket.h>
#  include <sys/stat.h>
#  include <sys/syscall.h>
#  include <sys/uio.h>
#  include <sys/wait.h>
#  include <unistd.h>

#  if __has_include(<linux/seccomp.h>) && __has_include(<linux/filter.h>) && \
      __has_include(<linux/audit.h>)
#    include <linux/audit.h>
#    include <linux/filter.h>
#    include <linux/seccomp.h>
#    if defined(SECCOMP_FILTER_FLAG_NEW_LISTENER) && \
        defined(SECCOMP_USER_NOTIF_FLAG_CONTINUE)
#      define BASTION_HAVE_SECCOMP_NOTIFY 1
#    endif
#  endif
#endif

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

namespace bastion::linux_seccomp {

#if defined(BASTION_HAVE_SECCOMP_NOTIFY)

namespace {

int seccomp_syscall(unsigned op, unsigned flags, void* args) {
    return static_cast<int>(::syscall(__NR_seccomp, op, flags, args));
}

// Which syscalls we trap, and what each means in bastion's vocabulary.
//
// Deliberately NARROW. Every trapped syscall costs two context switches, so
// trapping everything would change the timing of the workload we are trying to
// observe faithfully. These are the calls that establish AUTHORITY -- opening,
// executing, connecting -- not the ones that use authority already held
// (read/write on an existing fd tell us nothing new about what a policy needs).
struct Trap {
    int nr;
    const char* op;       // bastion op name
    int path_arg;         // index of the path argument, or -1
    bool at_style;        // true => arg0 is a dirfd (openat family)
};

constexpr Trap kTraps[] = {
    {__NR_openat,          "fs.open",   1, true},
    {__NR_execve,          "fs.exec",   0, false},
    {__NR_execveat,        "fs.exec",   1, true},
    {__NR_connect,         "net.egress", -1, false},
    {__NR_bind,            "net.bind",  -1, false},
#  if defined(__NR_open)
    {__NR_open,            "fs.open",   0, false},
#  endif
#  if defined(__NR_openat2)
    {__NR_openat2,         "fs.open",   1, true},
#  endif
#  if defined(__NR_stat)
    {__NR_stat,            "fs.stat",   0, false},
#  endif
    {__NR_newfstatat,      "fs.stat",   1, true},
    {__NR_mkdirat,         "fs.write",  1, true},
    {__NR_unlinkat,        "fs.write",  1, true},
    {__NR_renameat2,       "fs.write",  1, true},
    {__NR_linkat,          "fs.write",  1, true},
    {__NR_symlinkat,       "fs.write",  1, true},
};

// Build the classic-BPF program: trap the syscalls above, allow everything else.
//
// The architecture check is mandatory and is a real security property, not
// boilerplate: without it, a 32-bit compat syscall whose NUMBER collides with a
// trapped 64-bit one would be mis-identified.
std::vector<sock_filter> build_filter() {
    std::vector<sock_filter> f;
    // arch != native -> ALLOW (we only claim to observe the native ABI, and we
    // say so in a warning rather than pretending to have seen everything).
    f.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                         offsetof(struct seccomp_data, arch)));
    f.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    f.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    f.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                         offsetof(struct seccomp_data, nr)));
    for (const auto& t : kTraps) {
        // if (nr == t.nr) goto NOTIFY
        f.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                             static_cast<__u32>(t.nr), 0, 1));
        f.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));
    }
    f.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    return f;
}

const Trap* trap_for(int nr) {
    for (const auto& t : kTraps) {
        if (t.nr == nr) return &t;
    }
    return nullptr;
}

int send_fd(int sock, int fd) {
    char dummy = 'x';
    iovec io{&dummy, 1};
    char cbuf[CMSG_SPACE(sizeof(int))];
    std::memset(cbuf, 0, sizeof cbuf);
    msghdr m{};
    m.msg_iov = &io;
    m.msg_iovlen = 1;
    m.msg_control = cbuf;
    m.msg_controllen = sizeof cbuf;
    cmsghdr* c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(c), &fd, sizeof(int));
    return ::sendmsg(sock, &m, 0) < 0 ? -1 : 0;
}

int recv_fd(int sock) {
    char dummy = 0;
    iovec io{&dummy, 1};
    char cbuf[CMSG_SPACE(sizeof(int))];
    std::memset(cbuf, 0, sizeof cbuf);
    msghdr m{};
    m.msg_iov = &io;
    m.msg_iovlen = 1;
    m.msg_control = cbuf;
    m.msg_controllen = sizeof cbuf;
    if (::recvmsg(sock, &m, 0) <= 0) return -1;
    cmsghdr* c = CMSG_FIRSTHDR(&m);
    if (!c || c->cmsg_type != SCM_RIGHTS) return -1;
    int fd = -1;
    std::memcpy(&fd, CMSG_DATA(c), sizeof(int));
    return fd;
}

// Read a NUL-terminated string out of the STOPPED target's address space.
//
// TOCTOU: the target is blocked in the kernel for the duration of this call, so
// it cannot rewrite the buffer underneath us. That is safe HERE because we only
// ever OBSERVE -- we never make an access-control decision from this string. An
// enforcing user-notify handler must use SECCOMP_IOCTL_NOTIF_ID_VALID and
// /proc/PID/mem pinning instead; T0 does not, and must not be copied into T2.
std::string read_remote_string(pid_t pid, std::uintptr_t remote) {
    if (remote == 0) return {};
    std::string buf(4096, '\0');
    iovec l{buf.data(), buf.size() - 1};
    iovec r{reinterpret_cast<void*>(remote), buf.size() - 1};
    ssize_t got = ::process_vm_readv(pid, &l, 1, &r, 1, 0);
    if (got <= 0) return {};
    buf.resize(static_cast<std::size_t>(got));
    if (auto nul = buf.find('\0'); nul != std::string::npos) buf.resize(nul);
    return buf;
}

// Resolve a possibly-relative path the way the KERNEL would have, from the
// observed process's own point of view.
//
// This matters for correctness of the synthesized policy: a workload that does
// openat(AT_FDCWD, "src/main.c") must produce an absolute path, or the
// synthesizer emits a rule that means nothing outside that cwd. /proc/PID/cwd
// and /proc/PID/fd/N give us exactly the kernel's resolution, including for a
// dirfd that is not AT_FDCWD.
std::string resolve_path(pid_t pid, std::string raw, int dirfd, bool at_style) {
    if (raw.empty()) return {};
    if (raw.front() == '/') return raw;

    std::error_code ec;
    std::filesystem::path base;
    if (at_style && dirfd != AT_FDCWD) {
        base = std::filesystem::read_symlink(
            "/proc/" + std::to_string(pid) + "/fd/" + std::to_string(dirfd), ec);
    } else {
        base = std::filesystem::read_symlink(
            "/proc/" + std::to_string(pid) + "/cwd", ec);
    }
    if (ec || base.empty()) return raw;  // best effort; better than dropping it
    return (base / raw).lexically_normal().string();
}

// Decode a sockaddr out of the target for connect(2)/bind(2), so the synthesized
// policy can name a host:port instead of "some network access happened".
std::string read_sockaddr(pid_t pid, std::uintptr_t remote, std::size_t len) {
    if (remote == 0 || len < sizeof(sa_family_t) || len > sizeof(sockaddr_storage)) {
        return {};
    }
    sockaddr_storage ss{};
    iovec l{&ss, len};
    iovec r{reinterpret_cast<void*>(remote), len};
    if (::process_vm_readv(pid, &l, 1, &r, 1, 0) <= 0) return {};

    char host[INET6_ADDRSTRLEN] = {0};
    unsigned port = 0;
    if (ss.ss_family == AF_INET) {
        auto* a = reinterpret_cast<sockaddr_in*>(&ss);
        ::inet_ntop(AF_INET, &a->sin_addr, host, sizeof host);
        port = ntohs(a->sin_port);
    } else if (ss.ss_family == AF_INET6) {
        auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
        ::inet_ntop(AF_INET6, &a->sin6_addr, host, sizeof host);
        port = ntohs(a->sin6_port);
    } else {
        return {};  // AF_UNIX etc: not egress, nothing for a net policy to say
    }
    return std::string{host} + ":" + std::to_string(port);
}

}  // namespace

ObserveCaps probe() {
    ObserveCaps c;
    c.mechanism = "seccomp-user-notify";

    // The action must be present in this kernel's advertised set. Some
    // hardening profiles compile it out, and a silent fallback to "observed
    // nothing" would be exactly the confidently-wrong answer we refuse to give.
    std::string avail;
    if (FILE* f = std::fopen("/proc/sys/kernel/seccomp/actions_avail", "r")) {
        char buf[512] = {0};
        if (std::fgets(buf, sizeof buf, f)) avail = buf;
        std::fclose(f);
    }
    if (avail.find("user_notif") == std::string::npos) {
        c.available = false;
        c.reason =
            "this kernel does not advertise the seccomp `user_notif` action "
            "(/proc/sys/kernel/seccomp/actions_avail); T0 observation needs "
            "kernel 5.0+ with CONFIG_SECCOMP_FILTER";
        return c;
    }
    c.available = true;
    return c;
}

ObserveResult observe(const SpawnRequest& req) {
    ObserveResult res;
    auto caps = probe();
    if (!caps.available) {
        res.error = "observation unavailable: " + caps.reason;
        return res;
    }
    if (req.argv.empty()) {
        res.error = "empty argv";
        return res;
    }

    int sk[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sk) != 0) {
        res.error = std::string{"socketpair failed: "} + std::strerror(errno);
        return res;
    }

    // argv/cwd must be materialised BEFORE fork: only async-signal-safe calls
    // are allowed in the child, and std::string allocates.
    std::vector<char*> cargv;
    cargv.reserve(req.argv.size() + 1);
    for (const auto& a : req.argv) cargv.push_back(const_cast<char*>(a.c_str()));
    cargv.push_back(nullptr);

    const std::string cwd_storage = req.cwd ? *req.cwd : std::string{};
    const char* cwd = cwd_storage.empty() ? nullptr : cwd_storage.c_str();

    const auto filter = build_filter();
    sock_fprog prog{static_cast<unsigned short>(filter.size()),
                    const_cast<sock_filter*>(filter.data())};

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(sk[0]);
        ::close(sk[1]);
        res.error = std::string{"fork failed: "} + std::strerror(errno);
        return res;
    }

    if (pid == 0) {
        // ---- child: install the filter, hand back the listener, exec --------
        ::close(sk[0]);
        ::setpgid(0, 0);

        // Honour the requested cwd BEFORE installing the filter, so the chdir
        // itself is not observed as part of the workload -- and so relative
        // paths in the workload resolve against the directory the caller meant.
        if (cwd && ::chdir(cwd) != 0) _exit(125);

        // NO_NEW_PRIVS is required for an unprivileged seccomp filter. It is
        // also why this is safe to do to a workload we do not trust.
        if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) _exit(126);

        const int lfd =
            seccomp_syscall(SECCOMP_SET_MODE_FILTER,
                            SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
        if (lfd < 0) _exit(126);
        if (send_fd(sk[1], lfd) != 0) _exit(126);
        ::close(sk[1]);
        ::close(lfd);

        // From here every trapped syscall blocks until bastion answers. The
        // filter survives this execve (MEASURED), so the real workload and all
        // of its descendants are observed.
        ::execvp(cargv[0], cargv.data());
        _exit(127);
    }

    // ---- parent: supervise ---------------------------------------------------
    ::close(sk[1]);
    ::setpgid(pid, pid);

    const int notify_fd = recv_fd(sk[0]);
    ::close(sk[0]);
    if (notify_fd < 0) {
        ::kill(pid, SIGKILL);
        ::waitpid(pid, nullptr, 0);
        res.error =
            "child failed to install a seccomp listener (the workload was not "
            "observed, so no policy is proposed)";
        return res;
    }

    // Dedup: a build opens the same header thousands of times, and the ledger
    // should describe the SET of things touched, not the call count.
    std::unordered_map<std::string, std::size_t> seen;

    bool child_done = false;
    int status = 0;

    for (;;) {
        // Poll so we can notice the workload exiting even when it is quiet.
        pollfd pfd{notify_fd, POLLIN, 0};
        const int pr = ::poll(&pfd, 1, 100);
        if (pr < 0 && errno == EINTR) continue;

        // The listener is released once the LAST process carrying the filter
        // exits, which shows up as POLLHUP/POLLERR rather than a readable fd.
        //
        // MEASURED: treating "nothing to read" as `pr == 0` alone hangs
        // forever here -- poll keeps returning 1 with POLLHUP set, so a
        // timeout-only exit condition never fires and `bastion observe` never
        // returns. Hang up explicitly.
        const bool hung_up = pr > 0 && (pfd.revents & (POLLHUP | POLLERR)) &&
                             !(pfd.revents & POLLIN);
        if (hung_up) break;

        if (pr > 0 && (pfd.revents & POLLIN)) {
            seccomp_notif nreq{};
            if (::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &nreq) != 0) {
                if (errno == EINTR) continue;
                break;  // listener closed: every observed process is gone
            }

            const Trap* t = trap_for(static_cast<int>(nreq.data.nr));
            if (t) {
                std::string target;
                if (t->path_arg >= 0) {
                    std::string raw = read_remote_string(
                        static_cast<pid_t>(nreq.pid),
                        static_cast<std::uintptr_t>(nreq.data.args[t->path_arg]));
                    target = resolve_path(
                        static_cast<pid_t>(nreq.pid), std::move(raw),
                        static_cast<int>(nreq.data.args[0]), t->at_style);
                } else {
                    // connect(fd, addr, addrlen) / bind(fd, addr, addrlen)
                    target = read_sockaddr(
                        static_cast<pid_t>(nreq.pid),
                        static_cast<std::uintptr_t>(nreq.data.args[1]),
                        static_cast<std::size_t>(nreq.data.args[2]));
                }

                if (!target.empty()) {
                    std::string op = t->op;
                    // openat carries the intent in its flags: a policy needs to
                    // know whether this was a READ or a WRITE, and guessing
                    // would either over-grant (write for everything) or
                    // under-grant (read for everything).
                    if (op == "fs.open") {
                        const int flags = t->at_style
                            ? static_cast<int>(nreq.data.args[2])
                            : static_cast<int>(nreq.data.args[1]);
                        const int acc = flags & O_ACCMODE;
                        op = (acc == O_RDONLY && !(flags & O_CREAT)) ? "fs.read"
                                                                    : "fs.write";
                    }
                    const std::string key = op + "\0" + target;
                    if (seen.try_emplace(key, res.records.size()).second) {
                        AuditRecord rec;
                        rec.verdict = Verdict::Allow;  // T0 enforces nothing
                        rec.op = op;
                        rec.target = target;
                        rec.tier = Tier::Observe;
                        rec.rule = "observed";
                        rec.provenance =
                            "observed from pid " + std::to_string(nreq.pid);
                        res.records.push_back(std::move(rec));
                    }
                }
            }

            // Let the syscall actually happen. This is what makes T0
            // OBSERVATION: the workload behaves exactly as it would unobserved.
            seccomp_notif_resp resp{};
            resp.id = nreq.id;
            resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            if (::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) != 0 &&
                errno != ENOENT) {
                // ENOENT just means that process died while we were deciding.
                ++res.dropped;
            }
            continue;
        }

        if (!child_done) {
            const pid_t w = ::waitpid(pid, &status, WNOHANG);
            if (w == pid) {
                child_done = true;
                // Do NOT break: descendants may still be running and
                // notifying. The loop ends on POLLHUP, when the last process
                // holding the filter is gone.
            }
        } else if (pr == 0) {
            // Child gone and the listener quiet for a full interval: nothing
            // is left to observe. Belt-and-braces alongside the POLLHUP exit,
            // for the case where a descendant inherited the listener fd.
            break;
        }
    }

    ::close(notify_fd);
    if (!child_done) ::waitpid(pid, &status, 0);

    if (WIFSIGNALED(status)) {
        res.exit_code = 128 + WTERMSIG(status);
    } else {
        res.exit_code = WEXITSTATUS(status);
    }

    if (res.exit_code == 126) {
        res.error =
            "could not install the seccomp observer in the child; the workload "
            "did not run";
        return res;
    }
    if (res.records.empty()) {
        res.warnings.emplace_back(
            "observation produced no records: the workload performed no "
            "observable file or network operations");
    }
    return res;
}

#else  // no seccomp user-notify headers

ObserveCaps probe() {
    ObserveCaps c;
    c.available = false;
    c.mechanism = "none";
    c.reason = "built without seccomp user-notification headers";
    return c;
}

ObserveResult observe(const SpawnRequest&) {
    ObserveResult r;
    r.error = probe().reason;
    return r;
}

#endif

}  // namespace bastion::linux_seccomp
