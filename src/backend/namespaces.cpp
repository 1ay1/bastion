#include "bastion/backend/namespaces.hpp"

#include "bastion/unique_fd.hpp"

#if defined(__linux__)

#  include <fcntl.h>
#  include <sched.h>
#  include <sys/mount.h>
#  include <sys/wait.h>
#  include <unistd.h>

#  include <cerrno>
#  include <cstdio>
#  include <cstring>

namespace bastion::linux_ns {

namespace {

// Write a whole buffer to a /proc file. These accept exactly one write(2), so a
// partial write is a hard failure rather than something to retry.
// `err` receives errno on failure, for an actionable message.
bool write_file(const char* path, const char* data, int* err = nullptr) {
    const int fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        if (err) *err = errno;
        return false;
    }
    const ssize_t n = ::write(fd, data, std::strlen(data));
    if (err && n != static_cast<ssize_t>(std::strlen(data))) *err = errno;
    const bool ok = n == static_cast<ssize_t>(std::strlen(data));
    ::close(fd);
    return ok;
}

}  // namespace

NsCaps probe() {
    NsCaps c;

    // Probing by ATTEMPT, not by reading sysctls: the sysctl names differ
    // between distros (kernel.unprivileged_userns_clone is Debian/Arch-specific,
    // user.max_user_namespaces is upstream) and neither accounts for a seccomp
    // profile that blocks unshare(2) outright. Forking a throwaway child and
    // asking the kernel is the only answer that cannot be wrong.
    const pid_t pid = ::fork();
    if (pid < 0) {
        c.reason = std::string{"fork failed: "} + std::strerror(errno);
        return c;
    }
    if (pid == 0) {
        if (::unshare(CLONE_NEWUSER) != 0) _exit(1);
        if (::unshare(CLONE_NEWPID) != 0) _exit(2);
        if (::unshare(CLONE_NEWNS) != 0) _exit(3);
        _exit(0);
    }
    int st = 0;
    ::waitpid(pid, &st, 0);
    const int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;

    c.available = code == 0 || code >= 2;  // user ns worked if we got past it
    c.pid = code == 0 || code == 3;
    c.mount = code == 0;
    if (code == 1) {
        c.available = false;
        c.reason =
            "unprivileged user namespaces are disabled on this system "
            "(sysctl user.max_user_namespaces or kernel.unprivileged_userns_clone); "
            "process-table isolation is unavailable, the kernel file/network "
            "boundary is unaffected";
    } else if (code != 0) {
        c.reason = "partial namespace support; some isolation is unavailable";
    }
    return c;
}

bool enter_namespaces(ForkChild tok, const char** err) noexcept {
    (void)tok;  // compile-time proof of context; no runtime state
    const auto setf = [err](const char* m) { if (err) *err = m; };
    setf(nullptr);

    // ALLOCATION-FREE FROM HERE DOWN. This runs between fork() and exec(), and
    // at T3 the egress broker's accept thread was live at fork time -- so a
    // std::string here could deadlock forever on a malloc lock owned by a
    // thread that does not exist in this process. Every error is a static
    // string; UniqueFd only ever calls close(2), which is async-signal-safe.

    // The uid/gid map of a new user namespace CANNOT be written by the process
    // that created it: an unprivileged self-write returns EPERM, because
    // writing a map requires CAP_SETUID in the PARENT namespace and the
    // unshared process no longer has it there.
    //
    // MEASURED (kernel 7.2.2, uid 1000): unshare(CLONE_NEWUSER) succeeds, then
    // write("/proc/self/uid_map") -> EPERM. Writing /proc/CHILD/uid_map from
    // the parent succeeds. This is why `unshare --map-root-user` works while a
    // naive in-process version does not, and it is the whole reason this
    // function is structured as fork-then-map rather than a straight line.
    //
    // So: fork FIRST, let the child unshare, and have the parent write its map.
    int rp[2] = {-1, -1};   // child -> parent: "I have unshared"
    int mp[2] = {-1, -1};   // parent -> child: "your map is written"
    if (::pipe(rp) != 0) {
        setf("pipe(ready) failed");
        return false;
    }
    UniqueFd ready_r{rp[0]}, ready_w{rp[1]};
    if (::pipe(mp) != 0) {
        setf("pipe(mapped) failed");
        return false;  // ready_* closed by ~UniqueFd
    }
    UniqueFd mapped_r{mp[0]}, mapped_w{mp[1]};

    const uid_t uid = ::getuid();
    const gid_t gid = ::getgid();

    const pid_t child = ::fork();
    if (child < 0) {
        setf("fork for user namespace failed");
        return false;  // all four ends closed by ~UniqueFd
    }

    if (child > 0) {
        // ---- parent: write the child's maps, then mirror its exit ----------
        ready_w.reset();
        mapped_r.reset();

        char c = 0;
        ssize_t n;
        do {
            n = ::read(ready_r.get(), &c, 1);
        } while (n < 0 && errno == EINTR);
        const bool unshared = n == 1 && c == 'u';
        ready_r.reset();

        if (unshared) {
            char path[64];
            char buf[64];

            // setgroups must be denied BEFORE gid_map, or the kernel refuses
            // the gid_map write. That ordering is a documented security
            // requirement: it stops a process dropping a supplementary group
            // to gain access it would otherwise be denied.
            std::snprintf(path, sizeof path, "/proc/%d/setgroups", child);
            write_file(path, "deny");

            std::snprintf(path, sizeof path, "/proc/%d/gid_map", child);
            std::snprintf(buf, sizeof buf, "0 %u 1", static_cast<unsigned>(gid));
            write_file(path, buf);

            std::snprintf(path, sizeof path, "/proc/%d/uid_map", child);
            std::snprintf(buf, sizeof buf, "0 %u 1", static_cast<unsigned>(uid));
            write_file(path, buf);
        }

        c = 'm';
        (void)::write(mapped_w.get(), &c, 1);
        mapped_w.reset();

        // Mirror the workload's exit status so this extra process level is
        // invisible to everything upstream.
        int st = 0;
        while (::waitpid(child, &st, 0) < 0 && errno == EINTR) {
        }
        if (WIFSIGNALED(st)) {
            ::signal(WTERMSIG(st), SIG_DFL);
            ::raise(WTERMSIG(st));
        }
        _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 1);
    }

    // ---- child: unshare, wait to be mapped, then become pid 1 --------------
    ready_r.reset();
    mapped_w.reset();

    if (::unshare(CLONE_NEWUSER) != 0) {
        setf("unshare(CLONE_NEWUSER) failed");
        return false;
    }

    char c = 'u';
    (void)::write(ready_w.get(), &c, 1);
    ready_w.reset();

    // Block until the parent has written our uid/gid map. Acting before that
    // would run as `nobody` (65534) and every subsequent step would fail in a
    // way that looks like a permissions bug rather than a race.
    ssize_t n;
    do {
        n = ::read(mapped_r.get(), &c, 1);
    } while (n < 0 && errno == EINTR);
    mapped_r.reset();

    // PID + IPC. IPC keeps SysV queues and POSIX shared memory from being a
    // side channel to processes outside the sandbox.
    if (::unshare(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC) != 0) {
        setf("unshare(CLONE_NEWPID|NEWNS|NEWIPC) failed");
        return false;
    }

    // unshare(CLONE_NEWPID) does NOT move the caller into the new namespace --
    // it only takes effect for children. So we fork again: the grandchild
    // becomes pid 1 and goes on to be the workload, while this level stays
    // behind to reap it and mirror its exit status.
    const pid_t inner = ::fork();
    if (inner < 0) {
        setf("fork into PID namespace failed");
        return false;
    }
    if (inner > 0) {
        int st = 0;
        while (::waitpid(inner, &st, 0) < 0 && errno == EINTR) {
        }
        if (WIFSIGNALED(st)) {
            ::signal(WTERMSIG(st), SIG_DFL);
            ::raise(WTERMSIG(st));
        }
        _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 1);
    }

    // ---- we are now pid 1 in a private PID namespace ------------------------

    // Make mount propagation private, or mounting /proc would escape into the
    // host mount namespace and affect the whole machine.
    ::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr);

    // A fresh /proc is what makes the PID namespace OBSERVABLE. Without it the
    // inherited /proc still shows every host process -- the isolation would be
    // real but invisible, and `ps aux` would keep leaking. Best-effort: if it
    // fails the PID namespace still contains the workload, so this is a loss of
    // observability rather than of confinement.
    ::mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr);

    return true;
}

}  // namespace bastion::linux_ns

#else

namespace bastion::linux_ns {
NsCaps probe() {
    NsCaps c;
    c.reason = "not Linux";
    return c;
}
bool enter_namespaces(ForkChild, const char** err) noexcept {
    if (err) *err = "namespaces are Linux-only";
    return false;
}
}  // namespace bastion::linux_ns

#endif
