#include "bastion/backend/landlock.hpp"

#if defined(__linux__)
#  include "bastion/backend/namespaces.hpp"

#  include <fcntl.h>
#  include <sys/prctl.h>
#  include <sys/stat.h>
#  include <sys/syscall.h>
#  include <unistd.h>
#  if __has_include(<linux/landlock.h>)
#    include <linux/landlock.h>
#    define BASTION_LANDLOCK_HEADERS 1
#  endif
#endif

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

namespace bastion::linux_ll {

#if defined(BASTION_LANDLOCK_HEADERS)

namespace {

// Landlock has no glibc wrappers; go through syscall(2) directly.
int ll_create_ruleset(const struct landlock_ruleset_attr* attr, std::size_t size,
                      std::uint32_t flags) {
    return static_cast<int>(::syscall(SYS_landlock_create_ruleset, attr, size, flags));
}
int ll_add_rule(int fd, enum landlock_rule_type type, const void* attr,
                std::uint32_t flags) {
    return static_cast<int>(::syscall(SYS_landlock_add_rule, fd, type, attr, flags));
}
int ll_restrict_self(int fd, std::uint32_t flags) {
    return static_cast<int>(::syscall(SYS_landlock_restrict_self, fd, flags));
}

// Right bundles. Note these are defined in terms of what the ABI *supports*;
// the caller clamps them.
constexpr std::uint64_t kReadRights =
    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

constexpr std::uint64_t kWriteRights =
    LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
    LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
    LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
    LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
    LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM;

constexpr std::uint64_t kExecRights = LANDLOCK_ACCESS_FS_EXECUTE;

// Rights that are only meaningful on a DIRECTORY. The kernel returns EINVAL if
// a path_beneath rule carries one of these for a non-directory fd, so apply()
// strips them per-inode.
//
// Two of these were found the hard way, each taking down every spawn that hit
// it (a failed add_rule aborts apply(), and a failed apply() is fail-closed):
//   - READ_DIR, via the ergonomic floor's read grant on the regular file
//     /etc/ld.so.cache.
//   - REFER, via a SYNTHESIZED policy: `observe` records a write to an output
//     FILE (/tmp/ws/copy.txt), and a write grant carries REFER. The UAPI is
//     explicit that REFER is granted "for a specific directory" -- it governs
//     reparenting a hierarchy, which is meaningless for a regular file.
constexpr std::uint64_t kDirOnlyRights =
    LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |
    LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
    LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
    LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
    LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |
    LANDLOCK_ACCESS_FS_REFER;

// The per-run private temp dir, when the user has no $TMPDIR of their own.
//
// Created 0700 under /tmp, so it is writable by this sandbox and unreadable by
// other users and other agents on the box -- the isolation a blanket /tmp
// grant would destroy. The name is derived from the PID and is computed ONCE
// per process: compile() must name the same directory that spawn() puts in the
// child's $TMPDIR, or the toolchain would be pointed somewhere ungranted.
// Defined below, outside this anonymous namespace, because spawn() needs it too.

// The full mask for a given ABI level. Requesting a bit the kernel does not
// know makes landlock_create_ruleset fail with EINVAL, taking the ENTIRE
// sandbox with it -- so every version-gated right is added conditionally.
std::uint64_t fs_mask_for(const AbiInfo& abi) {
    std::uint64_t m = kReadRights | kWriteRights | kExecRights;
    if (abi.has_refer) m |= LANDLOCK_ACCESS_FS_REFER;
    if (abi.has_truncate) m |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi.has_ioctl_dev) m |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    return m;
}

std::uint64_t net_mask_for(const AbiInfo& abi) {
    if (!abi.has_net_tcp) return 0;
    return LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
}

std::uint16_t parse_port(std::string_view host_port) {
    auto colon = host_port.rfind(':');
    if (colon == std::string_view::npos) return 0;
    auto tail = host_port.substr(colon + 1);
    unsigned v = 0;
    for (char c : tail) {
        if (c < '0' || c > '9') return 0;
        v = v * 10 + static_cast<unsigned>(c - '0');
        if (v > 65535) return 0;
    }
    return static_cast<std::uint16_t>(v);
}

}  // namespace

const std::string& private_tmp_dir() {
    static const std::string dir = [] {
        const char* base = std::getenv("XDG_RUNTIME_DIR");
        std::string root =
            (base && *base == '/') ? std::string{base} : std::string{"/tmp"};
        std::string d =
            root + "/bastion-tmp-" + std::to_string(static_cast<long>(::getpid()));
        std::error_code ec;
        std::filesystem::create_directories(d, ec);
        if (ec) return std::string{};
        // 0700: owner only. Landlock grants authority, but the DAC bits keep
        // other UIDs out even before the sandbox is involved.
        std::filesystem::permissions(d, std::filesystem::perms::owner_all,
                                     std::filesystem::perm_options::replace, ec);

        // Scratch space is per-RUN, so it must not outlive the run: one stale
        // 0700 directory per invocation would otherwise pile up forever in
        // $XDG_RUNTIME_DIR (measured: 7 dirs after 7 runs). Registered once,
        // and only after the directory was actually created.
        static std::string cleanup_path;
        cleanup_path = d;
        std::atexit([] {
            if (cleanup_path.empty()) return;
            std::error_code rec;
            std::filesystem::remove_all(cleanup_path, rec);
        });
        return d;
    }();
    return dir;
}

std::size_t AbiCore::ruleset_attr_size() const noexcept {
    // Field growth by ABI version (each field is __u64):
    //   v1-v3 : handled_access_fs             (1 field)
    //   v4+   : + handled_access_net          (2 fields)
    //   v6+   : + scoped                      (3 fields)
    //   v10+  : + quiet_access_fs/net/scoped  (6 fields)
    // Clamped to what the build-time struct can actually hold, so a binary
    // built against older headers never claims a larger struct than it has.
    std::size_t fields = 1;
    if (version >= 4) fields = 2;
    if (version >= 6) fields = 3;
    if (version >= 10) fields = 6;
    const std::size_t want = fields * sizeof(std::uint64_t);
    return want > sizeof(struct landlock_ruleset_attr)
               ? sizeof(struct landlock_ruleset_attr)
               : want;
}

AbiInfo probe_abi() {
    AbiInfo info;
    int v = ll_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (v < 0) {
        info.version = -1;
        info.note = (errno == ENOSYS)
                        ? "Landlock not supported by this kernel (ENOSYS); "
                          "needs Linux 5.13+"
                        : std::string{"Landlock unavailable: "} + std::strerror(errno) +
                              " (check CONFIG_SECURITY_LANDLOCK and the lsm= boot "
                              "parameter)";
        return info;
    }
    info.version = v;
    info.has_refer = v >= 2;
    info.has_truncate = v >= 3;
    info.has_net_tcp = v >= 4;
    info.has_ioctl_dev = v >= 5;
    info.has_scoped = v >= 6;
    info.has_quiet = v >= 10;
    info.note = "Landlock ABI v" + std::to_string(v);
    return info;
}

Result<Ruleset> compile(const Sealed& policy, const AbiInfo& abi,
                        std::uint16_t proxy_port) {
    Ruleset rs;
    if (abi.version < 0) {
        // No usable Landlock: return the reason, never a half-built ruleset
        // that a caller could hand to the kernel.
        return Error{abi.note};
    }

    // Unconfined: no ruleset at all. The audit ledger still records everything
    // (DESIGN.md §1) -- we decline to *enforce*, not to observe.
    if (policy.is_unconfined()) {
        rs.warnings.emplace_back(
            "unconfined: no Landlock ruleset applied; operations are still "
            "recorded");
        return rs;
    }

    rs.handled_fs = fs_mask_for(abi);
    rs.handled_net = net_mask_for(abi);

    if (!abi.has_refer) {
        rs.warnings.emplace_back(
            "Landlock ABI v1: link/rename ACROSS directories is always denied "
            "(no FS_REFER). Builds that rename between dirs may fail; "
            "kernel 5.19+ fixes this.");
    }
    if (!abi.has_truncate) {
        rs.warnings.emplace_back(
            "Landlock ABI <3: truncate() is not mediated, so a granted-read "
            "file may still be truncated.");
    }
    if (!abi.has_ioctl_dev) {
        // Found by the ABI matrix test: v3 and v4 warned about NOTHING, even
        // though ioctl(2) on a granted device is unmediated there. A tier that
        // quietly enforces less than it promises is the failure mode this
        // project exists to prevent, so every gap gets a sentence.
        rs.warnings.emplace_back(
            "Landlock ABI <5: ioctl() on device files is not mediated, so a "
            "granted device can be reconfigured through an ioctl this policy "
            "cannot see; kernel 6.10+ adds FS_IOCTL_DEV.");
    }
    if (!abi.has_scoped) {
        rs.warnings.emplace_back(
            "Landlock ABI <6: abstract UNIX sockets and signals are not "
            "scoped, so the sandbox can signal and connect to processes "
            "outside it; kernel 6.12+ adds LANDLOCK_SCOPE_*. Use --tier t3 "
            "for IPC isolation via namespaces.");
    }

    // The ergonomic floor (DESIGN.md §4): without these, toolchains break in
    // ways that look like broken code and burn agent turns.
    //
    // MEASURED additions (kernel 7.2.2): the TLS trust store and the resolver
    // config. Without them `curl https://...` fails at T3 with
    //   error adding trust anchors from file: /etc/ssl/certs/ca-certificates.crt
    // even though egress was correctly ALLOWED -- a network policy that looks
    // like a broken CA store, which is precisely the diagnosis-burning failure
    // §4 exists to prevent. The macOS backend never hit this because it grants
    // read on all of /etc; the Linux floor is narrower and has to be explicit.
    // Both the symlink and its target are listed: on Arch/Debian
    // /etc/ssl/certs/ca-certificates.crt points into /etc/ca-certificates,
    // and Landlock resolves the target, so granting only the link is useless.
    static constexpr const char* kBaseRead[] = {
        "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc/ld.so.cache",
        "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives",
        "/etc/localtime", "/proc/self", "/sys/devices/system/cpu",
        // TLS trust anchors (distro variance; missing entries are skipped).
        "/etc/ssl", "/etc/pki", "/etc/ca-certificates",
        // Name resolution: without these, DNS fails inside the sandbox and
        // every network error is misreported as a connectivity problem.
        "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf",
        "/etc/host.conf", "/etc/services", "/etc/gai.conf",
    };
    for (const char* p : kBaseRead) {
        std::error_code ec;
        if (!std::filesystem::exists(p, ec) || ec) continue;  // distro variance
        rs.paths.push_back({p, kReadRights | kExecRights});
    }

    // VERSION CONTROL CONFIG. READ-ONLY, and under $HOME so it cannot be
    // hardcoded in the list above.
    //
    // MEASURED: `git status` -- the single most common command an agent runs --
    // failed OUTRIGHT in the sandbox:
    //   warning: unable to access '/home/ayush/.gitconfig': Permission denied
    //   fatal: unknown error occurred while reading the configuration files
    // Not a degraded result: git refuses to operate at all. An agent that
    // cannot run `git status` cannot work, and would conclude the sandbox is
    // broken rather than that it needs a grant -- exactly the friction
    // DESIGN.md §4 says gets sandboxes switched off.
    //
    // Read-only is the whole point: the agent may READ the user's identity and
    // aliases, which is what git needs to start, but cannot rewrite them. A
    // writable .gitconfig would be a persistence vector -- core.pager and
    // core.editor are command strings git executes.
    //
    // Credentials are deliberately NOT here, and this is why the list names
    // FILES rather than directories.
    //
    // MEASURED: granting ~/.config/git as a directory leaked
    // ~/.config/git/credentials -- git's own documented credential-store
    // location, sitting right beside the config file we wanted. A confined
    // agent read a token straight out of it. Path-set authority grants
    // everything BENEATH a directory, so "the config lives in that folder" is
    // never a safe reason to grant the folder.
    //
    // So: only the exact files git needs to start, each named. A new config
    // file appearing in that directory is a missing grant (a warning the user
    // can act on), not a silent credential leak.
    if (const char* home = std::getenv("HOME"); home && *home == '/') {
        const std::string h{home};
        for (const char* rel : {"/.gitconfig",
                                "/.config/git/config",
                                "/.config/git/attributes",
                                "/.config/git/ignore",
                                "/.gitignore_global",
                                "/.hgrc"}) {
            const std::string p = h + rel;
            std::error_code ec;
            // Regular files only: if any of these is a directory (or a symlink
            // to one), granting it would reopen exactly the hole above.
            if (!std::filesystem::is_regular_file(p, ec) || ec) continue;
            rs.paths.push_back({p, kReadRights});
        }
    }
    for (const char* p : {"/etc/gitconfig", "/etc/gitattributes"}) {
        std::error_code ec;
        if (!std::filesystem::is_regular_file(p, ec) || ec) continue;
        rs.paths.push_back({p, kReadRights});
    }

    // Character devices every toolchain expects.
    for (const char* p : {"/dev/null", "/dev/zero", "/dev/urandom", "/dev/random",
                          "/dev/tty", "/dev/ptmx"}) {
        std::error_code ec;
        if (!std::filesystem::exists(p, ec) || ec) continue;
        std::uint64_t r = kReadRights | LANDLOCK_ACCESS_FS_WRITE_FILE;
        if (abi.has_ioctl_dev) r |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
        rs.paths.push_back({p, r});
    }

    // A WRITABLE TEMP DIR. The single biggest ergonomic win in the field report
    // was "the return of rw in /tmp" (DESIGN.md §4): without it GCC/Clang cannot
    // create scratch files and every compile dies with
    //   cc: Cannot create temporary file in /tmp/: Permission denied
    // which reads as a broken toolchain, not as a policy decision -- the exact
    // failure mode that gets sandboxes switched off. MEASURED on kernel 7.2.2:
    // before this, `cc m.c -o m` failed inside the sandbox on a trivial file.
    //
    // SECURITY: we deliberately do NOT grant shared /tmp, for the reason the
    // macOS backend spells out -- it is world-readable, so a blanket grant
    // leaks cross-session data between agents on the same box. MEASURED: an
    // earlier version of this code granted /tmp as a fallback and immediately
    // opened 6 escapes in tests/adversarial_test.cpp (the suite keeps its
    // "secret" dir under /tmp, exactly like a second agent would).
    //
    // macOS gets a private $TMPDIR (/var/folders/...) for free; Linux usually
    // has $TMPDIR unset, so bastion MAKES one -- a per-run directory that only
    // this sandbox can see. spawn() points TMPDIR/TMP/TEMP at it, so the
    // toolchain finds it the normal way.
    {
        std::vector<std::string> tmp_dirs;
        for (const char* var : {"TMPDIR", "TMP", "TEMP"}) {
            if (const char* v = std::getenv(var); v && *v && v[0] == '/') {
                tmp_dirs.emplace_back(v);
            }
        }
        if (tmp_dirs.empty()) {
            // No $TMPDIR: mint a private one rather than falling back to the
            // shared, world-readable /tmp.
            if (const std::string priv = private_tmp_dir(); !priv.empty()) {
                tmp_dirs.push_back(priv);
            }
        }

        // Toolchain caches, so dependencies are not re-downloaded every run
        // (DESIGN.md §4).
        for (const char* var : {"CARGO_HOME", "GOCACHE", "GOMODCACHE",
                                "npm_config_cache", "PIP_CACHE_DIR",
                                "CCACHE_DIR", "ZIG_GLOBAL_CACHE_DIR"}) {
            if (const char* v = std::getenv(var); v && *v && v[0] == '/') {
                tmp_dirs.emplace_back(v);
            }
        }

        // DEFAULT cache locations, for the (normal) case where none of those
        // are set. An unset CARGO_HOME does not mean "cargo needs no cache" --
        // it means cargo uses ~/.cargo, which a policy that only grants the
        // workspace does NOT cover. Every build then re-downloads the world,
        // or fails outright, and the agent looks broken for reasons that have
        // nothing to do with its task. `bastion doctor` used to just WARN
        // about this; warning about a problem bastion can simply fix is worse
        // than fixing it.
        //
        // Only paths that already EXIST are granted, so this never invents
        // authority for a toolchain the user does not have installed.
        if (const char* home = std::getenv("HOME"); home && *home == '/') {
            const std::string h{home};
            for (const char* rel : {"/.cargo", "/.rustup", "/.cache/go-build",
                                    "/go/pkg/mod", "/.npm", "/.cache/pip",
                                    "/.ccache", "/.cache/zig",
                                    "/.cache/uv", "/.cache/yarn"}) {
                tmp_dirs.push_back(h + rel);
            }
        }

        for (const auto& t : tmp_dirs) {
            std::error_code ec;
            auto canon = std::filesystem::weakly_canonical(t, ec);
            const std::string path = ec ? t : canon.string();
            if (!std::filesystem::is_directory(path, ec) || ec) continue;

            // Skip anything already granted, so a workspace that IS $TMPDIR
            // does not get a second, wider rule.
            bool dup = false;
            for (const auto& existing : rs.paths) {
                if (existing.path == path) { dup = true; break; }
            }
            if (dup) continue;

            // Same right set a user-supplied write rule gets. TRUNCATE is
            // load-bearing, not incidental: cc1 opens its scratch file with
            // O_CREAT|O_TRUNC, so without it `touch /tmp/x` succeeds while
            // every real compile fails with
            //   cc1: fatal error: cannot open '/tmp/ccXXXX.s' for writing
            // MEASURED on kernel 7.2.2 (ABI v10).
            std::uint64_t w = kReadRights | kWriteRights;
            if (abi.has_truncate) w |= LANDLOCK_ACCESS_FS_TRUNCATE;
            if (abi.has_refer) w |= LANDLOCK_ACCESS_FS_REFER;
            if (abi.has_ioctl_dev) w |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
            rs.paths.push_back({path, w});
        }
    }

    bool net_requested = false;
    const bool t3_broker = (proxy_port != 0 && policy.tier() >= Tier::Isolate);

    for (const auto& r : policy.rules()) {
        if (any(r.right & (Right::NetEgress | Right::NetBind))) {
            net_requested = true;
            // At T3 the per-host allowlist is enforced by the broker, not by
            // the kernel: the kernel's only job is to make the broker the sole
            // reachable destination (see the proxy_port rule below), so
            // individual host rules are deliberately NOT translated here.
            if (t3_broker) continue;

            std::uint16_t port = parse_port(r.scope);
            if (port == 0) {
                // Landlock filters by PORT, not hostname. Saying so is the
                // point -- see DESIGN.md §6 / `bastion explain`.
                rs.warnings.emplace_back(
                    "net rule '" + r.scope +
                    "' has no usable port; Landlock cannot filter by hostname. "
                    "Use --tier t3 for per-host allowlisting.");
                continue;
            }
            Ruleset::PortRule pr;
            pr.port = port;
            pr.connect = any(r.right & Right::NetEgress);
            pr.bind = any(r.right & Right::NetBind);
            rs.ports.push_back(pr);
            continue;
        }

        std::uint64_t allowed = 0;
        if (any(r.right & Right::FsRead)) allowed |= kReadRights;
        if (any(r.right & Right::FsWrite)) {
            allowed |= kWriteRights;
            if (abi.has_truncate) allowed |= LANDLOCK_ACCESS_FS_TRUNCATE;
            if (abi.has_refer) allowed |= LANDLOCK_ACCESS_FS_REFER;
        }
        if (any(r.right & Right::FsExec)) allowed |= kExecRights;
        if (allowed == 0) continue;

        std::error_code ec;
        if (!std::filesystem::exists(r.scope, ec) || ec) {
            // Landlock rules need an openable path. A grant for a not-yet-created
            // directory is a real ergonomic case (build output), so warn rather
            // than fail the whole policy.
            rs.warnings.emplace_back("path does not exist yet, rule skipped: " +
                                     r.scope);
            continue;
        }
        rs.paths.push_back({r.scope, allowed});
    }

    // T3: the broker's loopback port is the ONLY permitted connect target.
    // Everything else is denied by handled_access_net, so a compromised child
    // cannot open its own socket and must go through the allowlist.
    if (t3_broker) {
        if (!abi.has_net_tcp) {
            // Fail closed: T3 must not silently degrade to T2. Returning an
            // Error rather than a flagged Ruleset means no caller can proceed
            // to enforce this.
            return Error{
                "T3 brokered egress needs Landlock ABI v4+ (kernel 6.7) to pin "
                "outbound to the broker port; this kernel is " + abi.note +
                ". Refusing to claim per-host filtering it cannot enforce."};
        }
        Ruleset::PortRule pr;
        pr.port = proxy_port;
        pr.connect = true;
        pr.bind = false;
        rs.ports.push_back(pr);
    }

    if (net_requested && !abi.has_net_tcp) {
        rs.warnings.emplace_back(
            "network rules requested but Landlock ABI <4 cannot mediate "
            "network access; egress is UNRESTRICTED at T2 on this kernel. Use "
            "T3 for network isolation.");
        rs.handled_net = 0;
        rs.ports.clear();
    }

    return rs;
}

bool apply_compiled(ForkChild tok, const Ruleset& rs, const AbiCore& abi,
                    const char** err) noexcept {
    // The token carries no runtime state: its whole job is to make the
    // "only callable in a post-fork child" contract checkable by the compiler.
    (void)tok;
    const auto setf = [err](const char* m) { if (err) *err = m; };
    setf(nullptr);

    // ASYNC-SIGNAL-SAFE FROM HERE DOWN, and now machine-checked rather than
    // merely asserted in a comment: `tok` proves we are in a post-fork child,
    // and ForkChild::check() makes using a non-trivially-copyable value here a
    // COMPILE error. The values we cross the boundary with are the ABI struct
    // (trivial) and raw const char* into strings the PARENT already built.
    ForkChild::check(abi);

    // NO_NEW_PRIVS is mandatory: landlock_restrict_self fails with EPERM
    // without it for an unprivileged process. It also independently prevents
    // setuid binaries from regaining privilege inside the sandbox -- which is
    // the exact class of hole that makes firejail's setuid-root design unsafe
    // (DESIGN.md §3.1).
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        setf("prctl(PR_SET_NO_NEW_PRIVS) failed");
        return false;
    }

    struct landlock_ruleset_attr attr {};
    attr.handled_access_fs = rs.handled_fs;
#  if defined(LANDLOCK_ACCESS_NET_CONNECT_TCP)
    attr.handled_access_net = rs.handled_net;
#  endif

    // Pass the ABI-appropriate size, not sizeof() (see ruleset_attr_size).
    const int fd = ll_create_ruleset(&attr, abi.ruleset_attr_size(), 0);
    if (fd < 0) {
        setf("landlock_create_ruleset failed");
        return false;
    }

    for (const auto& p : rs.paths) {
        // p.path is a std::string built by the PARENT; .c_str() only reads it.
        const int pfd = ::open(p.path.c_str(), O_PATH | O_CLOEXEC);
        if (pfd < 0) continue;  // vanished between compile and apply; skip

        // Mask to the handled set: a rule may not grant a right the ruleset
        // does not handle (EINVAL), and this also clamps to the probed ABI.
        std::uint64_t allowed = p.allowed & rs.handled_fs;

        // MEASURED (kernel 7.2.2, ABI v10): the kernel rejects a rule with
        // EINVAL if it carries a directory-ONLY right on a non-directory --
        // e.g. READ_DIR on the regular file /etc/ld.so.cache. Because one
        // failed add_rule aborts apply(), and a failed apply() is fail-closed,
        // this took down EVERY confined spawn on Linux: the loader-cache rule
        // comes from the ergonomic floor, so it is on every policy. compile()
        // assigns rights per right-set and cannot know the inode type, so the
        // clamp belongs here, where we hold the fd.
        struct stat st {};
        if (::fstat(pfd, &st) == 0 && !S_ISDIR(st.st_mode)) {
            allowed &= ~kDirOnlyRights;
        }

        // Nothing left to grant (a dir-only rule on a file): skip rather than
        // send an empty rule, which is itself EINVAL.
        if (allowed == 0) {
            ::close(pfd);
            continue;
        }

        struct landlock_path_beneath_attr pb {};
        pb.parent_fd = pfd;
        pb.allowed_access = allowed;
        const int rc = ll_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
        ::close(pfd);
        if (rc != 0) {
            ::close(fd);
            setf("landlock_add_rule(path) failed");
            return false;
        }
    }

    // NOTE: the guard here is LANDLOCK_ACCESS_NET_CONNECT_TCP (a #define), NOT
    // LANDLOCK_RULE_NET_PORT.
    //
    // MEASURED BUG (kernel 7.2.2, ABI v10): LANDLOCK_RULE_NET_PORT is an
    // ENUMERATOR, not a macro, so `#if defined(LANDLOCK_RULE_NET_PORT)` is
    // ALWAYS FALSE and silently deleted this entire loop. The effect was the
    // worst possible shape for a security tool: handled_access_net was still
    // set, so the kernel denied ALL egress, but the one allow-rule for the
    // broker port was never added -- so T3 "worked" (nothing got out) while
    // being totally unusable (the workload could not reach the broker either).
    // Availability failure masquerading as enforcement.
#  if defined(LANDLOCK_ACCESS_NET_CONNECT_TCP)
    for (const auto& pr : rs.ports) {
        if (rs.handled_net == 0) break;
        struct landlock_net_port_attr np {};
        np.port = pr.port;
        np.allowed_access = 0;
        if (pr.connect) np.allowed_access |= LANDLOCK_ACCESS_NET_CONNECT_TCP;
        if (pr.bind) np.allowed_access |= LANDLOCK_ACCESS_NET_BIND_TCP;
        np.allowed_access &= rs.handled_net;
        if (np.allowed_access == 0) continue;
        if (ll_add_rule(fd, LANDLOCK_RULE_NET_PORT, &np, 0) != 0) {
            ::close(fd);
            setf("landlock_add_rule(net) failed");
            return false;
        }
    }
#  endif

    if (ll_restrict_self(fd, 0) != 0) {
        ::close(fd);
        setf("landlock_restrict_self failed");
        return false;
    }
    ::close(fd);
    return true;
}

std::string apply(const Sealed& policy, std::uint16_t proxy_port) {
    AbiInfo abi = probe_abi();
    if (abi.version < 0) return abi.note;

    auto compiled = compile(policy, abi, proxy_port);
    if (!compiled) return "ruleset compilation failed: " + compiled.error();
    if (policy.is_unconfined()) return {};  // nothing to enforce, by design

    const char* err = nullptr;
    // Safe to mint here: apply() is the single-threaded, allocating entry
    // point, so it is standing in for a child that has already forked.
    if (apply_compiled(ForkBoundary::in_child(), compiled.value(), abi, &err)) {
        return {};
    }
    // Allocation is fine here: this overload is for single-threaded callers.
    return std::string{err ? err : "landlock apply failed"} + ": " +
           std::strerror(errno);
}

BackendCaps probe() {
    BackendCaps c;
    c.name = "landlock";
    AbiInfo abi = probe_abi();
    c.fs_path_authority = abi.version >= 1;
    c.net_egress_filter = abi.has_net_tcp;  // by PORT; per-host needs the T3 broker
    c.device_control = abi.has_ioctl_dev;
    // T3's process half. Probed at runtime, never assumed: hardened distros
    // disable unprivileged user namespaces, and bastion itself may be running
    // inside a container that forbids nesting.
    {
        const auto ns = linux_ns::probe();
        c.namespace_isolation = ns.available && ns.pid;
    }
    c.requires_setuid = false;      // unprivileged by design
    // T3 (brokered per-host egress) needs ABI v4+ to pin outbound to the
    // broker port. Without it we can only promise T2, and say so.
    if (!c.fs_path_authority) {
        c.max_tier = Tier::Advisory;
    } else if (abi.has_net_tcp) {
        c.max_tier = Tier::Isolate;
    } else {
        c.max_tier = Tier::Kernel;
    }
    c.version_note = abi.note;
    if (c.fs_path_authority && !abi.has_net_tcp) {
        c.version_note += " (no network mediation; T3 needs ABI v4+/kernel 6.7)";
    }
    return c;
}

#else  // no Landlock headers / not Linux

AbiInfo probe_abi() {
    AbiInfo i;
    i.version = -1;
    i.note = "built without <linux/landlock.h>";
    return i;
}

std::size_t AbiCore::ruleset_attr_size() const noexcept { return 0; }

Ruleset compile(const Sealed&, const AbiInfo& abi, std::uint16_t) {
    Ruleset rs;
    rs.error = abi.note;
    return rs;
}

std::string apply(const Sealed&, std::uint16_t) {
    return "Landlock backend not compiled in";
}

const std::string& private_tmp_dir() {
    static const std::string none;  // nothing granted, so nothing to point at
    return none;
}

BackendCaps probe() {
    BackendCaps c;
    c.name = "landlock";
    c.max_tier = Tier::Advisory;
    c.version_note = "not compiled in";
    return c;
}

#endif

}  // namespace bastion::linux_ll
