#include "bastion/backend/landlock.hpp"

#if defined(__linux__)
#  include <fcntl.h>
#  include <sys/prctl.h>
#  include <sys/syscall.h>
#  include <unistd.h>
#  if __has_include(<linux/landlock.h>)
#    include <linux/landlock.h>
#    define BASTION_LANDLOCK_HEADERS 1
#  endif
#endif

#include <cerrno>
#include <cstring>
#include <filesystem>

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

std::size_t AbiInfo::ruleset_attr_size() const noexcept {
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

Ruleset compile(const Sealed& policy, const AbiInfo& abi) {
    Ruleset rs;
    if (abi.version < 0) {
        rs.error = abi.note;
        return rs;
    }

    // Unconfined: no ruleset at all. The audit ledger still records everything
    // (DESIGN.md §1) -- we decline to *enforce*, not to observe.
    if (policy.is_unconfined()) {
        rs.ok = true;
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

    // The ergonomic floor (DESIGN.md §4): without these, toolchains break in
    // ways that look like broken code and burn agent turns.
    static constexpr const char* kBaseRead[] = {
        "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc/ld.so.cache",
        "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives",
        "/etc/localtime", "/proc/self", "/sys/devices/system/cpu",
    };
    for (const char* p : kBaseRead) {
        std::error_code ec;
        if (!std::filesystem::exists(p, ec) || ec) continue;  // distro variance
        rs.paths.push_back({p, kReadRights | kExecRights});
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

    bool net_requested = false;
    for (const auto& r : policy.rules()) {
        if (any(r.right & (Right::NetEgress | Right::NetBind))) {
            net_requested = true;
            std::uint16_t port = parse_port(r.scope);
            if (port == 0) {
                // Landlock filters by PORT, not hostname. Saying so is the
                // point -- see DESIGN.md §6 / `bastion explain`.
                rs.warnings.emplace_back(
                    "net rule '" + r.scope +
                    "' has no usable port; Landlock cannot filter by hostname. "
                    "Use T3 (proxy) for per-host allowlisting.");
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

    if (net_requested && !abi.has_net_tcp) {
        rs.warnings.emplace_back(
            "network rules requested but Landlock ABI <4 cannot mediate "
            "network access; egress is UNRESTRICTED at T2 on this kernel. Use "
            "T3 for network isolation.");
        rs.handled_net = 0;
        rs.ports.clear();
    }

    rs.ok = true;
    return rs;
}

std::string apply(const Sealed& policy) {
    AbiInfo abi = probe_abi();
    if (abi.version < 0) return abi.note;

    Ruleset rs = compile(policy, abi);
    if (!rs.ok) return "ruleset compilation failed: " + rs.error;
    if (policy.is_unconfined()) return {};  // nothing to enforce, by design

    // NO_NEW_PRIVS is mandatory: landlock_restrict_self fails with EPERM
    // without it for an unprivileged process. It also independently prevents
    // setuid binaries from regaining privilege inside the sandbox -- which is
    // the exact class of hole that makes firejail's setuid-root design unsafe
    // (DESIGN.md §3.1).
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return std::string{"prctl(PR_SET_NO_NEW_PRIVS) failed: "} +
               std::strerror(errno);
    }

    struct landlock_ruleset_attr attr {};
    attr.handled_access_fs = rs.handled_fs;
#  if defined(LANDLOCK_ACCESS_NET_CONNECT_TCP)
    attr.handled_access_net = rs.handled_net;
#  endif

    // Pass the ABI-appropriate size, not sizeof() (see AbiInfo::ruleset_attr_size).
    int fd = ll_create_ruleset(&attr, abi.ruleset_attr_size(), 0);
    if (fd < 0) {
        return std::string{"landlock_create_ruleset failed: "} +
               std::strerror(errno);
    }

    for (const auto& p : rs.paths) {
        int pfd = ::open(p.path.c_str(), O_PATH | O_CLOEXEC);
        if (pfd < 0) continue;  // vanished between compile and apply; skip
        struct landlock_path_beneath_attr pb {};
        pb.parent_fd = pfd;
        // Mask to the handled set: a rule may not grant a right the ruleset
        // does not handle (EINVAL), and this also clamps to the probed ABI.
        pb.allowed_access = p.allowed & rs.handled_fs;
        int rc = ll_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
        ::close(pfd);
        if (rc != 0) {
            ::close(fd);
            return "landlock_add_rule failed for " + p.path + ": " +
                   std::strerror(errno);
        }
    }

#  if defined(LANDLOCK_RULE_NET_PORT)
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
            return "landlock_add_rule(net) failed: " + std::string{std::strerror(errno)};
        }
    }
#  endif

    if (ll_restrict_self(fd, 0) != 0) {
        ::close(fd);
        return std::string{"landlock_restrict_self failed: "} + std::strerror(errno);
    }
    ::close(fd);
    return {};
}

BackendCaps probe() {
    BackendCaps c;
    c.name = "landlock";
    AbiInfo abi = probe_abi();
    c.fs_path_authority = abi.version >= 1;
    c.net_egress_filter = abi.has_net_tcp;  // by PORT only, not hostname
    c.device_control = abi.has_ioctl_dev;
    c.namespace_isolation = false;  // that is T3's job
    c.requires_setuid = false;      // unprivileged by design
    c.max_tier = c.fs_path_authority ? Tier::Kernel : Tier::Advisory;
    c.version_note = abi.note;
    return c;
}

#else  // no Landlock headers / not Linux

AbiInfo probe_abi() {
    AbiInfo i;
    i.version = -1;
    i.note = "built without <linux/landlock.h>";
    return i;
}

std::size_t AbiInfo::ruleset_attr_size() const noexcept { return 0; }

Ruleset compile(const Sealed&, const AbiInfo& abi) {
    Ruleset rs;
    rs.error = abi.note;
    return rs;
}

std::string apply(const Sealed&) {
    return "Landlock backend not compiled in";
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
