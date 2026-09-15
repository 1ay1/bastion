// bastion/backend/landlock.hpp — Linux Landlock LSM backend (T2).
//
// This is the mechanism that makes "run in any working directory" free
// (DESIGN.md §3): Landlock answers the question an agent sandbox actually asks
// -- "which paths may be read and written?" -- directly, with no mount
// namespace, no topology rewrite, no setuid, and no privilege. The ruleset is
// derived from the real CWD at spawn time, so there is nothing to rebuild and
// nothing to freeze into a fixed $HOME/sandbox.
//
// ABI COMPATIBILITY is the whole difficulty here. Landlock gains access rights
// with each ABI version, and `landlock_create_ruleset` FAILS (EINVAL) if the
// handled-rights mask contains a bit the running kernel does not know. So the
// mask must be clamped to the probed ABI rather than assumed from headers --
// a binary built on a new kernel must still confine correctly on an old one.
#pragma once

#include "bastion/policy.hpp"
#include "bastion/tier.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace bastion::linux_ll {

// Landlock ABI feature levels, from the kernel UAPI header and docs:
//   v1  (5.13) filesystem rights, no REFER -> cross-dir link/rename always denied
//   v2  (5.19) FS_REFER
//   v3  (6.2)  FS_TRUNCATE
//   v4  (6.7)  network TCP bind/connect
//   v5  (6.10) FS_IOCTL_DEV
//   v6  (6.12) scoped abstract-unix/signal
//   v9         FS_RESOLVE_UNIX
//   v10        UDP rights + quiet_* fields; RESTRICT_SELF_NO_NEW_PRIVS
struct AbiInfo {
    int version = -1;              // -1 => Landlock unavailable
    bool has_refer = false;        // v2+
    bool has_truncate = false;     // v3+
    bool has_net_tcp = false;      // v4+
    bool has_ioctl_dev = false;    // v5+
    bool has_scoped = false;       // v6+
    bool has_quiet = false;        // v10+
    std::string note;

    // Byte size of landlock_ruleset_attr to pass for THIS kernel.
    //
    // CRITICAL for portability: the struct grows across ABI versions (it is now
    // 6 x __u64). Passing sizeof() from newer headers to an older kernel is
    // rejected (E2BIG/EINVAL) and would take the entire sandbox with it -- the
    // "built on a new kernel, must still confine on an old one" case. So the
    // size is derived from the PROBED version, never from the headers.
    [[nodiscard]] std::size_t ruleset_attr_size() const noexcept;
};

// Query the running kernel. Never inferred from build-time headers.
[[nodiscard]] AbiInfo probe_abi();

// The per-run private temp dir granted by the ergonomic floor when the user has
// no $TMPDIR of their own, or "" if one could not be created.
//
// Created 0700 and named per-PID. Linux (unlike macOS) usually leaves $TMPDIR
// unset, and granting shared world-readable /tmp instead would leak data
// between agents on the same box -- MEASURED as 6 escapes in the adversarial
// suite. spawn() exports this as the child's TMPDIR/TMP/TEMP, so compile() and
// the child agree on which directory the toolchain should use.
[[nodiscard]] const std::string& private_tmp_dir();

struct Ruleset {
    std::uint64_t handled_fs = 0;    // clamped to the probed ABI
    std::uint64_t handled_net = 0;
    struct PathRule {
        std::string path;
        std::uint64_t allowed = 0;
    };
    std::vector<PathRule> paths;
    struct PortRule {
        std::uint16_t port = 0;
        bool connect = false;
        bool bind = false;
    };
    std::vector<PortRule> ports;
    std::vector<std::string> warnings;
    bool ok = false;
    std::string error;
};

// Translate a Sealed policy into a Landlock ruleset for THIS kernel.
//
// `proxy_port`, when non-zero and the policy is T3+, pins egress to that
// loopback port: it becomes the ONLY permitted TCP connect target, and
// bastion's broker enforces the per-host allowlist there (see proxy.hpp).
// Requires ABI v4+; on older kernels network rules cannot be mediated at all
// and compile() says so in `warnings` rather than pretending.
[[nodiscard]] Ruleset compile(const Sealed& policy, const AbiInfo& abi,
                              std::uint16_t proxy_port = 0);

// Apply to the current thread and its future children. Irreversible.
// Must be called after fork() and before exec(); returns empty on success.
//
// Also sets PR_SET_NO_NEW_PRIVS, without which Landlock refuses to enforce for
// an unprivileged process -- and which independently blocks setuid escalation.
[[nodiscard]] std::string apply(const Sealed& policy,
                                std::uint16_t proxy_port = 0);

[[nodiscard]] BackendCaps probe();

}  // namespace bastion::linux_ll
