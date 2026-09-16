// bastion/tier.hpp — enforcement tiers and the backend contract.
//
// The central invariant (DESIGN.md §1):
//
//     Lowering a tier never lowers observability.
//
// Policy evaluation, violation attribution, and audit records are produced by
// the SAME code path at every tier — including T0 (no enforcement) and including
// a total Unconfined grant. "Easier flow" therefore never degrades into
// "you're on your own".
#pragma once

#include "bastion/capability.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bastion {

// ---------------------------------------------------------------------------
// Tiers
// ---------------------------------------------------------------------------

enum class Tier {
    Observe = 0,    // no enforcement; full policy eval + audit (dry run, CI)
    Advisory = 1,   // in-process interposition; deny + log (best effort)
    Kernel = 2,     // Landlock / Seatbelt / AppContainer+WFP  <-- default
    Isolate = 3,    // Kernel + user/net/pid/ipc namespaces, /tmp instance
    Virtualize = 4, // microVM / Hyper-V / Virtualization.framework
};

constexpr std::string_view tier_name(Tier t) noexcept {
    switch (t) {
        case Tier::Observe:    return "T0:observe";
        case Tier::Advisory:   return "T1:advisory";
        case Tier::Kernel:     return "T2:kernel";
        case Tier::Isolate:    return "T3:isolate";
        case Tier::Virtualize: return "T4:virtualize";
    }
    return "unknown";
}

// Honest about what a tier actually defends against. `bastion explain` prints
// this — the antidote to "the diff from bwrap to firejail is hair raising".
constexpr std::string_view tier_guarantee(Tier t) noexcept {
    switch (t) {
        case Tier::Observe:
            return "No enforcement. Records what WOULD be denied. Not a boundary.";
        case Tier::Advisory:
            return "Best-effort, in-process. Stops accidents, not a motivated "
                   "adversary: native code can bypass it.";
        case Tier::Kernel:
            // "No network isolation" was WRONG and actively misleading: on
            // Linux the kernel denies ALL egress at T2 unless a port rule is
            // granted. Measured -- curl exits 7 under a plain `bastion run`.
            // Saying the opposite sent users hunting a network fault. What T2
            // lacks is per-HOST filtering, which needs the T3 broker.
            return "Kernel-enforced path-set authority. Survives arbitrary "
                   "native code in the target. Egress is all-or-nothing: "
                   "denied unless granted, and not filterable by host (use "
                   "T3 for that).";
        case Tier::Isolate:
            return "Kernel enforcement + namespace isolation (net/pid/ipc, "
                   "instanced /tmp). Unprivileged; no setuid component.";
        case Tier::Virtualize:
            return "Separate kernel. Strongest boundary; highest cost.";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// Verdicts and audit records
// ---------------------------------------------------------------------------

enum class Verdict { Allow, Deny, WouldDeny };  // WouldDeny == T0/T1 shadow mode

struct Remedy {
    std::string grant;                  // "FsWrite(/etc/hosts)"
    std::string cmd;                    // "bastion grant fs.write /etc/hosts"
    std::string sanctioned_alternative; // "write under $WORKSPACE or $TMPDIR"
};

// Emitted on every denial, in-band, machine-readable. This is what replaces a
// hand-written AGENTS.md describing the sandbox (DESIGN.md §4.1): the agent is
// told what was refused, why, and what the legitimate move is.
struct AuditRecord {
    Verdict verdict{};
    std::string op;      // "fs.write", "net.egress", "device.open"
    std::string target;  // path / host:port / device
    Tier tier{};
    std::string rule;    // matched rule, or "default-deny"
    std::string provenance;
    std::optional<Remedy> remedy;

    [[nodiscard]] std::string to_json() const;
};

// ---------------------------------------------------------------------------
// Backend contract
// ---------------------------------------------------------------------------

struct BackendCaps {
    bool fs_path_authority = false;  // can express a path SET natively
    bool net_egress_filter = false;
    bool device_control = false;
    bool namespace_isolation = false;
    bool requires_setuid = false;    // bastion refuses these outright (§3.1)
    Tier max_tier = Tier::Advisory;
    std::string name;
    std::string version_note;
};

class Backend {
public:
    virtual ~Backend() = default;

    // What this backend can actually do on THIS machine, probed at runtime —
    // never assumed from the build configuration.
    [[nodiscard]] virtual BackendCaps probe() const = 0;

    // Preflight: assert the ergonomic floor (DESIGN.md §4) BEFORE the agent
    // runs. Returns the unmet invariants. A non-empty result must block spawn:
    // a sandbox that breaks the toolchain makes agents thrash, and thrashing
    // agents get their sandboxes switched off.
    [[nodiscard]] virtual std::vector<std::string> preflight() const = 0;
};

// What this machine can actually enforce, probed at runtime.
//
// The FIRST question any embedder asks: bastion is linked in, but is it
// usable HERE? A kernel too old for Landlock, a container that forbids
// seccomp, a platform with no backend at all — each answers with a lower
// max_tier rather than a failure at spawn time, so a host can choose a
// different sandbox instead of discovering the gap on the first tool call.
//
// Lived in cli.cpp until agentty needed it. That is the tell for a missing
// API: a host embedding bastion as a library had no way to ask this without
// running the CLI and parsing its stdout, which is both fragile and a
// process spawn for a question answerable in-process.
[[nodiscard]] BackendCaps active_backend();

}  // namespace bastion
