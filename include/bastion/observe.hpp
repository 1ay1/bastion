// bastion/observe.hpp — T0/observation: learn what a workload ACTUALLY touches.
//
// This is what makes `--yolo` an on-ramp instead of a dead end. Without a real
// observation source, `bastion synthesize` can only see process spawns, and
// happily reports "no grants needed" for a workload that read /etc/hosts and
// wrote /tmp -- a confident, wrong answer that is worse than no answer at all.
//
// macOS: Seatbelt's `(allow default (with report))` makes the kernel emit an
// audit line per access decision, which we read back from the unified log.
// Measured unprivileged on macOS 26.6.2 -- no root, no fs_usage, no dtrace
// (both of those require privileges we refuse to ask for):
//
//   Sandbox: obs(94613) allow file-read-data  /private/etc/hosts
//   Sandbox: obs(94613) allow file-write-create /private/tmp/obs-probe.txt
//
// Paths arrive already canonicalized by the kernel, which is exactly what the
// policy layer wants (DESIGN.md §2.1).
#pragma once

#include "bastion/ledger.hpp"
#include "bastion/policy.hpp"
#include "bastion/spawn.hpp"

#include <string>
#include <vector>

namespace bastion {

// Why observation is or is not possible on this machine. Reported honestly:
// a synthesizer that cannot see must say so rather than emit an empty policy.
struct ObserveCaps {
    bool available = false;
    std::string mechanism;   // "seatbelt-report+unified-log", "landlock-audit", ...
    std::string reason;      // when unavailable, why
    bool needs_privileges = false;
};

[[nodiscard]] ObserveCaps observe_probe();

struct ObserveResult {
    std::vector<AuditRecord> records;
    int exit_code = -1;
    std::string error;
    std::vector<std::string> warnings;
    std::size_t dropped = 0;  // log lines we could not attribute

    [[nodiscard]] bool ok() const noexcept { return error.empty(); }
};

// Run a command under FULL access but with kernel reporting enabled, and
// collect every access it performed.
//
// This is the T0 tier: no enforcement, complete observation. It is how a user
// goes from "just let it run" to a least-privilege policy without ever having
// to guess.
[[nodiscard]] ObserveResult observe(const SpawnRequest& req);

}  // namespace bastion
