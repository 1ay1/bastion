// bastion/spawn.hpp — the Spawned typestate: run a process under a Sealed policy.
//
//     Policy  --seal()-->  Sealed  --spawn()-->  Spawned
#pragma once

#include "bastion/policy.hpp"

#include <optional>
#include <string>
#include <vector>

namespace bastion {

struct SpawnRequest {
    std::vector<std::string> argv;
    std::optional<std::string> cwd;   // defaults to the CURRENT directory:
                                      // path-set authority means any cwd works,
                                      // so there is no fixed sandbox root.
    std::vector<std::string> env;     // "K=V"; if empty, a sanitized env is built
    bool inherit_env = false;
};

struct SpawnResult {
    int exit_code = -1;
    bool signalled = false;
    int signal_number = 0;
    std::string error;                     // non-empty => failed to launch
    std::vector<std::string> warnings;     // rights not enforceable here
    std::string profile;                   // exact policy applied, for auditing

    [[nodiscard]] bool launched() const noexcept { return error.empty(); }
};

// Run argv under the policy, wait, and return the outcome.
//
// SECURITY — the ordering in the child is load-bearing:
//   1. fork()
//   2. chdir()                    (before confinement, so cwd is reachable)
//   3. apply the kernel policy    (irreversible)
//   4. exec()
// Confinement must land AFTER fork and BEFORE exec: applying it in the parent
// would confine bastion itself, and applying it after exec is impossible. If
// step 3 fails we _exit() immediately with a distinguished code rather than
// exec'ing unconfined — a failed sandbox must never degrade to no sandbox.
[[nodiscard]] SpawnResult spawn(const Sealed& policy, const SpawnRequest& req);

// Build a sanitized environment that satisfies the ergonomic floor (DESIGN.md
// §4): TMPDIR inside a writable location, toolchain caches, a coherent PATH.
// Secrets in the ambient environment are dropped unless explicitly passed.
[[nodiscard]] std::vector<std::string> sanitized_env(const Sealed& policy);

}  // namespace bastion
