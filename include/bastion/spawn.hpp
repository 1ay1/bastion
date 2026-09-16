// bastion/spawn.hpp — the Spawned typestate: run a process under a Sealed policy.
//
//     Policy  --seal()-->  Sealed  --spawn()-->  Spawned
#pragma once

#include "bastion/policy.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace bastion {

// Resource ceilings applied to the child (setrlimit(2), so they are inherited
// by the whole subtree and cannot be raised back -- lowering the HARD limit is
// irreversible for an unprivileged process).
//
// WHY: "resource exhaustion" was listed as out of scope, with the honest note
// that a confined process "can fork-bomb or fill the disk within its granted
// paths". MEASURED: a T2 child spawned 200 processes unimpeded. A sandbox that
// stops an agent reading ~/.ssh but lets it wedge the machine has stopped the
// interesting attack and left the boring one.
//
// OFF BY DEFAULT. A limit that fires during a legitimate build is exactly the
// friction that gets sandboxes switched off (DESIGN.md §4), and the right
// ceiling is workload-specific -- a Rust build legitimately wants hundreds of
// processes. So this is opt-in and the defaults below are generous.
struct ResourceLimits {
    // Max processes/threads for the child's real uid. 0 = leave alone.
    //
    // READ THIS BEFORE PICKING A NUMBER. RLIMIT_NPROC is not what its name
    // suggests: the kernel counts every THREAD already owned by the real uid,
    // SYSTEM-WIDE, not the processes inside this sandbox. MEASURED on a normal
    // desktop session: 113 processes but 787 threads for uid 1000 -- so
    // --max-procs 512 made `cc` fail to fork immediately, while the same build
    // succeeded uncapped and at 4000.
    //
    // So this is a BACKSTOP against a runaway fork bomb, not a tight budget:
    // set it above your session's current thread count
    // (`ps -u $(id -u) -L --no-headers | wc -l`) plus headroom. A tight value
    // does not confine the workload, it just breaks it.
    //
    // A true per-sandbox process budget needs a cgroup (pids.max), which needs
    // either cgroup-v2 delegation or systemd-run; that is a bigger change and
    // is not done here.
    unsigned max_processes = 0;

    // Max size of any file the child creates, in bytes. 0 = leave alone.
    // Caps "fill the disk", which granted write paths otherwise permit.
    unsigned long long max_file_bytes = 0;

    // Max CPU seconds. 0 = leave alone. Catches runaway loops; the child gets
    // SIGXCPU, so it dies visibly rather than hanging a CI job forever.
    unsigned max_cpu_seconds = 0;

    // Max core dump size. Defaults to 0 = no cores: a crashing confined
    // process should not scatter memory images (which may hold secrets read
    // from granted paths) into the workspace.
    bool allow_core_dumps = false;

    [[nodiscard]] bool any() const noexcept {
        return max_processes || max_file_bytes || max_cpu_seconds;
    }
};

struct SpawnRequest {
    std::vector<std::string> argv;
    std::optional<std::string> cwd;   // defaults to the CURRENT directory:
                                      // path-set authority means any cwd works,
                                      // so there is no fixed sandbox root.
    std::vector<std::string> env;     // "K=V"; if empty, a sanitized env is built
    bool inherit_env = false;

    ResourceLimits limits;            // opt-in; see above

    // When false, spawn() returns as soon as the child is running instead of
    // waiting for it. Required by T0 observation: audit records must be drained
    // and attributed WHILE the subtree is alive, because getpgid() cannot
    // resolve a process that has already exited.
    bool wait = true;
};

struct EgressAttempt;  // proxy.hpp

struct SpawnResult {
    int exit_code = -1;
    bool signalled = false;
    int signal_number = 0;
    std::string error;                     // non-empty => failed to launch
    std::vector<std::string> warnings;     // rights not enforceable here
    std::string profile;                   // exact policy applied, for auditing
    int pid = -1;                          // child pid
    int pgid = -1;                         // child process GROUP (== pid)

    // Which of BASTION'S OWN setup steps failed in the child, reported over a
    // CLOEXEC status pipe: 0 = none (the workload really exec'd), 1 = chdir,
    // 2 = sandbox apply, 3 = exec. Never inferred from the exit code, because
    // a shell produces 126/127 itself when a confined exec is denied -- which
    // made a correctly BLOCKED attack look like a bastion failure.
    unsigned char setup_stage = 0;

    // T3 egress broker results. Populated when the policy is T3+ and carries
    // network rules; these feed the audit ledger and `bastion synthesize`.
    std::uint16_t proxy_port = 0;
    std::uint64_t egress_allowed = 0;
    std::uint64_t egress_denied = 0;
    std::vector<std::pair<std::string, bool>> egress_attempts;  // host:port, allowed

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
//
// At T3 with egress rules, spawn() owns an EgressProxy for the duration of the
// run and pins the kernel policy to its port. Inspect it through
// SpawnResult::egress_attempts / egress_allowed / egress_denied — passing your
// own proxy in is deliberately not supported, because the port the child is
// authorized to reach and the port the broker listens on must be the same by
// construction, not by convention.
[[nodiscard]] SpawnResult spawn(const Sealed& policy, const SpawnRequest& req);

// Wait for a child previously started with `wait = false`, filling in the exit
// status fields of `result`.
void spawn_wait(SpawnResult& result);

// Build a sanitized environment that satisfies the ergonomic floor (DESIGN.md
// §4): TMPDIR inside a writable location, toolchain caches, a coherent PATH.
// Secrets in the ambient environment are dropped unless explicitly passed.
[[nodiscard]] std::vector<std::string> sanitized_env(const Sealed& policy);

}  // namespace bastion
