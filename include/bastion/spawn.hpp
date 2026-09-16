// bastion/spawn.hpp — the Spawned typestate: run a process under a Sealed policy.
//
//     Policy  --seal()-->  Sealed  --spawn()-->  Spawned
#pragma once

#include "bastion/policy.hpp"
// Pulled in so a caller using `wait = false` can hold a SignalForwarder over
// the detached window without hunting for a second header -- the advice on
// SpawnRequest::wait would otherwise not compile as written.
#include "bastion/signal_forward.hpp"

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
    // Max processes for the sandbox. 0 = leave alone.
    //
    // TWO MECHANISMS, and which one you get changes the MEANING:
    //
    //   cgroup v2 (preferred) -- pids.max on a cgroup containing only this
    //     sandbox. A true per-sandbox budget: `--max-procs 20` means twenty
    //     processes HERE, regardless of what else the user is running.
    //
    //   setrlimit (fallback) -- RLIMIT_NPROC, which is not what its name
    //     suggests: the kernel counts every THREAD already owned by the real
    //     uid SYSTEM-WIDE. MEASURED on an ordinary desktop: 113 processes but
    //     787 threads, so `--max-procs 512` made `cc` fail its first fork
    //     while the same build succeeded uncapped. A fork-bomb backstop only;
    //     set it above your session's thread count, not to a tight budget.
    //
    // spawn() reports which one was used, so a number that behaves oddly can
    // be explained rather than just disbelieved.
    unsigned max_processes = 0;

    // Max resident memory for the WHOLE sandbox, in bytes. 0 = unlimited.
    //
    // cgroup-only: there is no rlimit that means this. RLIMIT_AS caps virtual
    // address space, which modern allocators and sanitizers reserve lavishly,
    // so capping it breaks working programs long before it stops a leak.
    // Ignored (with a warning) when no delegated cgroup is available.
    unsigned long long max_memory_bytes = 0;

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
        return max_processes || max_file_bytes || max_cpu_seconds ||
               max_memory_bytes;
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
    //
    // THE CALLER THEN OWNS SIGNAL FORWARDING. spawn() arms a SignalForwarder
    // so that killing bastion takes the child's whole process group with it,
    // but that forwarder is scoped to the call -- returning early tears it
    // down, leaving the detached child unprotected until the caller waits.
    // A caller using this MUST hold its own bastion::SignalForwarder over the
    // window, or an agent harness killing bastion mid-run orphans the subtree
    // (see signal_forward.hpp for why that is a confinement problem, not just
    // untidiness).
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
//
// Does NOT forward signals: spawn()'s forwarder was torn down when it returned
// early, so between that return and this call the child subtree is unprotected.
// Hold a bastion::SignalForwarder{result.pgid} across that window (see
// SpawnRequest::wait), or a harness killing bastion orphans the subtree.
void spawn_wait(SpawnResult& result);

// Build a sanitized environment that satisfies the ergonomic floor (DESIGN.md
// §4): TMPDIR inside a writable location, toolchain caches, a coherent PATH.
// Secrets in the ambient environment are dropped unless explicitly passed.
[[nodiscard]] std::vector<std::string> sanitized_env(const Sealed& policy);

// The directories the child's PATH will contain, vetted for safety.
//
// Derived from the user's own $PATH rather than a hardcoded list, because
// toolchains no longer live in /usr: webinstall.dev, pipx, cargo/go install,
// and the mise/asdf/pyenv shim directories all use per-user prefixes that
// cannot be enumerated in advance. Entries that are relative, missing, or
// world-writable-and-not-ours are dropped -- a PATH entry is an EXEC grant,
// so it has to be vetted like one.
//
// The backend grants read+exec on these, so a command that RESOLVES here can
// also RUN. Exposed for that reason: resolution and enforcement must agree, or
// the sandbox finds a binary it then refuses to execute.
[[nodiscard]] const std::vector<std::string>& sandbox_path_dirs();

}  // namespace bastion
