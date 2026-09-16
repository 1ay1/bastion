// bastion/signal_forward.hpp — kill the SUBTREE, not just bastion.
//
// WHY THIS EXISTS
// MEASURED: `kill -TERM` on bastion left SIX orphaned processes running -- the
// workload and everything it had spawned.
//
// This matters specifically for agents. Harnesses run commands with a timeout
// and kill them when it expires; an agent that runs a dev server, a watcher, or
// a hung test then leaks a process tree per attempt until the machine is full.
// It is also a confinement question rather than mere hygiene: an orphan still
// holds every path the policy granted, and the supervisor that was accounting
// for it is gone -- so nothing observes it and `bastion synthesize` never sees
// what it did.
//
// Both supervisors need this. `run` waits in spawn(); `observe` has its OWN
// wait loop in the seccomp backend, and MEASURED separately, it leaked four
// processes with the identical bug. Shared here so a fix to one is a fix to
// both -- duplicating it is how they drift apart again.
//
// Every child bastion spawns is put in its own process group (setpgid in the
// child, mirrored in the parent to close the race), so the whole subtree --
// grandchildren included -- is signalled as one unit. That group is why this is
// a few lines rather than a process-tree walk racing against fork().
#pragma once

#include <sys/types.h>

namespace bastion {

// Forwards termination signals to a child's process group for as long as it is
// alive, restoring the previous handlers on destruction (so a library embedding
// bastion does not inherit our disposition).
//
// Handles SIGTERM, SIGINT, SIGHUP and SIGQUIT. SIGHUP is deliberate: an agent
// harness closing its pty must not leave the subtree running detached.
class SignalForwarder {
public:
    explicit SignalForwarder(pid_t child_pgid) noexcept;
    ~SignalForwarder();

    SignalForwarder(const SignalForwarder&) = delete;
    SignalForwarder& operator=(const SignalForwarder&) = delete;
};

}  // namespace bastion
