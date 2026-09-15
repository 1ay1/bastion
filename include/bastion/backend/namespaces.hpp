// bastion/backend/namespaces.hpp — the other half of T3.
//
// T3 is defined in tier.hpp as "Kernel + user/net/pid/ipc namespaces". The
// egress broker delivered the network half; this delivers the process half.
//
// WHY IT MATTERS
// Until now "enumerate host processes" was the one escape the adversarial suite
// reported as a DOCUMENTED LIMIT rather than a block:
//
//     [LIMIT] enumerate host processes
//             -> T2/T3 have no PID namespace; process listing is visible.
//
// That is a real leak. `ps aux` inside the sandbox shows every process on the
// box: other agents' command lines (which routinely carry tokens and repo
// paths), what the user is running, and enough structure to target the rest of
// the machine. Neither Landlock nor Seatbelt can mediate it -- it is not a
// filesystem or network operation.
//
// MECHANISM: unprivileged user + PID + IPC namespaces (CLONE_NEWUSER wins the
// privilege to create the others), then a fresh /proc mount inside a mount
// namespace so the PID namespace is actually observable.
//
// UNPRIVILEGED BY DESIGN. bastion never asks for root or setuid, so we take the
// user-namespace route and accept its constraints (uid mapping via
// /proc/self/uid_map, setgroups denied first). Where the kernel forbids it --
// some hardened distros set user.max_user_namespaces=0 or
// kernel.unprivileged_userns_clone=0 -- we DEGRADE HONESTLY: the workload still
// runs with the full T2/T3 kernel boundary, and the lost capability is
// reported, never silently assumed.
#pragma once

#include <string>

namespace bastion::linux_ns {

struct NsCaps {
    bool available = false;    // can we create a user namespace unprivileged?
    bool pid = false;          // ... and a PID namespace within it?
    bool mount = false;        // ... and remount /proc, so PIDs are hidden?
    std::string reason;        // why not, when unavailable
};

// Runtime probe. Never inferred from build flags: availability depends on
// sysctls and on the container/seccomp profile bastion itself runs under.
[[nodiscard]] NsCaps probe();

// Enter new user/PID/IPC namespaces in the CURRENT process.
//
// Must be called in the child, BEFORE the sandbox is applied and before exec.
// Returns empty on success, else an error message.
//
// IMPORTANT: unshare(CLONE_NEWPID) does not move the caller into the new PID
// namespace -- only its children get pid 1. The caller must fork() afterwards;
// enter_namespaces() therefore does that fork itself and returns only in the
// grandchild, so callers can treat it as "after this, I am isolated".
[[nodiscard]] std::string enter_namespaces();

}  // namespace bastion::linux_ns
