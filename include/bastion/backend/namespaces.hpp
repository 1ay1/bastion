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

#include "bastion/forksafe.hpp"

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
// Returns true on success; on failure `err` receives a STATIC string naming the
// step that failed.
//
// ALLOCATION-FREE, and the ForkChild token makes that checkable rather than
// merely documented (see forksafe.hpp). This runs between fork() and exec() in
// a process that may be multithreaded -- at T3 the egress broker's accept
// thread is live -- where building a std::string can deadlock forever on a
// malloc lock held by a thread that does not exist in the child. An earlier
// version returned std::string here; that was the same latent bug already found
// and fixed in the Landlock path.
//
// IMPORTANT: unshare(CLONE_NEWPID) does not move the caller into the new PID
// namespace -- only its children get pid 1. The caller must fork() afterwards;
// enter_namespaces() therefore does that fork itself and returns only in the
// grandchild, so callers can treat it as "after this, I am isolated".
[[nodiscard]] bool enter_namespaces(ForkChild tok, const char** err) noexcept;

}  // namespace bastion::linux_ns
