// bastion/backend/seccomp_notify.hpp — Linux T0 observation.
//
// WHY THIS EXISTS
// Observation is what makes `--yolo` an ON-RAMP rather than a dead end
// (DESIGN.md §1): a wide-open run is still fully recorded, so `bastion
// synthesize` can propose the minimal policy that would have sufficed. Without
// an observation source that story collapses -- the synthesizer sees only
// process spawns and would emit a policy derived from nothing.
//
// macOS gets this from Seatbelt's `(with report)` plus the unified log. Linux
// had nothing, so `bastion observe` failed outright and `synthesize` correctly
// refused to guess. This closes that gap.
//
// MECHANISM: seccomp user-notification (SECCOMP_FILTER_FLAG_NEW_LISTENER).
// The child installs a filter that traps the syscalls we care about and passes
// the listener fd back over SCM_RIGHTS; bastion reads each notification, records
// the access, and answers SECCOMP_USER_NOTIF_FLAG_CONTINUE so the syscall runs
// for real.
//
// Why this and not the alternatives:
//   - Landlock audit needs ABI v7+ (kernel 6.15) and only reports DENIALS, so
//     it cannot see what an unconfined workload legitimately used.
//   - eBPF needs CAP_BPF/root. bastion refuses to ask for privileges.
//   - ptrace stops every syscall in both directions and does not compose with
//     a workload that uses ptrace itself (debuggers, sanitizers).
// seccomp user-notify is the only one that is unprivileged AND complete.
//
// MEASURED on kernel 7.2.2-zen1, uid 1000, via tools/probe/seccomp_notify_probe.c:
//   [1] unprivileged NEW_LISTENER install : OK
//   [2] filter survives execve            : YES  (grandchildren are covered)
//   [3] read path from stopped process    : YES  (process_vm_readv)
//   [4] CONTINUE lets syscalls proceed    : YES  (workload exit 0, unchanged)
//
// [2] and [4] are the load-bearing ones. [2] means `sh -c 'cat /etc/hosts'` is
// observed even though `cat` is a grandchild that lives for microseconds --
// the exact case the macOS backend needs a pid-window heuristic to recover.
// Here the kernel tells us the pid, so attribution is EXACT, not inferred.
#pragma once

#include "bastion/observe.hpp"

namespace bastion::linux_seccomp {

// Runtime probe. Never inferred from build flags: a kernel can be built without
// CONFIG_SECCOMP_FILTER, and some hardening profiles remove `user_notif` from
// /proc/sys/kernel/seccomp/actions_avail.
[[nodiscard]] ObserveCaps probe();

// Run argv under FULL access with every interesting syscall reported.
// Enforces NOTHING -- that is the point of T0.
[[nodiscard]] ObserveResult observe(const SpawnRequest& req);

}  // namespace bastion::linux_seccomp
