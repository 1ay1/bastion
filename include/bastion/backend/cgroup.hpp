// bastion/backend/cgroup.hpp — a real PER-SANDBOX resource budget (Linux).
//
// WHY THIS EXISTS
// `--max-procs` is implemented with setrlimit(RLIMIT_NPROC), and that call does
// not mean what its name suggests: the kernel counts every THREAD already owned
// by the real uid SYSTEM-WIDE. MEASURED on an ordinary desktop session: 113
// processes but 787 threads, so `--max-procs 512` made `cc` fail its very first
// fork while the same build succeeded uncapped. It is a fork-bomb backstop, not
// a budget, and the security model says so.
//
// cgroup v2 is the primitive that actually expresses "THIS sandbox may have N
// processes and M bytes of memory": the limit applies to a subtree we create,
// counts only processes we put in it, and is enforced by the kernel rather than
// by an inherited rlimit the workload shares with the user's whole session.
//
// UNPRIVILEGED, via systemd's cgroup delegation. MEASURED on kernel 7.2.2 with
// systemd, uid 1000:
//
//   /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service
//     owner=ayush, controllers = cpu memory pids, subtree_control = cpu memory pids
//
//   $ mkdir .../user@1000.service/bastion-probe.scope   -> OK
//   $ echo 20 > .../bastion-probe.scope/pids.max        -> OK
//   $ <fork bomb inside it>                             -> capped at 20
//   $ cat .../pids.events                               -> max 2
//
// THE SUBTLETY THAT COSTS AN HOUR: you cannot create the sandbox cgroup inside
// your CURRENT cgroup. A terminal's scope is `cgroup.type = domain threaded`,
// and a threaded cgroup cannot enable domain controllers -- the write to
// cgroup.subtree_control fails SILENTLY (no error, controllers simply never
// appear), and the child cgroup then has no pids.max to write at all. So we
// walk UP to the delegation root (the first ancestor we own that is a plain
// domain) and create the sandbox cgroup there.
//
// Degrades honestly. No cgroup2, no delegation, a non-systemd box, or a
// container that hides /sys/fs/cgroup: bastion reports the loss and falls back
// to the setrlimit ceilings. A resource budget is a mitigation, not a boundary,
// so losing it must never turn into refusing to run.
#pragma once

#include <string>

namespace bastion::linux_cgroup {

struct CgroupCaps {
    bool available = false;  // can we create a delegated cgroup at all?
    bool pids = false;       // ... with the pids controller?
    bool memory = false;     // ... with the memory controller?
    std::string root;        // delegation root we would create under
    std::string reason;      // why not, when unavailable
};

// Runtime probe. Never inferred from the presence of /sys/fs/cgroup: the mount
// existing says nothing about whether THIS user may create a subtree in it.
[[nodiscard]] CgroupCaps probe();

// A cgroup that lives as long as the sandbox and takes its processes with it.
class Cgroup {
public:
    // Create a sandbox cgroup with the given ceilings (0 = unlimited).
    // Returns an empty optional-like object (valid() == false) on failure;
    // check error() for why.
    static Cgroup create(unsigned max_processes, unsigned long long max_memory_bytes);

    Cgroup() = default;
    Cgroup(const Cgroup&) = delete;
    Cgroup& operator=(const Cgroup&) = delete;
    Cgroup(Cgroup&&) noexcept;
    Cgroup& operator=(Cgroup&&) noexcept;
    ~Cgroup();

    [[nodiscard]] bool valid() const noexcept { return !path_.empty(); }
    [[nodiscard]] const std::string& error() const noexcept { return error_; }
    [[nodiscard]] const std::string& path() const noexcept { return path_; }

    // Move a pid into this cgroup. Called from the PARENT after fork, because
    // the child is confined moments later and would no longer be able to write
    // to /sys/fs/cgroup itself. Returns empty on success.
    [[nodiscard]] std::string add_process(int pid) const;

    // Did the kernel actually refuse anything? Reads pids.events / memory.events
    // so a hit is REPORTED rather than surfacing only as a mysterious
    // "fork: Resource temporarily unavailable" from the workload.
    [[nodiscard]] unsigned long long pids_max_hits() const;
    [[nodiscard]] unsigned long long memory_max_hits() const;
    [[nodiscard]] unsigned long long peak_pids() const;

private:
    std::string path_;
    std::string error_;
};

}  // namespace bastion::linux_cgroup
