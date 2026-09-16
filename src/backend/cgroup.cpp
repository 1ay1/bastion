#include "bastion/backend/cgroup.hpp"

#if defined(__linux__)

#  include <fcntl.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <unistd.h>

#  include <cerrno>
#  include <cstdio>
#  include <cstring>
#  include <filesystem>
#  include <fstream>
#  include <string>

namespace bastion::linux_cgroup {

namespace {

namespace fs = std::filesystem;

constexpr const char* kMount = "/sys/fs/cgroup";

std::string read_first_line(const fs::path& p) {
    std::ifstream in(p);
    std::string line;
    std::getline(in, line);
    return line;
}

bool write_value(const fs::path& p, const std::string& v, std::string* err = nullptr) {
    // Deliberately not std::ofstream: cgroup files need a single write(2) and
    // report failures via errno, which the stream API hides behind failbit.
    const int fd = ::open(p.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        if (err) *err = std::string{p.string()} + ": " + std::strerror(errno);
        return false;
    }
    const ssize_t n = ::write(fd, v.data(), v.size());
    const bool ok = n == static_cast<ssize_t>(v.size());
    if (!ok && err) *err = std::string{p.string()} + ": " + std::strerror(errno);
    ::close(fd);
    return ok;
}

// This process's cgroup path, e.g. "/user.slice/.../app.scope".
std::string current_cgroup() {
    std::ifstream in("/proc/self/cgroup");
    std::string line;
    while (std::getline(in, line)) {
        // cgroup v2 has exactly one line, always "0::<path>".
        if (line.rfind("0::", 0) == 0) return line.substr(3);
    }
    return {};
}

// Read a key from a flat-keyed cgroup file ("max 2\n" style).
unsigned long long read_keyed(const fs::path& p, const char* key) {
    std::ifstream in(p);
    std::string k;
    unsigned long long v = 0;
    while (in >> k >> v) {
        if (k == key) return v;
    }
    return 0;
}

// Walk UP from our own cgroup to the nearest ancestor that we own AND that can
// actually host a resource-limited child.
//
// Two conditions, both learned by measurement:
//   1. we must be able to write cgroup.subtree_control there (delegation), and
//   2. it must NOT be `domain threaded` -- a threaded cgroup silently refuses
//      to enable domain controllers, so a child created under it has no
//      pids.max at all and the whole feature fails with a confusing ENOENT.
// A terminal's own scope is typically threaded, which is exactly why creating
// the sandbox cgroup "right here" does not work.
fs::path find_delegation_root() {
    const std::string mine = current_cgroup();
    if (mine.empty()) return {};

    const uid_t me = ::getuid();
    fs::path p = fs::path{kMount} / fs::path{mine}.relative_path();

    std::error_code ec;
    while (!p.empty() && p != fs::path{kMount}) {
        struct ::stat st {};
        const bool owned = ::stat(p.c_str(), &st) == 0 && st.st_uid == me;
        const bool writable = ::access((p / "cgroup.subtree_control").c_str(), W_OK) == 0;
        const std::string type = read_first_line(p / "cgroup.type");
        // "domain" is fine; "domain threaded" and "threaded" are not.
        const bool domain = type.empty() || type == "domain";

        if (owned && writable && domain) return p;
        p = p.parent_path();
    }
    return {};
}

}  // namespace

CgroupCaps probe() {
    CgroupCaps c;

    std::error_code ec;
    if (!fs::exists(fs::path{kMount} / "cgroup.controllers", ec)) {
        c.reason =
            "cgroup v2 is not mounted at /sys/fs/cgroup (a v1 or hybrid "
            "hierarchy cannot express a per-sandbox budget)";
        return c;
    }

    const fs::path root = find_delegation_root();
    if (root.empty()) {
        c.reason =
            "no delegated cgroup available to this user; a per-sandbox budget "
            "needs systemd-style delegation (user@UID.service). Falling back "
            "to setrlimit ceilings.";
        return c;
    }
    c.root = root.string();

    // What the PARENT makes available to its children is subtree_control;
    // cgroup.controllers is only what the parent itself received.
    const std::string enabled = read_first_line(root / "cgroup.subtree_control");
    const std::string offered = read_first_line(root / "cgroup.controllers");
    const std::string& avail = enabled.empty() ? offered : enabled;

    c.pids = avail.find("pids") != std::string::npos;
    c.memory = avail.find("memory") != std::string::npos;
    c.available = c.pids || c.memory;
    if (!c.available) {
        c.reason = "delegated cgroup offers neither the pids nor the memory "
                   "controller (have: " + avail + ")";
    }
    return c;
}

Cgroup Cgroup::create(unsigned max_processes, unsigned long long max_memory_bytes) {
    Cgroup g;
    const auto caps = probe();
    if (!caps.available) {
        g.error_ = caps.reason;
        return g;
    }

    const fs::path root{caps.root};

    // Reap leftovers from earlier runs that died before their destructor ran
    // (SIGKILL, a crash, a power cut). Each is named after its pid, so one
    // whose pid is gone AND whose cgroup.procs is empty is certainly dead.
    // Without this, an abnormally-terminated bastion leaves a directory behind
    // forever and they accumulate silently in the user's slice.
    {
        std::error_code lec;
        for (const auto& e : fs::directory_iterator(root, lec)) {
            if (lec) break;
            if (!e.is_directory()) continue;
            const std::string name = e.path().filename().string();
            if (name.rfind("bastion-", 0) != 0) continue;

            // cgroup.procs must be READ, not stat'd: kernel files always
            // report size 0, so file_size() would call every cgroup empty
            // and delete one that is still running a workload.
            if (read_first_line(e.path() / "cgroup.procs").empty()) {
                std::error_code rec;
                fs::remove(e.path(), rec);
            }
        }
    }

    // Ask the parent to expose the controllers we need. Best effort: they are
    // usually already on, and a failure here shows up as a missing pids.max
    // below, which is reported with a better message.
    if (caps.pids) write_value(root / "cgroup.subtree_control", "+pids");
    if (caps.memory) write_value(root / "cgroup.subtree_control", "+memory");

    // Name it after our pid so concurrent bastion runs never collide, and so a
    // leftover directory is traceable to the run that made it.
    const fs::path dir =
        root / ("bastion-" + std::to_string(static_cast<long>(::getpid())) + ".scope");

    std::error_code ec;
    fs::create_directory(dir, ec);
    if (ec && !fs::exists(dir, ec)) {
        g.error_ = "could not create " + dir.string() + ": " + ec.message();
        return g;
    }

    std::string err;
    if (max_processes > 0 && caps.pids) {
        if (!write_value(dir / "pids.max", std::to_string(max_processes), &err)) {
            fs::remove(dir, ec);
            g.error_ = "could not set pids.max: " + err;
            return g;
        }
    }
    if (max_memory_bytes > 0 && caps.memory) {
        if (!write_value(dir / "memory.max", std::to_string(max_memory_bytes), &err)) {
            fs::remove(dir, ec);
            g.error_ = "could not set memory.max: " + err;
            return g;
        }
        // Do NOT let the kernel push the workload into swap to stay under the
        // limit: that turns a clean OOM-kill into an unbounded slowdown, which
        // is far harder to diagnose. Best effort; not all kernels expose it.
        write_value(dir / "memory.swap.max", "0");
    }

    g.path_ = dir.string();
    return g;
}

std::string Cgroup::add_process(int pid) const {
    if (!valid()) return "cgroup not created";
    std::string err;
    if (!write_value(fs::path{path_} / "cgroup.procs", std::to_string(pid), &err)) {
        return "could not move pid " + std::to_string(pid) + " into the cgroup: " + err;
    }
    return {};
}

unsigned long long Cgroup::pids_max_hits() const {
    if (!valid()) return 0;
    return read_keyed(fs::path{path_} / "pids.events", "max");
}

unsigned long long Cgroup::memory_max_hits() const {
    if (!valid()) return 0;
    return read_keyed(fs::path{path_} / "memory.events", "max");
}

unsigned long long Cgroup::peak_pids() const {
    if (!valid()) return 0;
    const std::string v = read_first_line(fs::path{path_} / "pids.peak");
    return v.empty() ? 0 : std::strtoull(v.c_str(), nullptr, 10);
}

Cgroup::Cgroup(Cgroup&& o) noexcept
    : path_(std::move(o.path_)), error_(std::move(o.error_)) {
    o.path_.clear();
}

Cgroup& Cgroup::operator=(Cgroup&& o) noexcept {
    if (this != &o) {
        path_ = std::move(o.path_);
        error_ = std::move(o.error_);
        o.path_.clear();
    }
    return *this;
}

Cgroup::~Cgroup() {
    if (path_.empty()) return;

    // rmdir(2) on a cgroup fails with EBUSY while ANY process is still in it,
    // and the workload's background children routinely outlive the process we
    // waited on -- `sh -c '... &'` returns immediately, leaving `sleep` behind.
    // MEASURED: a single rmdir leaked one empty directory per fork-bomb run.
    //
    // So retry briefly. This is bounded and short: the cgroup is already
    // unreachable (nothing new can join it), the stragglers are exiting, and a
    // leftover directory is a cosmetic leak rather than a safety problem -- so
    // we never block the caller for long over it.
    std::error_code ec;
    for (int attempt = 0; attempt < 50; ++attempt) {
        if (fs::remove(path_, ec)) return;
        ::usleep(20 * 1000);  // 20ms x 50 = 1s worst case
    }
    // Still busy: a process escaped our wait (e.g. a daemonised grandchild).
    // Leave the directory -- it is empty of authority, and a visible remnant
    // is better than silently pretending cleanup succeeded.
}

}  // namespace bastion::linux_cgroup

#else

namespace bastion::linux_cgroup {

CgroupCaps probe() {
    CgroupCaps c;
    c.reason = "cgroups are Linux-only";
    return c;
}

Cgroup Cgroup::create(unsigned, unsigned long long) {
    Cgroup g;
    return g;
}
std::string Cgroup::add_process(int) const { return "not Linux"; }
unsigned long long Cgroup::pids_max_hits() const { return 0; }
unsigned long long Cgroup::memory_max_hits() const { return 0; }
unsigned long long Cgroup::peak_pids() const { return 0; }
Cgroup::Cgroup(Cgroup&&) noexcept = default;
Cgroup& Cgroup::operator=(Cgroup&&) noexcept = default;
Cgroup::~Cgroup() = default;

}  // namespace bastion::linux_cgroup

#endif
