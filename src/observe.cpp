#include "bastion/observe.hpp"

#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <unordered_set>

namespace bastion {

namespace {

// Map a Seatbelt operation name to a bastion op + right.
// Names come from the kernel's own audit lines, e.g. "file-read-data".
struct OpMap {
    std::string_view seatbelt;
    std::string_view op;
};

constexpr OpMap kOps[] = {
    {"file-read-data", "fs.read"},
    {"file-read-metadata", "fs.stat"},     // traversal only; not a real need
    {"file-read-xattr", "fs.stat"},
    {"file-write-data", "fs.write"},
    {"file-write-create", "fs.write"},
    {"file-write-unlink", "fs.write"},
    {"file-write-mode", "fs.write"},
    {"file-write-owner", "fs.write"},
    {"file-write-flags", "fs.write"},
    {"file-write-times", "fs.write"},
    {"file-write-setugid", "fs.write"},
    {"file-write-xattr", "fs.write"},
    {"process-exec", "fs.exec"},
    {"process-exec-interpreter", "fs.exec"},
    {"network-outbound", "net.egress"},
    {"network-inbound", "net.bind"},
    {"network-bind", "net.bind"},
    {"file-ioctl", "device.open"},
};

std::string_view map_op(std::string_view sb) {
    for (const auto& m : kOps) {
        if (m.seatbelt == sb) return m.op;
    }
    return {};
}

// Parse one unified-log line emitted by the Sandbox kernel extension:
//
//  2026-09-15 20:43:37.088 Df kernel[0:2306bd] (Sandbox) Sandbox: obs(94613) \
//      allow file-read-data /private/etc/hosts
//
// Returns false if the line is not an attributable access decision.
bool parse_sandbox_line(std::string_view line, AuditRecord& out,
                        std::string& proc_name, pid_t& out_pid) {
    auto marker = line.find("Sandbox: ");
    if (marker == std::string_view::npos) return false;
    auto rest = line.substr(marker + 9);

    // "<procname>(<pid>) <verdict> <operation> <path...>"
    auto paren = rest.find('(');
    if (paren == std::string_view::npos) return false;
    proc_name = std::string{rest.substr(0, paren)};

    auto close = rest.find(')', paren);
    if (close == std::string_view::npos) return false;
    const std::string pid_s{rest.substr(paren + 1, close - paren - 1)};
    out_pid = static_cast<pid_t>(std::atoi(pid_s.c_str()));

    auto tail = rest.substr(close + 1);
    while (!tail.empty() && tail.front() == ' ') tail.remove_prefix(1);

    // verdict
    std::string_view verdict;
    if (tail.starts_with("allow ")) {
        verdict = "allow";
        tail.remove_prefix(6);
    } else if (tail.starts_with("deny(")) {
        verdict = "deny";
        auto sp = tail.find(' ');
        if (sp == std::string_view::npos) return false;
        tail.remove_prefix(sp + 1);
    } else if (tail.starts_with("deny ")) {
        verdict = "deny";
        tail.remove_prefix(5);
    } else {
        return false;
    }

    auto sp = tail.find(' ');
    if (sp == std::string_view::npos) return false;
    const std::string_view operation = tail.substr(0, sp);
    std::string_view target = tail.substr(sp + 1);
    while (!target.empty() && target.front() == ' ') target.remove_prefix(1);
    if (target.empty()) return false;

    const std::string_view op = map_op(operation);
    if (op.empty()) return false;

    out.verdict = (verdict == "allow") ? Verdict::Allow : Verdict::Deny;
    out.op = std::string{op};
    out.target = std::string{target};
    out.tier = Tier::Observe;
    out.rule = "observed";
    out.provenance = "observed from " + proc_name + "(" + pid_s + ")";
    return true;
}

}  // namespace

#if defined(__APPLE__)

ObserveCaps observe_probe() {
    ObserveCaps c;
    // `log` is present on every macOS install; the Sandbox kext always reports
    // when a profile asks it to. Verified unprivileged on macOS 26.6.2.
    c.available = (::access("/usr/bin/log", X_OK) == 0);
    c.mechanism = "seatbelt-report+unified-log";
    if (!c.available) {
        c.reason = "/usr/bin/log not available";
    }
    return c;
}

ObserveResult observe(const SpawnRequest& req) {
    ObserveResult res;
    auto caps = observe_probe();
    if (!caps.available) {
        res.error = "observation unavailable: " + caps.reason;
        return res;
    }
    if (req.argv.empty()) {
        res.error = "empty argv";
        return res;
    }

    // Full access, but every decision is reported to the unified log.
    // This is T0: we deliberately enforce NOTHING here, so the workload runs
    // exactly as it would unsandboxed and we learn its true requirements.
    auto observe_policy = Policy{Tier::Observe}
                              .allow_report_all("T0 observation")
                              .seal();

    // Start the log reader BEFORE the child so nothing is missed. Filter to the
    // Sandbox sender to keep the stream small.
    //
    // Deliberately NOT popen(): `log stream` never exits, so pclose() blocks
    // forever waiting for it (measured -- this hung the CLI for 90s+ until
    // killed). We fork it ourselves so we can SIGKILL it when done.
    int pipefd[2];
    if (::pipe(pipefd) != 0) {
        res.error = "pipe failed";
        return res;
    }

    const pid_t logger = ::fork();
    if (logger < 0) {
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        res.error = "fork failed for log reader";
        return res;
    }
    if (logger == 0) {
        ::dup2(pipefd[1], STDOUT_FILENO);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDERR_FILENO);
            ::close(devnull);
        }
        ::execl("/usr/bin/log", "log", "stream", "--style", "compact",
                "--predicate",
                "senderImagePath CONTAINS \"Sandbox\"",
                nullptr);
        _exit(127);
    }
    ::close(pipefd[1]);
    const int read_fd = pipefd[0];

    // Give the stream a moment to attach, else the first accesses are lost.
    ::usleep(900 * 1000);

    // Start the workload WITHOUT waiting. Audit records must be attributed
    // while the subtree is still alive: getpgid() cannot resolve a process that
    // has already exited, so a wait-then-drain design loses every short-lived
    // grandchild (which is most of them).
    SpawnRequest run_req = req;
    run_req.wait = false;
    SpawnResult child = spawn(observe_policy, run_req);
    res.exit_code = child.exit_code;
    if (!child.launched()) {
        ::kill(logger, SIGKILL);
        ::waitpid(logger, nullptr, 0);
        ::close(read_fd);
        res.error = child.error;
        return res;
    }

    int flags = ::fcntl(read_fd, F_GETFL, 0);
    ::fcntl(read_fd, F_SETFL, flags | O_NONBLOCK);

    std::unordered_set<pid_t> ours;
    ours.insert(static_cast<pid_t>(child.pid));
    const pid_t want_pgid = static_cast<pid_t>(child.pgid);
    pid_t max_seen_pid = static_cast<pid_t>(child.pid);

    std::string pending;
    auto drain = [&] {
        std::array<char, 8192> chunk{};
        for (;;) {
            ssize_t n = ::read(read_fd, chunk.data(), chunk.size());
            if (n > 0) {
                pending.append(chunk.data(), static_cast<std::size_t>(n));
                continue;
            }
            break;
        }
        // Consume whole lines only; keep any partial tail for the next pass.
        std::size_t start = 0;
        for (;;) {
            auto nl = pending.find('\n', start);
            if (nl == std::string::npos) break;
            std::string_view line{pending.data() + start, nl - start};
            start = nl + 1;

            AuditRecord rec;
            std::string proc;
            pid_t pid = 0;
            if (!parse_sandbox_line(line, rec, proc, pid)) continue;

            // Resolve membership while the process may still exist.
            //
            // A short-lived grandchild is the hard case, and the common one:
            // in `sh -c 'cat /etc/hosts'`, cat gets a NEW pid and exits in
            // microseconds, so by the time we parse its line getpgid() already
            // fails with ESRCH and the read is unattributable. Dropping it lost
            // exactly the grant the user cared about.
            //
            // Three signals, cheapest first:
            //   1. pid already known to be ours (we saw it earlier);
            //   2. pgid still resolves to the workload's process group;
            //   3. pid is UNRESOLVABLE (already exited) but falls inside the
            //      window [child.pid, max seen] -- fork() allocates pids
            //      monotonically, so a dead pid in that range was spawned by
            //      our subtree during this run.
            // (3) is a heuristic, but it is bounded by the run's own pid range
            // and only ever applies to processes that no longer exist.
            const pid_t pgid = (pid > 0) ? ::getpgid(pid) : -1;
            bool mine = ours.contains(pid) || (pgid > 0 && pgid == want_pgid);
            if (!mine && pgid < 0 && pid >= want_pgid && pid <= max_seen_pid + 64) {
                mine = true;  // exited descendant, within our pid window
            }
            if (!mine) {
                ++res.dropped;
                continue;
            }
            ours.insert(pid);
            if (pid > max_seen_pid) max_seen_pid = pid;
            res.records.push_back(std::move(rec));
        }
        pending.erase(0, start);
    };

    // Poll until the child exits, draining as we go.
    for (;;) {
        int status = 0;
        pid_t w = ::waitpid(static_cast<pid_t>(child.pid), &status, WNOHANG);
        drain();
        if (w == static_cast<pid_t>(child.pid)) {
            if (WIFSIGNALED(status)) {
                child.signalled = true;
                child.signal_number = WTERMSIG(status);
                child.exit_code = 128 + child.signal_number;
            } else {
                child.exit_code = WEXITSTATUS(status);
            }
            break;
        }
        if (w < 0 && errno != EINTR) break;
        ::usleep(15 * 1000);
    }

    // Trailing records can lag the exit; keep draining briefly.
    for (int i = 0; i < 40; ++i) {
        ::usleep(25 * 1000);
        drain();
    }

    res.exit_code = child.exit_code;
    ::kill(logger, SIGKILL);
    ::waitpid(logger, nullptr, 0);
    ::close(read_fd);

    if (res.records.empty()) {
        res.warnings.emplace_back(
            "observation produced no records. The workload may have exited too "
            "quickly, or the unified log is rate-limiting. Re-run, or use "
            "`--observe-timeout`.");
    }
    return res;
}

#else

ObserveCaps observe_probe() {
    ObserveCaps c;
    c.available = false;
    c.mechanism = "none";
    c.reason =
        "no observation backend for this platform yet. On Linux this needs "
        "Landlock audit (ABI v7+, kernel 6.15) or an eBPF/ptrace collector.";
    return c;
}

ObserveResult observe(const SpawnRequest&) {
    ObserveResult r;
    r.error = observe_probe().reason;
    return r;
}

#endif

}  // namespace bastion
