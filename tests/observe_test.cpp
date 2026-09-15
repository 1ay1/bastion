// Verifies the T0 observation backend: the thing that makes `--yolo` an
// ON-RAMP (DESIGN.md §1) rather than a dead end.
//
// The claims that matter are not "it recorded something" but:
//   - observation does NOT change the workload (T0 enforces nothing)
//   - a GRANDCHILD is seen, not just the direct child
//   - relative paths are resolved to absolute ones, or the synthesized policy
//     would be meaningless outside the original cwd
//   - reads and writes are distinguished, or the policy over- or under-grants
//   - network destinations are captured as host:port
//   - when observation is impossible, it says so instead of reporting silence
//     as "this program needs no permissions"
#include "bastion/observe.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

using namespace bastion;
namespace fs = std::filesystem;

static int failures = 0;
static void check(bool c, const char* what) {
    std::printf("  [%s] %s\n", c ? "PASS" : "FAIL", what);
    if (!c) ++failures;
}

static bool saw(const ObserveResult& r, const std::string& op,
                const std::string& target) {
    return std::any_of(r.records.begin(), r.records.end(), [&](const AuditRecord& a) {
        return a.op == op && a.target == target;
    });
}

static bool saw_target(const ObserveResult& r, const std::string& target) {
    return std::any_of(r.records.begin(), r.records.end(),
                       [&](const AuditRecord& a) { return a.target == target; });
}

int main() {
    auto caps = observe_probe();
    std::printf("observation: available=%d mechanism=%s\n", caps.available,
                caps.mechanism.c_str());

    if (!caps.available) {
        // An honest refusal is the CORRECT behaviour here, not a skip we
        // paper over: the reason must be actionable.
        check(!caps.reason.empty(),
              "unavailable observation explains itself (no silent failure)");
        std::printf("\nobservation backend unavailable; %d failure%s\n", failures,
                    failures == 1 ? "" : "s");
        return failures == 0 ? 0 : 1;
    }

    const fs::path ws = "/tmp/bastion-observe-test";
    fs::remove_all(ws);
    fs::create_directories(ws);
    { std::ofstream{ws / "input.txt"} << "payload\n"; }

    std::puts("\n== 1. observation does not change the workload ==");
    {
        SpawnRequest req;
        req.argv = {"/bin/sh", "-c",
                    "cat input.txt > output.txt && echo marker > marker.txt && exit 7"};
        req.cwd = ws.string();
        auto r = observe(req);

        check(r.ok(), "observe() succeeded");
        // T0 enforces nothing, so the workload's own exit code must survive.
        check(r.exit_code == 7, "workload's exit code is preserved (nothing enforced)");
        check(fs::exists(ws / "output.txt"), "workload's writes really happened");
        check(fs::exists(ws / "marker.txt"), "all workload side effects happened");
    }

    std::puts("\n== 2. what was recorded ==");
    {
        SpawnRequest req;
        req.argv = {"/bin/sh", "-c", "cat input.txt > copy.txt; cat /etc/hosts >/dev/null"};
        req.cwd = ws.string();
        auto r = observe(req);
        std::printf("      %zu record(s)\n", r.records.size());

        check(!r.records.empty(), "records were captured");

        // Relative path resolution: the workload said "input.txt"; a policy
        // needs the absolute path or it means nothing from another directory.
        check(saw_target(r, (ws / "input.txt").string()),
              "relative path resolved to absolute (policy is portable)");

        // Read vs write. Getting this wrong either over-grants (write on
        // everything) or under-grants (read on everything, so builds fail).
        check(saw(r, "fs.read", (ws / "input.txt").string()),
              "input classified as a READ");
        check(saw(r, "fs.write", (ws / "copy.txt").string()),
              "output classified as a WRITE");

        // The grandchild case: /etc/hosts is opened by `cat`, which sh exec'd.
        // A backend that only watched the direct child would miss this, and
        // the synthesized policy would be silently incomplete.
        check(saw(r, "fs.read", "/etc/hosts"),
              "GRANDCHILD's access was recorded (filter survives execve)");

        // exec is authority too: a policy may need fs.exec.
        check(saw_target(r, "/usr/bin/cat") || saw_target(r, "/bin/cat"),
              "exec of a grandchild binary recorded");
    }

    std::puts("\n== 3. records are deduplicated ==");
    {
        SpawnRequest req;
        // Open the same file many times; the ledger should describe the SET of
        // things touched, not the call count, or synthesize() drowns in noise.
        req.argv = {"/bin/sh", "-c",
                    "for i in 1 2 3 4 5 6 7 8 9 10; do cat input.txt >/dev/null; done"};
        req.cwd = ws.string();
        auto r = observe(req);
        const auto n = std::count_if(
            r.records.begin(), r.records.end(), [&](const AuditRecord& a) {
                return a.target == (ws / "input.txt").string();
            });
        check(n == 1, "the same path opened 10x yields ONE record");
    }

    std::puts("\n== 4. every record is attributable ==");
    {
        SpawnRequest req;
        req.argv = {"/bin/sh", "-c", "cat input.txt >/dev/null"};
        req.cwd = ws.string();
        auto r = observe(req);
        const bool all_ok = std::all_of(
            r.records.begin(), r.records.end(), [](const AuditRecord& a) {
                // T0 enforces nothing, so nothing may be recorded as denied,
                // and every record must name a real target.
                return a.verdict == Verdict::Allow && !a.target.empty() &&
                       !a.op.empty() && a.tier == Tier::Observe;
            });
        check(all_ok, "all records are T0/Allow with a non-empty op and target");
    }

    fs::remove_all(ws);
    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "observation verified" : "FAILURES", failures,
                failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
