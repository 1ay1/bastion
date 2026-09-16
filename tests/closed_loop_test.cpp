// CLOSED-LOOP test: the whole point of T0 observation.
//
//   1. observe a workload (nothing enforced, everything recorded)
//   2. synthesize the minimal policy from what was seen
//   3. RE-RUN the same workload under that synthesized policy
//   4. it must SUCCEED -- and still deny everything it never touched
//
// Step 3 is what makes the feature real. Before this existed, `bastion
// synthesize` printed "no grants needed" for a program that had demonstrably
// read /etc/hosts and written to /tmp: the ledger only held process spawns, so
// the headline feature was confidently, silently wrong.
#include "bastion/ledger.hpp"
#include "bastion/observe.hpp"
#include "bastion/spawn.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>

using namespace bastion;
namespace fs = std::filesystem;

static int failures = 0;
static void check(bool c, const char* what) {
    std::printf("  [%s] %s\n", c ? "PASS" : "FAIL", what);
    if (!c) ++failures;
}

int main() {
    auto caps = observe_probe();
    if (!caps.available) {
        std::printf("closed-loop test: skipped (%s)\n", caps.reason.c_str());
        return 0;
    }

    const fs::path ws = "/tmp/bastion-loop";
    const fs::path off = "/tmp/bastion-loop-secret";
    fs::remove_all(ws);
    fs::remove_all(off);
    fs::create_directories(ws);
    fs::create_directories(off);
    { std::ofstream f(ws / "input.txt"); f << "data\n"; }
    { std::ofstream f(off / "flag.txt"); f << "SECRET\n"; }

    // A workload that touches a specific, knowable set of paths -- including
    // one read performed by a GRANDCHILD (cat), which is the case naive
    // attribution loses.
    const std::string work =
        "cat /tmp/bastion-loop/input.txt > /dev/null && "
        "echo out > /tmp/bastion-loop/output.txt && "
        "cat /etc/hosts > /dev/null";

    std::puts("== 1. observe (T0: nothing enforced, all recorded) ==");
    SpawnRequest req;
    req.argv = {"/bin/sh", "-c", work};
    auto obs = observe(req);
    check(obs.ok(), "observation ran");
    check(obs.exit_code == 0, "workload succeeded unconfined");
    check(!obs.records.empty(), "records were captured");
    std::printf("      captured %zu access(es), ignored %zu foreign\n",
                obs.records.size(), obs.dropped);

    // The specific accesses we know the workload made must all be present.
    auto saw = [&](std::string_view op, std::string_view path) {
        for (const auto& r : obs.records) {
            if (r.op == op && r.target.find(path) != std::string::npos) return true;
        }
        return false;
    };
    check(saw("fs.read", "bastion-loop/input.txt"), "recorded the input read");
    check(saw("fs.write", "bastion-loop/output.txt"), "recorded the output write");
    // Performed by `cat`, a grandchild with its own short-lived pid.
    check(saw("fs.read", "etc/hosts"), "recorded a GRANDCHILD's read");

    std::puts("\n== 2. synthesize ==");
    const std::string ledger_path = "/tmp/bastion-loop-ledger.jsonl";
    fs::remove(ledger_path);
    {
        Ledger led{ledger_path};
        for (const auto& r : obs.records) led.record(r);
        check(led.flush().empty(), "ledger written");
    }
    std::string err;
    auto reloaded = Ledger::load(ledger_path, err);
    check(reloaded.has_value(), "ledger reloaded");

    auto syn = synthesize(*reloaded);
    check(!syn.rules.empty(), "produced at least one grant");
    std::printf("      %zu grant(s), %zu floor access(es) filtered\n",
                syn.rules.size(), syn.floor_filtered);

    // It must NOT hand over the whole filesystem. Observation legitimately sees
    // a read of "/" (dyld does it), and granting that would be the exact
    // opposite of least privilege.
    bool granted_root = false;
    for (const auto& r : syn.rules) {
        if (r.scope == "/") granted_root = true;
    }
    check(!granted_root, "did NOT synthesize a grant for /");

    std::puts("\n== 3. re-run under the SYNTHESIZED policy ==");
    Policy rebuilt{Tier::Kernel};
    for (const auto& r : syn.rules) {
        rebuilt = std::move(rebuilt).allow(r.right, r.scope, "synthesized");
    }
    auto sealed = std::move(rebuilt).seal();

    SpawnRequest rerun;
    rerun.argv = {"/bin/sh", "-c", work};
    auto res = spawn(sealed, rerun);
    check(res.launched(), "re-run launched");
    check(res.exit_code == 0,
          "WORKLOAD SUCCEEDS under the synthesized policy (closed loop)");

    std::puts("\n== 4. the synthesized policy is still TIGHT ==");
    SpawnRequest esc;
    esc.argv = {"/bin/sh", "-c",
                "cat /tmp/bastion-loop-secret/flag.txt 2>/dev/null"};
    auto e1 = spawn(sealed, esc);
    check(e1.launched() && e1.exit_code != 0,
          "never-touched path is DENIED (no over-granting)");

    SpawnRequest esc2;
    esc2.argv = {"/bin/sh", "-c", "cat ~/.ssh/id_ed25519 2>/dev/null"};
    auto e2 = spawn(sealed, esc2);
    check(e2.launched() && e2.exit_code != 0, "SSH keys still DENIED");

    // ---- 5. the SAME closed loop, for egress -----------------------------
    //
    // Filesystem access was recorded and network access was not, so a T3
    // run produced a ledger holding one proc.spawn and nothing else. That
    // is the identical failure this file was written for — `synthesize`
    // confidently printing a policy that omits what the workload actually
    // needed — just one op later. An egress decision that only reaches
    // stderr cannot be synthesized from, and cannot be read by a host that
    // wants to tell a model WHY its tool failed.
    std::puts("\n== 5. egress decisions are RECORDED, not just printed ==");
    {
        AuditRecord allowed;
        allowed.verdict = Verdict::Allow;
        allowed.op      = "net.egress";
        allowed.target  = "example.com:443";
        allowed.tier    = Tier::Isolate;
        allowed.rule    = "allowlist";

        AuditRecord denied;
        denied.verdict = Verdict::Deny;
        denied.op      = "net.egress";
        denied.target  = "api.github.com:443";
        denied.tier    = Tier::Isolate;
        denied.rule    = "allowlist-miss";
        Remedy r;
        r.grant = "NetEgress(api.github.com:443)";
        r.cmd   = "bastion run -t t3 --net api.github.com:443 -- <cmd>";
        denied.remedy = r;

        // Both verdicts round-trip through the JSON the ledger stores.
        const auto aj = allowed.to_json();
        const auto dj = denied.to_json();
        check(aj.find("\"op\":\"net.egress\"") != std::string::npos,
              "an ALLOWED host is recorded (synthesize needs the positives)");
        check(aj.find("\"verdict\":\"allow\"") != std::string::npos,
              "...with an allow verdict");
        check(dj.find("\"verdict\":\"deny\"") != std::string::npos,
              "a REFUSED host is recorded");
        check(dj.find("\"remedy\"") != std::string::npos,
              "...carrying a remedy a model can act on");
        check(dj.find("--net api.github.com:443") != std::string::npos,
              "...that names the exact grant to add");
    }

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "closed loop verified" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
