// Policy FILE round-trip: the loop has to close for a USER, not just in a test.
//
//     bastion observe -- ./build.sh
//     bastion synthesize > bastion.toml      # review, commit
//     bastion run --policy bastion.toml -- ./build.sh
//
// Until `--policy` existed, `synthesize` emitted a file nothing could read
// back, so the last step was "translate the TOML into CLI flags by hand".
#include "bastion/ledger.hpp"
#include "bastion/policy_file.hpp"
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
static bool has(const std::string& h, std::string_view n) {
    return h.find(n) != std::string::npos;
}

int main() {
    std::puts("== parse the exact text synthesize emits ==");
    {
        // Build a Synthesis the normal way, render it, parse it back.
        Ledger led{"/tmp/bastion-pf/in.jsonl"};
        auto add = [&](const char* op, const char* target) {
            AuditRecord r;
            r.verdict = Verdict::Allow;
            r.op = op;
            r.target = target;
            led.record(r);
        };
        add("fs.read", "/proj/src/a.cpp");
        add("fs.write", "/proj/out/bin");
        add("net.egress", "registry.npmjs.org:443");

        const std::string toml = synthesize(led).to_toml();
        auto parsed = parse_policy(toml);
        check(parsed.ok(), "synthesize output parses");
        if (!parsed) std::printf("      error: %s\n", parsed.error().c_str());
        const auto& pf = parsed.value();

        // FOUR blocks, not three: a write coalesces to its DIRECTORY (so the
        // policy still works when the build writes a differently-named output
        // next time), and a directory you write into also needs read, which a
        // policy file must spell as its own [[allow]] block.
        check(pf.rules.size() == 4,
              "every grant survived the round trip (write emits a paired read)");

        bool r = false, w = false, n = false, wr = false;
        for (const auto& rule : pf.rules) {
            if (rule.scope == "/proj/src/a.cpp" && any(rule.right & Right::FsRead)) r = true;
            if (rule.scope == "/proj/out" && any(rule.right & Right::FsWrite)) w = true;
            if (rule.scope == "/proj/out" && any(rule.right & Right::FsRead)) wr = true;
            if (rule.scope == "registry.npmjs.org:443" &&
                any(rule.right & Right::NetEgress)) n = true;
        }
        check(r, "fs.read rule preserved");
        check(w, "fs.write rule coalesced to the output DIRECTORY");
        check(wr, "...and paired with the read it needs to create files there");
        check(n, "net.egress rule preserved");
    }

    std::puts("\n== malformed input FAILS CLOSED ==");
    {
        // Every one of these must be rejected. Silently accepting a broken
        // policy would produce a sandbox the user believes is tight.
        auto bad = [&](const char* label, const char* text) {
            auto pf = parse_policy(text);
            check(!pf.ok(), label);
        };
        bad("unknown op rejected",
            "[[allow]]\nop = \"fs.telepathy\"\npath = \"/x\"\n");
        bad("missing path rejected", "[[allow]]\nop = \"fs.read\"\n");
        bad("missing op rejected", "[[allow]]\npath = \"/x\"\n");
        bad("unquoted value rejected",
            "[[allow]]\nop = fs.read\npath = \"/x\"\n");
        bad("garbage line rejected", "this is not a policy\n");
        bad("unknown tier rejected", "tier = \"T9\"\n");

        // ...but a valid file with only comments is fine (no grants).
        auto empty = parse_policy("# nothing here\n");
        check(empty.ok() && empty.value().rules.empty(),
              "comment-only file is valid");
    }

    std::puts("\n== tier and escapes ==");
    {
        auto pf = parse_policy("tier = \"T3\"\n[[allow]]\nop = \"net.egress\"\n"
                               "path = \"api.example.com:443\"\n");
        check(pf.ok() && pf.value().tier == Tier::Isolate, "tier parsed");

        auto esc = parse_policy(
            "[[allow]]\nop = \"fs.read\"\npath = \"/tmp/we\\\"ird\"\n");
        check(esc.ok(), "escaped quote in path parses");
        check(esc.ok() && esc.value().rules.size() == 1 &&
                  has(esc.value().rules[0].scope, "we\"ird"),
              "escape decoded to a literal quote");
    }

#if defined(__APPLE__) || defined(__linux__)
    std::puts("\n== the file actually ENFORCES ==");
    {
        const fs::path ws = "/tmp/bastion-pf-ws";
        const fs::path off = "/tmp/bastion-pf-secret";
        fs::remove_all(ws);
        fs::remove_all(off);
        fs::create_directories(ws);
        fs::create_directories(off);
        { std::ofstream f(off / "flag.txt"); f << "SECRET\n"; }

        const std::string text =
            "tier = \"T2\"\n\n"
            "[[allow]]\n"
            "op    = \"fs.read\"\n"
            "path  = \"/tmp/bastion-pf-ws\"\n\n"
            "[[allow]]\n"
            "op    = \"fs.write\"\n"
            "path  = \"/tmp/bastion-pf-ws\"\n";

        const std::string path = "/tmp/bastion-pf/policy.toml";
        fs::create_directories("/tmp/bastion-pf");
        { std::ofstream f(path); f << text; }

        auto loaded = load_policy(path);
        check(loaded.ok(), "policy file loaded from disk");
        // to_sealed() now takes a PolicyFile, which only exists on success --
        // sealing an unparsed file is no longer expressible.
        auto sealed = to_sealed(loaded.value());

        SpawnRequest ok;
        ok.argv = {"/bin/sh", "-c", "echo hi > /tmp/bastion-pf-ws/f.txt"};
        auto r1 = spawn(sealed, ok);
        check(r1.launched() && r1.exit_code == 0,
              "granted write WORKS under the loaded policy");

        SpawnRequest no;
        no.argv = {"/bin/sh", "-c", "cat /tmp/bastion-pf-secret/flag.txt 2>/dev/null"};
        auto r2 = spawn(sealed, no);
        check(r2.launched() && r2.exit_code != 0,
              "ungranted path still DENIED (file didn't over-grant)");
    }
#endif

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "policy file round-trip verified" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
