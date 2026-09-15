// Tests the audit ledger and policy synthesizer -- the machinery that makes
// "--yolo is an on-ramp to a tight policy" true rather than aspirational.
#include "bastion/ledger.hpp"

#include <cassert>
#include <cstdio>
#include <filesystem>

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
    const std::string path = "/tmp/bastion-ledger-test/ledger.jsonl";
    fs::remove_all("/tmp/bastion-ledger-test");

    std::puts("== round-trip ==");
    {
        Ledger led{path};
        auto add = [&](Verdict v, const char* op, const char* target) {
            AuditRecord r;
            r.verdict = v;
            r.op = op;
            r.target = target;
            r.tier = Tier::Kernel;
            r.rule = "unconfined";
            r.provenance = "UNCONFINED: user passed --yolo";
            led.record(r);
        };
        // A realistic unconfined build: several files in one dir, plus a denial.
        add(Verdict::Allow, "fs.read", "/proj/src/a.cpp");
        add(Verdict::Allow, "fs.read", "/proj/src/b.cpp");
        add(Verdict::Allow, "fs.read", "/proj/src/c.cpp");
        add(Verdict::Allow, "fs.read", "/proj/src/d.cpp");
        add(Verdict::Allow, "fs.write", "/proj/build/out.o");
        add(Verdict::Allow, "net.egress", "registry.npmjs.org:443");
        add(Verdict::Deny,  "fs.read", "/Users/ayush/.ssh/id_ed25519");
        check(led.flush().empty(), "ledger flushed to disk");
    }
    check(fs::exists(path), "ledger file created");

    std::string err;
    auto loaded = Ledger::load(path, err);
    check(loaded.has_value(), "ledger reloaded from disk");
    check(loaded && loaded->records().size() == 7, "all 7 records survived");

    std::puts("\n== synthesis ==");
    auto syn = synthesize(*loaded);
    check(syn.observations == 7, "counted every observation");
    check(syn.denials_seen == 1, "counted the denial");

    const std::string toml = syn.to_toml();
    std::printf("\n%s\n", toml.c_str());

    // Coalescing: 4 files under /proj/src should collapse to the directory.
    check(has(toml, "/proj/src\""), "sibling reads coalesced to /proj/src");
    check(!has(toml, "/proj/src/a.cpp"), "individual files not emitted");
    check(has(toml, "/proj/build/out.o"), "lone write emitted individually");
    check(has(toml, "registry.npmjs.org:443"), "egress grant preserved");

    // THE security property: a denied operation must never become a grant.
    // Otherwise synthesis would hand over exactly what the sandbox stopped.
    check(!has(toml, "id_ed25519"), "DENIED path NOT turned into a grant");
    check(has(toml, "NOT turned into grants"), "denial surfaced as a note");

    std::puts("== never-widen guard ==");
    {
        Ledger led2{"/tmp/bastion-ledger-test/l2.jsonl"};
        // Many reads directly under $HOME must not coalesce into $HOME itself.
        for (const char* p : {"/Users/ayush/a", "/Users/ayush/b",
                              "/Users/ayush/c", "/Users/ayush/d"}) {
            AuditRecord r;
            r.verdict = Verdict::Allow;
            r.op = "fs.read";
            r.target = p;
            led2.record(r);
        }
        SynthesisOptions opts;
        opts.never_widen_to.push_back("/Users/ayush");
        auto s2 = synthesize(led2, opts);
        const std::string t2 = s2.to_toml();
        check(!has(t2, "path  = \"/Users/ayush\"\n"),
              "did NOT coalesce into the home directory");
        check(has(t2, "declined to coalesce"), "explained the refusal");
        check(has(t2, "/Users/ayush/a"), "emitted individual paths instead");
    }

    std::puts("\n== cpp output ==");
    const std::string cpp = syn.to_cpp();
    check(has(cpp, "bastion::Policy{bastion::Tier::Kernel}"), "emits builder code");
    check(has(cpp, ".seal()"), "emits seal()");
    check(has(cpp, "Right::FsWrite"), "emits correct rights");

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "all ledger tests passed" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
