// Tests the audit ledger and policy synthesizer -- the machinery that makes
// "--yolo is an on-ramp to a tight policy" true rather than aspirational.
#include "bastion/ledger.hpp"

#include <cassert>
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
        // The phantom filter drops grants for paths that do not exist, so a
        // test using purely notional paths would measure that filter instead
        // of the coalescing it means to test. Stage a real tree.
        fs::create_directories("/tmp/bastion-ledger-test/proj/src");
        fs::create_directories("/tmp/bastion-ledger-test/proj/build");
        for (const char* f : {"a.cpp", "b.cpp", "c.cpp", "d.cpp"}) {
            std::ofstream{std::string{"/tmp/bastion-ledger-test/proj/src/"} + f}
                << "int x;\n";
        }
        std::ofstream{"/tmp/bastion-ledger-test/proj/build/out.o"} << "obj\n";

        add(Verdict::Allow, "fs.read", "/tmp/bastion-ledger-test/proj/src/a.cpp");
        add(Verdict::Allow, "fs.read", "/tmp/bastion-ledger-test/proj/src/b.cpp");
        add(Verdict::Allow, "fs.read", "/tmp/bastion-ledger-test/proj/src/c.cpp");
        add(Verdict::Allow, "fs.read", "/tmp/bastion-ledger-test/proj/src/d.cpp");
        add(Verdict::Allow, "fs.write", "/tmp/bastion-ledger-test/proj/build/out.o");
        add(Verdict::Allow, "net.egress", "registry.npmjs.org:443");
        add(Verdict::Deny,  "fs.read", "/home/user/.ssh/id_ed25519");
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
    check(has(toml, "/tmp/bastion-ledger-test/proj/src\""), "sibling reads coalesced to /proj/src");
    check(!has(toml, "/tmp/bastion-ledger-test/proj/src/a.cpp"), "individual files not emitted");

    // A WRITE coalesces to its directory from a SINGLE observation, unlike a
    // read. This test previously asserted the opposite -- that a lone write
    // stayed a per-file grant -- and that was measured to be wrong in the one
    // way that matters: the resulting policy could not be re-used.
    //
    // A build's outputs are NEW files every run (the compiler's temp object,
    // the linked binary), so a grant naming /proj/build/out.o authorises
    // exactly one historical file and nothing the next build creates. The
    // policy worked only for the run it was derived from, which defeats the
    // observe -> synthesize -> run loop entirely.
    check(has(toml, "/tmp/bastion-ledger-test/proj/build\""),
          "a lone write coalesces to its DIRECTORY, so new outputs work");
    check(!has(toml, "/tmp/bastion-ledger-test/proj/build/out.o"),
          "...and the one-shot per-file grant is gone");

    // Writing into a directory requires READ on it too: Landlock needs read to
    // resolve a path inside a directory, so a write-only grant means `ld`
    // cannot create its output there.
    {
        const auto bpos = toml.find("/tmp/bastion-ledger-test/proj/build\"");
        const bool paired =
            bpos != std::string::npos &&
            toml.find("fs.read", bpos) != std::string::npos;
        check(paired, "a write-coalesced directory also gets fs.read");
    }

    check(has(toml, "registry.npmjs.org:443"), "egress grant preserved");

    // THE security property: a denied operation must never become a grant.
    // Otherwise synthesis would hand over exactly what the sandbox stopped.
    check(!has(toml, "id_ed25519"), "DENIED path NOT turned into a grant");
    check(has(toml, "NOT turned into grants"), "denial surfaced as a note");

    std::puts("== never-widen guard ==");
    {
        Ledger led2{"/tmp/bastion-ledger-test/l2.jsonl"};
        // Stand-in for $HOME. Staged for real, because the phantom filter
        // drops grants whose path does not exist -- with notional paths this
        // test would pass for the wrong reason, never reaching the coalescing
        // guard it means to check.
        const std::string home = "/tmp/bastion-ledger-test/home";
        fs::create_directories(home);
        for (const char* f : {"a", "b", "c", "d"}) {
            std::ofstream{home + "/" + f} << "x\n";
        }
        // Many reads directly under $HOME must not coalesce into $HOME itself.
        for (const std::string p : {home + "/a", home + "/b",
                                    home + "/c", home + "/d"}) {
            AuditRecord r;
            r.verdict = Verdict::Allow;
            r.op = "fs.read";
            r.target = p;
            led2.record(r);
        }
        SynthesisOptions opts;
        opts.never_widen_to.push_back(home);
        auto s2 = synthesize(led2, opts);
        const std::string t2 = s2.to_toml();
        check(!has(t2, "path  = \"" + home + "\"\n"),
              "did NOT coalesce into the home directory");
        check(has(t2, "declined to coalesce"), "explained the refusal");
        check(has(t2, home + "/a"), "emitted individual paths instead");
    }

    std::puts("\n== cpp output ==");
    const std::string cpp = syn.to_cpp();
    check(has(cpp, "bastion::Policy{bastion::Tier::Kernel}"), "emits builder code");
    check(has(cpp, ".seal()"), "emits seal()");
    check(has(cpp, "Right::FsWrite"), "emits correct rights");

    std::puts("\n== a synthesized policy stays REVIEWABLE ==");
    {
        // The number that decides whether anyone reads the output. A policy a
        // human will not read is one that gets --yolo'd, so rule count is a
        // security property, not a cosmetic one.
        //
        // MEASURED before this filtering existed: a ONE-FILE C build produced
        // 27 rules, including three exec grants for `cc` paths that do not
        // exist (failed $PATH probes), two compiler scratch files that would
        // never exist again, and a /usr/include -> bits -> types chain where
        // the first rule already subsumed the rest. The one binary that
        // actually ran did not appear at all.
        Ledger led3{"/tmp/bastion-ledger-test/l3.jsonl"};
        const std::string proj = "/tmp/bastion-ledger-test/rv";
        fs::create_directories(proj + "/deep/deeper");
        std::ofstream{proj + "/main.c"} << "int main(){}\n";
        std::ofstream{proj + "/deep/a.h"} << "\n";
        std::ofstream{proj + "/deep/deeper/b.h"} << "\n";

        auto rec = [&](const char* op, const std::string& t) {
            AuditRecord r;
            r.verdict = Verdict::Allow;
            r.op = op;
            r.target = t;
            led3.record(r);
        };

        // A nested tree: every level must collapse to the top one.
        rec("fs.read", proj);
        rec("fs.read", proj + "/deep");
        rec("fs.read", proj + "/deep/deeper");
        rec("fs.read", proj + "/deep/deeper/b.h");
        rec("fs.read", proj + "/main.c");
        // Phantom: a failed PATH probe for a binary that is not there.
        rec("fs.exec", "/usr/local/sbin/definitely-not-here");
        // Transient: compiler scratch, gone before the policy is ever used.
        rec("fs.read", "/tmp/ccAbCdEf.s");
        rec("fs.read", "/tmp/ccAbCdEf.o");
        // Floor: already granted, so repeating it is pure noise.
        rec("fs.read", "/etc/ld.so.cache");

        const std::string t3 = synthesize(led3).to_toml();
        const auto count = [&](const std::string& needle) {
            std::size_t n = 0, pos = 0;
            while ((pos = t3.find(needle, pos)) != std::string::npos) {
                ++n;
                pos += needle.size();
            }
            return n;
        };

        const std::size_t rules = count("[[allow]]");
        std::printf("      9 observations -> %zu rule(s)\n", rules);

        check(!has(t3, "definitely-not-here"),
              "a grant for a path that does not exist is dropped");
        check(!has(t3, "ccAbCdEf"),
              "compiler scratch files are dropped");
        check(!has(t3, "ld.so.cache"),
              "paths the ergonomic floor already grants are dropped");
        check(!has(t3, "deeper"),
              "a nested tree collapses to its top-most granted directory");
        check(rules <= 2,
              "the whole observation reduces to a reviewable policy");
    }

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "all ledger tests passed" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
