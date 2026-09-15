// LIVE enforcement tests. These spawn real processes and assert the kernel
// actually blocked them -- not that we generated plausible-looking policy text.
#include "bastion/spawn.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#if defined(__APPLE__)
#  include "bastion/backend/seatbelt.hpp"
#endif

using namespace bastion;
namespace fs = std::filesystem;

static int failures = 0;

static void check(bool cond, const char* what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) ++failures;
}

// Run a shell command under a policy; return the child's exit code.
static SpawnResult run(const Sealed& p, const std::string& sh) {
    SpawnRequest req;
    req.argv = {"/bin/sh", "-c", sh};
    return spawn(p, req);
}

int main() {
#if !defined(__APPLE__)
    std::puts("live enforcement tests: skipped (no backend on this platform)");
    return 0;
#else
    const fs::path ws = "/tmp/bastion-live";
    fs::remove_all(ws);
    fs::create_directories(ws / "sub");
    { std::ofstream f(ws / "in.txt"); f << "workspace data\n"; }

    const fs::path outside = "/tmp/bastion-outside";
    fs::remove_all(outside);
    fs::create_directories(outside);
    { std::ofstream f(outside / "secret.txt"); f << "SECRET\n"; }

    // A tight T2 policy over an arbitrary directory -- no fixed sandbox root.
    auto tight = Policy{Tier::Kernel}
                     .allow(Right::FsRead | Right::FsWrite, ws, "workspace")
                     .seal();

    std::puts("\n== T2 kernel enforcement (live) ==");

    auto r1 = run(tight, "cat /tmp/bastion-live/in.txt > /dev/null");
    check(r1.launched() && r1.exit_code == 0, "read inside workspace ALLOWED");

    auto r2 = run(tight, "echo written > /tmp/bastion-live/out.txt");
    check(r2.launched() && r2.exit_code == 0, "write inside workspace ALLOWED");
    check(fs::exists(ws / "out.txt"), "written file actually exists");

    auto r3 = run(tight, "cat /tmp/bastion-outside/secret.txt 2>/dev/null");
    check(r3.launched() && r3.exit_code != 0, "read OUTSIDE workspace DENIED");

    auto r4 = run(tight, "cat /etc/passwd 2>/dev/null");
    check(r4.launched() && r4.exit_code != 0, "read /etc/passwd DENIED");

    auto r5 = run(tight, "echo pwned > /tmp/bastion-outside/pwned.txt 2>/dev/null");
    check(r5.launched() && r5.exit_code != 0, "write OUTSIDE workspace DENIED");
    check(!fs::exists(outside / "pwned.txt"), "no file created outside");

    // Sibling-prefix attack: /tmp/bastion-live must not authorize
    // /tmp/bastion-live-evil. Verifies SBPL subpath component boundaries agree
    // with Sealed::covers().
    const fs::path sibling = "/tmp/bastion-live-evil";
    fs::remove_all(sibling);
    fs::create_directories(sibling);
    { std::ofstream f(sibling / "s.txt"); f << "SIBLING\n"; }
    auto r6 = run(tight, "cat /tmp/bastion-live-evil/s.txt 2>/dev/null");
    check(r6.launched() && r6.exit_code != 0, "sibling-prefix dir DENIED");

    // The home directory / SSH keys: the thing users actually fear.
    auto r7 = run(tight, "cat ~/.ssh/id_ed25519 2>/dev/null || cat ~/.ssh/id_rsa 2>/dev/null");
    check(r7.launched() && r7.exit_code != 0, "SSH private keys DENIED");

    std::puts("\n== ergonomic floor (DESIGN.md 4) ==");
    // These are the failures the field report hit empirically over a day.
    auto e1 = run(tight, "test -w /dev/null && echo ok > /dev/null");
    check(e1.launched() && e1.exit_code == 0, "/dev/null writable");

    auto e2 = run(tight, "head -c 8 /dev/urandom > /dev/null");
    check(e2.launched() && e2.exit_code == 0, "/dev/urandom readable");

    auto e3 = run(tight, "sh -c 'echo nested works' > /dev/null");
    check(e3.launched() && e3.exit_code == 0, "nested process spawn works");

    auto e4 = run(tight, "ls /usr/bin > /dev/null");
    check(e4.launched() && e4.exit_code == 0, "PATH dirs readable");

    std::puts("\n== network: honest about the boundary ==");
    auto net = Policy{Tier::Kernel}
                   .allow(Right::FsRead | Right::FsWrite, ws, "workspace")
                   .allow_egress("example.com:443", "test")
                   .seal();
    auto compiled_net = darwin::compile(net);
    bool warned = false;
    for (const auto& w : compiled_net.warnings) {
        if (w.find("cannot restrict by hostname") != std::string::npos) warned = true;
    }
    check(warned, "warns that Seatbelt cannot filter by hostname");

    auto nonet = run(tight, "curl -s -m 3 -o /dev/null https://example.com 2>/dev/null");
    check(nonet.launched() && nonet.exit_code != 0, "egress DENIED without grant");

    std::puts("\n== unconfined: allows all, still audited ==");
    Broker broker;
    auto yolo = Policy{Tier::Kernel}
                    .unconfined(broker.grant_unconfined(Witness{"live test --yolo"}))
                    .seal();
    auto y1 = run(yolo, "cat /tmp/bastion-outside/secret.txt > /dev/null");
    check(y1.launched() && y1.exit_code == 0, "unconfined CAN read outside");
    auto y2 = run(yolo, "cat /etc/passwd > /dev/null");
    check(y2.launched() && y2.exit_code == 0, "unconfined CAN read /etc/passwd");
    check(yolo.evaluate("fs.read", "/etc/passwd").rule == "unconfined",
          "unconfined access still attributed in the ledger");
    check(yolo.explain().find("live test --yolo") != std::string::npos,
          "witness recorded in explain output");

    std::puts("\n== fail-closed behaviour ==");
    // A path with a control character must be rejected, not escaped-and-hoped.
    std::string bad = std::string{"/tmp/ba"} + '\n' + "d";
    auto badpol = Policy{Tier::Kernel}.allow(Right::FsRead, bad, "injection").seal();
    auto bc = darwin::compile(badpol);
    check(!bc.ok, "control-character path REJECTED at compile time");

    // The injection payload measured in tools/probe must not escalate.
    std::string inj = "/tmp/bastion-live\") (allow file-read* (subpath \"/";
    auto injpol = Policy{Tier::Kernel}.allow(Right::FsRead, inj, "injection").seal();
    auto ic = darwin::compile(injpol);
    if (ic.ok) {
        SpawnRequest req;
        req.argv = {"/bin/sh", "-c", "cat /etc/passwd 2>/dev/null"};
        auto ir = spawn(injpol, req);
        check(ir.launched() && ir.exit_code != 0,
              "SBPL injection payload does NOT grant total read");
    } else {
        check(true, "SBPL injection payload rejected at compile time");
    }

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "all live enforcement tests passed" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
#endif
}
