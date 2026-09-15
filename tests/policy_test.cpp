// Asserts the BEHAVIOURAL claims of DESIGN.md §1 and §4.1:
//   - a denial carries a machine-readable remedy (replaces AGENTS.md prose)
//   - T0/T1 report WouldDeny, never a fake boundary
//   - Unconfined allows everything but STILL records every operation
//   - path-set authority works from an arbitrary CWD (no fixed $HOME/sandbox)
#include "bastion/policy.hpp"

#include <cassert>
#include <cstdio>
#include <string>

using namespace bastion;

static bool has(const std::string& hay, std::string_view needle) {
    return hay.find(needle) != std::string::npos;
}

int main() {
    // ---- 1. A tight T2 policy in an ARBITRARY directory --------------------
    auto sealed = Policy{Tier::Kernel}
                      .allow(Right::FsRead | Right::FsWrite, "/tmp/bastion-demo",
                             "workspace root")
                      .allow(Right::FsRead, "/usr/include", "toolchain headers")
                      .allow_egress("registry.npmjs.org:443", "package install")
                      .seal();

    auto ok = sealed.evaluate("fs.write", "/tmp/bastion-demo/src/main.cpp");
    assert(ok.verdict == Verdict::Allow);

    // component-boundary check: /tmp/bastion-demo must NOT cover a sibling
    auto sib = sealed.evaluate("fs.write", "/tmp/bastion-demo-evil/x");
    assert(sib.verdict == Verdict::Deny);

    // read-only rule must not confer write
    auto ro = sealed.evaluate("fs.write", "/usr/include/stdio.h");
    assert(ro.verdict == Verdict::Deny);

    // ---- 2. Denials are machine-readable, not prose (§4.1) -----------------
    auto denied = sealed.evaluate("fs.write", "/etc/hosts");
    assert(denied.verdict == Verdict::Deny);
    assert(denied.remedy.has_value());
    const std::string j = denied.to_json();
    assert(has(j, "\"verdict\":\"deny\""));
    assert(has(j, "\"rule\":\"default-deny\""));
    assert(has(j, "bastion grant fs.write /etc/hosts"));
    assert(has(j, "$WORKSPACE"));
    std::printf("denial record:\n  %s\n\n", j.c_str());

    // ---- 3. T0 never claims a boundary it does not have --------------------
    auto observe = Policy{Tier::Observe}.seal();
    auto shadow = observe.evaluate("fs.write", "/etc/hosts");
    assert(shadow.verdict == Verdict::WouldDeny);
    assert(has(shadow.to_json(), "would_deny"));

    // ---- 4. THE THESIS: --yolo allows all, still audits all ---------------
    Broker broker;
    auto yolo = Policy{Tier::Kernel}
                    .unconfined(broker.grant_unconfined(
                        Witness{"user passed --yolo"}))
                    .seal();
    assert(yolo.is_unconfined());

    for (auto* t : {"/etc/hosts", "/Users/ayush/.ssh/id_ed25519", "evil.com:443"}) {
        auto r = yolo.evaluate(t[0] == '/' ? "fs.write" : "net.egress", t);
        assert(r.verdict == Verdict::Allow);      // frictionless
        assert(r.rule == "unconfined");           // attributed
        assert(has(r.provenance, "--yolo"));      // witnessed
        assert(has(r.to_json(), t));              // recorded
    }

    const std::string expl = yolo.explain();
    assert(has(expl, "UNCONFINED GRANT ACTIVE"));
    assert(has(expl, "Auditing remains fully active"));
    assert(has(expl, "--yolo"));
    std::printf("bastion explain (--yolo):\n%s\n", expl.c_str());

    // ---- 5. Tier honesty ---------------------------------------------------
    assert(has(std::string{tier_guarantee(Tier::Advisory)}, "not a motivated"));
    assert(has(std::string{tier_guarantee(Tier::Isolate)}, "no setuid"));

    std::puts("all policy tests passed");
    return 0;
}
