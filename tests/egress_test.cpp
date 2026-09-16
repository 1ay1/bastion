// T3 egress tests: per-host network allowlisting that a compromised child
// cannot route around.
//
// The design is a composition, and BOTH halves are tested here:
//   kernel : denies all egress except one loopback port (unforgeable)
//   proxy  : accepts there and enforces the host allowlist (expressive)
//
// A proxy alone would be advisory -- the workload could just open its own
// socket. The measured kernel pin (tools/probe/egress_probe.c) is what makes it
// a boundary.
#include "bastion/proxy.hpp"
#include "bastion/spawn.hpp"

#include <cstdio>
#include <string>

using namespace bastion;

static int failures = 0;
static void check(bool c, const char* what) {
    std::printf("  [%s] %s\n", c ? "PASS" : "FAIL", what);
    if (!c) ++failures;
}

int main() {
    std::puts("== rule parsing / matching ==");
    {
        auto r = parse_egress_rule("api.example.com:443");
        check(r.host == "api.example.com" && r.port == 443, "host:port parsed");
        check(r.matches("api.example.com", 443), "exact match");
        check(!r.matches("api.example.com", 80), "wrong port rejected");
        check(!r.matches("evil.com", 443), "wrong host rejected");

        auto any_port = parse_egress_rule("example.com");
        check(any_port.port == 0, "bare host = any port");
        check(any_port.matches("example.com", 8080), "any port matches");

        auto wild = parse_egress_rule("*.example.com:443");
        check(wild.matches("api.example.com", 443), "wildcard matches subdomain");
        check(wild.matches("a.b.example.com", 443), "wildcard matches deep sub");
        check(!wild.matches("example.com", 443),
              "wildcard does NOT match bare apex (must be listed explicitly)");
        check(!wild.matches("notexample.com", 443),
              "wildcard is not a substring match");
        check(!wild.matches("example.com.evil.net", 443),
              "suffix confusion rejected");

        // Case-insensitivity: DNS is case-insensitive, so the allowlist must be
        // too, or `EXAMPLE.com` silently bypasses a rule for `example.com`.
        auto up = parse_egress_rule("API.Example.COM:443");
        check(up.host == "api.example.com", "host lowercased on parse");
    }

    std::puts("\n== proxy lifecycle ==");
    std::string err;
    auto proxy = EgressProxy::start({parse_egress_rule("example.com:443")}, err);
    check(proxy != nullptr, "proxy started");
    if (!proxy) {
        std::printf("  error: %s\n", err.c_str());
        return 1;
    }
    check(proxy->port() != 0, "bound an ephemeral port");
    std::printf("      listening on 127.0.0.1:%u\n", proxy->port());

#if defined(__APPLE__) || defined(__linux__)
    std::puts("\n== T3 live enforcement ==");
    // NOTE: spawn() owns the broker. An earlier version of this test started
    // its own proxy and asserted against ITS counters, which stayed at 0/0
    // while the child talked to spawn's proxy on a different port -- the test
    // passed for the wrong reason. Always assert on SpawnResult.
    auto policy = Policy{Tier::Isolate}
                      .allow(Right::FsRead | Right::FsWrite, "/tmp/bastion-t3", "ws")
                      .allow_egress("example.com:443", "allowlisted host")
                      .seal();

    auto run = [&](const std::string& sh) {
        SpawnRequest req;
        req.argv = {"/bin/sh", "-c", sh};
        return spawn(policy, req);
    };

    // 1. The allowlisted host must actually work, end to end, through the
    //    tunnel. If T3 blocked legitimate traffic it would just be friction.
    auto ok = run("curl -s -m 10 -o /dev/null -w '%{http_code}' "
                  "https://example.com 2>/dev/null | grep -q 200");
    check(ok.launched() && ok.exit_code == 0,
          "ALLOWLISTED host reachable through the tunnel (HTTP 200)");
    check(ok.proxy_port != 0, "kernel policy was pinned to the broker port");
    check(ok.egress_allowed >= 1, "broker recorded the permitted connection");

    // 2. A non-allowlisted host must be refused BY THE BROKER.
    //
    // Asserted on the BROKER'S OWN COUNTER, not on curl's error text. The
    // wording is a moving target: curl 8.x says "CONNECT tunnel failed,
    // response 403", curl 7.81 (ubuntu-22.04) phrases it differently, and
    // MEASURED, that made the older-ABI CI job report a T3 ENFORCEMENT
    // FAILURE while enforcement was working perfectly. A security test that
    // fails on a distro's error-message wording trains you to ignore it.
    //
    // egress_denied comes from the broker deciding, so it cannot be faked by
    // a connection that failed for some unrelated reason -- and curl must
    // still fail, which is checked alongside it.
    auto no = run("curl -sS -m 10 -o /dev/null https://cloudflare.com");
    check(no.launched() && no.exit_code != 0,
          "NON-allowlisted host: the request FAILS");
    check(no.egress_denied >= 1,
          "...and the broker is what refused it (egress_denied recorded)");
    bool named = false;
    for (const auto& [hostport, allowed] : no.egress_attempts) {
        if (hostport.starts_with("cloudflare.com") && !allowed) named = true;
    }
    check(named, "refusal is attributed to the specific host (auditable)");

    // 3. The kernel half: the child must not be able to skip the broker.
    //    Without this, the allowlist would be advisory -- a compromised child
    //    would simply open its own socket.
    auto direct = run("curl -s -m 8 --noproxy '*' -o /dev/null "
                      "https://1.1.1.1 2>/dev/null");
    check(direct.launched() && direct.exit_code != 0,
          "DIRECT egress (bypassing the broker) is kernel-DENIED");

    // 4. Even a raw socket to an arbitrary port is denied, so the pin is on
    //    egress generally and not just on HTTP clients honouring *_PROXY.
    auto raw = run("nc -w 3 -z 1.1.1.1 443 2>/dev/null");
    check(raw.launched() && raw.exit_code != 0, "raw socket egress DENIED");
#endif

    proxy->stop();
    std::puts("  [PASS] proxy stopped cleanly");

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "T3 egress tests passed" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
