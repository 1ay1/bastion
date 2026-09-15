// bastion/proxy.hpp — T3 egress broker: real per-host network allowlisting.
//
// WHY THIS EXISTS
// Neither kernel backend can filter egress by hostname. Seatbelt matches
// sockets, Landlock matches ports. So at T2 a single `--net` grant means "all
// outbound", which `bastion explain` has to warn about. That is the largest
// honest gap in the T2 boundary.
//
// T3 closes it by composing the two layers, each doing what it is good at:
//
//   kernel : deny ALL egress except one loopback port   (unforgeable)
//   proxy  : accept on that port, enforce the allowlist (expressive)
//
// Measured on macOS 26.6.2 (tools/probe/egress_probe.c) -- this is the whole
// design in one table:
//
//   profile                                    :8888   :9999   1.1.1.1:443
//   (deny default)                             EPERM   EPERM   EPERM
//   + (allow network-outbound (remote ip       CONN    EPERM   EPERM
//         "localhost:8888"))
//   + (allow network-outbound)                 refused refused CONNECTED
//
// Row 2 is the T3 primitive: the proxy port is reachable and nothing else is,
// so the proxy is not a politeness the workload can route around -- the kernel
// makes it the only way out. A compromised child cannot open its own socket.
//
// The allowlist is enforced on the CONNECT target for tunnelled TLS, so we
// never terminate or inspect TLS: bastion sees the hostname the client asked
// for and either opens the tunnel or refuses it. No CA to install, no
// certificate trust to weaken, no plaintext.
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace bastion {

struct EgressRule {
    std::string host;      // "api.example.com", or "*.example.com"
    std::uint16_t port{};  // 0 = any port

    [[nodiscard]] bool matches(std::string_view h, std::uint16_t p) const;
};

struct ProxyStats {
    std::atomic<std::uint64_t> allowed{0};
    std::atomic<std::uint64_t> denied{0};
};

// A denied connection attempt, recorded for the audit ledger.
struct EgressAttempt {
    std::string host;
    std::uint16_t port{};
    bool allowed{};
};

class EgressProxy {
public:
    // Binds 127.0.0.1:0 (an ephemeral port) so concurrent bastion sessions
    // never collide, then serves until stop(). Returns the bound port.
    [[nodiscard]] static std::unique_ptr<EgressProxy> start(
        std::vector<EgressRule> allow, std::string& error);

    ~EgressProxy();
    EgressProxy(const EgressProxy&) = delete;
    EgressProxy& operator=(const EgressProxy&) = delete;

    [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
    void stop();

    // Drains the attempts seen so far. Feeds `bastion synthesize`, so an
    // observed run proposes exactly the hosts it actually used.
    [[nodiscard]] std::vector<EgressAttempt> take_attempts();

    [[nodiscard]] std::uint64_t allowed_count() const noexcept;
    [[nodiscard]] std::uint64_t denied_count() const noexcept;

private:
    EgressProxy() = default;

    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::uint16_t port_ = 0;
};

// Parse "host:port" / "host" / "*.example.com:443" into a rule.
[[nodiscard]] EgressRule parse_egress_rule(std::string_view spec);

}  // namespace bastion
