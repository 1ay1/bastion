#include "bastion/proxy.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <thread>
#include <utility>

namespace bastion {

namespace {

std::string to_lower(std::string_view s) {
    std::string out{s};
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    return out;
}

// Wildcard host match. `*.example.com` matches one-or-more leading labels, and
// deliberately does NOT match the bare apex: granting "*.example.com" should not
// silently include "example.com" (list it explicitly if you want it).
bool host_matches(std::string_view pattern, std::string_view host) {
    if (pattern == "*") return true;
    if (pattern == host) return true;
    if (pattern.starts_with("*.")) {
        auto suffix = pattern.substr(1);  // ".example.com"
        return host.size() > suffix.size() && host.ends_with(suffix);
    }
    return false;
}

bool set_nonblocking(int fd) {
    int f = ::fcntl(fd, F_GETFL, 0);
    return f >= 0 && ::fcntl(fd, F_SETFL, f | O_NONBLOCK) == 0;
}

// Connect to host:port, honouring every resolved address in turn.
int dial(const std::string& host, std::uint16_t port) {
    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    const std::string port_s = std::to_string(port);
    struct addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res) != 0) return -1;

    int fd = -1;
    for (auto* p = res; p; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(res);
    return fd;
}

// Pump bytes both ways until either side closes.
void splice(int a, int b) {
    set_nonblocking(a);
    set_nonblocking(b);
    char buf[16384];
    struct pollfd fds[2];
    fds[0].fd = a;
    fds[1].fd = b;
    for (;;) {
        fds[0].events = POLLIN;
        fds[1].events = POLLIN;
        if (::poll(fds, 2, 120'000) <= 0) return;
        for (int i = 0; i < 2; ++i) {
            if ((fds[i].revents & (POLLIN | POLLHUP | POLLERR)) == 0) continue;
            const int from = fds[i].fd;
            const int to = fds[1 - i].fd;
            ssize_t n = ::recv(from, buf, sizeof buf, 0);
            if (n <= 0) {
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
                return;
            }
            ssize_t off = 0;
            while (off < n) {
                ssize_t w = ::send(to, buf + off, static_cast<std::size_t>(n - off), 0);
                if (w > 0) { off += w; continue; }
                if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    struct pollfd wf { to, POLLOUT, 0 };
                    if (::poll(&wf, 1, 30'000) <= 0) return;
                    continue;
                }
                return;
            }
        }
    }
}

}  // namespace

bool EgressRule::matches(std::string_view h, std::uint16_t p) const {
    if (port != 0 && port != p) return false;
    return host_matches(host, h);
}

EgressRule parse_egress_rule(std::string_view spec) {
    EgressRule r;
    auto colon = spec.rfind(':');
    // Only treat a trailing :NNN as a port (guards IPv6-ish inputs).
    if (colon != std::string_view::npos &&
        spec.find_first_not_of("0123456789", colon + 1) == std::string_view::npos &&
        colon + 1 < spec.size()) {
        r.host = to_lower(spec.substr(0, colon));
        unsigned v = 0;
        for (char c : spec.substr(colon + 1)) v = v * 10 + static_cast<unsigned>(c - '0');
        r.port = static_cast<std::uint16_t>(v > 65535 ? 0 : v);
    } else {
        r.host = to_lower(spec);
        r.port = 0;
    }
    return r;
}

struct EgressProxy::Impl {
    std::vector<EgressRule> allow;
    int listen_fd = -1;
    std::thread accept_thread;
    std::atomic<bool> running{false};
    ProxyStats stats;
    std::mutex attempts_mu;
    std::vector<EgressAttempt> attempts;

    void record(std::string host, std::uint16_t port, bool ok) {
        if (ok) stats.allowed.fetch_add(1, std::memory_order_relaxed);
        else stats.denied.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard lk{attempts_mu};
        attempts.push_back(EgressAttempt{std::move(host), port, ok});
    }

    [[nodiscard]] bool permitted(const std::string& host, std::uint16_t port) const {
        for (const auto& r : allow) {
            if (r.matches(host, port)) return true;
        }
        return false;
    }

    void serve_conn(int client);
    void run();
};

void EgressProxy::Impl::serve_conn(int client) {
    // Read the CONNECT request line. We never terminate TLS: the allowlist is
    // enforced on the requested authority, then bytes are tunnelled opaquely.
    // No CA to install, no certificate trust weakened, no plaintext exposure.
    std::string req;
    req.reserve(1024);
    char c = 0;
    while (req.size() < 8192) {
        ssize_t n = ::recv(client, &c, 1, 0);
        if (n <= 0) { ::close(client); return; }
        req += c;
        if (req.size() >= 4 && req.compare(req.size() - 4, 4, "\r\n\r\n") == 0) break;
    }

    static constexpr std::string_view kBadReq =
        "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
    if (!req.starts_with("CONNECT ")) {
        // Only CONNECT is supported. Plain HTTP would mean bastion handling
        // request bodies, which is a much larger attack surface for no gain --
        // agents talk to HTTPS endpoints.
        ::send(client, kBadReq.data(), kBadReq.size(), 0);
        ::close(client);
        return;
    }

    auto sp = req.find(' ', 8);
    if (sp == std::string::npos) {
        ::send(client, kBadReq.data(), kBadReq.size(), 0);
        ::close(client);
        return;
    }
    const std::string authority = req.substr(8, sp - 8);
    auto colon = authority.rfind(':');
    std::string host = to_lower(
        colon == std::string::npos ? authority : authority.substr(0, colon));
    std::uint16_t port = 443;
    if (colon != std::string::npos) {
        port = static_cast<std::uint16_t>(std::atoi(authority.c_str() + colon + 1));
    }

    if (!permitted(host, port)) {
        record(host, port, false);
        // 403 with a body the agent can actually act on -- the same principle
        // as a filesystem denial carrying a remedy (DESIGN.md §4.1).
        const std::string body =
            "bastion: egress to " + host + ":" + std::to_string(port) +
            " is not allowlisted.\n"
            "remedy: bastion run -t t3 --net " + host + ":" +
            std::to_string(port) + " -- <cmd>\n";
        const std::string resp =
            "HTTP/1.1 403 Forbidden\r\nContent-Length: " +
            std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        ::send(client, resp.data(), resp.size(), 0);
        ::close(client);
        return;
    }

    int upstream = dial(host, port);
    if (upstream < 0) {
        record(host, port, true);  // permitted by policy; upstream just failed
        static constexpr std::string_view kBadGw =
            "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
        ::send(client, kBadGw.data(), kBadGw.size(), 0);
        ::close(client);
        return;
    }

    record(host, port, true);
    static constexpr std::string_view kOk = "HTTP/1.1 200 Connection Established\r\n\r\n";
    ::send(client, kOk.data(), kOk.size(), 0);
    splice(client, upstream);
    ::close(upstream);
    ::close(client);
}

void EgressProxy::Impl::run() {
    while (running.load(std::memory_order_relaxed)) {
        struct pollfd pf { listen_fd, POLLIN, 0 };
        int pr = ::poll(&pf, 1, 200);
        if (pr <= 0) continue;
        int client = ::accept(listen_fd, nullptr, nullptr);
        if (client < 0) continue;
        std::thread{[this, client] { serve_conn(client); }}.detach();
    }
}

std::unique_ptr<EgressProxy> EgressProxy::start(std::vector<EgressRule> allow,
                                                std::string& error) {
    auto impl = std::make_unique<Impl>();
    impl->allow = std::move(allow);

    impl->listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (impl->listen_fd < 0) {
        error = std::string{"socket: "} + std::strerror(errno);
        return nullptr;
    }
    int one = 1;
    ::setsockopt(impl->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;  // ephemeral: concurrent sessions never collide
    // htonl/ntohs are MACROS on macOS, so they cannot be ::-qualified.
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // loopback ONLY
    if (::bind(impl->listen_fd, reinterpret_cast<struct sockaddr*>(&addr),
               sizeof addr) != 0) {
        error = std::string{"bind: "} + std::strerror(errno);
        ::close(impl->listen_fd);
        return nullptr;
    }
    if (::listen(impl->listen_fd, 64) != 0) {
        error = std::string{"listen: "} + std::strerror(errno);
        ::close(impl->listen_fd);
        return nullptr;
    }

    struct sockaddr_in bound {};
    socklen_t blen = sizeof bound;
    if (::getsockname(impl->listen_fd, reinterpret_cast<struct sockaddr*>(&bound),
                      &blen) != 0) {
        error = "getsockname failed";
        ::close(impl->listen_fd);
        return nullptr;
    }

    auto proxy = std::unique_ptr<EgressProxy>(new EgressProxy());
    proxy->port_ = ntohs(bound.sin_port);
    proxy->impl_ = std::move(impl);
    proxy->impl_->running.store(true, std::memory_order_relaxed);
    proxy->impl_->accept_thread = std::thread{[p = proxy->impl_.get()] { p->run(); }};
    return proxy;
}

void EgressProxy::stop() {
    if (!impl_) return;
    impl_->running.store(false, std::memory_order_relaxed);
    if (impl_->accept_thread.joinable()) impl_->accept_thread.join();
    if (impl_->listen_fd >= 0) {
        ::close(impl_->listen_fd);
        impl_->listen_fd = -1;
    }
}

EgressProxy::~EgressProxy() { stop(); }

std::vector<EgressAttempt> EgressProxy::take_attempts() {
    if (!impl_) return {};
    std::lock_guard lk{impl_->attempts_mu};
    return std::exchange(impl_->attempts, {});
}

std::uint64_t EgressProxy::allowed_count() const noexcept {
    return impl_ ? impl_->stats.allowed.load(std::memory_order_relaxed) : 0;
}
std::uint64_t EgressProxy::denied_count() const noexcept {
    return impl_ ? impl_->stats.denied.load(std::memory_order_relaxed) : 0;
}

}  // namespace bastion
