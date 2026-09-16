#include "bastion/signal_forward.hpp"

#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstddef>
#include <iterator>

namespace bastion {

namespace {

// The signals an agent harness actually sends. SIGHUP is included so a closed
// pty does not leave the subtree running detached.
constexpr int kSignals[] = {SIGTERM, SIGINT, SIGHUP, SIGQUIT};
constexpr std::size_t kCount = std::size(kSignals);

// Handler state must be at namespace scope and sig_atomic_t: a signal can
// arrive between any two instructions, so nothing here may allocate, lock, or
// be half-written.
volatile std::sig_atomic_t g_child_pgid = 0;

struct sigaction g_saved[kCount];

extern "C" void forward_to_child(int sig) {
    // ASYNC-SIGNAL-SAFE: only kill(2) and a read of sig_atomic_t. errno is
    // saved and restored because kill() can clobber it, and the interrupted
    // code may be mid-way through its own errno check.
    const int saved_errno = errno;
    const pid_t pgid = static_cast<pid_t>(g_child_pgid);
    if (pgid > 0) {
        ::kill(-pgid, sig);  // negative pid => the entire process group
    }
    errno = saved_errno;
}

}  // namespace

SignalForwarder::SignalForwarder(pid_t child_pgid) noexcept {
    g_child_pgid = static_cast<std::sig_atomic_t>(child_pgid);
    for (std::size_t i = 0; i < kCount; ++i) {
        // `struct sigaction sa {}` is ambiguous where sigaction is ALSO a
        // function (it is, on macOS): clang parses the braces as a function
        // declarator and reports "expected unqualified-id". Naming the type
        // without the elaborated-specifier, then value-initialising, is
        // unambiguous on both platforms.
        struct sigaction sa;
        sa = {};
        sa.sa_handler = forward_to_child;
        ::sigemptyset(&sa.sa_mask);
        // Deliberately NOT SA_RESTART: waitpid() should return EINTR so the
        // supervisor notices promptly rather than blocking until the workload
        // happens to exit on its own. Both callers retry on EINTR, so the only
        // effect is that they get to re-check their own state.
        sa.sa_flags = 0;
        ::sigaction(kSignals[i], &sa, &g_saved[i]);
    }
}

SignalForwarder::~SignalForwarder() {
    for (std::size_t i = 0; i < kCount; ++i) {
        ::sigaction(kSignals[i], &g_saved[i], nullptr);
    }
    g_child_pgid = 0;
}

}  // namespace bastion
