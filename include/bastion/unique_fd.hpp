// bastion/unique_fd.hpp — an owned file descriptor that cannot leak.
//
// WHY THIS EXISTS
// bastion closes descriptors by hand in ~47 places across the backends, and
// every one of them is a chance to leak on an early return. That is not
// hypothetical: an audit found a real leak on the macOS status-pipe path, where
// pipe() succeeds but fcntl() fails and the function returns without closing
// either end. Descriptors matter more here than in ordinary code -- a leaked fd
// is not just a resource, it is AUTHORITY. Access rights attach to the open
// file description, so an fd that outlives its scope can carry access straight
// through a sandbox boundary (see close_inherited_fds, a MEASURED escape).
//
// So ownership becomes a type. UniqueFd closes exactly once, on every path,
// including exceptions and early returns; -1 is the only "empty" state and it
// is never closed.
//
// FORK-SAFE BY CONSTRUCTION: the whole type is trivially... almost. It holds
// one int and its destructor calls close(2), which IS async-signal-safe, so it
// is legal in the post-fork child. But it is deliberately NOT ForkSafe
// (forksafe.hpp), because copying an owning handle across a fork boundary would
// mean two owners and a double close. In the child, pass the raw int via get().
#pragma once

#include <unistd.h>

#include <utility>

namespace bastion {

class UniqueFd {
public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}

    UniqueFd(const UniqueFd&) = delete;             // unforgeable: no copies
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& o) noexcept : fd_(std::exchange(o.fd_, -1)) {}
    UniqueFd& operator=(UniqueFd&& o) noexcept {
        if (this != &o) {
            reset();
            fd_ = std::exchange(o.fd_, -1);
        }
        return *this;
    }

    ~UniqueFd() { reset(); }

    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
    explicit operator bool() const noexcept { return valid(); }

    // Relinquish ownership: the caller is now responsible for closing.
    // Used where a descriptor is deliberately handed to another owner, e.g.
    // sent over SCM_RIGHTS or stored in a long-lived struct.
    [[nodiscard]] int release() noexcept { return std::exchange(fd_, -1); }

    void reset(int fd = -1) noexcept {
        if (fd_ >= 0 && fd_ != fd) {
            // close(2) is async-signal-safe, so this is legal even in a child
            // between fork() and exec(). EINTR is deliberately NOT retried:
            // on Linux the descriptor is always released regardless, and
            // retrying can close a descriptor another thread has since opened.
            ::close(fd_);
        }
        fd_ = fd;
    }

private:
    int fd_ = -1;
};

}  // namespace bastion
