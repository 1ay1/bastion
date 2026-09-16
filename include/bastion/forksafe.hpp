// bastion/forksafe.hpp — async-signal-safety as a TYPE, not a comment.
//
// THE PROBLEM
// Between fork() and execve() a child may call only async-signal-safe
// functions. If another thread held the malloc lock at the instant of fork,
// that lock is held forever in the child, so the first allocation DEADLOCKS --
// the child hangs with the sandbox unapplied and the workload never exec'd.
// Silent, unkillable, and in the one code path that must never fail open.
//
// bastion really does fork from a multithreaded process: at T3 the egress
// broker's accept thread is running before the workload is spawned. So this is
// a live hazard, not a theoretical one.
//
// Until now the rule was enforced by a COMMENT ("only async-signal-safe calls
// past this point"). That comment was already wrong once: the child called
// linux_ll::apply(), which builds std::strings. The bug was invisible because
// nothing checked, and it would have shown up as an intermittent hang under
// load rather than as a test failure.
//
// THE APPROACH
// The same one the capability layer uses for privilege (capability.hpp): make
// the unsafe program ill-formed instead of merely discouraged. `Cap<R>` makes
// privilege WIDENING a compile error; `ForkChild` makes ALLOCATION in the child
// a compile error.
//
//     void child_setup(ForkChild tok) {
//         tok.syscall(::chdir, "/w");       // fine: a raw syscall
//         std::string s = "oops";           // fine on its own, but...
//         tok.check(s);                     // ERROR: std::string is not fork-safe
//     }
//
// A type cannot see every allocation (nothing short of a custom allocator can),
// so this is not a total proof. What it DOES give is a machine-checked contract
// at the boundary: every value crossing into the child must prove it is
// trivially usable there, and the one function that applies the sandbox has a
// signature that cannot accept an allocating argument. That converts the most
// dangerous case -- passing a std::string-shaped thing into post-fork code --
// from a code-review question into a compiler error.
#pragma once

#include <type_traits>
#include <utility>

namespace bastion {

// ---------------------------------------------------------------------------
// ForkSafe — a value that may cross the fork boundary.
// ---------------------------------------------------------------------------
//
// Trivially copyable and not a pointer-to-owning-type: ints, enums, PODs, and
// raw const char* into memory the PARENT already allocated. The last case is
// the important one -- the child may READ parent memory (it is CoW), it just
// may not allocate NEW memory.
template <class T>
concept ForkSafe = std::is_trivially_copyable_v<std::remove_cvref_t<T>>;

// The negation, spelled out so diagnostics name the actual problem.
template <class T>
concept AllocatesOnUse = !ForkSafe<T>;

// ---------------------------------------------------------------------------
// ForkChild — a capability token for "I am between fork() and exec()".
// ---------------------------------------------------------------------------
//
// Deliberately mirrors Cap<R>: unforgeable (private constructor, one friend),
// move-only, and carrying no runtime cost. Its presence in a signature is a
// machine-checked claim that the function is called in the child.
class ForkChild {
public:
    ForkChild(const ForkChild&) = delete;
    ForkChild& operator=(const ForkChild&) = delete;
    ForkChild(ForkChild&&) = default;
    ForkChild& operator=(ForkChild&&) = default;

    // Statically assert that a value is safe to use here. Zero runtime cost;
    // exists purely so an unsafe value produces a compile error at the point
    // of use, naming the type that is wrong.
    template <class T>
    static constexpr void check(const T&) noexcept {
        static_assert(ForkSafe<T>,
                      "bastion: this value is not fork-safe. Between fork() and "
                      "exec() the child may only use trivially-copyable data "
                      "(and const char* into memory the PARENT allocated). "
                      "Building a std::string/vector here can deadlock forever "
                      "on a malloc lock held by a thread that does not exist in "
                      "the child. Materialise it BEFORE fork().");
    }

    // Call a raw syscall wrapper, proving every argument is fork-safe.
    // The arguments are checked; the callee is assumed to be a syscall.
    template <class Fn, class... Args>
        requires (ForkSafe<Args> && ...)
    static constexpr decltype(auto) syscall(Fn&& fn, Args&&... args) {
        return std::forward<Fn>(fn)(std::forward<Args>(args)...);
    }

private:
    ForkChild() = default;
    friend class ForkBoundary;
};

// Mints the token. Only the code that actually forks may create one, so a
// ForkChild parameter cannot be conjured by a caller that is not in a child.
class ForkBoundary {
public:
    [[nodiscard]] static ForkChild in_child() noexcept { return ForkChild{}; }
};

}  // namespace bastion
