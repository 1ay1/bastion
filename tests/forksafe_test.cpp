// Negative compile tests for the fork-safety type system (forksafe.hpp).
//
// Mirrors cap_test.cpp: the POSITIVE cases run as a normal test, and each
// NEGATIVE case must FAIL to compile. A "this is a compile error" security
// claim is worthless unless something verifies that it really is one.
//
// What is being guaranteed: between fork() and exec(), the child may only use
// trivially-copyable data. Allocating there can deadlock forever on a malloc
// lock held by a thread that does not exist in the child -- and bastion really
// does fork from a multithreaded process (the T3 egress broker's accept
// thread), so this is a live hazard rather than a theoretical one.
#include "bastion/forksafe.hpp"

#include <cstdio>
#include <map>
#include <string>
#include <vector>

using namespace bastion;

// ---------------------------------------------------------------------------
// Negative cases: each MUST be rejected by the compiler.
// ---------------------------------------------------------------------------
#if defined(CASE)

#  if CASE == 1
// A std::string in the child: the classic deadlock. The parent may build it,
// but the child must receive a const char* into the parent's memory instead.
void negative() {
    std::string owned = "allocated";
    ForkChild::check(owned);
}
#  endif

#  if CASE == 2
// A vector is no better -- and this is exactly the shape of the real bug:
// Ruleset holds vectors, so it must be built BEFORE fork and only READ after.
void negative() {
    std::vector<int> v{1, 2, 3};
    ForkChild::check(v);
}
#  endif

#  if CASE == 3
// Passing an allocating argument to a syscall wrapper. The `requires` clause
// rejects the call rather than silently constructing a temporary in the child.
void negative() {
    std::string path = "/tmp/x";
    ForkChild::syscall([](std::string) { return 0; }, path);
}
#  endif

#  if CASE == 4
// ForkChild must be UNFORGEABLE: a caller cannot conjure the token to gain
// access to post-fork-only APIs. Only ForkBoundary may mint one.
void negative() {
    ForkChild tok{};  // private constructor
    (void)tok;
}
#  endif

#  if CASE == 5
// The token is move-only, like Cap<R>: copying it would let post-fork
// authority be duplicated into a context that never forked.
void negative() {
    ForkChild a = ForkBoundary::in_child();
    ForkChild b = a;  // copy constructor is deleted
    (void)b;
}
#  endif

#else
// ---------------------------------------------------------------------------
// Positive cases: these MUST compile and pass.
// ---------------------------------------------------------------------------

struct TrivialAbi {
    int version;
    bool has_net;
    unsigned long mask;
};

static int calls = 0;
static int fake_syscall(int fd, unsigned long flags) {
    ++calls;
    return static_cast<int>(fd + flags);
}

int main() {
    // 1. Trivially-copyable data crosses the boundary freely.
    ForkChild::check(42);
    ForkChild::check(TrivialAbi{10, true, 0xffff});
    static_assert(ForkSafe<TrivialAbi>);
    static_assert(ForkSafe<int>);

    // 2. A raw const char* IS fork-safe: the child may READ memory the parent
    //    allocated (it is copy-on-write); it just may not allocate its own.
    //    This is precisely how paths reach the child in spawn.cpp.
    const std::string parent_owned = "/tmp/workspace";
    const char* borrowed = parent_owned.c_str();
    ForkChild::check(borrowed);
    static_assert(ForkSafe<const char*>);

    // 3. The owning types are correctly classified as unsafe.
    static_assert(!ForkSafe<std::string>);
    static_assert(!ForkSafe<std::vector<int>>);
    static_assert(!ForkSafe<std::map<int, int>>);
    static_assert(AllocatesOnUse<std::string>);

    // 4. Syscalls with fork-safe arguments go through.
    auto tok = ForkBoundary::in_child();
    const int rc = ForkChild::syscall(fake_syscall, 3, 0x10ul);
    static_assert(std::is_same_v<decltype(rc), const int>);
    if (rc != 3 + 0x10 || calls != 1) {
        std::puts("FAIL: syscall forwarding is wrong");
        return 1;
    }

    // 5. The token is move-only (like Cap<R>), so post-fork authority cannot
    //    be silently duplicated.
    static_assert(!std::is_copy_constructible_v<ForkChild>);
    static_assert(std::is_move_constructible_v<ForkChild>);
    auto moved = std::move(tok);
    (void)moved;

    std::puts("all fork-safety tests passed");
    return 0;
}
#endif
