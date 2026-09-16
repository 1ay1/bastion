// Negative compile tests for the invariant types: Result<T> and UniqueFd.
//
// Both exist to make a class of BUG unrepresentable rather than merely
// discouraged, so both need the same treatment as cap_test.cpp: prove the
// compiler actually rejects the shapes we claim are impossible.
//
// What is being guaranteed:
//   Result<T>  -- you cannot reach a value that was never produced, and you
//                 cannot build "succeeded, but here is an error".
//   UniqueFd   -- a descriptor has exactly one owner, so it cannot be closed
//                 twice or leaked on an early return. Descriptors are
//                 AUTHORITY here: rights attach to the open file description,
//                 so a leaked fd carries access past a sandbox boundary.
#include "bastion/result.hpp"
#include "bastion/unique_fd.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <string>
#include <utility>

using namespace bastion;

#if defined(CASE)

#  if CASE == 1
// A Result must be consumed. Ignoring one means ignoring a failure, which in
// this codebase means running unconfined.
Result<int> make() { return ok(42); }
void negative() {
    make();  // [[nodiscard]] -- and -Werror makes it fatal
}
#  endif

#  if CASE == 2
// An Error cannot be silently converted to the success type: "failed" and
// "succeeded with a default value" must stay distinguishable.
void negative() {
    Result<int> r = fail("nope");
    int v = r;  // no implicit unwrap
    (void)v;
}
#  endif

#  if CASE == 3
// A descriptor has ONE owner. Copying would double-close, which at best
// corrupts an unrelated descriptor opened in the meantime.
void negative() {
    UniqueFd a{::open("/dev/null", O_RDONLY)};
    UniqueFd b = a;  // copy constructor deleted
    (void)b;
}
#  endif

#  if CASE == 4
// Nor by assignment.
void negative() {
    UniqueFd a{::open("/dev/null", O_RDONLY)};
    UniqueFd b;
    b = a;  // copy assignment deleted
}
#  endif

#  if CASE == 5
// A raw int must not silently become an owning handle: that is how a
// descriptor ends up with two owners, one of which does not know it.
void take(UniqueFd) {}
void negative() {
    int raw = ::open("/dev/null", O_RDONLY);
    take(raw);  // constructor is explicit
}
#  endif

#else
// ---------------------------------------------------------------------------
// Positive cases.
// ---------------------------------------------------------------------------

static int failures = 0;
static void check(bool c, const char* what) {
    std::printf("  [%s] %s\n", c ? "PASS" : "FAIL", what);
    if (!c) ++failures;
}

int main() {
    std::puts("== Result<T> ==");
    {
        Result<int> good = ok(7);
        check(good.ok() && good.value() == 7, "a value round-trips");

        Result<int> bad = fail("disk on fire");
        check(!bad.ok(), "a failure is not ok()");
        check(bad.error() == "disk on fire", "the reason survives");

        // The whole point: there is no fourth state. A Result is a value XOR a
        // reason, so "ok but with an error" cannot be constructed at all.
        check(good.ok() != bad.ok(), "value and error are mutually exclusive");

        // value_or is the safe read for callers that genuinely have a default.
        check(bad.value_or(-1) == -1, "value_or falls back on failure");
        check(good.value_or(-1) == 7, "value_or passes through on success");
    }

    std::puts("\n== Result<void> / Status ==");
    {
        Status s = ok();
        check(s.ok(), "a bare success");

        Status f = fail("could not apply policy");
        check(!f.ok() && f.error() == "could not apply policy",
              "a failure carries its reason");
    }

    std::puts("\n== UniqueFd ==");
    {
        UniqueFd empty;
        check(!empty.valid() && empty.get() == -1,
              "default-constructed is empty, and -1 is never closed");

        UniqueFd fd{::open("/dev/null", O_RDONLY)};
        check(fd.valid(), "wraps a real descriptor");
        const int raw = fd.get();

        // Moving transfers ownership: exactly one owner at all times.
        UniqueFd moved = std::move(fd);
        check(moved.get() == raw, "move transfers the descriptor");
        check(!fd.valid(), "the moved-from handle is empty, so it won't close");

        // release() hands ownership to the caller -- used where an fd is
        // deliberately given away (SCM_RIGHTS, or a child that must outlive
        // the scope).
        const int taken = moved.release();
        check(taken == raw && !moved.valid(), "release yields ownership");
        ::close(taken);

        // reset() closes eagerly and is idempotent.
        UniqueFd r{::open("/dev/null", O_RDONLY)};
        r.reset();
        check(!r.valid(), "reset closes and empties");
        r.reset();  // must not double-close
        check(!r.valid(), "reset is idempotent");
    }

    std::puts("\n== no descriptor leaks across many scopes ==");
    {
        // If UniqueFd leaked, this would exhaust the fd table long before the
        // loop ended. Measuring the fd number is a cheap proxy for "nothing
        // accumulated".
        int first = -1, last = -1;
        for (int i = 0; i < 200; ++i) {
            UniqueFd f{::open("/dev/null", O_RDONLY)};
            if (i == 0) first = f.get();
            last = f.get();
        }
        check(first == last, "200 scoped descriptors reuse the same slot");
    }

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "invariant types verified" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
#endif
