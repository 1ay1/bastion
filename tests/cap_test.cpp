// Verifies the compile-time security claims of capability.hpp.
// Negative cases are checked by the build script via -DCASE=n (must NOT compile).
#include "bastion/capability.hpp"

#include <cassert>
#include <cstdio>
#include <type_traits>

using namespace bastion;

// --- static claims ---------------------------------------------------------
static_assert(!std::is_copy_constructible_v<Cap<Right::FsRead>>,
              "capabilities must be unforgeable (no copy)");
static_assert(!std::is_default_constructible_v<Cap<Right::FsRead>>,
              "capabilities must not be summonable from nothing");
static_assert(std::is_move_constructible_v<Cap<Right::FsRead>>,
              "capabilities must be transferable");
static_assert(!std::is_copy_assignable_v<Cap<Right::FsWrite>>);

static_assert(subsumes(Right::FsRead | Right::FsWrite, Right::FsRead));
static_assert(!subsumes(Right::FsRead, Right::FsWrite));
static_assert(!subsumes(Right::FsRead | Right::FsWrite, Right::Unconfined));

static_assert(Readable<Cap<Right::FsRead | Right::FsWrite>>);
static_assert(!Writable<Cap<Right::FsRead>>);
static_assert(Readable<UnconfinedCap> && Writable<UnconfinedCap>,
              "Unconfined must satisfy every requirement");

// A function whose authority requirement is visible in its signature.
static std::string read_with(Cap<Right::FsRead>&& c) {
    return std::string{c.scope()};
}

#if defined(CASE)
// ---- negative cases: each MUST fail to compile ----
void negative() {
    Broker b;
#  if CASE == 1
    // widening read -> read|write
    auto c = b.grant<Right::FsRead>("/w", Witness{"t"});
    auto bad = std::move(c).derive<Right::FsRead | Right::FsWrite>();
#  elif CASE == 2
    // read-only cap passed where write authority is required
    auto c = b.grant<Right::FsRead>("/w", Witness{"t"});
    static_assert(Writable<decltype(c)>);
#  elif CASE == 3
    // copying a capability
    auto c = b.grant<Right::FsRead>("/w", Witness{"t"});
    auto dup = c;
#  elif CASE == 4
    // laundering Unconfined in with ordinary rights to hide the bypass
    auto c = b.grant<Right::FsRead | Right::Unconfined>("/w", Witness{"t"});
#  endif
}
#else

int main() {
    Broker b;

    // 1. grants carry provenance
    auto rw = b.grant<Right::FsRead | Right::FsWrite>(
        "/tmp/bastion-workspace", Witness{"workspace root"});
    assert(rw.provenance().find("workspace root") != std::string_view::npos);
    assert(rw.provenance().find("cap_test.cpp") != std::string_view::npos);

    // 2. narrowing is allowed, and preserves scope + provenance
    auto ro = std::move(rw).derive<Right::FsRead>();
    assert(ro.scope() == "/tmp/bastion-workspace");
    assert(Readable<decltype(ro)> && !Writable<decltype(ro)>);

    // 3. authority is usable where required
    auto s = read_with(std::move(ro));
    assert(!s.empty());

    // 4. the bypass is recorded, not silent
    auto yolo = b.grant_unconfined(Witness{"user ran --yolo"});
    assert(yolo.provenance().starts_with("UNCONFINED:"));
    assert(yolo.provenance().find("--yolo") != std::string_view::npos);

    // 5. Unconfined can still be attenuated back down (on-ramp to tight policy)
    auto narrowed = std::move(yolo).derive<Right::FsRead>();
    assert(!Writable<decltype(narrowed)>);
    assert(narrowed.provenance().starts_with("UNCONFINED:"));

    std::puts("all capability tests passed");
    return 0;
}
#endif
