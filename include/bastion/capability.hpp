// bastion/capability.hpp — unforgeable, move-only, monotonically attenuating
// authority tokens.
//
// Design rules enforced *by the compiler*, not by review:
//   1. A Cap cannot be default-constructed, copied, or forged. Only Broker mints.
//   2. Attenuation is monotone: derive() to a wider right set is ill-formed.
//   3. Authority is visible in the signature. A function that writes takes
//      Cap<Right::FsWrite>&&; ambient authority is unreachable by accident.
//   4. Unconfined requires a Witness, so the bypass leaves a record by
//      construction (DESIGN.md §1).
#pragma once

#include <bit>
#include <concepts>
#include <cstdint>
#include <source_location>
#include <string>
#include <string_view>
#include <utility>

namespace bastion {

// ---------------------------------------------------------------------------
// Rights
// ---------------------------------------------------------------------------

enum class Right : std::uint32_t {
    None = 0,
    FsRead = 1u << 0,
    FsWrite = 1u << 1,
    FsExec = 1u << 2,
    NetEgress = 1u << 3,
    NetBind = 1u << 4,
    DeviceRead = 1u << 5,
    DeviceWrite = 1u << 6,
    ProcSpawn = 1u << 7,
    Ipc = 1u << 8,
    Unconfined = 1u << 31,
};

consteval Right operator|(Right a, Right b) noexcept {
    return static_cast<Right>(std::to_underlying(a) | std::to_underlying(b));
}
constexpr Right operator&(Right a, Right b) noexcept {
    return static_cast<Right>(std::to_underlying(a) & std::to_underlying(b));
}
constexpr bool any(Right r) noexcept { return std::to_underlying(r) != 0; }

// Subset test: is `sub` wholly contained in `super`?
//
// Unconfined is the TOP of the lattice: it subsumes every right, so an
// Unconfined cap satisfies every Authorizes<> requirement and can be attenuated
// down to any narrower set. Without this, the total-bypass capability would
// paradoxically authorize nothing (bit 31 has no overlap with FsRead etc.).
constexpr bool subsumes(Right super, Right sub) noexcept {
    if (std::to_underlying(super & Right::Unconfined) != 0) return true;
    return (std::to_underlying(super) & std::to_underlying(sub)) == std::to_underlying(sub);
}

constexpr int right_count(Right r) noexcept {
    return std::popcount(std::to_underlying(r));
}

// ---------------------------------------------------------------------------
// Witness — the audit record that makes a grant explainable.
// ---------------------------------------------------------------------------

struct Witness {
    std::string reason;
    std::source_location where;

    explicit Witness(std::string why,
                     std::source_location loc = std::source_location::current())
        : reason(std::move(why)), where(loc) {}
};

// ---------------------------------------------------------------------------
// Cap<R> — authority for exactly the right set R.
// ---------------------------------------------------------------------------

class Broker;

template <Right R>
class Cap {
public:
    static constexpr Right rights = R;

    Cap(const Cap&) = delete;             // unforgeable: no copies
    Cap& operator=(const Cap&) = delete;
    Cap(Cap&&) noexcept = default;        // transferable
    Cap& operator=(Cap&&) noexcept = default;

    // Monotone attenuation. Widening is a hard compile error, so privilege
    // cannot creep along a call chain (DESIGN.md §5).
    template <Right Sub>
    [[nodiscard]] Cap<Sub> derive() && noexcept {
        static_assert(subsumes(R, Sub),
                      "bastion: derive() may only narrow authority. The requested "
                      "right set is not a subset of this capability's rights.");
        return Cap<Sub>{scope_, std::move(provenance_)};
    }

    [[nodiscard]] std::string_view scope() const noexcept { return scope_; }
    [[nodiscard]] std::string_view provenance() const noexcept { return provenance_; }

private:
    friend class Broker;
    template <Right> friend class Cap;

    Cap(std::string scope, std::string provenance)
        : scope_(std::move(scope)), provenance_(std::move(provenance)) {}

    std::string scope_;       // path / host / device pattern this authorizes
    std::string provenance_;  // why it exists — flows into the audit log
};

// A total-authority capability is just Cap<Unconfined>. It is a *type*, so it is
// greppable and reviewable, and it still carries provenance.
using UnconfinedCap = Cap<Right::Unconfined>;

// ---------------------------------------------------------------------------
// Concepts — express requirements on authority at the API surface.
// ---------------------------------------------------------------------------

template <typename C, Right Need>
concept Authorizes = subsumes(C::rights, Need);

template <typename C>
concept Readable = Authorizes<C, Right::FsRead>;

template <typename C>
concept Writable = Authorizes<C, Right::FsWrite>;

// ---------------------------------------------------------------------------
// Broker — the sole minter of authority.
// ---------------------------------------------------------------------------

class Broker {
public:
    Broker() = default;
    Broker(const Broker&) = delete;
    Broker& operator=(const Broker&) = delete;

    template <Right R>
    [[nodiscard]] Cap<R> grant(std::string scope, const Witness& w) {
        static_assert(!subsumes(R, Right::Unconfined) || R == Right::Unconfined,
                      "bastion: Unconfined may not be bundled with other rights; "
                      "request it alone so the bypass stays visible.");
        return Cap<R>{std::move(scope), describe(w)};
    }

    // Total bypass. Deliberately separate, deliberately noisy, still recorded:
    // "easier flow" without ever becoming "you're on your own" (DESIGN.md §1).
    [[nodiscard]] UnconfinedCap grant_unconfined(const Witness& w) {
        return UnconfinedCap{"*", "UNCONFINED: " + describe(w)};
    }

private:
    static std::string describe(const Witness& w) {
        return w.reason + " @" + w.where.file_name() + ":" +
               std::to_string(w.where.line());
    }
};

}  // namespace bastion
