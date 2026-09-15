// bastion/policy.hpp — typestate-tracked policy construction.
//
//     Policy  --seal()-->  Sealed  --spawn()-->  Spawned
//
// These are distinct TYPES, not an enum plus a flag. `allow()` does not exist on
// Sealed, which mirrors the kernel's own semantics (a Landlock ruleset is
// immutable once enforced) instead of re-checking it at runtime.
#pragma once

#include "bastion/capability.hpp"
#include "bastion/tier.hpp"

#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace bastion {

struct Rule {
    Right right{};
    std::string scope;
    std::string provenance;
};

class Sealed;

// ---------------------------------------------------------------------------
// Policy — mutable builder stage.
//
// Builder methods consume `&&` and return a Policy BY VALUE. Returning
// `Policy&&` instead would be a live footgun: the natural non-chained usage
//
//     p = std::move(p).allow(...);      // self-move-assignment!
//
// silently clears the rule vector, producing an EMPTY policy that still looks
// valid. That defect shipped here once and the CLI demo caught it -- writes to
// the workspace were denied and `explain` printed "rules (0)". Returning by
// value makes the temporary a distinct object, so both styles are safe.
// ---------------------------------------------------------------------------

class Policy {
public:
    explicit Policy(Tier t = Tier::Kernel) : tier_(t) {}

    // Path-set authority: paths are canonicalized here, and the symlink
    // ancestry of each is recorded so backends can authorize traversal
    // metadata. Both are required for correctness — measured, see DESIGN.md
    // §2.1: an un-canonicalized rule silently UNDER-grants on macOS, while a
    // symlink farm silently OVER-grants under bwrap.
    [[nodiscard]] Policy allow(Right r, const std::filesystem::path& p,
                               std::string why) && {
        std::error_code ec;
        auto canon = std::filesystem::weakly_canonical(p, ec);
        rules_.push_back(Rule{r, (ec ? p : canon).string(), std::move(why)});
        if (!ec && canon != p) {
            // Authorize metadata on the as-written path so traversal via the
            // symlink resolves (macOS Seatbelt evaluates the path as written).
            rules_.push_back(Rule{Right::FsRead, p.string(),
                                  "symlink traversal for " + canon.string()});
        }
        return std::move(*this);
    }

    [[nodiscard]] Policy allow_egress(std::string host_port, std::string why) && {
        rules_.push_back(Rule{Right::NetEgress, std::move(host_port), std::move(why)});
        return std::move(*this);
    }

    [[nodiscard]] Policy at_tier(Tier t) && {
        tier_ = t;
        return std::move(*this);
    }

    // ---- The bypass, as a capability rather than a power switch -----------
    //
    // This is what `--yolo` / `--dangerously-skip-permissions` maps to. Note
    // what it does NOT do: it does not disable bastion, does not drop below T1,
    // and does not stop the audit log. The user gets their frictionless flow;
    // the system keeps the ledger (DESIGN.md §1).
    [[nodiscard]] Policy unconfined(UnconfinedCap&& cap) && {
        rules_.push_back(Rule{Right::Unconfined, "*", std::string{cap.provenance()}});
        unconfined_ = true;
        if (tier_ < Tier::Advisory) tier_ = Tier::Advisory;
        return std::move(*this);
    }

    [[nodiscard]] Sealed seal() &&;

    [[nodiscard]] Tier tier() const noexcept { return tier_; }
    [[nodiscard]] const std::vector<Rule>& rules() const noexcept { return rules_; }
    [[nodiscard]] bool is_unconfined() const noexcept { return unconfined_; }

private:
    friend class Sealed;
    Tier tier_;
    std::vector<Rule> rules_;
    bool unconfined_ = false;
};

// ---------------------------------------------------------------------------
// Sealed — immutable. No allow() here, by construction.
// ---------------------------------------------------------------------------

class Sealed {
public:
    [[nodiscard]] Tier tier() const noexcept { return tier_; }
    [[nodiscard]] const std::vector<Rule>& rules() const noexcept { return rules_; }
    [[nodiscard]] bool is_unconfined() const noexcept { return unconfined_; }

    // Evaluate without enforcing. Identical code path at every tier — this is
    // the mechanism behind "lowering a tier never lowers observability", and
    // it is what lets a user run wide-open for a week and then ask bastion to
    // synthesize the minimal policy that would have sufficed.
    [[nodiscard]] AuditRecord evaluate(std::string_view op,
                                       std::string_view target) const;

    // Human-readable statement of the REAL boundary, including which requested
    // rights the active backend cannot actually enforce on this machine.
    [[nodiscard]] std::string explain() const;

private:
    friend class Policy;
    Sealed(Tier t, std::vector<Rule> r, bool unconf)
        : tier_(t), rules_(std::move(r)), unconfined_(unconf) {}

    Tier tier_;
    std::vector<Rule> rules_;
    bool unconfined_;
};

inline Sealed Policy::seal() && {
    return Sealed{tier_, std::move(rules_), unconfined_};
}

}  // namespace bastion
