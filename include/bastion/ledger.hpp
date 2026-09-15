// bastion/ledger.hpp — the audit ledger and policy synthesizer.
//
// This is what makes DESIGN.md §1 pay off. Because a wide-open session is still
// fully recorded, the bypass becomes the ON-RAMP to a tight policy instead of
// the end of observability:
//
//     bastion run --yolo -- <your build>      # frictionless, fully logged
//     bastion synthesize                      # -> minimal policy that suffices
//
// The user in the field report had the opposite experience: turning the sandbox
// off gave them nothing to work from, so they were told "you're on your own".
#pragma once

#include "bastion/policy.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace bastion {

// Append-only audit log. Written even at T0 and under an Unconfined grant.
class Ledger {
public:
    explicit Ledger(std::string path) : path_(std::move(path)) {}

    void record(const AuditRecord& rec);

    // Flush to disk as JSON Lines. Returns an error string, or empty on success.
    [[nodiscard]] std::string flush();

    [[nodiscard]] const std::vector<AuditRecord>& records() const noexcept {
        return records_;
    }

    [[nodiscard]] static std::optional<Ledger> load(const std::string& path,
                                                    std::string& error);

private:
    std::string path_;
    std::vector<AuditRecord> records_;
};

// ---------------------------------------------------------------------------
// Synthesis
// ---------------------------------------------------------------------------

struct SynthesisOptions {
    // Collapse sibling paths into their parent directory once this many
    // distinct children under it have been observed. Keeps the synthesized
    // policy readable instead of emitting a rule per file.
    std::size_t coalesce_threshold = 3;

    // Never widen a grant to one of these, even if the evidence suggests it.
    // A synthesized policy must not casually hand over $HOME or /.
    std::vector<std::string> never_widen_to = {
        "/", "/Users", "/home", "/etc", "/private/etc", "/usr", "/var",
        "/private/var", "/System", "/Library",
    };
};

struct Synthesis {
    std::vector<Rule> rules;
    std::vector<std::string> notes;
    std::size_t observations = 0;
    std::size_t denials_seen = 0;

    // Render as a policy file the user can review, edit and commit.
    [[nodiscard]] std::string to_toml() const;
    // Render as C++ using the builder API.
    [[nodiscard]] std::string to_cpp() const;
};

// Derive the minimal policy that would have allowed everything observed.
//
// Only ALLOWED and WOULD-DENY operations become grants: an operation that was
// actually denied and that the program survived is not evidence of a need.
[[nodiscard]] Synthesis synthesize(const Ledger& ledger,
                                   const SynthesisOptions& opts = {});

}  // namespace bastion
