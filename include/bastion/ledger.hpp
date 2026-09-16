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
    //
    // Rotates first when the file exceeds max_bytes: the current ledger is
    // renamed to <path>.1 (replacing any previous .1) and a fresh one started.
    // Append-only with no bound means a long-lived agent host grows the file
    // forever -- MEASURED at 89 bytes per run, so ~8MB per 100k runs and ~84MB
    // per million. That is slow enough to go unnoticed and large enough to
    // matter on a CI runner that never reboots.
    //
    // ONE generation is kept deliberately. The ledger's purpose is feeding
    // `synthesize`, which already scopes to the last session, so deep history
    // has no consumer -- keeping more would trade real disk for data nothing
    // reads. Rotation is never silent: the caller is told, because an audit
    // log that quietly discards records is worse than one that grows.
    [[nodiscard]] std::string flush();

    // Bytes after which flush() rotates. 0 disables rotation entirely, for a
    // caller who is managing retention themselves.
    void set_max_bytes(std::uintmax_t n) noexcept { max_bytes_ = n; }

    // Set by flush() when it rotated, so the CLI can say so once.
    [[nodiscard]] bool rotated() const noexcept { return rotated_; }

    [[nodiscard]] const std::vector<AuditRecord>& records() const noexcept {
        return records_;
    }

    [[nodiscard]] static std::optional<Ledger> load(const std::string& path,
                                                    std::string& error);

private:
    std::string path_;
    std::vector<AuditRecord> records_;
    // 32 MiB: roughly 375k runs of spawn records, or several very large
    // observation sessions. Big enough that normal use never rotates, small
    // enough that an unattended host cannot fill a disk with audit data.
    std::uintmax_t max_bytes_ = 32u * 1024u * 1024u;
    bool rotated_ = false;
};

// ---------------------------------------------------------------------------
// Synthesis
// ---------------------------------------------------------------------------

struct SynthesisOptions {
    // Collapse sibling paths into their parent directory once this many
    // distinct children under it have been observed. Keeps the synthesized
    // policy readable instead of emitting a rule per file.
    std::size_t coalesce_threshold = 3;

    // Synthesize from the LAST observed session only, not the whole file.
    //
    // The ledger is append-only and shared across every run, so without this a
    // policy accumulates everything the agent has ever touched. MEASURED: two
    // unrelated tasks in one directory produced a policy granting BOTH tasks'
    // files, and 30 `observe` runs left 1020 records behind. Over a long
    // session the derived policy widens monotonically toward --yolo, which
    // inverts the point of deriving it.
    //
    // A session is delimited by the `proc.spawn` record every run writes, so
    // "the last session" is the last workload observed -- which is what a user
    // running `bastion observe -- <cmd> && bastion synthesize` means.
    //
    // Set false to mine the full history deliberately, e.g. to build one
    // policy covering a whole suite of tasks.
    bool last_session_only = true;

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
    std::size_t floor_filtered = 0;  // accesses the ergonomic floor covers
    std::size_t sessions_skipped = 0;  // earlier runs deliberately ignored

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
