// bastion/policy_file.hpp — read a policy back from disk.
//
// Closes the loop for the USER, not just for the test suite:
//
//     bastion observe -- ./build.sh
//     bastion synthesize > bastion.toml     # review it, commit it
//     bastion run --policy bastion.toml -- ./build.sh
//
// Until this existed, `synthesize` emitted a file nothing could consume, so the
// "bypass is an on-ramp to a tight policy" story ended at a text file the user
// had to translate into CLI flags by hand.
//
// The format is the subset of TOML that `Synthesis::to_toml()` emits -- a hand
// written parser rather than a dependency, because a security tool should not
// grow a third-party parser to read its own output.
#pragma once

#include "bastion/policy.hpp"
#include "bastion/result.hpp"

#include <string>
#include <vector>

namespace bastion {

// A SUCCESSFULLY parsed policy file.
//
// There is no `ok` flag and no `error` field: a PolicyFile that exists is one
// that parsed. Failure is carried by Result<PolicyFile> instead, so the
// four-state `{ok, error}` shape -- including "succeeded but has an error" and
// "failed but says why not" -- cannot be constructed.
//
// This matters beyond tidiness. to_sealed() used to accept a PolicyFile whose
// ok flag was false, so a caller that forgot one `if` would turn a MALFORMED
// file into a live policy. Now the type makes that call impossible to write.
struct PolicyFile {
    Tier tier = Tier::Kernel;
    std::vector<Rule> rules;
    std::vector<std::string> warnings;  // recoverable oddities, e.g. unknown keys
};

// A parse failure: a reason, and where it happened.
struct ParseError {
    std::string message;
    int line = 0;

    [[nodiscard]] std::string describe() const {
        return line > 0 ? message + " (line " + std::to_string(line) + ")"
                        : message;
    }
};

// Parse policy text. Never throws. A malformed file yields an error, and
// because the error and the value share one slot the caller CANNOT reach a
// half-parsed policy -- the old contract ("the caller must refuse to run")
// was a comment; this is the type system.
[[nodiscard]] Result<PolicyFile> parse_policy(std::string_view text);

// Read and parse a file.
[[nodiscard]] Result<PolicyFile> load_policy(const std::string& path);

// Build a Sealed policy from a parsed file. Paths are canonicalized by
// Policy::allow(), exactly as if they had come from the command line.
//
// Takes a PolicyFile, which by construction parsed successfully.
[[nodiscard]] Sealed to_sealed(const PolicyFile& pf);

}  // namespace bastion
