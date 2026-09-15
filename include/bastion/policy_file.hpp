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

#include <string>
#include <vector>

namespace bastion {

struct PolicyFile {
    Tier tier = Tier::Kernel;
    std::vector<Rule> rules;
    std::vector<std::string> warnings;  // recoverable oddities, e.g. unknown keys
    bool ok = false;
    std::string error;                  // parse failure => refuse to run
    int error_line = 0;
};

// Parse policy text. Never throws; a malformed file yields ok=false and the
// caller must refuse to run rather than falling back to something permissive.
[[nodiscard]] PolicyFile parse_policy(std::string_view text);

// Read and parse a file.
[[nodiscard]] PolicyFile load_policy(const std::string& path);

// Build a Sealed policy from a parsed file. Paths are canonicalized by
// Policy::allow(), exactly as if they had come from the command line.
[[nodiscard]] Sealed to_sealed(const PolicyFile& pf);

}  // namespace bastion
