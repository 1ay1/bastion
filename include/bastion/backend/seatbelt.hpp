// bastion/backend/seatbelt.hpp — macOS Seatbelt (TrustedBSD MAC) backend.
//
// Compiles a Sealed policy into SBPL and enforces it via sandbox_init(3).
//
// We link the API, NOT the deprecated sandbox-exec(1) CLI that Anthropic's
// `srt` and OpenAI's Codex both shell out to. Verified working and enforcing on
// macOS 26.6.2 (DESIGN.md §2.1). sandbox_init is weak-linked and probed at
// runtime, so a future removal degrades to a reported capability loss rather
// than a link failure or a silently-unconfined process.
#pragma once

#include "bastion/policy.hpp"
#include "bastion/tier.hpp"

#include <string>

namespace bastion::darwin {

// Escape a path for safe embedding in an SBPL string literal.
//
// SECURITY: this is not cosmetic. Measured on macOS 26.6.2 (tools/probe):
//   - a path containing `"` aborts profile compilation (fail-closed, but a DoS)
//   - a crafted path `…/x") (allow file-read* (subpath "/` INJECTS a rule
//     granting total filesystem read when interpolated naively
//   - with `"` and `\` escaped, that same payload is parsed as a literal
//     directory name and grants nothing
// Agents create files from model output, so attacker-influenced path text
// reaching a profile is a live threat, not a hypothetical.
[[nodiscard]] std::string sbpl_escape(std::string_view path);

// Reject paths that cannot be safely or meaningfully expressed in a profile.
// Returns an error string, or empty if acceptable.
[[nodiscard]] std::string validate_path(std::string_view path);

struct CompileResult {
    std::string profile;                 // SBPL text
    std::vector<std::string> warnings;   // rights the backend cannot enforce
    bool ok = false;
    std::string error;
};

// Compile a sealed policy to SBPL.
//
// Encodes measured Seatbelt semantics (all verified in tools/probe):
//   - `subpath` respects component boundaries: /x/normal does NOT match
//     /x/normal-evil. Matches Sealed::covers(), so eval and enforcement agree.
//   - `subpath` behaves identically with or without a trailing slash.
//   - `literal` does NOT grant children; directory grants must use `subpath`.
//   - traversal needs `file-read-metadata`: a rule naming a canonical path is
//     EPERM when opened via a symlink without it (DESIGN.md §2.1).
[[nodiscard]] CompileResult compile(const Sealed& policy);

// Apply the policy to the CURRENT process. Irreversible.
// Returns empty on success, else an error message.
//
// Intended to be called in the child between fork() and exec().
[[nodiscard]] std::string apply(const Sealed& policy);

// Runtime capability probe — never inferred from build flags.
[[nodiscard]] BackendCaps probe();

}  // namespace bastion::darwin
