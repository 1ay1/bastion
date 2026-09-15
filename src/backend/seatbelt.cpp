#include "bastion/backend/seatbelt.hpp"

#include <dlfcn.h>

#include <filesystem>
#include <sstream>
#include <unordered_set>

// sandbox_init(3) is not declared in any public SDK header (there is no
// /usr/include/sandbox.h), so declare it and weak-link it.
extern "C" int sandbox_init(const char* profile, uint64_t flags, char** errorbuf)
    __attribute__((weak_import));
extern "C" void sandbox_free_error(char* errorbuf) __attribute__((weak_import));

namespace bastion::darwin {

namespace {

// Paths that must always be readable or the toolchain breaks. This is the
// ergonomic floor as a *security* feature (DESIGN.md §4): a sandbox that breaks
// the compiler makes agents thrash, and thrashing agents get switched off.
constexpr std::string_view kBaseReadPaths[] = {
    "/usr/lib", "/usr/share", "/System/Library", "/Library/Preferences",
    "/private/var/db/dyld", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
    "/private/var/select", "/Library/Developer/CommandLineTools",
    "/Applications/Xcode.app",
};

}  // namespace

std::string sbpl_escape(std::string_view path) {
    std::string out;
    out.reserve(path.size() + 8);
    for (char c : path) {
        // Order matters: backslash first, else we'd double-escape our own
        // inserted escapes. Measured: an unescaped `\` silently changes which
        // directory the rule matches (tools/probe case G).
        if (c == '\\' || c == '"') out += '\\';
        out += c;
    }
    return out;
}

std::string validate_path(std::string_view path) {
    if (path.empty()) return "empty path";
    if (path == "*") return {};  // the Unconfined sentinel
    if (path.front() != '/') {
        return "path must be absolute (got: " + std::string{path} + ")";
    }
    // Control characters and newlines have no legitimate place in a policy path
    // and are a profile-injection vector. Fail closed.
    for (char c : path) {
        if (static_cast<unsigned char>(c) < 0x20 ||
            static_cast<unsigned char>(c) == 0x7f) {
            return "path contains a control character: " + std::string{path};
        }
    }
    return {};
}

CompileResult compile(const Sealed& policy) {
    CompileResult res;
    std::ostringstream o;

    o << "(version 1)\n";

    // T0 observation: allow everything, but make the kernel REPORT each access
    // decision to the unified log so `bastion synthesize` has real evidence.
    // Measured on macOS 26.6.2: `(allow default (with report))` yields lines like
    //   Sandbox: sh(123) allow file-read-data /private/etc/hosts
    // unprivileged -- no root, no fs_usage, no dtrace (both need privileges we
    // refuse to ask for). Paths arrive canonicalized, which is what we want.
    if (policy.is_report_all()) {
        o << ";; T0 OBSERVE: no enforcement, full reporting.\n"
          << "(allow default (with report))\n";
        res.profile = o.str();
        res.ok = true;
        res.warnings.emplace_back(
            "T0 observe: nothing is enforced; every access is recorded");
        return res;
    }

    // An Unconfined policy still produces a real, valid profile: we allow
    // everything rather than skipping enforcement, so that the SAME code path
    // runs at every tier (DESIGN.md §1) and the audit ledger stays authoritative.
    if (policy.is_unconfined()) {
        o << ";; UNCONFINED grant active -- auditing remains in force.\n"
          << "(allow default)\n";
        res.profile = o.str();
        res.ok = true;
        res.warnings.emplace_back(
            "unconfined: no filesystem or network restriction is enforced; "
            "operations are still recorded");
        return res;
    }

    o << "(deny default)\n";

    std::unordered_set<std::string> seen_tmp;

    // Traversal metadata. REQUIRED for correctness, not a convenience:
    // without it, a rule naming a canonical path returns EPERM when the file is
    // opened through a symlink (/etc -> /private/etc), which silently
    // under-grants and makes the agent thrash (DESIGN.md §2.1).
    o << ";; path traversal (metadata only -- does not expose contents)\n"
      << "(allow file-read-metadata)\n";

    o << ";; process basics\n"
      << "(allow process-fork)\n"
      << "(allow signal (target self))\n"
      << "(allow sysctl-read)\n"
      << "(allow mach-lookup)\n";

    // REQUIRED for any child process to run at all. Diagnosed from the kernel's
    // own denial (`Sandbox: sh deny(1) file-read-data /`) after every confined
    // spawn aborted:
    //   - `process-exec` gates execve entirely; without it exec returns EPERM.
    //   - dyld additionally reads the ROOT DIRECTORY itself. A `subpath` grant
    //     does NOT cover its own ancestors, so /bin being readable is not
    //     enough -- "/" needs an explicit grant.
    // Using `literal` (not `subpath`) is what keeps this safe: verified that it
    // permits exec while /etc/passwd and ~/.ssh stay denied (tools/probe).
    o << ";; exec support: dyld reads the root directory itself.\n"
      << ";; `literal` not `subpath` -- grants the dir entry, not the tree.\n"
      << "(allow process-exec)\n"
      << "(allow file-read* (literal \"/\"))\n";

    o << ";; ergonomic floor: devices every toolchain expects (DESIGN.md 4)\n"
      << "(allow file-read* file-write-data (literal \"/dev/null\"))\n"
      << "(allow file-read* (literal \"/dev/urandom\") (literal \"/dev/random\"))\n"
      << "(allow file-read* (literal \"/dev/zero\"))\n"
      << "(allow file-ioctl file-read* file-write* (subpath \"/dev/ttys\"))\n"
      << "(allow file-read* (literal \"/dev/dtracehelper\"))\n";

    o << ";; ergonomic floor: system read paths\n";
    for (auto p : kBaseReadPaths) {
        o << "(allow file-read* (subpath \"" << sbpl_escape(p) << "\"))\n";
    }

    // Writable temp. THE most important line in this file for usability.
    //
    // The field report's biggest single win was "the return of rw in /tmp ...
    // the LLMs will stop going around in circles". Verified live here: without
    // the REAL $TMPDIR granted, Apple's clang cannot create its xcrun cache or
    // temporary files and every compile fails with
    //   "couldn't create cache file ... (errno=Operation not permitted)"
    // which reads like a broken toolchain rather than a policy denial. On macOS
    // $TMPDIR is a per-user /var/folders/... path, so granting /tmp alone is
    // NOT enough.
    o << ";; ergonomic floor: writable temp (see DESIGN.md 4)\n";
    bool have_tmp = false;
    for (const char* var : {"TMPDIR", "TMP", "TEMP"}) {
        if (const char* v = std::getenv(var); v && *v && v[0] == '/') {
            std::error_code ec;
            auto canon = std::filesystem::weakly_canonical(v, ec);
            const std::string t = ec ? std::string{v} : canon.string();
            if (validate_path(t).empty() && seen_tmp.insert(t).second) {
                o << "(allow file-read* file-write* (subpath \"" << sbpl_escape(t)
                  << "\"))\n";
                have_tmp = true;
            }
        }
    }
    // Deliberately NOT granting world-shared /tmp by default. It is readable by
    // every user and every other agent on the box, so a blanket grant would
    // leak cross-session data -- the isolation the live tests assert. macOS
    // always sets a per-user $TMPDIR (/var/folders/...), which is private and
    // is what clang actually needs. Only fall back to /tmp if there is no
    // $TMPDIR at all, since some temp dir is required for anything to build.
    if (!have_tmp) {
        o << ";; no $TMPDIR set; falling back to shared /tmp\n";
        for (const char* t : {"/private/tmp"}) {
            if (seen_tmp.insert(t).second) {
                o << "(allow file-read* file-write* (subpath \"" << sbpl_escape(t)
                  << "\"))\n";
            }
        }
        res.warnings.emplace_back(
            "no $TMPDIR set: granted shared /tmp, which other users and agents "
            "can also read. Set TMPDIR to a private directory.");
    }
    // Toolchain caches must be writable or every build re-downloads the world.
    for (const char* var : {"CARGO_HOME", "GOCACHE", "GOMODCACHE",
                            "npm_config_cache", "PIP_CACHE_DIR", "CCACHE_DIR",
                            "ZIG_GLOBAL_CACHE_DIR"}) {
        if (const char* v = std::getenv(var); v && *v && v[0] == '/') {
            std::error_code ec;
            auto canon = std::filesystem::weakly_canonical(v, ec);
            const std::string t = ec ? std::string{v} : canon.string();
            if (validate_path(t).empty() && seen_tmp.insert(t).second) {
                o << "(allow file-read* file-write* (subpath \"" << sbpl_escape(t)
                  << "\"))\n";
            }
        }
    }

    bool any_egress = false;
    std::unordered_set<std::string> seen;

    for (const auto& r : policy.rules()) {
        if (auto err = validate_path(r.scope); !err.empty() &&
                                               r.right != Right::NetEgress &&
                                               r.right != Right::NetBind) {
            res.error = "rule rejected: " + err;
            return res;  // fail closed
        }

        const std::string esc = sbpl_escape(r.scope);
        std::error_code ec;
        const bool is_dir = std::filesystem::is_directory(r.scope, ec);
        // `literal` does NOT grant children (measured, probe case I), so a
        // directory grant must use `subpath`. For a path that does not exist
        // yet we assume directory: an agent creating build output under a
        // granted workspace is the common case, and subpath is a superset of
        // literal for a leaf file.
        const char* form = (is_dir || ec) ? "subpath" : "literal";

        auto emit = [&](std::string_view ops) {
            std::string key = std::string{ops} + "|" + form + "|" + esc;
            if (!seen.insert(key).second) return;
            o << "(allow " << ops << " (" << form << " \"" << esc << "\"))\n";
        };

        if (any(r.right & Right::FsRead))  emit("file-read*");
        if (any(r.right & Right::FsWrite)) emit("file-write*");
        if (any(r.right & Right::FsExec))  emit("process-exec");
        if (any(r.right & Right::NetEgress)) any_egress = true;

        if (any(r.right & (Right::DeviceRead | Right::DeviceWrite))) {
            res.warnings.emplace_back(
                "device rights are expressed as filesystem rules under Seatbelt; "
                "IOKit class filtering is not available at T2");
        }
    }

    // Seatbelt cannot filter egress by hostname -- only by socket/port. Rather
    // than pretend, we grant socket egress and warn loudly. Host-level
    // allowlisting requires T3 (proxy interception); saying so is the point
    // (DESIGN.md §6: `bastion explain` prints the REAL boundary).
    if (any_egress) {
        o << ";; NOTE: Seatbelt filters sockets, not hostnames.\n"
          << "(allow network-outbound)\n"
          << "(allow network-bind (local ip \"localhost:*\"))\n"
          << "(allow system-socket)\n"
          << "(allow file-read* (subpath \"/private/etc\"))\n";  // resolv.conf
        res.warnings.emplace_back(
            "net.egress granted, but Seatbelt cannot restrict by hostname: ALL "
            "outbound connections are permitted at T2. Use T3 (proxy) for "
            "per-host allowlisting.");
    }

    res.profile = o.str();
    res.ok = true;
    return res;
}

std::string apply(const Sealed& policy) {
    if (&sandbox_init == nullptr) {
        return "sandbox_init unavailable on this system";
    }
    auto compiled = compile(policy);
    if (!compiled.ok) return "profile compilation failed: " + compiled.error;

    char* err = nullptr;
    if (sandbox_init(compiled.profile.c_str(), 0, &err) != 0) {
        std::string msg = err ? err : "unknown sandbox_init failure";
        if (err && &sandbox_free_error != nullptr) sandbox_free_error(err);
        return "sandbox_init failed: " + msg;
    }
    return {};
}

BackendCaps probe() {
    BackendCaps c;
    c.name = "seatbelt";
    c.fs_path_authority = (&sandbox_init != nullptr);
    c.net_egress_filter = false;  // sockets only, not hostnames -- be honest
    c.device_control = false;
    c.namespace_isolation = false;
    c.requires_setuid = false;
    c.max_tier = c.fs_path_authority ? Tier::Kernel : Tier::Advisory;
    c.version_note =
        "sandbox_init(3), weak-linked. sandbox-exec(1) is deprecated but the "
        "underlying API is verified working on macOS 26.x.";
    return c;
}

}  // namespace bastion::darwin
