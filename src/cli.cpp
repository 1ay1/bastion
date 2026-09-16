// bastion CLI.
//
// UX thesis (DESIGN.md §1): the bypass is a capability, not a power switch.
// `--yolo` gives the user a frictionless wide-open run, and STILL produces a
// full ledger they can turn into a tight policy with `bastion synthesize`.
// Nobody is ever told "you're on your own".
#include "bastion/ledger.hpp"
#include "bastion/observe.hpp"
#include "bastion/policy_file.hpp"
#include "bastion/spawn.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#if defined(__APPLE__)
#  include "bastion/backend/seatbelt.hpp"
#elif defined(__linux__)
#  include "bastion/backend/cgroup.hpp"
#  include "bastion/backend/landlock.hpp"
#endif

namespace fs = std::filesystem;
using namespace bastion;

namespace {

// Minimal JSON string escaping for the --json summary.
//
// Duplicated rather than exported from policy.cpp: that one serialises audit
// records for the ledger, and coupling the CLI's output format to the ledger's
// on-disk format would mean a change to either silently breaks the other.
std::string json_str(std::string_view s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                // Control characters must be escaped or the output is not
                // valid JSON and an agent's parser rejects the whole object.
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    o += buf;
                } else {
                    o += c;
                }
        }
    }
    return o;
}

// The op name for a right set, matching the vocabulary used in policy files
// so an agent can feed `granted` straight back into an [[allow]] block.
const char* op_for(Right r) {
    if (any(r & Right::FsWrite))   return "fs.write";
    if (any(r & Right::FsExec))    return "fs.exec";
    if (any(r & Right::FsRead))    return "fs.read";
    if (any(r & Right::NetEgress)) return "net.egress";
    if (any(r & Right::NetBind))   return "net.bind";
    return "unknown";
}

// Walk up from `start` looking for a project root marker.
//
// WHY: the default workspace is the current directory, which is correct for a
// flat repo and wrong for every monorepo. MEASURED: an agent working in
// packages/app could not read ../lib or ../../tsconfig.json -- both denied,
// with nothing explaining why. That is the single most common real-world
// layout, and the failure looks like a broken toolchain rather than a policy
// decision.
//
// The markers are deliberately VCS/lockfile roots rather than "any directory
// with a package.json": in a monorepo every package has one of those, so the
// nearest match would be the subdirectory we are already in. A .git directory
// or a workspace lockfile identifies the tree a developer thinks of as "the
// project", which is the boundary they expect.
//
// Bounded: stops at $HOME or / so a stray .git in a parent directory cannot
// silently widen the sandbox to the whole home directory.
std::optional<fs::path> find_project_root(const fs::path& start) {
    static constexpr const char* kMarkers[] = {
        ".git", ".hg", ".svn", ".jj",
        "go.work", "pnpm-workspace.yaml", "lerna.json", "nx.json",
        "Cargo.toml", "go.mod",
    };

    std::error_code ec;
    fs::path home;
    if (const char* h = std::getenv("HOME"); h && *h == '/') home = h;

    for (fs::path dir = start; !dir.empty() && dir != dir.root_path();
         dir = dir.parent_path()) {
        // Never treat $HOME ITSELF as the project root. Dotfile repos are
        // common, so a .git directly in the home directory is normal -- and
        // accepting it would silently widen the sandbox from one project to
        // everything the user owns. Checked BEFORE the markers, so the match
        // never happens rather than happening and being regretted.
        if (!home.empty() && dir == home) break;

        for (const char* m : kMarkers) {
            if (fs::exists(dir / m, ec) && !ec) return dir;
        }
    }
    return std::nullopt;
}

BackendCaps active_backend() {
#if defined(__APPLE__)
    return darwin::probe();
#elif defined(__linux__)
    return linux_ll::probe();
#else
    BackendCaps c;
    c.name = "none";
    c.max_tier = Tier::Advisory;
    c.version_note = "no kernel backend for this platform";
    return c;
#endif
}

std::string default_ledger_path() {
    if (const char* e = std::getenv("BASTION_LEDGER"); e && *e) return e;
    const char* home = std::getenv("HOME");
    return std::string{home ? home : "/tmp"} + "/.bastion/ledger.jsonl";
}

void print_usage() {
    std::puts(R"(bastion — capability-based sandboxing for AI agents

USAGE
  bastion run [OPTIONS] -- <command>...    run a command under a policy
  bastion observe -- <command>...          run unconfined, RECORD every access
  bastion explain [OPTIONS]                print the REAL enforced boundary
  bastion doctor                           check backend + ergonomic floor
  bastion synthesize [--ledger PATH]       turn a session log into a policy

POLICY OPTIONS
  -p, --policy FILE      load a policy file (as written by `synthesize`).
                         Combines with the flags below; both are applied.
  -w, --workspace PATH   read+write grant (default: current directory)
  -r, --read PATH        read-only grant
      --net HOST:PORT    allow egress to a host:port (wildcards: *.example.com)
  -t, --tier TIER        t0|t1|t2|t3  (default: t2)

  At t3, --net becomes a REAL per-host allowlist: the kernel denies all direct
  egress and bastion brokers connections on loopback, so a compromised child
  cannot route around it. At t2, --net is all-or-nothing (the kernel matches
  sockets, not hostnames) and bastion says so rather than implying otherwise.

  --yolo                 grant Unconfined: no restriction is enforced.
                         NOT the same as disabling bastion — the audit ledger
                         stays fully active, so `bastion synthesize` can turn
                         the run into a least-privilege policy afterwards.

RESOURCE LIMITS (opt-in)
  --max-procs N          cap processes in THIS sandbox (cgroup v2 pids.max),
                         falling back to RLIMIT_NPROC where no delegated
                         cgroup exists — see below, the meaning differs
  --max-mem-mb N         cap memory for the whole sandbox (cgroup v2 only)
  --max-file-mb N        cap the size of any file the child creates
  --max-cpu-sec N        cap CPU seconds (runaway loops die with SIGXCPU)

  Off by default and deliberately so: a ceiling that fires during a legitimate
  build is exactly the friction that gets sandboxes turned off. Core dumps are
  always disabled, since a crashing confined process should not write memory
  images into the workspace.

  With cgroup v2, --max-procs is a TRUE per-sandbox budget: 20 means 20 here.
  Without it, the fallback is RLIMIT_NPROC, which the kernel counts per-UID
  across your whole session (threads, not processes) — a fork-bomb backstop
  only. bastion reports which mechanism it used.

OTHER
  --ledger PATH          audit log location (default ~/.bastion/ledger.jsonl)
  --no-ledger            do not write an audit log
  --json                 machine-readable output
  -h, --help             this message

ENVIRONMENT
  BASTION_MIN_TIER=t2    operator floor: --yolo and lower --tier are REFUSED,
                         not silently downgraded. Set it where the agent is
                         launched; unset locally and nothing changes.

  A ./bastion.toml (or .bastion.toml) in the current directory is used
  automatically, but only to NARROW: grants pointing outside that
  directory are refused, as is egress and any tier below the one asked
  for. The sandboxed workload can write to its own workspace, so a
  discovered file must not be able to widen the sandbox. Use --policy to
  apply a file in full -- that is you vouching for it from outside.

EXAMPLES
  # Tight, in whatever directory you happen to be in:
  bastion run -- cargo test

  # Don't know what it needs? Watch it, then lock it down:
  bastion observe -- ./weird-legacy-build.sh
  bastion synthesize > bastion.toml
  bastion run --policy bastion.toml -- ./weird-legacy-build.sh

  # Wide open because you're in a hurry — still recorded:
  bastion run --yolo -- ./weird-legacy-build.sh

  # Real per-host network allowlisting:
  bastion run -t t3 --net '*.githubusercontent.com:443' -- pip install -r reqs.txt)");
}

Tier parse_tier(std::string_view s, bool& ok) {
    ok = true;
    if (s == "t0" || s == "0" || s == "observe")    return Tier::Observe;
    if (s == "t1" || s == "1" || s == "advisory")   return Tier::Advisory;
    if (s == "t2" || s == "2" || s == "kernel")     return Tier::Kernel;
    if (s == "t3" || s == "3" || s == "isolate")    return Tier::Isolate;
    if (s == "t4" || s == "4" || s == "virtualize") return Tier::Virtualize;
    ok = false;
    return Tier::Kernel;
}

// The operator floor, read once and applied everywhere a workload can run.
//
// Returns false and fills `error` if `requested` is below it. Shared rather
// than inlined into build_policy(), because MEASURED: `observe` did not
// consult it, and `observe` runs the workload UNCONFINED by design -- so
// `BASTION_MIN_TIER=t2 bastion observe -- cat ~/.ssh/id_*` printed the key
// while `bastion run --yolo` was correctly refused. A floor with one
// unguarded entrance is not a floor.
bool floor_permits(Tier requested, bool is_yolo, std::string& error) {
    const char* mt = std::getenv("BASTION_MIN_TIER");
    if (!mt || !*mt) return true;

    bool ok = false;
    const Tier floor = parse_tier(mt, ok);
    if (!ok) {
        error = std::string{"BASTION_MIN_TIER is not a tier: "} + mt +
                " (expected t0|t1|t2|t3)";
        return false;
    }

    if (is_yolo) {
        error = "--yolo is refused: BASTION_MIN_TIER=" +
                std::string{tier_name(floor)} +
                " requires enforcement.\n"
                "       Run under the policy instead, or use `bastion observe` "
                "to find out what the workload needs.";
        return false;
    }
    if (requested < floor) {
        error = std::string{tier_name(requested)} +
                " is below BASTION_MIN_TIER=" + std::string{tier_name(floor)};
        return false;
    }
    return true;
}


struct Args {
    std::string cmd;
    std::vector<std::string> workspace;
    std::vector<std::string> read;
    std::vector<std::string> net;
    std::string policy_file;
    Tier tier = Tier::Kernel;
    bool tier_explicit = false;
    bool yolo = false;
    bool json = false;
    bool no_ledger = false;
    std::string ledger = default_ledger_path();
    ResourceLimits limits;
    std::vector<std::string> argv;
    std::string error;
};

Args parse(int argc, char** argv) {
    Args a;
    if (argc < 2) {
        a.error = "no subcommand";
        return a;
    }
    a.cmd = argv[1];

    int i = 2;
    for (; i < argc; ++i) {
        std::string_view s = argv[i];
        if (s == "--") {
            ++i;
            break;
        }
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) {
                a.error = std::string{"missing value for "} + what;
                return {};
            }
            return argv[++i];
        };
        if (s == "-w" || s == "--workspace")   a.workspace.push_back(next("--workspace"));
        else if (s == "-r" || s == "--read")   a.read.push_back(next("--read"));
        else if (s == "-p" || s == "--policy") a.policy_file = next("--policy");
        else if (s == "--net")                 a.net.push_back(next("--net"));
        else if (s == "--ledger")              a.ledger = next("--ledger");
        else if (s == "--no-ledger")           a.no_ledger = true;
        else if (s == "--json")                a.json = true;
        else if (s == "--yolo")                a.yolo = true;
        else if (s == "--max-procs" || s == "--max-file-mb" ||
                 s == "--max-cpu-sec" || s == "--max-mem-mb") {
            const std::string flag{s};
            const std::string_view raw = next(flag.c_str());
            if (!a.error.empty()) return a;
            // Parse strictly: a typo'd ceiling that silently becomes 0 would
            // disable the very limit the user asked for.
            unsigned long long v = 0;
            const auto* b = raw.data();
            const auto* e = raw.data() + raw.size();
            auto [ptr, ec] = std::from_chars(b, e, v);
            if (ec != std::errc{} || ptr != e || v == 0) {
                a.error = flag + " needs a positive integer";
                return a;
            }
            if (flag == "--max-procs") {
                a.limits.max_processes = static_cast<unsigned>(v);
            } else if (flag == "--max-cpu-sec") {
                a.limits.max_cpu_seconds = static_cast<unsigned>(v);
            } else if (flag == "--max-mem-mb") {
                a.limits.max_memory_bytes = v * 1024ull * 1024ull;
            } else {
                a.limits.max_file_bytes = v * 1024ull * 1024ull;
            }
        }
        else if (s == "-t" || s == "--tier") {
            bool ok = false;
            a.tier = parse_tier(next("--tier"), ok);
            a.tier_explicit = true;
            if (!ok) a.error = "unknown tier";
        } else if (s == "-h" || s == "--help") {
            a.cmd = "help";
            return a;
        } else if (s.starts_with("-")) {
            a.error = "unknown option: " + std::string{s};
            return a;
        } else {
            break;  // start of the command
        }
        if (!a.error.empty()) return a;
    }
    for (; i < argc; ++i) a.argv.emplace_back(argv[i]);
    return a;
}

// Returns nullopt (with `error` set) if a policy file was requested but is
// unusable. A malformed policy must stop the run, never silently fall back to
// the permissive default of "grant the current directory".
//
// Returns by optional rather than an out-param because `Sealed` is
// deliberately NOT default-constructible -- the typestate says a sealed policy
// can only come from Policy::seal(), and weakening that to make an out-param
// compile would trade a compile-time guarantee for convenience.
std::optional<Sealed> build_policy(const Args& a, Broker& broker,
                                   std::string& error) {
    // The operator floor. Checked BEFORE --yolo is honoured, precisely because
    // --yolo is the thing being bounded: a floor the bypass can step over is
    // decoration. Shared with cmd_observe(), which needs the same guard for a
    // stronger reason -- it runs the workload unconfined by design.
    if (!floor_permits(a.tier, a.yolo, error)) return std::nullopt;

    Policy p{a.tier};

    if (a.yolo) {
        // The bypass, as a capability. Witnessed, and still audited.
        return std::move(p)
            .unconfined(broker.grant_unconfined(Witness{"user passed --yolo"}))
            .seal();
    }

    bool from_file = false;

    // POLICY DISCOVERY.
    //
    // A committed ./bastion.toml used to be inert: present, readable, and
    // silently ignored unless the user remembered --policy. MEASURED: a
    // read-only policy sat beside a workload that happily wrote to the
    // directory, because the default "workspace = cwd" grant applied instead.
    // A policy file that does not bind is worse than none -- it looks like
    // protection.
    //
    // So the file is now found the way every other tool finds its config, and
    // --policy remains available to name one explicitly.
    std::string policy_path = a.policy_file;
    bool discovered = false;
    if (policy_path.empty()) {
        std::error_code dec;
        const auto here = fs::current_path(dec);
        if (!dec) {
            for (const char* name : {"bastion.toml", ".bastion.toml"}) {
                const auto cand = here / name;
                if (fs::is_regular_file(cand, dec) && !dec) {
                    policy_path = cand.string();
                    discovered = true;
                    std::fprintf(stderr, "bastion: using %s\n", name);
                    break;
                }
            }
        }
    }

    if (!policy_path.empty()) {
        auto loaded = load_policy(policy_path);
        if (!loaded) {
            // The line number is already folded into the message by
            // ParseError::describe(), so there is no second field to forget.
            error = policy_path + ": " + loaded.error();
            return std::nullopt;
        }
        // Only reachable on success, so `pf` is a policy that really parsed --
        // the type system, not a convention, guarantees it.
        const PolicyFile& pf = loaded.value();

        for (const auto& w : pf.warnings) {
            std::fprintf(stderr, "bastion: [warning] %s\n", w.c_str());
        }
        // DISCOVERED POLICIES MAY NARROW, NEVER WIDEN.
        //
        // MEASURED escape. `bastion run` auto-loads ./bastion.toml, and the
        // workspace it grants is WRITABLE BY THE CONFINED WORKLOAD. So the
        // agent writes its own policy file and the next invocation hands it
        // whatever it asked for:
        //
        //   bastion run -- sh -c 'printf ... path="/home/me" > bastion.toml'
        //   bastion run -- cat ~/.ssh/id_ed25519      # -> the private key
        //
        // Two runs, no privilege, complete escape -- and it survives a reboot
        // because the file persists. The bug is not in the parser or the
        // backend; it is that authority was being taken from an input inside
        // the blast radius. A sandbox may never widen itself on the say-so of
        // the thing it is sandboxing.
        //
        // Discovery is a CONVENIENCE, so it gets convenience's authority: a
        // discovered file may restrict what happens in its own directory, and
        // may not reach outside it. --policy is the OPERATOR speaking, from
        // outside the sandbox, and is honoured in full.
        //
        // Deliberately not solved by checking file ownership or permissions:
        // the agent runs as the same uid as the operator, so the file it
        // writes is indistinguishable from one the operator wrote. Only
        // PROVENANCE separates them, and provenance is exactly the thing
        // `--policy` carries and discovery does not.
        std::vector<std::string> refused;
        if (discovered) {
            std::error_code rec;
            const auto base = fs::path(policy_path).parent_path();
            const auto root = fs::weakly_canonical(base, rec);
            const std::string prefix = (rec ? base : root).string();

            std::vector<Rule> kept;
            for (const auto& r : pf.rules) {
                // Egress is never local to a directory, so a discovered file
                // cannot open the network at all.
                if (any(r.right & (Right::NetEgress | Right::NetBind))) {
                    refused.push_back("net " + r.scope);
                    continue;
                }
                const auto cs = fs::weakly_canonical(fs::path(r.scope), rec);
                const std::string s = (rec ? fs::path(r.scope) : cs).string();
                // Inside the policy's own directory, or the directory itself.
                const bool inside =
                    s == prefix ||
                    (s.size() > prefix.size() && s.starts_with(prefix) &&
                     s[prefix.size()] == '/');
                if (inside) {
                    kept.push_back(r);
                } else {
                    refused.push_back(r.scope);
                }
            }
            if (!refused.empty()) {
                std::fprintf(stderr,
                    "bastion: [warning] %s grants %zu path(s) outside %s; "
                    "refused.\n"
                    "         A discovered policy can only narrow what happens "
                    "in its own\n"
                    "         directory -- the sandboxed workload can write to "
                    "that directory,\n"
                    "         so it must not be able to widen itself. Use "
                    "--policy %s to\n"
                    "         apply it in full (that is you, the operator, "
                    "vouching for it).\n",
                    fs::path(policy_path).filename().string().c_str(),
                    refused.size(), prefix.c_str(), policy_path.c_str());
                for (const auto& s : refused) {
                    std::fprintf(stderr, "         refused: %s\n", s.c_str());
                }
            }
            // A discovered file may not raise the tier either: T0/T1 do not
            // enforce, so "tier = T0" in an attacker-written file would
            // disable the sandbox outright.
            const Tier ft = a.tier_explicit ? a.tier : pf.tier;
            p = Policy{ft < a.tier ? a.tier : ft};
            for (const auto& r : kept) {
                p = std::move(p).allow(r.right, r.scope, r.provenance);
            }
        } else {
            // An explicit --tier on the command line overrides the file, so a
            // user can tighten a committed policy without editing it.
            p = Policy{a.tier_explicit ? a.tier : pf.tier};
            for (const auto& r : pf.rules) {
                if (any(r.right & (Right::NetEgress | Right::NetBind))) {
                    p = std::move(p).allow_egress(r.scope, r.provenance);
                } else {
                    p = std::move(p).allow(r.right, r.scope, r.provenance);
                }
            }
        }
        from_file = true;
    }

    // Default the workspace to the CURRENT directory -- but only when the user
    // gave no grants at all. A policy file that deliberately omits the cwd must
    // not have it added back silently.
    if (!from_file && a.workspace.empty() && a.read.empty()) {
        // Path-set authority means the CURRENT directory just works -- there is
        // no fixed sandbox root to symlink things into (DESIGN.md §3).
        //
        // But "current directory" is the wrong default inside a monorepo. An
        // agent working in packages/app needs ../lib and the root config, and
        // got `Permission denied` on both with nothing saying why. So the
        // default is the PROJECT ROOT when one is detectable -- the tree the
        // developer thinks of as "the project" -- and the cwd otherwise.
        //
        // Reported, so the boundary is never a surprise: a grant wider than
        // the directory you are standing in has to be visible.
        std::error_code ec;
        auto cwd = fs::current_path(ec);
        if (!ec) {
            fs::path ws = cwd;
            const char* why = "current directory (default workspace)";
            if (auto root = find_project_root(cwd); root && *root != cwd) {
                ws = *root;
                why = "project root (detected; use -w to override)";
                if (!a.json) {
                    std::fprintf(stderr,
                                 "bastion: workspace = %s (project root)\n",
                                 ws.c_str());
                }
            }
            p = std::move(p).allow(Right::FsRead | Right::FsWrite, ws, why);
        }
    }
    for (const auto& w : a.workspace) {
        p = std::move(p).allow(Right::FsRead | Right::FsWrite, w, "--workspace");
    }
    for (const auto& r : a.read) {
        p = std::move(p).allow(Right::FsRead, r, "--read");
    }
    for (const auto& n : a.net) {
        p = std::move(p).allow_egress(n, "--net");
    }
    return std::move(p).seal();
}

int cmd_doctor() {
    auto caps = active_backend();
    std::printf("backend:     %s\n", caps.name.c_str());
    std::printf("note:        %s\n", caps.version_note.c_str());
    std::printf("max tier:    %s\n", std::string{tier_name(caps.max_tier)}.c_str());
    std::printf("path authority:   %s\n", caps.fs_path_authority ? "yes" : "NO");
    std::printf("net filtering:    %s\n",
                caps.net_egress_filter ? "yes (by port)" : "no (T3 required)");
    std::printf("namespace isolation: %s\n", caps.namespace_isolation ? "yes" : "no");
#if defined(__linux__)
    // Which mechanism a --max-procs would actually get. The two differ in
    // MEANING, not just quality, so the user needs to know before choosing a
    // number: a cgroup budget of 20 means 20 processes here, while the rlimit
    // fallback is counted against every thread the uid owns system-wide.
    {
        const auto cg = linux_cgroup::probe();
        if (cg.available) {
            std::printf("resource budget:  cgroup v2 (%s%s) \u2014 per-sandbox\n",
                        cg.pids ? "pids" : "",
                        cg.memory ? (cg.pids ? "+memory" : "memory") : "");
        } else {
            std::printf("resource budget:  setrlimit only \u2014 per-uid, a "
                        "fork-bomb backstop\n                  (%s)\n",
                        cg.reason.c_str());
        }
    }
#endif
    std::printf("requires setuid:  %s\n",
                caps.requires_setuid ? "YES -- REFUSED" : "no");

    if (caps.requires_setuid) {
        std::puts("\nFATAL: a setuid-root mechanism is its own privilege-escalation\n"
                  "surface (cf. firejail CVE-2022-31214). bastion refuses these.");
        return 2;
    }

    // The ergonomic floor (DESIGN.md §4). These are the failures the field
    // report hit empirically, over a day, as mysterious compiler errors.
    std::puts("\nergonomic floor:");
    int problems = 0;
    auto check = [&](const char* label, bool ok, const char* fix) {
        std::printf("  [%s] %s\n", ok ? "ok" : "!!", label);
        if (!ok) {
            std::printf("         -> %s\n", fix);
            ++problems;
        }
    };

    const char* tmpdir = std::getenv("TMPDIR");
    std::string tmp = (tmpdir && *tmpdir) ? tmpdir : "/tmp";
    std::error_code ec;
    check("writable temp dir", fs::exists(tmp, ec) && !ec,
          "set TMPDIR to a writable path; without it builds fail in ways that "
          "look like broken code");

    check("/dev/null present", fs::exists("/dev/null", ec), "check your system");
    check("/dev/urandom present", fs::exists("/dev/urandom", ec), "check your system");

    // Toolchain caches. NOT a warning any more: an unset CARGO_HOME does not
    // mean "no cache needed", it means the default (~/.cargo) is used, and the
    // backend now grants those defaults when they exist. Report what will
    // actually be granted, so the user can see it rather than be told off
    // about an environment variable bastion does not need them to set.
    std::vector<std::string> caches;
    for (const char* k : {"CARGO_HOME", "GOCACHE", "GOMODCACHE",
                          "npm_config_cache", "PIP_CACHE_DIR", "CCACHE_DIR",
                          "ZIG_GLOBAL_CACHE_DIR"}) {
        if (const char* v = std::getenv(k); v && *v) {
            caches.push_back(std::string{k} + "=" + v);
        }
    }
    std::size_t defaults_found = 0;
    if (const char* home = std::getenv("HOME"); home && *home) {
        for (const char* rel : {"/.cargo", "/.rustup", "/.cache/go-build",
                                "/go/pkg/mod", "/.npm", "/.cache/pip",
                                "/.ccache", "/.cache/zig"}) {
            if (fs::exists(std::string{home} + rel, ec)) ++defaults_found;
        }
    }
    check("toolchain caches granted", !caches.empty() || defaults_found > 0,
          "no toolchain caches found; if you use cargo/go/npm, their default "
          "cache dirs do not exist yet and the first build will populate them");
    if (!caches.empty()) {
        std::printf("         explicit: ");
        for (std::size_t i = 0; i < caches.size(); ++i) {
            std::printf("%s%s", i ? ", " : "", caches[i].c_str());
        }
        std::printf("\n");
    }
    if (defaults_found > 0) {
        std::printf("         default:  %zu cache dir(s) under $HOME\n",
                    defaults_found);
    }

    std::printf("\n%s\n", problems == 0
                              ? "ready: the floor is satisfied."
                              : "warnings above will cause agent thrashing.");
    return 0;
}

int cmd_explain(const Args& a) {
    Broker broker;
    std::string perr;
    auto built = build_policy(a, broker, perr);
    if (!built) {
        std::fprintf(stderr, "error: %s\n", perr.c_str());
        return 2;
    }
    const Sealed& policy = *built;
    auto caps = active_backend();

    std::printf("%s", policy.explain().c_str());
    std::printf("\nbackend:   %s (%s)\n", caps.name.c_str(),
                caps.version_note.c_str());

    if (policy.tier() > caps.max_tier) {
        std::printf(
            "\n!! requested %s but this backend supports at most %s.\n"
            "   bastion will NOT silently downgrade: the run would be refused.\n",
            std::string{tier_name(policy.tier())}.c_str(),
            std::string{tier_name(caps.max_tier)}.c_str());
    }

#if defined(__APPLE__)
    auto compiled = darwin::compile(policy);
    if (!compiled) {
        // Same reasoning as the Linux branch: a policy the kernel cannot
        // express is the most important thing `explain` can report.
        std::printf("\n[ERROR] this policy cannot be enforced on this system:\n"
                    "        %s\n", compiled.error().c_str());
        return 1;
    }
    for (const auto& w : compiled.value().warnings) {
        std::printf("\n[warning] %s\n", w.c_str());
    }
#elif defined(__linux__)
    auto abi = linux_ll::probe_abi();
    auto rs = linux_ll::compile(policy, abi);
    if (!rs) {
        // `explain` exists to tell the user what the boundary REALLY is, so a
        // policy the kernel cannot express is the single most important thing
        // it can report. The previous code read .warnings off the result and
        // silently ignored the failure.
        std::printf("\n[ERROR] this policy cannot be enforced on this kernel:\n"
                    "        %s\n", rs.error().c_str());
        return 1;
    }
    for (const auto& w : rs.value().warnings) {
        std::printf("\n[warning] %s\n", w.c_str());
    }
#endif
    return 0;
}

int cmd_run(const Args& a) {
    if (a.argv.empty()) {
        std::fputs("error: no command given (use `--` before it)\n", stderr);
        return 2;
    }

    Broker broker;
    std::string perr;
    auto built = build_policy(a, broker, perr);
    if (!built) {
        std::fprintf(stderr, "error: %s\n", perr.c_str());
        return 2;
    }
    const Sealed& policy = *built;
    auto caps = active_backend();

    // Never silently downgrade. A sandbox that quietly becomes weaker than
    // requested is worse than one that refuses, because the user still
    // believes they are protected.
    if (policy.tier() > caps.max_tier && !policy.is_unconfined()) {
        std::fprintf(stderr,
                     "error: policy requires %s but backend '%s' supports at "
                     "most %s (%s).\nRefusing to run with weaker enforcement "
                     "than requested. Pass an explicit --tier to accept it.\n",
                     std::string{tier_name(policy.tier())}.c_str(),
                     caps.name.c_str(),
                     std::string{tier_name(caps.max_tier)}.c_str(),
                     caps.version_note.c_str());
        return 2;
    }

    if (policy.is_unconfined()) {
        std::fprintf(stderr,
                     "bastion: UNCONFINED — no restriction is enforced.\n"
                     "         Auditing stays active; run `bastion synthesize` "
                     "afterwards to derive a least-privilege policy.\n");
    }

    SpawnRequest req;
    req.argv = a.argv;
    req.limits = a.limits;
    auto result = spawn(policy, req);

    if (result.proxy_port != 0) {
        std::fprintf(stderr,
                     "bastion: T3 egress broker on 127.0.0.1:%u — direct "
                     "outbound is kernel-denied.\n",
                     result.proxy_port);
    }
    for (const auto& w : result.warnings) {
        std::fprintf(stderr, "bastion: [warning] %s\n", w.c_str());
    }
    for (const auto& [hostport, allowed] : result.egress_attempts) {
        if (!allowed) {
            std::fprintf(stderr,
                         "bastion: egress REFUSED %s\n"
                         "         remedy: bastion run -t t3 --net %s -- <cmd>\n",
                         hostport.c_str(), hostport.c_str());
        }
    }
    if (!result.launched()) {
        std::fprintf(stderr, "bastion: %s\n", result.error.c_str());

        // The workload never started, so the advisory further down is never
        // reached -- but this is the MOST likely W^X case, not the least:
        // `bastion run -- ./my-binary` execs the binary directly, so a denied
        // exec surfaces here rather than as a shell's 126. MEASURED: an agent
        // that had just built ./t got only "exec failed (binary missing or not
        // executable)", which reads as a build problem.
        if (result.setup_stage == 3 /* ChildStage::Exec */ &&
            !policy.is_unconfined() && !a.json) {
            std::error_code ec;
            const bool exists = fs::exists(a.argv.front(), ec);
            if (exists) {
                // lexically_normal(): without it a relative `./t` yields
                // "/tmp/ws/." as the parent, which is valid but looks broken
                // in a snippet the agent is meant to paste.
                const auto dir = fs::absolute(a.argv.front(), ec)
                                     .lexically_normal()
                                     .parent_path();
                std::fprintf(stderr,
                    "         the file EXISTS, so this is the policy: a write "
                    "grant does not include execute.\n"
                    "         To run a binary you built, add an `fs.exec` rule "
                    "for its directory:\n"
                    "\n"
                    "           [[allow]]\n"
                    "           op   = \"fs.exec\"\n"
                    "           path = \"%s\"\n"
                    "\n"
                    "         then: bastion run --policy <file> -- %s\n",
                    dir.c_str(), a.argv.front().c_str());
            }
        }
        return 2;
    }

    // Record the run. Written at EVERY tier, including unconfined.
    if (!a.no_ledger) {
        Ledger led{a.ledger};
        AuditRecord rec;
        rec.verdict = policy.is_unconfined() ? Verdict::Allow : Verdict::Allow;
        rec.op = "proc.spawn";
        rec.target = a.argv.front();
        rec.tier = policy.tier();
        rec.rule = policy.is_unconfined() ? "unconfined" : "policy";
        for (const auto& r : policy.rules()) {
            if (r.right == Right::Unconfined) rec.provenance = r.provenance;
        }
        led.record(rec);
        if (auto err = led.flush(); !err.empty()) {
            std::fprintf(stderr, "bastion: [warning] ledger: %s\n", err.c_str());
        } else if (led.rotated()) {
            // Never silent: an audit log that quietly discards history is
            // worse than one that grows, so say which file the old records
            // moved to.
            std::fprintf(stderr,
                         "bastion: ledger rotated; previous history is now %s.1\n",
                         a.ledger.c_str());
        }
    }

    // THE MOMENT THAT DECIDES WHETHER AN AGENT RECOVERS OR THRASHES.
    //
    // A confined command that fails prints whatever the tool printed --
    // "Permission denied", "Could not connect" -- with nothing tying it to
    // bastion. An agent then "fixes" its code, retries, fails identically, and
    // burns turns on a problem that is not in its code at all. That is exactly
    // the thrashing DESIGN.md §4 says gets sandboxes switched off.
    //
    // But the inverse is just as bad. Printing this on EVERY nonzero exit
    // means a genuine `test` failure gets told "maybe it was the sandbox" --
    // which sends the agent chasing a policy problem that does not exist.
    // MEASURED while dogfooding: `sh -c 'exit 1'` produced the full advisory
    // block, pointing at nothing.
    //
    // So speak only with EVIDENCE that the boundary was actually involved:
    //   - the broker refused a host, or
    //   - the shell reported "cannot execute" / "not found" (126/127), which
    //     under confinement usually means an exec the policy denied.
    // Otherwise the failure is the workload's own and bastion stays quiet.
    const bool egress_blocked = result.egress_denied > 0;
    const bool exec_denied = result.exit_code == 126 || result.exit_code == 127;

    // T2 has no broker, so a denied connection produces no bastion-side record
    // at all -- the agent just sees curl's "Could not connect". That is bad for
    // thrashing, because it reads like a network outage.
    //
    // But there is NO kernel signal to confirm it: Landlock does not report
    // denials at T2. Exit codes alone are far too weak to assert a cause --
    // MEASURED: `sh -c 'exit 7'` is indistinguishable from curl's "couldn't
    // connect", and the first version of this confidently told a plain failing
    // command that the network was blocked.
    //
    // So this does NOT claim the network was the problem. It adds one factual
    // line about the policy, phrased conditionally, and only when the policy
    // really does deny all egress. Being wrong here costs more than being
    // silent: a false cause sends the agent somewhere there is no bug.
    bool has_net_rule = false;
    for (const auto& r : policy.rules()) {
        if (any(r.right & (Right::NetEgress | Right::NetBind))) has_net_rule = true;
    }
    const bool net_is_denied = !has_net_rule && policy.tier() >= Tier::Kernel;

    const bool likely_ours = egress_blocked || exec_denied;

    if (result.exit_code != 0 && likely_ours && !policy.is_unconfined() &&
        !a.json) {
        std::fprintf(stderr,
            "\nbastion: this failure looks like the sandbox, not your code "
            "(confined at %s).\n",
            std::string{tier_name(policy.tier())}.c_str());

        // Name what is actually granted, so the agent can tell at a glance
        // whether the path it wanted is inside the boundary.
        std::fprintf(stderr, "         granted:");
        int shown = 0;
        for (const auto& r : policy.rules()) {
            if (any(r.right & (Right::FsRead | Right::FsWrite))) {
                if (shown++ < 4) std::fprintf(stderr, " %s", r.scope.c_str());
            }
        }
        if (shown == 0) std::fprintf(stderr, " (nothing)");
        else if (shown > 4) std::fprintf(stderr, " (+%d more)", shown - 4);
        std::fprintf(stderr, "\n");

        if (exec_denied) {
            // W^X is deliberate and surprising: a workspace grant carries no
            // execute right, so a freshly built binary will not run. Say so
            // outright -- this is the single most confusing denial in normal
            // build-and-test use.
            std::fprintf(stderr,
                "         note:    a write grant does NOT include execute. To run "
                "a binary you just built,\n"
                "                  add an `fs.exec` rule for its directory in a "
                "policy file.\n");
        }
        if (egress_blocked && policy.tier() < Tier::Isolate) {
            std::fprintf(stderr,
                "         network: DENIED at %s — use `-t t3 --net HOST:PORT`\n",
                std::string{tier_name(policy.tier())}.c_str());
        }
        if (net_is_denied) {
            // Stated as a FACT about the policy, not as a diagnosis of this
            // failure -- we cannot know whether the network was involved.
            std::fprintf(stderr,
                "         network: this policy grants no egress, so all "
                "outbound is kernel-denied.\n"
                "                  If the command needed the network: "
                "bastion run -t t3 --net HOST:PORT -- <cmd>\n");
        }
        std::fprintf(stderr,
            "         next:    bastion observe -- <cmd> && bastion synthesize\n");
    }

    // MACHINE-READABLE SUMMARY. `--json` was accepted, documented, and did
    // nothing except suppress the human advisories -- so an agent that asked
    // for structured output got an empty stream and had to scrape stderr
    // prose instead. That is the primary integration surface for the tool's
    // entire audience, so it emits a real object.
    //
    // Written to STDOUT after the workload's own output, as one line, so it
    // can be tailed or piped to a JSON parser. Everything an agent needs to
    // decide what happened next: whether it ran, whether the SANDBOX caused
    // the failure, what was granted, and what to do about it.
    if (a.json) {
        std::printf("{\"exit_code\":%d", result.exit_code);
        std::printf(",\"launched\":%s", result.launched() ? "true" : "false");
        std::printf(",\"tier\":\"%s\"",
                    std::string{tier_name(policy.tier())}.c_str());
        std::printf(",\"unconfined\":%s",
                    policy.is_unconfined() ? "true" : "false");

        // The distinction that matters most to a caller: did the sandbox do
        // this, or did the workload fail on its own? Same evidence the human
        // advisory uses -- never a guess from the exit code alone.
        std::printf(",\"sandbox_implicated\":%s",
                    (result.exit_code != 0 && likely_ours) ? "true" : "false");

        if (!result.error.empty()) {
            std::printf(",\"error\":\"%s\"",
                        json_str(result.error).c_str());
        }

        std::printf(",\"granted\":[");
        bool first = true;
        for (const auto& r : policy.rules()) {
            if (r.scope == "*") continue;
            std::printf("%s{\"op\":\"%s\",\"path\":\"%s\"}",
                        first ? "" : ",",
                        op_for(r.right),
                        json_str(r.scope).c_str());
            first = false;
        }
        std::printf("]");

        std::printf(",\"egress\":{\"allowed\":%llu,\"denied\":%llu,\"refused\":[",
                    (unsigned long long)result.egress_allowed,
                    (unsigned long long)result.egress_denied);
        first = true;
        for (const auto& [hostport, allowed] : result.egress_attempts) {
            if (allowed) continue;
            std::printf("%s\"%s\"", first ? "" : ",",
                        json_str(hostport).c_str());
            first = false;
        }
        std::printf("]}");

        std::printf(",\"warnings\":[");
        first = true;
        for (const auto& w : result.warnings) {
            std::printf("%s\"%s\"", first ? "" : ",", json_str(w).c_str());
            first = false;
        }
        std::printf("]}\n");
    }

    return result.exit_code;
}

int cmd_observe(const Args& a) {
    if (a.argv.empty()) {
        std::fputs("error: no command given (use `--` before it)\n", stderr);
        return 2;
    }

    // THE FLOOR APPLIES HERE TOO, and this is the entrance that matters most.
    //
    // `observe` runs the workload UNCONFINED -- that is what T0 IS, and it is
    // the whole reason the mode exists. So it is a strictly more powerful
    // bypass than --yolo: MEASURED, `BASTION_MIN_TIER=t2 bastion observe --
    // cat ~/.ssh/id_*` printed the private key while the same command under
    // `run --yolo` was correctly refused.
    //
    // An operator who sets a floor above T0 is saying "nothing unconfined runs
    // here", and observation is unconfined. The refusal names the tradeoff
    // rather than just denying, because observing IS how you build a policy --
    // the answer is to do it somewhere the floor permits it.
    std::string ferr;
    if (!floor_permits(Tier::Observe, /*is_yolo=*/false, ferr)) {
        std::fprintf(stderr,
            "error: `observe` runs the workload UNCONFINED, and %s\n"
            "       Observation is how a policy is discovered, so do it on a "
            "machine without a floor\n"
            "       (or with BASTION_MIN_TIER=t0), review the result, and "
            "commit it as bastion.toml.\n",
            ferr.c_str());
        return 2;
    }
    auto caps = observe_probe();
    if (!caps.available) {
        std::fprintf(stderr, "error: %s\n", caps.reason.c_str());
        return 2;
    }

    std::fprintf(stderr,
                 "bastion: T0 OBSERVE via %s — nothing is enforced, every\n"
                 "         access is recorded. Ctrl-C is safe.\n",
                 caps.mechanism.c_str());

    SpawnRequest req;
    req.argv = a.argv;
    auto res = observe(req);

    for (const auto& w : res.warnings) {
        std::fprintf(stderr, "bastion: [warning] %s\n", w.c_str());
    }
    if (!res.ok()) {
        std::fprintf(stderr, "bastion: %s\n", res.error.c_str());
        return 2;
    }

    if (!a.no_ledger) {
        Ledger led{a.ledger};

        // A session boundary, written BEFORE the observed accesses.
        //
        // The ledger is append-only and shared across runs, so without a
        // delimiter `synthesize` cannot tell this observation from every
        // earlier one -- MEASURED: two unrelated tasks produced a policy
        // granting both tasks' files. `run` already writes a proc.spawn
        // record; `observe` did not, so its output was indistinguishable from
        // the previous session's.
        AuditRecord start;
        start.verdict = Verdict::Allow;
        start.op = "proc.spawn";
        start.target = a.argv.front();
        start.tier = Tier::Observe;
        start.rule = "observed";
        led.record(start);

        for (const auto& r : res.records) led.record(r);
        if (auto err = led.flush(); !err.empty()) {
            std::fprintf(stderr, "bastion: [warning] ledger: %s\n", err.c_str());
        } else if (led.rotated()) {
            std::fprintf(stderr,
                         "bastion: ledger rotated; previous history is now %s.1\n",
                         a.ledger.c_str());
        }
    }

    std::fprintf(stderr,
                 "\nbastion: recorded %zu access(es)"
                 "%s\n         next: bastion synthesize%s\n",
                 res.records.size(),
                 res.dropped ? " (ignored other processes)" : "",
                 a.no_ledger ? " (note: --no-ledger, nothing was saved)" : "");
    return res.exit_code;
}

int cmd_synthesize(const Args& a) {
    std::string err;
    auto led = Ledger::load(a.ledger, err);
    if (!led) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        std::fputs("Run something under `bastion run` first — even with "
                   "--yolo; the ledger is written either way.\n", stderr);
        return 2;
    }
    auto syn = synthesize(*led);
    std::printf("%s", syn.to_toml().c_str());

    // Close the loop. The policy goes to STDOUT so it can be redirected; the
    // instructions go to STDERR so they never end up inside the file. Without
    // this the command just stops, and the user is left holding a policy with
    // no idea that `--policy` is what consumes it -- the on-ramp (DESIGN.md
    // §1) only works if its last step is discoverable.
    if (!syn.rules.empty()) {
        std::fprintf(stderr,
            "\nbastion: %zu grant(s) from %zu observed operation(s).\n"
            "         save:   bastion synthesize > bastion.toml\n"
            "         check:  bastion explain --policy bastion.toml\n"
            "         use:    bastion run --policy bastion.toml -- <cmd>\n"
            "\n"
            "         Review it first: these grants describe what the workload "
            "DID,\n"
            "         which is not always what it SHOULD be allowed to do.\n",
            syn.rules.size(), syn.observations);
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    Args a = parse(argc, argv);
    if (!a.error.empty()) {
        std::fprintf(stderr, "error: %s\n\n", a.error.c_str());
        print_usage();
        return 2;
    }
    if (a.cmd == "help" || a.cmd == "-h" || a.cmd == "--help") {
        print_usage();
        return 0;
    }
    if (a.cmd == "run")        return cmd_run(a);
    if (a.cmd == "observe")    return cmd_observe(a);
    if (a.cmd == "explain")    return cmd_explain(a);
    if (a.cmd == "doctor")     return cmd_doctor();
    if (a.cmd == "synthesize") return cmd_synthesize(a);

    std::fprintf(stderr, "error: unknown subcommand '%s'\n\n", a.cmd.c_str());
    print_usage();
    return 2;
}
