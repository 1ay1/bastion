// bastion CLI.
//
// UX thesis (DESIGN.md §1): the bypass is a capability, not a power switch.
// `--yolo` gives the user a frictionless wide-open run, and STILL produces a
// full ledger they can turn into a tight policy with `bastion synthesize`.
// Nobody is ever told "you're on your own".
#include "bastion/ledger.hpp"
#include "bastion/observe.hpp"
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
#  include "bastion/backend/landlock.hpp"
#endif

namespace fs = std::filesystem;
using namespace bastion;

namespace {

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

OTHER
  --ledger PATH          audit log location (default ~/.bastion/ledger.jsonl)
  --no-ledger            do not write an audit log
  --json                 machine-readable output
  -h, --help             this message

EXAMPLES
  # Tight, in whatever directory you happen to be in:
  bastion run -- cargo test

  # Don't know what it needs? Watch it, then lock it down:
  bastion observe -- ./weird-legacy-build.sh
  bastion synthesize > bastion.toml

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

struct Args {
    std::string cmd;
    std::vector<std::string> workspace;
    std::vector<std::string> read;
    std::vector<std::string> net;
    Tier tier = Tier::Kernel;
    bool yolo = false;
    bool json = false;
    bool no_ledger = false;
    std::string ledger = default_ledger_path();
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
        else if (s == "--net")                 a.net.push_back(next("--net"));
        else if (s == "--ledger")              a.ledger = next("--ledger");
        else if (s == "--no-ledger")           a.no_ledger = true;
        else if (s == "--json")                a.json = true;
        else if (s == "--yolo")                a.yolo = true;
        else if (s == "-t" || s == "--tier") {
            bool ok = false;
            a.tier = parse_tier(next("--tier"), ok);
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

Sealed build_policy(const Args& a, Broker& broker) {
    Policy p{a.tier};

    if (a.yolo) {
        // The bypass, as a capability. Witnessed, and still audited.
        return std::move(p)
            .unconfined(broker.grant_unconfined(Witness{"user passed --yolo"}))
            .seal();
    }

    if (a.workspace.empty() && a.read.empty()) {
        // Path-set authority means the CURRENT directory just works -- there is
        // no fixed sandbox root to symlink things into (DESIGN.md §3).
        std::error_code ec;
        auto cwd = fs::current_path(ec);
        if (!ec) {
            p = std::move(p).allow(Right::FsRead | Right::FsWrite, cwd,
                                   "current directory (default workspace)");
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

    bool any_cache = false;
    for (const char* k : {"CARGO_HOME", "GOCACHE", "npm_config_cache",
                          "PIP_CACHE_DIR", "CCACHE_DIR"}) {
        if (const char* v = std::getenv(k); v && *v) any_cache = true;
    }
    check("toolchain cache env present", any_cache,
          "no CARGO_HOME/GOCACHE/npm_config_cache set; builds will re-download "
          "dependencies on every run and the agent will look broken");

    std::printf("\n%s\n", problems == 0
                              ? "ready: the floor is satisfied."
                              : "warnings above will cause agent thrashing.");
    return 0;
}

int cmd_explain(const Args& a) {
    Broker broker;
    auto policy = build_policy(a, broker);
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
    for (const auto& w : compiled.warnings) {
        std::printf("\n[warning] %s\n", w.c_str());
    }
#elif defined(__linux__)
    auto abi = linux_ll::probe_abi();
    auto rs = linux_ll::compile(policy, abi);
    for (const auto& w : rs.warnings) std::printf("\n[warning] %s\n", w.c_str());
#endif
    return 0;
}

int cmd_run(const Args& a) {
    if (a.argv.empty()) {
        std::fputs("error: no command given (use `--` before it)\n", stderr);
        return 2;
    }

    Broker broker;
    auto policy = build_policy(a, broker);
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
                         "         remedy: bastion run --net %s\n",
                         hostport.c_str(), hostport.c_str());
        }
    }
    if (!result.launched()) {
        std::fprintf(stderr, "bastion: %s\n", result.error.c_str());
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
        }
    }
    return result.exit_code;
}

int cmd_observe(const Args& a) {
    if (a.argv.empty()) {
        std::fputs("error: no command given (use `--` before it)\n", stderr);
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
        for (const auto& r : res.records) led.record(r);
        if (auto err = led.flush(); !err.empty()) {
            std::fprintf(stderr, "bastion: [warning] ledger: %s\n", err.c_str());
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
