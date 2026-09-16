#include "bastion/spawn.hpp"

#include "bastion/signal_forward.hpp"
#include "bastion/unique_fd.hpp"

#include <spawn.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <set>
#include <memory>

#if defined(__APPLE__)
#  include <crt_externs.h>
#  define BASTION_ENVIRON (*_NSGetEnviron())
#  include "bastion/backend/seatbelt.hpp"
#  include "bastion/proxy.hpp"
// Declared at file scope: sandbox_init(3) has no public SDK header.
extern "C" int sandbox_init(const char* profile, uint64_t flags, char** errorbuf);
#elif defined(__linux__)
#  include "bastion/backend/cgroup.hpp"
#  include "bastion/backend/landlock.hpp"
#  include "bastion/backend/namespaces.hpp"
#  include "bastion/proxy.hpp"
extern "C" char** environ;
#  define BASTION_ENVIRON environ
#else
extern "C" char** environ;
#  define BASTION_ENVIRON environ
#endif

namespace bastion {

namespace {

// Distinguished exit codes so a confinement failure is never mistaken for the
// child's own exit status.
constexpr int kExitSandboxFailed = 126;
constexpr int kExitChdirFailed = 125;
constexpr int kExitExecFailed = 127;

// Which setup step failed, reported over a CLOEXEC pipe rather than inferred
// from the exit status.
//
// MEASURED: exit-code signalling alone is AMBIGUOUS and reports false escapes.
// A POSIX shell exits 126 for "found but not executable" and 127 for "not
// found" -- exactly the codes above. So a *correctly confined* child that
// tried to exec a binary Landlock denied came back as "bastion failed to apply
// the policy", turning a successful block into a reported failure
// (tests/adversarial_test.cpp §4, "exec a copied shell to shed policy").
//
// The pipe is unambiguous: it carries a byte ONLY if bastion's own setup
// failed, and execve() closes it silently on success (O_CLOEXEC), so EOF
// means "the child really started".
enum class ChildStage : unsigned char {
    Chdir = 1,
    Sandbox = 2,
    Exec = 3,

    // DEGRADED, not failed. Everything above means "bastion could not set the
    // child up, so it was NOT executed". This one means the workload DID run
    // with the full kernel boundary, but one defence-in-depth layer could not
    // be installed. Reported as a warning; the exit code stays the workload's
    // own, because the run really did happen.
    //
    // It exists because the alternative was worse: the namespace failure used
    // to be discarded entirely, so a run that silently lost process isolation
    // was indistinguishable from one that had it.
    Namespace = 100,
};

// Is this stage a setup FAILURE (workload never ran) or a DEGRADATION?
constexpr bool is_fatal_stage(ChildStage s) noexcept {
    return s != ChildStage::Namespace;
}

// Pick a working directory the child actually has authority to read.
//
// ERGONOMIC FLOOR (DESIGN.md §4). If the child inherits bastion's cwd without a
// grant covering it, `getcwd(3)` fails and every shell start-up emits
//   "shell-init: error retrieving current directory"
// on stderr. Observed live: 26 such lines across one test run. Tools then
// misbehave in ways that look like broken code rather than a policy problem,
// which is exactly how an agent ends up "going around in circles" and how a
// sandbox ends up switched off. So: prefer the widest writable grant (the
// workspace), else a readable grant, else $TMPDIR.
std::string choose_cwd(const Sealed& policy) {
    // PREFER THE DIRECTORY THE USER IS STANDING IN, if the policy grants it.
    //
    // MEASURED: a synthesized policy contains grants for several directories
    // (the workspace, /tmp, toolchain caches). Picking the first writable one
    // in rule order dropped the child into /tmp, so `bastion run --policy p
    // -- cc m.c` failed with "m.c: No such file or directory" -- the file was
    // right there in the user's cwd. Every relative path an agent uses is
    // relative to where it invoked bastion, so that is the only cwd that does
    // not silently break them.
    std::error_code cec;
    const auto here = std::filesystem::current_path(cec);
    if (!cec) {
        const std::string cwd = here.string();
        for (const auto& r : policy.rules()) {
            if (r.scope == "*") continue;
            if (!any(r.right & (Right::FsRead | Right::FsWrite))) continue;
            // Granted exactly, or as an ancestor (path-set authority covers
            // everything beneath a granted directory).
            if (cwd == r.scope ||
                (cwd.size() > r.scope.size() && cwd.starts_with(r.scope) &&
                 cwd[r.scope.size()] == '/')) {
                return cwd;
            }
        }
    }

    // Otherwise fall back to a granted directory, preferring a writable one.
    const std::string* read_only = nullptr;
    for (const auto& r : policy.rules()) {
        if (r.scope == "*") continue;
        std::error_code ec;
        if (!std::filesystem::is_directory(r.scope, ec) || ec) continue;
        if (any(r.right & Right::FsWrite)) return r.scope;  // best: writable
        if (!read_only && any(r.right & Right::FsRead)) read_only = &r.scope;
    }
    if (read_only) return *read_only;
    const char* tmp = std::getenv("TMPDIR");
    return (tmp && *tmp) ? tmp : "/tmp";
}

const char* getenv_or(const char* k, const char* fallback) {
    const char* v = std::getenv(k);
    return (v && *v) ? v : fallback;
}

// Environment variables that must never be inherited into a sandbox: they are
// either credential material or a code-injection vector.
bool is_dangerous_env(std::string_view kv) {
    static constexpr std::string_view kDeny[] = {
        "DYLD_INSERT_LIBRARIES=", "DYLD_LIBRARY_PATH=", "LD_PRELOAD=",
        "LD_LIBRARY_PATH=", "LD_AUDIT=",
    };
    for (auto d : kDeny) {
        if (kv.starts_with(d)) return true;
    }
    // Heuristic credential scrub.
    static constexpr std::string_view kSecrets[] = {
        "_TOKEN=", "_SECRET=", "_KEY=", "_PASSWORD=", "_CREDENTIALS=",
        "AWS_", "GITHUB_TOKEN", "ANTHROPIC_API", "OPENAI_API",
    };
    for (auto s : kSecrets) {
        if (kv.find(s) != std::string_view::npos) return true;
    }
    return false;
}

// Close every descriptor above stderr before exec.
//
// SECURITY -- this closes a MEASURED sandbox escape, not a theoretical one.
// Access rights attach to an OPEN FILE DESCRIPTION, not to the path, on both
// Seatbelt and Landlock (the Landlock docs state this explicitly). So a
// descriptor opened BEFORE confinement keeps working afterwards and survives
// exec. Verified: a child denied the path could still read(2) an inherited fd
// and recovered the secret in full -- the entire path policy bypassed by one
// leaked descriptor.
//
// Agent hosts are exactly the programs that hold config, credential and log
// files open while spawning tools, so this is a live exposure. bastion closes
// the range rather than trusting every caller to set O_CLOEXEC everywhere.
//
// Async-signal-safe: only close(2) and getrlimit-derived arithmetic.
//
// `keep` is spared: it is bastion's own CLOEXEC status pipe, which must survive
// until execve() closes it (that closure is the success signal). It is not an
// inherited descriptor -- we created it -- and it is write-only to the parent.
void close_inherited_fds(int keep = -1) {
    int max_fd = -1;
    struct rlimit rl {};
    if (::getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY) {
        max_fd = static_cast<int>(rl.rlim_cur);
    }
    if (max_fd < 0 || max_fd > 65536) max_fd = 65536;  // sane cap
    for (int fd = STDERR_FILENO + 1; fd < max_fd; ++fd) {
        if (fd == keep) continue;
        ::close(fd);  // EBADF is fine and expected
    }
}

// System directories, always present so a sandbox works even with no $PATH.
constexpr std::string_view kSystemPath =
    "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin";

// The PATH the child will see, and the directories the floor grants exec on.
//
// THE PROBLEM. Toolchains do not live in /usr any more. webinstall.dev puts Go
// in ~/.local/opt and links it into ~/.local/bin; pipx, `go install`, `cargo
// install`, bun, deno all use their own prefixes; mise/asdf/pyenv/rbenv use
// per-user SHIM directories whose paths nobody can guess. REPORTED against a
// sibling project and reproduced here: `gofmt` failed with "binary missing or
// not executable" inside the sandbox while sitting plainly on the user's PATH
// outside.
//
// THE WRONG FIX is a hardcoded list of ~/.local/bin, ~/.cargo/bin, ~/go/bin,
// ~/.bun/bin, ~/.asdf/shims ... That list is never finished, and every entry
// it lacks is the same bug reported again by a different user.
//
// THE FIX: inherit the user's OWN $PATH, which is the authoritative statement
// of where their tools are -- they already maintain it, for exactly this
// purpose. Filtered, because a sandbox may not simply trust an inherited
// environment variable:
//
//   - relative entries are dropped. A "." or "build/bin" on PATH resolves
//     against the WORKLOAD's cwd, so a hostile repo could ship a `git` that
//     runs on checkout. Absolute paths only.
//   - world-writable directories are dropped unless owned by this user. A
//     stale /tmp/mybin on someone's PATH is a place any local process can
//     plant a binary that the sandbox would then execute.
//   - non-existent entries are dropped, so a typo'd PATH does not turn into a
//     grant for a directory someone can later create.
//
// Order is preserved, so which tool a name resolves to is the same inside the
// sandbox as outside -- a sandbox that silently ran a DIFFERENT `python` than
// the shell would be worse than one that ran none.
}  // namespace

const std::vector<std::string>& sandbox_path_dirs() {
    static const std::vector<std::string> dirs = [] {
        std::vector<std::string> out;
        std::set<std::string> seen;
        const uid_t me = ::getuid();

        const auto consider = [&](std::string_view d) {
            if (d.empty() || d.front() != '/') return;  // relative: unsafe
            std::error_code ec;
            const std::string s{d};
            if (!std::filesystem::is_directory(s, ec) || ec) return;

            // Reject anything world-writable that we do not own: another
            // local user could drop a binary in it.
            struct ::stat st {};
            if (::stat(s.c_str(), &st) != 0) return;
            if ((st.st_mode & S_IWOTH) && st.st_uid != me) return;

            if (seen.insert(s).second) out.push_back(s);
        };

        // The user's PATH first, in their order.
        if (const char* p = std::getenv("PATH"); p && *p) {
            std::string_view rest{p};
            while (!rest.empty()) {
                const auto colon = rest.find(':');
                consider(rest.substr(0, colon));
                if (colon == std::string_view::npos) break;
                rest = rest.substr(colon + 1);
            }
        }
        // Then the system defaults, so a cleared or minimal PATH still yields
        // a working sandbox rather than one that cannot find /bin/sh.
        {
            std::string_view rest = kSystemPath;
            while (!rest.empty()) {
                const auto colon = rest.find(':');
                consider(rest.substr(0, colon));
                if (colon == std::string_view::npos) break;
                rest = rest.substr(colon + 1);
            }
        }
        return out;
    }();
    return dirs;
}

namespace {

// The same set as a PATH string for the child's environment.
const std::string& sandbox_path() {
    static const std::string p = [] {
        std::string s;
        for (const auto& d : sandbox_path_dirs()) {
            if (!s.empty()) s += ':';
            s += d;
        }
        return s;
    }();
    return p;
}

// Resolve a bare command name to an absolute path, the way a shell would.
//
// WHY THIS IS NOT execvp(): the child must confine BEFORE exec, and by then it
// cannot search $PATH -- a Landlock ruleset built around the workspace will not
// grant read on every PATH entry, and the child may not allocate anyway. So the
// lookup happens HERE, in the parent, before the policy is compiled.
//
// It searches the same directories the CHILD will get (sandbox_path_dirs()),
// not bastion's own raw PATH. Resolving against an unvetted PATH would find
// binaries in directories the sandbox does not grant exec on, turning a clear
// "not found" into a confusing mid-run denial.
//
// MEASURED: without this, `bastion run -- cc main.c` failed with "exec failed
// (binary missing or not executable)" while `bastion observe -- cc main.c`
// worked, because the observe backend used execvp(). Two subcommands, two
// behaviours, and the first thing an agent types is a bare command name.
std::string resolve_argv0(const std::string& cmd) {
    // Anything with a slash is already a path: absolute, or relative to cwd,
    // exactly as execve() would treat it.
    if (cmd.find('/') != std::string::npos) return cmd;

    for (const auto& dir : sandbox_path_dirs()) {
        std::string candidate = dir;
        candidate += '/';
        candidate += cmd;

        // access(X_OK) is NOT sufficient: it returns 0 for a DIRECTORY with
        // the search bit set, and PATH directories really do contain
        // subdirectories (/usr/bin/core_perl, /usr/bin/db5.3 on this box). A
        // bare `core_perl` would then resolve to a directory and execve would
        // fail with EACCES -- reported as "binary missing or not executable",
        // which is exactly the confusing message this function exists to
        // prevent. Require a regular file, as a shell does.
        struct ::stat st {};
        if (::stat(candidate.c_str(), &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;
        if (::access(candidate.c_str(), X_OK) == 0) return candidate;
    }
    // Not found: hand back the original so the error names what was asked for
    // rather than some half-built path.
    return cmd;
}

}  // namespace

std::vector<std::string> sanitized_env(const Sealed& policy) {
    std::vector<std::string> env;

    // A coherent PATH whose entries are readable under the base profile.
    env.emplace_back("PATH=" + sandbox_path());
    env.emplace_back(std::string{"HOME="} + getenv_or("HOME", "/tmp"));
    env.emplace_back(std::string{"USER="} + getenv_or("USER", "agent"));
    env.emplace_back(std::string{"SHELL="} + getenv_or("SHELL", "/bin/sh"));
    env.emplace_back("LANG=en_US.UTF-8");
    env.emplace_back(std::string{"TERM="} + getenv_or("TERM", "dumb"));

    // The ergonomic floor (DESIGN.md §4). The field report's single biggest
    // win was "the return of rw in /tmp ... LLMs will stop going around in
    // circles", so TMPDIR pointing at a writable location is asserted here
    // rather than left to chance.
    //
    // It must point at a directory the policy actually GRANTS. On Linux the
    // backend refuses to grant shared world-readable /tmp (it would leak
    // between agents on the same box -- measured as 6 adversarial escapes) and
    // mints a private per-run dir instead, so TMPDIR has to name that one.
    // Defaulting to "/tmp" here would hand the toolchain a path the kernel
    // denies, which is the "broken compiler" failure §4 exists to prevent.
    std::string tmp = getenv_or("TMPDIR", "");
#if defined(__linux__)
    if (tmp.empty() && !policy.is_unconfined()) tmp = linux_ll::private_tmp_dir();
#endif
    if (tmp.empty()) tmp = "/tmp";
    env.emplace_back("TMPDIR=" + tmp);
    // Some toolchains read TMP/TEMP instead; keep all three consistent so the
    // scratch dir is the granted one no matter which name is consulted.
    env.emplace_back("TMP=" + tmp);
    env.emplace_back("TEMP=" + tmp);

    // Toolchain caches must be writable AND persistent across runs, or every
    // build re-downloads the world and the agent looks broken.
    for (const char* k : {"CARGO_HOME", "RUSTUP_HOME", "GOCACHE", "GOMODCACHE",
                          "GOPATH", "npm_config_cache", "PIP_CACHE_DIR",
                          "CCACHE_DIR", "ZIG_GLOBAL_CACHE_DIR"}) {
        if (const char* v = std::getenv(k); v && *v) {
            env.emplace_back(std::string{k} + "=" + v);
        }
    }

    env.emplace_back("BASTION_ACTIVE=1");
    env.emplace_back(std::string{"BASTION_TIER="} +
                     std::string{tier_name(policy.tier())});
    if (policy.is_unconfined()) env.emplace_back("BASTION_UNCONFINED=1");

    // PWD must agree with the cwd we chdir to, or shells report a stale path.
    if (!policy.is_unconfined()) {
        env.emplace_back("PWD=" + choose_cwd(policy));
    }
    return env;
}

SpawnResult spawn(const Sealed& policy, const SpawnRequest& req) {
    SpawnResult out;
    if (req.argv.empty()) {
        out.error = "empty argv";
        return out;
    }

    // ---- T3 egress broker (platform-independent) --------------------------
    //
    // The broker itself is portable C++; only the KERNEL PIN that makes it
    // unbypassable is backend-specific (Seatbelt `remote ip localhost:PORT`,
    // Landlock NET_CONNECT_TCP on that port). So it is started here, before
    // either backend compiles its policy, and both pin to the same port.
    std::unique_ptr<EgressProxy> proxy;
    std::uint16_t proxy_port = 0;
#if defined(__APPLE__) || defined(__linux__)
    if (policy.tier() >= Tier::Isolate && !policy.is_unconfined()) {
        std::vector<EgressRule> allow;
        for (const auto& r : policy.rules()) {
            if (any(r.right & (Right::NetEgress | Right::NetBind))) {
                allow.push_back(parse_egress_rule(r.scope));
            }
        }
        if (!allow.empty()) {
            std::string perr;
            proxy = EgressProxy::start(std::move(allow), perr);
            if (!proxy) {
                out.error = "T3 requires the egress proxy, which failed to "
                            "start: " + perr +
                            " (refusing to run with unrestricted egress)";
                return out;  // fail closed
            }
            proxy_port = proxy->port();
            out.proxy_port = proxy_port;
        }
    }
#endif

#if defined(__APPLE__)
    auto compiled_r = darwin::compile(policy, proxy_port);
    if (!compiled_r) {
        out.error = "policy compilation failed: " + compiled_r.error();
        return out;  // fail closed: never launch with a broken policy
    }
    // Only reachable on success, so the profile really compiled.
    const darwin::CompileResult compiled = std::move(compiled_r).value();
    out.profile = compiled.profile;
    out.warnings = compiled.warnings;

#elif defined(__linux__)
    // Landlock has no text profile; the ruleset is applied directly in the
    // child (see below). Compile HERE, in the parent, for two reasons:
    //   1. fail BEFORE forking if the kernel cannot express what was asked for;
    //   2. the child must not allocate. At T3 the egress broker's accept
    //      thread is already running, and a child forked from a multithreaded
    //      process deadlocks if it takes a malloc lock another thread held at
    //      fork time. So the child gets a ready-made Ruleset and only makes
    //      syscalls (linux_ll::apply_compiled).
    const auto ll_abi = linux_ll::probe_abi();
    if (ll_abi.version < 0 && policy.tier() >= Tier::Kernel &&
        !policy.is_unconfined()) {
        out.error =
            "policy requires T2 kernel enforcement but Landlock is "
            "unavailable: " + ll_abi.note +
            " -- refusing to run unconfined";
        return out;  // fail closed
    }
    // NOTE: compiled WITH proxy_port. An earlier version compiled without it
    // here and re-compiled inside the child, so this copy silently lacked the
    // T3 broker port rule; now that the child uses this exact ruleset, the
    // port must be baked in or T3 would deny its own broker.
    auto ll_compiled = linux_ll::compile(policy, ll_abi, proxy_port);
    if (!ll_compiled && policy.tier() >= Tier::Kernel && !policy.is_unconfined()) {
        out.error = "ruleset compilation failed: " + ll_compiled.error();
        return out;  // fail closed
    }
    // Only the TRIVIALLY COPYABLE half crosses into the child. ll_abi carries a
    // std::string note, and touching that in the child could deadlock on the
    // allocator -- forksafe.hpp turns that mistake into a compile error.
    const linux_ll::AbiCore ll_core = ll_abi.core();

    // An empty Ruleset stands in when compilation failed at a tier that
    // tolerates it (T0/T1). ll_ready gates the child, so it is never enforced.
    // NOTE: read ok() BEFORE moving out of the Result -- reading it after would
    // be querying a moved-from object.
    const bool ll_ready = ll_compiled.ok() && !policy.is_unconfined();
    const linux_ll::Ruleset ll_rules =
        ll_compiled ? std::move(ll_compiled).value() : linux_ll::Ruleset{};
    {
        out.warnings = ll_rules.warnings;
        out.profile = "landlock: " + ll_abi.note + ", " +
                      std::to_string(ll_rules.paths.size()) + " path rule(s), " +
                      std::to_string(ll_rules.ports.size()) + " port rule(s)";
    }

#else
    out.warnings.emplace_back(
        "no kernel backend compiled for this platform; T2 unavailable");
    if (policy.tier() >= Tier::Kernel && !policy.is_unconfined()) {
        out.error =
            "policy requires T2 kernel enforcement but no backend is available "
            "on this platform; refusing to launch unconfined";
        return out;  // a missing sandbox must never silently become no sandbox
    }
#endif

    // Build argv/env as raw pointers before forking: no allocation is safe
    // between fork() and exec() in a multithreaded process.
    std::vector<std::string> env_storage =
        req.inherit_env ? std::vector<std::string>{} : sanitized_env(policy);
    if (req.inherit_env) {
        for (char** e = BASTION_ENVIRON; e && *e; ++e) {
            if (!is_dangerous_env(*e)) env_storage.emplace_back(*e);
        }
    }
    for (const auto& kv : req.env) env_storage.push_back(kv);

#if defined(__APPLE__) || defined(__linux__)
    // Point the child at the broker. Every mainstream HTTP client honours
    // these, so tools work unmodified -- and it does not matter if one does
    // not: the kernel has already denied every other route out, so ignoring
    // the variables means no network rather than a bypass.
    if (proxy_port != 0) {
        const std::string url =
            "http://127.0.0.1:" + std::to_string(proxy_port);
        for (const char* k : {"HTTP_PROXY", "HTTPS_PROXY", "http_proxy",
                              "https_proxy", "ALL_PROXY", "all_proxy"}) {
            env_storage.push_back(std::string{k} + "=" + url);
        }
        env_storage.emplace_back("NO_PROXY=");
        env_storage.emplace_back("no_proxy=");
        env_storage.push_back("BASTION_PROXY_PORT=" + std::to_string(proxy_port));
    }
#endif

    // Resolve a bare command name against the SANDBOX's PATH before forking.
    // The child cannot search PATH itself: it is confined before exec, and may
    // not allocate. Held in a named string so the c_str() below stays valid.
    const std::string argv0 = resolve_argv0(req.argv[0]);

    std::vector<char*> cargv;
    cargv.reserve(req.argv.size() + 1);
    cargv.push_back(const_cast<char*>(argv0.c_str()));
    for (std::size_t i = 1; i < req.argv.size(); ++i) {
        cargv.push_back(const_cast<char*>(req.argv[i].c_str()));
    }
    cargv.push_back(nullptr);

    std::vector<char*> cenv;
    cenv.reserve(env_storage.size() + 1);
    for (const auto& e : env_storage) cenv.push_back(const_cast<char*>(e.c_str()));
    cenv.push_back(nullptr);

    // A cwd the child can actually read (see choose_cwd). An explicit request
    // wins; otherwise we pick a granted directory rather than inheriting an
    // unauthorized one.
    const std::string cwd_storage =
        req.cwd ? *req.cwd
                : (policy.is_unconfined() ? std::string{} : choose_cwd(policy));
    const char* cwd = cwd_storage.empty() ? nullptr : cwd_storage.c_str();

    // T3 process isolation: decided BEFORE fork, because probe() forks and
    // allocates and neither is allowed in the child half of this function.
    bool ns_isolate = false;

    // Per-sandbox budget state. Declared unconditionally so the child block
    // below (which is compiled on every platform) can reference it.
    bool cgroup_took_pids = false;
    std::string cgroup_procs_storage;

#if defined(__linux__)
    if (policy.tier() >= Tier::Isolate && !policy.is_unconfined()) {
        const auto ns = linux_ns::probe();
        ns_isolate = ns.available && ns.pid;
        if (!ns_isolate && !ns.reason.empty()) {
            out.warnings.push_back(ns.reason);
        }
    }

    // A real per-sandbox budget, when the kernel and the session allow one.
    // Created BEFORE fork so the child can join it the instant it exists, and
    // held by the parent for the lifetime of the run (its destructor rmdir's
    // it, which only succeeds once the cgroup is empty).
    linux_cgroup::Cgroup cg;
    if (req.limits.max_processes > 0 || req.limits.max_memory_bytes > 0) {
        cg = linux_cgroup::Cgroup::create(req.limits.max_processes,
                                          req.limits.max_memory_bytes);
        if (cg.valid()) {
            cgroup_took_pids = req.limits.max_processes > 0;
            // Materialised now: the child may only make async-signal-safe
            // calls, so the path string cannot be built after fork.
            cgroup_procs_storage = cg.path() + "/cgroup.procs";
        } else {
            // Not fatal: a budget is a mitigation, not a boundary. Losing it
            // must never become a refusal to run behind a working kernel
            // boundary -- but it must be SAID, not silently dropped.
            if (req.limits.max_memory_bytes > 0) {
                out.warnings.push_back(
                    "memory limit ignored: " + cg.error() +
                    " (no rlimit equivalent -- RLIMIT_AS caps address space, "
                    "not resident memory, and breaks working programs)");
            }
            if (req.limits.max_processes > 0) {
                out.warnings.push_back(
                    "per-sandbox process budget unavailable: " + cg.error() +
                    " falling back to RLIMIT_NPROC, which is counted per-uid");
            }
        }
    }

    // RLIMIT_NPROC counts THREADS already owned by this uid system-wide, not
    // processes in this sandbox. A cap below the current count makes the very
    // first fork fail with EAGAIN, which surfaces as "/bin/sh: fork: Resource
    // temporarily unavailable" and looks like a broken toolchain rather than a
    // limit the user chose. Warn BEFORE running rather than let them debug it.
    //
    // Only relevant on the FALLBACK path: with a cgroup the number means what
    // the user thinks it means, and this warning would be nonsense.
    if (req.limits.max_processes > 0 && !cgroup_took_pids) {
        std::error_code lec;
        std::size_t threads = 0;
        const uid_t me = ::getuid();
        for (const auto& e :
             std::filesystem::directory_iterator("/proc", lec)) {
            if (lec) break;
            const auto name = e.path().filename().string();
            if (name.empty() || !std::isdigit(static_cast<unsigned char>(name[0]))) {
                continue;
            }
            // Only OUR uid: RLIMIT_NPROC is accounted per real uid.
            // (`struct stat` and `::stat` collide here, so go through the
            // filesystem library rather than the POSIX call.)
            struct ::stat st {};
            if (::stat(e.path().c_str(), &st) != 0 ||
                st.st_uid != me) {
                continue;
            }

            std::error_code tec;
            for (const auto& t :
                 std::filesystem::directory_iterator(e.path() / "task", tec)) {
                if (tec) break;
                (void)t;
                ++threads;
            }
        }
        if (threads > 0 && req.limits.max_processes <= threads) {
            out.warnings.push_back(
                "--max-procs " + std::to_string(req.limits.max_processes) +
                " is at or below the ~" + std::to_string(threads) +
                " threads this uid already has running; RLIMIT_NPROC counts "
                "those, so the workload will fail to fork. Raise it well above "
                "that number -- it is a fork-bomb backstop, not a budget.");
        }
    }
#endif

    // Materialised before fork: the child may only make async-signal-safe
    // calls, so neither the string nor c_str() may happen after it.
    const char* cgroup_procs =
        cgroup_procs_storage.empty() ? nullptr : cgroup_procs_storage.c_str();

    // Status pipe: the child writes one ChildStage byte if ITS OWN setup fails.
    // O_CLOEXEC means a successful execve closes it without a write, so the
    // parent reads EOF and knows the workload really started -- no inference
    // from an exit code the workload itself can produce.
    //
    // Owned by UniqueFd so no return path can leak them. An earlier version
    // hand-closed these and MISSED the macOS case where pipe() succeeds but
    // fcntl() fails -- two descriptors leaked per attempt. A leaked fd here is
    // not merely a resource: rights attach to the open file description, so a
    // stray descriptor is authority that outlives its scope.
    int raw_pipe[2] = {-1, -1};
#if defined(__linux__)
    // pipe2 sets CLOEXEC atomically: with pipe()+fcntl() a concurrent fork in
    // another thread could inherit the not-yet-CLOEXEC write end and hold it
    // open, and the parent would then block forever waiting for an EOF.
    const bool created = ::pipe2(raw_pipe, O_CLOEXEC) == 0;
    UniqueFd pipe_r{raw_pipe[0]}, pipe_w{raw_pipe[1]};
    const bool pipe_ok = created;
#else
    // macOS has no pipe2(2), so there is an unavoidable window between pipe()
    // and fcntl() in which a concurrent fork could inherit the write end.
    // bastion DOES fork from a multithreaded process at T3 (the egress broker
    // runs an accept thread), but only bastion itself forks, and it does so
    // from this one function -- so nothing else is racing these descriptors.
    const bool created = ::pipe(raw_pipe) == 0;
    // Adopt IMMEDIATELY, before the fcntl calls that may fail: from here on
    // both ends are closed by the destructor no matter which path is taken.
    UniqueFd pipe_r{raw_pipe[0]}, pipe_w{raw_pipe[1]};
    const bool pipe_ok =
        created &&
        ::fcntl(pipe_r.get(), F_SETFD, FD_CLOEXEC) == 0 &&
        ::fcntl(pipe_w.get(), F_SETFD, FD_CLOEXEC) == 0;
#endif
    if (!pipe_ok) {
        out.error = std::string{"status pipe failed: "} + std::strerror(errno);
        return out;  // both ends closed by ~UniqueFd
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        out.error = std::string{"fork failed: "} + std::strerror(errno);
        return out;  // both ends closed by ~UniqueFd
    }

    if (pid == 0) {
        // ---- child ---------------------------------------------------------
        // Ordering is load-bearing (see spawn.hpp). Only async-signal-safe
        // calls past this point; no allocation, no iostreams.
        //
        // Raw ints from here: UniqueFd's destructor would close the write end
        // on the _exit path, and the child must control that lifetime itself.
        pipe_r.reset();
        const int sfd = pipe_w.release();

        // Report which step failed, then exit. write(2) is async-signal-safe;
        // the result is deliberately ignored (nothing useful to do if the
        // parent is gone, and the exit code still carries a coarse signal).
        const auto fail = [sfd](ChildStage st, int code) {
            const unsigned char b = static_cast<unsigned char>(st);
            ssize_t n;
            do { n = ::write(sfd, &b, 1); } while (n < 0 && errno == EINTR);
            _exit(code);
        };

        // Report a DEGRADATION and keep going: the workload still runs behind
        // the kernel boundary, it has just lost one defence-in-depth layer.
        // The parent turns this into a warning rather than an error.
        const auto fail_soft = [sfd](ChildStage st) {
            const unsigned char b = static_cast<unsigned char>(st);
            ssize_t n;
            do { n = ::write(sfd, &b, 1); } while (n < 0 && errno == EINTR);
        };

        if (cwd && ::chdir(cwd) != 0) fail(ChildStage::Chdir, kExitChdirFailed);

        // Join the per-sandbox cgroup. The CHILD does this to itself rather
        // than the parent doing it after fork, which would race: the child
        // could reach execve -- or fork again -- before the parent's write
        // landed, and anything spawned in that window would escape the budget.
        // Writing our own pid is race-free by construction.
        //
        // Must be here: before namespaces (inside a user namespace the cgroup
        // directory is no longer ours to write) and before Landlock (which
        // makes /sys/fs/cgroup unreachable). Only open/write/close, so it is
        // async-signal-safe.
        if (cgroup_procs) {
            const int cfd = ::open(cgroup_procs, O_WRONLY | O_CLOEXEC);
            if (cfd >= 0) {
                char buf[24];
                int n = 0;
                unsigned long v = static_cast<unsigned long>(::getpid());
                char tmp[24];
                int t = 0;
                if (v == 0) tmp[t++] = '0';
                while (v > 0) { tmp[t++] = static_cast<char>('0' + v % 10); v /= 10; }
                while (t > 0) buf[n++] = tmp[--t];
                (void)::write(cfd, buf, static_cast<std::size_t>(n));
                ::close(cfd);
            }
            // A failure here loses the budget, not the boundary, and the
            // parent already reported whether the cgroup was created.
        }

        // Resource ceilings. Applied BEFORE confinement so they bound the
        // sandbox setup too, and before exec so the workload can never run
        // without them. Lowering the HARD limit is irreversible for an
        // unprivileged process, so the child cannot raise these back.
        //
        // setrlimit failures are deliberately NOT fatal: a ceiling we could
        // not install is a lost mitigation, not a breach, and refusing to run
        // would trade a working kernel boundary for nothing.
        {
            const auto& L = req.limits;
            struct rlimit rl {};
            // Only when no cgroup took the budget: applying BOTH would mean the
            // effective cap is the uid-wide rlimit, silently overriding the
            // per-sandbox number the user actually asked for.
            if (L.max_processes > 0 && !cgroup_took_pids) {
                rl.rlim_cur = rl.rlim_max = L.max_processes;
                ::setrlimit(RLIMIT_NPROC, &rl);
            }
            if (L.max_file_bytes > 0) {
                rl.rlim_cur = rl.rlim_max = L.max_file_bytes;
                ::setrlimit(RLIMIT_FSIZE, &rl);
            }
            if (L.max_cpu_seconds > 0) {
                rl.rlim_cur = rl.rlim_max = L.max_cpu_seconds;
                ::setrlimit(RLIMIT_CPU, &rl);
            }
            if (!L.allow_core_dumps) {
                // A crashing confined process should not write a memory image
                // (which can hold secrets read from granted paths) into the
                // workspace. Cheap, and safe to apply unconditionally.
                rl.rlim_cur = rl.rlim_max = 0;
                ::setrlimit(RLIMIT_CORE, &rl);
            }
        }

        // Own process group, so the ENTIRE subtree (children, grandchildren,
        // anything exec'd) shares one pgid. T0 observation filters audit
        // records on this; without it, attribution has to guess by process
        // name and loses every grandchild's accesses.
        ::setpgid(0, 0);

        // Drop inherited descriptors BEFORE confining. An fd opened by the
        // parent carries its own access rights past the sandbox boundary
        // (measured -- see close_inherited_fds), so leaving one open would
        // hand the child a hole straight through the path policy.
        close_inherited_fds(sfd);

#if defined(__APPLE__)
        // Confinement lands here: after fork (so bastion stays unconfined),
        // before exec (so the child can never run unconfined).
        if (sandbox_init(compiled.profile.c_str(), 0, nullptr) != 0) {
            fail(ChildStage::Sandbox, kExitSandboxFailed);
        }
#elif defined(__linux__)
        // T3's process half (tier.hpp: "Kernel + user/net/pid/ipc namespaces").
        // The broker covers the network; this hides the host process table, so
        // `ps aux` inside the sandbox cannot read other agents' command lines.
        //
        // Ordering: BEFORE Landlock. A Landlock ruleset is immutable once
        // enforced and unshare/mount would then be denied, so namespaces must
        // come first. It is still after close_inherited_fds(), so nothing
        // leaks in either direction.
        //
        // Degrades honestly: if unprivileged user namespaces are disabled, the
        // workload keeps the full Landlock boundary and only loses process
        // isolation, which compile() reports as a warning. Refusing to run
        // would be worse -- it trades a real filesystem boundary for nothing.
        if (ns_isolate) {
            const char* nserr = nullptr;
            if (!linux_ns::enter_namespaces(bastion::ForkBoundary::in_child(),
                                            &nserr)) {
                // Report, do NOT abort. Losing process isolation is a lost
                // mitigation; losing the Landlock boundary would be a hole. An
                // earlier version discarded this result entirely, so a failure
                // here was invisible -- the run looked isolated when it was not.
                fail_soft(ChildStage::Namespace);
            }
        }

        // Confinement lands here: after fork (so bastion stays unconfined),
        // before exec (so the child can never run unconfined).
        //
        // Uses the PRE-COMPILED ruleset and an allocation-free apply: at T3
        // the egress broker's accept thread is already running when we fork,
        // and a child of a multithreaded process that allocates can deadlock
        // forever on a malloc lock held by a thread that does not exist here.
        // That would hang with the sandbox unapplied -- so compilation happens
        // in the parent and this path performs syscalls only.
        if (ll_ready) {
            const char* lerr = nullptr;
            if (!linux_ll::apply_compiled(bastion::ForkBoundary::in_child(),
                                          ll_rules, ll_core, &lerr)) {
                fail(ChildStage::Sandbox, kExitSandboxFailed);
            }
        } else if (!policy.is_unconfined()) {
            // Compilation failed in the parent, which already recorded why.
            // Fail closed rather than exec an unconfined workload.
            fail(ChildStage::Sandbox, kExitSandboxFailed);
        }
#endif
        ::execve(cargv[0], cargv.data(), cenv.data());
        fail(ChildStage::Exec, kExitExecFailed);
        _exit(kExitExecFailed);  // unreachable; keeps the compiler happy
    }

    // ---- parent ------------------------------------------------------------
    // The write end must not stay open here, or the read below would never see
    // EOF on the success path.
    pipe_w.reset();

    out.pid = static_cast<int>(pid);
    out.pgid = static_cast<int>(pid);  // setpgid(0,0) in the child => pgid == pid
    // Also set it from the parent to close the race where the child has not yet
    // run setpgid but the observer is already reading audit lines.
    ::setpgid(pid, pid);

    // Armed HERE, not around spawn_wait(), and it stays armed for the rest of
    // the call. Everything below -- the blocking read() on the status pipe,
    // then the wait -- is time in which an agent harness may kill us, and a
    // SIGTERM arriving before this point terminates bastion with the DEFAULT
    // disposition, orphaning the child subtree.
    //
    // MEASURED: with the forwarder scoped to spawn_wait() only, killing
    // bastion at T3 left SIX processes running while T2 left none. T3's child
    // forks twice more (the namespace supervisors) before reaching execve, so
    // it lingers in the read() above for measurably longer -- a window T2
    // barely has. Same bug at T2, just far harder to hit.
    const SignalForwarder forwarder{static_cast<pid_t>(out.pgid)};

    // Returns as soon as the child either reports a setup failure (one byte) or
    // reaches execve (EOF, because the pipe is O_CLOEXEC). This does not wait
    // on the workload -- only on bastion's own setup finishing.
    //
    // FORWARDING IS ALREADY ACTIVE HERE. It is armed immediately after fork(),
    // above, rather than around spawn_wait() below, because this read() blocks
    // and everything between fork() and it is a window in which a SIGTERM would
    // kill bastion with the default disposition -- leaving the child subtree
    // orphaned. MEASURED: at T3, where the child forks twice more for the
    // namespace levels and so takes measurably longer to reach execve, killing
    // bastion left SIX processes running while T2 left none.
    {
        unsigned char b = 0;
        ssize_t n;
        do {
            n = ::read(pipe_r.get(), &b, 1);
        } while (n < 0 && errno == EINTR);
        // n == 1: the child reported a stage. n == 0: EOF, it exec'd. n < 0 is
        // a pipe error we cannot attribute, so we do NOT invent a stage --
        // spawn_wait() still reports the child's real exit status.
        out.setup_stage = (n == 1) ? b : 0;
    }
    pipe_r.reset();

    if (!req.wait) return out;  // caller will spawn_wait() later

    spawn_wait(out);

#if defined(__linux__)
    // Ask the KERNEL whether it refused anything, rather than leaving the user
    // to decode a bare exit code. A memory kill arrives as SIGKILL (exit 137)
    // with no message at all, and a pids refusal surfaces only as the
    // workload's own "fork: Resource temporarily unavailable" -- both look
    // like the workload broke on its own. cgroup.events records the truth.
    if (cg.valid()) {
        if (const auto hits = cg.memory_max_hits(); hits > 0) {
            out.warnings.push_back(
                "the memory limit was hit " + std::to_string(hits) +
                " time(s); the kernel OOM-killed the workload (exit 137 is "
                "SIGKILL, not a crash in your program). Raise --max-mem-mb.");
        }
        if (const auto hits = cg.pids_max_hits(); hits > 0) {
            out.warnings.push_back(
                "the process limit was hit " + std::to_string(hits) +
                " time(s) (peak " + std::to_string(cg.peak_pids()) +
                " processes); forks inside the sandbox were refused. "
                "Raise --max-procs.");
        }
    }
#endif

#if defined(__APPLE__) || defined(__linux__)
    // Harvest the broker's ledger before it is torn down. Every egress
    // decision the workload triggered is reported to the caller, so a T3 run
    // is as auditable as a filesystem one.
    if (proxy) {
        out.egress_allowed = proxy->allowed_count();
        out.egress_denied = proxy->denied_count();
        for (const auto& a : proxy->take_attempts()) {
            out.egress_attempts.emplace_back(
                a.host + ":" + std::to_string(a.port), a.allowed);
        }
        if (out.egress_denied > 0) {
            out.warnings.push_back(
                std::to_string(out.egress_denied) +
                " egress attempt(s) were REFUSED by the allowlist");
        }
        proxy->stop();
    }
#endif
    return out;
}

void spawn_wait(SpawnResult& out) {
    if (out.pid <= 0) return;
    const pid_t pid = static_cast<pid_t>(out.pid);

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            out.error = std::string{"waitpid failed: "} + std::strerror(errno);
            return;
        }
    }

    if (WIFSIGNALED(status)) {
        out.signalled = true;
        out.signal_number = WTERMSIG(status);
        out.exit_code = 128 + out.signal_number;
        return;
    }

    out.exit_code = WEXITSTATUS(status);

    // Attribution comes from the status pipe, NOT from the exit code. A shell
    // exits 126/127 on its own when a confined exec is denied, so keying off
    // the code alone reported a correctly-blocked attack as a bastion failure.
    // setup_stage is nonzero only if bastion's own setup actually failed.
    switch (static_cast<ChildStage>(out.setup_stage)) {
        case ChildStage::Sandbox:
            out.error = "child failed to apply the sandbox policy; it was NOT "
                        "executed (fail-closed)";
            break;
        case ChildStage::Chdir:
            out.error = "child could not chdir to the requested directory";
            break;
        case ChildStage::Exec:
            out.error = "exec failed (binary missing or not executable)";
            break;
        case ChildStage::Namespace:
            // NOT an error: the workload ran with the full kernel boundary and
            // only lost process-table isolation. Setting out.error here would
            // make launched() false for a run that really happened.
            out.warnings.push_back(
                "T3 process isolation could not be installed; the workload ran "
                "with the full filesystem and network boundary but the host "
                "process table was visible to it");
            break;
        default:
            break;
    }
}

}  // namespace bastion
