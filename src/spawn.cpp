#include "bastion/spawn.hpp"

#include <spawn.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>

#if defined(__APPLE__)
#  include <crt_externs.h>
#  define BASTION_ENVIRON (*_NSGetEnviron())
#  include "bastion/backend/seatbelt.hpp"
// Declared at file scope: sandbox_init(3) has no public SDK header.
extern "C" int sandbox_init(const char* profile, uint64_t flags, char** errorbuf);
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
void close_inherited_fds() {
    int max_fd = -1;
    struct rlimit rl {};
    if (::getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY) {
        max_fd = static_cast<int>(rl.rlim_cur);
    }
    if (max_fd < 0 || max_fd > 65536) max_fd = 65536;  // sane cap
    for (int fd = STDERR_FILENO + 1; fd < max_fd; ++fd) {
        ::close(fd);  // EBADF is fine and expected
    }
}

}  // namespace

std::vector<std::string> sanitized_env(const Sealed& policy) {
    std::vector<std::string> env;

    // A coherent PATH whose entries are readable under the base profile.
    env.emplace_back("PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin");
    env.emplace_back(std::string{"HOME="} + getenv_or("HOME", "/tmp"));
    env.emplace_back(std::string{"USER="} + getenv_or("USER", "agent"));
    env.emplace_back(std::string{"SHELL="} + getenv_or("SHELL", "/bin/sh"));
    env.emplace_back("LANG=en_US.UTF-8");
    env.emplace_back(std::string{"TERM="} + getenv_or("TERM", "dumb"));

    // The ergonomic floor (DESIGN.md §4). The field report's single biggest
    // win was "the return of rw in /tmp ... LLMs will stop going around in
    // circles", so TMPDIR pointing at a writable location is asserted here
    // rather than left to chance.
    const char* tmp = getenv_or("TMPDIR", "/tmp");
    env.emplace_back(std::string{"TMPDIR="} + tmp);

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

#if defined(__APPLE__)
    auto compiled = darwin::compile(policy);
    if (!compiled.ok) {
        out.error = "policy compilation failed: " + compiled.error;
        return out;  // fail closed: never launch with a broken policy
    }
    out.profile = compiled.profile;
    out.warnings = compiled.warnings;
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

    std::vector<char*> cargv;
    cargv.reserve(req.argv.size() + 1);
    for (const auto& a : req.argv) cargv.push_back(const_cast<char*>(a.c_str()));
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

    pid_t pid = ::fork();
    if (pid < 0) {
        out.error = std::string{"fork failed: "} + std::strerror(errno);
        return out;
    }

    if (pid == 0) {
        // ---- child ---------------------------------------------------------
        // Ordering is load-bearing (see spawn.hpp). Only async-signal-safe
        // calls past this point; no allocation, no iostreams.
        if (cwd && ::chdir(cwd) != 0) _exit(kExitChdirFailed);

        // Own process group, so the ENTIRE subtree (children, grandchildren,
        // anything exec'd) shares one pgid. T0 observation filters audit
        // records on this; without it, attribution has to guess by process
        // name and loses every grandchild's accesses.
        ::setpgid(0, 0);

        // Drop inherited descriptors BEFORE confining. An fd opened by the
        // parent carries its own access rights past the sandbox boundary
        // (measured -- see close_inherited_fds), so leaving one open would
        // hand the child a hole straight through the path policy.
        close_inherited_fds();

#if defined(__APPLE__)
        // Confinement lands here: after fork (so bastion stays unconfined),
        // before exec (so the child can never run unconfined).
        if (sandbox_init(compiled.profile.c_str(), 0, nullptr) != 0) {
            _exit(kExitSandboxFailed);
        }
#endif
        ::execve(cargv[0], cargv.data(), cenv.data());
        _exit(kExitExecFailed);
    }

    // ---- parent ------------------------------------------------------------
    out.pid = static_cast<int>(pid);
    out.pgid = static_cast<int>(pid);  // setpgid(0,0) in the child => pgid == pid
    // Also set it from the parent to close the race where the child has not yet
    // run setpgid but the observer is already reading audit lines.
    ::setpgid(pid, pid);

    if (!req.wait) return out;  // caller will spawn_wait() later

    spawn_wait(out);
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
    switch (out.exit_code) {
        case kExitSandboxFailed:
            out.error = "child failed to apply the sandbox policy; it was NOT "
                        "executed (fail-closed)";
            break;
        case kExitChdirFailed:
            out.error = "child could not chdir to the requested directory";
            break;
        case kExitExecFailed:
            out.error = "exec failed (binary missing or not executable)";
            break;
        default:
            break;
    }
}

}  // namespace bastion
