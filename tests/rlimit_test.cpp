// Resource ceilings: the \"resource exhaustion\" row of the security model.
//
// A sandbox that stops an agent reading ~/.ssh but lets it fork-bomb the
// machine has stopped the interesting attack and left the boring one. These
// limits are opt-in, so the tests assert BOTH directions: they bite when asked
// for, and they are absent when not.
#include "bastion/spawn.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>

using namespace bastion;
namespace fs = std::filesystem;

static int failures = 0;
static void check(bool c, const char* what) {
    std::printf("  [%s] %s\n", c ? "PASS" : "FAIL", what);
    if (!c) ++failures;
}

int main() {
    const fs::path ws = "/tmp/bastion-rlimit-test";
    fs::remove_all(ws);
    fs::create_directories(ws);

    auto policy = [&] {
        return Policy{Tier::Kernel}
            .allow(Right::FsRead | Right::FsWrite, ws, "workspace")
            .seal();
    };

    auto run = [&](const char* sh, const ResourceLimits& lim) {
        SpawnRequest req;
        req.argv = {"/bin/sh", "-c", sh};
        req.cwd = ws.string();
        req.limits = lim;
        auto p = policy();
        return spawn(p, req);
    };

    std::puts("== 1. file size ceiling ==");
    {
        ResourceLimits lim;
        lim.max_file_bytes = 1024 * 1024;  // 1 MiB
        auto r = run("head -c 20000000 /dev/zero > big.bin", lim);

        // SIGXFSZ kills the writer, so the shell reports 128+25.
        check(r.launched(), "ran under a file-size ceiling");
        std::error_code ec;
        const auto sz = fs::file_size(ws / "big.bin", ec);
        check(!ec && sz <= 1024 * 1024,
              "a 20MB write was capped at the 1MB ceiling");
    }

    std::puts("\n== 2. no ceiling means no interference ==");
    {
        auto r = run("head -c 4000000 /dev/zero > ok.bin && echo done", {});
        std::error_code ec;
        const auto sz = fs::file_size(ws / "ok.bin", ec);
        check(r.launched() && r.exit_code == 0 && !ec && sz == 4000000,
              "the same write succeeds in full with limits OFF (opt-in)");
    }

    std::puts("\n== 3. core dumps are always off ==");
    {
        // RLIMIT_CORE is set to 0 unconditionally: a crashing confined process
        // must not write a memory image (which can hold secrets read from
        // granted paths) into the workspace.
        auto r = run("test \"$(ulimit -c)\" = 0 && echo zero", {});
        check(r.launched() && r.exit_code == 0,
              "the child's core dump limit is 0 even with no limits requested");
    }

    std::puts("\n== 4. a too-low process cap is explained, not just broken ==");
    {
        // RLIMIT_NPROC counts THREADS for the whole uid, so a small number is
        // almost always wrong. The failure mode ("sh: fork: Resource
        // temporarily unavailable") looks like a broken toolchain, so bastion
        // must warn with the real number rather than let the user debug it.
        ResourceLimits lim;
        lim.max_processes = 1;  // guaranteed to be below the current count
        auto r = run("echo hi", lim);

        bool explained = false;
        for (const auto& w : r.warnings) {
            if (w.find("max-procs") != std::string::npos &&
                w.find("threads") != std::string::npos) {
                explained = true;
            }
        }
#if defined(__linux__)
        check(explained,
              "an unusably low --max-procs warns, naming the thread count");
#else
        check(true, "thread-count warning is Linux-only");
#endif
    }

    fs::remove_all(ws);
    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "resource limits verified" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
