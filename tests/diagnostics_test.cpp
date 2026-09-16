// Diagnostics: does a FAILING run tell the agent enough to recover?
//
// This is an ergonomics test, and in this project ergonomics is a security
// property (DESIGN.md §4): an agent that cannot tell "the sandbox denied this"
// from "my code is wrong" retries the wrong fix, burns turns, and eventually
// the sandbox gets switched off.
//
// Both directions matter, and the second is the one that is easy to get wrong:
//
//   SILENCE ON A REAL DENIAL  -- the agent thrashes on a problem not in its code
//   NOISE ON A GENUINE FAILURE -- the agent chases a policy bug that is not there
//
// A failing unit test must NOT be told "maybe it was the sandbox". Measured
// while dogfooding: the first version of this feature printed its advisory on
// every nonzero exit, including `sh -c 'exit 1'`.
#include "bastion/spawn.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

static int failures = 0;
static void check(bool c, const char* what) {
    std::printf("  [%s] %s\n", c ? "PASS" : "FAIL", what);
    if (!c) ++failures;
}

// Run the real CLI and capture stderr, which is where guidance goes.
static std::string run_cli(const std::string& args) {
    const std::string out = "/tmp/bastion-diag-out.txt";
    const std::string cmd =
        std::string{BASTION_CLI} + " " + args + " 2>" + out + " >/dev/null";
    (void)std::system(cmd.c_str());
    std::ifstream f(out);
    std::string all((std::istreambuf_iterator<char>(f)),
                    std::istreambuf_iterator<char>());
    fs::remove(out);
    return all;
}

static bool has(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

int main() {
    const fs::path ws = "/tmp/bastion-diag-ws";
    fs::remove_all(ws);
    fs::create_directories(ws);
    { std::ofstream{ws / "in.txt"} << "data\n"; }

    const std::string base =
        "run --no-ledger -w " + ws.string() + " ";

    std::puts("== 1. a bare command name resolves, like a shell ==");
    {
        // The FIRST thing an agent types is `cc main.c`, not `/usr/bin/cc`.
        // execve() needs an absolute path, so without PATH resolution in the
        // parent this failed with "exec failed" -- while `bastion observe`
        // accepted it, because that backend used execvp(). Two subcommands,
        // two behaviours.
        const std::string err = run_cli(base + "-- sh -c 'exit 0'");
        check(!has(err, "exec failed"),
              "`sh` (no path) is found via the sandbox PATH");
    }

    std::puts("\n== 2. a GENUINE failure is not blamed on the sandbox ==");
    {
        const std::string err = run_cli(base + "-- sh -c 'exit 3'");
        check(!has(err, "looks like the sandbox"),
              "a plain nonzero exit produces NO sandbox advisory");
        check(!has(err, "network:"),
              "...and no network advice either");
    }

    std::puts("\n== 3. a W^X denial explains itself ==");
    {
        // Copy a real binary into the workspace: writable, but a write grant
        // carries no execute right. This is the most confusing denial in
        // ordinary build-and-test use, because the file plainly exists.
        std::error_code ec;
        fs::copy_file("/bin/sh", ws / "copied", 
                      fs::copy_options::overwrite_existing, ec);
        if (!ec) {
            const std::string err = run_cli(base + "-- sh -c './copied -c true'");
            check(has(err, "looks like the sandbox"),
                  "an exec denial IS attributed to the sandbox");
            check(has(err, "does NOT include execute"),
                  "...and names W^X as the cause");
            check(has(err, "fs.exec"),
                  "...and names the rule that fixes it");
        } else {
            std::puts("  [skip] could not stage a binary in the workspace");
        }
    }

    std::puts("\n== 4. the advisory names what IS granted ==");
    {
        std::error_code ec;
        fs::copy_file("/bin/sh", ws / "copied2",
                      fs::copy_options::overwrite_existing, ec);
        if (!ec) {
            const std::string err = run_cli(base + "-- sh -c './copied2 -c true'");
            // Without this the agent cannot tell whether the path it wanted is
            // inside the boundary, which is the first thing it needs to know.
            check(has(err, ws.string().c_str()),
                  "the granted workspace is printed");
        }
    }

    std::puts("\n== 5. every advisory ends with an actionable next step ==");
    {
        std::error_code ec;
        fs::copy_file("/bin/sh", ws / "copied3",
                      fs::copy_options::overwrite_existing, ec);
        if (!ec) {
            const std::string err = run_cli(base + "-- sh -c './copied3 -c true'");
            // The remedy must name commands that EXIST. An earlier version of
            // the remedy machinery pointed at `bastion grant`, which was never
            // implemented -- worse than silence, because it sends the reader
            // somewhere that cannot help.
            check(has(err, "bastion observe") && has(err, "bastion synthesize"),
                  "the next step is the observe -> synthesize loop");
        }
    }

    std::puts("\n== 6. no FALSE attribution on ambiguous exit codes ==");
    {
        // An earlier version treated curl's exit 7 ("couldn't connect") as
        // proof the sandbox blocked the network. But `sh -c 'exit 7'` is
        // indistinguishable, so a plain failing command was confidently told
        // the network was the problem -- sending the agent somewhere there is
        // no bug. Landlock gives no T2 denial signal, so the cause CANNOT be
        // known; bastion must not claim it.
        for (const char* code : {"4", "6", "7"}) {
            const std::string err =
                run_cli(base + "-- sh -c 'exit " + code + "'");
            check(!has(err, "looks like the sandbox"),
                  (std::string{"exit "} + code +
                   " is not blamed on the sandbox").c_str());
        }
    }

    std::puts("\n== 7. a directory in PATH is not mistaken for a command ==");
    {
        // access(X_OK) returns 0 for a DIRECTORY with the search bit set, and
        // PATH directories really do contain subdirectories
        // (/usr/bin/core_perl on this box). Resolving one would hand execve a
        // directory, which fails as "binary missing or not executable" -- the
        // exact confusing message PATH resolution exists to prevent. A shell
        // requires a regular file; so must we.
        std::error_code ec;
        std::string dirname;
        for (const char* d : {"/usr/bin", "/bin", "/usr/sbin"}) {
            for (const auto& e : fs::directory_iterator(d, ec)) {
                if (ec) break;
                if (e.is_directory(ec) && !ec) {
                    dirname = e.path().filename().string();
                    break;
                }
            }
            if (!dirname.empty()) break;
        }
        if (!dirname.empty()) {
            const std::string err = run_cli(base + "-- " + dirname);
            check(has(err, "exec failed"),
                  ("a PATH subdirectory ('" + dirname +
                   "') is not run as a command").c_str());
        } else {
            std::puts("  [skip] no subdirectory found in PATH to test");
        }
    }

    fs::remove_all(ws);
    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "diagnostics verified" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
