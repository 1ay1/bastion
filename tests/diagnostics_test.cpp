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

    std::puts("\n== 8. --json emits a parseable object, not prose ==");
    {
        // `--json` is the primary integration surface for an agent, and it
        // used to be a no-op: accepted, documented, and emitting nothing
        // except suppressed advisories. A caller asking for structured output
        // got an empty stream and had to scrape stderr.
        //
        // stdout only -- the human advisories go to stderr, so redirecting
        // stdout must yield something a parser accepts.
        const std::string out = "/tmp/bastion-diag-json.txt";
        const std::string cmd = std::string{BASTION_CLI} + " run --json " +
                                "--no-ledger -w " + ws.string() +
                                " -- sh -c 'exit 0' >" + out + " 2>/dev/null";
        (void)std::system(cmd.c_str());

        std::ifstream f(out);
        std::string body((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
        fs::remove(out);

        check(has(body, "\"exit_code\""), "the summary reports exit_code");
        check(has(body, "\"tier\""), "...and the tier that was enforced");
        check(has(body, "\"granted\""), "...and what the policy granted");
        // The field that lets an agent branch without reading prose.
        check(has(body, "\"sandbox_implicated\""),
              "...and whether the SANDBOX caused a failure");
        // Balanced braces is a cheap structural check that the object is not
        // truncated; a real parse happens in the shell test above.
        int depth = 0;
        bool balanced = true;
        for (char c : body) {
            if (c == '{') ++depth;
            if (c == '}' && --depth < 0) balanced = false;
        }
        check(balanced && depth == 0, "the object is well-formed");
    }

    std::puts("\n== 9. --json distinguishes OUR failure from the workload's ==");
    {
        auto json_of = [&](const char* script) {
            const std::string out = "/tmp/bastion-diag-json2.txt";
            const std::string cmd =
                std::string{BASTION_CLI} + " run --json --no-ledger -w " +
                ws.string() + " -- sh -c '" + script + "' >" + out +
                " 2>/dev/null";
            (void)std::system(cmd.c_str());
            std::ifstream f(out);
            std::string s((std::istreambuf_iterator<char>(f)),
                          std::istreambuf_iterator<char>());
            fs::remove(out);
            return s;
        };

        // A plain failing command is the workload's own problem.
        check(has(json_of("exit 3"), "\"sandbox_implicated\":false"),
              "a genuine failure reports sandbox_implicated=false");

        // A denied exec is ours. Staged binary: writable, but a write grant
        // carries no execute right.
        std::error_code ec;
        fs::copy_file("/bin/sh", ws / "jsonexec",
                      fs::copy_options::overwrite_existing, ec);
        if (!ec) {
            check(has(json_of("./jsonexec -c true"),
                      "\"sandbox_implicated\":true"),
                  "a W^X denial reports sandbox_implicated=true");
        }
    }

    std::puts("\n== 10. a committed policy file BINDS without --policy ==");
    {
        // A ./bastion.toml used to be inert -- present, readable, and silently
        // ignored unless the caller remembered --policy. That is worse than
        // having no policy, because it LOOKS like protection: a read-only
        // policy sat beside a workload that happily wrote to the directory.
        const fs::path proj = "/tmp/bastion-diag-proj";
        fs::remove_all(proj);
        fs::create_directories(proj);
        {
            std::ofstream f(proj / "bastion.toml");
            f << "tier = \"t2\"\n\n[[allow]]\nop   = \"fs.read\"\npath = \""
              << proj.string() << "\"\nwhy  = \"read-only by design\"\n";
        }

        // Run from INSIDE the project, with no --policy flag at all.
        const std::string out = "/tmp/bastion-diag-disc.txt";
        const std::string cmd =
            "cd " + proj.string() + " && " + BASTION_CLI +
            " run --no-ledger -- sh -c 'echo x > w.txt' >" + out + " 2>&1";
        (void)std::system(cmd.c_str());

        std::ifstream rf(out);
        std::string body((std::istreambuf_iterator<char>(rf)),
                         std::istreambuf_iterator<char>());
        fs::remove(out);

        check(has(body, "bastion.toml"),
              "the discovered policy file is named in the output");
        // The policy grants READ only, so the write must fail. If discovery
        // silently failed, the default "workspace = cwd" grant would allow it.
        std::error_code wec;
        check(!fs::exists(proj / "w.txt", wec),
              "the discovered policy actually BINDS (write denied)");

        fs::remove_all(proj);
    }

    std::puts("\n== 11. BASTION_MIN_TIER is a floor --yolo cannot cross ==");
    {
        // The mechanism that lets one binary serve both audiences: a developer
        // who wants no friction, and an operator who must guarantee some.
        // Without it, --yolo is unconditional and no configuration can forbid
        // reading ~/.ssh on a shared host.
        auto run_with_floor = [&](const char* floor, const char* args) {
            const std::string out = "/tmp/bastion-diag-floor.txt";
            const std::string cmd = std::string{"BASTION_MIN_TIER="} + floor +
                                    " " + BASTION_CLI + " run --no-ledger " +
                                    args + " -w " + ws.string() +
                                    " -- sh -c 'echo ran' >" + out + " 2>&1";
            (void)std::system(cmd.c_str());
            std::ifstream f(out);
            std::string s((std::istreambuf_iterator<char>(f)),
                          std::istreambuf_iterator<char>());
            fs::remove(out);
            return s;
        };

        check(has(run_with_floor("t2", "--yolo"), "--yolo is refused"),
              "--yolo is REFUSED below the floor");
        check(has(run_with_floor("t2", "-t t0"), "below BASTION_MIN_TIER"),
              "a tier downgrade is refused too");
        check(has(run_with_floor("t2", "-t t2"), "ran"),
              "...but running AT the floor still works");
        // A malformed floor must fail closed, not be ignored.
        check(!has(run_with_floor("t9", ""), "ran"),
              "an unparseable BASTION_MIN_TIER fails closed");
    }

    std::puts("\n== 12. `observe` cannot be used to bypass the floor ==");
    {
        // The hole in the first version of BASTION_MIN_TIER. `observe` runs
        // the workload UNCONFINED by design -- that is what T0 IS -- so it was
        // a strictly MORE powerful bypass than --yolo, which the floor had
        // just been added to block. MEASURED: with the floor set,
        // `bastion observe -- cat ~/.ssh/id_*` printed the private key while
        // `run --yolo` was correctly refused.
        auto observe_with = [&](const char* floor) {
            const std::string out = "/tmp/bastion-diag-obs.txt";
            std::string cmd;
            if (floor) cmd += std::string{"BASTION_MIN_TIER="} + floor + " ";
            cmd += std::string{BASTION_CLI} +
                   " observe --no-ledger -- sh -c 'echo observed' >" + out +
                   " 2>&1";
            (void)std::system(cmd.c_str());
            std::ifstream f(out);
            std::string s((std::istreambuf_iterator<char>(f)),
                          std::istreambuf_iterator<char>());
            fs::remove(out);
            return s;
        };

        check(has(observe_with("t2"), "UNCONFINED"),
              "observe is REFUSED under a floor above T0");
        check(!has(observe_with("t2"), "observed"),
              "...and the workload really does not run");
        // The refusal must stay actionable: observation is HOW a policy is
        // discovered, so a bare denial would be a dead end.
        check(has(observe_with("t2"), "bastion.toml"),
              "...and the message says how to proceed");

        // An operator who sets t0 has explicitly allowed unconfined runs.
        check(has(observe_with("t0"), "observed"),
              "BASTION_MIN_TIER=t0 permits observation");
        check(has(observe_with(nullptr), "observed"),
              "no floor set leaves observe untouched");
    }

    std::puts("\n== 13. tools outside /usr are found and runnable ==");
    {
        // REPORTED against a sibling project: a Go toolchain installed by
        // webinstall.dev lives in ~/.local/opt and links into ~/.local/bin, so
        // `gofmt` failed inside the sandbox with "binary missing or not
        // executable" while working fine outside. The same bug reproduced here.
        //
        // The fix is to inherit the user's OWN $PATH rather than hardcode a
        // list -- pipx, cargo/go install, bun, deno, and the mise/asdf/pyenv
        // shim directories all use prefixes nobody can enumerate in advance,
        // so a fixed list is never finished and every gap is this bug again.
        //
        // Both halves must work: the command has to RESOLVE, and it then has
        // to RUN. Granting one without the other produces "not executable"
        // about a file that plainly exists.
        const fs::path bindir = ws / "toolbin";
        fs::create_directories(bindir);
        const fs::path tool = bindir / "bastion-fake-tool";
        {
            std::ofstream f(tool);
            f << "#!/bin/sh\necho tool-ran\n";
        }
        fs::permissions(tool, fs::perms::owner_all | fs::perms::group_exec |
                                  fs::perms::others_exec);

        const std::string out = "/tmp/bastion-diag-path.txt";
        const std::string cmd = "PATH=" + bindir.string() + ":$PATH " +
                                BASTION_CLI + " run --no-ledger -w " +
                                ws.string() + " -- bastion-fake-tool >" + out +
                                " 2>&1";
        (void)std::system(cmd.c_str());

        std::ifstream f(out);
        std::string body((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
        fs::remove(out);

        check(has(body, "tool-ran"),
              "a tool on the user's PATH but outside /usr runs");
        check(!has(body, "binary missing"),
              "...and is not reported as missing");
    }

    std::puts("\n== 14. a PATH entry is an exec grant, so it is vetted ==");
    {
        // Every directory inherited from $PATH becomes a read+exec grant, so
        // it has to be treated as one. Three classes must never survive:
        //
        //   relative (".")  -- resolves against the WORKLOAD's cwd, so a
        //                      hostile repo could ship a `git` that runs on
        //                      checkout
        //   world-writable -- any local process can plant a binary there
        //   missing        -- a typo must not become a grant for a directory
        //                     someone creates later
        const std::string out = "/tmp/bastion-diag-vet.txt";
        const std::string cmd =
            "PATH=/tmp:.:/nonexistent:/usr/bin " + std::string{BASTION_CLI} +
            " explain -w " + ws.string() + " >" + out + " 2>&1";
        (void)std::system(cmd.c_str());

        std::ifstream f(out);
        std::string body((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
        fs::remove(out);

        // /tmp is world-writable and not ours; "." is relative; /nonexistent
        // does not exist. None may appear as a granted rule.
        check(!has(body, "\n  rx /tmp\n") && !has(body, "  r  /tmp\n"),
              "world-writable /tmp is not granted from PATH");
        check(!has(body, "/nonexistent"),
              "a missing PATH entry is not granted");
    }

    std::puts("\n== 15. a monorepo subdirectory can reach its own project ==");
    {
        // The most common real layout, and it was broken. An agent working in
        // packages/app got `Permission denied` on ../lib and on the root
        // tsconfig.json, because the default workspace was the CURRENT
        // directory. Nothing explained why, so it reads as a broken toolchain.
        const fs::path mono = "/tmp/bastion-diag-mono";
        fs::remove_all(mono);
        fs::create_directories(mono / "packages/app");
        fs::create_directories(mono / "packages/lib");
        fs::create_directories(mono / ".git");  // the root marker
        { std::ofstream{mono / "packages/lib/l.txt"} << "lib\n"; }
        { std::ofstream{mono / "root.json"} << "root\n"; }

        const std::string out = "/tmp/bastion-diag-mono.txt";
        const std::string cmd =
            "cd " + (mono / "packages/app").string() + " && " + BASTION_CLI +
            " run --no-ledger -- sh -c 'cat ../lib/l.txt && cat ../../root.json'"
            " >" + out + " 2>&1";
        (void)std::system(cmd.c_str());

        std::ifstream f(out);
        std::string body((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
        fs::remove(out);

        check(has(body, "lib") && has(body, "root"),
              "a sibling package and the repo root are both readable");
        // The wider grant must be VISIBLE. Silently widening the boundary is
        // how a user ends up surprised by what the sandbox allowed.
        check(has(body, "project root"),
              "...and the widened workspace is announced, not silent");
    }

    std::puts("\n== 16. project-root detection stops at $HOME ==");
    {
        // Dotfile repos are common, so a .git directly in the home directory
        // is normal. Treating it as a project root would widen the sandbox
        // from one project to everything the user owns -- the exact
        // over-grant this feature must not introduce.
        const fs::path fake_home = "/tmp/bastion-diag-home";
        fs::remove_all(fake_home);
        fs::create_directories(fake_home / "sub/deep");
        fs::create_directories(fake_home / ".git");  // dotfiles repo

        const std::string out = "/tmp/bastion-diag-home.txt";
        const std::string cmd =
            "cd " + (fake_home / "sub/deep").string() + " && HOME=" +
            fake_home.string() + " " + BASTION_CLI +
            " run --no-ledger -- pwd >" + out + " 2>&1";
        (void)std::system(cmd.c_str());

        std::ifstream f(out);
        std::string body((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
        fs::remove(out);
        fs::remove_all(fake_home);

        check(!has(body, "project root"),
              "a .git in $HOME itself is NOT treated as a project root");
    }

    fs::remove_all(ws);
    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "diagnostics verified" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
