// Lifecycle: does killing bastion take the whole sandboxed subtree with it?
//
// This is an AGENT problem before it is a correctness problem. Harnesses run
// commands under a timeout and kill them when it expires, so a workload that
// survives its supervisor leaks a process per attempt -- a dev server, a
// watcher, a hung test -- until the machine is full. It is also a confinement
// question: an orphan still holds whatever the policy granted, and nothing is
// left to observe or account for it.
//
// MEASURED before the fix: `kill -TERM` on bastion left SIX `sleep` processes
// running.
//
// Written in C++ rather than shell because a shell's own job control reaps and
// re-parents things underneath the test, which makes the result meaningless.
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <filesystem>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static int failures = 0;
static void check(bool c, const char* what) {
    std::printf("  [%s] %s\n", c ? "PASS" : "FAIL", what);
    if (!c) ++failures;
}

// Count processes whose command line contains `needle`, by walking /proc
// directly -- pgrep would match this test's own argv.
static int count_matching(const char* needle) {
    int n = 0;
    FILE* p = ::popen("ls /proc 2>/dev/null", "r");
    if (!p) return -1;
    char name[64];
    while (std::fgets(name, sizeof name, p)) {
        name[std::strcspn(name, "\n")] = '\0';
        if (name[0] < '0' || name[0] > '9') continue;

        char path[128];
        std::snprintf(path, sizeof path, "/proc/%s/cmdline", name);
        FILE* f = std::fopen(path, "rb");
        if (!f) continue;
        char buf[4096] = {0};
        const std::size_t got = std::fread(buf, 1, sizeof buf - 1, f);
        std::fclose(f);

        // cmdline is NUL-separated; join so a multi-arg match works.
        for (std::size_t i = 0; i + 1 < got; ++i) {
            if (buf[i] == '\0') buf[i] = ' ';
        }
        if (std::strstr(buf, needle)) ++n;
    }
    ::pclose(p);
    return n;
}

// Runs `bastion <subcommand>` on a workload that backgrounds three sleeps,
// kills bastion, and reports how many survive. Returns the survivor count.
static int orphans_after_kill(const char* subcommand, const char* tier,
                              const std::string& marker) {
    // `exec -a NAME` sets argv[0], so each grandchild carries the marker in
    // its own /proc/PID/cmdline. It must appear in EACH child's argv, not just
    // the `sh -c` string: a trailing `# marker` comment lives only in the
    // shell's command line, so the grandchildren would be invisible and this
    // would count one process where it should count four -- which is exactly
    // the failure being tested, so getting it wrong would be self-defeating.
    const std::string sleeper = "sh -c 'exec -a " + marker + " sleep 45'";
    const std::string script = sleeper + " & " + sleeper + " & " + sleeper;

    const pid_t bp = ::fork();
    if (bp < 0) return -1;
    if (bp == 0) {
        ::setsid();  // detach from the test's terminal/job control
        const int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDOUT_FILENO);
            ::dup2(devnull, STDERR_FILENO);
        }
        if (tier != nullptr) {
            ::execl(BASTION_CLI, "bastion", subcommand, "--no-ledger",
                    "-t", tier, "--", "sh", "-c", script.c_str(),
                    (char*)nullptr);
        } else {
            ::execl(BASTION_CLI, "bastion", subcommand, "--no-ledger", "--",
                    "sh", "-c", script.c_str(), (char*)nullptr);
        }
        _exit(127);
    }

    const char* label = tier ? tier : subcommand;

    ::usleep(1500 * 1000);  // let the workload get going
    const int before = count_matching(marker.c_str());
    std::printf("      %-8s running before kill: %d\n", label, before);

    ::kill(bp, SIGTERM);  // what an agent harness does on timeout
    int st = 0;
    ::waitpid(bp, &st, 0);
    ::usleep(1500 * 1000);  // give the subtree a moment to die

    const int after = count_matching(marker.c_str());
    std::printf("      %-8s surviving after kill: %d (bastion signalled=%d)\n",
                label, after, WIFSIGNALED(st));

    if (after != 0) {
        // Do not leave the machine dirtier than we found it.
        const std::string cleanup =
            "pkill -9 -f '" + marker + "' 2>/dev/null";
        (void)std::system(cleanup.c_str());
    }
    return after;
}

int main() {
    std::puts("== killing bastion kills the whole subtree ==");

    // BOTH supervisors, and T3 specifically.
    //
    // `run` waits in spawn(); `observe` has its own wait loop in the seccomp
    // backend and did NOT inherit the fix -- it leaked four processes after
    // `run` was already correct. They share one implementation now.
    //
    // T3 is listed separately because it exposed the timing half of the bug:
    // its child forks twice more for the namespace supervisors, so it lingers
    // before execve and reliably catches a SIGTERM that lands before the
    // forwarder is armed. With the forwarder scoped to spawn_wait() only, T3
    // leaked six processes while T2 leaked none -- the same defect, just far
    // harder to hit without the extra fork levels.
    //
    // `observe` is the most serious of the three: an observed workload runs
    // UNCONFINED, so an orphan from it holds the user's full authority.
    struct Case { const char* sub; const char* tier; const char* label; };
    const Case cases[] = {
        {"run",     nullptr, "run"},
        {"run",     "t3",    "run-t3"},
        {"observe", nullptr, "observe"},
    };

    for (const auto& c : cases) {
        // Marker unique per run AND per case, so a stale process from an
        // earlier phase cannot make a broken build look healthy.
        const std::string marker = std::string{"bastion-lifecycle-"} + c.label +
                                   "-" + std::to_string(::getpid());
        const int orphaned = orphans_after_kill(c.sub, c.tier, marker);
        if (orphaned < 0) {
            std::printf("  [FAIL] could not spawn `bastion %s`\n", c.sub);
            ++failures;
            continue;
        }
        check(orphaned == 0,
              (std::string{"SIGTERM on `bastion "} + c.label +
               "` leaves NO orphaned processes").c_str());
    }

    // The OTHER half, and the one an agent actually reaches: bastion is not
    // killed at all. It exits normally, and the workload has deliberately
    // detached a process (setsid + background) to outlive it.
    //
    // MEASURED, and it is a TIER BOUNDARY rather than a bug. All three
    // outcomes below are measured, not assumed:
    //
    //   run t2 -- the survivor LIVES. setsid() leaves the process group, and
    //         the group is the only handle a path-set sandbox has on the
    //         subtree; killpg cannot reach what has left the group. It keeps
    //         exactly the authority the policy granted -- narrow, but after
    //         bastion is gone.
    //
    //   run t3 -- the survivor DIES, for free and with no reaper: the PID
    //         namespace is torn down when its init exits and the kernel
    //         SIGKILLs everything inside. setsid does not escape a namespace.
    //
    //   observe -- the survivor DIES TOO, which is the outcome that matters
    //         most: an observed workload runs UNCONFINED, so a survivor would
    //         hold the user's FULL authority indefinitely and keep appending
    //         to the ledger that `synthesize` later mines. It dies because
    //         the supervisor loop runs until the seccomp listener reports
    //         POLLHUP -- i.e. until the last process carrying the filter is
    //         gone -- and a detached child inherits the filter across setsid
    //         and execve. So observation outlasts the thing being observed.
    //
    // All three are asserted, so none can drift silently. If you need a
    // CONFINED workload's background processes reaped on exit, that is what
    // --tier t3 is for.
    //
    // Measured with a FILE BEACON, not by grepping /proc. Process-name
    // matching is treacherous here: the marker string also appears in the
    // cmdline of the shell that launched the test, so a grep counts ancestors
    // as survivors and a pkill cleanup kills the test's own shell (both
    // happened, and both made the test silently vacuous). A beacon written
    // after bastion has exited is unambiguous.
    std::puts("\n== a detached process vs. a CLEAN exit (T2 limit, T3 closes) ==");

    // T3's half of this needs a PID NAMESPACE, which not every host offers --
    // GitHub Actions runners do not. Ask `doctor`, which is both the user's
    // own source of truth and free of a link dependency here. Asserting a
    // guarantee the kernel cannot provide turns a real capability gap into a
    // red test and hides the failures that matter. Where namespaces are
    // missing the ceiling is T2 (probe() enforces that), so there is no T3
    // behaviour to check.
    bool have_ns = false;
    {
        const std::string out = "/tmp/bastion-lifecycle-doctor.txt";
        (void)std::system((std::string{BASTION_CLI} + " doctor >" + out +
                           " 2>&1")
                              .c_str());
        if (FILE* f = std::fopen(out.c_str(), "rb")) {
            char buf[4096] = {0};
            (void)std::fread(buf, 1, sizeof buf - 1, f);
            std::fclose(f);
            have_ns = std::strstr(buf, "namespace isolation: yes") != nullptr;
        }
        ::unlink(out.c_str());
    }
    if (!have_ns) {
        std::puts("      (no PID namespace on this host -- T3 case skipped; "
                  "the ceiling is T2 here)");
    }

    struct DetachCase { const char* sub; const char* tier; bool must_die; };
    for (const auto& d : {DetachCase{"run", "t2", false},
                          DetachCase{"run", "t3", true},
                          DetachCase{"observe", "t0", true}}) {
        if (std::string{d.tier} == "t3" && !have_ns) continue;
        const std::string beacon = std::string{"/tmp/bastion-detach-"} +
                                   d.sub + "-" + d.tier + "-" +
                                   std::to_string(::getpid());
        ::unlink(beacon.c_str());

        // Sleep PAST bastion's exit, then write. If the sandbox reaps the
        // subtree the write never happens; if it does not, the beacon appears
        // after bastion is already gone -- which is exactly the property.
        // The workspace must include /tmp for the confined case to be able to
        // write at all, so the beacon tests lifetime, not permission.
        const std::string cmd =
            std::string{BASTION_CLI} + " " + d.sub + " --no-ledger " +
            (std::string{d.sub} == "run"
                 ? std::string{"--tier "} + d.tier + " -w /tmp "
                 : std::string{}) +
            "-- sh -c 'setsid sh -c \"sleep 2; echo alive > " + beacon +
            "\" </dev/null >/dev/null 2>&1 &' >/dev/null 2>&1";
        (void)std::system(cmd.c_str());

        // bastion has returned by now; wait past the detached sleep.
        ::usleep(3500 * 1000);

        std::error_code bec;
        const bool survived = std::filesystem::exists(beacon, bec);
        std::printf("      %-8s %s: detached process %s\n", d.sub, d.tier,
                    survived ? "SURVIVED" : "was reaped");
        if (d.must_die) {
            check(!survived,
                  std::string{d.sub} == "observe"
                      ? "observe: a detached process cannot outlive "
                        "observation (it would hold UNCONFINED authority)"
                      : "T3: a detached process CANNOT outlive bastion "
                        "(PID namespace teardown)");
        } else {
            // Documented, not silently tolerated: T2 grants paths, and a
            // process that has left the process group is beyond killpg's
            // reach. If this ever starts being reaped at T2 the docs are
            // wrong and must be corrected upward.
            check(survived,
                  "T2/T0: a detached process outlives bastion -- documented "
                  "limit, closed by --tier t3");
        }
        ::unlink(beacon.c_str());
    }

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "lifecycle verified" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
