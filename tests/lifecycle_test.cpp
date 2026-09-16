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

int main() {
    // A marker unique to this run, so a stale process from an earlier test
    // cannot make a broken build look healthy.
    //
    // It must appear in EACH child's own argv, not just in the `sh -c` string.
    // A trailing `# marker` comment lives only in the shell's command line, so
    // the grandchildren would be invisible and the test would count one
    // process where it should count four -- which is exactly the failure this
    // test exists to catch, so getting it wrong would be self-defeating.
    const std::string marker =
        "bastion-lifecycle-" + std::to_string(::getpid());

    // `exec -a NAME` sets argv[0], so each grandchild carries the marker in
    // its own /proc/PID/cmdline.
    const std::string sleeper =
        "sh -c 'exec -a " + marker + " sleep 45'";

    std::puts("== killing bastion kills the whole subtree ==");

    // Spawn bastion running THREE background sleeps: the workload plus
    // grandchildren, which is the case that actually leaks.
    const pid_t bp = ::fork();
    if (bp < 0) {
        std::puts("  [FAIL] fork");
        return 1;
    }
    if (bp == 0) {
        ::setsid();  // detach from the test's terminal/job control
        const int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDOUT_FILENO);
            ::dup2(devnull, STDERR_FILENO);
        }
        const std::string script =
            sleeper + " & " + sleeper + " & " + sleeper;
        ::execl(BASTION_CLI, "bastion", "run", "--no-ledger", "-w", "/tmp",
                "--", "sh", "-c", script.c_str(), (char*)nullptr);
        _exit(127);
    }

    // Let the workload get going.
    ::usleep(1500 * 1000);
    const int before = count_matching(marker.c_str());
    std::printf("      running before kill: %d\n", before);
    check(before >= 3, "the workload and its children are running");

    // The thing an agent harness does on timeout.
    ::kill(bp, SIGTERM);

    int st = 0;
    ::waitpid(bp, &st, 0);
    ::usleep(1500 * 1000);  // give the subtree a moment to die

    const int after = count_matching(marker.c_str());
    std::printf("      surviving after kill: %d\n", after);
    check(after == 0, "SIGTERM on bastion leaves NO orphaned processes");

    if (after != 0) {
        // Do not leave the machine dirtier than we found it.
        const std::string cleanup = "pkill -9 -f '" + marker + "' 2>/dev/null";
        (void)std::system(cleanup.c_str());
    }

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "lifecycle verified" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
