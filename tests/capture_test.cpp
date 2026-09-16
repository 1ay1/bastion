// Output capture: the seam that lets a HOST embed bastion.
//
// The CLI never needed this — a terminal user wants the workload's output on
// their terminal. A host does: agentty runs tools whose output IS the tool
// result, and it has to read those bytes rather than leak them to whatever
// terminal agentty was launched from. Without capture in spawn(), embedding
// means re-implementing the pipe plumbing in the parent, outside the fd
// discipline spawn() already owns.
//
// The interesting case is not "does it capture" — it is the 64 KiB pipe
// buffer. A child writing more than that blocks in write() until someone
// reads; if the parent is in waitpid(), neither side moves. That deadlock
// appears for every real build log and no small fixture, so it is tested
// explicitly.
#include "bastion/policy.hpp"
#include "bastion/spawn.hpp"

#include <cstdio>
#include <string>

#include <chrono>
#include <unistd.h>

using namespace bastion;

static int failures = 0;
static void check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++failures;
}

int main() {
    auto sealed = Policy{Tier::Kernel}
                      .allow(Right::FsRead,  "/",     "test")
                      .allow(Right::FsExec,  "/",     "test")
                      .allow(Right::FsWrite, "/tmp",  "test")
                      .seal();

    std::puts("== 1. stdout and stderr are captured, interleaved ==");
    {
        SpawnRequest r;
        r.argv = {"/bin/sh", "-c", "echo to-stdout; echo to-stderr >&2"};
        r.capture_output = true;
        auto res = spawn(sealed, r);
        check(res.launched(), "launched");
        check(res.output.find("to-stdout") != std::string::npos, "stdout captured");
        check(res.output.find("to-stderr") != std::string::npos, "stderr captured");
        check(!res.output_truncated, "not marked truncated");
    }

    std::puts("\n== 2. output LARGER than the pipe buffer does not deadlock ==");
    {
        // ~256 KiB, four times the pipe. If the parent waited before
        // draining, this hangs forever rather than failing — which is why it
        // is a test and not a comment.
        SpawnRequest r;
        r.argv = {"/bin/sh", "-c",
                  "i=0; while [ $i -lt 4096 ]; do "
                  "printf '%064d\\n' $i; i=$((i+1)); done"};
        r.capture_output = true;
        auto res = spawn(sealed, r);
        check(res.launched(), "launched");
        check(res.exit_code == 0, "child completed (no deadlock)");
        check(res.output.size() > 200000, "the whole stream was read");
    }

    std::puts("\n== 3. the cap truncates and SAYS SO ==");
    {
        SpawnRequest r;
        r.argv = {"/bin/sh", "-c",
                  "i=0; while [ $i -lt 4096 ]; do "
                  "printf '%064d\\n' $i; i=$((i+1)); done"};
        r.capture_output = true;
        r.max_output_bytes = 4096;
        auto res = spawn(sealed, r);
        check(res.exit_code == 0, "child still completes (cap is not a kill)");
        check(res.output.size() <= 4096, "output held to the cap");
        check(res.output_truncated, "truncation is REPORTED, not silent");
    }

    std::puts("\n== 4. capture is opt-in ==");
    {
        // Default: the child inherits our descriptors and nothing is
        // intercepted. A host that did not ask must not silently lose its
        // workload's output to an empty string.
        SpawnRequest r;
        r.argv = {"/bin/sh", "-c", "true"};
        auto res = spawn(sealed, r);
        check(res.launched(), "launched");
        check(res.output.empty(), "no capture without capture_output");
    }

    std::puts("\n== 5. a DENIED command's diagnostic is captured too ==");
    {
        // The point of capture for a host: the reason a sandboxed tool failed
        // has to reach the caller. If denials were lost, a host would see a
        // bare exit code and have nothing to tell the model.
        auto tight = Policy{Tier::Kernel}
                         .allow(Right::FsRead, "/usr", "test")
                         .allow(Right::FsExec, "/",    "test")
                         .seal();
        SpawnRequest r;
        r.argv = {"/bin/sh", "-c", "cat /etc/shadow"};
        r.capture_output = true;
        auto res = spawn(tight, r);
        check(res.launched(), "launched");
        check(res.exit_code != 0, "the denied read failed");
        check(!res.output.empty(), "the diagnostic reached the caller");
    }

    std::puts("\n== 6. the deadline bounds a hung child ==");
    {
        // The regression this closes: with capture_output the parent blocks in
        // read() until EOF, and a child that never exits never sends one. A
        // host cannot bound that itself -- bastion owns the descriptor -- so
        // before timeout_seconds existed, one hung tool hung the agent forever.
        SpawnRequest r;
        r.argv = {"/bin/sh", "-c", "sleep 30"};
        r.capture_output   = true;
        r.timeout_seconds  = 1;

        const auto t0 = std::chrono::steady_clock::now();
        auto res = spawn(sealed, r);
        const auto secs = std::chrono::duration_cast<std::chrono::seconds>(
                              std::chrono::steady_clock::now() - t0).count();

        check(res.launched(), "launched");
        check(res.timed_out, "timed_out is REPORTED, not inferred from a code");
        check(secs < 10, "returned at the deadline, not at the child's leisure");
    }

    std::puts("\n== 7. output written BEFORE the deadline survives ==");
    {
        // A timeout must not discard what the workload already said. The
        // partial transcript is usually the only evidence of where it hung,
        // so losing it turns a diagnosable hang into a bare "timed out".
        SpawnRequest r;
        r.argv = {"/bin/sh", "-c", "echo progress-so-far; sleep 30"};
        r.capture_output  = true;
        r.timeout_seconds = 1;
        auto res = spawn(sealed, r);
        check(res.timed_out, "timed out");
        check(res.output.find("progress-so-far") != std::string::npos,
              "pre-deadline output is kept");
    }

    std::puts("\n== 8. the deadline kills the GROUP, not just the leader ==");
    {
        // A workload that forked leaves children holding every path the policy
        // granted. Killing only the leader leaves them running unsupervised,
        // which is the orphan bug signal_forward.hpp exists to prevent -- the
        // deadline path has to honour it too.
        const char* marker = "/tmp/bastion-deadline-orphan.probe";
        ::unlink(marker);
        SpawnRequest r;
        r.argv = {"/bin/sh", "-c",
                  "sh -c 'sleep 3; echo leaked > /tmp/bastion-deadline-orphan.probe' &"
                  " sleep 30"};
        r.capture_output  = true;
        r.timeout_seconds = 1;
        auto res = spawn(sealed, r);
        check(res.timed_out, "timed out");
        ::sleep(5);          // past when the grandchild would have written
        check(::access(marker, F_OK) != 0,
              "the forked grandchild was killed too, not orphaned");
        ::unlink(marker);
    }

    std::puts("\n== 9. a child that finishes early is NOT marked timed out ==");
    {
        // The deadline must be a ceiling, not a schedule: a fast command with
        // a generous timeout has to return immediately and cleanly. Getting
        // this wrong would make every bounded run look like a failure.
        SpawnRequest r;
        r.argv = {"/bin/sh", "-c", "echo quick"};
        r.capture_output  = true;
        r.timeout_seconds = 30;

        const auto t0 = std::chrono::steady_clock::now();
        auto res = spawn(sealed, r);
        const auto secs = std::chrono::duration_cast<std::chrono::seconds>(
                              std::chrono::steady_clock::now() - t0).count();

        check(!res.timed_out, "not marked timed out");
        check(res.exit_code == 0, "clean exit preserved");
        check(res.output.find("quick") != std::string::npos, "output captured");
        check(secs < 5, "returned when the CHILD did, not at the deadline");
    }

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "capture verified" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
