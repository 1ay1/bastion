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

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "capture verified" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
