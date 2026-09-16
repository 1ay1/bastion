// ABI degradation: does a binary built on a NEW kernel still confine correctly
// on an OLD one?
//
// This is the single most likely way bastion breaks in the field, and the
// hardest to catch: development happens on Landlock ABI v10, where every
// capability exists, so none of the version-gating code is ever exercised. A
// CI runner with an older kernel helps, but only for the versions someone
// happens to have.
//
// The insight that makes this testable HERE: compile() is a pure function of
// (policy, AbiInfo). Nothing about it reads the running kernel -- probe_abi()
// does that, separately. So every ABI level from v1 to v10 can be exercised on
// this machine by handing compile() a synthetic AbiInfo, and the properties
// below are checked against ALL of them rather than against whichever kernel
// the test happens to run on.
//
// The two failure modes being excluded:
//   OVER-CLAIMING -- requesting a right the old kernel does not know. The
//     kernel rejects the whole ruleset with EINVAL, so the sandbox does not
//     merely lose that right, it FAILS ENTIRELY. Fail-closed turns that into
//     "nothing runs", which is safe but looks like bastion is broken.
//   SILENT DEGRADATION -- quietly enforcing less than the tier promises. This
//     is the dangerous one: the user believes they have T3 per-host egress and
//     actually have none.
#include "bastion/backend/landlock.hpp"

#include <cstdio>
#include <string>

using namespace bastion;
using namespace bastion::linux_ll;

static int failures = 0;
static void check(bool c, const std::string& what) {
    std::printf("  [%s] %s\n", c ? "PASS" : "FAIL", what.c_str());
    if (!c) ++failures;
}

// Synthesise the AbiInfo a kernel at `version` would report. Mirrors
// probe_abi()'s feature mapping exactly -- if that drifts, these tests are
// testing a fiction, so the mapping is asserted against the real probe below.
static AbiInfo abi_at(int version) {
    AbiInfo a;
    a.version = version;
    a.has_refer = version >= 2;
    a.has_truncate = version >= 3;
    a.has_net_tcp = version >= 4;
    a.has_ioctl_dev = version >= 5;
    a.has_scoped = version >= 6;
    a.has_quiet = version >= 10;
    a.note = "synthetic ABI v" + std::to_string(version);
    return a;
}

// Every Landlock FS right, by the ABI version that introduced it. A ruleset
// must never request a bit from a LATER version than the kernel reports.
struct RightBit {
    std::uint64_t bit;
    int since;
    const char* name;
};

int main() {
    // The synthetic mapping must match the real one, or every test below is
    // measuring an invention rather than the shipping behaviour.
    {
        const AbiInfo real = probe_abi();
        if (real.version >= 0) {
            const AbiInfo synth = abi_at(real.version);
            check(synth.has_refer == real.has_refer &&
                      synth.has_truncate == real.has_truncate &&
                      synth.has_net_tcp == real.has_net_tcp &&
                      synth.has_ioctl_dev == real.has_ioctl_dev &&
                      synth.has_scoped == real.has_scoped &&
                      synth.has_quiet == real.has_quiet,
                  "synthetic ABI matches probe_abi() on this kernel (v" +
                      std::to_string(real.version) + ")");
        } else {
            std::puts("  [skip] no Landlock on this kernel; synthetic only");
        }
    }

    auto workspace = [] {
        return Policy{Tier::Kernel}
            .allow(Right::FsRead | Right::FsWrite, "/tmp", "workspace")
            .allow(Right::FsRead | Right::FsExec, "/usr", "toolchain")
            .seal();
    };

    std::puts("\n== 1. no ruleset requests a right its kernel lacks ==");
    {
        // Bits that do not exist before a given ABI. Requesting one makes
        // landlock_create_ruleset fail with EINVAL and takes the ENTIRE
        // sandbox with it -- the "built new, must run old" case.
        static constexpr RightBit kGated[] = {
            {1ull << 13, 2, "REFER"},
            {1ull << 14, 3, "TRUNCATE"},
            {1ull << 15, 5, "IOCTL_DEV"},
        };

        for (int v = 1; v <= 10; ++v) {
            auto rs = compile(workspace(), abi_at(v));
            if (!rs) {
                check(false, "v" + std::to_string(v) + ": compile failed: " +
                                 rs.error());
                continue;
            }
            const auto& r = rs.value();

            bool clean = true;
            std::string offender;
            for (const auto& g : kGated) {
                if (v < g.since && (r.handled_fs & g.bit)) {
                    clean = false;
                    offender = g.name;
                }
                // Per-path rules are masked to handled_fs by apply(), but a
                // rule asking for more than the ruleset handles is EINVAL too.
                for (const auto& p : r.paths) {
                    if (v < g.since && (p.allowed & g.bit & ~r.handled_fs)) {
                        clean = false;
                        offender = std::string{g.name} + " on " + p.path;
                    }
                }
            }
            check(clean, "v" + std::to_string(v) +
                             ": handled mask contains no post-v" +
                             std::to_string(v) + " bits" +
                             (clean ? "" : " (got " + offender + ")"));
        }
    }

    std::puts("\n== 2. attr size never exceeds what the kernel accepts ==");
    {
        // Passing a struct larger than the kernel knows is E2BIG. The size must
        // come from the PROBED version, never from sizeof() on build headers.
        for (int v = 1; v <= 10; ++v) {
            const std::size_t sz = abi_at(v).ruleset_attr_size();
            const std::size_t expect_fields =
                v >= 10 ? 6 : (v >= 6 ? 3 : (v >= 4 ? 2 : 1));
            check(sz <= expect_fields * sizeof(std::uint64_t),
                  "v" + std::to_string(v) + ": attr size " +
                      std::to_string(sz) + " fits a v" + std::to_string(v) +
                      " kernel");
        }
    }

    std::puts("\n== 3. T3 REFUSES below ABI v4 rather than degrading ==");
    {
        // The dangerous failure mode. Below v4 the kernel cannot mediate
        // network access at all, so the broker port cannot be pinned -- a
        // compromised child could simply open its own socket. Claiming T3
        // there would be a lie, so compilation must FAIL.
        auto t3 = Policy{Tier::Isolate}
                      .allow(Right::FsRead | Right::FsWrite, "/tmp", "ws")
                      .allow_egress("example.com:443", "api")
                      .seal();

        for (int v = 1; v <= 3; ++v) {
            auto rs = compile(t3, abi_at(v), /*proxy_port=*/40000);
            check(!rs, "v" + std::to_string(v) + ": T3 refused, not degraded");
            if (!rs) {
                check(rs.error().find("v4") != std::string::npos,
                      "v" + std::to_string(v) + ": the error names the needed ABI");
            }
        }
        for (int v = 4; v <= 10; ++v) {
            auto rs = compile(t3, abi_at(v), /*proxy_port=*/40000);
            check(rs.ok(), "v" + std::to_string(v) + ": T3 compiles");
            if (rs) {
                // The broker port MUST be allowed, or T3 denies its own broker
                // -- the exact bug the enum-vs-macro guard once caused.
                bool pinned = false;
                for (const auto& p : rs.value().ports) {
                    if (p.port == 40000 && p.connect) pinned = true;
                }
                check(pinned, "v" + std::to_string(v) +
                                  ": the broker port is pinned");
            }
        }
    }

    std::puts("\n== 4. lost capabilities are REPORTED, never silent ==");
    {
        // Losing a right is acceptable; losing it quietly is not. The user has
        // to be able to tell what boundary they actually got. Checked up to v5
        // because v6 is the first level with no missing FS/scope capability.
        for (int v = 1; v <= 5; ++v) {
            auto rs = compile(workspace(), abi_at(v));
            check(rs.ok(), "v" + std::to_string(v) + ": T2 still compiles");
            if (!rs) continue;

            const auto& w = rs.value().warnings;
            check(!w.empty(), "v" + std::to_string(v) +
                                  ": degraded enforcement is warned about");
        }

        // A T2 policy with network rules on a pre-v4 kernel: egress is
        // UNRESTRICTED, which the user must be told in as many words.
        auto net_t2 = Policy{Tier::Kernel}
                          .allow(Right::FsRead, "/tmp", "ws")
                          .allow_egress("example.com:443", "api")
                          .seal();
        auto rs = compile(net_t2, abi_at(3));
        check(rs.ok(), "v3: T2 with net rules compiles");
        if (rs) {
            bool said = false;
            for (const auto& w : rs.value().warnings) {
                if (w.find("UNRESTRICTED") != std::string::npos) said = true;
            }
            check(said, "v3: unenforceable egress is called UNRESTRICTED");
            check(rs.value().handled_net == 0,
                  "v3: no net mask is claimed when it cannot be enforced");
        }
    }

    std::puts("\n== 5. the ergonomic floor survives every ABI ==");
    {
        // A sandbox that cannot run a dynamically-linked binary is useless, no
        // matter how old the kernel. The loader paths must be granted at v1.
        for (int v = 1; v <= 10; ++v) {
            auto rs = compile(workspace(), abi_at(v));
            if (!rs) continue;
            bool usr = false, tmp = false;
            for (const auto& p : rs.value().paths) {
                if (p.path == "/usr") usr = true;
                if (p.path == "/tmp") tmp = true;
            }
            check(usr && tmp,
                  "v" + std::to_string(v) + ": floor + workspace both granted");
        }
    }

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ABI degradation verified across v1-v10"
                              : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
