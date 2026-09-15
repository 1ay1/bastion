// Isolate WHICH step of linux_ll::apply() fails on a real kernel.
// Runs apply() in a forked child (it is irreversible) and reports the message.
#include "bastion/backend/landlock.hpp"
#include "bastion/policy.hpp"

#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <string>

using namespace bastion;

int main(int argc, char** argv) {
    const std::string dir = argc > 1 ? argv[1] : std::filesystem::current_path().string();

    auto abi = linux_ll::probe_abi();
    std::printf("abi: version=%d note=%s attr_size=%zu\n", abi.version,
                abi.note.c_str(), abi.ruleset_attr_size());
    std::printf("     refer=%d truncate=%d net=%d ioctl=%d scoped=%d quiet=%d\n",
                abi.has_refer, abi.has_truncate, abi.has_net_tcp,
                abi.has_ioctl_dev, abi.has_scoped, abi.has_quiet);

    auto sealed = Policy{Tier::Kernel}
                      .allow(Right::FsRead | Right::FsWrite, dir, "probe workspace")
                      .allow(Right::FsRead | Right::FsExec, "/usr", "toolchain")
                      .allow(Right::FsRead, "/etc", "config")
                      .seal();

    auto rs = linux_ll::compile(sealed, abi, 0);
    std::printf("\ncompile: ok=%d error=%s\n", rs.ok, rs.error.c_str());
    std::printf("  handled_fs=0x%llx handled_net=0x%llx paths=%zu ports=%zu\n",
                (unsigned long long)rs.handled_fs,
                (unsigned long long)rs.handled_net, rs.paths.size(),
                rs.ports.size());
    for (const auto& w : rs.warnings) std::printf("  warn: %s\n", w.c_str());
    for (const auto& p : rs.paths)
        std::printf("  path: %-40s allowed=0x%llx\n", p.path.c_str(),
                    (unsigned long long)p.allowed);

    std::fflush(stdout);
    pid_t pid = ::fork();
    if (pid == 0) {
        std::string err = linux_ll::apply(sealed, 0);
        if (err.empty()) {
            std::printf("\napply: OK (enforcing)\n");
            // Prove it actually enforces.
            std::printf("  read /etc/shadow -> %s\n",
                        ::access("/etc/shadow", R_OK) == 0 ? "readable" : "denied");
            std::fflush(stdout);
            _exit(0);
        }
        std::printf("\napply: FAILED: %s\n", err.c_str());
        std::fflush(stdout);
        _exit(1);
    }
    int st = 0;
    ::waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}
