// ADVERSARIAL escape suite. Every case is a real technique a prompt-injected
// agent (or the code it was tricked into running) would try. A failure here is
// a sandbox escape, not a style nit.
//
// Cases that reveal a genuine LIMIT of the tier rather than a bug are asserted
// as *known* limits, so the suite documents the true boundary instead of
// flattering it. An honest "this is not covered at T2" beats a silent hole
// (DESIGN.md §6).
#include "bastion/spawn.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

using namespace bastion;
namespace fs = std::filesystem;

static int failures = 0;
static int known_limits = 0;

static void must_deny(const char* attack, const SpawnResult& r) {
    const bool blocked = r.launched() && r.exit_code != 0;
    std::printf("  [%s] %s\n", blocked ? "BLOCKED" : "ESCAPED!", attack);
    if (!blocked) ++failures;
}

static void must_allow(const char* what, const SpawnResult& r) {
    const bool ok = r.launched() && r.exit_code == 0;
    std::printf("  [%s] %s\n", ok ? "OK" : "BROKEN", what);
    if (!ok) ++failures;
}

// A limit we accept and document at this tier.
static void known_limit(const char* what, bool escaped, const char* why) {
    std::printf("  [%s] %s\n", escaped ? "LIMIT" : "BLOCKED", what);
    if (escaped) {
        std::printf("          -> %s\n", why);
        ++known_limits;
    }
}

int main() {
#if !defined(__APPLE__) && !defined(__linux__)
    std::puts("adversarial suite: skipped (no kernel backend here)");
    return 0;
#else
    // Every attack below is platform-independent: they are things a
    // prompt-injected agent would actually try, not API exercises. The Linux
    // backend is expected to block all of them, but that is UNVERIFIED until
    // someone runs this on a real kernel (docs/linux-bringup.md §6.2).
    const fs::path ws = "/tmp/bastion-adv";
    const fs::path secret_dir = "/tmp/bastion-adv-secret";
    fs::remove_all(ws);
    fs::remove_all(secret_dir);
    fs::create_directories(ws);
    fs::create_directories(secret_dir);
    { std::ofstream f(secret_dir / "flag.txt"); f << "FLAG{escaped}\n"; }

    auto policy = Policy{Tier::Kernel}
                      .allow(Right::FsRead | Right::FsWrite, ws, "workspace")
                      .seal();

    auto run = [&](const std::string& sh) {
        SpawnRequest req;
        req.argv = {"/bin/sh", "-c", sh};
        return spawn(policy, req);
    };

    std::puts("\n== 1. symlink escapes (the field report's workaround) ==");
    // This is precisely what the user did: symlink the target into the jail.
    // Under bwrap this OVER-grants. Under path-set authority it must not.
    must_deny("symlink in workspace -> secret dir",
              run("ln -s /tmp/bastion-adv-secret /tmp/bastion-adv/link 2>/dev/null; "
                  "cat /tmp/bastion-adv/link/flag.txt 2>/dev/null"));
    must_deny("symlink to /etc",
              run("ln -s /etc /tmp/bastion-adv/etclink 2>/dev/null; "
                  "cat /tmp/bastion-adv/etclink/passwd 2>/dev/null"));
    must_deny("symlink to / then traverse",
              run("ln -s / /tmp/bastion-adv/root 2>/dev/null; "
                  "cat /tmp/bastion-adv/root/etc/passwd 2>/dev/null"));

    std::puts("\n== 2. path traversal ==");
    must_deny("../ escape from workspace",
              run("cat /tmp/bastion-adv/../bastion-adv-secret/flag.txt 2>/dev/null"));
    must_deny("deep ../../ traversal",
              run("cat /tmp/bastion-adv/../../etc/passwd 2>/dev/null"));
    must_deny("dot-slash noise",
              run("cat /tmp/./bastion-adv/.././bastion-adv-secret/flag.txt 2>/dev/null"));
    must_deny("double slashes",
              run("cat //tmp//bastion-adv-secret//flag.txt 2>/dev/null"));

    std::puts("\n== 3. sibling-prefix confusion ==");
    // /tmp/bastion-adv must not authorize /tmp/bastion-adv-secret even though
    // it is a string prefix. This is why covers() checks component boundaries.
    must_deny("string-prefix sibling directory",
              run("cat /tmp/bastion-adv-secret/flag.txt 2>/dev/null"));

    std::puts("\n== 4. re-confinement / privilege regain ==");
    must_deny("write outside via tee",
              run("echo x | tee /tmp/bastion-adv-secret/pwn.txt >/dev/null 2>&1"));
    must_deny("exec a copied shell to shed policy",
              run("cp /bin/sh /tmp/bastion-adv/sh2 2>/dev/null && "
                  "/tmp/bastion-adv/sh2 -c 'cat /etc/passwd' 2>/dev/null"));
    // Seatbelt policy is inherited across fork/exec; verify nested children
    // cannot escape it.
    must_deny("nested subshell escape",
              run("sh -c 'sh -c \"cat /etc/passwd\"' 2>/dev/null"));

    std::puts("\n== 5. credential targets ==");
    must_deny("~/.ssh", run("cat ~/.ssh/* 2>/dev/null"));
    must_deny("~/.aws/credentials", run("cat ~/.aws/credentials 2>/dev/null"));
    must_deny("keychain", run("cat ~/Library/Keychains/* 2>/dev/null"));
    must_deny("shell history", run("cat ~/.zsh_history ~/.bash_history 2>/dev/null"));
    must_deny("git global config", run("cat ~/.gitconfig 2>/dev/null"));
    must_deny("npmrc token", run("cat ~/.npmrc 2>/dev/null"));

    std::puts("\n== 5b. inherited file descriptors (MEASURED escape) ==");
    // Access rights attach to the open file DESCRIPTION, not the path, on both
    // Seatbelt and Landlock. An fd opened before confinement therefore keeps
    // working afterwards and survives exec -- verified to leak a secret in
    // full before spawn() started closing inherited descriptors.
    {
        const std::string leak = "/tmp/bastion-adv-secret/flag.txt";
        int fd = ::open(leak.c_str(), O_RDONLY);
        if (fd < 0) {
            std::puts("  [SKIP] could not open the secret to test with");
        } else {
            // Read the RAW descriptor: no path is involved, so only closing
            // the fd can stop this.
            must_deny("read(2) a pre-confinement fd inherited across exec",
                      run("exec 2>/dev/null; read -r line <&" +
                          std::to_string(fd) + " && echo \"$line\" | grep -q FLAG"));
            // And via /dev/fd, which is the path-flavoured variant.
            must_deny("read an inherited fd via /dev/fd/N",
                      run("cat /dev/fd/" + std::to_string(fd) +
                          " 2>/dev/null | grep -q FLAG"));
            ::close(fd);
        }
    }

    std::puts("\n== 6. environment hygiene ==");
    // Secrets must not be handed to the child, and injection vars must be
    // stripped even when the caller asks to inherit the environment.
    {
        setenv("MY_API_TOKEN", "super-secret-value", 1);
        setenv("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib", 1);
        SpawnRequest req;
        req.argv = {"/bin/sh", "-c",
                    "test -z \"$MY_API_TOKEN\" && test -z \"$DYLD_INSERT_LIBRARIES\""};
        req.inherit_env = true;
        must_allow("secrets + DYLD_* stripped from inherited env", spawn(policy, req));
    }

    std::puts("\n== 7. writes that matter ==");
    must_deny("write to /etc", run("echo x > /etc/bastion-pwn 2>/dev/null"));
    must_deny("write to ~/.zshrc (persistence)",
              run("echo 'evil' >> ~/.zshrc 2>/dev/null"));
    must_deny("write into /usr/local/bin (PATH hijack)",
              run("echo x > /usr/local/bin/bastion-pwn 2>/dev/null"));
    must_deny("create a LaunchAgent (persistence)",
              run("echo x > ~/Library/LaunchAgents/pwn.plist 2>/dev/null"));

    std::puts("\n== 8. the workspace still works ==");
    must_allow("write in workspace", run("echo ok > /tmp/bastion-adv/f.txt"));
    must_allow("read back", run("grep -q ok /tmp/bastion-adv/f.txt"));
    must_allow("mkdir in workspace", run("mkdir -p /tmp/bastion-adv/a/b/c"));
    must_allow("rename within workspace",
               run("touch /tmp/bastion-adv/x && mv /tmp/bastion-adv/x /tmp/bastion-adv/y"));

    std::puts("\n== 9. documented limits of T2, and how T3 closes them ==");
#if defined(__APPLE__)
    // Seatbelt filters sockets, not hostnames, so at T2 any --net grant means
    // all outbound. Asserted as a LIMIT so the docs can never drift from the
    // enforced reality.
    //
    // Linux differs: Landlock filters by PORT (ABI v4+), so a --net grant with
    // a port is genuinely narrower at T2 than it is on macOS. Left unasserted
    // here until measured on a real kernel rather than guessed at.
    auto net = Policy{Tier::Kernel}
                   .allow(Right::FsRead | Right::FsWrite, ws, "workspace")
                   .allow_egress("example.com:443", "explicit grant")
                   .seal();
    SpawnRequest nreq;
    nreq.argv = {"/bin/sh", "-c",
                 "curl -s -m 5 -o /dev/null https://1.1.1.1 2>/dev/null"};
    auto nres = spawn(net, nreq);
    known_limit("T2: egress to a NON-allowlisted host after any --net grant",
                nres.launched() && nres.exit_code == 0,
                "Seatbelt filters sockets, not hostnames. Use --tier t3, which "
                "pins egress to a loopback broker that enforces the allowlist.");
#endif

    // ...and T3 must actually close it. This is an ATTACK assertion, not a
    // limit: at T3 a non-allowlisted host must fail, and the child must not be
    // able to skip the broker by opening its own socket.
    auto t3 = Policy{Tier::Isolate}
                  .allow(Right::FsRead | Right::FsWrite, ws, "workspace")
                  .allow_egress("example.com:443", "explicit grant")
                  .seal();
    must_deny("T3: egress to a non-allowlisted host",
              [&] {
                  SpawnRequest r;
                  r.argv = {"/bin/sh", "-c",
                            "curl -s -m 8 -o /dev/null https://1.1.1.1 2>/dev/null"};
                  return spawn(t3, r);
              }());
    must_deny("T3: raw socket bypassing the broker",
              [&] {
                  SpawnRequest r;
                  r.argv = {"/bin/sh", "-c", "nc -w 3 -z 1.1.1.1 443 2>/dev/null"};
                  return spawn(t3, r);
              }());

    auto ps = run("ps aux 2>/dev/null | head -2");
    known_limit("enumerate host processes",
                ps.launched() && ps.exit_code == 0,
                "T2/T3 have no PID namespace on macOS; process listing is "
                "visible. Needs T4.");

    std::printf("\n%s: %d escape(s), %d documented limit(s)\n",
                failures == 0 ? "NO ESCAPES" : "SANDBOX ESCAPED",
                failures, known_limits);
    return failures == 0 ? 0 : 1;
#endif
}
