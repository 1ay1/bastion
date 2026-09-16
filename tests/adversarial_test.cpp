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

// The suite counts itself. Every number the README and security-model quote
// comes from the summary line below, and tools/check_claims.sh fails the build
// if a doc drifts from it -- otherwise "27 attempts" outlives the 27th attempt.
static int attempts = 0;    // things an attacker tries and must not get
static int positives = 0;   // things a legitimate agent does and must get

static void must_deny(const char* attack, const SpawnResult& r) {
    const bool blocked = r.launched() && r.exit_code != 0;
    ++attempts;
    std::printf("  [%s] %s\n", blocked ? "BLOCKED" : "ESCAPED!", attack);
    if (!blocked) ++failures;
}

static void must_allow(const char* what, const SpawnResult& r) {
    const bool ok = r.launched() && r.exit_code == 0;
    ++positives;
    std::printf("  [%s] %s\n", ok ? "OK" : "BROKEN", what);
    if (!ok) ++failures;
}

// A limit we accept and document at this tier. It is still an ATTEMPT: the
// attacker tries it either way, and whether it lands is what the tier decides.
static void known_limit(const char* what, bool escaped, const char* why) {
    ++attempts;
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

    // Stage a credential file where git actually keeps one, so the check below
    // is REAL. must_deny() passes when a command fails for any reason,
    // including "no such file" -- so without this the most important case in
    // this section would pass vacuously on a machine that happens not to have
    // one. This is the file that leaked when the floor granted the directory.
    const fs::path git_cfg_dir = fs::path{std::getenv("HOME") ? std::getenv("HOME")
                                                              : "/tmp"} /
                                 ".config/git";
    const fs::path planted = git_cfg_dir / "bastion-test-credentials";
    bool planted_ok = false;
    {
        std::error_code ec;
        fs::create_directories(git_cfg_dir, ec);
        if (!ec) {
            std::ofstream f(planted);
            if (f) {
                f << "https://token:x-oauth-basic@github.com\n";
                planted_ok = true;
            }
        }
    }

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
    must_deny("npmrc token", run("cat ~/.npmrc 2>/dev/null"));

    // GIT CONFIG IS READABLE BY DESIGN -- and the line between "config" and
    // "credential" is exactly where this gets dangerous.
    //
    // `git status` is the most common command an agent runs, and without
    // ~/.gitconfig git does not degrade, it REFUSES: "fatal: unknown error
    // occurred while reading the configuration files". So the floor grants it
    // read-only.
    //
    // The trap, MEASURED: granting ~/.config/git as a DIRECTORY leaked
    // ~/.config/git/credentials, git's own documented credential store,
    // sitting beside the config file. Path-set authority covers everything
    // beneath a directory, so the floor must name individual FILES. These
    // cases pin that boundary in both directions.
    must_deny("~/.git-credentials", run("cat ~/.git-credentials 2>/dev/null"));
    if (planted_ok) {
        must_deny("credentials INSIDE the git config dir",
                  run("cat " + planted.string() + " 2>/dev/null"));
    } else {
        std::puts("  [skip] could not stage a credential file to test");
    }
    must_deny("gh CLI token", run("cat ~/.config/gh/hosts.yml 2>/dev/null"));
    must_deny("~/.netrc", run("cat ~/.netrc 2>/dev/null"));
    // Readable, but NOT writable: core.pager and core.editor are command
    // strings git executes, so a writable .gitconfig is a persistence vector.
    must_deny("WRITING to ~/.gitconfig",
              run("echo '[core]' >> ~/.gitconfig 2>/dev/null"));

    // CACHE GRANTS MUST NOT REACH SECRETS. The ergonomic floor grants
    // toolchain caches so builds do not re-download the world, and the
    // tempting shortcut is to grant $XDG_DATA_HOME (~/.local/share) wholesale
    // because that is where pnpm and friends keep their stores.
    //
    // MEASURED: doing exactly that exposed ~/.local/share/keyrings/
    // login.keyring -- the GNOME keyring -- because that directory is general
    // "application state", not a cache. Same trap as ~/.config/git, where
    // granting the folder leaked the credential file sitting beside the
    // config. "The cache lives in that directory" is never a reason to grant
    // the directory.
    //
    // Staged for real, because must_deny() also passes when a file is simply
    // absent -- without this the check would pass vacuously on any machine
    // without a keyring.
    {
        const fs::path kr = fs::path{std::getenv("HOME") ? std::getenv("HOME")
                                                          : "/tmp"} /
                            ".local/share/keyrings";
        std::error_code ec;
        fs::create_directories(kr, ec);
        const fs::path secret = kr / "bastion-test.keyring";
        bool staged = false;
        if (!ec) {
            std::ofstream f(secret);
            if (f) {
                f << "SECRET_KEYRING_MATERIAL\n";
                staged = true;
            }
        }
        if (staged) {
            must_deny("keyring under the granted cache root",
                      run("cat " + secret.string() + " 2>/dev/null"));
            fs::remove(secret, ec);
        } else {
            std::puts("  [skip] could not stage a keyring file to test");
        }
    }

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

    std::puts("\n== 7b. attacks on the POLICY, not on the sandbox ==");
    // Every section above tries to break OUT of a policy. This one tries to
    // CHANGE it -- the class the suite originally missed, and the class that
    // produced its only critical bug (security-model 4.5): `bastion run`
    // auto-discovered ./bastion.toml, which the confined workload can write,
    // so the agent granted itself $HOME in two invocations.
    //
    // The general rule being asserted: an input the sandbox reads from inside
    // its own blast radius must not carry authority. These check the files a
    // confined workload can reach and bastion might later believe.
    must_deny("overwrite the operator's global bastion config",
              run("echo 'tier=\"t0\"' > ~/.bastion/config.toml 2>/dev/null"));
    must_deny("tamper with the audit ledger",
              run("echo '{}' >> ~/.bastion/ledger.jsonl 2>/dev/null"));
    must_deny("drop a policy where a PARENT project would discover it",
              run("echo 'tier=\"t0\"' > /tmp/bastion.toml 2>/dev/null"));

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

    // Process-table isolation. This was a DOCUMENTED LIMIT until T3 grew its
    // namespace half: `ps aux` inside the sandbox listed every process on the
    // box, leaking other agents' command lines (which carry tokens and repo
    // paths). Neither Landlock nor Seatbelt can mediate it -- it is not a file
    // or a socket -- so it needed unprivileged user+PID namespaces.
    //
    // Asserted at T3, because that is the tier that promises it (tier.hpp:
    // "Kernel + user/net/pid/ipc namespaces"). At T2 it remains visible by
    // design, and the tier guarantee says so.
    {
        SpawnRequest r;
        // Count /proc entries rather than shelling to ps: ps needs a readable
        // /proc, and this measures the kernel boundary rather than a tool.
        r.argv = {"/bin/sh", "-c",
                  "ls /proc 2>/dev/null | grep -c '^[0-9]' "
                  "| awk '{exit ($1 > 20) ? 0 : 1}'"};
        auto pids = spawn(t3, r);
#if defined(__linux__)
        // exit != 0 means FEWER than 20 pids were visible, i.e. isolated.
        must_deny("T3: enumerate host processes", pids);
#else
        known_limit("enumerate host processes",
                    pids.launched() && pids.exit_code == 0,
                    "macOS has no PID namespace; Seatbelt cannot hide the "
                    "process table. Needs T4.");
#endif
    }

    // Never leave a (fake) credential file behind in the user's real git dir.
    if (planted_ok) {
        std::error_code ec;
        fs::remove(planted, ec);
    }

    // THE FILESYSTEM VIEW AT T3, asserted precisely.
    //
    // The limits table says path EXISTENCE is probeable while contents are
    // not, and that claim has to be pinned in both directions -- a documented
    // limit that is not tested is a claim that drifts.
    //
    // MEASURED on kernel 7.2.2: Landlock denies listing / and /home and
    // reading /etc/shadow, but `test -e` on a denied path still succeeds,
    // because traversal metadata must be granted for nested rules to resolve
    // (fs.stat is unconditionally floor-granted). pivot_root would close it at
    // the cost of a bind-mount farm -- see security-model.md "On pivot_root".
    {
        SpawnRequest r;
        r.argv = {"/bin/sh", "-c", "ls / >/dev/null 2>&1"};
        must_deny("T3: list the root directory", spawn(t3, r));
    }
    {
        SpawnRequest r;
        r.argv = {"/bin/sh", "-c", "ls /home >/dev/null 2>&1"};
        must_deny("T3: enumerate /home", spawn(t3, r));
    }
    {
        SpawnRequest r;
        r.argv = {"/bin/sh", "-c", "cat /etc/shadow >/dev/null 2>&1"};
        must_deny("T3: read /etc/shadow", spawn(t3, r));
    }
    {
        // The OTHER direction: this is the documented residual leak. It is
        // expected to succeed, and the suite records it as a known limit so a
        // future change that closes it shows up as a deliberate improvement
        // rather than an unexplained behaviour change.
        SpawnRequest r;
        r.argv = {"/bin/sh", "-c", "test -e /etc/shadow"};
        auto probe = spawn(t3, r);
        known_limit("path existence is probeable",
                    probe.launched() && probe.exit_code == 0,
                    "stat(2) distinguishes exists/absent on a denied path; "
                    "traversal metadata must be granted for nested rules to "
                    "resolve. Closing it needs pivot_root -- see "
                    "security-model.md.");
    }

    std::printf("\n%s: %d escape(s), %d documented limit(s)\n",
                failures == 0 ? "NO ESCAPES" : "SANDBOX ESCAPED",
                failures, known_limits);
    // Machine-readable, for tools/check_claims.sh. Docs quote these; the script
    // greps them back out and diffs, so a new attack updates the prose too.
    std::printf("CLAIMS attempts=%d escapes=%d limits=%d positives=%d\n",
                attempts, failures, known_limits, positives);
    return failures == 0 ? 0 : 1;
#endif
}
