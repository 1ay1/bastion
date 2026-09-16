# Security model

What bastion defends against, what it does not, and which claims are measured
versus assumed. Read this before trusting it with anything.

The governing rule: **every claim here is either measured on real hardware or
labelled as unverified.** Where a limit exists it is asserted as a limit in the
test suite, so the documented boundary cannot drift from the enforced one.

---

## 1. Threat model

### In scope

1. **Prompt-injected agents.** The model is tricked into running code that
   exfiltrates credentials, edits files outside the task, or calls home. This is
   the primary threat.
2. **Malicious/compromised dependencies.** A postinstall script or build plugin
   that reads `~/.ssh` or POSTs your environment somewhere.
3. **Accidental destruction.** `rm -rf` with a bad variable; writes outside the
   workspace.
4. **Native code.** The confined process may execute arbitrary machine code. T2+
   is a *kernel* boundary precisely because in-process checks cannot survive
   this.

### Out of scope

1. **Kernel exploits.** A Landlock or Seatbelt bypass defeats bastion. Use T4
   (unimplemented) when the kernel is inside your threat model.
2. **Side channels.** Timing, cache, power. No mitigation.
3. **Resource exhaustion — addressed on Linux, partially elsewhere.** Opt-in
   ceilings: `--max-procs`, `--max-mem-mb`, `--max-file-mb`, `--max-cpu-sec`.
   Core dumps are always disabled.

   Where a delegated **cgroup v2** exists (systemd's `user@UID.service`, no
   root required), `--max-procs` and `--max-mem-mb` are a true PER-SANDBOX
   budget: `--max-procs 20` means twenty processes *in this sandbox*, and the
   kernel reports every refusal so an OOM-kill is explained rather than
   arriving as a bare exit 137. Otherwise bastion falls back to `setrlimit`
   and **says so** — `RLIMIT_NPROC` is accounted per-uid across the whole
   system (threads, not processes), so it is a fork-bomb backstop only, and
   `--max-mem-mb` is dropped entirely because no rlimit means it.
   `bastion doctor` prints which mechanism you have.

   Still missing: a disk-*space* quota (`--max-file-mb` caps single files, not
   total bytes written) and CPU weight/quota beyond a wall of CPU-seconds.
4. **A hostile *host*.** bastion confines children. If the agent host itself is
   compromised, it simply spawns without bastion.
5. **Data already given.** Anything inside the workspace is readable by design.
   The boundary is the workspace, not the data.

### The config/credential line

The ergonomic floor grants **read** on a short list of tool config *files* —
`~/.gitconfig`, `~/.config/git/config`, `/etc/gitconfig`. Without them `git`
does not degrade, it refuses: *"fatal: unknown error occurred while reading the
configuration files"*. An agent that cannot run `git status` cannot work.

These are **files, never directories**, and that distinction is load-bearing.
Granting `~/.config/git` as a directory leaked `~/.config/git/credentials` —
git's own documented credential store, sitting beside the config file. Path-set
authority covers everything beneath a directory, so *"the config lives in that
folder"* is never a safe reason to grant the folder.

Still denied, and asserted by the adversarial suite: `~/.git-credentials`,
`~/.netrc`, `~/.config/gh/hosts.yml`, anything else inside the git config
directory, and **writes** to `~/.gitconfig` (`core.pager` and `core.editor` are
command strings git executes, so a writable config is a persistence vector).

---

## 2. What each tier actually promises

| Tier | Real guarantee | Survives native code? |
|---|---|---|
| T0 observe | **None** (by design). Records what the workload actually did, without changing it. | — |
| T1 advisory | Stops accidents. In-process, so bypassable. | No |
| T2 kernel | Kernel-enforced path-set authority. | **Yes** |
| T3 isolate | T2 + brokered per-host egress + PID/IPC isolation (Linux). | **Yes** |
| T4 virtualize | Separate kernel. *Not implemented.* | — |

T0 and T1 are **not boundaries** against a motivated adversary, and
`tier_guarantee()` says so in those words. They exist for dry-runs, CI diffing
and learning what a workload needs — not for containment.

---

## 3. Measured results

All on macOS 26.6.2 / arm64 / Apple clang 21. **Linux is unverified** — see
`docs/linux-bringup.md`.

### 3.1 Adversarial suite: 29 attempts, 0 escapes

| Class | Attempts | Result |
|---|---|---|
| Symlink escapes (→ secret dir, `/etc`, `/`) | 3 | Blocked |
| Path traversal (`../`, `.././`, `//`) | 4 | Blocked |
| Sibling-prefix confusion | 1 | Blocked |
| Re-confinement / privilege regain | 3 | Blocked |
| Credential theft (`~/.ssh`, `~/.aws`, keychain, history, `.gitconfig`, `.npmrc`) | 6 | Blocked |
| Inherited descriptors | 2 | Blocked (§4.1) |
| Environment hygiene | 1 | Stripped |
| Persistence writes (`/etc`, `~/.zshrc`, `/usr/local/bin`, LaunchAgents) | 4 | Blocked |
| T3 egress bypass (proxy skip, raw socket) | 2 | Blocked |
| Workspace remains usable | 4 | Works |

The symlink cases are the *field report's own workaround* run as an attack:
under `bwrap` a symlink farm over-grants; path-set authority denies all three.

### 3.2 Type-level claims

Four programs must **fail to compile**, verified by `ctest`: widening a
capability, using a read-only cap where write is required, copying a capability,
and laundering `Unconfined` into a normal grant set.

---

## 4. Vulnerabilities found and fixed

Documented because the reasoning generalizes, and because a security doc that
lists no findings has not been looked at hard enough.

### 4.1 Inherited file descriptors bypass the path policy

**Severity: critical.** On both Seatbelt and Landlock, access rights attach to
the **open file description**, not the path — the Landlock docs state this
outright. A descriptor opened before confinement keeps working after it and
survives `exec`:

```
parent opened fd=4 on /tmp/bastion-fd-secret.txt BEFORE confinement
confined.
  CHILD: read(4) succeeded -> FLAG{fd-inherited}
```

The child was denied the path and still read the file in full. One leaked
descriptor voids the entire filesystem policy — and agent hosts are exactly the
programs that hold config, credential and log files open while spawning tools.

**Fix:** `spawn()` closes every descriptor above stderr in the child, before
confining. Relying on callers to set `O_CLOEXEC` is not acceptable: a sandbox
that is only safe when every caller is careful is not a boundary.

**Near-miss worth recording:** the first probe used `/dev/fd/N` and reported *no
leak*, because that path is itself mediated. Only a raw `read(2)` on the
descriptor exposed it. A weak probe nearly certified a critical hole as safe.

### 4.2 SBPL policy injection via crafted paths

**Severity: high.** Paths are interpolated into a Seatbelt profile. Measured:

- a path containing `"` aborts profile compilation (fail-closed, but a DoS);
- `…/x") (allow file-read* (subpath "/` **injects a rule granting total
  filesystem read** when interpolated naively.

Agents create files from model output, so attacker-influenced path text reaching
a profile is a live threat.

**Fix:** `sbpl_escape()` escapes `\` *before* `"` (order matters — an unescaped
backslash silently changes which directory a rule matches), and control
characters are rejected outright rather than escaped and hoped for. The
injection payload is now parsed as a literal directory name and grants nothing.
Both are regression-tested.

### 4.3 Synthesizer proposed `fs.read /`

**Severity: medium.** Observation legitimately sees dyld reading the root
directory, so the first synthesizer emitted a grant for `/` — the entire
filesystem, inside a policy presented as least-privilege.

**Fix:** `/` is refused explicitly, and floor-covered accesses are filtered.
Related: a denied operation is **never** turned into a grant, or synthesis would
hand over exactly what the sandbox stopped.

### 4.4 Synthesizer claimed "no grants needed" with no evidence

**Severity: medium (trust).** With only spawn records in the ledger, synthesis
reported that a workload which had demonstrably read `/etc/hosts` and written
`/tmp` needed nothing. A confident wrong answer is worse than no answer.

**Fix:** it now refuses to emit a policy without access evidence and points at
`bastion observe`.

---

## 5. Known limits

Each is asserted as a `LIMIT` in the test suite. If one ever tightens, the test
flips and the docs get corrected.

| Limit | Tier | Mitigation |
|---|---|---|
| Egress is all-or-nothing | T2 | Use `--tier t3` |
| Host processes visible (`ps aux`) | T2 | Use `--tier t3` on Linux (PID namespace). Still open on macOS, which has no unprivileged equivalent. |
| No disk-space quota | all | `--max-file-mb` caps single files, not total bytes written |
| `--max-procs`/`--max-mem-mb` need a delegated cgroup | Linux | With one, they are a true per-sandbox budget; without, bastion falls back to RLIMIT_NPROC (per-uid, thread-counted) and reports the downgrade |
| Path EXISTENCE is probeable | all | Landlock denies reading and listing, but `stat(2)` on a denied path still distinguishes "exists" from "does not". MEASURED: a T3 workload cannot list `/`, read `/etc/shadow` or enumerate `/home`, but `test -e /home/alice` succeeds. Closing it needs `pivot_root`; see below. |
| Kernel exploits | all | Out of scope; T4 |
| Landlock ABI < v2 denies cross-dir rename | T2 Linux | Kernel 5.19+ |
| Landlock ABI < v4 cannot mediate network | T3 Linux | T3 **refused**, not degraded |
| Unprivileged user namespaces disabled | T3 Linux | Process isolation is dropped and **reported**; the file/network boundary is unaffected |

---

### On `pivot_root`

T3 creates user, PID, IPC and mount namespaces, but does **not** `pivot_root`
into a minimal tree. That is deliberate, and it is worth showing the working
because the obvious reading — "the workload can see the whole filesystem" — is
wrong.

Measured on kernel 7.2.2, inside `bastion run -t t3`:

| Probe | Result |
|---|---|
| `ls /` | **denied** |
| `cat /etc/shadow` | **denied** |
| `ls /home` | **denied** |
| `test -e /home/alice` | **succeeds** |

Landlock already denies reading and listing everything outside the policy. What
survives is *existence*: `stat(2)` on a denied path still distinguishes "exists"
from "does not", because path traversal metadata has to be granted for any
nested rule to resolve at all (`fs.stat` is unconditionally floor-granted for
that reason).

`pivot_root` would close it — verified working unprivileged inside T3's existing
namespaces, hiding the host tree completely. The cost is that every path the
workload needs must then be bind-mounted in: `/usr`, `/lib`, the loader cache,
the workspace, `$TMPDIR`, the toolchain caches. That is the mount-topology
problem this project exists to avoid (DESIGN.md §2–3), reintroduced to close a
leak that reveals *whether a path exists* and nothing about its contents.

So the trade is stated rather than taken: **a narrow, named leak instead of a
broad, fragile mechanism.** If existence-probing is inside your threat model,
T4 is the honest answer, not a bind-mount farm.

---

## 6. Design rules that are load-bearing

Violating any of these silently converts bastion from a boundary into a
suggestion.

1. **Fail closed, always.** Compilation failure, missing kernel support, failed
   `apply` — every one prevents `exec`. A failed sandbox never becomes no
   sandbox.
2. **Never silently downgrade.** If the policy asks for a tier the backend
   cannot deliver, refuse. A sandbox that quietly weakens is worse than one that
   stops, because the user still believes they are protected.
3. **No setuid, ever.** `firejail` is excluded from the default path for exactly
   this reason (CVE-2022-31214: a crafted join target yields an environment
   still in the initial user namespace with `NO_NEW_PRIVS` unset — local root).
   A sandbox whose own mechanism is a privilege-escalation surface inverts the
   threat model.
4. **Probe at runtime.** Never infer capability from build flags. A kernel may
   lack Landlock where the headers exist.
5. **Report what you cannot enforce.** `bastion explain` prints the real
   boundary, including gaps. Silence about a limit is the failure this project
   exists to fix.
6. **Lowering a tier never lowers observability.** `--yolo` is a maximal grant
   at a retained tier, fully witnessed and logged — never `--sandbox off`.

---

## 7. Reporting a vulnerability

A reproducer beats a description. The most useful shape is a new case in
`tests/adversarial_test.cpp` that fails — that is exactly how §4.1 was found and
how it stays fixed.

If you are unsure whether something is a bug or a documented limit, check §5
and `tier_guarantee()` first: the tier may already be telling you it does not
defend against that.
