# bastion — design notes

## 0. Provenance

This design is driven by a field report from an Agentty user who spent a full day
fighting `bwrap`/`firejail` confinement for an agent, plus source review of the
current state of the art (Anthropic `sandbox-runtime`, OpenAI Codex CLI
`seatbelt`/`landlock`/`RestrictedToken`, Chromium's Windows sandbox, Landlock
upstream docs, `seccomp_unotify(2)`).

The field report is treated as a specification. Verbatim complaints, and what
each one actually diagnoses:

| Report | Real defect |
|---|---|
| "I lost the flexibility of running Agentty in any working directory and now have a fixed `$HOME/sandbox`" | Confinement was built out of **mount topology**, which is expensive and fragile to recompute per directory — so it gets frozen. |
| "I just quickly symlink the directory I need in there" | A symlink farm is a **security regression**, not a workaround (§2). |
| "One aspect I found positive was the return of rw in `/tmp`. So most compiling errors will be gone and the LLMs will stop going around in circles" | A sandbox that breaks the toolchain **burns agent turns**. Ergonomics is a correctness property here, not a nicety. |
| "I had a very detailed AGENTS.md which is no longer needed" | Policy that must be **explained in prose to the model** is a policy with no machine-readable failure channel. |
| "The diff from bwrap to firejail is hair raising" | Two tools, same nominal job, wildly different real boundary. The user cannot see the actual enforced surface. |
| "if you're paranoid, turn `--sandbox off` and get apparmor or selinux, but **you're on your own**" | The framework's own escape hatch drops the user off a cliff. This is the central failure. |

The last row is the thesis of this project.

---

## 1. Thesis: the bypass is a capability, not a power switch

Every shipping agent sandbox models safety as a **scalar**: `off | workspace-write
| read-only | danger-full-access`. Turning it down to get work done discards the
policy language, the audit trail, and the diagnostics all at once. So the user's
two real options are "fight the jail" or "you're on your own" — exactly what the
report describes.

`bastion` splits that scalar into two independent axes.

**Axis 1 — enforcement tier.** *How strong is the wall?*

```
T0 Observe     no enforcement; full policy eval + audit log   (dry run, CI diffing)
T1 Advisory    in-process interposition; deny + log            (best-effort, any OS)
T2 Kernel      Landlock / Seatbelt / AppContainer+WFP          (the default)
T3 Isolate     T2 + user/net/pid/ipc namespaces, /tmp instance
T4 Virtualize  microVM / Hyper-V / Virtualization.framework
```

**Axis 2 — capability grants.** *Which specific holes are punched?*

```
FsRead(path, depth)   FsWrite(path)    NetEgress(host:port)
Device(class)         Exec(binary)     Ipc(socket)         Unconfined(witness)
```

The rule that makes this work:

> **Lowering a tier never lowers observability.** Policy evaluation, violation
> attribution, and the audit log are produced by the *same* code path at every
> tier, including T0 and including a total `Unconfined` grant. You can always
> answer "what did it actually touch?"

So "I want to bypass everything for an easier flow" is expressed as a **maximal
grant set at a retained tier** — not as `--sandbox off`. The user gets their
frictionless flow; the system keeps the ledger. Nobody is ever "on their own".

`--yolo` is therefore not the absence of bastion. It is:

```
tier = T1, grants = { Unconfined(witness: "user ran --yolo at <ts>") }
```

Still audited. Still explainable. Still diffable against what the agent *would*
have been denied — which means a user can run wide-open for a week, then ask
bastion to synthesize the minimal policy that would have sufficed. Bypass becomes
the **on-ramp to a tight policy**, instead of its abandonment.

---

## 2. Finding: the symlink farm is a hole, not a workaround

The report's fix for the fixed-root problem is:

```sh
ln -s ~/work/myrepo ~/sandbox/myrepo
```

This is unsound under `bwrap`, for a reason that is easy to miss:

1. `bwrap` binds are resolved **on the host**, before the namespace is entered.
   A symlink inside the jail pointing to `~/work/myrepo` dangles unless the
   *target's real path* is also bound in.
2. Once the real path is bound to satisfy the link, the agent reaches it by its
   true name. The jail root stops being the boundary.
3. If the bind is a **parent** of the target (the common convenience), the agent
   traverses sideways into every sibling under it.
4. Writes through the link land on a path that the jail's own accounting believes
   is outside the sandbox, so violation attribution silently under-reports.

The pressure to do this comes entirely from choosing mount topology as the
enforcement mechanism. Which brings us to the actual technical fix.

### 2.1 Measured: symlinks break the *other* way on macOS

Measured on macOS 26.6.2 / arm64, Apple clang 21, via `sandbox_init(3)` (see
`tools/probe/seatbelt_probe.c`):

| Profile | `/private/etc/hosts` | `/etc/hosts` (symlink) | `/private/etc/passwd` |
|---|---|---|---|
| `(allow file-read* (literal "/private/etc/hosts"))` | OPEN | **EPERM** | EPERM |
| `+ (allow file-read-metadata)`, `subpath "/private/etc"` | OPEN | OPEN | OPEN |

Two hard rules fall out:

1. **Seatbelt evaluates the path as written, not just the canonical target.**
   `/etc` is a symlink to `private/etc`, so a rule naming the canonical path
   does *not* authorize access via the symlink — the traversal needs
   `file-read-metadata` on the link path itself. Every path entering a bastion
   profile is therefore canonicalized **and** its symlink ancestry authorized
   for metadata; a rule set built from un-canonicalized paths silently
   under-grants and the agent thrashes (§4).
2. **Symlinks are a portability trap in both directions.** Under `bwrap` a
   symlink farm silently *over*-grants (§2); under Seatbelt the same farm
   silently *under*-grants. A design that requires users to hand-maintain
   symlinks cannot be made to behave consistently across platforms. Path-set
   authority (§3) removes the need for the farm entirely.

Also confirmed: `sandbox_init` returns `rc=0` and enforces correctly on macOS
26.6.2 despite the `sandbox-exec(1)` CLI being marked deprecated. bastion links
the **API** (weak-linked, capability-probed at runtime) rather than shelling out
to the deprecated binary, which is what Anthropic's `srt` and Codex both do.

---

## 3. Fix: path-set authority instead of mount topology

`bwrap` and `firejail` answer the question *"what should the mount table look
like?"* An agent's requirement is *"which paths may be read and written?"*
Approximating a path set with a mount namespace is lossy, order-dependent, and
costly to rebuild — so implementors freeze one namespace and live in it.

**Landlock answers the path-set question directly.** No mount namespace, no
topology rewrite, no `setuid`, no privilege, operating on the real filesystem
in place. Consequences:

- **"Run in any working directory" is free.** The ruleset is derived from the
  actual CWD at spawn time. There is nothing to rebuild and nothing to freeze,
  so the fixed `$HOME/sandbox` and its symlink farm both disappear.
- Rights are attached to the opened path, not to a mount — no dangling-target
  class of bug (§2.1), and no sideways traversal from an over-broad bind.

Namespaces are retained, but demoted to **T3, for the jobs Landlock genuinely
cannot do**: network isolation, PID/IPC separation, and a per-session `/tmp`
instance. That is a much smaller, much more auditable use of `bwrap` than using
it to express the filesystem policy.

### 3.1 `firejail` is not a candidate for the default path

`firejail` ships **`setuid`-root**. CVE-2022-31214 (`join.c`, 0.9.68) is the
canonical illustration: a crafted container accepted as a join target yields an
environment still in the initial user namespace with `NO_NEW_PRIVS` unset —
local root. A sandbox whose *own* mechanism is a privilege-escalation surface
inverts the threat model we are here to improve.

`bwrap` is preferred wherever namespaces are needed, **non-setuid, on unprivileged
user namespaces**. The report's reluctant conclusion — "it's hard to think that
using bwrap is actually a bad choice" — is correct, and bastion narrows its
responsibility further.

---

## 4. The ergonomic floor is a security feature

> "the return of rw in `/tmp`. So most compiling errors will be gone and the LLMs
> will stop going around in circles"

This is the most underrated line in the report. A sandbox that breaks the
toolchain does not merely annoy — it makes the agent **thrash**, and thrashing
agents get their sandboxes switched off. Friction is the dominant cause of
real-world unconfinement, which makes ergonomics part of the security argument.

So a bastion profile carries **invariants that are asserted before the agent ever
runs**, not hoped for:

- writable `/tmp` (instanced at T3) with `TMPDIR` pointing into it
- writable, *persistent* toolchain caches — `CARGO_HOME`, `GOCACHE`,
  `GOMODCACHE`, `npm_config_cache`, `PIP_CACHE_DIR`, `CCACHE_DIR`, `ZIG_*`
- a coherent `PATH` where every entry is actually executable under the policy
- `/dev/null`, `/dev/urandom`, `/dev/zero`, a pty
- DNS reachability iff `NetEgress` is granted at all

`bastion doctor` runs these as a **preflight**, and refuses to hand a profile to
an agent while one is violated. Compare: the user had to discover a missing
writable `/tmp` empirically, over a day, via mysterious compiler failures.

### 4.1 Machine-readable denials replace AGENTS.md

> "I had a very detailed AGENTS.md which is no longer needed"

That file existed because the boundary was invisible to the model, so it had to
be narrated in prose — unverifiable, and stale the moment the policy changed.
Every bastion denial instead emits a structured record:

```json
{
  "verdict": "deny", "op": "fs.write", "path": "/etc/hosts",
  "tier": "T2", "rule": "default-deny",
  "remedy": { "grant": "FsWrite(/etc/hosts)", "cmd": "bastion grant fs.write /etc/hosts" },
  "sanctioned_alternative": "write under $WORKSPACE or $TMPDIR"
}
```

The agent is told what was refused, *why*, and what the legitimate move is —
in-band, at the moment of failure. Prose documentation of the sandbox becomes
unnecessary because the sandbox explains itself.

---

## 5. Why modern type-theoretic C++

The properties above want to be **compile-time** properties.

- **Capabilities are unforgeable tokens.** Move-only, non-copyable, no public
  constructor; only `Broker` can mint one. A function that needs write access
  takes `Cap<FsWrite>&&`. Authority becomes visible in the signature, and
  ambient authority stops being reachable by accident.
- **Attenuation is monotone by construction.** `derive()` accepts a target right
  set only if it is a subset of the parent's. **Widening is a compile error**, so
  privilege cannot creep along a call chain.
- **Typestate for the lifecycle.** `Policy → Sealed → Spawned` are distinct
  types, not an enum plus a flag. `add_rule()` does not exist on `Sealed`, which
  mirrors the kernel's own semantics (a Landlock ruleset is immutable once
  enforced) instead of re-checking it at runtime.
- **`Unconfined` requires a witness.** The bypass is a *type*, so it is greppable,
  reviewable, and impossible to reach without leaving a record — which is what
  makes §1's promise mechanically true rather than aspirational.

C++23/26 concepts, `consteval`, and deducing-`this` make this expressible with no
runtime cost, and C++ is the right host language for a layer that must sit
directly on `landlock_*`, `sandbox_init`, `CreateProcessAsUser`, and
`seccomp_unotify`.

---

## 6. Threat model, and what is actually verified

### 6.1 Measured: inherited file descriptors bypass the path policy

The most serious finding of the build so far, and the reason path-set authority
needs a spawn discipline rather than just a good profile.

On **both** Seatbelt and Landlock, access rights attach to the **open file
description**, not to the path. The Landlock docs state this outright. So a
descriptor opened *before* confinement keeps working *after* it, and survives
`exec`. Measured (`/tmp/fdraw.cpp`, reproduced in `tests/adversarial_test.cpp`
§5b):

```
parent opened fd=4 on /tmp/bastion-fd-secret.txt BEFORE confinement
confined.
  CHILD: read(4) succeeded -> FLAG{fd-inherited}
  ==> FD_LEAK: inherited descriptor bypasses path policy
```

The child was denied the path and still recovered the full contents. One leaked
descriptor voids the entire filesystem policy.

This is a live exposure for agent hosts specifically: they are exactly the
programs that hold config, credential, session and log files open while spawning
tools. `O_CLOEXEC` discipline in the host is not a sufficient answer, because a
sandbox that is only safe when every caller is careful is not a boundary.
`spawn()` therefore closes every descriptor above stderr in the child, between
`fork()` and confinement.

### 6.2 Verified with adversarial tests, not assertions

`tests/adversarial_test.cpp` runs 27 real escape attempts: **0 escapes**.

| Class | Attempts | Notable |
|---|---|---|
| Symlink escapes | 3 | link workspace → secret dir, → `/etc`, → `/` |
| Path traversal | 4 | `../`, `.././`, `//double//slash` |
| Sibling-prefix confusion | 1 | `/x/ws` must not authorize `/x/ws-secret` |
| Re-confinement / regain | 3 | copy `sh` into workspace and exec it; nested subshells |
| Credential theft | 6 | `~/.ssh`, `~/.aws`, keychain, history, `.gitconfig`, `.npmrc` |
| Inherited descriptors | 2 | raw `read(2)` and `/dev/fd/N` (§6.1) |
| Environment hygiene | 1 | `DYLD_INSERT_LIBRARIES` + `*_TOKEN` stripped |
| Persistence writes | 4 | `/etc`, `~/.zshrc`, `/usr/local/bin`, LaunchAgents |
| Workspace still usable | 4 | write, read, mkdir, rename |

The symlink cases are the field report's own workaround, run as an attack: under
`bwrap` a symlink farm over-grants, whereas path-set authority denies all three.

### 6.3 T3 closes the egress gap by composition

At T2 egress is all-or-nothing: Seatbelt matches sockets, Landlock matches
ports, neither matches hostnames. T3 fixes this by letting each layer do what it
is actually good at:

```
kernel : deny ALL egress except one loopback port   (unforgeable)
broker : accept there, enforce the host allowlist   (expressive)
```

The kernel half is what makes it a boundary rather than a politeness. Measured
(`tools/probe/egress_probe.c`):

| profile | `:8888` (broker) | `:9999` | `1.1.1.1:443` |
|---|---|---|---|
| `(deny default)` | EPERM | EPERM | EPERM |
| `+ (allow network-outbound (remote ip "localhost:8888"))` | **CONNECT** | EPERM | EPERM |
| `+ (allow network-outbound)` | refused | refused | CONNECTED |

Row 2 is T3. A compromised child cannot open its own socket, so it cannot route
around the allowlist — ignoring the `*_PROXY` variables yields no network at
all, not a bypass.

The broker enforces the allowlist on the **CONNECT authority**, then tunnels
bytes opaquely. bastion never terminates TLS: there is no CA to install, no
certificate trust to weaken, and no plaintext exposure. Refusals carry a remedy,
like filesystem denials do (§4.1):

```
bastion: egress REFUSED cloudflare.com:443
         remedy: bastion run --net cloudflare.com:443
```

Wildcards are supported (`*.example.com`) and deliberately do **not** match the
bare apex — granting `*.example.com` should not silently include
`example.com`. Host matching is case-insensitive, since DNS is.

### 6.4 Honest limits that remain

The suite asserts these as `LIMIT`, so the documented boundary can never drift
from the enforced one:

- **T2 egress is all-or-nothing.** Use `--tier t3`. Asserted as a limit at T2
  *and* asserted closed at T3, so the pair cannot silently diverge.
- **Host processes are visible.** macOS offers no unprivileged PID namespace, so
  `ps aux` works at T2 and T3 alike. That needs T4 (Virtualization.framework).
- **T0/T1 are not boundaries** against a motivated adversary, and say so.

---

## 7. Non-goals

- Not a container runtime; no image format, no registry, no OCI.
- Not a replacement for SELinux/AppArmor — bastion composes with them (Landlock
  is a *stackable* LSM) rather than competing.
- No `setuid` binary, ever.
- At T0/T1, no claim of enforcement against a motivated adversary. The tier name
  says so, and `bastion explain` prints the real boundary — the antidote to
  "the diff from bwrap to firejail is hair raising".
