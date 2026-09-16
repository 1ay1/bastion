# bastion

Cross-platform sandboxing for AI agents, in modern type-theoretic C++23.

**The bypass is a capability, not a power switch.**

```sh
bastion run -- cargo test                     # tight, in whatever dir you're in
bastion run -t t3 --net '*.pypi.org:443' -- pip install -r reqs.txt
bastion observe -- ./legacy-build.sh          # don't know what it needs? watch it
bastion synthesize > bastion.toml             # then lock it down, from evidence
bastion run --policy bastion.toml -- ./legacy-build.sh
```

| | |
|---|---|
| **macOS** | Working. T2 + T3, 13/13 tests, 29 adversarial escape attempts, 0 escapes. |
| **Linux** | Working, and the most complete backend. T0–T3 **measured on kernel 7.2.2 (Landlock ABI v10)**: 21/21 tests, 30 adversarial escape attempts, **0 escapes and 0 documented limits**. Observation is unprivileged (seccomp user-notification) and PID/IPC isolation is real. See [`docs/linux-bringup.md`](docs/linux-bringup.md). |
| **Windows** | Specified only (AppContainer + restricted token). |

**Docs:** [CLI](docs/cli.md) · [Architecture](docs/architecture.md) ·
[Security model](docs/security-model.md) · [Linux bring-up](docs/linux-bringup.md) ·
[Design rationale](DESIGN.md)

---

## The problem

From a field report by an Agentty user, after a day fighting `bwrap`/`firejail`:

> "I lost the flexibility of running Agentty in any working directory and now
> have a fixed `$HOME/sandbox` [...] if I have to work on a repo, I just quickly
> symlink the directory I need in there."

> "if you're paranoid of the AI doomsday, then turn `--sandbox off` and get
> either apparmor or selinux [...] **but you're on your own.**"

Both quotes have one root cause. Every shipping agent sandbox models safety as a
**scalar** — `off | workspace-write | read-only | full-access` — so turning it
down to get work done throws away the policy language, the audit trail and the
diagnostics in one move. The only options are *fight the jail* or *fly blind*.

## The fix: two axes, not one

**Enforcement tier** — how strong is the wall?

| Tier | Mechanism | Honest guarantee |
|---|---|---|
| T0 `observe` | none | Records what *would* be denied. Not a boundary. |
| T1 `advisory` | in-process | Stops accidents, not a motivated adversary. |
| T2 `kernel` | Landlock / Seatbelt | **Default.** Survives arbitrary native code. |
| T3 `isolate` | T2 + brokered egress | Real per-host network allowlisting. |
| T4 `virtualize` | microVM | Separate kernel. Not implemented. |

**Capability grants** — which specific holes are punched? `FsRead`, `FsWrite`,
`NetEgress`, `Device`, `Exec`, `Ipc`, `Unconfined`.

The invariant that makes it work:

> **Lowering a tier never lowers observability.** Policy evaluation, violation
> attribution and the audit log come from the *same* code path at every tier —
> including T0 and including a total `Unconfined` grant.

So "let me bypass everything" becomes a **maximal grant at a retained tier**:

```
--yolo  ==  tier T1, grants { Unconfined(witness: "user ran --yolo at <ts>") }
```

Frictionless for the user; the system still keeps the ledger. Nobody is ever
"on their own":

```
$ bastion explain --yolo
!! UNCONFINED GRANT ACTIVE -- no access restriction is enforced.
   Auditing remains fully active; every operation is still recorded and
   attributed. Run `bastion synthesize` to turn this session's log into a
   minimal least-privilege policy.
   witness: UNCONFINED: user passed --yolo @main.cpp:59
```

Because a wide-open run is still fully recorded, **the bypass is the on-ramp to
a tight policy** — and the loop closes for real, not just in a test:

```sh
bastion observe -- ./build.sh             # nothing enforced, everything recorded
bastion synthesize > bastion.toml         # review it, commit it
bastion run --policy bastion.toml -- ./build.sh
```

CI proves it end to end: observe → synthesize → **re-run under the derived
policy** → it must succeed, while paths it never touched stay denied.

## Run in any directory

`bwrap`/`firejail` answer *"what should the mount table look like?"* An agent
needs *"which paths may be read and written?"* Approximating a path set with
mount topology is lossy and expensive to rebuild — so implementors freeze one
namespace and live in it.

bastion uses **path-set authority** (Landlock on Linux, Seatbelt on macOS): the
ruleset comes from the actual CWD at spawn time. Nothing to rebuild, nothing to
freeze, no symlink farm.

That farm isn't merely unnecessary, it's **unsound in both directions** —
measured:

| Seatbelt profile | `/private/etc/hosts` | `/etc/hosts` (symlink) |
|---|---|---|
| `(allow file-read* (literal "/private/etc/hosts"))` | OPEN | **EPERM** |

Under `bwrap` a symlink farm silently **over**-grants; under Seatbelt the same
farm silently **under**-grants. `firejail` is excluded from the default path
entirely: it ships `setuid`-root (cf. CVE-2022-31214), so its own mechanism is a
privilege-escalation surface.

## The ergonomic floor is a security feature

> "the return of rw in `/tmp`. So most compiling errors will be gone and the
> LLMs will stop going around in circles"

A sandbox that breaks the toolchain makes agents **thrash**, and thrashing
agents get their sandboxes switched off. `bastion doctor` asserts the floor as a
**preflight** — writable `$TMPDIR`, persistent toolchain caches, a coherent
`PATH`, `/dev/null`, DNS iff egress is granted — and refuses to hand over a
profile while one is violated.

That user discovered a missing writable `/tmp` empirically, over a day, through
mysterious compiler failures.

Every denial is structured and in-band, which is why an `AGENTS.md` describing
the sandbox is dead weight — the sandbox explains itself:

```json
{"verdict":"deny","op":"fs.write","target":"/etc/hosts","tier":"T2:kernel",
 "remedy":{"cmd":"bastion run -w /etc/hosts -- <cmd>"},
 "sanctioned_alternative":"write under $WORKSPACE or $TMPDIR"}
```

## Why type-theoretic C++

Capabilities are **move-only, unforgeable** tokens (no public ctor; only
`Broker` mints). Attenuation is **monotone by construction** — widening is a
*compile error*, so privilege cannot creep along a call chain. Lifecycle is
**typestate**: `Policy → Sealed → Spawned` are distinct types, and `allow()`
does not exist on `Sealed`, mirroring the kernel's own semantics.

Verified, not asserted — four negative cases must **fail to compile**, enforced
by `ctest`:

```
negative_compile_1 ... Passed   # widening read -> read|write
negative_compile_2 ... Passed   # read-only cap used where write required
negative_compile_3 ... Passed   # copying a capability
negative_compile_4 ... Passed   # laundering Unconfined in with normal rights
```

## Verified, not asserted

**29 real escape attempts, 0 escapes** — symlink farms pointed at `/etc` and
`/`, `../` traversal, sibling-prefix confusion, copying `sh` into the workspace
to shed policy, `~/.ssh` + `~/.aws` + keychain + shell history,
`DYLD_INSERT_LIBRARIES` injection, LaunchAgent persistence, T3 proxy bypass.

**The escape this found:** on both Seatbelt and Landlock, access rights attach to
the **open file description**, not the path. A descriptor opened *before*
confinement keeps working *after* it and survives `exec`:

```
parent opened fd=4 on secret.txt BEFORE confinement
confined.
  CHILD: read(4) succeeded -> FLAG{fd-inherited}
```

The child was denied the path and still read the file in full. `spawn()` now
closes every fd above stderr before confining — a sandbox that is only safe when
every caller remembers `O_CLOEXEC` is not a boundary. Full list in
[`docs/security-model.md`](docs/security-model.md) §4.

**Limits are asserted as limits**, so the documented boundary can't drift from
the enforced one: `ps aux` works at T2/T3 (no unprivileged PID namespace on
macOS), and T2 egress is all-or-nothing — asserted at T2 *and* asserted closed
at T3.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
(cd build && ctest --output-on-failure)     # 21/21

./build/bastion doctor
```

Needs C++23 (GCC 13+ / Clang 17+) and CMake 3.24+. On Linux, start with
[`docs/linux-bringup.md`](docs/linux-bringup.md).

## Non-goals

Not a container runtime (no images, no registry, no OCI). Not a replacement for
SELinux/AppArmor — Landlock is *stackable*, so bastion composes with them. **No
`setuid` binary, ever.** At T0/T1 there is no claim of enforcement against a
motivated adversary; the tier says so and `bastion explain` prints the real
boundary.
