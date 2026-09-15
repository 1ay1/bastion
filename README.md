# bastion

Cross-platform sandboxing for AI agents, in modern type-theoretic C++23.

**Status:** foundation layer. Capability algebra, tier model, and policy
evaluation are implemented and tested (6/6). Platform backends are specified
(`DESIGN.md`) and not yet wired.

## The problem this exists to fix

From a real field report by an Agentty user, after a day of fighting
`bwrap`/`firejail`:

> "I lost the flexibility of running Agentty in any working directory and now
> have a fixed `$HOME/sandbox` [...] if I have to work on a repo, I just quickly
> symlink the directory I need in there."

> "if you're paranoid of the AI doomsday, then turn `--sandbox off` and get
> either apparmor or selinux [...] **but you're on your own.**"

Both quotes describe the same root cause. Every shipping agent sandbox models
safety as a **scalar** — `off | workspace-write | read-only | full-access` — so
turning it down to get work done throws away the policy language, the audit
trail, and the diagnostics in one move. The user's only options are *fight the
jail* or *you're on your own*.

## The fix: the bypass is a capability, not a power switch

bastion splits that scalar into two independent axes:

**Enforcement tier** — how strong is the wall?

| Tier | Mechanism | Honest guarantee |
|---|---|---|
| T0 `observe` | none | Records what *would* be denied. Not a boundary. |
| T1 `advisory` | in-process | Stops accidents, not a motivated adversary. |
| T2 `kernel` | Landlock / Seatbelt / AppContainer | **Default.** Survives native code. |
| T3 `isolate` | T2 + namespaces, instanced `/tmp` | Unprivileged; no setuid component. |
| T4 `virtualize` | microVM / Hyper-V / VZ.framework | Separate kernel. |

**Capability grants** — which specific holes are punched? `FsRead`, `FsWrite`,
`NetEgress`, `Device`, `Exec`, `Ipc`, `Unconfined`.

The invariant that makes this work:

> **Lowering a tier never lowers observability.** Policy evaluation, violation
> attribution, and the audit log come from the *same* code path at every tier —
> including T0 and including a total `Unconfined` grant.

So "let me bypass everything for an easier flow" becomes a **maximal grant set at
a retained tier**, not `--sandbox off`:

```
--yolo  ==  tier T1, grants { Unconfined(witness: "user ran --yolo at <ts>") }
```

Frictionless for the user; the system still keeps the ledger. Nobody is ever
"on their own". Real output from the test suite:

```
$ bastion explain          # with --yolo active
tier:      T2:kernel
guarantee: Kernel-enforced path-set authority. Survives arbitrary native code.

!! UNCONFINED GRANT ACTIVE -- no access restriction is enforced.
   Auditing remains fully active; every operation is still
   recorded and attributed. Run `bastion synthesize` to turn this
   session's log into a minimal least-privilege policy.
   witness: UNCONFINED: user passed --yolo @main.cpp:59
```

Because a wide-open session is still fully recorded, **the bypass is the on-ramp
to a tight policy**: run unconfined for a week, then `bastion synthesize` the
minimal policy that would have sufficed.

## Run in any directory (no fixed `$HOME/sandbox`, no symlink farm)

`bwrap`/`firejail` answer *"what should the mount table look like?"* An agent
needs *"which paths may be read and written?"* Approximating a path set with
mount topology is lossy and expensive to rebuild — so implementors freeze one
namespace and live in it.

bastion uses **path-set authority** (Landlock on Linux, Seatbelt on macOS): the
ruleset is derived from the actual CWD at spawn time. Nothing to rebuild, nothing
to freeze. Namespaces are demoted to T3, for the jobs Landlock genuinely cannot
do (network/PID/IPC isolation, instanced `/tmp`).

The symlink farm isn't just unnecessary, it's **unsound in both directions** —
measured on this machine (`tools/probe/seatbelt_probe.c`):

| Seatbelt profile | `/private/etc/hosts` | `/etc/hosts` (symlink) |
|---|---|---|
| `(allow file-read* (literal "/private/etc/hosts"))` | OPEN | **EPERM** |

Under `bwrap` a symlink farm silently **over**-grants (binding the link target
exposes it by its real name, and siblings with it); under Seatbelt the same farm
silently **under**-grants. bastion canonicalizes every path *and* authorizes its
symlink ancestry. `firejail` is excluded from the default path entirely: it ships
`setuid`-root (cf. CVE-2022-31214), so its own mechanism is a privilege-escalation
surface.

## The ergonomic floor is a security feature

> "One aspect I found positive was the return of rw in `/tmp`. So most compiling
> errors will be gone and the LLMs will stop going around in circles."

A sandbox that breaks the toolchain makes agents **thrash**, and thrashing agents
get their sandboxes switched off. `bastion doctor` asserts these as a
**preflight** and refuses to hand a profile to an agent while one is violated:
writable `/tmp` + `TMPDIR`, persistent toolchain caches (`CARGO_HOME`, `GOCACHE`,
`npm_config_cache`, `CCACHE_DIR`, …), a coherent `PATH`, `/dev/null`+`urandom`,
a pty, and DNS iff egress is granted.

That user discovered a missing writable `/tmp` empirically, over a day, through
mysterious compiler failures.

### Denials replace `AGENTS.md`

> "I had a very detailed AGENTS.md which is no longer needed"

That file existed because the boundary was invisible to the model. Every bastion
denial is instead structured and in-band:

```json
{"verdict":"deny","op":"fs.write","target":"/etc/hosts","tier":"T2:kernel",
 "rule":"default-deny",
 "remedy":{"grant":"FsWrite(/etc/hosts)","cmd":"bastion grant fs.write /etc/hosts"},
 "sanctioned_alternative":"write under $WORKSPACE or $TMPDIR"}
```

The agent learns what was refused, why, and the legitimate move — at the moment
of failure. The sandbox explains itself, so prose documentation of it is dead
weight.

## Why type-theoretic C++

Capabilities are **move-only, unforgeable** tokens (no public ctor; only `Broker`
mints). Attenuation is **monotone by construction** — widening is a *compile
error*, so privilege cannot creep along a call chain. Lifecycle is
**typestate**: `Policy → Sealed → Spawned` are distinct types, and `allow()`
simply does not exist on `Sealed`, mirroring the kernel's own semantics (a
Landlock ruleset is immutable once enforced) instead of re-checking at runtime.

These claims are **verified, not asserted** — four negative cases must fail to
compile, enforced by `ctest`:

```
negative_compile_1 ... Passed   # widening read -> read|write
negative_compile_2 ... Passed   # read-only cap used where write required
negative_compile_3 ... Passed   # copying a capability
negative_compile_4 ... Passed   # laundering Unconfined in with normal rights
```

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
(cd build && ctest --output-on-failure)     # 6/6
```

## Non-goals

Not a container runtime (no images, no registry, no OCI). Not a replacement for
SELinux/AppArmor — Landlock is *stackable*, so bastion composes with them. **No
`setuid` binary, ever.** At T0/T1 there is no claim of enforcement against a
motivated adversary; the tier name says so and `bastion explain` prints the real
boundary.

See [`DESIGN.md`](DESIGN.md) for the full rationale and measurements.
