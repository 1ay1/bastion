# bastion

Cross-platform sandboxing for AI agents, in modern type-theoretic C++23.

**Status:** working sandbox on macOS. Capability algebra, tier model, policy
evaluation, Seatbelt (T2) enforcement, T3 brokered per-host egress, spawn, T0
kernel observation, audit ledger, synthesizer and CLI are implemented and tested
(12/12, incl. 29 adversarial escape attempts and a closed
observe→synthesize→enforce loop). The Landlock (T2/Linux) backend is written
with ABI v1..v10 probing and its UAPI usage is typechecked in CI, but is **not
yet run on a live kernel**. Windows AppContainer and T4 are specified only
(`DESIGN.md`).

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
to a tight policy**. And you don't have to guess what a workload needs — watch it:

```sh
$ bastion observe -- ./weird-legacy-build.sh
bastion: T0 OBSERVE via seatbelt-report+unified-log — nothing is enforced,
         every access is recorded. Ctrl-C is safe.
bastion: recorded 62 access(es)
         next: bastion synthesize

$ bastion synthesize
# Synthesized by `bastion synthesize` from 62 observed operation(s).
# 48 access(es) omitted: already covered by the ergonomic floor
# (dyld, locale data, /bin, /dev/null, traversal metadata, ...).
tier = "T2"

[[allow]]
op    = "fs.read"
path  = "/private/etc/hosts"
...
```

On macOS this is real kernel observation, unprivileged: Seatbelt's
`(allow default (with report))` makes the kernel emit an audit record per access
decision, which bastion reads back from the unified log. No root, no `fs_usage`,
no `dtrace` — both of those need privileges a sandbox has no business asking for.

**The loop is closed, and CI proves it** (`tests/closed_loop_test.cpp`): observe a
workload → synthesize → **re-run under the derived policy** → it must succeed,
while paths it never touched stay denied. A synthesizer whose output is never
executed is just a plausible-looking text generator.

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

These claims are **verified, not asserted** — see below.

## Verified, not asserted

Security claims are worth nothing unless CI checks them. `ctest` runs **12
suites**, all green on macOS 26.6.2 / arm64 / Apple clang 21.

**29 real escape attempts, 0 escapes** (`tests/adversarial_test.cpp`) — symlink
farms pointed at `/etc` and `/`, `../` traversal, sibling-prefix confusion,
copying `sh` into the workspace to shed policy, `~/.ssh` + `~/.aws` + keychain +
shell history, `DYLD_INSERT_LIBRARIES` injection, LaunchAgent persistence.

The three symlink cases are the field report's own workaround, run as an attack.
Under `bwrap` a symlink farm over-grants; path-set authority denies all three.

### The escape this found

On **both** Seatbelt and Landlock, access rights attach to the **open file
description**, not the path. So a descriptor opened *before* confinement keeps
working *after* it and survives `exec`:

```
parent opened fd=4 on /tmp/bastion-fd-secret.txt BEFORE confinement
confined.
  CHILD: read(4) succeeded -> FLAG{fd-inherited}
  ==> FD_LEAK: inherited descriptor bypasses path policy
```

The child was denied the path and still read the file in full. One leaked
descriptor voids the whole filesystem policy — and agent hosts are exactly the
programs that hold credentials and logs open while spawning tools. `spawn()` now
closes every fd above stderr in the child before confining; `O_CLOEXEC`
discipline in the caller is not an acceptable answer, because a sandbox that is
only safe when every caller is careful is not a boundary.

### Type-level claims: 4 negative cases must FAIL to compile

```
negative_compile_1 ... Passed   # widening read -> read|write
negative_compile_2 ... Passed   # read-only cap used where write required
negative_compile_3 ... Passed   # copying a capability
negative_compile_4 ... Passed   # laundering Unconfined in with normal rights
```

### Honest limits (asserted as limits, so docs can't drift)

- **T2 egress is all-or-nothing** — use `--tier t3` (below). The limit is
  asserted at T2 *and* asserted closed at T3, so the two can't diverge.
- **Host processes are visible.** macOS has no unprivileged PID namespace, so
  `ps aux` works at T2/T3. Needs T4.
- **T0/T1 are not boundaries** against a motivated adversary, and say so.

## T3: per-host network allowlisting

No kernel can filter egress by hostname — Seatbelt matches sockets, Landlock
matches ports. T3 composes the two layers so each does what it's good at:

```
kernel : deny ALL egress except one loopback port   (unforgeable)
broker : accept there, enforce the host allowlist   (expressive)
```

```sh
$ bastion run -t t3 --net example.com:443 -- curl -s https://example.com
HTTP 200
bastion: T3 egress broker on 127.0.0.1:56653 — direct outbound is kernel-denied.

$ bastion run -t t3 --net example.com:443 -- curl -sS https://cloudflare.com
curl: (56) CONNECT tunnel failed, response 403
bastion: egress REFUSED cloudflare.com:443
         remedy: bastion run --net cloudflare.com:443
```

The kernel half is what makes this a boundary and not a politeness — measured:

| profile | `:8888` (broker) | `:9999` | `1.1.1.1:443` |
|---|---|---|---|
| `(deny default)` | EPERM | EPERM | EPERM |
| `+ (allow network-outbound (remote ip "localhost:8888"))` | **CONNECT** | EPERM | EPERM |
| `+ (allow network-outbound)` | refused | refused | CONNECTED |

A compromised child can't open its own socket, so ignoring the `*_PROXY`
variables gets it *no network*, not a bypass. The adversarial suite proves both
halves: non-allowlisted host refused, and raw `nc` to `1.1.1.1:443` kernel-denied.

bastion enforces on the **CONNECT authority** and tunnels bytes opaquely — TLS
is never terminated, so there's no CA to install and no plaintext exposure.
Wildcards (`*.example.com`) work and deliberately don't match the bare apex.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
(cd build && ctest --output-on-failure)     # 12/12

./tools/demo.sh                            # end-to-end CLI walkthrough
```

## Try it

```sh
# Tight, in whatever directory you're already in:
bastion run -- cargo test

# Don't know what it needs? Watch it, then lock it down from evidence:
bastion observe -- ./weird-legacy-build.sh
bastion synthesize > bastion.toml

# See the REAL boundary, including what the backend can't enforce:
bastion explain -w . --net api.example.com:443

# Check the ergonomic floor before an agent hits it the hard way:
bastion doctor

# Wide open because you're in a hurry -- still fully recorded:
bastion run --yolo -- ./weird-legacy-build.sh
```

## Non-goals

Not a container runtime (no images, no registry, no OCI). Not a replacement for
SELinux/AppArmor — Landlock is *stackable*, so bastion composes with them. **No
`setuid` binary, ever.** At T0/T1 there is no claim of enforcement against a
motivated adversary; the tier name says so and `bastion explain` prints the real
boundary.

See [`DESIGN.md`](DESIGN.md) for the full rationale and measurements.
