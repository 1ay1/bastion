# Architecture

How bastion is put together, and why each seam is where it is. Read this before
adding a backend or changing the policy layer.

For the *rationale* — why a tier/capability split at all — see `DESIGN.md`.
This document is about structure.

---

## 1. The pipeline

```
   Policy  ──seal()──►  Sealed  ──spawn()──►  running child
  (mutable)            (immutable)         (confined by a backend)
      │                    │                        │
      │                    ├─ evaluate() ───────► AuditRecord ──► Ledger
      │                    └─ explain()                              │
      │                                                        synthesize()
      └───────────────── Cap<R> grants authority ◄──────────────────┘
```

Three properties hold at every stage, and every change should preserve them:

1. **Authority is explicit.** A `Cap<R>` is move-only and unforgeable; only
   `Broker` mints one. Widening is a compile error.
2. **Policy is immutable once sealed.** `Sealed` has no `allow()`. This mirrors
   the kernel (a Landlock ruleset is immutable once enforced) instead of
   re-checking at runtime.
3. **Observation is tier-independent.** `evaluate()` produces the same record at
   T0 as at T3, including under a total `Unconfined` grant. This is what makes
   "the bypass is a capability, not a power switch" mechanically true.

---

## 2. Layers

| Layer | Files | Knows about |
|---|---|---|
| Capability algebra | `capability.hpp` | Nothing. Pure types. |
| Policy | `policy.hpp`, `policy.cpp` | Capabilities, tiers. **No OS.** |
| Tier / backend contract | `tier.hpp` | Policy. Declares what a backend must answer. |
| Backends | `backend/seatbelt.*`, `backend/landlock.*` | One OS each. Translate a `Sealed`. |
| Spawn | `spawn.cpp` | Backends, proxy. Owns process lifecycle. |
| Egress broker | `proxy.hpp/.cpp` | Sockets only. **Portable.** |
| Observation | `observe.cpp` | One OS each. Produces `AuditRecord`s. |
| Ledger / synthesis | `ledger.*` | `AuditRecord` only. **Portable.** |
| CLI | `cli.cpp` | All of the above. |

**The rule that keeps this honest:** a backend *translates* an already-sealed
policy; it never decides what to grant. If you need to edit `policy.hpp` for a
platform-specific reason, the abstraction is wrong — the platform detail belongs
in the backend.

Everything below `spawn` is portable. That is deliberate: the ledger,
synthesizer and closed-loop test are the same code on every platform, so a new
backend inherits them for free.

---

## 3. The capability type

```cpp
template <Right R> class Cap {
    Cap(const Cap&) = delete;              // unforgeable
    Cap(Cap&&) = default;                  // transferable
    template <Right Sub> Cap<Sub> derive() && {
        static_assert(subsumes(R, Sub), "may only narrow authority");
    }
};
```

Two subtleties worth knowing before you touch it:

**`Unconfined` is the lattice top.** `subsumes()` special-cases it to subsume
every right. Without that, the total-bypass capability paradoxically authorizes
nothing — bit 31 has no overlap with `FsRead`. Caught by `cap_test` on the first
run.

**Negative cases are enforced by CI.** `cmake/negative_compile.cmake` asserts
four programs *fail* to compile (widening, wrong-right use, copying, laundering
`Unconfined` into a normal grant set). A "this is a compile error" claim that
CI never checks is worthless.

---

## 4. Policy: path-set authority

`Policy::allow()` canonicalizes every path and, when the input differs from the
canonical form, adds a metadata rule for the as-written path. Both halves are
required — measured, `DESIGN.md` §2.1:

- macOS Seatbelt evaluates paths **as written**, so a rule naming
  `/private/etc/hosts` returns `EPERM` when opened via `/etc/hosts`.
- `evaluate()` canonicalizes its *target* too, or a canonical rule never matches
  a raw target (`/tmp` → `/private/tmp`).

**Builder methods return by value, not `Policy&&`.** Returning an rvalue
reference makes the natural non-chained form a self-move-assignment:

```cpp
p = std::move(p).allow(...);   // silently empties the policy
```

That shipped once. It looked valid, denied everything, and printed `rules (0)`;
only the live CLI demo caught it. `policy_test` now covers both styles.

---

## 5. Backend contract

A backend answers three questions:

```cpp
BackendCaps probe();                              // what can this MACHINE do?
CompileResult compile(const Sealed&, uint16_t);   // translate (+ T3 proxy port)
std::string apply(const Sealed&, uint16_t);       // enforce, irreversibly
```

Rules for any new backend:

- **Probe at runtime, never infer from build flags.** A kernel may lack Landlock
  where the headers exist. `probe()` reports what is live.
- **Report what you cannot enforce** in `warnings`. `bastion explain` prints
  them. Silence about a limit is the failure mode this project exists to fix.
- **Never silently downgrade.** If the policy asks for more than `max_tier`,
  `spawn` refuses. A sandbox that quietly weakens is worse than one that stops,
  because the user still believes they are protected.
- **Fail closed.** Compilation error, missing kernel support, failed `apply` —
  all must prevent `exec`, never permit an unconfined run.

### `max_tier` is a claim you must be able to defend

Seatbelt reports `T3` because brokered egress works — but **not** namespace
isolation, which macOS does not offer unprivileged. Landlock reports `T3` only
at ABI v4+, and `T2` below. When you extend a tier, update `probe()` in the same
commit: after T3 landed, the CLI refused every `--tier t3` run until `probe()`
was corrected.

---

## 6. Spawn: the ordering is the security

```
fork()
  ├─ chdir()                 cwd must be reachable, and granted
  ├─ join cgroup             child writes its OWN pid: race-free
  ├─ setrlimit()             ceilings bound the sandbox setup too
  ├─ setpgid(0,0)            own process group → T0 attribution
  ├─ close_inherited_fds()   MEASURED escape (below)
  ├─ enter_namespaces()      T3 only; before Landlock, which freezes mounts
  ├─ apply_compiled()        irreversible; failure ⇒ _exit(126)
  └─ execve()
```

Confinement must land **after** `fork` (applying it in the parent would confine
bastion itself) and **before** `exec` (afterwards is impossible). If `apply`
fails the child `_exit`s with a distinguished code rather than exec'ing — a
failed sandbox must never degrade to no sandbox.

### Async-signal-safety is a type, not a comment

Everything in that child block runs between `fork()` and `execve()`, where only
async-signal-safe calls are legal. If another thread held the malloc lock at the
instant of `fork`, that lock is held **forever** in the child, so the first
allocation deadlocks — the child hangs with the sandbox unapplied and the
workload never exec'd. Silent, unkillable, and in the one path that must never
fail open.

This is not theoretical here: at T3 the egress broker's accept thread is already
running when bastion forks. **bastion forks from a multithreaded process.**

The rule used to be a comment — *"only async-signal-safe calls past this
point"* — and that comment was already wrong: the child called
`linux_ll::apply()`, which builds `std::string`s. Nothing checked, so the bug
would have surfaced as an intermittent hang under load, not a test failure.

So fork-safety is now enforced the same way privilege is (§3): make the unsafe
program *ill-formed*.

```cpp
// include/bastion/forksafe.hpp
template <class T>
concept ForkSafe = std::is_trivially_copyable_v<std::remove_cvref_t<T>>;

[[nodiscard]] bool apply_compiled(ForkChild tok, const Ruleset&,
                                  const AbiCore&, const char** err) noexcept;
```

- `ForkChild` is **unforgeable** (private constructor, one friend), exactly like
  `Cap<R>`. Only the code that forks can mint one, so a post-fork-only API
  cannot be called from ordinary code by accident.
- `AbiInfo` was **split**. It carried a `std::string note`, so passing it to the
  child was an allocation waiting to happen; the trivially-copyable `AbiCore`
  crosses the boundary and the string stays in the parent. The compiler found
  this — it was not noticed by review.
- The `Ruleset` is compiled in the **parent** and only *read* in the child. A
  `const char*` into parent memory is fork-safe (it is copy-on-write); building
  a new `std::string` is not.

Five negative-compile tests assert each unsafe shape is rejected, including the
exact shape of the original bug. As with the capability tests: a "this is a
compile error" claim is worthless unless something verifies that it really is.

The type system cannot see *every* allocation — nothing short of a custom
allocator could. What it gives is a machine-checked contract at the boundary,
which turns the most dangerous case (passing a string-shaped thing into
post-fork code) from a review question into a compiler error.

### Two more invariants held by types

The same reasoning applies wherever a comment was carrying a safety property.

**`Result<T>` — a failure you cannot ignore.** The old shape was
`struct { bool ok; std::string error; ... }`, which admits four states, two of
them lies: *succeeded but carries an error*, and *failed but says nothing*.
Worse, `to_sealed()` accepted a `PolicyFile` whose `ok` was `false`, so one
forgotten `if` turned a **malformed policy file into a live policy**. Now
`parse_policy` returns `Result<PolicyFile>`, the value and the error share one
slot, and `PolicyFile` has no `ok` field at all — a `PolicyFile` that exists is
one that parsed. The bug is no longer expressible:

```cpp
auto pf = parse_policy(text);
auto sealed = to_sealed(pf);   // error: cannot convert Result<PolicyFile>
                               //        to const PolicyFile&
```

**`UniqueFd` — a descriptor with exactly one owner.** Descriptors are not just
a resource here: rights attach to the *open file description*, so a leaked fd is
authority that outlives its scope (this is the mechanism behind the measured
inherited-fd escape). bastion closed fds by hand in ~47 places, and an audit
found a real leak on the macOS status-pipe path — `pipe()` succeeds, `fcntl()`
fails, both ends leak on the early return. `UniqueFd` closes exactly once on
every path including early returns; copying is deleted, so double-close and
two-owners are unrepresentable. `close(2)` is async-signal-safe, so it is
legal in the post-fork child too.

Ten negative-compile tests cover the two types (unused `Result`, implicit
unwrap, copying a descriptor, adopting a raw `int` implicitly, and the five
fork-safety shapes).

**`close_inherited_fds()` closes a real escape.** On both Seatbelt and Landlock,
access rights attach to the *open file description*, not the path. A descriptor
opened before confinement keeps working after it and survives `exec`:

```
parent opened fd=4 on secret.txt BEFORE confinement
confined.
  CHILD: read(4) succeeded -> FLAG{fd-inherited}
```

The child was denied the path and still read the file. Agent hosts are exactly
the programs holding credentials and logs open while spawning tools, so this is
live, not theoretical. Relying on callers to set `O_CLOEXEC` is not acceptable:
a sandbox that is only safe when every caller is careful is not a boundary.

`choose_cwd()` picks a directory the child can actually read. Without it every
shell prints `shell-init: error retrieving current directory` — 26 lines in one
early test run. Cosmetic-looking, but it is the "sandbox breaks the toolchain →
agent thrashes → user disables sandbox" chain that `DESIGN.md` §4 is about.

---

## 7. T3: enforcement by composition

Neither kernel can filter egress by hostname — Seatbelt matches sockets,
Landlock matches ports. T3 splits the job:

```
kernel : deny ALL egress except one loopback port   (unforgeable)
broker : accept there, enforce the host allowlist   (expressive)
```

Measured on macOS (`tools/probe/egress_probe.c`):

| profile | `:8888` (broker) | `:9999` | `1.1.1.1:443` |
|---|---|---|---|
| `(deny default)` | EPERM | EPERM | EPERM |
| `+ allow outbound to `localhost:8888`` | **CONNECT** | EPERM | EPERM |
| `+ allow outbound` (blanket) | refused | refused | CONNECTED |

Row 2 is the design. A compromised child cannot open its own socket, so ignoring
the `*_PROXY` variables yields *no network* rather than a bypass.

**`spawn` owns the broker.** Passing one in is deliberately unsupported: the
port the child is authorized to reach and the port the broker listens on must be
equal by construction. An early test started its own proxy and asserted on its
counters, which stayed `0/0` while the child used spawn's proxy on a different
port — it passed for the wrong reason.

The broker enforces on the CONNECT authority and tunnels bytes opaquely. TLS is
never terminated: no CA to install, no trust weakened, no plaintext.

---

## 8. Observation and synthesis

```
observe()  ──►  AuditRecord[]  ──►  Ledger (JSONL)  ──►  synthesize()  ──►  Policy
```

`observe()` is the only platform-specific part; everything downstream is shared.
On macOS it uses Seatbelt's `(allow default (with report))` plus the unified
log — unprivileged, kernel-canonical paths. Linux has no equivalent yet
(`docs/linux-bringup.md` §5.4).

Two invariants in `synthesize()` that exist because they were violated:

- **A denied operation never becomes a grant.** Otherwise synthesis hands over
  exactly what the sandbox stopped.
- **Floor-covered accesses are filtered, and `/` is never granted.** dyld
  legitimately reads the root directory; emitting `fs.read /` would hand over
  the whole filesystem inside a policy sold as least-privilege. 82 raw records
  become 4 reviewable grants.

With no evidence, `synthesize` refuses to emit a policy and says why. It
previously printed "no grants needed" for a workload that had demonstrably read
`/etc/hosts` and written `/tmp` — a confident wrong answer, worse than none.

`tests/closed_loop_test.cpp` is what makes the feature real: observe →
synthesize → **re-run under the derived policy** → must succeed, while
never-touched paths stay denied.

---

## 9. Testing philosophy

| Suite | Asserts |
|---|---|
| `cap` + `negative_compile_1..4` | Type-level claims, including 4 that must NOT compile |
| `policy` | Evaluation, canonicalization, builder regression |
| `live_enforcement` | Real processes, real kernel denials |
| `adversarial` | 29 escape attempts; a failure here is an escape |
| `closed_loop` | Synthesized policies actually run |
| `egress` | T3 both halves: allowlist *and* kernel pin |
| `landlock_uapi` | Linux UAPI usage + spawn wiring, from macOS |

Two habits worth keeping:

**Limits are asserted as limits.** `ps aux` works at T2/T3 on macOS (no
unprivileged PID namespace), so the suite asserts it *as a known limit*. If it
ever tightens, the test flips and the docs get corrected. Documented boundaries
cannot drift from enforced ones.

**Test the output, not the code.** Every serious bug in this project was found
by running the thing and reading what came out: the hollow synthesizer, the
self-move-assignment, the proxy port mismatch, the fd escape. Unit tests on
their own would have missed all four.

---

## 10. Adding a backend

1. Implement `probe()` / `compile()` / `apply()` in `src/backend/<os>.cpp`.
2. Add the source to `CMakeLists.txt` under the platform branch.
3. Add a `#elif defined(__<os>__)` branch in `spawn.cpp` — apply between
   `fork` and `exec`, `_exit(126)` on failure.
4. Extend `cli.cpp`'s `active_backend()`.
5. Run the adversarial suite with the platform gate removed. It is the
   acceptance test.
6. If the platform can observe accesses, implement `observe()` — the ledger,
   synthesizer and closed-loop test then work unchanged.

Windows is the open one: AppContainer + a restricted token for T2, WFP or the
existing broker for T3 egress. `DESIGN.md` §1 has the sketch.
