# Linux bring-up

Everything you need to get bastion enforcing on Linux.

**STATUS: the Landlock backend now runs, enforces, and passes its full suite on
a real kernel.** First bring-up measured on **kernel 7.2.2-zen1 (Landlock ABI
v10), GCC 16.2.1**: 13/13 tests green, adversarial suite 30 attempts / 0
escapes, T3 per-host egress verified end to end against a live host.

Five real bugs were found the moment it touched hardware; all are fixed, and
each is recorded as a MEASURED comment at the site so it cannot silently
regress:

| # | Bug | Symptom | Fix |
|---|---|---|---|
| 1 | `std::exchange` used without `<utility>` | build failed on GCC 16 | added the include (`src/proxy.cpp`) |
| 2 | directory-only rights sent for regular files | `add_rule` EINVAL on `/etc/ld.so.cache` → **every confined spawn failed closed** | strip `kDirOnlyRights` per-inode in `apply()` |
| 3 | `#if defined(LANDLOCK_RULE_NET_PORT)` — an *enumerator*, never a macro | whole net-rule loop compiled out: all egress denied **including the T3 broker**, so T3 was unusable while looking enforced | guard on `LANDLOCK_ACCESS_NET_CONNECT_TCP` (a real `#define`) |
| 4 | setup failure inferred from exit code | a shell's own 126/127 ("permission denied") was reported as "bastion failed to apply the policy" — a correctly BLOCKED attack looked like an escape | CLOEXEC status pipe carries the real stage (`src/spawn.cpp`) |
| 5 | ergonomic floor missing TLS/DNS/tmp | `curl` failed with "error adding trust anchors"; `cc` failed with "cannot create temporary file" | floor grants trust store, resolver config, and a **private per-run tmp dir** |

Bug 3 is the one to remember: it is the failure mode a security tool is worst
at noticing, because *more* was denied than intended. Nothing escaped, so no
test that only asks "did anything get out?" would ever have caught it. It was
found by asking the opposite question — does the thing that should be allowed
actually work?

On bug 5, note what was NOT done: the obvious fix is to grant `/tmp`, and that
is wrong. `/tmp` is world-readable, so a blanket grant leaks data between
agents on the same box — measured immediately as **6 new escapes** in the
adversarial suite. Linux usually leaves `$TMPDIR` unset (macOS does not), so
bastion mints a private 0700 per-run directory and points `TMPDIR`/`TMP`/`TEMP`
at it, removing it at exit.

§6 is the checklist. Numbers below labelled *expected* are still unverified on
other kernels — especially older ABI levels, which this box cannot exercise.

---

## 0. Verified on this kernel

```
$ uname -r
7.2.2-zen1-1-zen
$ cat /sys/kernel/security/lsm
capability,landlock,lockdown,yama,bpf
$ bastion doctor
backend:     landlock
note:        Landlock ABI v10
max tier:    T3:isolate
path authority:   yes
net filtering:    yes (by port)
$ ctest
100% tests passed out of 13
```

Still open on Linux: `bastion observe` has no backend (needs Landlock audit,
ABI v7+/kernel 6.15, or an eBPF collector), so `synthesize` has no evidence
source here — it correctly refuses to emit a policy rather than guessing. T4
(namespaces/microVM) is unimplemented, and `probe()` reports
`namespace isolation: no` accordingly.

---

## 1. Requirements

| Thing | Minimum | Why |
|---|---|---|
| Kernel | **5.13** | Landlock ABI v1. Below this there is no T2 at all. |
| Kernel | **5.19** recommended | ABI v2 = `FS_REFER`; below it, cross-directory `rename`/`link` is *always* denied and some builds break (§5.1). |
| Kernel | **6.7** for T3 | ABI v4 = network rules. Without it bastion refuses `--tier t3` rather than pretending (§4). |
| LSM enabled | `CONFIG_SECURITY_LANDLOCK=y` **and** `landlock` in `lsm=` | Compiled-in but not enabled is the most common failure. |
| Compiler | GCC 13+ / Clang 17+ | C++23: `std::to_underlying`, deducing-`this`, `<source_location>`. |
| CMake | 3.24+ | |
| Headers | `linux/landlock.h` | From `linux-libc-dev` / `kernel-headers`. Absent ⇒ backend compiles to a stub that always fails closed. |

Check in one line:

```sh
uname -r
grep -c landlock /sys/kernel/security/lsm 2>/dev/null || echo "securityfs not mounted"
ls /usr/include/linux/landlock.h 2>/dev/null || echo "MISSING kernel headers"
```

`bastion doctor` reports all of this once built, including the live ABI version.

### If Landlock is absent

`CONFIG_SECURITY_LANDLOCK=y` alone is not enough on many distros — the LSM also
has to be **activated at boot**. Add to the kernel command line:

```
lsm=landlock,lockdown,yama,integrity,apparmor
```

Keep whatever your distro already lists; just prepend `landlock`. Then:

```sh
dmesg | grep landlock          # expect: "landlock: Up and running"
```

Ubuntu 22.04+, Fedora 35+ and Arch ship it enabled. Debian 12 ships it compiled
but **not** in the default `lsm=` list.

---

## 2. Build and first run

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
(cd build && ctest --output-on-failure)

./build/bastion doctor
```

`doctor` is the first thing to run and the first thing to report if it looks
wrong. Expected shape on a healthy 6.7+ box:

```
backend:     landlock
note:        Landlock ABI v4
max tier:    T3:isolate
path authority:   yes
net filtering:    yes (by port)
requires setuid:  no
```

Then the smallest real test:

```sh
mkdir -p /tmp/ws && cd /tmp/ws
../../build/bastion run -- sh -c 'echo hi > ok.txt && cat ok.txt'   # must WORK
../../build/bastion run -- sh -c 'cat /etc/shadow'                  # must FAIL
```

---

## 3. What is implemented, and what is a stub

Be precise about this before debugging: several gaps are *by design* and are not
bugs to chase.

| Capability | Linux status |
|---|---|
| T2 filesystem (path-set authority) | **Implemented**, unverified on hardware |
| T2 `fs.exec` | Implemented (`LANDLOCK_ACCESS_FS_EXECUTE`) |
| T3 brokered per-host egress | **Implemented**, needs ABI v4+; the broker itself is portable and already tested on macOS |
| ABI clamping v1..v10 | Implemented, typechecked |
| Fail-closed on missing Landlock | Implemented |
| `NO_NEW_PRIVS` | Implemented (Landlock requires it; it also blocks setuid escalation) |
| Inherited-fd closing | Implemented, platform-independent |
| **T0 observation** | **NOT implemented.** `observe_probe()` returns unavailable, so `bastion observe` and therefore `synthesize` do not work on Linux. See §5.4 — this is the biggest gap. |
| T3 namespaces (PID/IPC/mount, instanced `/tmp`) | **Not implemented** on any platform. T3 currently means *brokered egress only*. |
| T4 virtualize | Not implemented |

---

## 4. Tier semantics on Linux

`bastion` refuses to run when the requested tier exceeds what the backend can
deliver, rather than silently downgrading — a sandbox that quietly becomes
weaker than requested is worse than one that refuses, because the user still
believes they are protected.

| Kernel | ABI | `max_tier` | Notes |
|---|---|---|---|
| < 5.13 | — | T1 advisory | No Landlock. `--tier t2` is **refused**. |
| 5.13–5.18 | v1 | T2 | No `FS_REFER` ⇒ cross-dir rename/link always denied (§5.1). |
| 5.19–6.1 | v2 | T2 | `FS_REFER` available. |
| 6.2–6.6 | v3 | T2 | `+ FS_TRUNCATE`. |
| 6.7+ | v4+ | **T3** | Network rules ⇒ brokered egress works. |

At T3, Landlock's job is *only* to make the broker the sole reachable
destination: `handled_access_net` denies all TCP connects, and a single
`LANDLOCK_RULE_NET_PORT` rule permits the broker's loopback port. The per-host
allowlist is enforced by the broker. If the kernel is below v4, T3 **fails
closed** with an explicit message rather than degrading to "all outbound".

---

## 5. Expected divergences from macOS

These are the places where the two platforms genuinely differ. Each is a
prediction; correct the docs when you measure it.

### 5.1 `FS_REFER` and cross-directory renames

On ABI v1, Landlock denies `rename`/`link` **between directories**
unconditionally — even when both are granted. Build systems that write a temp
file then `mv` it into place will fail in a way that looks like a toolchain bug.

`compile()` emits a warning when the kernel is v1. If you see mysterious
`EXDEV`/`EACCES` from `rename`, check the ABI first.

### 5.2 The ergonomic floor differs

macOS needs `(literal "/")` because dyld reads the root directory
(§`DESIGN.md` 2.1). Linux's equivalent is the loader reading `/lib`,
`/lib64`, `/usr/lib` and `/etc/ld.so.cache`, all of which are in `kBaseRead` in
`src/backend/landlock.cpp`. Distro layout varies — **Alpine/musl, NixOS and
Guix are the likely failures**, since paths like `/nix/store` are not in the
list. If a dynamically-linked binary fails to start under T2, that list is the
first place to look.

### 5.3 There is no `(with report)` equivalent

macOS T0 observation works because Seatbelt can be told to *allow everything and
report every decision*, unprivileged. Landlock has no equivalent in ABI ≤ v6.
This is why `bastion observe` is unavailable on Linux (§5.4).

### 5.4 T0 observation is the biggest gap

Without it, `bastion synthesize` has no evidence and — correctly — refuses to
emit a policy. Three candidate implementations, in order of preference:

1. **Landlock audit logging** (ABI v7+, kernel 6.15): the kernel can emit audit
   records for Landlock denials. Denials alone are weaker than macOS's
   allow-and-report (you learn what was blocked, not what was needed), so this
   suits an *iterative* loop: run tight, collect denials, widen, repeat.
2. **`fanotify` with `FAN_OPEN_PERM`**: gives allow-and-report semantics much
   closer to macOS, but needs `CAP_SYS_ADMIN`. bastion's rule is no setuid and
   no privilege escalation, so this would have to be opt-in and clearly labelled.
3. **`ptrace`/`seccomp-unotify`**: unprivileged and precise, but intrusive and
   slow, and `seccomp_unotify` has documented TOCTOU hazards for anything that
   *enforces*. For pure observation the hazards are milder.

Recommendation: start with (1). It needs no privileges and matches the
fail-closed philosophy. Implement `observe_probe()`/`observe()` in
`src/observe.cpp` behind `#if defined(__linux__)` — the ledger, synthesizer and
closed-loop test are all platform-independent and will work unchanged.

### 5.5 Landlock is stackable; SELinux/AppArmor still apply

Landlock composes with existing LSMs rather than replacing them. If a workload
is denied something bastion granted, check `dmesg`/`audit.log` for an AppArmor
or SELinux denial before assuming a bastion bug. This is a feature: bastion
adds a layer, it does not weaken your distro's.

---

## 6. Verification checklist

Work top to bottom. Each item is a claim that is currently **unverified**.

### 6.1 Basics

- [x] `bastion doctor` reports `landlock` and the expected ABI version (v10)
- [x] `ctest` passes — 13/13 on 7.2.2
- [x] Write inside the workspace succeeds
- [x] Read outside the workspace fails
- [x] `/etc/shadow`, `~/.ssh`, `~/.aws` all denied
- [x] A dynamically-linked binary (`/bin/ls`) runs at T2 — the loader-path check
- [x] A compiler (`cc hello.c`) works, including its temp files — needed the
      private-tmp + `FS_TRUNCATE` fixes; `cc1` opens scratch `O_CREAT|O_TRUNC`,
      so a write grant without TRUNCATE compiles nothing

### 6.2 Adversarial (`build/adversarial_test`)

Already enabled on Linux — the attacks are platform-independent, so this suite
runs as-is. It is the acceptance test for the backend: if it is green, the
filesystem boundary holds.

- [x] Symlink in workspace → outside target is denied
- [x] `../` traversal denied
- [x] Sibling-prefix (`/tmp/ws` must not authorize `/tmp/ws-evil`) denied
- [x] Copying `sh` into the workspace and exec'ing it does not shed policy —
      denied by W^X: a write grant carries no `FS_EXECUTE`, so the copy is
      created but never executable. Grant `fs.exec` in a policy file to run
      binaries you build.
- [x] **Inherited fd**: CONFIRMED identical to macOS — rights attach to the
      open file description, and `close_inherited_fds()` is indeed the only
      thing stopping it (it now spares one fd: the CLOEXEC status pipe).

Two assertions are macOS-gated and stay that way: the Seatbelt hostname warning
(Landlock filters by port, so the T2 message differs) and SBPL injection
(Landlock takes structured syscall arguments — there is no profile parser to
fool). The Linux build substitutes a portable equivalent.

### 6.3 ABI compatibility (the part most likely to break)

- [ ] v1 kernel (5.13–5.18): ruleset applies, `FS_REFER` warning appears
- [ ] v4+ kernel: `--tier t3` accepted
- [ ] **Old kernel, new headers**: build on 6.12+, run on 5.15. This is what
      `AbiInfo::ruleset_attr_size()` exists for — `landlock_ruleset_attr` has
      grown to 6 × `__u64`, and passing `sizeof()` to an older kernel is
      rejected. If this fails, the size table is wrong.
- [ ] Landlock disabled (`lsm=` without it): bastion **refuses to run** at T2
      rather than running unconfined

### 6.4 T3 egress

- [x] Allowlisted host reachable through the broker (`example.com` → 200)
- [x] Non-allowlisted host refused with `403` on CONNECT
- [x] `curl --noproxy '*' https://1.1.1.1` **kernel-denied**
- [x] `nc -z 1.1.1.1 443` **kernel-denied** (raw socket, not just HTTP clients)
- [ ] ABI < v4: `--tier t3` refused with the ABI message, not silently degraded

### 6.5 Distro matrix

Ubuntu 24.04 is the reference. The interesting cases are the ones likely to
break §5.2:

- [ ] Ubuntu 24.04 (v4+) — reference
- [ ] Debian 12 — verify the `lsm=` boot-parameter path
- [ ] Fedora 40 (v5) — SELinux enforcing, to confirm §5.5 stacking
- [ ] Alpine (musl) — most likely to expose a missing loader path
- [ ] NixOS — `/nix/store` is not in `kBaseRead`; expect this to fail first

---

## 7. Debugging

**Landlock denials are silent by default** — no `dmesg` line, no audit record on
kernels below v7. A process just gets `EACCES`. This is the single most
disorienting difference from macOS, where the kernel logs every decision.

```sh
# What did the policy actually ask for?
bastion explain -w /tmp/ws --net example.com:443

# Which syscall failed, and on what path?
strace -f -e trace=openat,connect,rename bastion run -- <cmd> 2>&1 | grep EACCES

# Is Landlock even on?
dmesg | grep landlock
cat /sys/kernel/security/lsm
```

On ABI v7+ (kernel 6.15+), enable audit records for a much better experience:

```sh
auditctl -a always,exit -F arch=b64 -S all -F key=landlock
ausearch -k landlock -ts recent
```

| Symptom | Likely cause |
|---|---|
| Every spawn exits 126 | Confinement failed; `apply()` returned an error. Check ABI and `NO_NEW_PRIVS`. |
| Binary won't start, no message | Loader path missing from `kBaseRead` (§5.2) |
| `rename` fails across dirs | ABI v1, no `FS_REFER` (§5.1) |
| `--tier t3` refused | Kernel < 6.7 (ABI < v4) — working as intended |
| `landlock_create_ruleset` EINVAL | Handled-rights mask or `attr` size exceeds the kernel's ABI. This is the bug `ruleset_attr_size()` prevents; if it recurs the table needs a new row. |
| Everything denied incl. workspace | Rule paths must exist at `apply()` time; non-existent paths are skipped with a warning |

---

## 8. Code map

| File | Role |
|---|---|
| `src/backend/landlock.cpp` | ABI probe, ruleset compile, apply. **Start here.** |
| `include/bastion/backend/landlock.hpp` | `AbiInfo`, `Ruleset`, the ABI table |
| `src/spawn.cpp` | `#elif defined(__linux__)` branch: where `apply()` is called, between `fork` and `exec` |
| `src/observe.cpp` | `#else` branch returns unavailable — **implement T0 here** (§5.4) |
| `src/proxy.cpp` | Egress broker; portable, no changes needed |
| `tools/check_landlock.sh` | Typechecks UAPI usage + asserts the spawn path stays wired. Run it on macOS too. |

The layering to preserve: `Policy` → `Sealed` → backend. The backend only ever
translates an already-sealed policy; it never decides *what* to grant. Keep new
Linux logic inside `landlock.cpp` and `observe.cpp` — if you find yourself
editing `policy.hpp` for a Linux reason, that is a sign the abstraction is wrong.

---

## 9. Reporting results

When something here turns out to be false, fix the doc in the same commit and
include the measurement — the whole project is built on measured claims rather
than assumed ones (`DESIGN.md` §2.1, §6.1). A one-line table row with a real
kernel version beats a paragraph of hedging.
