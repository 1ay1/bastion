# CLI reference

```
bastion run        [OPTIONS] -- <command>...   run under a policy
bastion observe             -- <command>...   run unconfined, RECORD every access
bastion explain    [OPTIONS]                  print the REAL enforced boundary
bastion doctor                                check backend + ergonomic floor
bastion synthesize [--ledger PATH]            turn a session log into a policy
```

---

## Policy options

| Option | Meaning |
|---|---|
| `-p, --policy FILE` | load a policy file (as written by `synthesize`). Combines with the flags below. |
| `-w, --workspace PATH` | read+write grant. Repeatable. Default: current directory. |
| `-r, --read PATH` | read-only grant. Repeatable. |
| `--net HOST:PORT` | allow egress. Wildcards: `*.example.com`. Repeatable. |
| `-t, --tier TIER` | `t0`/`t1`/`t2`/`t3`. Default `t2`. |
| `--yolo` | grant `Unconfined`. Auditing stays active. |
| `--ledger PATH` | audit log. Default `~/.bastion/ledger.jsonl`, or `$BASTION_LEDGER`. |
| `--no-ledger` | do not write an audit log. |
| `--json` | machine-readable output. |

### When something fails

bastion tells you when a failure is probably **its** fault, and stays quiet when
it is not. That second half matters as much as the first: an agent told "maybe
it was the sandbox" after a genuine test failure will chase a policy bug that
does not exist.

The advisory appears only with evidence the boundary was involved — the broker
refused a host, an exec was denied, or a connection failed at a tier that
denies all egress:

```sh
$ bastion run -- ./my-binary
bastion: exec failed (binary missing or not executable)
         the file EXISTS, so this is the policy: a write grant does not include execute.
         To run a binary you built, add an `fs.exec` rule for its directory:

           [[allow]]
           op   = "fs.exec"
           path = "/tmp/project"

         then: bastion run --policy <file> -- ./my-binary
```

A plain `exit 1` from your test suite produces no such block.

Commands are resolved against the **sandbox's** `PATH`, not yours, so
`bastion run -- cc main.c` works without an absolute path — and a binary that
only exists in a directory the sandbox cannot execute fails as "not found"
rather than as a confusing mid-run denial.

### Resource ceilings

Opt-in, and off by default: a ceiling that fires during a legitimate build is
exactly the friction that gets sandboxes switched off.

| Option | Meaning |
|---|---|
| `--max-procs N` | cap processes in this sandbox |
| `--max-mem-mb N` | cap memory for the whole sandbox (cgroup only) |
| `--max-file-mb N` | cap the size of any single file the child creates |
| `--max-cpu-sec N` | cap CPU seconds; a runaway loop dies with `SIGXCPU` |

Core dumps are *always* disabled, so a crashing child cannot scatter memory
images (which may hold secrets read from granted paths) into the workspace.

**Two mechanisms, and the meaning differs.** Run `bastion doctor` to see which
one you have:

- **cgroup v2** (`resource budget: cgroup v2 (pids+memory) — per-sandbox`).
  Requires a delegated cgroup — systemd's `user@UID.service` gives every login
  session one, with no root needed. `--max-procs 20` means *twenty processes in
  this sandbox*, and `--max-mem-mb` works.
- **setrlimit fallback** (`resource budget: setrlimit only — per-uid`).
  `--max-procs` becomes `RLIMIT_NPROC`, which counts every **thread** owned by
  your uid system-wide — a desktop session sits around 800 — so it is only a
  fork-bomb backstop. Set it well above
  `ps -u $(id -u) -L --no-headers | wc -l` or the first `fork` fails and the
  build looks broken; bastion warns when your value is below that count.
  `--max-mem-mb` is dropped with a warning, because no rlimit expresses it
  (`RLIMIT_AS` caps address space, which allocators reserve lavishly).

When the kernel refuses something, bastion says so — an OOM kill is reported as
such rather than surfacing as an unexplained exit 137.

There is **no fixed sandbox root**. Path-set authority derives the ruleset from
the actual working directory at spawn time, so `bastion run -- make` works in
any directory with no symlinks and nothing to pre-create.

---

## `bastion run`

Runs a command under the policy and exits with the child's status.

```sh
bastion run -- cargo test                      # cwd as workspace
bastion run -w src -r /usr/include -- ./build.sh
bastion run -t t3 --net '*.pypi.org:443' -- pip install -r requirements.txt
```

Refuses to start if the requested tier exceeds the backend's `max_tier`:

```
error: policy requires T3:isolate but backend 'landlock' supports at most
T2:kernel (Landlock ABI v2). Refusing to run with weaker enforcement than
requested.
```

This is deliberate. A sandbox that quietly weakens is worse than one that stops,
because you still believe you are protected.

### Exit codes

| Code | Meaning |
|---|---|
| *child's* | Normal pass-through |
| `125` | Child could not `chdir` to the workspace |
| `126` | **Confinement failed — the command was NOT executed** |
| `127` | `exec` failed (binary missing or not executable) |
| `2` | bastion refused to run (bad policy, tier unavailable, proxy failed) |

`126` is the important one: a failed sandbox never degrades to an unconfined run.

---

## `bastion observe`

Runs the command with **nothing enforced** and records every filesystem and
network access. This is the T0 tier, and the input to `synthesize`.

```sh
$ bastion observe -- ./weird-legacy-build.sh
bastion: T0 OBSERVE via seccomp-user-notify — nothing is enforced,
         every access is recorded. Ctrl-C is safe.
bastion: recorded 62 access(es)
         next: bastion synthesize
```

**Nothing is enforced during observation.** Only run workloads you would run
unsandboxed anyway.

Backends: **macOS** uses Seatbelt's `(with report)` plus the unified log;
**Linux** uses seccomp user-notification, which is unprivileged and survives
`execve`, so short-lived grandchildren (`sh -c 'cat …'`) are recorded with
exact pid attribution rather than an inferred pid window.

---

## `bastion synthesize`

Derives the minimal policy that would have allowed everything observed.

```sh
bastion observe -- ./build.sh
bastion synthesize > bastion.toml
bastion run --policy bastion.toml -- ./build.sh    # the loop closes here
```

```toml
# Synthesized by `bastion synthesize` from 62 observed operation(s).
# 48 access(es) omitted: already covered by the ergonomic floor.
tier = "T2"

[[allow]]
op    = "fs.read"
path  = "/private/etc/hosts"
why   = "synthesized from observed use"
```

Guarantees worth knowing:

- **Denied operations never become grants** — that would hand over exactly what
  the sandbox stopped.
- **`/` is never granted**, even though dyld legitimately reads it.
- **Never widens into `$HOME`, `/etc`, `/usr`** and similar; it emits individual
  rules instead and explains the refusal.
- **With no evidence it refuses to emit a policy** rather than claiming "no
  grants needed".

### Policy files

`--policy FILE` reads the format back. It is a small TOML subset, parsed by
hand rather than by a dependency — a security tool should not grow a
third-party parser to read its own output.

```toml
tier = "T2"

[[allow]]
op    = "fs.write"       # fs.read | fs.write | fs.exec | net.egress | net.bind
path  = "/srv/app"       # absolute path, or host:port for net.*
why   = "build output"   # optional, carried into the audit log
```

Parsing **fails closed**: an unknown `op`, a missing `path`, an unquoted value
or a bad tier stops the run with a line number rather than falling back to the
permissive default.

```
$ bastion run --policy bad.toml -- ./build.sh
error: bad.toml:1: unknown op 'fs.telepathy' (expected fs.read, fs.write,
fs.exec, net.egress, net.bind)
```

A policy file **replaces** the default "grant the current directory" behaviour,
so a file that deliberately omits the cwd does not get it back silently. Flags
combine with the file (`--policy p.toml -r /extra`), and an explicit `--tier`
overrides the file's, letting you tighten a committed policy without editing it.

---

## `bastion explain`

Prints the boundary that will actually be enforced, including what the backend
*cannot* do.

```sh
$ bastion explain -w /tmp/ws --net api.example.com:443
tier:      T2:kernel
guarantee: Kernel-enforced path-set authority. Survives arbitrary native code.

rules (3):
  rw  /private/tmp/ws        (--workspace)
  r   /tmp/ws                (symlink traversal for /private/tmp/ws)
  net api.example.com:443    (--net)

[warning] net.egress granted, but Seatbelt cannot restrict by hostname: ALL
outbound connections are permitted at T2. Use --tier t3 for per-host
allowlisting.
```

Run this whenever a denial surprises you. The symlink-traversal rule appearing
automatically is normal — see `DESIGN.md` §2.1.

---

## `bastion doctor`

Checks the backend and the **ergonomic floor** — the conditions a toolchain
needs. A sandbox that breaks the compiler makes agents thrash, and thrashing
agents get their sandboxes switched off, so this is a security check, not a
convenience.

```sh
$ bastion doctor
backend:     seatbelt
max tier:    T3:isolate
path authority:   yes
requires setuid:  no

ergonomic floor:
  [ok] writable temp dir
  [ok] /dev/null present
  [ok] toolchain caches granted
         default:  5 cache dir(s) under $HOME

ready: the floor is satisfied.
```

On Linux it additionally reports the live Landlock ABI, whether process
isolation is available, and which resource-budget mechanism you get:

```sh
$ bastion doctor
backend:     landlock
note:        Landlock ABI v10
max tier:    T3:isolate
path authority:   yes
net filtering:    yes (by port)
namespace isolation: yes
resource budget:  cgroup v2 (pids+memory) — per-sandbox
requires setuid:  no
```

Run it first on a new machine.

---

## Tiers

| Tier | Guarantee | Use for |
|---|---|---|
| `t0` | None. Records only. | Dry runs, CI diffs |
| `t1` | Best-effort. Stops accidents. | Legacy, unsupported platforms |
| `t2` | Kernel path-set authority. Survives native code. | **Default** |
| `t3` | T2 + brokered per-host egress + PID/IPC isolation (Linux). | Network-touching or untrusted workloads |

T0 and T1 are **not boundaries** against a motivated adversary, and say so.

### T3 networking

```sh
$ bastion run -t t3 --net example.com:443 -- curl -s https://example.com
HTTP 200
bastion: T3 egress broker on 127.0.0.1:56653 — direct outbound is kernel-denied.

$ bastion run -t t3 --net example.com:443 -- curl -sS https://cloudflare.com
curl: (56) CONNECT tunnel failed, response 403
bastion: egress REFUSED cloudflare.com:443
         remedy: bastion run --net cloudflare.com:443
```

The kernel denies all direct egress and permits only the broker's loopback port,
so a compromised child that ignores `*_PROXY` gets *no network* rather than a
bypass. TLS is never terminated — no CA to install.

Wildcards match subdomains but deliberately **not** the bare apex: granting
`*.example.com` does not include `example.com`.

---

## `--yolo`

```sh
bastion run --yolo -- ./legacy-installer.sh
```

```
bastion: UNCONFINED — no restriction is enforced.
         Auditing stays active; run `bastion synthesize` afterwards to derive
         a least-privilege policy.
```

`--yolo` is **not** `--sandbox off`. It is a maximal grant at a retained tier:
the witness is recorded, the ledger keeps running, and `bastion explain` shows
the grant and who asked for it. That is what makes the bypass an on-ramp to a
tight policy instead of the end of observability.

---

## Environment

| Variable | Effect |
|---|---|
| `BASTION_LEDGER` | Default ledger path |
| `TMPDIR` | Granted read+write (the floor). Private `$TMPDIR` preferred over shared `/tmp`. |
| `CARGO_HOME`, `GOCACHE`, `GOMODCACHE`, `npm_config_cache`, `PIP_CACHE_DIR`, `CCACHE_DIR`, `ZIG_GLOBAL_CACHE_DIR` | Granted read+write if set, so builds don't re-download on every run |

Set **inside** the child:

| Variable | Value |
|---|---|
| `BASTION_ACTIVE` | `1` |
| `BASTION_TIER` | e.g. `T2:kernel` |
| `BASTION_UNCONFINED` | `1` when `--yolo` |
| `BASTION_PROXY_PORT`, `HTTP(S)_PROXY` | T3 broker port |

Secrets (`*_TOKEN`, `*_SECRET`, `*_KEY`, `AWS_*`, `GITHUB_TOKEN`, …) and
injection vectors (`DYLD_INSERT_LIBRARIES`, `LD_PRELOAD`, …) are stripped even
with `inherit_env`.

---

## Denials are machine-readable

Every denial is structured and in-band, so an agent can act on it without the
boundary being narrated in prose:

```json
{"verdict":"deny","op":"fs.write","target":"/etc/hosts","tier":"T2:kernel",
 "rule":"default-deny",
 "remedy":{"grant":"FsWrite(/etc/hosts)","cmd":"bastion run -w /etc/hosts -- <cmd>"},
 "sanctioned_alternative":"write under $WORKSPACE or $TMPDIR"}
```

This is why an `AGENTS.md` describing the sandbox is unnecessary: the sandbox
explains itself at the moment of failure.
