#!/bin/sh
# Typecheck the Landlock backend's LINUX branch on a non-Linux host by faking
# just enough of the kernel UAPI + glibc surface. Catches the errors that
# actually bite (wrong field names, missing constants, bad struct sizes)
# without needing a Linux box or Docker.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
FAKE=$(mktemp -d)
mkdir -p "$FAKE/linux" "$FAKE/sys"

# Real UAPI definitions, transcribed from
# include/uapi/linux/landlock.h (torvalds/linux master).
cat > "$FAKE/linux/landlock.h" <<'EOF'
#pragma once
#include <stdint.h>
struct landlock_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
    uint64_t scoped;
    uint64_t quiet_access_fs;
    uint64_t quiet_access_net;
    uint64_t quiet_scoped;
};
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#define LANDLOCK_CREATE_RULESET_ERRATA  (1U << 1)
enum landlock_rule_type {
    LANDLOCK_RULE_PATH_BENEATH = 1,
    LANDLOCK_RULE_NET_PORT,
};
struct landlock_path_beneath_attr {
    uint64_t allowed_access;
    int32_t  parent_fd;
} __attribute__((packed));
struct landlock_net_port_attr {
    uint64_t allowed_access;
    uint64_t port;
};
#define LANDLOCK_ACCESS_FS_EXECUTE     (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE  (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE   (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR    (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR  (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR   (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR    (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG    (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK   (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO   (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK  (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM    (1ULL << 12)
#define LANDLOCK_ACCESS_FS_REFER       (1ULL << 13)
#define LANDLOCK_ACCESS_FS_TRUNCATE    (1ULL << 14)
#define LANDLOCK_ACCESS_FS_IOCTL_DEV   (1ULL << 15)
#define LANDLOCK_ACCESS_NET_BIND_TCP    (1ULL << 0)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
EOF

cat > "$FAKE/sys/prctl.h" <<'EOF'
#pragma once
#define PR_SET_NO_NEW_PRIVS 38
extern "C" int prctl(int, ...);
EOF

cat > "$FAKE/sys/syscall.h" <<'EOF'
#pragma once
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_add_rule       445
#define SYS_landlock_restrict_self  446
extern "C" long syscall(long, ...);
EOF

echo "typechecking Landlock LINUX branch against real UAPI definitions..."
# We cannot simply define __linux__ on a macOS host: libc++'s own headers then
# take their Linux paths and fail. Instead compile a small TU that includes the
# faked UAPI headers and exercises the exact syscall/struct usage the backend
# relies on, so field names, constants and struct layout are all verified.
cat > "$FAKE/tu.cpp" <<'EOF'
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <cstdint>
#include <cstddef>

// Mirror of the helpers in src/backend/landlock.cpp.
static int ll_create_ruleset(const struct landlock_ruleset_attr* a, std::size_t n,
                             std::uint32_t f) {
    return static_cast<int>(::syscall(SYS_landlock_create_ruleset, a, n, f));
}
static int ll_add_rule(int fd, enum landlock_rule_type t, const void* a,
                       std::uint32_t f) {
    return static_cast<int>(::syscall(SYS_landlock_add_rule, fd, t, a, f));
}
static int ll_restrict_self(int fd, std::uint32_t f) {
    return static_cast<int>(::syscall(SYS_landlock_restrict_self, fd, f));
}

// The ABI-size clamp must never exceed the real struct.
static std::size_t attr_size(int version) {
    std::size_t fields = 1;
    if (version >= 4) fields = 2;
    if (version >= 6) fields = 3;
    if (version >= 10) fields = 6;
    std::size_t want = fields * sizeof(std::uint64_t);
    return want > sizeof(struct landlock_ruleset_attr)
               ? sizeof(struct landlock_ruleset_attr) : want;
}

static_assert(sizeof(struct landlock_ruleset_attr) == 6 * sizeof(std::uint64_t),
              "ruleset_attr is 6 x __u64 in current UAPI");
static_assert(sizeof(struct landlock_path_beneath_attr) == 12,
              "path_beneath_attr must be packed (8 + 4), not padded to 16");

// REGRESSION GUARD (measured on kernel 7.2.2): LANDLOCK_RULE_NET_PORT is an
// ENUMERATOR, not a macro, so `#if defined(LANDLOCK_RULE_NET_PORT)` is always
// false and silently compiles out every net rule -- which left handled_net set
// (all egress denied) with no allow-rule for the T3 broker, so T3 denied the
// workload its own broker. Guard net code on LANDLOCK_ACCESS_NET_CONNECT_TCP,
// which really is a #define.
#if defined(LANDLOCK_RULE_NET_PORT)
#  error "LANDLOCK_RULE_NET_PORT is now a macro; revisit the net-rule guards"
#endif
#if !defined(LANDLOCK_ACCESS_NET_CONNECT_TCP)
#  error "LANDLOCK_ACCESS_NET_CONNECT_TCP must be a macro; it is the net guard"
#endif

int main() {
    struct landlock_ruleset_attr attr{};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
                             LANDLOCK_ACCESS_FS_READ_DIR |
                             LANDLOCK_ACCESS_FS_WRITE_FILE |
                             LANDLOCK_ACCESS_FS_EXECUTE |
                             LANDLOCK_ACCESS_FS_REFER |
                             LANDLOCK_ACCESS_FS_TRUNCATE |
                             LANDLOCK_ACCESS_FS_IOCTL_DEV;
    attr.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP |
                              LANDLOCK_ACCESS_NET_CONNECT_TCP;

    int v = ll_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
    int fd = ll_create_ruleset(&attr, attr_size(v), 0);

    struct landlock_path_beneath_attr pb{};
    pb.parent_fd = 3;
    pb.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE & attr.handled_access_fs;
    ll_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);

    struct landlock_net_port_attr np{};
    np.port = 443;
    np.allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP;
    ll_add_rule(fd, LANDLOCK_RULE_NET_PORT, &np, 0);

    ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    return ll_restrict_self(fd, 0);
}
EOF

# Pick a C++23 flag this compiler actually accepts. Apple clang on macos-14
# rejects `-std=c++23` outright ("invalid value 'c++23'") but takes the older
# spelling `c++2b` for the same standard -- MEASURED: this job failed on every
# push for days with `error: invalid value 'c++23' in '-std=c++23'`, which
# looked like a code error and was a flag-spelling error.
STD=c++2b
if echo 'int main(){}' | c++ -std=c++23 -fsyntax-only -x c++ - 2>/dev/null; then
    STD=c++23
fi
echo "using -std=$STD"

c++ -std=$STD -Wall -Wextra -Wno-unused-function \
    -I"$FAKE" -fsyntax-only "$FAKE/tu.cpp"
echo "OK: UAPI struct layout, field names and syscall usage verified"

# Also confirm the backend itself still parses on the host (fallback branch).
c++ -std=$STD -Wall -Wextra -I"$ROOT/include" \
    -fsyntax-only "$ROOT/src/backend/landlock.cpp"
echo "OK: landlock.cpp parses clean on host"

# ---------------------------------------------------------------------------
# Cross-TU consistency. The checks above validate UAPI usage but NOT that the
# Linux branch of spawn.cpp agrees with the Landlock backend's signatures --
# and those live behind #if defined(__linux__), so a macOS build never sees
# them. A mismatch there is invisible until someone builds on Linux, which is
# exactly the failure this script exists to prevent.
#
# We cannot define __linux__ on macOS (libc++ takes its Linux paths and breaks),
# so instead assert the call sites textually against the declarations.
# ---------------------------------------------------------------------------
fail=0
check_decl() {
  desc="$1"; file="$2"; pattern="$3"
  if grep -qE "$pattern" "$file"; then
    echo "OK: $desc"
  else
    echo "MISSING: $desc  (expected /$pattern/ in $file)"
    fail=1
  fi
}

check_decl "spawn.cpp includes the Landlock backend on Linux" \
  "$ROOT/src/spawn.cpp" 'elif defined\(__linux__\)'
check_decl "spawn.cpp applies Landlock in the child" \
  "$ROOT/src/spawn.cpp" 'linux_ll::apply_compiled\('
check_decl "child proves fork-safety with a ForkChild token" \
  "$ROOT/src/spawn.cpp" 'ForkBoundary::in_child\(\)'
check_decl "child crosses the fork boundary with the TRIVIAL AbiCore" \
  "$ROOT/src/spawn.cpp" 'll_core'
check_decl "spawn.cpp pre-compiles the ruleset in the PARENT" \
  "$ROOT/src/spawn.cpp" 'linux_ll::compile\(policy, ll_abi, proxy_port\)'

# The child must NOT call the allocating apply(). At T3 the egress broker's
# accept thread is running when we fork, and a child of a multithreaded process
# deadlocks if it takes a malloc lock another thread held at fork time -- it
# would hang with the sandbox unapplied and the workload never exec'd.
if grep -q 'linux_ll::apply(policy' "$ROOT/src/spawn.cpp"; then
  echo "FAIL: child calls the ALLOCATING linux_ll::apply(); use apply_compiled()"
  echo "      (forking from the T3 broker's thread + malloc = possible deadlock)"
  fail=1
else
  echo "OK: child uses the allocation-free apply_compiled()"
fi
check_decl "spawn.cpp fails closed when Landlock is unavailable" \
  "$ROOT/src/spawn.cpp" 'refusing to run unconfined'
check_decl "landlock.hpp declares apply(policy, proxy_port)" \
  "$ROOT/include/bastion/backend/landlock.hpp" 'apply\(const Sealed& policy,'
check_decl "landlock.hpp declares compile(policy, abi, proxy_port)" \
  "$ROOT/include/bastion/backend/landlock.hpp" 'compile\(const Sealed& policy, const AbiInfo& abi,'
check_decl "T3 pins egress to the broker port" \
  "$ROOT/src/backend/landlock.cpp" 't3_broker'
check_decl "T3 fails closed below ABI v4" \
  "$ROOT/src/backend/landlock.cpp" 'needs Landlock ABI v4\+'

# The net-rule loop must NOT be guarded on LANDLOCK_RULE_NET_PORT: that is an
# enumerator, so `#if defined(...)` is always false and deletes the loop, which
# denies T3 its own broker port while still denying all other egress (a silent
# availability failure that looks like enforcement).
if grep -q '^# *if defined(LANDLOCK_RULE_NET_PORT)' "$ROOT/src/backend/landlock.cpp"; then
  echo "FAIL: net rules guarded on LANDLOCK_RULE_NET_PORT (an enum, never defined)"
  echo "      use LANDLOCK_ACCESS_NET_CONNECT_TCP, which is a real #define"
  fail=1
else
  echo "OK: net rules are guarded on a real macro, not the enumerator"
fi

rm -rf "$FAKE"

# ---------------------------------------------------------------------------
# DOES IT STILL BUILD ON AN OLD DISTRO?
#
# The runtime ABI gates (abi.has_refer and friends) are `if`s, not `#if`s, so
# they say nothing about whether the file COMPILES where a constant is missing.
# MEASURED: the older-ABI CI job failed for days with
#   error: 'LANDLOCK_ACCESS_FS_REFER' was not declared in this scope
# because Ubuntu 22.04 ships the v1 header. Developing on ABI v10 hides this
# completely, and abi_matrix_test cannot see it -- that test proves the runtime
# LOGIC degrades, using the headers of whatever machine it was built on.
#
# So: compile the backend against a synthetic v1 header. This is a real
# compile, not a grep, and it fails the build the way the distro would.
if [ "$(uname -s)" = "Linux" ]; then
  OLD=$(mktemp -d)
  mkdir -p "$OLD/linux"
  cat > "$OLD/linux/landlock.h" <<'EOF'
/* Synthetic Landlock ABI v1 UAPI header -- what Ubuntu 22.04 ships.
 * v1 filesystem rights only: no REFER (v2), TRUNCATE (v3), IOCTL_DEV (v5),
 * and no networking (v4) -- neither the constants NOR the struct members. */
#ifndef _LINUX_LANDLOCK_H
#define _LINUX_LANDLOCK_H
#include <linux/types.h>
struct landlock_ruleset_attr { __u64 handled_access_fs; };
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
enum landlock_rule_type { LANDLOCK_RULE_PATH_BENEATH = 1 };
struct landlock_path_beneath_attr {
	__u64 allowed_access;
	__s32 parent_fd;
} __attribute__((packed));
#define LANDLOCK_ACCESS_FS_EXECUTE     (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE  (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE   (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR    (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR  (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR   (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR    (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG    (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK   (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO   (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK  (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM    (1ULL << 12)
#endif
EOF
  if c++ -std=$STD -Wall -Wextra -Werror -I"$ROOT/include" -I"$OLD" \
         -fsyntax-only "$ROOT/src/backend/landlock.cpp" 2>/tmp/bastion-oldhdr.log; then
    echo "OK: backend still compiles against a Landlock ABI v1 header"
  else
    echo "FAIL: backend does NOT compile against an old Landlock header"
    echo "      (this is what Ubuntu 22.04 and other LTS distros ship)"
    head -20 /tmp/bastion-oldhdr.log
    fail=1
  fi

  # COMPILING IS NOT ENFORCING.
  #
  # The first attempt at old-header support made the file compile by skipping
  # the network setup when the header lacked the types. It compiled cleanly and
  # silently stopped mediating egress: on ubuntu-22.04 (5.15 headers, v4-capable
  # KERNEL) a T2 sandbox with no egress grant reached the internet while doctor
  # still said "net filtering: yes". A compile check cannot see that.
  #
  # So assert the property that actually matters: the network rights must reach
  # the kernel regardless of what the build header knew. handled_access_net is
  # set unconditionally, and the net rule loop is not guarded away.
  guarded=$(awk '/attr.handled_access_net = /{print NR}' "$ROOT/src/backend/landlock.cpp" | head -1)
  if [ -n "$guarded" ] && \
     sed -n "$((guarded-3)),$((guarded))p" "$ROOT/src/backend/landlock.cpp" \
       | grep -qE '^# *if'; then
    echo "FAIL: handled_access_net is behind a build-header #if"
    echo "      an old header would then silently disable egress mediation"
    echo "      on a kernel that supports it -- gate on the RUNTIME probe"
    fail=1
  else
    echo "OK: network rights are not gated on the build header"
  fi
  rm -rf "$OLD"
fi

# ---------------------------------------------------------------------------
# DOES THE NON-LINUX BRANCH STILL COMPILE?
#
# Nothing on Linux compiles the `#else` halves of the platform splits, so they
# ROT SILENTLY and only macOS CI notices -- one round-trip per bug, blind.
# MEASURED: the non-Linux compile() stub still returned a bare `Ruleset` with
# an `.error` field long after the signature became Result<Ruleset> and Ruleset
# deliberately lost that field. A plain type error, invisible here for weeks.
#
# This does not make macOS VERIFIED -- it runs nothing, and glibc is not
# Apple's libc. It only catches the class that bit us: signatures that drifted
# and headers that are missing. Cheap, and it turns a CI round-trip into a
# local error.
if [ "$(uname -s)" = "Linux" ]; then
  ok=1
  for f in "$ROOT/src/backend/landlock.cpp" "$ROOT/src/observe.cpp"; do
    # -U__linux__ takes the non-Linux path; -D__APPLE__ is NOT set, because
    # that would pull in Darwin-only headers this machine does not have.
    if ! c++ -std=$STD -U__linux__ -I"$ROOT/include" -fsyntax-only "$f" \
         2>/tmp/bastion-nonlinux.log; then
      echo "FAIL: $(basename "$f") does not compile with __linux__ undefined"
      head -12 /tmp/bastion-nonlinux.log
      ok=0
      fail=1
    fi
  done
  [ "$ok" -eq 1 ] && echo "OK: the non-Linux branch still compiles"
fi

# ---------------------------------------------------------------------------
# POSIX NAMES THAT ARE MACROS ON macOS.
#
# Several <signal.h> and <sys/wait.h> names are real FUNCTIONS in glibc but
# function-like MACROS in Apple's SDK:
#     #define sigemptyset(set) (*(set) = 0, 0)
# A `::`-qualified call then expands to `::(*(&x) = 0, 0)`, and clang reports
# "expected unqualified-id" pointing at the ::. MEASURED: this broke the macOS
# job while building perfectly here, because glibc has the function.
#
# A grep, not a compile, because reproducing it needs Apple's headers. Written
# so it points straight at the fix rather than at a confusing parse error.
macro_hits=$(grep -rnE '::(sigemptyset|sigfillset|sigaddset|sigdelset|sigismember|WIFEXITED|WEXITSTATUS|WIFSIGNALED|WTERMSIG|WIFSTOPPED|WSTOPSIG)\(' \
  --include='*.cpp' --include='*.hpp' "$ROOT/src" "$ROOT/include" "$ROOT/tests" 2>/dev/null \
  | grep -v '^\s*//' | grep -v 'NOT ::' || true)
if [ -n "$macro_hits" ]; then
  echo "FAIL: :: -qualified call to a name that is a MACRO on macOS"
  echo "      drop the :: -- these are macros in Apple's SDK and functions in glibc"
  echo "$macro_hits" | head -5
  fail=1
else
  echo "OK: no ::-qualified calls to macOS macros"
fi

if [ "$fail" -ne 0 ]; then
  echo "FAILED: Linux spawn path is out of sync with the Landlock backend"
  exit 1
fi
echo "OK: Linux spawn path is wired to the Landlock backend"
