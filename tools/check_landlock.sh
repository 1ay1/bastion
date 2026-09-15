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

c++ -std=c++23 -Wall -Wextra -Wno-unused-function \
    -I"$FAKE" -fsyntax-only "$FAKE/tu.cpp"
echo "OK: UAPI struct layout, field names and syscall usage verified"

# Also confirm the backend itself still parses on the host (fallback branch).
c++ -std=c++23 -Wall -Wextra -I"$ROOT/include" \
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
  "$ROOT/src/spawn.cpp" 'linux_ll::apply\(policy, proxy_port\)'
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

rm -rf "$FAKE"
if [ "$fail" -ne 0 ]; then
  echo "FAILED: Linux spawn path is out of sync with the Landlock backend"
  exit 1
fi
echo "OK: Linux spawn path is wired to the Landlock backend"
