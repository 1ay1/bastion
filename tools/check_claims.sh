#!/bin/sh
# Every number in the docs must come from a run, not from memory.
#
# The failure this prevents is specific and had already happened: five files
# quoted the adversarial suite's size as 27, 29, 30, and 34 simultaneously,
# because each was written when that was true and none was updated when an
# attack was added. A security document whose numbers are stale is worse than
# one with no numbers -- the reader cannot tell which claims were measured.
#
# So: the suite prints its own totals (CLAIMS attempts=... ), the docs are
# required to quote them through a fixed phrase, and this script diffs the two.
# Adding an attack now breaks the build until the prose is corrected.
#
# Usage: check_claims.sh <adversarial_test binary> <ctest binary dir> <doc root>
set -e

ADV=${1:?adversarial_test binary}
BUILD=${2:?build dir}
ROOT=${3:?source root}

fail=0
note() { printf '  %s\n' "$*"; }
bad()  { printf '  MISMATCH: %s\n' "$*"; fail=1; }

# ---- ground truth, measured now -------------------------------------------
claims=$("$ADV" 2>/dev/null | sed -n 's/^CLAIMS //p')
[ -n "$claims" ] || { echo "check_claims: adversarial suite printed no CLAIMS line"; exit 1; }
for kv in $claims; do
    case $kv in
        attempts=*) ATTEMPTS=${kv#*=} ;;
        escapes=*)  ESCAPES=${kv#*=}  ;;
        limits=*)   LIMITS=${kv#*=}   ;;
    esac
done

# Test count comes from ctest's own registry, not from a hand-kept tally.
TESTS=$(cd "$BUILD" && ctest -N 2>/dev/null | sed -n 's/^Total Tests: //p')
[ -n "$TESTS" ] || TESTS=0

note "measured: $ATTEMPTS attempts, $ESCAPES escapes, $LIMITS limits, $TESTS tests"

# ---- what the docs say -----------------------------------------------------
# Docs must use these exact phrasings so the claim is greppable. Anything else
# is prose and may say what it likes, as long as it quotes no bare numbers.
docs="$ROOT/README.md $ROOT/DESIGN.md $ROOT/docs/security-model.md
      $ROOT/docs/architecture.md $ROOT/docs/linux-bringup.md"

for doc in $docs; do
    [ -f "$doc" ] || continue
    rel=${doc#"$ROOT"/}

    # "<N> escape attempts" / "<N> attempts"
    for n in $(grep -oE '[0-9]+ (real )?(adversarial )?(escape )?attempts' "$doc" \
               | grep -oE '^[0-9]+' | sort -u); do
        [ "$n" = "$ATTEMPTS" ] || bad "$rel says $n attempts, suite runs $ATTEMPTS"
    done

    # "<N>/<M> tests"
    for n in $(grep -oE '[0-9]+/[0-9]+ tests' "$doc" | cut -d/ -f1 | sort -u); do
        [ "$n" = "$TESTS" ] || bad "$rel says $n tests, ctest registers $TESTS"
    done

    # "<N> escapes" -- must match, and in practice must be 0.
    for n in $(grep -oE '\*?\*?[0-9]+ escapes' "$doc" | grep -oE '[0-9]+' | sort -u); do
        [ "$n" = "$ESCAPES" ] || bad "$rel says $n escapes, suite measured $ESCAPES"
    done

    # "<N> documented limit(s)" / "<N> known limit(s)"
    for n in $(grep -oE '[0-9]+ (documented|known|residual) limit' "$doc" \
               | grep -oE '^[0-9]+' | sort -u); do
        [ "$n" = "$LIMITS" ] || bad "$rel says $n limits, suite reports $LIMITS"
    done
done

if [ "$fail" -ne 0 ]; then
    echo
    echo "Docs have drifted from the suite. Update the prose, or the number in"
    echo "the docs is a claim nobody measured."
    exit 1
fi

echo "  docs agree with the suite"
