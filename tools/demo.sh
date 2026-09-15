#!/bin/sh
# End-to-end CLI walkthrough: the exact workflow the field report needed.
#
# Run from anywhere; resolves its own repo root so there are no absolute paths.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
B="$ROOT/build/bastion"

if [ ! -x "$B" ]; then
  echo "build bastion first:  cmake -S . -B build && cmake --build build"
  exit 1
fi

BASTION_LEDGER=${BASTION_LEDGER:-/tmp/bastion-demo-ledger.jsonl}
export BASTION_LEDGER
rm -f "$BASTION_LEDGER"

WS=${TMPDIR:-/tmp}/bastion-demo-ws
rm -rf "$WS"
mkdir -p "$WS"

echo "############ 1. doctor: is the floor satisfied? ############"
"$B" doctor || true

echo
echo "############ 2. run in an ARBITRARY directory (no fixed root) ############"
echo 'int main(){return 0;}' > "$WS/t.c"
cd "$WS"
echo "cwd: $(pwd)"
"$B" run -- /bin/sh -c 'echo "  wrote: $(pwd)/out.txt" > out.txt; cat out.txt'
echo "exit=$?"

echo
echo "############ 3. escape attempts are blocked ############"
"$B" run -- /bin/sh -c 'cat /etc/passwd >/dev/null 2>&1 && echo "  LEAKED" || echo "  /etc/passwd: DENIED"'
"$B" run -- /bin/sh -c 'cat ~/.ssh/* >/dev/null 2>&1 && echo "  LEAKED" || echo "  ~/.ssh: DENIED"'
"$B" run -- /bin/sh -c 'curl -s -m 3 https://example.com >/dev/null 2>&1 && echo "  LEAKED" || echo "  network: DENIED"'

echo
echo "############ 4. compiling works (the ergonomic floor) ############"
cd "$ROOT"
"$B" run -w "$WS" -r /usr -r /Library/Developer -- /usr/bin/cc -o "$WS/t" "$WS/t.c" 2>&1 | head -5 || true
test -x "$WS/t" && echo "  cc: BUILT OK under sandbox" || echo "  cc: failed"

echo
echo "############ 5. explain: the REAL boundary ############"
"$B" explain -w "$WS" --net api.example.com:443

echo
echo "############ 6. --yolo: wide open, STILL audited ############"
"$B" run --yolo -- /bin/sh -c 'head -1 /etc/hosts' || true

echo
echo "############ 7. explain --yolo ############"
"$B" explain --yolo

echo
echo "############ 8. observe -> synthesize (the closed loop) ############"
"$B" observe -- /bin/sh -c "cat /etc/hosts > /dev/null; echo hi > $WS/a.txt" || true
"$B" synthesize
