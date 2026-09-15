#!/bin/sh
# End-to-end CLI walkthrough: the exact workflow the field report needed.
B=./build/bastion
export BASTION_LEDGER=/tmp/bastion-demo-ledger.jsonl
rm -f "$BASTION_LEDGER"

echo "############ 1. doctor: is the floor satisfied? ############"
$B doctor

echo
echo "############ 2. run in an ARBITRARY directory (no fixed root) ############"
rm -rf /tmp/anywhere && mkdir -p /tmp/anywhere && cd /tmp/anywhere
echo 'int main(){return 0;}' > t.c
echo "cwd: $(pwd)"
/Users/ayush/projects/bastion/build/bastion run -- /bin/sh -c 'echo "  wrote: $(pwd)/out.txt" > out.txt; cat out.txt'
echo "exit=$?"

echo
echo "############ 3. escape attempts are blocked ############"
/Users/ayush/projects/bastion/build/bastion run -- /bin/sh -c 'cat /etc/passwd >/dev/null 2>&1 && echo LEAKED || echo "  /etc/passwd: DENIED"'
/Users/ayush/projects/bastion/build/bastion run -- /bin/sh -c 'cat ~/.ssh/id_ed25519 >/dev/null 2>&1 && echo LEAKED || echo "  ~/.ssh: DENIED"'
/Users/ayush/projects/bastion/build/bastion run -- /bin/sh -c 'curl -s -m 2 https://example.com >/dev/null 2>&1 && echo LEAKED || echo "  network: DENIED"'

echo
echo "############ 4. compiling works (the ergonomic floor) ############"
cd /Users/ayush/projects/bastion
$B run -w /tmp/anywhere -r /usr -r /Library/Developer -- /usr/bin/cc -o /tmp/anywhere/t /tmp/anywhere/t.c 2>&1 | head -5
test -x /tmp/anywhere/t && echo "  cc: BUILT OK under sandbox" || echo "  cc: failed"

echo
echo "############ 5. explain: the REAL boundary ############"
$B explain -w /tmp/anywhere --net api.example.com:443

echo
echo "############ 6. --yolo: wide open, STILL audited ############"
$B run --yolo -- /bin/sh -c 'cat /etc/passwd | head -1'
echo "exit=$?"

echo
echo "############ 7. explain --yolo ############"
$B explain --yolo

echo
echo "############ 8. synthesize from the ledger ############"
$B synthesize
