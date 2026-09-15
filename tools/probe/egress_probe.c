// Probe: can Seatbelt restrict outbound to ONLY a loopback port?
// If yes, a local proxy becomes a REAL per-host egress boundary: the kernel
// makes the proxy the only way out, and the proxy enforces the allowlist.
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

extern int sandbox_init(const char*, unsigned long long, char**);

static void try_connect(const char* label, const char* ip, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { printf("  %-34s socket failed\n", label); return; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, ip, &a.sin_addr);
    int rc = connect(s, (struct sockaddr*)&a, sizeof a);
    printf("  %-34s %s\n", label, rc == 0 ? "CONNECTED" : strerror(errno));
    close(s);
}

int main(int argc, char** argv) {
    char* err = NULL;
    int rc = sandbox_init(argv[1], 0, &err);
    printf("rc=%d err=%s\n", rc, err ? err : "(none)");
    if (rc != 0) return 2;
    try_connect("loopback:8888 (the proxy)", "127.0.0.1", 8888);
    try_connect("loopback:9999 (other port)", "127.0.0.1", 9999);
    try_connect("1.1.1.1:443 (direct egress)", "1.1.1.1", 443);
    try_connect("93.184.216.34:80 (direct)", "93.184.216.34", 80);
    return 0;
}
