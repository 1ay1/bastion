// Minimal: does a Landlock NET_CONNECT_TCP rule on one port actually permit
// connect() to that port on loopback, with everything else denied?
//
// This is the exact primitive T3 rests on. Uses raw syscalls, no bastion code.
#include <linux/landlock.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int create_ruleset(const struct landlock_ruleset_attr *a, size_t s, __u32 f) {
    return (int)syscall(__NR_landlock_create_ruleset, a, s, f);
}
static int add_rule(int fd, enum landlock_rule_type t, const void *a, __u32 f) {
    return (int)syscall(__NR_landlock_add_rule, fd, t, a, f);
}
static int restrict_self(int fd, __u32 f) {
    return (int)syscall(__NR_landlock_restrict_self, fd, f);
}

// Connect to 127.0.0.1:port, report the outcome.
static void try_connect(const char *label, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    int rc = connect(s, (struct sockaddr *)&a, sizeof a);
    printf("  %-28s -> %s\n", label,
           rc == 0 ? "CONNECTED"
                   : (errno == EACCES ? "EACCES (landlock)" : strerror(errno)));
    close(s);
}

int main(int argc, char **argv) {
    // A listener so "allowed" is distinguishable from "nothing there".
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    sa.sin_port = 0;
    bind(srv, (struct sockaddr *)&sa, sizeof sa);
    listen(srv, 8);
    socklen_t sl = sizeof sa;
    getsockname(srv, (struct sockaddr *)&sa, &sl);
    const int allowed_port = ntohs(sa.sin_port);

    int other = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sb;
    memset(&sb, 0, sizeof sb);
    sb.sin_family = AF_INET;
    sb.sin_addr.s_addr = inet_addr("127.0.0.1");
    sb.sin_port = 0;
    bind(other, (struct sockaddr *)&sb, sizeof sb);
    listen(other, 8);
    sl = sizeof sb;
    getsockname(other, (struct sockaddr *)&sb, &sl);
    const int denied_port = ntohs(sb.sin_port);

    printf("allowed port=%d  denied port=%d\n", allowed_port, denied_port);

    // Mirror what bastion asks for: handle FS + NET, allow only one TCP port.
    struct landlock_ruleset_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.handled_access_net =
        LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;

    // argv[1] = "fsalso" also handles the filesystem, like a real policy.
    const int with_fs = argc > 1 && strcmp(argv[1], "fsalso") == 0;
    if (with_fs) attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;

    int fd = create_ruleset(&attr, sizeof attr, 0);
    if (fd < 0) { perror("create_ruleset"); return 1; }

    struct landlock_net_port_attr np;
    memset(&np, 0, sizeof np);
    np.allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP;
    np.port = (__u64)allowed_port;
    if (add_rule(fd, LANDLOCK_RULE_NET_PORT, &np, 0) != 0) {
        perror("add_rule(net)"); return 1;
    }

    if (with_fs) {
        // Grant read on / so the FS layer is not what denies things.
        int root = open("/", O_PATH | O_CLOEXEC);
        struct landlock_path_beneath_attr pb;
        memset(&pb, 0, sizeof pb);
        pb.parent_fd = root;
        pb.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
        add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
        close(root);
    }

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (restrict_self(fd, 0) != 0) { perror("restrict_self"); return 1; }
    close(fd);

    printf("enforcing (handled_fs=%s):\n", with_fs ? "yes" : "no");
    try_connect("allowed port", allowed_port);
    try_connect("NON-allowed port", denied_port);
    return 0;
}
