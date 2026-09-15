// Feasibility probe for T0 observation on Linux via seccomp user-notification.
//
// The four things that decide whether the design is viable at all:
//   1. can an UNPRIVILEGED process install a NEW_LISTENER filter?
//   2. does the filter survive execve, so a GRANDCHILD's syscalls are seen?
//   3. can the supervisor read the path argument out of the stopped process?
//   4. does SECCOMP_USER_NOTIF_FLAG_CONTINUE let the syscall proceed, so this
//      is pure OBSERVATION -- no enforcement, no emulation, no behaviour change?
//
// (4) is the crux. If CONTINUE works, T0 can watch without altering the
// workload; if it did not, "observation" would silently become enforcement.
//
// Build: cc -D_GNU_SOURCE tools/probe/seccomp_notify_probe.c -o /tmp/scprobe
#define _GNU_SOURCE
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int seccomp(unsigned op, unsigned flags, void *args) {
    return (int)syscall(__NR_seccomp, op, flags, args);
}

// Trap openat(2) to the supervisor; let every other syscall run untouched.
static int install_listener(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof filter / sizeof filter[0]),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    return seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}

static int send_fd(int sock, int fd) {
    char dummy = 'x';
    struct iovec io = { .iov_base = &dummy, .iov_len = 1 };
    char cbuf[CMSG_SPACE(sizeof(int))];
    memset(cbuf, 0, sizeof cbuf);
    struct msghdr m = { .msg_iov = &io, .msg_iovlen = 1,
                        .msg_control = cbuf, .msg_controllen = sizeof cbuf };
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    return sendmsg(sock, &m, 0) < 0 ? -1 : 0;
}

static int recv_fd(int sock) {
    char dummy;
    struct iovec io = { .iov_base = &dummy, .iov_len = 1 };
    char cbuf[CMSG_SPACE(sizeof(int))];
    memset(cbuf, 0, sizeof cbuf);
    struct msghdr m = { .msg_iov = &io, .msg_iovlen = 1,
                        .msg_control = cbuf, .msg_controllen = sizeof cbuf };
    if (recvmsg(sock, &m, 0) < 0) return -1;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    if (!c || c->cmsg_type != SCM_RIGHTS) return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof(int));
    return fd;
}

// Read a NUL-terminated string out of the target's address space.
static int read_string(pid_t pid, unsigned long remote, char *out, size_t n) {
    struct iovec l = { .iov_base = out, .iov_len = n - 1 };
    struct iovec r = { .iov_base = (void *)remote, .iov_len = n - 1 };
    ssize_t got = process_vm_readv(pid, &l, 1, &r, 1, 0);
    if (got < 0) return -1;
    out[got] = '\0';
    return 0;
}

int main(void) {
    printf("uid=%d (unprivileged=%s)\n", getuid(), getuid() != 0 ? "yes" : "no");

    int sk[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sk) != 0) { perror("socketpair"); return 1; }

    pid_t pid = fork();
    if (pid == 0) {
        close(sk[0]);
        int lfd = install_listener();
        if (lfd < 0) { perror("  seccomp(NEW_LISTENER)"); _exit(2); }
        if (send_fd(sk[1], lfd) != 0) { perror("  send_fd"); _exit(2); }
        close(sk[1]);
        close(lfd);
        // execve: the whole question of whether grandchildren are covered.
        execlp("cat", "cat", "/etc/hostname", (char *)NULL);
        _exit(3);
    }
    close(sk[1]);

    int notify_fd = recv_fd(sk[0]);
    if (notify_fd < 0) { fprintf(stderr, "recv_fd failed\n"); return 1; }
    printf("[1] unprivileged NEW_LISTENER install: OK (fd received via SCM_RIGHTS)\n");

    int seen = 0, continued = 0, post_exec = 0;
    for (;;) {
        struct seccomp_notif req;
        memset(&req, 0, sizeof req);
        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) != 0) {
            if (errno == EINTR) continue;
            break;  // ENOENT/EPIPE: the workload is gone
        }
        char path[512] = {0};
        // openat(dirfd, pathname, ...): arg 1 is the path pointer.
        int rc = read_string(req.pid, (unsigned long)req.data.args[1], path, sizeof path);
        if (++seen <= 8) {
            printf("    openat pid=%d path=%s%s\n", req.pid,
                   rc == 0 ? path : "<unreadable>",
                   rc == 0 ? "" : " (process_vm_readv failed)");
        }
        // /etc/hostname is opened by `cat`, i.e. AFTER execve.
        if (rc == 0 && strstr(path, "hostname")) post_exec = 1;

        struct seccomp_notif_resp resp;
        memset(&resp, 0, sizeof resp);
        resp.id = req.id;
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;  // let it really happen
        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) == 0) continued = 1;
    }

    int st = 0;
    waitpid(pid, &st, 0);
    const int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;

    printf("[2] filter survived execve: %s\n", post_exec ? "YES" : "NO");
    printf("[3] read path from stopped process: %s\n", seen ? "YES" : "NO");
    printf("[4] CONTINUE let syscalls proceed: %s\n", continued ? "YES" : "NO");
    printf("    notifications seen: %d\n", seen);
    printf("    workload exit=%d (0 == `cat /etc/hostname` really worked)\n", code);
    printf("\nVERDICT: %s\n",
           (post_exec && continued && code == 0)
               ? "seccomp user-notify is VIABLE for unprivileged T0 observation"
               : "NOT viable as written");
    return 0;
}
