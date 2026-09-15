// Rigorous fd-inheritance probe: read(2) the raw inherited descriptor directly,
// with no path involved at all.
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" int sandbox_init(const char*, unsigned long long, char**);

int main(int argc, char** argv) {
    // Child mode: read(2) from the fd number we were handed.
    if (argc > 1 && std::strcmp(argv[1], "--child") == 0) {
        int fd = std::atoi(argv[2]);
        char buf[64] = {};
        ssize_t n = ::read(fd, buf, sizeof buf - 1);
        if (n > 0) {
            std::printf("  CHILD: read(%d) succeeded -> %s", fd, buf);
            std::puts("  ==> FD_LEAK: inherited descriptor bypasses path policy");
        } else {
            std::printf("  CHILD: read(%d) failed: %s\n", fd, std::strerror(errno));
            std::puts("  ==> no leak via raw descriptor");
        }
        return 0;
    }

    const char* secret = "/tmp/bastion-fd-secret.txt";
    int fd = ::open(secret, O_RDONLY);
    if (fd < 0) { std::perror("open"); return 1; }
    std::printf("parent opened fd=%d on %s BEFORE confinement\n", fd, secret);

    // Confine to a workspace that does NOT include the secret.
    const char* prof =
        "(version 1)(deny default)(allow file-read-metadata)(allow process-fork)"
        "(allow process-exec)(allow file-read* (literal \"/\"))"
        "(allow sysctl-read)(allow mach-lookup)(allow signal (target self))"
        "(allow file-read* (subpath \"/usr/lib\"))"
        "(allow file-read* (subpath \"/private/var/db/dyld\"))"
        "(allow file-read* (subpath \"/System/Library\"))"
        "(allow file-read* (subpath \"/tmp/bastion-fd\"))"
        "(allow file-read* (subpath \"/private/tmp/bastion-fd\"))";
    char* err = nullptr;
    if (sandbox_init(prof, 0, &err) != 0) {
        std::printf("sandbox_init failed: %s\n", err ? err : "?");
        return 2;
    }
    std::puts("confined.");

    // Can WE still read it post-confinement?
    char buf[64] = {};
    ssize_t n = ::read(fd, buf, sizeof buf - 1);
    std::printf("  SELF: read(%d) -> %s\n", fd,
                n > 0 ? "SUCCEEDED (fd rights survive confinement)"
                      : std::strerror(errno));
    ::lseek(fd, 0, SEEK_SET);

    // And can the exec'd child?
    char fdarg[16];
    std::snprintf(fdarg, sizeof fdarg, "%d", fd);
    char* av[] = {argv[0], const_cast<char*>("--child"), fdarg, nullptr};
    ::execv(argv[0], av);
    std::perror("execv");
    return 1;
}
