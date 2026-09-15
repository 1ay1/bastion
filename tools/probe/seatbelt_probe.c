#include <stdio.h>
#include <string.h>
#include <errno.h>

extern int sandbox_init(const char *profile, unsigned long long flags, char **errorbuf);

static void try_open(const char *label, const char *path) {
    errno = 0;
    FILE *f = fopen(path, "r");
    printf("  %-28s %-22s %s\n", label, path,
           f ? "OPEN" : strerror(errno));
    if (f) fclose(f);
}

int main(int argc, char **argv) {
    const char *prof = argv[1];
    char *err = NULL;
    int rc = sandbox_init(prof, 0, &err);
    printf("profile rc=%d err=%s\n", rc, err ? err : "(none)");
    if (rc != 0) return 2;
    try_open("literal target", "/private/etc/hosts");
    try_open("via /etc symlink", "/etc/hosts");
    try_open("unlisted", "/private/etc/passwd");
    return 0;
}
