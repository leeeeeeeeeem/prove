// bench-write: syscall micro-benchmarks for the file_permission hook (SPEC 10.3).
// Replaces lmbench's lat_syscall / lat_ctx, which Debian 13 does not package.
//
//   bench-write null N     N one-byte write() calls to /dev/null
//   bench-write read N     N one-byte read() calls from /dev/zero
//   bench-write uinput N   N write() calls of one SYN_REPORT event to a uinput device
//   bench-write pipe N     N round trips of one byte between two processes over pipes
//                          (two context switches, two reads and two writes per round trip)
// Prints nanoseconds per operation.
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/uinput.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}

static void die(const char *what) { perror(what); exit(1); }

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: bench-write null|read|uinput|pipe N\n"); return 64; }
    long n = atol(argv[2]);
    char byte = 0;
    double t0, t1;

    if (!strcmp(argv[1], "null")) {
        int fd = open("/dev/null", O_WRONLY);
        if (fd < 0) die("open");
        t0 = now_ns();
        for (long i = 0; i < n; i++) if (write(fd, &byte, 1) != 1) die("write");
        t1 = now_ns();
    } else if (!strcmp(argv[1], "read")) {
        int fd = open("/dev/zero", O_RDONLY);
        if (fd < 0) die("open");
        t0 = now_ns();
        for (long i = 0; i < n; i++) if (read(fd, &byte, 1) != 1) die("read");
        t1 = now_ns();
    } else if (!strcmp(argv[1], "uinput")) {
        int fd = open("/dev/uinput", O_WRONLY);
        if (fd < 0) die("open /dev/uinput");
        ioctl(fd, UI_SET_EVBIT, EV_KEY);
        ioctl(fd, UI_SET_KEYBIT, KEY_A);
        struct uinput_setup s = { .id = { .bustype = BUS_VIRTUAL } };
        strcpy(s.name, "prove-bench-write");
        if (ioctl(fd, UI_DEV_SETUP, &s) < 0 || ioctl(fd, UI_DEV_CREATE) < 0) die("uinput create");
        struct input_event ev = { .type = EV_SYN, .code = SYN_REPORT };
        t0 = now_ns();
        for (long i = 0; i < n; i++) if (write(fd, &ev, sizeof ev) != sizeof ev) die("write uinput");
        t1 = now_ns();
        ioctl(fd, UI_DEV_DESTROY);
    } else if (!strcmp(argv[1], "pipe")) {
        int a[2], b[2];
        if (pipe(a) || pipe(b)) die("pipe");
        pid_t child = fork();
        if (child == 0) {
            close(a[1]); close(b[0]);
            while (read(a[0], &byte, 1) == 1) if (write(b[1], &byte, 1) != 1) break;
            _exit(0);
        }
        close(a[0]); close(b[1]);
        t0 = now_ns();
        for (long i = 0; i < n; i++) if (write(a[1], &byte, 1) != 1 || read(b[0], &byte, 1) != 1) die("pipe io");
        t1 = now_ns();
        close(a[1]);
        waitpid(child, NULL, 0);
    } else {
        return 64;
    }
    printf("%.1f\n", (t1 - t0) / n);
    return 0;
}
