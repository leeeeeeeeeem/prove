// bench-register N: device registration latency (SPEC 11.3).
// N times: set up a uinput keyboard and time the UI_DEV_CREATE ioctl, which runs
// input_register_device() (and PROVE's fexit program) synchronously. Prints the median in ns.
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/uinput.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}

static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 200;
    double *t = malloc(n * sizeof *t);
    for (long i = 0; i < n; i++) {
        int fd = open("/dev/uinput", O_WRONLY);
        if (fd < 0) { perror("open /dev/uinput"); return 1; }
        ioctl(fd, UI_SET_EVBIT, EV_KEY);
        ioctl(fd, UI_SET_KEYBIT, KEY_A);
        struct uinput_setup s = { .id = { .bustype = BUS_VIRTUAL } };
        strcpy(s.name, "prove-bench-register");
        ioctl(fd, UI_DEV_SETUP, &s);
        double t0 = now_ns();
        if (ioctl(fd, UI_DEV_CREATE) < 0) { perror("UI_DEV_CREATE"); return 1; }
        t[i] = now_ns() - t0;
        ioctl(fd, UI_DEV_DESTROY);
        close(fd);
    }
    qsort(t, n, sizeof *t, cmp);
    printf("%.0f\n", t[n / 2]);
    return 0;
}
