// bench-latency N: input latency through the kernel input core (SPEC 10.3).
// Creates a uinput keyboard, opens its evdev node, and N times measures the time from just
// before the write() of a key event to the return of the read() that delivers it.
// Run as root (needs the evdev node). Prints "median_ns p99_ns".
#define _GNU_SOURCE
#include <fcntl.h>
#include <glob.h>
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

static void die(const char *what) { perror(what); exit(1); }

int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 10000;
    int ufd = open("/dev/uinput", O_WRONLY);
    if (ufd < 0) die("open /dev/uinput");
    ioctl(ufd, UI_SET_EVBIT, EV_KEY);
    ioctl(ufd, UI_SET_KEYBIT, KEY_A);
    struct uinput_setup s = { .id = { .bustype = BUS_VIRTUAL } };
    strcpy(s.name, "prove-bench-latency");
    if (ioctl(ufd, UI_DEV_SETUP, &s) < 0 || ioctl(ufd, UI_DEV_CREATE) < 0) die("uinput create");

    char sysname[64] = { 0 }, pattern[160];
    if (ioctl(ufd, UI_GET_SYSNAME(sizeof sysname), sysname) < 0) die("UI_GET_SYSNAME");
    snprintf(pattern, sizeof pattern, "/sys/devices/virtual/input/%s/event*", sysname);
    glob_t g;
    if (glob(pattern, 0, NULL, &g) || g.gl_pathc < 1) die("glob event node");
    char node[96];
    snprintf(node, sizeof node, "/dev/input/%s", strrchr(g.gl_pathv[0], '/') + 1);
    int efd = -1;
    for (int tries = 0; tries < 200 && efd < 0; tries++) {  // udev creates the node
        efd = open(node, O_RDONLY);
        if (efd < 0) usleep(10000);
    }
    if (efd < 0) die(node);
    ioctl(efd, EVIOCGRAB, 1);  // keep the events away from the console

    double *lat = malloc(n * sizeof *lat);
    struct input_event out[2] = { { .type = EV_KEY, .code = KEY_A }, { .type = EV_SYN, .code = SYN_REPORT } }, in[4];
    for (long i = 0; i < n; i++) {
        out[0].value = (i & 1) ? 0 : 1;
        double t0 = now_ns();
        if (write(ufd, out, sizeof out) != sizeof out) die("write uinput");
        if (read(efd, in, sizeof in) < (ssize_t)sizeof in[0]) die("read evdev");
        lat[i] = now_ns() - t0;
    }
    qsort(lat, n, sizeof *lat, cmp);
    printf("%.0f %.0f\n", lat[n / 2], lat[n * 99 / 100]);
    ioctl(ufd, UI_DEV_DESTROY);
    return 0;
}
