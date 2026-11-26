// inject-helper: a stand-in for an allow-listed injection tool (a remapper, ydotoold, ...).
// Installed root-owned and listed in allow-inject.toml by tests/fixtures/setup.sh.
//
//   inject-helper pass <fd> <secs>   create a uinput keyboard, send its fd over the unix
//                                    socket <fd> (SCM_RIGHTS), stay alive <secs> seconds
//   inject-helper type <code>        create a uinput keyboard and press key <code> once
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/uinput.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int create_keyboard(void) {
    int fd = open("/dev/uinput", O_WRONLY | O_CLOEXEC);
    if (fd < 0) { printf("open %s\n", strerrorname_np(errno)); exit(1); }
    ioctl(fd, UI_SET_EVBIT, EV_KEY);
    for (int k = 1; k < 128; k++) ioctl(fd, UI_SET_KEYBIT, k);
    struct uinput_setup s = { .id = { .bustype = BUS_USB, .vendor = 0x1234, .product = 0x0001 } };
    strcpy(s.name, "prove-inject-helper");
    if (ioctl(fd, UI_DEV_SETUP, &s) < 0) { printf("setup %s\n", strerrorname_np(errno)); exit(1); }
    if (ioctl(fd, UI_DEV_CREATE) < 0) { printf("create %s\n", strerrorname_np(errno)); exit(1); }
    return fd;
}

static void nap(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static int emit(int fd, int type, int code, int value) {
    struct input_event ev = { .type = type, .code = code, .value = value };
    return write(fd, &ev, sizeof ev) == sizeof ev ? 0 : -1;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 4 && !strcmp(argv[1], "pass")) {
        int sock = atoi(argv[2]);
        int fd = create_keyboard();
        char byte = 'F', ctl[CMSG_SPACE(sizeof(int))] = { 0 };
        struct iovec iov = { &byte, 1 };
        struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = ctl, .msg_controllen = sizeof ctl };
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &fd, sizeof(int));
        if (sendmsg(sock, &msg, 0) < 0) { printf("sendmsg %s\n", strerrorname_np(errno)); return 1; }
        nap(atol(argv[3]) * 1000);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "type")) {
        int fd = create_keyboard(), code = atoi(argv[2]);
        printf("created %d\n", fd);
        nap(300);
        if (emit(fd, EV_KEY, code, 1) || emit(fd, EV_SYN, 0, 0) || emit(fd, EV_KEY, code, 0) || emit(fd, EV_SYN, 0, 0)) {
            printf("write %s\n", strerrorname_np(errno));
            return 1;
        }
        printf("wrote\n");
        nap(300);
        return 0;
    }
    fprintf(stderr, "usage: inject-helper pass <fd> <secs> | type <code>\n");
    return 64;
}
