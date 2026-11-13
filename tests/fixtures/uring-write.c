// uring-write <fd> <key code>: submit one IORING_OP_WRITE of a key-down event to an
// inherited uinput fd, using raw io_uring syscalls. Prints "io_uring OK" or the errno name.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/input.h>
#include <linux/io_uring.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 64;
    int fd = atoi(argv[1]);
    struct input_event ev[2] = { { .type = EV_KEY, .code = atoi(argv[2]), .value = 1 }, { .type = EV_SYN } };

    struct io_uring_params p = { 0 };
    int ring = syscall(SYS_io_uring_setup, 4, &p);
    if (ring < 0) { printf("io_uring setup:%s\n", strerrorname_np(errno)); return 2; }
    size_t sq_len = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cq_len = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    char *sq = mmap(NULL, sq_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_SQ_RING);
    char *cq = mmap(NULL, cq_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_CQ_RING);
    struct io_uring_sqe *sqes = mmap(NULL, p.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE,
                                     MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_SQES);
    if (sq == MAP_FAILED || cq == MAP_FAILED || sqes == MAP_FAILED) { printf("io_uring mmap:%s\n", strerrorname_np(errno)); return 2; }

    memset(&sqes[0], 0, sizeof sqes[0]);
    sqes[0].opcode = IORING_OP_WRITE;
    sqes[0].fd = fd;
    sqes[0].addr = (unsigned long)ev;
    sqes[0].len = sizeof ev;
    ((unsigned *)(sq + p.sq_off.array))[0] = 0;
    __atomic_store_n((unsigned *)(sq + p.sq_off.tail), 1, __ATOMIC_RELEASE);

    if (syscall(SYS_io_uring_enter, ring, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0) < 0) {
        printf("io_uring enter:%s\n", strerrorname_np(errno));
        return 2;
    }
    struct io_uring_cqe *cqe = (struct io_uring_cqe *)(cq + p.cq_off.cqes);
    if (cqe->res < 0) { printf("io_uring %s\n", strerrorname_np(-cqe->res)); return 1; }
    printf("io_uring OK\n");
    return 0;
}
