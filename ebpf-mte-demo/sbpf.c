/*
 * To be compiled with -march=armv8.5-a+memtag
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>

/*
 * From arch/arm64/include/uapi/asm/hwcap.h
 */
#define HWCAP2_MTE              (1 << 18)

/*
 * From arch/arm64/include/uapi/asm/mman.h
 */
#define PROT_MTE                 0x20

/*
 * From include/uapi/linux/prctl.h
 */
#define PR_SET_TAGGED_ADDR_CTRL 55
#define PR_GET_TAGGED_ADDR_CTRL 56
# define PR_TAGGED_ADDR_ENABLE  (1UL << 0)
# define PR_MTE_TCF_SHIFT       1
# define PR_MTE_TCF_NONE        (0UL << PR_MTE_TCF_SHIFT)
# define PR_MTE_TCF_SYNC        (1UL << PR_MTE_TCF_SHIFT)
# define PR_MTE_TCF_ASYNC       (2UL << PR_MTE_TCF_SHIFT)
# define PR_MTE_TCF_MASK        (3UL << PR_MTE_TCF_SHIFT)
# define PR_MTE_TAG_SHIFT       3
# define PR_MTE_TAG_MASK        (0xffffUL << PR_MTE_TAG_SHIFT)

/*
 * Insert a random logical tag into the given pointer.
 */
#define insert_random_tag(ptr) ({                       \
        uint64_t __val;                                 \
        asm("irg %0, %1" : "=r" (__val) : "r" (ptr));   \
        __val;                                          \
})

/*
 * Set the allocation tag on the destination address.
 */
#define set_tag(tagged_addr) do {                                      \
        asm volatile("stg %0, [%0]" : : "r" (tagged_addr) : "memory"); \
} while (0)

#define TAG_KERNEL  0b0000
#define TAG_EBPF    0b1111
#define TAG_SHIFT   56

#define ADD_TAG(x, tag) (void*)((long)(x) | ((long)tag << TAG_SHIFT))

uint8_t ld(uint8_t *addr) {
    // printf("[ATTACKER]\ttry to load\t%p\n", addr);
    return *addr;
}

void st(uint8_t *addr, uint8_t val) {
    // printf("[ATTACKER]\ttry to store\t%p with 0x%x\n", addr, val);
    *addr = val;
}

uint8_t ld_s(uint8_t *addr) {
    // printf("[ATTACKER]\ttry to load\t%p\n", addr);
    addr = ADD_TAG(addr, TAG_EBPF);
    printf("[TAG Enforced]\tactual load addr\t%p\n", addr);
    return *addr;
}

int ebpf_set_tag(unsigned char* addr, size_t len, uint8_t tag) {
    addr = ADD_TAG(addr, tag);
    for (size_t offset; offset < len; offset += 16) {
        set_tag(addr + offset);
    }
    return 0;
}

int ebpf_attacker(void* ebpf_dat, void* secret) {

    printf("======================\n"
            "eBPF accessing ebpf data on %p...\n"
           "======================\n" , ebpf_dat);
    printf("Test 0: EBPF accessing non-tagged normal data, without IR instrumentation...\n");
    printf("The data on %p is 0x%x\n", ebpf_dat, ld(ebpf_dat));
    printf("Test 1: EBPF accessing non-tagged normal data, with IR instrumentation...\n");
    printf("The data on %p is 0x%x\n", ebpf_dat, ld_s(ebpf_dat));
    // st(ebpf_dat, 0xff);

    printf("======================\n"
            "eBPF accessing *normal* data on %p...\n"
            "======================\n", secret);
    printf("Test 2: EBPF accessing non-tagged normal data, without IR instrumentation...\n");
    printf("The secret on %p is 0x%x\n", secret, ld(secret));
    printf("Test 3: EBPF accessing non-tagged normal data, with IR instrumentation...\n");
    printf("The secret on %p is 0x%x\n", secret, ld_s(secret));
    // ld(secret);
    // st(secret, 0xff);

    return 0;
}
int main()
{
        unsigned char *a;
        unsigned long page_sz = sysconf(_SC_PAGESIZE);
        unsigned long hwcap2 = getauxval(AT_HWCAP2);
        unsigned char *ebpf_dat, *secret, *tagged_ebpf_dat;

        printf("======================\n"
                "Initialzing ...\n"
               "======================\n");

        /* check if MTE is present */
        if (!(hwcap2 & HWCAP2_MTE))
                return EXIT_FAILURE;

        /*
         * Enable the tagged address ABI, synchronous or asynchronous MTE
         * tag check faults (based on per-CPU preference) and allow all
         * non-zero tags in the randomly generated set.
         */
        // !! QEMU USER MODE DOES NOT RECOGNIZE PR_MTE_TCF_ASYNC!!
        // IF YOU ADD THAT FLAG, QEMU WILL TELL YOU 'Invalid argument'
        if (prctl(PR_SET_TAGGED_ADDR_CTRL,
                  PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC |
                  (0xfffe << PR_MTE_TAG_SHIFT),
                  0, 0, 0)) {
                perror("prctl() failed");
                return EXIT_FAILURE;
        }

        a = mmap(0, page_sz, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (a == MAP_FAILED) {
                perror("mmap() failed");
                return EXIT_FAILURE;
        }

        /*
         * Enable MTE on the above anonymous mmap. The flag could be passed
         * directly to mmap() and skip this step.
         */
        if (mprotect(a, page_sz, PROT_READ | PROT_WRITE | PROT_MTE)) {
                perror("mprotect() failed");
                return EXIT_FAILURE;
        }

        ebpf_dat = a;
        secret = a + 0x100;

        *ebpf_dat = 0x12;
        *secret = 0x34;

        // ebpf_set_tag(ebpf_dat, 0x10, TAG_EBPF);
        tagged_ebpf_dat = ADD_TAG(ebpf_dat, TAG_EBPF);
        set_tag(tagged_ebpf_dat);
        printf("ebpf data on:      \t%p\n", ebpf_dat);
        printf("tagged ebpf data on:\t%p\n", tagged_ebpf_dat);
        printf("normal data on:    \t%p\n", secret);


        ebpf_attacker(tagged_ebpf_dat, secret);



        return 0;
}
