// libnvme: https://github.com/hgst/libnvme
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LIBNVME_ARCH_H
#define LIBNVME_ARCH_H

#if defined(__x86_64__)

#define NVME_ARCH "x86_64"
#define NVME_ARCH_X86_64 1
#define NVME_ARCH_64 1
#undef  NVME_ARCH_X86
#define NVME_CACHE_LINE_SIZE 64
#define NVME_MMIO_64BIT 1

#elif defined(__i386__)

#define NVME_ARCH "x86"
#undef NVME_ARCH_X86_64
#undef NVME_ARCH_64
#define NVME_ARCH_X86 1
#define NVME_CACHE_LINE_SIZE 64
#undef NVME_MMIO_64BIT

#else

#error "Unsupported architecture type"

#endif

#ifndef asm
#define asm __asm__
#endif

/*
 * Compiler barrier.
 * Guarantees that operation reordering does not occur at compile time
 * for operations directly before and after the barrier.
 */
#define nvme_compiler_barrier() do {        \
    __asm__ volatile ("" : : : "memory");   \
} while(0)

/*
 * General memory barrier.
 * Guarantees that the LOAD and STORE operations generated before the
 * barrier occur before the LOAD and STORE operations generated after.
 * This function is architecture dependent.
 */
#define nvme_mb() __asm__ volatile("mfence" ::: "memory")

/*
 * Write memory barrier.
 * Guarantees that the STORE operations generated before the barrier
 * occur before the STORE operations generated after.
 * This function is architecture dependent.
 */
#define nvme_wmb() __asm__ volatile("sfence" ::: "memory")

/*
 * Read memory barrier.
 * Guarantees that the LOAD operations generated before the barrier
 * occur before the LOAD operations generated after.
 * This function is architecture dependent.
 */
#define nvme_rmb() __asm__ volatile("lfence" ::: "memory")

/*
 * General memory barrier between CPUs.
 * Guarantees that the LOAD and STORE operations that precede the
 * nvme_smp_mb() call are globally visible across the lcores
 * before the the LOAD and STORE operations that follows it.
 */
#define nvme_smp_mb() nvme_mb()

/*
 * Write memory barrier between CPUs.
 * Guarantees that the STORE operations that precede the
 * nvme_smp_wmb() call are globally visible across the lcores
 * before the the STORE operations that follows it.
 */
#define nvme_smp_wmb() nvme_compiler_barrier()

/*
 * Read memory barrier between CPUs.
 * Guarantees that the LOAD operations that precede the
 * nvme_smp_rmb() call are globally visible across the lcores
 * before the the LOAD operations that follows it.
 */
#define nvme_smp_rmb() nvme_compiler_barrier()

/*
 * Get the number of cycles since boot from the default timer.
 */
static inline __u64 nvme_rdtsc(void)
{
    union {
        __u64 tsc_64;
        struct {
            __u32 lo_32;
            __u32 hi_32;
        };
    } tsc;

    asm volatile("rdtsc" :
             "=a" (tsc.lo_32),
             "=d" (tsc.hi_32));
    return tsc.tsc_64;
}

static inline __u32 nvme_mmio_read_4(const volatile __u32 *addr)
{
    return *addr;
}

static inline void nvme_mmio_write_4(volatile __u32 *addr, __u32 val)
{
    *addr = val;
}

static inline __u64 nvme_mmio_read_8(volatile __u64 *addr)
{
#ifdef NVME_MMIO_64BIT
        return *addr;
#else
    volatile __u32 *addr32 = (volatile __u32 *)addr;
    __u64 val;

    /*
     * Read lower 4 bytes before upper 4 bytes.
     * This particular order is required by I/OAT.
     * If the other order is required, use a pair of
     * _nvme_mmio_read_4() calls.
     */
    val = addr32[0];
    val |= (__u64)addr32[1] << 32;

    return val;
#endif
}

static inline void nvme_mmio_write_8(volatile __u64 *addr, __u64 val)
{

#ifdef NVME_MMIO_64BIT
        *addr = val;
#else
    volatile __u32 *addr32 = (volatile __u32 *)addr;

    addr32[0] = (__u32)val;
    addr32[1] = (__u32)(val >> 32);
#endif
}

#endif // LIBNVME_ARCH_H
