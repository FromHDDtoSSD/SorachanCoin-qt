// libnvme: https://github.com/hgst/libnvme
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LIBNVME_COMMON_H
#define LIBNVME_COMMON_H

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <nvme/nvme.h>
#include <nvme/nvme_arch.h>
#include <util/logging.h>

/*
 * Check if a branch is likely to be taken.
 */
#ifndef likely
#define likely(x)  __builtin_expect((x),1)
#endif /* likely */

/*
 * Check if a branch is unlikely to be taken.
 */
#ifndef unlikely
#define unlikely(x)  __builtin_expect((x),0)
#endif /* unlikely */

#ifndef typeof
#define typeof __typeof__
#endif

/*
 * Macro to evaluate a scalar expression and
 * abort the program if the assertion is false.
 */
#define _nvme_assert_default(exp)    \
    do {                             \
        if (unlikely(!(exp)))        \
            nvme_panic("line %d, assert %s failed\n",    \
                   __LINE__, # exp); \
    } while (0)
#define _nvme_assert_msg(exp, msg)    \
    do {                              \
        if (unlikely(!(exp)))         \
            nvme_panic("%s\n", msg);  \
    } while (0)

#define _NVME_GET_ASSERT_OVERLOAD(_1, _2, NAME, args...) NAME
#define nvme_assert(args...) \
    _NVME_GET_ASSERT_OVERLOAD(args, \
                  _nvme_assert_msg, \
                  _nvme_assert_default) \
                  (args)

/*
 * Macro to return the minimum of two numbers
 */
#define nvme_min(a, b) ({    \
        typeof (a) _a = (a); \
        typeof (b) _b = (b); \
        _a < _b ? _a : _b;   \
    })

/*
 * Macro to return the maximum of two numbers
 */
#define nvme_max(a, b) ({    \
        typeof (a) _a = (a); \
        typeof (b) _b = (b); \
        _a > _b ? _a : _b;   \
    })

namespace nvme {

/*
 * Trim whitespace from a string in place.
 */
extern void nvme_str_trim(char *s);

/*
 * Split string into tokens
 */
extern int nvme_str_split(char *string, int stringlen, char **tokens, int maxtokens, char delim);

/*
 * Converts a numeric string to the equivalent uint64_t value.
 * As well as straight number conversion, also recognises the suffixes
 * k, m and g for kilobytes, megabytes and gigabytes respectively.
 *
 * If a negative number is passed in, zero is returned.
 * Zero is also returned in the case of an error with the
 * strtoull call in the function.
 */
static inline size_t nvme_str2size(const char *str)
{
    unsigned long long size;
    char *endptr;

    while (isspace((int)*str))
        str++;
    if (*str == '-')
        return 0;

    errno = 0;
    size = ::strtoull(str, &endptr, 0);
    if (errno)
        return 0;

    /* Allow 1 space gap between number and unit */
    if (*endptr == ' ')
        endptr++;

    switch (*endptr){
    case 'G':
    case 'g':
        size *= 1024;
        /* Fall through */
    case 'M':
    case 'm':
        size *= 1024;
        /* Fall through */
    case 'K':
    case 'k':
        size *= 1024;
    }

    return size;
}

/*
 * Function to read a single numeric value from a file on the filesystem.
 * Used to read information from files on /sys
 */
extern int nvme_parse_sysfs_value(const char *filename, unsigned long *val);

/*
 * Get a file size in Bytes.
 */
extern uint64_t nvme_file_get_size(int fd);

/*
 * Get a block device block size in Bytes.
 */
extern ssize_t nvme_dev_get_blocklen(int fd);

/*
 * Get current time in nano seconds.
 */
static inline unsigned long long nvme_time_nsec(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);

    return (unsigned long long) ts.tv_sec * 1000000000ULL
        + (unsigned long long) ts.tv_nsec;
}

/*
 * Get current time in micro seconds.
 */
static inline unsigned long long nvme_time_usec(void)
{
    return nvme_time_nsec() / 1000;
}

/*
 * Get current time in milli seconds.
 */
static inline unsigned long long nvme_time_msec(void)
{
    return nvme_time_nsec() / 1000000;
}

/*
 * PAUSE instruction for tight loops (avoid busy waiting)
 */
#ifdef __SSE2__
#include <emmintrin.h>
static inline void nvme_pause(void)
{
    _mm_pause();
}
#else
static inline void nvme_pause(void) {}
#endif

/*
 * Micro-seconds sleep.
 */
static inline void nvme_usleep(int usecs)
{
    struct timeval tv;

    tv.tv_sec = usecs / 1000000;
    tv.tv_usec = usecs % 1000000;
    ::select(0, nullptr, nullptr, nullptr, &tv);
}

/*
 * Milli-seconds sleep.
 */
static inline void nvme_msleep(int msecs)
{
    struct timeval tv;

    tv.tv_sec = msecs / 1000;
    tv.tv_usec = (msecs - tv.tv_sec * 1000) * 1000;
    ::select(0, nullptr, nullptr, nullptr, &tv);
}

/*
 * Provide notification of a critical non-recoverable error and stop.
 */
static inline void nvme_panic(const char *format, const char *args, ...) {
    std::string panic(format);
    panic += " :nvme_panic";
    LogPrintf(panic.c_str(), args);
}

static inline void nvme_err(const char *format, const char *args, ...) {
    std::string panic(format);
    panic += " :nvme_err";
    LogPrintf(panic.c_str(), args);
}

static inline void nvme_log(const char *format, const char *args, ...) {
    LogPrintf(format, args);
}

/*
 * Returns true if n is a power of 2.
 */
static inline int nvme_is_pow2(__u64 v)
{
    return v && !(v & (v - 1));
}

/*
 * Return the power of 2 immediately after v.
 */
static inline __u64 nvme_align_pow2(__u64 v)
{
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;

    return v + 1;
}

/*
 * Calculate log2 of a power of 2 size.
 */
static inline size_t nvme_log2(size_t size)
{
    size_t bits = 0;

        if (!nvme_is_pow2(size))
                return 0;

        while (size >>= 1)
        bits++;

    return bits;
}

/*
 * Handle alignements.
 */
#define nvme_align_down(val, align) \
    ((val) & (~((typeof(val))((align) - 1))))
#define nvme_align_up(val, align) \
    nvme_align_down((val) + (align) - 1, (align))

/*
 * Test a bit value.
 */
static inline int test_bit(__u8 *bitmap, unsigned int bit)
{
        return bitmap[bit >> 3] & (1U << (bit & 0x7));
}

/*
 * Set a bit.
 */
static inline void set_bit(__u8 *bitmap, unsigned int bit)
{
        bitmap[bit >> 3] |= 1U << (bit & 0x7);
}

/*
 * Clear a bit.
 */
static inline void clear_bit(__u8 *bitmap, unsigned int bit)
{
        bitmap[bit >> 3] &= ~(1U << (bit & 0x7));
}

/*
 * Find the first zero bit in a bitmap of size nr_bits.
 * If no zero bit is found, return -1.
 */
static inline int find_first_zero_bit(__u8 *bitmap, unsigned int nr_bits)
{
    __u64 *b = (__u64 *)bitmap;
    unsigned int i, j, bit, count = (nr_bits + 63) >> 6;

    for(i = 0; i < count; i++) {
        if (b[i] != ~0UL)
            break;
    }

    bit = i << 6;
    for (j = bit; j < nr_bits; j++) {
        if (!test_bit(bitmap, j))
            return j;
    }

    return -1;
}

/*
 * Close all open controllers on exit.
 */
extern void nvme_ctrlr_cleanup(void);

} // namespace

#endif
