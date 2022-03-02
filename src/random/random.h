// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RANDOM_H
#define BITCOIN_RANDOM_H

#include <crypto/chacha20.h>
#include <crypto/common.h>
#include <const/no_instance.h>
#include <uint256.h>
#include <stdint.h>
#include <limits>

namespace latest_crypto {
class CSHA512;
class random : private no_instance {
private:
    enum class RNGLevel {
        FAST, //!< Automatically called by GetRandBytes
        SLOW, //!< Automatically called by GetStrongRandBytes
        SLEEP, //!< Called by RandAddSeedSleep()
    };
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
    static bool g_rdrand_supported;
    static bool g_rdseed_supported;
#endif
    static constexpr bool g_mock_deterministic_tests{false};

private:
    [[noreturn]] static void RandFailure();
    static int64_t GetPerformanceCounter();
    static void GetCPUID(uint32_t leaf, uint32_t subleaf, uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d);
    static void ReportHardwareRand();
    static uint64_t GetRdRand();
    static uint64_t GetRdSeed();
    static void SeedHardwareFast(CSHA512 &hasher);
    static void SeedHardwareSlow(CSHA512 &hasher);
    static void RandAddSeedPerfmon(CSHA512 &hasher);
#ifndef WIN32
    static void GetDevURandom(unsigned char *ent32);
#endif
    static void SeedTimestamp(CSHA512 &hasher);
    static void SeedFast(CSHA512 &hasher);
    static void SeedSlow(CSHA512 &hasher);
    static void SeedSleep(CSHA512 &hasher);
    static void SeedStartup(CSHA512 &hasher);
    static void ProcRand(unsigned char *out, int num, RNGLevel level);

    /* Number of random bytes returned by GetOSRand.
     * When changing this constant make sure to change all call sites, and make
     * sure that the underlying OS APIs for all platforms support the number.
     * (many cap out at 256 bytes).
     */
    static constexpr int NUM_OS_RANDOM_BYTES = 32;

public:
    static void InitHardwareRand(); // called class RNGState

    /**
     * Overall design of the RNG and entropy sources.
     *
     * We maintain a single global 256-bit RNG state for all high-quality randomness.
     * The following (classes of) functions interact with that state by mixing in new
     * entropy, and optionally extracting random output from it:
     *
     * - The GetRand*() class of functions, as well as construction of FastRandomContext objects,
     *   perform 'fast' seeding, consisting of mixing in:
     *   - A stack pointer (indirectly committing to calling thread and call stack)
     *   - A high-precision timestamp (rdtsc when available, c++ high_resolution_clock otherwise)
     *   - 64 bits from the hardware RNG (rdrand) when available.
     *   These entropy sources are very fast, and only designed to protect against situations
     *   where a VM state restore/copy results in multiple systems with the same randomness.
     *   FastRandomContext on the other hand does not protect against this once created, but
     *   is even faster (and acceptable to use inside tight loops).
     *
     * - The GetStrongRand*() class of function perform 'slow' seeding, including everything
     *   that fast seeding includes, but additionally:
     *   - OS entropy (/dev/urandom, getrandom(), ...). The application will terminate if
     *     this entropy source fails.
     *   - Bytes from OpenSSL's RNG (which itself may be seeded from various sources)
     *   - Another high-precision timestamp (indirectly committing to a benchmark of all the
     *     previous sources).
     *   These entropy sources are slower, but designed to make sure the RNG state contains
     *   fresh data that is unpredictable to attackers.
     *
     * - RandAddSeedSleep() seeds everything that fast seeding includes, but additionally:
     *   - A high-precision timestamp before and after sleeping 1ms.
     *   - (On Windows) Once every 10 minutes, performance monitoring data from the OS.
     *   These just exploit the fact the system is idle to improve the quality of the RNG
     *   slightly.
     *
     * On first use of the RNG (regardless of what function is called first), all entropy
     * sources used in the 'slow' seeder are included, but also:
     * - 256 bits from the hardware RNG (rdseed or rdrand) when available.
     * - (On Windows) Performance monitoring data from the OS.
     * - (On Windows) Through OpenSSL, the screen contents.
     *
     * When mixing in new entropy, H = SHA512(entropy || old_rng_state) is computed, and
     * (up to) the first 32 bytes of H are produced as output, while the last 32 bytes
     * become the new RNG state.
    */

    /**
     * Generate random data via the internal PRNG.
     *
     * These functions are designed to be fast (sub microsecond), but do not necessarily
     * meaningfully add entropy to the PRNG state.
     *
     * Thread-safe.
     */
    static void GetRandBytes(unsigned char* buf, int num) { ProcRand(buf, num, RNGLevel::FAST); }
    static uint64_t GetRand(uint64_t nMax) {
        return FastRandomContext(g_mock_deterministic_tests).randrange(nMax);
    }
    static int GetRandInt(int nMax) {
        return GetRand(nMax);
    }
    static uint256 GetRandHash() {
        uint256 hash;
        GetRandBytes((unsigned char *)&hash, sizeof(hash));
        return hash;
    }

    /**
     * Gather entropy from various sources, feed it into the internal PRNG, and
     * generate random data using it.
     *
     * This function will cause failure whenever the OS RNG fails.
     *
     * Thread-safe.
     */
    static void GetStrongRandBytes(unsigned char *buf, int num) { ProcRand(buf, num, RNGLevel::SLOW); }

    /**
     * Sleep for 1ms, gather entropy from various sources, and feed them to the PRNG state.
     *
     * Thread-safe.
     */
    static void RandAddSeedSleep() { ProcRand(nullptr, 0, RNGLevel::SLEEP); }

    /**
     * Fast randomness source. This is seeded once with secure random data, but
     * is completely deterministic and does not gather more entropy after that.
     *
     * Note: This class is NOT thread-safe.
     */
    class FastRandomContext {
    private:
        bool requires_seed;
        ChaCha20 rng;

        unsigned char bytebuf[64];
        int bytebuf_size;

        uint64_t bitbuf;
        int bitbuf_size;

        void RandomSeed();
        void FillByteBuffer();
        void FillBitBuffer();
    public:
        explicit FastRandomContext(bool fDeterministic = false);

        /** Initialize with explicit seed (only for testing) */
        explicit FastRandomContext(const uint256 &seed);

        // Do not permit copying a FastRandomContext (move it, or create a new one to get reseeded).
        FastRandomContext(const FastRandomContext &) = delete;
        FastRandomContext(FastRandomContext &&) = delete;
        FastRandomContext &operator=(const FastRandomContext &&) = delete;

        /** Move a FastRandomContext. If the original one is used again, it will be reseeded. */
        FastRandomContext &operator=(FastRandomContext &&from);

        /** Generate a random 64-bit integer. */
        uint64_t rand64() {
            if (bytebuf_size < 8) FillByteBuffer();
            uint64_t ret = ReadLE64(bytebuf + 64 - bytebuf_size);
            bytebuf_size -= 8;
            return ret;
        }

        /** Generate a random (bits)-bit integer. */
        uint64_t randbits(int bits) {
            if (bits == 0) {
                return 0;
            } else if (bits > 32) {
                return rand64() >> (64 - bits);
            } else {
                if (bitbuf_size < bits) FillBitBuffer();
                uint64_t ret = bitbuf & (~(uint64_t)0 >> (64 - bits));
                bitbuf >>= bits;
                bitbuf_size -= bits;
                return ret;
            }
        }

        /** Generate a random integer in the range [0..range). */
        uint64_t randrange(uint64_t range) {
            --range;
            int bits = CountBits(range);
            while (true) {
                uint64_t ret = randbits(bits);
                if (ret <= range) return ret;
            }
        }

        /** Generate random bytes. */
        std::vector<unsigned char> randbytes(size_t len);

        /** Generate a random 32-bit integer. */
        uint32_t rand32() { return randbits(32); }

        /** generate a random uint256. */
        uint256 rand256();

        /** Generate a random boolean. */
        bool randbool() { return randbits(1); }

        // Compatibility with the C++11 UniformRandomBitGenerator concept
        using result_type = uint64_t;
        static constexpr uint64_t min() { return 0; }
        static constexpr uint64_t max() { return std::numeric_limits<uint64_t>::max(); }
        inline uint64_t operator()() { return rand64(); }
    };

    /** More efficient than using std::shuffle on a FastRandomContext.
     *
     * This is more efficient as std::shuffle will consume entropy in groups of
     * 64 bits at the time and throw away most.
     *
     * This also works around a bug in libstdc++ std::shuffle that may cause
     * type::operator=(type&&) to be invoked on itself, which the library's
     * debug mode detects and panics on. This is a known issue, see
     * https://stackoverflow.com/questions/22915325/avoiding-self-assignment-in-stdshuffle
     */
    template<typename I, typename R>
    static void Shuffle(I first, I last, R &&rng) {
        while (first != last) {
            size_t j = rng.randrange(last - first);
            if (j) {
                using std::swap;
                swap(*first, *(first + j));
            }
            ++first;
        }
    }

    /** Get 32 bytes of system entropy. Do not use this in application code: use
     * GetStrongRandBytes instead.
     */
    static void GetOSRand(unsigned char *ent32);

    /** Check that OS randomness is available and returning the requested number
     * of bytes.
     */
    static bool Random_SanityCheck();

    /**
     * Initialize global RNG state and log any CPU features that are used.
     *
     * Calling this function is optional. RNG state will be initialized when first
     * needed if it is not called.
     */
    static void RandomInit();
};
} // namespace latest_crypto

#endif // BITCOIN_RANDOM_H
