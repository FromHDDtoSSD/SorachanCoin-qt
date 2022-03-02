// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <random/random.h>
#include <crypto/sha512.h>
#include <cleanse/cleanse.h>

#ifdef WIN32
# include <compat.h> // for Windows API
# include <wincrypt.h>
#endif

#include <util/time.h> // for GetTime()
#include <util.h> // for seed(by OpenSSL)
#include <sync/lsync.h> // for WAIT_LOCK and debugcs (lsync.h: Mutex, sync.h: CWaitableCriticalSection)
#include <stdlib.h>
#include <chrono>
#include <thread>
#include <allocator/allocators.h>

#ifndef WIN32
# include <fcntl.h>
# include <sys/time.h>
#endif

#ifdef HAVE_SYS_GETRANDOM
# include <sys/syscall.h>
# include <linux/random.h>
#endif
#if defined(HAVE_GETENTROPY) || (defined(HAVE_GETENTROPY_RAND) && defined(MAC_OSX))
# include <unistd.h>
#endif
#if defined(HAVE_GETENTROPY_RAND) && defined(MAC_OSX)
# include <sys/random.h>
#endif
#ifdef HAVE_SYSCTL_ARND
# include <util/strencodings.h> // for ARRAYLEN
# include <sys/sysctl.h>
#endif

//#include <mutex>

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
# include <cpuid.h>
#endif

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

namespace latest_crypto {

[[noreturn]] void random::RandFailure() {
    logging::LogPrintf("Failed to read randomness, aborting\n");
    std::abort();
}

int64_t random::GetPerformanceCounter() {
    // Read the hardware time stamp counter when available.
    // See https://en.wikipedia.org/wiki/Time_Stamp_Counter for more information.
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
    return __rdtsc();
#elif !defined(_MSC_VER) && defined(__i386__)
    uint64_t r = 0;
    __asm__ volatile ("rdtsc" : "=A"(r)); // Constrain the r variable to the eax:edx pair.
    return r;
#elif !defined(_MSC_VER) && (defined(__x86_64__) || defined(__amd64__))
    uint64_t r1 = 0, r2 = 0;
    __asm__ volatile ("rdtsc" : "=a"(r1), "=d"(r2)); // Constrain r1 to rax and r2 to rdx.
    return (r2 << 32) | r1;
#else
    // Fall back to using C++11 clock (usually microsecond or nanosecond precision)
    return std::chrono::high_resolution_clock::now().time_since_epoch().count();
#endif
}

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__) // begin [A] macro
bool random::g_rdrand_supported = false;
bool random::g_rdseed_supported = false;
# ifdef bit_RDRND
static constexpr uint32_t CPUID_F1_ECX_RDRAND = 0x40000000;
static_assert(CPUID_F1_ECX_RDRAND == bit_RDRND, "Unexpected value for bit_RDRND");
# endif
# ifdef bit_RDSEED
static constexpr uint32_t CPUID_F7_EBX_RDSEED = 0x00040000;
static_assert(CPUID_F7_EBX_RDSEED == bit_RDSEED, "Unexpected value for bit_RDSEED");
# endif

void random::GetCPUID(uint32_t leaf, uint32_t subleaf, uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    // We can't use __get_cpuid as it doesn't support subleafs.
# ifdef __GNUC__
    __cpuid_count(leaf, subleaf, a, b, c, d);
# else
    __asm__ ("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "0"(leaf), "2"(subleaf));
# endif
}

void random::InitHardwareRand() {
    uint32_t eax, ebx, ecx, edx;
    GetCPUID(1, 0, eax, ebx, ecx, edx);
    if (ecx & CPUID_F1_ECX_RDRAND) {
        g_rdrand_supported = true;
    }
    GetCPUID(7, 0, eax, ebx, ecx, edx);
    if (ebx & CPUID_F7_EBX_RDSEED) {
        g_rdseed_supported = true;
    }
}

void random::ReportHardwareRand() {
    // This must be done in a separate function, as HWRandInit() may be indirectly called
    // from global constructors, before logging is initialized.
    if (g_rdseed_supported) {
        logging::LogPrintf("Using RdSeed as additional entropy source\n");
    }
    if (g_rdrand_supported) {
        logging::LogPrintf("Using RdRand as an additional entropy source\n");
    }
}

/** Read 64 bits of entropy using rdrand.
 *
 * Must only be called when RdRand is supported.
 */
uint64_t random::GetRdRand() {
    // RdRand may very rarely fail. Invoke it up to 10 times in a loop to reduce this risk.
# ifdef __i386__
    uint8_t ok;
    uint32_t r1, r2;
    for (int i = 0; i < 10; ++i) {
        __asm__ volatile (".byte 0x0f, 0xc7, 0xf0; setc %1" : "=a"(r1), "=q"(ok) :: "cc"); // rdrand %eax
        if (ok) break;
    }
    for (int i = 0; i < 10; ++i) {
        __asm__ volatile (".byte 0x0f, 0xc7, 0xf0; setc %1" : "=a"(r2), "=q"(ok) :: "cc"); // rdrand %eax
        if (ok) break;
    }
    return (((uint64_t)r2) << 32) | r1;
# elif defined(__x86_64__) || defined(__amd64__)
    uint8_t ok;
    uint64_t r1;
    for (int i = 0; i < 10; ++i) {
        __asm__ volatile (".byte 0x48, 0x0f, 0xc7, 0xf0; setc %1" : "=a"(r1), "=q"(ok) :: "cc"); // rdrand %rax
        if (ok) break;
    }
    return r1;
# else
#  error "RdRand is only supported on x86 and x86_64"
# endif
}

/** Read 64 bits of entropy using rdseed.
 *
 * Must only be called when RdSeed is supported.
 */
uint64_t random::GetRdSeed() {
    // RdSeed may fail when the HW RNG is overloaded. Loop indefinitely until enough entropy is gathered,
    // but pause after every failure.
# ifdef __i386__
    uint8_t ok;
    uint32_t r1, r2;
    do {
        __asm__ volatile (".byte 0x0f, 0xc7, 0xf8; setc %1" : "=a"(r1), "=q"(ok) :: "cc"); // rdseed %eax
        if (ok) break;
        __asm__ volatile ("pause");
    } while(true);
    do {
        __asm__ volatile (".byte 0x0f, 0xc7, 0xf8; setc %1" : "=a"(r2), "=q"(ok) :: "cc"); // rdseed %eax
        if (ok) break;
        __asm__ volatile ("pause");
    } while(true);
    return (((uint64_t)r2) << 32) | r1;
# elif defined(__x86_64__) || defined(__amd64__)
    uint8_t ok;
    uint64_t r1;
    do {
        __asm__ volatile (".byte 0x48, 0x0f, 0xc7, 0xf8; setc %1" : "=a"(r1), "=q"(ok) :: "cc"); // rdseed %rax
        if (ok) break;
        __asm__ volatile ("pause");
    } while(true);
    return r1;
#else
#error "RdSeed is only supported on x86 and x86_64"
# endif
}

#else // else [A] macro
/* Access to other hardware random number generators could be added here later,
 * assuming it is sufficiently fast (in the order of a few hundred CPU cycles).
 * Slower sources should probably be invoked separately, and/or only from
 * RandAddSeedSleep (which is called during idle background operation).
 */
void random::InitHardwareRand() {}
void random::ReportHardwareRand() {}
#endif // [A] macro

/** Add 64 bits of entropy gathered from hardware to hasher. Do nothing if not supported. */
void random::SeedHardwareFast(CSHA512 &hasher) {
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
    if (g_rdrand_supported) {
        uint64_t out = GetRdRand();
        hasher.Write((const unsigned char *)&out, sizeof(out));
        return;
    }
#endif
}

/** Add 256 bits of entropy gathered from hardware to hasher. Do nothing if not supported. */
void random::SeedHardwareSlow(CSHA512 &hasher) {
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
    // When we want 256 bits of entropy, prefer RdSeed over RdRand, as it's
    // guaranteed to produce independent randomness on every call.
    if (g_rdseed_supported) {
        for (int i = 0; i < 4; ++i) {
            uint64_t out = GetRdSeed();
            hasher.Write((const unsigned char*)&out, sizeof(out));
        }
        return;
    }
    // When falling back to RdRand, XOR the result of 1024 results.
    // This guarantees a reseeding occurs between each.
    if (g_rdrand_supported) {
        for (int i = 0; i < 4; ++i) {
            uint64_t out = 0;
            for (int j = 0; j < 1024; ++j) out ^= GetRdRand();
            hasher.Write((const unsigned char*)&out, sizeof(out));
        }
        return;
    }
#endif
}

void random::RandAddSeedPerfmon(CSHA512 &hasher) {
#ifdef WIN32
    // Don't need this on Linux, OpenSSL automatically uses /dev/urandom
    // Seed with the entire set of perfmon data

    // This can take up to 2 seconds, so only do it every 10 minutes
    static int64_t nLastPerfmon;
    if (util::GetTime() < nLastPerfmon + 10 * 60)
        return;
    nLastPerfmon = util::GetTime();

    std::vector<unsigned char> vData(250000, 0);
    long ret = 0;
    unsigned long nSize = 0;
    const size_t nMaxSize = 10000000; // Bail out at more than 10MB of performance data
    while (true) {
        nSize = vData.size();
        ret = ::RegQueryValueExA(HKEY_PERFORMANCE_DATA, "Global", nullptr, nullptr, vData.data(), &nSize);
        if (ret != ERROR_MORE_DATA || vData.size() >= nMaxSize)
            break;
        vData.resize(std::max((vData.size() * 3) / 2, nMaxSize)); // Grow size of buffer exponentially
    }
    ::RegCloseKey(HKEY_PERFORMANCE_DATA);
    if (ret == ERROR_SUCCESS) {
        hasher.Write(vData.data(), nSize);
        cleanse::memory_cleanse(vData.data(), nSize);
    } else {
        // Performance data is only a best-effort attempt at improving the
        // situation when the OS randomness (and other sources) aren't
        // adequate. As a result, failure to read it is isn't considered critical,
        // so we don't call RandFailure().
        // TODO: Add logging when the logger is made functional before global
        // constructors have been invoked.
    }
#endif
}

#ifndef WIN32
/** Fallback: get 32 bytes of system entropy from /dev/urandom. The most
 * compatible way to get cryptographic randomness on UNIX-ish platforms.
 */
void random::GetDevURandom(unsigned char *ent32) {
    int f = open("/dev/urandom", O_RDONLY);
    if (f == -1) {
        RandFailure();
    }
    int have = 0;
    do {
        ssize_t n = read(f, ent32 + have, NUM_OS_RANDOM_BYTES - have);
        if (n <= 0 || n + have > NUM_OS_RANDOM_BYTES) {
            close(f);
            RandFailure();
        }
        have += n;
    } while (have < NUM_OS_RANDOM_BYTES);
    close(f);
}
#endif

/** Get 32 bytes of system entropy. */
void random::GetOSRand(unsigned char *ent32) {
#if defined(WIN32)
    HCRYPTPROV hProvider;
    int ret = ::CryptAcquireContextW(&hProvider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    if (! ret) {
        RandFailure();
    }
    ret = ::CryptGenRandom(hProvider, NUM_OS_RANDOM_BYTES, ent32);
    if (! ret) {
        RandFailure();
    }
    ::CryptReleaseContext(hProvider, 0);
#elif defined(HAVE_SYS_GETRANDOM)
    /* Linux. From the getrandom(2) man page:
     * "If the urandom source has been initialized, reads of up to 256 bytes
     * will always return as many bytes as requested and will not be
     * interrupted by signals."
     */
    int rv = syscall(SYS_getrandom, ent32, NUM_OS_RANDOM_BYTES, 0);
    if (rv != NUM_OS_RANDOM_BYTES) {
        if (rv < 0 && errno == ENOSYS) {
            /* Fallback for kernel <3.17: the return value will be -1 and errno
             * ENOSYS if the syscall is not available, in that case fall back
             * to /dev/urandom.
             */
            GetDevURandom(ent32);
        } else {
            RandFailure();
        }
    }
#elif defined(HAVE_GETENTROPY) && defined(__OpenBSD__)
    /* On OpenBSD this can return up to 256 bytes of entropy, will return an
     * error if more are requested.
     * The call cannot return less than the requested number of bytes.
       getentropy is explicitly limited to openbsd here, as a similar (but not
       the same) function may exist on other platforms via glibc.
     */
    if (getentropy(ent32, NUM_OS_RANDOM_BYTES) != 0) {
        RandFailure();
    }
#elif defined(HAVE_GETENTROPY_RAND) && defined(MAC_OSX)
    // We need a fallback for OSX < 10.12
    if (&getentropy != nullptr) {
        if (getentropy(ent32, NUM_OS_RANDOM_BYTES) != 0) {
            RandFailure();
        }
    } else {
        GetDevURandom(ent32);
    }
#elif defined(HAVE_SYSCTL_ARND)
    /* FreeBSD and similar. It is possible for the call to return less
     * bytes than requested, so need to read in a loop.
     */
    static const int name[2] = {CTL_KERN, KERN_ARND};
    int have = 0;
    do {
        size_t len = NUM_OS_RANDOM_BYTES - have;
        if (sysctl(name, ARRAYLEN(name), ent32 + have, &len, nullptr, 0) != 0) {
            RandFailure();
        }
        have += len;
    } while (have < NUM_OS_RANDOM_BYTES);
#else
    /* Fall back to /dev/urandom if there is no specific method implemented to
     * get system entropy for this OS.
     */
    GetDevURandom(ent32);
#endif
}

namespace {
class RNGState {
private:
    Mutex m_mutex;
    /* The RNG state consists of 256 bits of entropy, taken from the output of
     * one operation's SHA512 output, and fed as input to the next one.
     * Carrying 256 bits of entropy should be sufficient to guarantee
     * unpredictability as long as any entropy source was ever unpredictable
     * to an attacker. To protect against situations where an attacker might
     * observe the RNG's state, fresh entropy is always mixed when
     * GetStrongRandBytes is called.
     */
    unsigned char m_state[32] GUARDED_BY(m_mutex) = {0};
    uint64_t m_counter GUARDED_BY(m_mutex) = 0;
    bool m_strongly_seeded GUARDED_BY(m_mutex) = false;
    Mutex **m_ppmutexOpenSSL = nullptr;

    static void LockingCallbackOpenSSL(int mode, int i, const char *file, int line) NO_THREAD_SAFETY_ANALYSIS
    {
        DEBUG_LSYNC_CS("called RNGState::LockingCallbackOpenSSL");
        (void)file; (void)line;
        RNGState &rng = RNGState::GetRNGState();
        if (mode & CRYPTO_LOCK)
            rng.GetOpenSSLMutex(i).lock();
        else
            rng.GetOpenSSLMutex(i).unlock();
    }

public:
    RNGState() {
        DEBUG_LSYNC_CS("called RNGState() 1");
        random::InitHardwareRand();

        // Init OpenSSL library multithreading support
        DEBUG_LSYNC_CS("called RNGState() 2");
        m_ppmutexOpenSSL = (Mutex **)OPENSSL_malloc(::CRYPTO_num_locks() * sizeof(Mutex*));
        if(! m_ppmutexOpenSSL)
            throw std::runtime_error("Out of memory: Init OpenSSL library multithreading support");
        for(int i=0; i<::CRYPTO_num_locks(); ++i)
            m_ppmutexOpenSSL[i] = new Mutex;

        DEBUG_LSYNC_CS("called RNGState() 3");
        ::CRYPTO_set_locking_callback(LockingCallbackOpenSSL);

        // OpenSSL can optionally load a config file which lists optional loadable modules and engines.
        // We don't use them so we don't require the config. However some of our libs may call functions
        // which attempt to load the config file, possibly resulting in an exit() or crash if it is missing
        // or corrupt. Explicitly tell OpenSSL not to try to load the file. The result for our libs will be
        // that the config appears to have been loaded and there are no modules/engines available.
        DEBUG_LSYNC_CS("called RNGState() 4");
        ::OPENSSL_no_config();

        /*
         * Moved to the GetRNGState(), because below they call the same RNGState before the RNGState object has created.
         *
#ifdef WIN32
        // Seed random number generator with screen scrape and other hardware sources
        //::RAND_screen(); // if OpenSSL
        DEBUG_LSYNC_CS("called RNGState() 5");
        ::RAND_poll();
#endif

        // Seed random number generator with performance counter
        DEBUG_LSYNC_CS("called RNGState() 6");
        seed::RandAddSeed();
        */
    }

    ~RNGState() {
        DEBUG_LSYNC_CS("called ~RNGState()");
        // Securely erase the memory used by the OpenSSL PRNG
        ::RAND_cleanup();
        // Shutdown OpenSSL library multithreading support
        ::CRYPTO_set_locking_callback(nullptr);

        for (int i=0; i<::CRYPTO_num_locks(); ++i)
            delete m_ppmutexOpenSSL[i];
        OPENSSL_free(m_ppmutexOpenSSL);
    }

    /** Extract up to 32 bytes of entropy from the RNG state, mixing in new entropy from hasher.
     *
     * If this function has never been called with strong_seed = true, false is returned.
     */
    bool MixExtract(unsigned char* out, size_t num, CSHA512 &&hasher, bool strong_seed) {
        assert(num <= 32);
        unsigned char buf[64];
        static_assert(sizeof(buf) == CSHA512::OUTPUT_SIZE, "Buffer needs to have hasher's output size");
        bool ret;
        {
            LOCK(m_mutex);
            ret = (m_strongly_seeded |= strong_seed);
            // Write the current state of the RNG into the hasher
            hasher.Write(m_state, 32);
            // Write a new counter number into the state
            hasher.Write((const unsigned char *)&m_counter, sizeof(m_counter));
            ++m_counter;
            // Finalize the hasher
            hasher.Finalize(buf);
            // Store the last 32 bytes of the hash output as new RNG state.
            std::memcpy(m_state, buf + 32, 32);
        }
        // If desired, copy (up to) the first 32 bytes of the hash output as output.
        if (num) {
            assert(out != nullptr);
            std::memcpy(out, buf, num);
        }
        // Best effort cleanup of internal state
        hasher.Reset();
        cleanse::memory_cleanse(buf, 64);
        return ret;
    }

    //! RNGState: Secure allocator
    // OPENSSL_malloc and OPENSSL_free do NOT fill zero or dummy to object
    // when the time of release.
    void *operator new(size_t size, const std::nothrow_t &) {
        DEBUG_LSYNC_CS("called GetRNGState() new operator");
        unsigned char *p = (unsigned char *)::malloc(size + sizeof(size_t));
        if(! p) return nullptr;
        *((size_t *)p) = size + sizeof(size_t);
        return (void *)(p + sizeof(size_t));
    }
    void *operator new(size_t size)=delete;
    void *operator new[](size_t size)=delete;
    void operator delete(void *p) {
        DEBUG_LSYNC_CS("called GetRNGState() delete operator");
        unsigned char *head = (unsigned char *)p - sizeof(size_t);
        const size_t size = *((size_t *)head);
        cleanse::OPENSSL_cleanse(head, size);
        ::free(head);
    }
    void operator delete[](void *p)=delete;

    static RNGState &GetRNGState() {
        class manage {
        private:
            RNGState *m_ptr;
        public:
            manage() : m_ptr(nullptr) {
                m_ptr = new (std::nothrow) RNGState;
                if(! m_ptr)
                    throw std::runtime_error("Out of memory: RNGState manage()");
            }
            ~manage() {
                if(m_ptr) delete m_ptr;
            }
            RNGState &get() {
                return *m_ptr;
            }
        };

        // This C++11 idiom relies on the guarantee that static variable are initialized
        // on first call, even when multiple parallel calls are permitted.
        DEBUG_LSYNC_CS("called GetRNGState()");
        static manage obj;
        static bool init=false;
        if(! init) {
            init=true;
#ifdef WIN32
            // Seed random number generator with screen scrape and other hardware sources
            //::RAND_screen(); // if OpenSSL
            DEBUG_LSYNC_CS("called RNGState() 5");
            ::RAND_poll();
#endif

            // Seed random number generator with performance counter
            DEBUG_LSYNC_CS("called RNGState() 6");
            seed::RandAddSeed();
        }
        return obj.get();
    }

    Mutex &GetOpenSSLMutex(int i) {
        return *(m_ppmutexOpenSSL[i]);
    }
};

//! SorachanCoin always uses OpenSSL to support older core.
//  Therefore, we need to generate this RNGState first.
static unsigned char g_dummy[10] = {0};
class OpenSSL_startup {
public:
    OpenSSL_startup() {
        unsigned char ch[32] = {0};
        CSHA512 hasher;
        hasher.Write(ch, sizeof(ch));
        RNGState &obj = RNGState::GetRNGState(); // generate RNGState
        obj.MixExtract(g_dummy, sizeof(g_dummy)/sizeof(char) - 1, std::move(hasher), false);
        g_dummy[9] = '\0';
        DEBUG_LSYNC_CS("called OpenSSL_startup()");
    }
};
OpenSSL_startup dummy_openssl;

} // global namespace

/* A note on the use of noexcept in the seeding functions below:
 *
 * None of the RNG code should ever throw any exception, with the sole exception
 * of MilliSleep in SeedSleep, which can (and does) support interruptions which
 * cause a boost::thread_interrupted to be thrown.
 *
 * This means that SeedSleep, and all functions that invoke it are throwing.
 * However, we know that GetRandBytes() and GetStrongRandBytes() never trigger
 * this sleeping logic, so they are noexcept. The same is true for all the
 * GetRand*() functions that use GetRandBytes() indirectly.
 *
 * TODO: After moving away from interruptible boost-based thread management,
 * everything can become noexcept here.
 */

void random::SeedTimestamp(CSHA512 &hasher) {
    int64_t perfcounter = GetPerformanceCounter();
    hasher.Write((const unsigned char *)&perfcounter, sizeof(perfcounter));
}

void random::SeedFast(CSHA512 &hasher) {
    unsigned char buffer[32];

    // Stack pointer to indirectly commit to thread/callstack
    const unsigned char *ptr = buffer;
    hasher.Write((const unsigned char *)&ptr, sizeof(ptr));

    // Hardware randomness is very fast when available; use it always.
    SeedHardwareFast(hasher);

    // High-precision timestamp
    SeedTimestamp(hasher);

    cleanse::OPENSSL_cleanse(buffer, sizeof(buffer));
}

void random::SeedSlow(CSHA512 &hasher) {
    unsigned char buffer[32];

    // Everything that the 'fast' seeder includes
    SeedFast(hasher);

    // OS randomness
    GetOSRand(buffer);
    hasher.Write(buffer, sizeof(buffer));

    // OpenSSL RNG (for now)
    seed::RandAddSeedPerfmon();
    ::RAND_bytes(buffer, sizeof(buffer));
    hasher.Write(buffer, sizeof(buffer));

    // High-precision timestamp.
    //
    // Note that we also commit to a timestamp in the Fast seeder, so we indirectly commit to a
    // benchmark of all the entropy gathering sources in this function).
    SeedTimestamp(hasher);

    cleanse::OPENSSL_cleanse(buffer, sizeof(buffer));
}

void random::SeedSleep(CSHA512 &hasher) {
    // Everything that the 'fast' seeder includes
    SeedFast(hasher);

    // High-precision timestamp
    SeedTimestamp(hasher);

    // Sleep for 1ms
    util::MilliSleep(1);

    // High-precision timestamp after sleeping (as we commit to both the time before and after, this measures the delay)
    SeedTimestamp(hasher);

    // Windows performance monitor data (once every 10 minutes)
    RandAddSeedPerfmon(hasher);
}

void random::SeedStartup(CSHA512 &hasher) {
#ifdef WIN32
    // Seed random number generator with screen scrape and other hardware sources
    //::RAND_screen(); // case OpenSSL
    ::RAND_poll();
#endif

    // Gather 256 bits of hardware randomness, if available
    SeedHardwareSlow(hasher);

    // Everything that the 'slow' seeder includes.
    SeedSlow(hasher);

    // Windows performance monitor data.
    RandAddSeedPerfmon(hasher);
}

void random::ProcRand(unsigned char *out, int num, RNGLevel level) {
    // Make sure the RNG is initialized first (as all Seed* function possibly need hwrand to be available).
    RNGState &rng = RNGState::GetRNGState();
    assert(num <= 32);

    CSHA512 hasher;
    switch (level) {
    case RNGLevel::FAST:
        SeedFast(hasher);
        break;
    case RNGLevel::SLOW:
        SeedSlow(hasher);
        break;
    case RNGLevel::SLEEP:
        SeedSleep(hasher);
        break;
    }

    // Combine with and update state
    if (! rng.MixExtract(out, num, std::move(hasher), false)) {
        // On the first invocation, also seed with SeedStartup().
        CSHA512 startup_hasher;
        SeedStartup(startup_hasher);
        rng.MixExtract(out, num, std::move(startup_hasher), true);
    }

    // For anything but the 'fast' level, feed the resulting RNG output (after an additional hashing step) back into OpenSSL.
    if (level != RNGLevel::FAST) {
        unsigned char buf[64];
        CSHA512().Write(out, num).Finalize(buf);
        ::RAND_add(buf, sizeof(buf), num);
        cleanse::memory_cleanse(buf, 64);
    }
}

void random::FastRandomContext::RandomSeed() {
    uint256 seed = GetRandHash();
    rng.SetKey(seed.begin(), 32);
    requires_seed = false;
}

void random::FastRandomContext::FillByteBuffer() {
    if (requires_seed)
        RandomSeed();

    rng.Output(bytebuf, sizeof(bytebuf));
    bytebuf_size = sizeof(bytebuf);
}

void random::FastRandomContext::FillBitBuffer() {
    bitbuf = rand64();
    bitbuf_size = 64;
}

uint256 random::FastRandomContext::rand256() {
    if (bytebuf_size < 32)
        FillByteBuffer();

    uint256 ret;
    std::memcpy(ret.begin(), bytebuf + 64 - bytebuf_size, 32);
    bytebuf_size -= 32;
    return ret;
}

std::vector<unsigned char> random::FastRandomContext::randbytes(size_t len) {
    if (requires_seed) RandomSeed();
    std::vector<unsigned char> ret(len);
    if (len > 0)
        rng.Output(&ret[0], len);

    return ret;
}

random::FastRandomContext::FastRandomContext(const uint256 &seed) : requires_seed(false), bytebuf_size(0), bitbuf_size(0) {
    rng.SetKey(seed.begin(), 32);
}

bool random::Random_SanityCheck() {
    uint64_t start = GetPerformanceCounter();

    /* This does not measure the quality of randomness, but it does test that
     * OSRandom() overwrites all 32 bytes of the output given a maximum
     * number of tries.
     */
    static constexpr ssize_t MAX_TRIES = 1024;
    uint8_t data[NUM_OS_RANDOM_BYTES];
    bool overwritten[NUM_OS_RANDOM_BYTES] = {}; /* Tracks which bytes have been overwritten at least once */
    int num_overwritten;
    int tries = 0;
    /* Loop until all bytes have been overwritten at least once, or max number tries reached */
    do {
        std::memset(data, 0, NUM_OS_RANDOM_BYTES);
        GetOSRand(data);
        for (int x=0; x < NUM_OS_RANDOM_BYTES; ++x) {
            overwritten[x] |= (data[x] != 0);
        }

        num_overwritten = 0;
        for (int x=0; x < NUM_OS_RANDOM_BYTES; ++x) {
            if (overwritten[x]) {
                num_overwritten += 1;
            }
        }

        tries += 1;
    } while (num_overwritten < NUM_OS_RANDOM_BYTES && tries < MAX_TRIES);
    if (num_overwritten != NUM_OS_RANDOM_BYTES) return false; /* If this failed, bailed out after too many tries */

    // Check that GetPerformanceCounter increases at least during a GetOSRand() call + 1ms sleep.
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    uint64_t stop = GetPerformanceCounter();
    if (stop == start) return false;

    // We called GetPerformanceCounter. Use it as entropy.
    CSHA512 to_add;
    to_add.Write((const unsigned char*)&start, sizeof(start));
    to_add.Write((const unsigned char*)&stop, sizeof(stop));
    RNGState::GetRNGState().MixExtract(nullptr, 0, std::move(to_add), false);

    return true;
}

random::FastRandomContext::FastRandomContext(bool fDeterministic) : requires_seed(!fDeterministic), bytebuf_size(0), bitbuf_size(0) {
    if (! fDeterministic)
        return;
    uint256 seed;
    rng.SetKey(seed.begin(), 32);
}

random::FastRandomContext &random::FastRandomContext::operator=(random::FastRandomContext &&from) {
    requires_seed = from.requires_seed;
    rng = from.rng;
    std::copy(std::begin(from.bytebuf), std::end(from.bytebuf), std::begin(bytebuf));
    bytebuf_size = from.bytebuf_size;
    bitbuf = from.bitbuf;
    bitbuf_size = from.bitbuf_size;
    from.requires_seed = true;
    from.bytebuf_size = 0;
    from.bitbuf_size = 0;
    return *this;
}

void random::RandomInit() {
    // Invoke RNG code to trigger initialization (if not already performed)
    ProcRand(nullptr, 0, RNGLevel::FAST);

    ReportHardwareRand();
}

} // namespace latest_crypto
