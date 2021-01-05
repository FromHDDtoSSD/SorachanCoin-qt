// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LSYNC_H
#define BITCOIN_LSYNC_H

// SorachanCoin: checking ...
// current apply: random.h[random.cpp]
#ifdef LSYNC_DEBUG
# define HAVE_THREAD_LOCAL
# define LDEBUG_LOCKCONTENTION
# define LDEBUG_LOCKORDER
# define DEBUG_LSYNC_CS(str) do {debugcs::instance() << (str) << debugcs::endl();} while(0)
#else
# define DEBUG_LSYNC_CS(str)
#endif

#include <thread/threadsafety.h>
#include <condition_variable>
#include <thread>
#include <mutex>
#include <debugcs/debugcs.h>

/////////////////////////////////////////////////
//                                             //
// THE SIMPLE DEFINITION, EXCLUDING DEBUG CODE //
//                                             //
/////////////////////////////////////////////////

/*
 * Note:
 * LOCK(), LOCK2() ... sync.h (old core),
 * LLOCK(), LLOCK2() ... lsync.h (latest core)
 *
RecursiveMutex mutex;
    std::recursive_mutex mutex;

LLOCK(mutex);
    std::unique_lock<std::recursive_mutex> criticalblock(mutex);

LLOCK2(mutex1, mutex2);
    std::unique_lock<std::recursive_mutex> criticalblock1(mutex1);
    std::unique_lock<std::recursive_mutex> criticalblock2(mutex2);

LTRY_LOCK(mutex, name);
    std::unique_lock<std::recursive_mutex> name(mutex, std::try_to_lock_t);

LENTER_CRITICAL_SECTION(mutex); // no RAII
    mutex.lock();

LLEAVE_CRITICAL_SECTION(mutex); // no RAII
    mutex.unlock();
 */

///////////////////////////////
//                           //
// THE ACTUAL IMPLEMENTATION //
//                           //
///////////////////////////////

#ifdef LDEBUG_LOCKORDER
void LEnterCritical(const char* pszName, const char* pszFile, int nLine, void* cs, bool fTry = false);
void LLeaveCritical();
std::string LLocksHeld();
void LAssertLockHeldInternal(const char* pszName, const char* pszFile, int nLine, void* cs) ASSERT_EXCLUSIVE_LOCK(cs);
void LAssertLockNotHeldInternal(const char* pszName, const char* pszFile, int nLine, void* cs);
void LDeleteLock(void* cs);

/**
 * Call abort() if a potential lock order deadlock bug is detected, instead of
 * just logging information and throwing a logic_error. Defaults to true, and
 * set to false in LDEBUG_LOCKORDER unit tests.
 */
extern bool g_debug_lockorder_abort;
#else
void static inline LEnterCritical(const char* pszName, const char* pszFile, int nLine, void* cs, bool fTry = false) {}
void static inline LLeaveCritical() {}
void static inline LAssertLockHeldInternal(const char* pszName, const char* pszFile, int nLine, void* cs) ASSERT_EXCLUSIVE_LOCK(cs) {}
void static inline LAssertLockNotHeldInternal(const char* pszName, const char* pszFile, int nLine, void* cs) {}
void static inline LDeleteLock(void* cs) {}
#endif
#define LAssertLockHeld(cs) LAssertLockHeldInternal(#cs, __FILE__, __LINE__, &cs)
#define LAssertLockNotHeld(cs) LAssertLockNotHeldInternal(#cs, __FILE__, __LINE__, &cs)

/**
 * Template mixin that adds -Wthread-safety locking annotations and lock order
 * checking to a subset of the mutex API.
 */
template <typename PARENT>
class LOCKABLE AnnotatedMixin : public PARENT
{
public:
    ~AnnotatedMixin() {
        LDeleteLock((void*)this);
    }

    void lock() EXCLUSIVE_LOCK_FUNCTION()
    {
        PARENT::lock();
    }

    void unlock() UNLOCK_FUNCTION()
    {
        PARENT::unlock();
    }

    bool try_lock() EXCLUSIVE_TRYLOCK_FUNCTION(true)
    {
        return PARENT::try_lock();
    }

    using UniqueLock = std::unique_lock<PARENT>;
};

/**
 * Wrapped mutex: supports recursive locking, but no waiting
 * TODO: We should move away from using the recursive lock by default.
 */
using RecursiveMutex = AnnotatedMixin<std::recursive_mutex>;
typedef AnnotatedMixin<std::recursive_mutex> LCCriticalSection;

/** Wrapped mutex: supports waiting but not recursive locking */
typedef AnnotatedMixin<std::mutex> Mutex;

#ifdef LDEBUG_LOCKCONTENTION
void LPrintLockContention(const char* pszName, const char* pszFile, int nLine);
#endif

/** Wrapper around std::unique_lock style lock for Mutex. */
template <typename Mutex, typename Base = typename Mutex::UniqueLock>
class SCOPED_LOCKABLE UniqueLock : public Base
{
private:
    void Enter(const char* pszName, const char* pszFile, int nLine)
    {
        LEnterCritical(pszName, pszFile, nLine, (void*)(Base::mutex()));
#ifdef LDEBUG_LOCKCONTENTION
        if (!Base::try_lock()) {
            LPrintLockContention(pszName, pszFile, nLine);
#endif
            Base::lock();
#ifdef LDEBUG_LOCKCONTENTION
        }
#endif
    }

    bool TryEnter(const char* pszName, const char* pszFile, int nLine)
    {
        LEnterCritical(pszName, pszFile, nLine, (void*)(Base::mutex()), true);
        Base::try_lock();
        if (!Base::owns_lock())
            LLeaveCritical();
        return Base::owns_lock();
    }

public:
    UniqueLock(Mutex& mutexIn, const char* pszName, const char* pszFile, int nLine, bool fTry = false) EXCLUSIVE_LOCK_FUNCTION(mutexIn) : Base(mutexIn, std::defer_lock)
    {
        if (fTry)
            TryEnter(pszName, pszFile, nLine);
        else
            Enter(pszName, pszFile, nLine);
    }

    UniqueLock(Mutex* pmutexIn, const char* pszName, const char* pszFile, int nLine, bool fTry = false) EXCLUSIVE_LOCK_FUNCTION(pmutexIn)
    {
        if (!pmutexIn) return;

        *static_cast<Base*>(this) = Base(*pmutexIn, std::defer_lock);
        if (fTry)
            TryEnter(pszName, pszFile, nLine);
        else
            Enter(pszName, pszFile, nLine);
    }

    ~UniqueLock() UNLOCK_FUNCTION()
    {
        if (Base::owns_lock())
            LLeaveCritical();
    }

    operator bool()
    {
        return Base::owns_lock();
    }
};

template<typename MutexArg>
using DebugLock = UniqueLock<typename std::remove_reference<typename std::remove_pointer<MutexArg>::type>::type>;

#define PASTE(x, y) x ## y
#define PASTE2(x, y) PASTE(x, y)

#define LLOCK(cs) DebugLock<decltype(cs)> PASTE2(criticalblock, __COUNTER__)(cs, #cs, __FILE__, __LINE__)
#define LLOCK2(cs1, cs2)                                               \
    DebugLock<decltype(cs1)> criticalblock1(cs1, #cs1, __FILE__, __LINE__); \
    DebugLock<decltype(cs2)> criticalblock2(cs2, #cs2, __FILE__, __LINE__);
#define LTRY_LOCK(cs, name) DebugLock<decltype(cs)> name(cs, #cs, __FILE__, __LINE__, true)
#define LWAIT_LOCK(cs, name) DebugLock<decltype(cs)> name(cs, #cs, __FILE__, __LINE__)

#define LENTER_CRITICAL_SECTION(cs)                            \
    {                                                         \
        EnterCritical(#cs, __FILE__, __LINE__, (void*)(&cs)); \
        (cs).lock();                                          \
    }

#define LLEAVE_CRITICAL_SECTION(cs) \
    {                              \
        (cs).unlock();             \
        LeaveCritical();           \
    }

class LCSemaphore
{
private:
    std::condition_variable condition;
    std::mutex mutex;
    int value;

public:
    explicit LCSemaphore(int init) : value(init) {}

    void wait()
    {
        std::unique_lock<std::mutex> lock(mutex);
        condition.wait(lock, [&]() { return value >= 1; });
        value--;
    }

    bool try_wait()
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (value < 1)
            return false;
        value--;
        return true;
    }

    void post()
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            value++;
        }
        condition.notify_one();
    }
};

/** RAII-style semaphore lock */
class LCSemaphoreGrant
{
private:
    LCSemaphore *sem;
    bool fHaveGrant;

public:
    void Acquire()
    {
        if (fHaveGrant)
            return;
        sem->wait();
        fHaveGrant = true;
    }

    void Release()
    {
        if (!fHaveGrant)
            return;
        sem->post();
        fHaveGrant = false;
    }

    bool TryAcquire()
    {
        if (!fHaveGrant && sem->try_wait())
            fHaveGrant = true;
        return fHaveGrant;
    }

    void MoveTo(LCSemaphoreGrant &grant)
    {
        grant.Release();
        grant.sem = sem;
        grant.fHaveGrant = fHaveGrant;
        fHaveGrant = false;
    }

    LCSemaphoreGrant() : sem(nullptr), fHaveGrant(false) {}

    explicit LCSemaphoreGrant(LCSemaphore &sema, bool fTry = false) : sem(&sema), fHaveGrant(false)
    {
        if (fTry)
            TryAcquire();
        else
            Acquire();
    }

    ~LCSemaphoreGrant()
    {
        Release();
    }

    operator bool() const
    {
        return fHaveGrant;
    }
};

#endif // BITCOIN_LSYNC_H
