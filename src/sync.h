// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2020 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef BITCOIN_SYNC_H
#define BITCOIN_SYNC_H

#include <mutex>
#include <condition_variable>

/** Wrapped mutex: supports recursive locking, but no waiting */
typedef std::recursive_mutex CCriticalSection;

/** Wrapped mutex: supports waiting but not recursive locking */
typedef std::mutex CWaitableCriticalSection;

#ifdef DEBUG_LOCKORDER
# include <boost/thread/locks.hpp>
# include <boost/thread/tss.hpp>
# include <boost/thread/condition_variable.hpp>
//
// Early deadlock detection
//
// Problem being solved:
//    Thread 1 locks  A, then B, then C
//    Thread 2 locks  D, then C, then A
//     --> may result in deadlock between the two threads, depending on when they run.
// Solution implemented here:
// Keep track of pairs of locks: (A before B), (A before C), etc.
// Complain if any thread tries to lock in a different order.
//
class CLockLocation
{
private:
    CLockLocation(); // {}
    // CLockLocation(const CLockLocation &); // {}
    // CLockLocation(const CLockLocation &&); // {}
    // CLockLocation &operator=(const CLockLocation &); // {}
    // CLockLocation &operator=(const CLockLocation &&); // {}

public:
    explicit CLockLocation(const char *pszName, const char *pszFile, int nLine) {
        mutexName = pszName;
        sourceFile = pszFile;
        sourceLine = nLine;
    }
    std::string ToString() const;
private:
    std::string mutexName;
    std::string sourceFile;
    int sourceLine;
};
typedef std::vector<std::pair<void *, CLockLocation> > LockStack;

class CLockOnTrack
{
private:
    static std::mutex dd_mutex;
    static std::map<std::pair<void *, void *>, LockStack> lockorders;
    static boost::thread_specific_ptr<LockStack> lockstack;

    static void potential_deadlock_detected(const std::pair<void *, void *> &mismatch, const LockStack &s1, const LockStack &s2);
    static void push_lock(void *c, const CLockLocation &locklocation, bool fTry);
    static void pop_lock();
public:
    static void EnterCritical(const char *pszName, const char *pszFile, int nLine, void *cs, bool fTry = false) {
        CLockOnTrack::push_lock(cs, CLockLocation(pszName, pszFile, nLine), fTry);
    }
    static void LeaveCritical() {
        CLockOnTrack::pop_lock();
    }
};
#else
class CLockOnTrack
{
public:
    static void EnterCritical(const char *pszName, const char *pszFile, int nLine, void *cs, bool fTry = false) {}
    static void LeaveCritical() {}
};
#endif
#define EnterCritical CLockOnTrack::EnterCritical
#define LeaveCritical CLockOnTrack::LeaveCritical

#ifdef DEBUG_LOCKCONTENTION
inline void PrintLockContention(const char *pszName, const char *pszFile, int nLine) {
    printf("LOCKCONTENTION: %s\n", pszName);
    printf("Locker: %s:%d\n", pszFile, nLine);
}
#endif

/** Wrapper around boost::unique_lock<Mutex> */
template<typename Mutex>
class CMutexLock
{
private:
    CMutexLock(const CMutexLock &); // {}
    CMutexLock(const CMutexLock &&); // {}
    CMutexLock &operator=(const CMutexLock &); // {}
    CMutexLock &operator=(const CMutexLock &&); // {}

    std::unique_lock<Mutex> lock;

public:
    void Enter(const char *pszName, const char *pszFile, int nLine) {
        if (! lock.owns_lock()) {
            EnterCritical(pszName, pszFile, nLine, (void *)(lock.mutex()));

#ifdef DEBUG_LOCKCONTENTION
            if (! lock.try_lock()) {
                PrintLockContention(pszName, pszFile, nLine);
#endif

                lock.lock();

#ifdef DEBUG_LOCKCONTENTION
            }
#endif

        }
    }

    void Leave() {
        if (lock.owns_lock()) {
            lock.unlock();
            LeaveCritical();
        }
    }

    bool TryEnter(const char *pszName, const char *pszFile, int nLine) {
        if (! lock.owns_lock()) {
            EnterCritical(pszName, pszFile, nLine, (void *)(lock.mutex()), true);
            lock.try_lock();
            if (! lock.owns_lock()) {
                LeaveCritical();
            }
        }
        return lock.owns_lock();
    }

    CMutexLock(Mutex &mutexIn, const char *pszName, const char *pszFile, int nLine, bool fTry = false) : lock(mutexIn, std::defer_lock) {
        if (fTry) {
            TryEnter(pszName, pszFile, nLine);
        } else {
            Enter(pszName, pszFile, nLine);
        }
    }

    ~CMutexLock() {
        if (lock.owns_lock()) {
            LeaveCritical();
        }
    }

    operator bool() {
        return lock.owns_lock();
    }

    std::unique_lock<Mutex> &GetLock() {
        return lock;
    }
};

typedef CMutexLock<CCriticalSection> CCriticalBlock;

#define LOCK(cs) CCriticalBlock criticalblock(cs, #cs, __FILE__, __LINE__)
#define LOCK2(cs1,cs2) CCriticalBlock criticalblock1(cs1, #cs1, __FILE__, __LINE__),criticalblock2(cs2, #cs2, __FILE__, __LINE__)
#define TRY_LOCK(cs,name) CCriticalBlock name(cs, #cs, __FILE__, __LINE__, true)

#define ENTER_CRITICAL_SECTION(cs) \
    { \
        EnterCritical(#cs, __FILE__, __LINE__, (void *)(&cs)); \
        (cs).lock(); \
    }

#define LEAVE_CRITICAL_SECTION(cs) \
    { \
        (cs).unlock(); \
        LeaveCritical(); \
    }

/** Semaphore single lock */
class CSemaphore
{
private:
    CSemaphore(const CSemaphore &); // {}
    CSemaphore(const CSemaphore &&); // {}
    CSemaphore &operator=(const CSemaphore &); // {}
    CSemaphore &operator=(const CSemaphore &&); // {}

    std::condition_variable condition;
    std::mutex mutex;
    int value;

public:
    CSemaphore(int init) : value(init) {}

    void wait() {
        std::unique_lock<std::mutex> lock(mutex);
        while(value < 1)
        {
            condition.wait(lock);
        }
        --value;
    }

    bool try_wait() {
        std::unique_lock<std::mutex> lock(mutex);
        if(value < 1) {
            return false;
        }
        --value;
        return true;
    }

    void post() {
        {
            std::unique_lock<std::mutex> lock(mutex);
            ++value;
        }
        condition.notify_one();
    }
};

/** RAII-style semaphore lock */
class CSemaphoreGrant
{
private:
    CSemaphoreGrant(const CSemaphoreGrant &); // {}
    CSemaphoreGrant(const CSemaphoreGrant &&); // {}
    CSemaphoreGrant &operator=(const CSemaphoreGrant &); // {}
    CSemaphoreGrant &operator=(const CSemaphoreGrant &&); // {}

    CSemaphore *sem;
    bool fHaveGrant;

public:
    void Acquire() {
        if (fHaveGrant) {
            return;
        }
        sem->wait();
        fHaveGrant = true;
    }

    void Release() {
        if (! fHaveGrant) {
            return;
        }
        sem->post();
        fHaveGrant = false;
    }

    bool TryAcquire() {
        if (!fHaveGrant && sem->try_wait()) {
            fHaveGrant = true;
        }
        return fHaveGrant;
    }

    void MoveTo(CSemaphoreGrant &grant) {
        grant.Release();
        grant.sem = sem;
        grant.fHaveGrant = fHaveGrant;

        sem = nullptr;
        fHaveGrant = false;
    }

    CSemaphoreGrant() : sem(nullptr), fHaveGrant(false) {}

    CSemaphoreGrant(CSemaphore &sema, bool fTry = false) : sem(&sema), fHaveGrant(false) {
        if (fTry) {
            TryAcquire();
        } else {
            Acquire();
        }
    }

    ~CSemaphoreGrant() {
        Release();
    }

    operator bool() {
        return fHaveGrant;
    }
};

/** WindowsAPI CRITICAL_SECTION */
# if (_MSC_VER) >= 1900
# include "compat.h"
class sync
{
private:
    sync(const sync &); // {}
    sync &operator=(const sync &); // {}
    mutable CRITICAL_SECTION cs;
public:
    sync() { ::InitializeCriticalSection(&cs); }
    ~sync() { ::DeleteCriticalSection(&cs); }
    void enter() const { ::EnterCriticalSection(&cs); }
    void leave() const { ::LeaveCriticalSection(&cs); }
};
# endif

#endif
