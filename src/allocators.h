// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2020 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef BITCOIN_ALLOCATORS_H
#define BITCOIN_ALLOCATORS_H

#include <assert.h>
#include <string>
#include <mutex>
#include <map>
#include <openssl/crypto.h> // for OPENSSL_cleanse()

#ifdef WIN32
# ifdef _WIN32_WINNT
#  undef _WIN32_WINNT
# endif
# define _WIN32_WINNT 0x0501
# ifdef WIN32_LEAN_AND_MEAN
#  undef WIN32_LEAN_AND_MEAN
# endif
# define WIN32_LEAN_AND_MEAN 1
# ifndef NOMINMAX
#  define NOMINMAX
# endif
# include <windows.h>
// This is used to attempt to keep keying material out of swap
// Note that VirtualLock does not provide this as a guarantee on Windows,
// but, in practice, memory that has been VirtualLock'd almost never gets written to
// the pagefile except in rare circumstances where memory is extremely low.
#else
# include <sys/mman.h>
# include <limits.h> // for PAGESIZE
# include <unistd.h> // for sysconf
#endif

class allocators_basis
{
    friend class LockedPageManager;

    allocators_basis(); // {}
    allocators_basis(const allocators_basis &); // {}
    allocators_basis(const allocators_basis &&); // {}

private:
    /** Determine system page size in bytes */
    static size_t GetSystemPageSize() {
        size_t page_size;

#if defined(WIN32)
        SYSTEM_INFO sSysInfo;
        ::GetSystemInfo(&sSysInfo);
        page_size = sSysInfo.dwPageSize;
#elif defined(PAGESIZE) // defined in limits.h
        page_size = PAGESIZE;
#else // assume some POSIX OS
        page_size = sysconf(_SC_PAGESIZE);
#endif

        return page_size;
    }

    /**
    * OS-dependent memory page locking/unlocking.
    * Defined as policy class to make stubbing for test possible.
    */
#ifndef WIN32
# if __GNUC__ <= 5
public:
# endif
#endif
    class MemoryPageLocker
    {
    private:
        MemoryPageLocker(const MemoryPageLocker &); // {}
        MemoryPageLocker(const MemoryPageLocker &&); // {}
        MemoryPageLocker &operator=(const MemoryPageLocker &); // {}
        MemoryPageLocker &operator=(const MemoryPageLocker &&); // {}

    public:
        MemoryPageLocker() noexcept {}
        ~MemoryPageLocker() noexcept {}

        //
        // Lock memory pages.
        // addr and len must be a multiple of the system page size
        //
        bool Lock(const void *addr, size_t len) noexcept {
#ifdef WIN32
            return ::VirtualLock(const_cast<void *>(addr), len) != 0;
#else
            return ::mlock(addr, len) == 0;
#endif
        }

        //
        // Unlock memory pages.
        // addr and len must be a multiple of the system page size
        //
        bool Unlock(const void *addr, size_t len) noexcept {
#ifdef WIN32
            return ::VirtualUnlock(const_cast<void *>(addr), len) != 0;
#else
            return ::munlock(addr, len) == 0;
#endif
        }
    };

    /**
    * Thread-safe class to keep track of locked (ie, non-swappable) memory pages.
    *
    * Memory locks do not stack, that is, pages which have been locked several times by calls to mlock()
    * will be unlocked by a single call to munlock(). This can result in keying material ending up in swap when
    * those functions are used naively. This class simulates stacking memory locks by keeping a counter per page.
    *
    * @note By using a map from each page base address to lock count, this class is optimized for
    * small objects that span up to a few pages, mostly smaller than a page. To support large allocations,
    * something like an interval tree would be the preferred data structure.
    */
    template <typename Locker>
    class LockedPageManagerBase
    {
    private:
        LockedPageManagerBase(); // {}
        LockedPageManagerBase(const LockedPageManagerBase &); // {}
        LockedPageManagerBase(const LockedPageManagerBase &&); // {}
        LockedPageManagerBase &operator=(const LockedPageManagerBase &); // {}
        LockedPageManagerBase &operator=(const LockedPageManagerBase &&); // {}

        // map of page base address to lock count; std::make_pair(page, counter)
        typedef std::map<size_t, int> Histogram;
        Histogram histogram;

        Locker locker; // OS-dependent memory page locking/unlocking
        std::mutex mtx;
        size_t page_size, page_mask;

    public:
        LockedPageManagerBase(size_t page_size) noexcept : page_size(page_size) {
            // Determine bitmask for extracting page from address
            assert(! (page_size & (page_size - 1))); // size must be power of two
            page_mask = ~(page_size - 1);
        }
        ~LockedPageManagerBase() noexcept {}

        // For all pages in affected range, increase lock count
        void LockRange(void *p, size_t size) noexcept {
            std::lock_guard<std::mutex> lock(mtx);
            if (! size) {
                return;
            }

            const size_t base_addr = reinterpret_cast<size_t>(p);
            const size_t start_page = base_addr & page_mask;
            const size_t end_page = (base_addr + size - 1) & page_mask;

            for (size_t page = start_page; page <= end_page; page += page_size)
            {
                Histogram::iterator it = histogram.find(page);
                if (it == histogram.end()) { // Newly locked page
                    locker.Lock(reinterpret_cast<void *>(page), page_size);
                    histogram.insert(std::make_pair(page, 1)); // New locked; 1 counter
                } else { // Page was already locked; increase counter
                    it->second += 1;
                }
            }
        }

        // For all pages in affected range, decrease lock count
        void UnlockRange(void *p, size_t size) noexcept {
            std::lock_guard<std::mutex> lock(mtx);
            if (! size) {
                return;
            }

            const size_t base_addr = reinterpret_cast<size_t>(p);
            const size_t start_page = base_addr & page_mask;
            const size_t end_page = (base_addr + size - 1) & page_mask;

            for (size_t page = start_page; page <= end_page; page += page_size)
            {
                Histogram::iterator it = histogram.find(page);
                assert(it != histogram.end()); // Cannot unlock an area that was not locked
                                               // Decrease counter for page, when it is zero, the page will be unlocked
                it->second -= 1;
                if (it->second == 0) { // Nothing on the page anymore that keeps it locked
                                       // Unlock page and remove the count from histogram
                    locker.Unlock(reinterpret_cast<void *>(page), page_size);
                    histogram.erase(it);
                }
            }
        }

        // Get number of locked pages for diagnostics
        int GetLockedPageCount() const noexcept {
            std::lock_guard<std::mutex> lock(mtx);
            return histogram.size();
        }
    };
};

//
// A, Singleton class to keep track of locked (ie, non-swappable) memory pages, for use in
// std::allocator templates.
//
class LockedPageManager : public allocators_basis::LockedPageManagerBase<allocators_basis::MemoryPageLocker>
{
public:
    static LockedPageManager instance; // instantiated in util.cpp
private:
    LockedPageManager() : allocators_basis::LockedPageManagerBase<allocators_basis::MemoryPageLocker>(allocators_basis::GetSystemPageSize()) {}
};

//
// B, Allocator that locks its contents from being paged
// out of memory and clears its contents before deletion.
//
template<typename T>
struct secure_allocator : public std::allocator<T>
{
    typedef std::allocator<T> base;
    typedef typename base::size_type size_type;
    typedef typename base::difference_type  difference_type;
    typedef typename base::pointer pointer;
    typedef typename base::const_pointer const_pointer;
    typedef typename base::reference reference;
    typedef typename base::const_reference const_reference;
    typedef typename base::value_type value_type;

    secure_allocator() throw() {}
    secure_allocator(const secure_allocator &a) throw() : base(a) {}

    template <typename U>
    secure_allocator(const secure_allocator<U> &a) throw() : base(a) {}
    ~secure_allocator() throw() {}

    template<typename _Other> struct rebind
    {
        typedef secure_allocator<_Other> other;
    };

    T *allocate(std::size_t n, const void *hint = 0) {
        T *p = std::allocator<T>::allocate(n, hint);
        if (p != nullptr) {
            LockedPageManager::instance.LockRange(p, sizeof(T) * n);
        }
        return p;
    }

    void deallocate(T *p, std::size_t n) {
        if (p != nullptr) {
            ::OPENSSL_cleanse(p, sizeof(T) * n);
            LockedPageManager::instance.UnlockRange(p, sizeof(T) * n);
        }
        std::allocator<T>::deallocate(p, n);
    }
};


//
// C, Allocator that clears its contents before deletion.
//
template<typename T>
struct zero_after_free_allocator : public std::allocator<T>
{
    typedef std::allocator<T> base;
    typedef typename base::size_type size_type;
    typedef typename base::difference_type  difference_type;
    typedef typename base::pointer pointer;
    typedef typename base::const_pointer const_pointer;
    typedef typename base::reference reference;
    typedef typename base::const_reference const_reference;
    typedef typename base::value_type value_type;

    zero_after_free_allocator() throw() {}
    zero_after_free_allocator(const zero_after_free_allocator& a) throw() : base(a) {}

    template <typename U>
    zero_after_free_allocator(const zero_after_free_allocator<U>& a) throw() : base(a) {}
    ~zero_after_free_allocator() throw() {}

    template<typename _Other> struct rebind
    {
        typedef zero_after_free_allocator<_Other> other;
    };

    void deallocate(T *p, std::size_t n) {
        if (p != nullptr) {
            ::OPENSSL_cleanse(p, sizeof(T) * n);
        }
        std::allocator<T>::deallocate(p, n);
    }
};

// This is exactly like std::string, but with a custom allocator.
//typedef std::basic_string<char, std::char_traits<char>, secure_allocator<char> > SecureString;
class SecureString : public std::basic_string<char, std::char_traits<char>, secure_allocator<char> >
{
public:
    SecureString &operator=(const std::string &obj) {
        *this = obj.c_str();
        return *this;
    }
    SecureString &operator<<(std::string &obj) {
        *this = obj.c_str();
        ::OPENSSL_cleanse(&obj, sizeof(char) * obj.size());
        obj = '\0';
        return *this;
    }
};

#endif
