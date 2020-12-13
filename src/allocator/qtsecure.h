// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QT_SECURE_H
#define QT_SECURE_H
#if defined(USE_QUANTUM)  // SorachanCoin-qt.pro

#include <quantum/quantum.h> // mlock(), mprotect(), SecureAllocator and malloc()
#include <cleanse/cleanse.h>
#include <debugcs/debugcs.h>
#include <sync/sync.h>
#include <map>
#include <QString>

// SorachanCoin: QtSecureAllocator
// singleton class
using namespace latest_crypto;
class QtSecureAllocator { // mlock() and OPENSSL_cleanse
    static constexpr size_t s_size = 2048 * 1024;
    static constexpr size_t block = 4096; // eg QtString: larger than passphrase size
private:
    // QtSecureLocked: mlock() and OPENSSL_cleanse
    // QtSecureMalloc: malloc() and OPENSSL_cleanse
    enum SecureStatus {
        SecureLocked,
        SecureMalloc,
        SecureBlank,
    };
    void *p_;
    CCriticalSection cs_;
    std::map<void *, SecureStatus> mapused_;

    QtSecureAllocator() {
        p_ = quantum_lib::secure_malloc(s_size);
        if(p_) {
            if(! quantum_lib::secure_mprotect_readwrite(p_)) // Qt is always R/W.
                throw std::runtime_error("QtSecureAllocator: failed to readwrite memory");
        }
    }
    ~QtSecureAllocator() {
        for(const std::pair<void *, SecureStatus> &obj: mapused_) {
            if(obj.second==SecureMalloc)
                ::free(obj.first);
        }
        if(p_)
            quantum_lib::secure_free(p_);
    }
    QtSecureAllocator(const QtSecureAllocator &)=delete;
    QtSecureAllocator(QtSecureAllocator &&)=delete;
    QtSecureAllocator &operator=(const QtSecureAllocator &)=delete;
    QtSecureAllocator &operator=(QtSecureAllocator &&)=delete;

public:
    void *alloc(size_t size) noexcept { // NG: nullptr
        auto LockedCounter = [](const std::map<void *, SecureStatus> &mapused) {
            size_t counter=0;
            for(const std::pair<void *, SecureStatus> &obj: mapused) {
                if(obj.second==SecureLocked) ++counter;
            }
            return counter;
        };

        LOCK(cs_);

        // 1, mlock() reuse
        if(size <= block) {
            for(const std::pair<void *, SecureStatus> &obj: mapused_) {
                if(obj.second==SecureBlank) {
                    assert(obj.first!=nullptr);
                    mapused_[obj.first] = SecureLocked;
                    return obj.first;
                }
            }
        }
        // 2, new alloc
        if(size <= block && LockedCounter(mapused_) < s_size/block && p_) {
            unsigned char *ptr = (unsigned char *)p_;
            for(size_t i=0; i<s_size/block; ++i) {
                if(mapused_.count((void *)ptr)==0) {
                    mapused_.insert(std::make_pair<void *, SecureStatus>((void *)ptr, SecureLocked));
                    return (void *)ptr;
                }
                ptr += block;
            }
        }
        unsigned char *mp = (unsigned char *)::malloc(size+sizeof(size_t));
        *(size_t *)mp=size;
        mapused_.insert(std::make_pair<void *, SecureStatus>((void *)mp, SecureMalloc));
        return (void *)(mp+sizeof(size_t));
    }

    void free(void *p) noexcept {
        LOCK(cs_);
        if(mapused_.count(p))
            mapused_[p] = SecureBlank;
        else {
            unsigned char *mp = (unsigned char *)p - sizeof(size_t);
            assert(mapused_[mp]==SecureMalloc);
            cleanse::OPENSSL_cleanse(mp+sizeof(size_t), *(size_t *)mp);
            ::free(mp);
            mapused_.erase((void *)mp);
        }
    }

    static QtSecureAllocator &instance() noexcept {
        static QtSecureAllocator obj;
        return obj;
    }
};

class QString_s : public QString {
public:
    void *operator new(size_t size) noexcept {
        debugcs::instance() << "QString_s new size: " << size << debugcs::endl();
        return QtSecureAllocator::instance().alloc(size);
    }
    void *operator new[](size_t size) noexcept {
        debugcs::instance() << "QString_s new[] size: " << size << debugcs::endl();
        return QtSecureAllocator::instance().alloc(size);
    }
    void operator delete(void *p) noexcept {
        debugcs::instance() << "QString_s delete p: " << p << debugcs::endl();
        QtSecureAllocator::instance().free(p);
    }
    void operator delete[](void *p) noexcept {
        debugcs::instance() << "QString_s delete[] p: " << p << debugcs::endl();
        QtSecureAllocator::instance().free(p);
    }
};

#endif // defined(USE_QUANTUM)

#endif
