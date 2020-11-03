// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Core developers
// Copyright (c) 2018-2020 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOIN_PREVECTOR_S_H_
#define _BITCOIN_PREVECTOR_S_H_
#if defined(USE_QUANTUM) && defined(LATEST_CRYPTO_ENABLE)

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <iterator>
#include <vector>
#include <memory>
#include <allocators.h>
#include <debugcs/debugcs.h>
#include <quantum/quantum.h>

#include <compat/compat.h> // IS_TRIVIALLY_CONSTRUCTIBLE

namespace latest_crypto {

template <typename T>
class stack_ptr {
    stack_ptr(); //{}
    stack_ptr(const stack_ptr &); // {}
    stack_ptr(const stack_ptr &&); // {}
    stack_ptr &operator=(const stack_ptr &); // {}
    stack_ptr &operator=(const stack_ptr &&); // {}
    T *ptr;
public:
    explicit stack_ptr(T *pIn) noexcept : ptr(pIn) {}
    operator T &() const noexcept {
        return *ptr;
    }
    T *operator->() const noexcept {
        return ptr;
    }
    ~stack_ptr() {
        ptr->~T();
    }
};

#define IMPLEMENT_MEMORY_READWRITE \
        unsigned char buf[sizeof(memory)]; \
        stack_ptr<memory> pmem(is_direct() ? new(buf) memory(_union.direct): new(buf) memory(_union._s.indirect)); \
        pmem->readwtite();
#define IMPLEMENT_MEMORY_READONLY \
        unsigned char buf[sizeof(memory)]; \
        stack_ptr<memory> pmem(is_direct() ? new(buf) memory(_union.direct): new(buf) memory(_union._s.indirect)); \
        pmem->readonly();
#define IMPLEMENT_MEMORY_SHARED_READWRITE \
        std::shared_ptr<memory> pmem(is_direct() ? new(std::nothrow) memory(_union.direct): new(std::nothrow) memory(_union._s.indirect)); \
        if(pmem == nullptr) {throw std::runtime_error("shared_ptr failed to allocate memory.");} \
        pmem->readwtite();
#define IMPLEMENT_MEMORY_SHARED_READONLY \
        std::shared_ptr<memory> pmem(is_direct() ? new(std::nothrow) memory(_union.direct): new(std::nothrow) memory(_union._s.indirect)); \
        if(pmem == nullptr) {throw std::runtime_error("shared_ptr failed to allocate memory.");} \
        pmem->readonly();
#define IMPLEMENT_MEMORY_SHARED_NONE_READWRITE \
        std::shared_ptr<memory> unused(nullptr);
#define IMPLEMENT_MEMORY_RAW_POINTER \
        raw_pointer ptr((char *)item_ptr(0));
#define IMPLEMENT_MEMORY_CONST_RAW_POINTER \
        const_raw_pointer ptr((const char *)item_ptr(0));
#define IMPLEMENT_MEMORY_RAW_REF(pos) \
        raw_ref ref((char *)item_ptr(0), (pos));
#define IMPLEMENT_MEMORY_CONST_RAW_REF(pos) \
        const_raw_ref ref((const char *)item_ptr(0), (pos));

#pragma pack(push, 1)
/**
 * Implements a drop-in replacement for std::vector<T> which stores up to N
 * elements directly (without heap allocation). The types Size and Diff are used
 * to store element counts, and can be any unsigned + signed type.
 *
 * Storage layout is either:
 * - Direct allocation:
 *   - Size _size: the number of used elements (between 0 and N)
 *   - T direct[N]: an array of N elements of type T
 *     (only the first _size are initialized).
 * - Indirect allocation:
 *   - Size _size: the number of used elements plus N + 1
 *   - Size capacity: the number of allocated elements
 *   - T* indirect: a pointer to an array of capacity elements of type T
 *     (only the first _size are initialized).
 *
*/
template <unsigned int N, typename T, typename Size = uint32_t,
    typename Diff = int32_t>
class prevector_s {
private:
    typedef secure_segment::secure_protect_allocator<T> A;
    class memory {
    private:
        memory(); // {}
        memory(const memory &); // {}
        memory(const memory &&); // {}
        memory &operator=(const memory &); // {}
        memory &operator=(const memory &&); // {}
        char *ptr;
    public:
        template<typename R> memory(R *pIn) noexcept : ptr(reinterpret_cast<char *>(pIn)) {}
        void readonly() const {
            quantum_lib::secure_mprotect_readonly(ptr);
        }
        void readwtite() const {
            quantum_lib::secure_mprotect_readwrite(ptr);
        }
        void noaccess() const {
            quantum_lib::secure_mprotect_noaccess(ptr);
        }
        ~memory() {
            noaccess();
        }
    };

public:
    typedef Size size_type;
    typedef Diff difference_type;
    typedef T value_type;
    typedef value_type &reference;
    typedef const value_type &const_reference;
    typedef value_type *pointer;
    typedef const value_type *const_pointer;

    class iterator {
        T *ptr;
        std::shared_ptr<memory> pmem;

    public:
        typedef Diff difference_type;
        typedef T value_type;
        typedef T *pointer;
        typedef T &reference;
        typedef std::random_access_iterator_tag iterator_category;
        iterator(std::shared_ptr<memory> &pmem_) noexcept : ptr(nullptr), pmem(pmem_) {}
        iterator(T *ptr_, std::shared_ptr<memory> &pmem_) noexcept : ptr(ptr_), pmem(pmem_) {}
        T &operator*() const noexcept { return *ptr; }
        T *operator->() const noexcept { return ptr; }
        T &operator[](size_type pos) noexcept { return ptr[pos]; }
        const T &operator[](size_type pos) const noexcept { return ptr[pos]; }
        iterator &operator++() noexcept {
            ++ptr;
            return *this;
        }
        iterator &operator--() noexcept {
            --ptr;
            return *this;
        }
        iterator operator++(int) noexcept {
            iterator copy(*this);
            ++(*this);
            return copy;
        }
        iterator operator--(int) noexcept {
            iterator copy(*this);
            --(*this);
            return copy;
        }
        difference_type friend operator-(iterator a, iterator b) noexcept {
            return (&(*a) - &(*b));
        }
        iterator operator+(size_type n) noexcept { return iterator(ptr + n, pmem); }
        iterator &operator+=(size_type n) noexcept {
            ptr += n;
            return *this;
        }
        iterator operator-(size_type n) noexcept { return iterator(ptr - n, pmem); }
        iterator &operator-=(size_type n) noexcept {
            ptr -= n;
            return *this;
        }
        bool operator==(iterator x) const noexcept { return ptr == x.ptr; }
        bool operator!=(iterator x) const noexcept { return ptr != x.ptr; }
        bool operator>=(iterator x) const noexcept { return ptr >= x.ptr; }
        bool operator<=(iterator x) const noexcept { return ptr <= x.ptr; }
        bool operator>(iterator x) const noexcept { return ptr > x.ptr; }
        bool operator<(iterator x) const noexcept { return ptr < x.ptr; }
    };

    class reverse_iterator {
        T *ptr;
        std::shared_ptr<memory> pmem;

    public:
        typedef Diff difference_type;
        typedef T value_type;
        typedef T *pointer;
        typedef T &reference;
        typedef std::bidirectional_iterator_tag iterator_category;
        reverse_iterator(std::shared_ptr<memory> pmem_) noexcept : ptr(nullptr), pmem(pmem_) {}
        reverse_iterator(T *ptr_, std::shared_ptr<memory> pmem_) noexcept : ptr(ptr_), pmem(pmem_) {}
        T &operator*() noexcept { return *ptr; }
        const T &operator*() const noexcept { return *ptr; }
        T *operator->() noexcept { return ptr; }
        const T *operator->() const noexcept { return ptr; }
        reverse_iterator &operator--() noexcept {
            ++ptr;
            return *this;
        }
        reverse_iterator &operator++() noexcept {
            --ptr;
            return *this;
        }
        reverse_iterator operator++(int) noexcept {
            reverse_iterator copy(*this);
            ++(*this);
            return copy;
        }
        reverse_iterator operator--(int) noexcept {
            reverse_iterator copy(*this);
            --(*this);
            return copy;
        }
        bool operator==(reverse_iterator x) const noexcept { return ptr == x.ptr; }
        bool operator!=(reverse_iterator x) const noexcept { return ptr != x.ptr; }
    };

    class const_iterator {
        const T *ptr;
        std::shared_ptr<memory> pmem;

    public:
        typedef Diff difference_type;
        typedef const T value_type;
        typedef const T *pointer;
        typedef const T &reference;
        typedef std::random_access_iterator_tag iterator_category;
        const_iterator(std::shared_ptr<memory> pmem_) noexcept : ptr(nullptr), pmem(pmem_) {}
        const_iterator(const T *ptr_, std::shared_ptr<memory> pmem_) noexcept : ptr(ptr_), pmem(pmem_) {}
        const_iterator(iterator x, std::shared_ptr<memory> pmem_) noexcept : ptr(&(*x)), pmem(pmem_) {}
        const T &operator*() const noexcept { return *ptr; }
        const T *operator->() const noexcept { return ptr; }
        const T &operator[](size_type pos) const noexcept { return ptr[pos]; }
        const_iterator &operator++() noexcept {
            ++ptr;
            return *this;
        }
        const_iterator &operator--() noexcept {
            --ptr;
            return *this;
        }
        const_iterator operator++(int) noexcept {
            const_iterator copy(*this);
            ++(*this);
            return copy;
        }
        const_iterator operator--(int) noexcept {
            const_iterator copy(*this);
            --(*this);
            return copy;
        }
        difference_type friend operator-(const_iterator a, const_iterator b) noexcept {
            return (&(*a) - &(*b));
        }
        const_iterator operator+(size_type n) noexcept {
            return const_iterator(ptr + n);
        }
        const_iterator &operator+=(size_type n) noexcept {
            ptr += n;
            return *this;
        }
        const_iterator operator-(size_type n) noexcept {
            return const_iterator(ptr - n);
        }
        const_iterator &operator-=(size_type n) noexcept {
            ptr -= n;
            return *this;
        }
        bool operator==(const_iterator x) const noexcept { return ptr == x.ptr; }
        bool operator!=(const_iterator x) const noexcept { return ptr != x.ptr; }
        bool operator>=(const_iterator x) const noexcept { return ptr >= x.ptr; }
        bool operator<=(const_iterator x) const noexcept { return ptr <= x.ptr; }
        bool operator>(const_iterator x) const noexcept { return ptr > x.ptr; }
        bool operator<(const_iterator x) const noexcept { return ptr < x.ptr; }
    };

    class const_reverse_iterator {
        const T *ptr;
        std::shared_ptr<memory> pmem;

    public:
        typedef Diff difference_type;
        typedef const T value_type;
        typedef const T *pointer;
        typedef const T &reference;
        typedef std::bidirectional_iterator_tag iterator_category;
        const_reverse_iterator(std::shared_ptr<memory> pmem_) noexcept : ptr(nullptr), pmem(pmem_) {}
        const_reverse_iterator(T *ptr_, std::shared_ptr<memory> pmem_) noexcept : ptr(ptr_), pmem(pmem_) {}
        const_reverse_iterator(reverse_iterator x, std::shared_ptr<memory> pmem_) noexcept : ptr(&(*x)), pmem(pmem_) {}
        const T &operator*() const noexcept { return *ptr; }
        const T *operator->() const noexcept { return ptr; }
        const_reverse_iterator &operator--() noexcept {
            ++ptr;
            return *this;
        }
        const_reverse_iterator &operator++() noexcept {
            --ptr;
            return *this;
        }
        const_reverse_iterator operator++(int) noexcept {
            const_reverse_iterator copy(*this);
            ++(*this);
            return copy;
        }
        const_reverse_iterator operator--(int) noexcept {
            const_reverse_iterator copy(*this);
            --(*this);
            return copy;
        }
        bool operator==(const_reverse_iterator x) const noexcept { return ptr == x.ptr; }
        bool operator!=(const_reverse_iterator x) const noexcept { return ptr != x.ptr; }
    };

    typedef class raw_pointer {
        char *ptr;
        raw_pointer(); // {}
        //raw_pointer(const raw_pointer &); // {}
        //raw_pointer(const raw_pointer &&); // {}
        //raw_pointer &operator=(const raw_pointer &); // {}
        //raw_pointer &operator=(const raw_pointer &&); // {}

    public:
        explicit raw_pointer(char *pIn) noexcept : ptr(pIn) {}
        explicit raw_pointer(unsigned char *pIn) noexcept : ptr((char *)pIn) {}
        template <typename R> operator R *() const {
            quantum_lib::secure_mprotect_readwrite(ptr);
            return reinterpret_cast<T *>(ptr);
        }
        ~raw_pointer() {
            quantum_lib::secure_mprotect_noaccess(ptr);
        }
    } rp;

    typedef class raw_ref {
        char *ptr;
        size_type pos;
        raw_ref(); // {}
        //raw_ref(const raw_ref &); // {}
        //raw_ref(const raw_ref &&); // {}
        //raw_ref &operator=(const raw_ref &); // {}
        //raw_ref &operator=(const raw_ref &&); // {}

    public:
        explicit raw_ref(char *pIn, size_type posIn) noexcept : ptr(pIn), pos(posIn) {}
        explicit raw_ref(unsigned char *pIn, size_type posIn) noexcept : ptr((char *)pIn), pos(posIn) {}
        template <typename R> operator R &() const {
            quantum_lib::secure_mprotect_readwrite(ptr);
            R *value = reinterpret_cast<R *>(ptr) + pos;
            return reinterpret_cast<R &>(*value);
        }
        ~raw_ref() {
            quantum_lib::secure_mprotect_noaccess(ptr);
        }
    } rr;

    typedef class const_raw_pointer {
        const char *ptr;
        const_raw_pointer(); // {}
        //const_raw_pointer(const raw_pointer &); // {}
        //const_raw_pointer(const raw_pointer &&); // {}
        //const_raw_pointer &operator=(const const_raw_pointer &); // {}
        //const_raw_pointer &operator=(const const_raw_pointer &&); // {}

    public:
        explicit const_raw_pointer(const char *pIn) noexcept : ptr(pIn) {}
        explicit const_raw_pointer(const unsigned char *pIn) noexcept : ptr((const char *)pIn) {}
        template <typename R> operator const R *() const {
            quantum_lib::secure_mprotect_readonly(ptr);
            return reinterpret_cast<const T *>(ptr);
        }
        ~const_raw_pointer() {
            quantum_lib::secure_mprotect_noaccess(ptr);
        }
    } crp;

    typedef class const_raw_ref {
        const char *ptr;
        size_type pos;
        const_raw_ref(); // {}
        //const_raw_ref(const const_raw_ref &); // {}
        //const_raw_ref(const const_raw_ref &&); // {}
        //const_raw_ref &operator=(const const_raw_ref &); // {}
        //const_raw_ref &operator=(const const_raw_ref &&); // {}

    public:
        explicit const_raw_ref(const char *pIn, size_type posIn) noexcept : ptr(pIn), pos(posIn) {}
        explicit const_raw_ref(const unsigned char *pIn, size_type posIn) noexcept : ptr((const char *)pIn), pos(posIn) {}
        template <typename R> operator const R &() const {
            quantum_lib::secure_mprotect_readonly(ptr);
            R *value = reinterpret_cast<R *>(ptr) + pos;
            return reinterpret_cast<R &>(*value);
        }
        ~const_raw_ref() {
            quantum_lib::secure_mprotect_noaccess(ptr);
        }
    } crr;

private:
    size_type _size;
    std::vector<unsigned char, A> *_invch;
    struct direct_or_indirect {
        char *direct;
        struct {
            size_type capacity;
            unsigned char *indirect;
        } _s;
        direct_or_indirect() noexcept {
            direct = nullptr;
        }
    } _union;

    void direct_alloc() {
        if(!_union.direct) {
            _union.direct = static_cast<char *>(quantum_lib::secure_malloc(sizeof(T) * N));
        }
        quantum_lib::secure_mprotect_noaccess(_union.direct);
    }
    void direct_free() noexcept {
        quantum_lib::secure_mprotect_readwrite(_union.direct);
        quantum_lib::secure_free(_union.direct);
        _union.direct = nullptr;
    }

    T *direct_ptr(difference_type pos) noexcept {
        return reinterpret_cast<T *>(_union.direct) + pos;
    }
    const T *direct_ptr(difference_type pos) const noexcept {
        return reinterpret_cast<const T *>(_union.direct) + pos;
    }
    T *indirect_ptr(difference_type pos) noexcept {
        return reinterpret_cast<T *>(_union._s.indirect) + pos;
    }
    const T *indirect_ptr(difference_type pos) const noexcept {
        return reinterpret_cast<const T *>(_union._s.indirect) + pos;
    }
    bool is_direct() const noexcept { return _size <= N; }

    void change_capacity(size_type new_capacity) {
        DEBUGCS_OUTPUT("prevector_s: void change_capacity(size_type new_capacity)");
        if(new_capacity <= N) {
            if(! is_direct()) {
                memory dm(_union.direct);
                dm.readwtite();
                quantum_lib::secure_mprotect_readwrite(_union._s.indirect);
                T *indirect = indirect_ptr(0);
                T *src = indirect;
                T *dst = direct_ptr(0);
                ::memcpy(dst, src, size() * sizeof(T));
                delete _invch;
                _invch = nullptr;
                _union._s.indirect = nullptr;
                _size -= N + 1;
            }
        } else {
            if(! is_direct()) {
                // FIXME: Because malloc/realloc here won't call new_handler if
                // allocation fails, assert success. These should instead use an
                // allocator or new/delete so that handlers are called as
                // necessary, but performance would be slightly degraded by
                // doing so.
                //
                // FIXED: Assign here std::vector instead of malloc/realloc and
                // increase N to avoid using this re-allocation as much possible.
                quantum_lib::secure_mprotect_readwrite(_union._s.indirect);
                _invch->resize((size_t)sizeof(T) * new_capacity);
                _union._s.indirect = &_invch->at(0);
                _union._s.capacity = new_capacity;
                quantum_lib::secure_mprotect_noaccess(_union._s.indirect);
            } else {
                _invch = new(std::nothrow) std::vector<unsigned char, A>();
                if(! _invch) {
                    throw std::runtime_error("prevector_s failed to allocate memory.");
                }
                _invch->resize((size_t)sizeof(T) * new_capacity);
                T *src = direct_ptr(0);
                T *dst = reinterpret_cast<T *>(&_invch->at(0));
                quantum_lib::secure_mprotect_readonly(src);
                ::memcpy(dst, src, size() * sizeof(T));
                quantum_lib::secure_mprotect_noaccess(src);
                _union._s.indirect = &_invch->at(0);
                _union._s.capacity = new_capacity;
                quantum_lib::secure_mprotect_noaccess(_union._s.indirect);
                _size += N + 1;
            }
        }
    }

    T *item_ptr(difference_type pos) noexcept {
        return is_direct() ? direct_ptr(pos) : indirect_ptr(pos);
    }
    const T *item_ptr(difference_type pos) const noexcept {
        return is_direct() ? direct_ptr(pos) : indirect_ptr(pos);
    }

    template <typename InputIterator>
    void copy(size_type pcur, InputIterator first, InputIterator last, size_type n) noexcept {
        //IMPLEMENT_MEMORY_READWRITE
        if(IS_TRIVIALLY_CONSTRUCTIBLE<T>::value) {
            ::memcpy(item_ptr(pcur), &(*first), n * sizeof(T));
            _size += n;
        } else {
            while(first != last)
            {
                new (static_cast<void *>(item_ptr(pcur++))) T(*first);
                ++_size;
                ++first;
            }
        }
    }

    void fill(size_type pcur, const T &val, size_type n) noexcept {
        //IMPLEMENT_MEMORY_READWRITE
        if(IS_TRIVIALLY_CONSTRUCTIBLE<T>::value) {
            const int *_val = reinterpret_cast<const int *>(&val);
            ::memset(item_ptr(pcur), *_val, n * sizeof(T));
            _size += n;
        } else {
            while(pcur < n)
            {
                new (static_cast<void *>(item_ptr(pcur++))) T(val);
                ++_size;
            }
        }
    }

public:
    void assign(size_type n, const T &val) {
        DEBUGCS_OUTPUT("prevector_s: void assign(size_type n, const T &val)");
        clear();
        if(capacity() < n) {
            change_capacity(n);
        }
        {
            IMPLEMENT_MEMORY_READWRITE
            fill(size(), val, n);
        }
    }

    template <typename InputIterator>
    void assign(InputIterator first, InputIterator last) {
        DEBUGCS_OUTPUT("prevector_s: void assign(InputIterator first, InputIterator last)");
        size_type n = last - first;
        clear();
        if(capacity() < n) {
            change_capacity(n);
        }
        {
            IMPLEMENT_MEMORY_READWRITE
            copy(size(), first, last, n);
        }
    }

    prevector_s() : _size(0), _invch(nullptr) {
        DEBUGCS_OUTPUT("prevector_s: prevector_s()");
        direct_alloc();
    }

    explicit prevector_s(size_type n) : _size(0), _invch(nullptr) {
        DEBUGCS_OUTPUT("prevector_s: explicit prevector_s(size_type n)");
        direct_alloc();
        resize(n);
    }

    //explicit prevector(size_type n, const T &val = T()) : _size(0), _invch(nullptr) { // FIXED: overload ambiguous
    explicit prevector_s(size_type n, const T &val) : _size(0), _invch(nullptr) {
        DEBUGCS_OUTPUT("prevector_s: prevector_s(size_type n, const T &val)");
        direct_alloc();
        change_capacity(n);
        {
            IMPLEMENT_MEMORY_READWRITE
            fill(size(), val, n);
        }
    }

    template <typename InputIterator>
    prevector_s(InputIterator first, InputIterator last) : _size(0), _invch(nullptr) {
        DEBUGCS_OUTPUT("prevector_s: prevector_s(InputIterator first, InputIterator last)");
        direct_alloc();
        const size_type n = last - first;
        change_capacity(n);
        {
            IMPLEMENT_MEMORY_READWRITE
            copy(size(), first, last, n);
        }
    }

    prevector_s(const prevector_s<N, T, Size, Diff> &other) : _size(0), _invch(nullptr) {
        DEBUGCS_OUTPUT("prevector_s: prevector_s(const prevector_s<N, T, Size, Diff> &other)");
        direct_alloc();
        change_capacity(other.size());
        {
            IMPLEMENT_MEMORY_READWRITE
            copy(size(), other.begin(), other.end(), other.size());
        }
    }

    prevector_s(prevector_s<N, T, Size, Diff> &&other) noexcept : _size(0), _invch(nullptr) {
        DEBUGCS_OUTPUT("prevector_s: prevector_s(prevector_s<N, T, Size, Diff> &&other) noexcept");
        direct_alloc();
        swap(other);
    }

    prevector_s &operator=(const prevector_s<N, T, Size, Diff> &other) {
        DEBUGCS_OUTPUT("prevector_s: prevctor_s &operator=(const prevector_s<N, T, Size, Diff> &other)");
        if(&other == this) {
            return *this;
        }
        direct_alloc();
        resize(0);
        change_capacity(other.size());
        {
            IMPLEMENT_MEMORY_READWRITE
            copy(size(), other.begin(), other.end(), other.size());
        }
        return *this;
    }

    prevector_s &operator=(prevector_s<N, T, Size, Diff> &&other) noexcept {
        DEBUGCS_OUTPUT("prevector_s: prevector_s &operator=(prevector_s<N, T, Size, Diff> &&other) noexcept");
        swap(other);
        return *this;
    }

    size_type size() const noexcept {
        DEBUGCS_OUTPUT("prevector_s:size_type size() const noexcept");
        return is_direct() ? _size : _size - N - 1;
    }

    bool empty() const noexcept {
        DEBUGCS_OUTPUT("prevector_s: bool empty() const");
        return (size() == 0);
    }

    iterator begin() {
        DEBUGCS_OUTPUT("prevector_s: iterator begin()");
        IMPLEMENT_MEMORY_SHARED_READWRITE
        return iterator(item_ptr(0), pmem);
    }
    const_iterator begin() const {
        DEBUGCS_OUTPUT("prevector_s: const_iterator begin() const");
        IMPLEMENT_MEMORY_SHARED_READONLY
        return const_iterator(item_ptr(0), pmem);
    }
    iterator end() noexcept {
        DEBUGCS_OUTPUT("prevector_s: iterator end() noexcept");
        IMPLEMENT_MEMORY_SHARED_NONE_READWRITE
        return iterator(item_ptr(size()), unused);
    }
    const_iterator end() const noexcept {
        DEBUGCS_OUTPUT("prevector_s: const_iterator end() const noexcept");
        IMPLEMENT_MEMORY_SHARED_NONE_READWRITE
        return const_iterator(item_ptr(size()), unused);
    }

    reverse_iterator rbegin() {
        DEBUGCS_OUTPUT("prevector_s: reverse_iterator rbegin()");
        IMPLEMENT_MEMORY_SHARED_READWRITE
        return reverse_iterator(item_ptr(size() - 1), pmem);
    }
    const_reverse_iterator rbegin() const {
        DEBUGCS_OUTPUT("prevector_s: const_reverse_iterator rbegin() const");
        IMPLEMENT_MEMORY_SHARED_READONLY
        return const_reverse_iterator(item_ptr(size() - 1), pmem);
    }
    reverse_iterator rend() noexcept {
        DEBUGCS_OUTPUT("prevector_s: rend() noexcept");
        IMPLEMENT_MEMORY_SHARED_NONE_READWRITE
        return reverse_iterator(item_ptr(-1), unused);
    }
    const_reverse_iterator rend() const noexcept {
        DEBUGCS_OUTPUT("prevector_s: const_reverse_iterator rend() const noexcept");
        IMPLEMENT_MEMORY_SHARED_NONE_READWRITE
        return const_reverse_iterator(item_ptr(-1), unused);
    }

    size_t capacity() const noexcept {
        DEBUGCS_OUTPUT("prevector_s: size_t capacity() const noexcept");
        if(is_direct()) {
            return N;
        } else {
            return _union._s.capacity;
        }
    }

    raw_ref operator[](size_type pos) noexcept {
        DEBUGCS_OUTPUT("prevector_s: ref_raw operator[](size_type pos) noexcept");
        IMPLEMENT_MEMORY_RAW_REF(pos)
        return ref;
    }

    const_raw_ref operator[](size_type pos) const noexcept {
        DEBUGCS_OUTPUT("prevector_s: const_raw_ref operator[](size_type pos) const noexcept");
        IMPLEMENT_MEMORY_CONST_RAW_REF(pos)
        return ref;
    }

    void resize(size_type new_size, const T &val = T()) {
        DEBUGCS_OUTPUT("prevector_s: void resize(size_type new_size, const T &val = T())");
        const size_type cur_size = size();
        if(cur_size == new_size) {
            return;
        }
        if(cur_size > new_size) {
            IMPLEMENT_MEMORY_SHARED_READWRITE
            iterator ite(item_ptr(new_size), pmem);
            erase(ite, end());
            return;
        }
        if(new_size > capacity()) {
            change_capacity(new_size);
        }
        size_type increase = new_size - cur_size;
        {
            IMPLEMENT_MEMORY_READWRITE
            fill(cur_size, val, increase);
        }
    }

    void reserve(size_type new_capacity) {
        DEBUGCS_OUTPUT("prevector_s: void reserve(size_type new_capacity)");
        if(new_capacity > capacity()) {
            change_capacity(new_capacity);
        }
    }

    void shrink_to_fit() {
        DEBUGCS_OUTPUT("prevector_s: void shrink_to_fit()");
        change_capacity(size());
    }

    void clear() {
        DEBUGCS_OUTPUT("prevector_s: void clear()");
        resize(0);
    }

    iterator insert(iterator pos, const T &value) {
        DEBUGCS_OUTPUT("prevector_s: itertaor insert(iterator pos, const T &value)");
        size_type p = pos - begin();
        size_type new_size = size() + 1;
        if(capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        {
            IMPLEMENT_MEMORY_READWRITE
            ::memmove(item_ptr(p + 1), item_ptr(p), (size() - p) * sizeof(T));
            ++_size;
            new (static_cast<void *>(item_ptr(p))) T(value);
        }
        IMPLEMENT_MEMORY_SHARED_READWRITE
        return iterator(item_ptr(p), pmem);
    }

    void insert(iterator pos, size_type count, const T &value) {
        DEBUGCS_OUTPUT("prevector_s: void insert(iterator pos, size_type count, const T &value)");
        size_type p = pos - begin();
        size_type new_size = size() + count;
        if(capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        {
            IMPLEMENT_MEMORY_READWRITE
            ::memmove(item_ptr(p + count), item_ptr(p), (size() - p) * sizeof(T));
            fill(p, value, count);
        }
    }

    template <typename InputIterator>
    void insert(iterator pos, InputIterator first, InputIterator last) {
        DEBUGCS_OUTPUT("prevector_s: void insert(iterator pos, InputIterator first, InputIterator last)");
        size_type p = pos - begin();
        difference_type count = last - first;
        size_type new_size = size() + count;
        if(capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        {
            IMPLEMENT_MEMORY_READWRITE
            ::memmove(item_ptr(p + count), item_ptr(p), (size() - p) * sizeof(T));
            copy(p, first, last, count);
        }
    }

    iterator erase(iterator pos) noexcept {
        DEBUGCS_OUTPUT("prevector_s: iterator erase(iterator pos) noexcept");
        return erase(pos, pos + 1);
    }

    iterator erase(iterator first, iterator last) noexcept {
        DEBUGCS_OUTPUT("prevector_s: iterator erase(iterator first, iterator last) noexcept");
        iterator p = first;
        char *endp = (char *)&(*end());
        if(!IS_TRIVIALLY_CONSTRUCTIBLE<T>::value) {
            while(p != last)
            {
                (*p).~T();
                --_size;
                ++p;
            }
        } else {
            _size -= last - p;
        }
        {
            IMPLEMENT_MEMORY_READWRITE
            ::memmove(&(*first), &(*last), endp - ((char *)(&(*last))));
        }
        return first;
    }

    void push_back(const T &value) {
        DEBUGCS_OUTPUT("prevector_s: void push_back(const T &value)");
        size_type new_size = size() + 1;
        if(capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        {
            IMPLEMENT_MEMORY_READWRITE
            new (item_ptr(size())) T(value);
        }
        ++_size;
    }

    void pop_back() noexcept {
        DEBUGCS_OUTPUT("prevector_s: void pop_back() noexcept");
        erase(end() - 1, end());
    }

    raw_ref front() noexcept {
        DEBUGCS_OUTPUT("prevector_s: raw_ref front() noexcept");
        IMPLEMENT_MEMORY_RAW_REF(0)
        return ref;
    }

    const_raw_ref front() const noexcept {
        DEBUGCS_OUTPUT("prevector_s: const_raw_ref front() const noexcept");
        IMPLEMENT_MEMORY_CONST_RAW_REF(0)
        return ref;
    }

    raw_ref back() noexcept {
        DEBUGCS_OUTPUT("prevector_s: raw_ref back() noexcept");
        IMPLEMENT_MEMORY_RAW_REF(size() - 1)
        return ref;
    }

    const_raw_ref back() const noexcept {
        DEBUGCS_OUTPUT("prevector_s: const_raw_ref back() const noexcept");
        IMPLEMENT_MEMORY_CONST_RAW_REF(size() - 1)
        return ref;
    }

    void swap(prevector<N, T, Size, Diff> &other) noexcept {
        DEBUGCS_OUTPUT("prevector_s: swap(prevector<N, T, Size, Diff> &other)");
        std::swap(_union, other._invch);
        std::swap(_union, other._union);
        std::swap(_size, other._size);
    }

    ~prevector_s() noexcept {
        DEBUGCS_OUTPUT("prevector_s: ~prevector_s() noexcept");
        if(! IS_TRIVIALLY_CONSTRUCTIBLE<T>::value) {
            clear();
        }
        if(! is_direct()) {
            quantum_lib::secure_mprotect_readwrite(_union._s.indirect);
            delete _invch;
            _invch = nullptr;
            _union._s.indirect = nullptr;
        }
        direct_free();
    }

    bool operator==(const prevector<N, T, Size, Diff> &other) const noexcept {
        DEBUGCS_OUTPUT("prevector_s: bool operator==(const prevector<N, T, Size, Diff> &other) const noexcept");
        if(other.size() != size()) {
            return false;
        }
        const_iterator b1 = begin();
        const_iterator b2 = other.begin();
        const_iterator e1 = end();
        while(b1 != e1)
        {
            if((*b1) != (*b2)) {
                return false;
            }
            ++b1;
            ++b2;
        }
        return true;
    }

    bool operator!=(const prevector<N, T, Size, Diff> &other) const noexcept {
        DEBUGCS_OUTPUT("prevector_s: bool operator!=(const prevector<N, T, Size, Diff> &other) const noexcept");
        return !(*this == other);
    }

    bool operator<(const prevector<N, T, Size, Diff> &other) const noexcept {
        DEBUGCS_OUTPUT("prevector_s: bool operator<(const prevector<N, T, Size, Diff> &other) const noexcept");
        if(size() < other.size()) {
            return true;
        }
        if(size() > other.size()) {
            return false;
        }
        const_iterator b1 = begin();
        const_iterator b2 = other.begin();
        const_iterator e1 = end();
        while(b1 != e1)
        {
            if((*b1) < (*b2)) {
                return true;
            }
            if((*b2) < (*b1)) {
                return false;
            }
            ++b1;
            ++b2;
        }
        return false;
    }

    bool operator>(const prevector<N, T, Size, Diff> &other) const noexcept {
        DEBUGCS_OUTPUT("prevector_s: bool operator>(const prevector<N, T, Size, Diff> &other) const noexcept");
        return ((!operator<(other)) && (!operator==(other)));
    }

    size_t allocated_memory() const noexcept {
        DEBUGCS_OUTPUT("prevector_s: size_t allocated_memory() const noexcept");
        if(is_direct()) {
            return 0;
        } else {
            return ((size_t)(sizeof(T))) * _union._s.capacity;
        }
    }

    raw_pointer data() noexcept {
        DEBUGCS_OUTPUT("prevector_s: raw_pointer data() noexcept");
        IMPLEMENT_MEMORY_RAW_POINTER
        return ptr;
    }

    const_raw_pointer data() const noexcept {
        DEBUGCS_OUTPUT("prevector_s: const_raw_pointer data() const noexcept");
        IMPLEMENT_MEMORY_CONST_RAW_POINTER
        return ptr;
    }

    const value_type &at(int pos) const noexcept {
        DEBUGCS_OUTPUT("prevector_s: value_type &at(int pos) const noexcept");
        return operator[](pos);
    }

    value_type &at(int pos) noexcept {
        DEBUGCS_OUTPUT("prevector_s: velue_type &at(int pos) noexcept");
        return operator[](pos);
    }

    //
    // Note:
    // The following operator isn't used because their interpretation is ambiguous.
    //
    // template <typename SA = secure_allocator<T> >
    // operator std::vector<T, SA>() const noexcept {
    //     DEBUGCS_OUTPUT("prevector_s: cast overload std::vector<T, SA>() const noexcept");
    //     std::vector<T, SA> obj(data(), data() + size());
    //     return obj;
    // }

    template <typename SA = secure_allocator<T> >
    std::vector<T, SA> get_std_vector() const noexcept {
        DEBUGCS_OUTPUT("prevector_s: std::vector<T, SA> get_std_vector() const noexcept");
        raw_pointer _data = data();
        std::vector<T, SA> obj(_data, _data + size());
        return obj;
    }

    template <typename SA = secure_allocator<T> >
    static prevector_s<N, T, Size, Diff> get_prevector(const std::vector<T, SA> &v) noexcept {
        DEBUGCS_OUTPUT("prevector_s: prevector<N, T, Size, Diff> get_prevector(const std::vector<T, SA> &v) noexcept");
        prevector_s<N, T, Size, Diff> obj(v.data(), v.data() + v.size());
        return obj;
    }
};
#pragma pack(pop)

//
// PREVECTOR_S Common N
//
const int PREVECTOR_S_N = 512;

//
// PREVECTOR_S mode
// Note: Macro ON: PREVECTOR, Macro OFF: std::vector<T, secure_allocator<T> >
//
#ifdef USE_PREVECTOR_S

#endif

} // namespace latest_crypto

#endif
#endif
