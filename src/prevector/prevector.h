// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOIN_PREVECTOR_H_
#define _BITCOIN_PREVECTOR_H_

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <vector>
#include <stdexcept>
#include <debugcs/debugcs.h>
#include <compat/compat.h> // IS_TRIVIALLY_CONSTRUCTIBLE

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
class prevector {
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

    public:
        typedef Diff difference_type;
        typedef T value_type;
        typedef T *pointer;
        typedef T &reference;
        typedef std::random_access_iterator_tag iterator_category;
        iterator() noexcept : ptr(nullptr) {}
        iterator(T *ptr_) noexcept : ptr(ptr_) {}
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
        iterator operator+(size_type n) noexcept { return iterator(ptr + n); }
        iterator &operator+=(size_type n) noexcept {
            ptr += n;
            return *this;
        }
        iterator operator-(size_type n) noexcept { return iterator(ptr - n); }
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

    public:
        typedef Diff difference_type;
        typedef T value_type;
        typedef T *pointer;
        typedef T &reference;
        typedef std::bidirectional_iterator_tag iterator_category;
        reverse_iterator() noexcept : ptr(nullptr) {}
        reverse_iterator(T *ptr_) noexcept : ptr(ptr_) {}
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

    public:
        typedef Diff difference_type;
        typedef const T value_type;
        typedef const T *pointer;
        typedef const T &reference;
        typedef std::random_access_iterator_tag iterator_category;
        const_iterator() noexcept : ptr(nullptr) {}
        const_iterator(const T *ptr_) noexcept : ptr(ptr_) {}
        const_iterator(iterator x) noexcept : ptr(&(*x)) {}
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

    public:
        typedef Diff difference_type;
        typedef const T value_type;
        typedef const T *pointer;
        typedef const T &reference;
        typedef std::bidirectional_iterator_tag iterator_category;
        const_reverse_iterator() noexcept : ptr(nullptr) {}
        const_reverse_iterator(T *ptr_) noexcept : ptr(ptr_) {}
        const_reverse_iterator(reverse_iterator x) noexcept : ptr(&(*x)) {}
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

private:
    size_type _size;
    std::vector<unsigned char> *_invch;
    union direct_or_indirect {
        char direct[sizeof(T) * N];
        struct {
            size_type capacity;
            unsigned char *indirect;
        } _s;
    } _union;

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
        DEBUGCS_OUTPUT("prevector: void change_capacity(size_type new_capacity)");
        if (new_capacity <= N) {
            if (! is_direct()) {
                T *indirect = indirect_ptr(0);
                T *src = indirect;
                T *dst = direct_ptr(0);
                std::memcpy(dst, src, size() * sizeof(T));
                delete _invch;
                _invch = nullptr;
                _size -= N + 1;
            }
        } else {
            if (! is_direct()) {
                // FIXME: Because malloc/realloc here won't call new_handler if
                // allocation fails, assert success. These should instead use an
                // allocator or new/delete so that handlers are called as
                // necessary, but performance would be slightly degraded by
                // doing so.
                //
                // FIXED: Assign here std::vector instead of malloc/realloc and
                // increase N to avoid using this re-allocation as much possible.
                _invch->resize((size_t)sizeof(T) * new_capacity);
                _union._s.indirect = &_invch->at(0);
                _union._s.capacity = new_capacity;
            } else {
                _invch = new(std::nothrow) std::vector<unsigned char>();
                if (! _invch) {
                    throw std::runtime_error("prevector memory allocate failure.");
                }
                _invch->resize((size_t)sizeof(T) * new_capacity);
                T *src = direct_ptr(0);
                T *dst = reinterpret_cast<T *>(&_invch->at(0));
                std::memcpy(dst, src, size() * sizeof(T));
                _union._s.indirect = &_invch->at(0);
                _union._s.capacity = new_capacity;
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
        if (IS_TRIVIALLY_CONSTRUCTIBLE<T>::value) {
            std::memcpy(item_ptr(pcur), &(*first), n * sizeof(T));
            _size += n;
        } else {
            while (first != last)
            {
                new (static_cast<void *>(item_ptr(pcur++))) T(*first);
                ++_size;
                ++first;
            }
        }
    }

    void fill(size_type pcur, const T &val, size_type n) noexcept {
        if (IS_TRIVIALLY_CONSTRUCTIBLE<T>::value) {
            const int *_val = reinterpret_cast<const int *>(&val);
            std::memset(item_ptr(pcur), *_val, n * sizeof(T));
            _size += n;
        } else {
            while (pcur < n)
            {
                new (static_cast<void *>(item_ptr(pcur++))) T(val);
                ++_size;
            }
        }
    }

public:
    void assign(size_type n, const T &val) {
        DEBUGCS_OUTPUT("prevector: void assign(size_type n, const T &val)");
        clear();
        if (capacity() < n) {
            change_capacity(n);
        }
        fill(size(), val, n);
    }

    template <typename InputIterator>
    void assign(InputIterator first, InputIterator last) {
        DEBUGCS_OUTPUT("prevector: void assign(InputIterator first, InputIterator last)");
        size_type n = last - first;
        clear();
        if (capacity() < n) {
            change_capacity(n);
        }
        copy(size(), first, last, n);
    }

    prevector() noexcept : _size(0), _invch(nullptr) {
        DEBUGCS_OUTPUT("prevector prevector() noexcept");
    }

    explicit prevector(size_type n) : _size(0), _invch(nullptr) {
        DEBUGCS_OUTPUT("prevector: explicit prevector(size_type n)");
        resize(n);
    }

    //explicit prevector(size_type n, const T &val = T()) : _size(0), _invch(nullptr) { // FIXED: overload ambiguous
    explicit prevector(size_type n, const T &val) : _size(0), _invch(nullptr) {
        DEBUGCS_OUTPUT("prevector: prevector(size_type n, const T &val)");
        change_capacity(n);
        fill(size(), val, n);
    }

    template <typename InputIterator>
    prevector(InputIterator first, InputIterator last) : _size(0), _invch(nullptr) {
        DEBUGCS_OUTPUT("prevector: prevector(InputIterator first, InputIterator last)");
        const size_type n = last - first;
        change_capacity(n);
        copy(size(), first, last, n);
    }

    prevector(const prevector<N, T, Size, Diff> &other) : _size(0), _invch(nullptr) {
        DEBUGCS_OUTPUT("prevector: prevector(const prevector<N, T, Size, Diff> &other)");
        change_capacity(other.size());
        copy(size(), other.begin(), other.end(), other.size());
    }

    prevector(prevector<N, T, Size, Diff> &&other) noexcept : _size(0), _invch(nullptr) {
        DEBUGCS_OUTPUT("prevector: prevector(prevector<N, T, Size, Diff> &&other) noexcept");
        swap(other);
    }

    prevector &operator=(const prevector<N, T, Size, Diff> &other) {
        DEBUGCS_OUTPUT("prevector: prevector &prevector=(const prevector<N, T, Size, Diff> &other)");
        if (&other == this) {
            return *this;
        }
        resize(0);
        change_capacity(other.size());
        copy(size(), other.begin(), other.end(), other.size());
        return *this;
    }

    prevector &operator=(prevector<N, T, Size, Diff> &&other) noexcept {
        DEBUGCS_OUTPUT("prevector: prevector &prevector=(prevector<N, T, Size, Diff> &&other) noexcept");
        swap(other);
        return *this;
    }

    size_type size() const noexcept {
        DEBUGCS_OUTPUT("prevector: size_type size() const noexcept");
        return is_direct() ? _size : _size - N - 1;
    }

    bool empty() const noexcept {
        DEBUGCS_OUTPUT("prevector: bool empty() const noexcept");
        return (size() == 0);
    }

    iterator begin() noexcept {
        DEBUGCS_OUTPUT("prevector: iterator begin() noexcept");
        return iterator(item_ptr(0));
    }
    const_iterator begin() const noexcept {
        DEBUGCS_OUTPUT("prevector: const_iterator begin() const noexcept");
        return const_iterator(item_ptr(0));
    }
    iterator end() noexcept {
        DEBUGCS_OUTPUT("prevector: iterator end() noexcept");
        return iterator(item_ptr(size()));
    }
    const_iterator end() const noexcept {
        DEBUGCS_OUTPUT("prevector: const_iterator end() const noexcept");
        return const_iterator(item_ptr(size()));
    }

    reverse_iterator rbegin() noexcept {
        DEBUGCS_OUTPUT("prevector: reverse_iterator rbegin() noexcept");
        return reverse_iterator(item_ptr(size() - 1));
    }
    const_reverse_iterator rbegin() const noexcept {
        DEBUGCS_OUTPUT("prevector: const_reverse_iterator rbegin() const noexcept");
        return const_reverse_iterator(item_ptr(size() - 1));
    }
    reverse_iterator rend() noexcept {
        DEBUGCS_OUTPUT("prevector: reverse_iterator rend() noexcept");
        return reverse_iterator(item_ptr(-1));
    }
    const_reverse_iterator rend() const noexcept {
        DEBUGCS_OUTPUT("prevector: const_reverse_iterator rend() const noexcept");
        return const_reverse_iterator(item_ptr(-1));
    }

    size_t capacity() const noexcept {
        DEBUGCS_OUTPUT("prevector: size_t capacity() const noexcept");
        if (is_direct()) {
            return N;
        } else {
            return _union._s.capacity;
        }
    }

    T &operator[](size_type pos) noexcept {
        DEBUGCS_OUTPUT("prevector: T &operator[](size_type pos) noexcept");
        return *item_ptr(pos);
    }

    const T &operator[](size_type pos) const noexcept {
        DEBUGCS_OUTPUT("prevector: const T &operator[](size_type pos) const noexcept");
        return *item_ptr(pos);
    }

    void resize(size_type new_size, const T &val = T()) {
        DEBUGCS_OUTPUT("prevector: void resize(size_type new_size, const T &val = T())");
        const size_type cur_size = size();
        if (cur_size == new_size) {
            return;
        }
        if (cur_size > new_size) {
            erase(item_ptr(new_size), end());
            return;
        }
        if (new_size > capacity()) {
            change_capacity(new_size);
        }
        size_type increase = new_size - cur_size;
        fill(cur_size, val, increase);
    }

    void reserve(size_type new_capacity) {
        DEBUGCS_OUTPUT("prevector: void reserve(size_type new_capacity)");
        if (new_capacity > capacity()) {
            change_capacity(new_capacity);
        }
    }

    void shrink_to_fit() {
        DEBUGCS_OUTPUT("prevector: void shrink_to_fit()");
        change_capacity(size());
    }

    void clear() {
        DEBUGCS_OUTPUT("prevector: void clear()");
        resize(0);
    }

    iterator insert(iterator pos, const T &value) {
        DEBUGCS_OUTPUT("prevector: iterator insert(iterator pos, const T &value)");
        size_type p = pos - begin();
        size_type new_size = size() + 1;
        if (capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        std::memmove(item_ptr(p + 1), item_ptr(p), (size() - p) * sizeof(T));
        ++_size;
        new (static_cast<void *>(item_ptr(p))) T(value);
        return iterator(item_ptr(p));
    }

    void insert(iterator pos, size_type count, const T &value) {
        DEBUGCS_OUTPUT("prevector: void insert(iterator pos, size_type count, const T &value)");
        size_type p = pos - begin();
        size_type new_size = size() + count;
        if (capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        std::memmove(item_ptr(p + count), item_ptr(p), (size() - p) * sizeof(T));
        fill(p, value, count);
    }

    template <typename InputIterator>
    void insert(iterator pos, InputIterator first, InputIterator last) {
        DEBUGCS_OUTPUT("prevectot: insert(iterator pos, InputIterator first, InputIterator last)");
        size_type p = pos - begin();
        difference_type count = last - first;
        size_type new_size = size() + count;
        if (capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        std::memmove(item_ptr(p + count), item_ptr(p), (size() - p) * sizeof(T));
        copy(p, first, last, count);
    }

    iterator erase(iterator pos) noexcept {
        DEBUGCS_OUTPUT("prevector: iterator erase(iterator pos) noexcept");
        return erase(pos, pos + 1);
    }

    iterator erase(iterator first, iterator last) noexcept {
        DEBUGCS_OUTPUT("prevector: iterator erase(iterator first, iterator last) noexcept");
        iterator p = first;
        char *endp = (char *)&(*end());
        if (! IS_TRIVIALLY_CONSTRUCTIBLE<T>::value) {
            while (p != last)
            {
                (*p).~T();
                --_size;
                ++p;
            }
        } else {
            _size -= last - p;
        }
        std::memmove(&(*first), &(*last), endp - ((char *)(&(*last))));
        return first;
    }

    void push_back(const T &value) {
        DEBUGCS_OUTPUT("prevector: void push_back(const T &value)");
        size_type new_size = size() + 1;
        if (capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        new (item_ptr(size())) T(value);
        ++_size;
    }

    void pop_back() noexcept {
        DEBUGCS_OUTPUT("prevector: void pop_back() noexcept");
        erase(end() - 1, end());
    }

    T &front() noexcept {
        DEBUGCS_OUTPUT("prevector: T &front() noexcept");
        return *item_ptr(0);
    }

    const T &front() const noexcept {
        DEBUGCS_OUTPUT("prevector: const T &front() const noexcept");
        return *item_ptr(0);
    }

    T &back() noexcept {
        DEBUGCS_OUTPUT("prevector: T &back() noexcept");
        return *item_ptr(size() - 1);
    }

    const T &back() const noexcept {
        DEBUGCS_OUTPUT("prevector: const T &back() const noexcept");
        return *item_ptr(size() - 1);
    }

    void swap(prevector<N, T, Size, Diff> &other) noexcept {
        DEBUGCS_OUTPUT("prevector: void swap(prevector<N, T, Size, Diff> &other) noexcept");
        std::swap(_invch, other._invch);
        std::swap(_union, other._union);
        std::swap(_size, other._size);
    }

    ~prevector() {
        DEBUGCS_OUTPUT("prevector: ~prevector() noexcept");
        if (! IS_TRIVIALLY_CONSTRUCTIBLE<T>::value) {
            clear();
        }
        if (! is_direct()) {
            delete _invch;
            _invch = nullptr;
            _union._s.indirect = nullptr;
        }
    }

    bool operator==(const prevector<N, T, Size, Diff> &other) const noexcept {
        DEBUGCS_OUTPUT("prevector: bool operator==(const prevector<N, T, Size, Diff> &other) const noexcept");
        if (other.size() != size()) {
            return false;
        }
        const_iterator b1 = begin();
        const_iterator b2 = other.begin();
        const_iterator e1 = end();
        while (b1 != e1)
        {
            if ((*b1) != (*b2)) {
                return false;
            }
            ++b1;
            ++b2;
        }
        return true;
    }

    bool operator!=(const prevector<N, T, Size, Diff> &other) const noexcept {
        DEBUGCS_OUTPUT("prevector: bool operator!=(const prevector<N, T, Size, Diff> &other) const noexcept");
        return !(*this == other);
    }

    bool operator<(const prevector<N, T, Size, Diff> &other) const noexcept {
        DEBUGCS_OUTPUT("prevector: bool operator<(const prevector<N, T, Size, Diff> &other) const noexcept");
        if (size() < other.size()) {
            return true;
        }
        if (size() > other.size()) {
            return false;
        }
        const_iterator b1 = begin();
        const_iterator b2 = other.begin();
        const_iterator e1 = end();
        while (b1 != e1)
        {
            if ((*b1) < (*b2)) {
                return true;
            }
            if ((*b2) < (*b1)) {
                return false;
            }
            ++b1;
            ++b2;
        }
        return false;
    }

    bool operator>(const prevector<N, T, Size, Diff> &other) const noexcept {
        DEBUGCS_OUTPUT("prevector: bool operator>(const prevector<N, T, Size, Diff> &other) const noexcept");
        return ((!operator<(other)) && (!operator==(other)));
    }

    size_t allocated_memory() const noexcept {
        DEBUGCS_OUTPUT("prevector: size_t allocated_memory() const noexcept");
        if (is_direct()) {
            return 0;
        } else {
            return ((size_t)(sizeof(T))) * _union._s.capacity;
        }
    }

    value_type *data() noexcept {
        DEBUGCS_OUTPUT("prevector: value_type *data() noexcept");
        return item_ptr(0);
    }

    const value_type *data() const noexcept {
        DEBUGCS_OUTPUT("prevector: const value_type *data() const noexcept");
        return item_ptr(0);
    }

    const value_type &at(int pos) const noexcept {
        DEBUGCS_OUTPUT("prevector: const value_type &at(int pos) const noexcept");
        return operator[](pos);
    }

    value_type &at(int pos) noexcept {
        DEBUGCS_OUTPUT("prevector: value_type &at(int pos) noexcept");
        return operator[](pos);
    }

    // Note:
    // The following operator isn't used because their interpretation is ambiguous.
    //
    // template <typename A = std::allocator<T> >
    // operator std::vector<T, A>() const noexcept {
    //     DEBUGCS_OUTPUT("prevector: cast overload std::vector<T, A>() const noexcept");
    //     std::vector<T, A> obj(data(), data() + size());
    //     return obj;
    // }

    template <typename A = std::allocator<T> > std::vector<T, A> get_std_vector() const noexcept {
        DEBUGCS_OUTPUT("prevector: std::vector<T, A> get_std_vector() const noexcept");
        std::vector<T, A> obj(data(), data() + size());
        return obj;
    }

    template <typename A = std::allocator<T> >
    static prevector<N, T, Size, Diff> get_prevector(const std::vector<T, A> &v) noexcept {
        DEBUGCS_OUTPUT("prevector: prevector<N, T, Size, Diff> get_prevector(const std::vector<T, A> &v)");
        prevector<N, T, Size, Diff> obj(v.data(), v.data() + v.size());
        return obj;
    }
};
#pragma pack(pop)

//
// PREVECTOR Common N
//
#ifdef BUILD64BIT
constexpr int PREVECTOR_DATASTREAM_N = 256;
constexpr int PREVECTOR_N = 256;
constexpr int PREVECTOR_BUFFER_N = 2048;
constexpr int PREVECTOR_BLOCK_N = 256;
#else
constexpr int PREVECTOR_DATASTREAM_N = 32;
constexpr int PREVECTOR_N = 32;
constexpr int PREVECTOR_BUFFER_N = 2048;
constexpr int PREVECTOR_BLOCK_N = 32;
#endif

//
// PREVECTOR mode
// Note: Macro ON: PREVECTOR, Macro OFF: std::vector
//
#ifdef USE_PREVECTOR
# ifdef BUILD64BIT
#  define DATASTREAM_PREVECTOR_ENABLE
#  define CSCRIPT_PREVECTOR_ENABLE
#  define BUFFER_PREVECTOR_ENABLE
#  define BLOCK_PREVECTOR_ENABLE
# else
#  define DATASTREAM_PREVECTOR_ENABLE
#  define CSCRIPT_PREVECTOR_ENABLE
#  define BUFFER_PREVECTOR_ENABLE
//#  define BLOCK_PREVECTOR_ENABLE
# endif
#endif

#endif
