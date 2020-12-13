// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_QUANTUM_H
#define SORACHANCOIN_QUANTUM_H
#if defined(USE_QUANTUM) // SorachanCoin-qt.pro

#include <memory>
#include <assert.h>
#include <cstdint>
#include <vector>
#include <crypto/blake2.h>
#include <const/attributes.h>

#ifdef WIN32
# include <compat/compat.h>
# include <wincrypt.h>
#else
# include <unistd.h>
#endif

/*
** Reference:
*/
// HASH     BLAKE2:            https://github.com/BLAKE2/libb2
// MEMORY   libsodium:         https://github.com/jedisct1/libsodium
// LAMPORT  Lamport Signature: https://github.com/GEO-Protocol/lib-crypto-lamport
//

namespace latest_crypto {

//
// Secure library
//
class quantum_lib
{
private:
    quantum_lib()=delete;
    quantum_lib(const quantum_lib &)=delete;
    quantum_lib(const quantum_lib &&)=delete;
    quantum_lib &operator=(const quantum_lib &)=delete;
    quantum_lib &operator=(const quantum_lib &&)=delete;

    typedef std::uint8_t byte;
    enum secure_type
    {
        LOCK_UNLOCK,
        LOCK_UNLOCK_DUMMY
    };

#pragma pack(push, 1)
    typedef union _tag_alloc_info
    {
        struct {
            byte m[4 * 1024];
        } align;
        struct {
            secure_type type;
            size_t size;
        } data;
    } alloc_info;
#pragma pack(pop)

    static const size_t alloc_info_size = sizeof(alloc_info);
private:
    class manage
    {
    private:
        manage(const manage &)=delete;
        manage(manage &&)=delete;
        manage &operator=(const manage &)=delete;
        manage &operator=(manage &&)=delete;
        void *ptr;
        size_t size;
    public:
        explicit manage(void *ptrIn, size_t sizeIn) noexcept : ptr(ptrIn), size(sizeIn) {}
        void readonly() const;
        void readwrite() const;
        ~manage();
    };
public:
    static void *secure_malloc(size_t sizeIn);
    static void secure_free(void *ptr, bool fRandom = false) noexcept;
    static void secure_memzero(void *ptr, size_t sizeIn) noexcept;
    static void secure_memrandom(void *ptr, size_t sizeIn) noexcept;
    static void secure_stackzero(const size_t sizeIn) noexcept;
    static void secure_stackrandom(const size_t sizeIn) noexcept;
    NODISCARD static bool secure_mprotect_noaccess(const void *ptr) noexcept;
    NODISCARD static bool secure_mprotect_readonly(const void *ptr) noexcept;
    NODISCARD static bool secure_mprotect_readwrite(void *ptr) noexcept;
    static void secure_randombytes_buf(unsigned char *data, size_t sizeIn);
};

//
// Hash Secure lib
//
namespace quantum_hash
{
    void blake2_generichash(std::uint8_t *hash, size_t size_hash, const std::uint8_t *data, size_t size_data) noexcept;
    void blake2_hash(std::uint8_t hash[CBLAKE2::Size()], const std::uint8_t *data, size_t size_data) noexcept;
}

//
// Secure Segment
//
template <typename T>
class CSecureSegment;

template <typename T>
class CSecureSegmentRW
{
private:
    CSecureSegmentRW()=delete;
    //CSecureSegmentRW &operator=(const CSecureSegmentRW &)=delete;
    //CSecureSegmentRW &operator=(CSecureSegmentRW &&)=delete;
    CSecureSegment<T> *segment;
public:
    //explicit CSecureSegmentRW(CSecureSegment<T> &obj, bool readonly) noexcept : segment(&obj) {
    //    readonly ? unlock_readonly(): unlock();
    //}
    explicit CSecureSegmentRW(const CSecureSegment<T> *p, bool readonly) noexcept : segment(nullptr) {
        segment = const_cast<CSecureSegment<T> *>(p);
        readonly ? unlock_readonly() : unlock();
    }
    CSecureSegmentRW(const CSecureSegmentRW<T> &obj) noexcept : segment(nullptr) {
        *this = obj;
    }
    ~CSecureSegmentRW() {
        lock();
    }

    void unlock() const {
        if(! quantum_lib::secure_mprotect_readwrite(segment->get_addr()))
            throw std::runtime_error("CSecureSegmentRW: failed to unlock memory");
    }
    void unlock_readonly() const {
        if(! quantum_lib::secure_mprotect_readonly(segment->get_addr()))
            throw std::runtime_error("CSecureSegmentRW: failed to readonly memory");
    }
    void lock() const {
        if(! quantum_lib::secure_mprotect_noaccess(segment->get_addr()))
            throw std::runtime_error("CSecureSegmentRW: failed to lock memory");
    }

    size_t get_size() const noexcept {
        return segment->get_size();
    }
    const T *get_addr() const noexcept {
        return segment->get_addr();
    }
    T *get_addr() noexcept {
        return segment->get_addr();
    }
};

template <typename T>
class CSecureSegment
{
    friend class CSecureSegmentRW<T>;
private:
    CSecureSegment()=delete;
    CSecureSegment(const CSecureSegment &)=delete;
    CSecureSegment(const CSecureSegment &&)=delete;
    CSecureSegment &operator=(const CSecureSegment &)=delete;
    CSecureSegment &operator=(const CSecureSegment &&)=delete;

    size_t size;
    T *data;
    size_t get_size() const noexcept {
        return size;
    }
    const T *get_addr() const noexcept {
        return data;
    }
    T *get_addr() noexcept {
        return data;
    }
public:
    explicit CSecureSegment(size_t sizeIn) : size(0), data(nullptr) {
        data = static_cast<T *>(quantum_lib::secure_malloc(sizeIn));
        if(! quantum_lib::secure_mprotect_noaccess(data))
            throw std::runtime_error("CSecureSegment: failed to CSecureSegment(size_t)");
        size = sizeIn;
    }
    ~CSecureSegment() {
        release();
    }

    void release() noexcept {
        if (data) quantum_lib::secure_free(data);
        data = nullptr;
        size = 0;
    }

    //
    // access to memory.
    //
    CSecureSegmentRW<T> unlockAndInitRW(bool readonly) const noexcept {
        return CSecureSegmentRW<T>(this, readonly);
    }
};

//
// Secure Segment vector, map, string
//
namespace secure_segment
{

    template <typename T>
    class secure_protect_allocator : public std::allocator<T>
    {
    public:
        typedef typename std::allocator<T>::pointer pointer;
        typedef typename std::allocator<T>::const_pointer const_pointer;
        typedef typename std::allocator<T>::size_type size_type;
        secure_protect_allocator() noexcept {}
        secure_protect_allocator(const secure_protect_allocator &) noexcept {}

#ifdef _MSC_VER
        pointer allocate(size_type sizeIn) {
#else
        pointer allocate(size_type sizeIn, const_pointer inp = nullptr) {
#endif
            void *ptr = quantum_lib::secure_malloc(sizeIn);
            return static_cast<pointer>(ptr);
        }
        void deallocate(pointer ptr, size_type) noexcept {
            quantum_lib::secure_free(ptr);
        }

        template <typename U>
        secure_protect_allocator(const secure_protect_allocator<U> &) {}

        template <typename U>
        struct rebind
        {
            typedef secure_protect_allocator<U> other;
        };
    };

    template <typename T>
    class vector
    {
    private:
        typedef typename std::vector<T, secure_protect_allocator<T> > vector_t;
        mutable std::vector<T, secure_protect_allocator<T> > vec; // Note: Can not inherits std. (No virtual)

        void readonly() const {
            T *ptr = vec.data();
            if(! quantum_lib::secure_mprotect_readonly(ptr))
                throw std::runtime_error("secure vector: failed to readonly");
        }
        void readwrite() const {
            T *ptr = vec.data();
            if(! quantum_lib::secure_mprotect_readwrite(ptr))
                throw std::runtime_error("secure vector: failed to readwrite");
        }
        void noaccess() const {
            T *ptr = vec.data();
            if(! quantum_lib::secure_mprotect_noaccess(ptr))
                throw std::runtime_error("secure vector: failed to noaccess");
        }
    public:
        vector() noexcept : vec() {
            noaccess();
        }
        explicit vector(const T *begin, const T *end) : vec(begin, end) {
            noaccess();
        }
        explicit vector(const typename vector_t::const_iterator &begin, const typename vector_t::const_iterator &end) : vec(begin, end) {
            noaccess();
        }
#ifndef _MSC_VER
        explicit vector(const typename std::vector<T>::const_iterator &begin, const typename std::vector<T>::const_iterator &end) : vec(begin, end) {
            noaccess();
        }
#endif

        vector(const vector &obj) {
            operator =(obj);
        }
        vector &operator=(const vector &obj) {
            readwrite();
            obj.readonly();
            this->vec = obj.vec;
            noaccess();
            obj.noaccess();
        }

        typename vector_t::const_iterator begin() const {
            readonly();
            return vec.begin();
        }
        typename vector_t::const_iterator end() const {
            return vec.end();
        }

        T &at(std::size_t n) {
            readwrite();
            return vec.at(n);
        }
        const T &at(std::size_t n) const {
            readonly();
            return vec.at(n);
        }
    };

} // secure_segment

//
// Lamport Sigunature
//
namespace Lamport {

    const size_t kRandomNumbersCount = 256 * 2;
    const size_t kRandomNumberSize = 256 / 8;
    typedef std::uint8_t byte;

    class util
    {
    //private:
        //util()=delete;
        //util(const util &)=delete;
        //util(util &&)=delete;
        //util &operator =(const util &)=delete;
        //util &operator =(util &&)=delete;
    protected:
        static void alloc(byte *&dest, const byte *dataIn, size_t size);
        static void alloc_secure_random(CSecureSegment<byte> *&secure, size_t kRandomNumbersCountIn, size_t kRandomNumberSizeIn);
        static void alloc_secure(CSecureSegment<byte> *&secure, const byte *dataIn, size_t sizeIn);
        static void release(byte *&data) noexcept;
        static void release(CSecureSegment<byte> *&secure) noexcept;
    };

    class CKeyBase : protected util
    {
    private:
        CKeyBase(const CKeyBase &)=delete;
        CKeyBase(CKeyBase &&)=delete;
        // CKeyBase &operator=(const CKeyBase &)=delete;
        // CKeyBase &operator=(CKeyBase &&)=delete;
    protected:
        //
        // Secure(count * size) + Random
        //
        explicit CKeyBase(size_t kRandomNumbersCountIn, size_t kRandomNumberSizeIn) : data(nullptr), secure(nullptr) {
            assert(kRandomNumbersCountIn * kRandomNumberSizeIn == get_size());
            alloc_secure_random(secure, kRandomNumbersCountIn, kRandomNumberSizeIn);
        }

        //
        // Alloc(size) only
        //
        explicit CKeyBase(size_t sizeIn) : data(nullptr), secure(nullptr) {
            assert(sizeIn == get_size());
            alloc(data, nullptr, sizeIn);
        }

        //
        // Copy(data, size, secure_flag)
        //
        explicit CKeyBase(const byte *dataIn, size_t sizeIn, bool isSecure) : data(nullptr), secure(nullptr) {
            assert(sizeIn == get_size());
            if (isSecure) alloc_secure(secure, dataIn, get_size());
            else alloc(data, dataIn, get_size());
        }

        virtual ~CKeyBase() {
            release(data);
            release(secure);
        }

        byte *data;
        CSecureSegment<byte> *secure;
    public:
        //
        // Copy
        //
        CKeyBase &operator=(const CKeyBase &obj) {
            if(data && obj.data)
                ::memcpy(data, obj.data, get_size());
            if(secure && obj.secure) {
                CSecureSegmentRW<byte> dest = secure->unlockAndInitRW(false);
                CSecureSegmentRW<byte> src  = obj.secure->unlockAndInitRW(true);
                ::memcpy(dest.get_addr(), src.get_addr(), dest.get_size());
            }
            return *this;
        }

        //
        // Key size
        // * @returns size if bytes of Lamport Key.
        // * Both PrivateKey and PublicKey are 16K long.
        //
        static const size_t get_size() noexcept {
            return Lamport::kRandomNumbersCount * Lamport::kRandomNumberSize;
        }

        //
        // Normal memory
        //
        const byte *get_addr() const noexcept {
            return data;
        }
        byte *get_addr() noexcept {
            return data;
        }

        //
        // Secure memory
        //
        const CSecureSegment<byte> *get_secure() const noexcept {
            return secure;
        }
        CSecureSegment<byte> *get_secure() noexcept {
            return secure;
        }
    };

    class CPublicKey : public CKeyBase
    {
        friend class CSignature;
    private:
        CPublicKey()=delete;
        CPublicKey(const CPublicKey &)=delete;
        CPublicKey(CPublicKey &&)=delete;
        CPublicKey &operator=(const CPublicKey &)=delete;
        CPublicKey &operator=(CPublicKey &&)=delete;
    public:
        explicit CPublicKey(size_t _size_check_) noexcept : CKeyBase(_size_check_) {}
        explicit CPublicKey(const byte *dataIn, size_t _size_check_) : CKeyBase(dataIn, _size_check_, false) {} // Note: disable secure_alloc (dataIn, _size_check_, false).
        ~CPublicKey() {}
    };

    class CPrivateKey : public CKeyBase
    {
        friend class CSignature;
    private:
        CPrivateKey(const CPrivateKey &)=delete;
        CPrivateKey(CPrivateKey &&)=delete;
        //CPrivateKey &operator=(const CPrivateKey &)=delete;
        //CPrivateKey &operator=(CPrivateKey &&)=delete;
        bool isCropped;
    public:
        //
        // Copy
        //
        CPrivateKey &operator=(const CPrivateKey &obj) {
            CKeyBase::operator=(obj);
            return *this;
        }

        CPrivateKey() : isCropped(false), CKeyBase(kRandomNumbersCount, kRandomNumberSize) {} // Note: generate random private key and enable secure_alloc.
        explicit CPrivateKey(const byte *dataIn, size_t _size_check_) : isCropped(false), CKeyBase(dataIn, _size_check_, true) {} // Note: enable secure_alloc (dataIn, _size_check_, true).
        bool is_ok() const noexcept {
            return isCropped;
        }
        void set_cropped() noexcept {
            isCropped = true;
        }

        //
        // private: Call to CSignature only.
        //
    private:
        std::shared_ptr<CPublicKey> derivePublicKey() const noexcept;
    };

    /**
    * BLAKE2KeyHash implements container for storing, serialization and deserialization
    * of hashes of private and public keys.
    */
    class BLAKE2KeyHash
    {
    public:
        constexpr static size_t kBytesSize = 32;
    private:
        BLAKE2KeyHash()=delete;
        BLAKE2KeyHash(const BLAKE2KeyHash &)=delete;
        BLAKE2KeyHash(const BLAKE2KeyHash &&)=delete;
        BLAKE2KeyHash &operator=(const BLAKE2KeyHash &)=delete;
        BLAKE2KeyHash &operator=(const BLAKE2KeyHash &&)=delete;
        byte data[BLAKE2KeyHash::kBytesSize];
    public:
        constexpr static size_t Size() {return kBytesSize;}
        explicit BLAKE2KeyHash(const CPrivateKey &key) noexcept;
        explicit BLAKE2KeyHash(std::shared_ptr<CPrivateKey> key) noexcept;
        explicit BLAKE2KeyHash(std::shared_ptr<CPublicKey> key) noexcept;
        explicit BLAKE2KeyHash(byte *buffer) noexcept;
        const byte *get_addr() const noexcept {
            return data;
        }
        friend bool operator==(const BLAKE2KeyHash &kh1, const BLAKE2KeyHash &kh2) {
            return (::memcmp(kh1.data, kh2.data, BLAKE2KeyHash::kBytesSize) == 0);
        }
        friend bool operator!=(const BLAKE2KeyHash &kh1, const BLAKE2KeyHash &kh2) {
            return !(kh1 == kh2);
        }
    };

    class CSignature
    {
    private:
        static const size_t hashSize = kRandomNumberSize;
        static const size_t hashCount = kRandomNumbersCount;
        static const size_t kSize = hashSize * hashCount / 2;
        static const int bitsInByte = 8;
        byte data[kSize];
    private:
        CSignature(const CSignature &)=delete;
        CSignature(const CSignature &&)=delete;
        CSignature operator=(const CSignature &)=delete;
        CSignature operator=(const CSignature &&)=delete;
        void collectSignature(byte *signature, const byte *key, const byte *messageHash) const noexcept;
    public:
        CSignature() noexcept {
            ::memset(data, 0x00, get_size());
        }
        explicit CSignature(const byte *dataIn, size_t _size_check_) noexcept {
            assert(_size_check_ == get_size());
            ::memcpy(data, dataIn, get_size());
        }
        virtual ~CSignature() {}

        size_t get_size() const noexcept {
            // signature has 8KB
            return kSize;
        }

        const byte *get_addr() const noexcept {return data;}
        byte *get_addr() noexcept {return data;}
        void clean() noexcept {quantum_lib::secure_memzero(data, get_size());}
        bool check(const byte *dataIn, size_t dataSize, std::shared_ptr<const CPublicKey> pubKey) const noexcept;
    protected:
        std::shared_ptr<CPublicKey> derivePublicKey(const byte *dataIn, size_t dataSize, CPrivateKey *pKey) noexcept;
        void createHash(const byte *dataIn, size_t dataSize, CPrivateKey *pKey) noexcept;
    };

    class CLamport : public CSignature
    {
    private:
        CPrivateKey privKey;
        //CLamport(const CLamport &)=delete;
        //CLamport(CLamport &&)=delete;
        //CLamport &operator=(const CLamport &)=delete;
        //CLamport &operator=(CLamport &&)=delete;
    public:
        CLamport(const CLamport &obj);
        CLamport &operator=(const CLamport &obj) noexcept;
        CLamport() noexcept; // Automatically, set random to privKey.
        explicit CLamport(const byte *dataIn, size_t _size_check_); // Manually, set 16KBytes random to privKey. Note: must _size_check_ is 16Kbytes.
        ~CLamport();

        std::shared_ptr<CPublicKey> create_pubkey(const std::uint8_t *dataIn, size_t dataSize) noexcept;
        void create_hashonly(const std::uint8_t *dataIn, size_t dataSize) noexcept;
    };

} // namespace Lamport

} // namespace latest_crypto

#endif // USE_QUANTUM
#endif // SORACHANCOIN_QUANTUM_HEADER
