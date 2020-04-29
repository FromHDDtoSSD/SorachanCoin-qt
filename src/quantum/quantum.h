// Copyright (c) 2018-2020 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef SORACHANCOIN_QUANTUM_H
#define SORACHANCOIN_QUANTUM_H
#ifdef USE_QUANTUM // SorachanCoin-qt.pro

#include <blake2.h>
#include <assert.h>
#include <vector>
#include <bitset>
#include <debugcs/debugcs.h>

#ifdef WIN32
# include <compat/compat.h>
# include <wincrypt.h>
#else
# include <unistd.h>
#endif

#include <openssl/rand.h>
#include <openssl/crypto.h> // for OPENSSL_cleanse()

/*
** Reference:
*/
// HASH     BLAKE2:            https://github.com/BLAKE2/libb2
// MEMORY   libsodium:         https://github.com/jedisct1/libsodium
// LAMPORT  Lamport Signature: https://github.com/GEO-Protocol/lib-crypto-lamport
//

//
// Secure library
//
class quantum_lib
{
private:
    quantum_lib(); // {}
    quantum_lib(const quantum_lib &); //{}
    quantum_lib(const quantum_lib &&); //{}
    quantum_lib &operator=(const quantum_lib &); // {}
    quantum_lib &operator=(const quantum_lib &&); // {}

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
        manage(const manage &); // {}
        manage(const manage &&); // {}
        manage &operator=(const manage &); // {}
        manage &operator=(const manage &&); // {}
        void *ptr;
        size_t size;
    public:
        explicit manage(void *ptrIn, size_t sizeIn) noexcept : ptr(ptrIn), size(sizeIn) {}
        void readonly() const {
#if defined(WIN32)
            DWORD old;
            if (! ::VirtualProtect(ptr, size, PAGE_READONLY, &old)) {
                throw std::runtime_error("secure_list::manage failure.");
            }
#else
            if (::mprotect(ptr, size, PROT_READ) != 0) {
                throw std::runtime_error("secure_list::manage failure.");
            }
#endif
        }
        void readwrite() const {
#if defined(WIN32)
            DWORD old;
            if (! ::VirtualProtect(ptr, size, PAGE_READWRITE, &old)) {
                throw std::runtime_error("secure_list::manage failure.");
            }
#else
            if (::mprotect(ptr, size, PROT_READ | PORT_WRITE) != 0) {
                throw std::runtime_error("secure_list::manage failure.");
            }
#endif
        }
        ~manage() noexcept {
#if defined(WIN32)
            DWORD old;
            (void)::VirtualProtect(ptr, size, PAGE_NOACCESS, &old);
#else
            (void)::mprotect(ptr, size, PROT_NONE);
#endif
        }
    };
public:
    static void *secure_malloc(size_t sizeIn) {
#if defined(WIN32)
        void *ptr = ::VirtualAlloc(nullptr, sizeIn + alloc_info_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
        void *ptr = nullptr;
        if ((ptr = ::mmap(nullptr, sizeIn + alloc_info_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_NOCORE, -1, 0)) == MAP_FAILED) {
            ptr = nullptr;
        }
#endif
        if (! ptr) {
            throw std::runtime_error("secure_alloc memory allocate failure.");
        }
#if defined(WIN32)
        bool lock_ret = false;
        lock_ret = (::VirtualLock(ptr, sizeIn + alloc_info_size) != FALSE) ? true : false;
#else
        lock_ret = (::mlock(ptr, sizeIn + alloc_info_size) == 0) ? true : false;
#endif
        if (! lock_ret) {
            throw std::runtime_error("secure_alloc virtual lock failure.");
        }
        alloc_info *pinfo = reinterpret_cast<alloc_info *>(ptr);
        pinfo->data.type = LOCK_UNLOCK;
        pinfo->data.size = sizeIn;
        return reinterpret_cast<void *>((byte *)ptr + alloc_info_size);
    }
    static void secure_free(void *ptr, bool fRandom = false) noexcept {
        void *fptr = reinterpret_cast<void *>((byte *)ptr - alloc_info_size);
        size_t size;
        {
            manage mem(fptr, alloc_info_size);
            mem.readonly();
            const alloc_info *pinfo = reinterpret_cast<const alloc_info *>(fptr);
            size = pinfo->data.size;
        }
        {
            manage mem(fptr, size + alloc_info_size);
            mem.readwrite();
            fRandom ? secure_memrandom(fptr, size + alloc_info_size) : secure_memzero(fptr, size + alloc_info_size);
#if defined(WIN32)
            (void)::VirtualUnlock(fptr, size + alloc_info_size);
#else
            (void)::munlock(fptr, size + alloc_info_size);
#endif
        }

#if defined(WIN32)
        (void)::VirtualFree(fptr, 0U, MEM_RELEASE);
#else
        (void)::munmap(fptr, size + alloc_info_size);
#endif
    }

    static void secure_memzero(void *ptr, size_t sizeIn) noexcept {
        ::OPENSSL_cleanse(ptr, sizeIn);
    }
    static void secure_memrandom(void *ptr, size_t sizeIn) noexcept {
        unsigned char *volatile pnt_ = (unsigned char *volatile)ptr;
        unsigned char buf[1024];
        (void)::RAND_bytes(buf, sizeof(buf) / sizeof(buf[0]));
        size_t i = (size_t)0U;
        while (i < sizeIn)
        {
            pnt_[i] = buf[i & (sizeof(buf) / sizeof(buf[0]) - 1)];
            ++i;
        }
    }
#ifdef _MSC_VER
    static void secure_stackzero(const size_t) noexcept {}
    static void secure_stackrandom(const size_t) noexcept {}
#else
    static void secure_stackzero(const size_t sizeIn) noexcept {
        unsigned char dummy[sizeIn];
        secure_memzero(dummy, sizeIn);
    }
    static void secure_stackrandom(const size_t sizeIn) noexcept {
        unsigned char dummy[sizeIn];
        secure_memrandom(dummy, sizeIn);
    }
#endif

    static void secure_mprotect_noaccess(const void *ptr) {
        //
        // success, return 0. error, return -1.(mprotect)
        //
        size_t size;
        void *__ptr = const_cast<void *>(ptr);
        {
            void *fptr = reinterpret_cast<void *>((byte *)__ptr - alloc_info_size);
            manage mem(fptr, alloc_info_size);
            mem.readonly();
            const alloc_info *pinfo = reinterpret_cast<const alloc_info *>(fptr);
            size = pinfo->data.size;
        }
#if defined(WIN32)
        DWORD old;
        int ret = ::VirtualProtect(__ptr, size, PAGE_NOACCESS, &old) ? 0 : -1;
#else
        int ret = ::mprotect(__ptr, size, PROT_NONE);
#endif
        if (ret != 0) {
            throw std::runtime_error("secure_mprotect_noaccess failure.");
        }
    }
    static void secure_mprotect_readonly(const void *ptr) {
        //
        // success, return 0. error, return -1.(mprotect)
        //
        size_t size;
        void *__ptr = const_cast<void *>(ptr);
        {
            void *fptr = reinterpret_cast<void *>((byte *)__ptr - alloc_info_size);
            manage mem(fptr, alloc_info_size);
            mem.readonly();
            const alloc_info *pinfo = reinterpret_cast<const alloc_info *>(fptr);
            size = pinfo->data.size;
        }
#if defined(WIN32)
        DWORD old;
        int ret = ::VirtualProtect(__ptr, size, PAGE_READONLY, &old) ? 0 : -1;
#else
        int ret = ::mprotect(__ptr, size, PROT_READ);
#endif
        if (ret != 0) {
            throw std::runtime_error("secure_mprotect_readonly failure.");
        }
    }
    static void secure_mprotect_readwrite(void *ptr) {
        //
        // success, return 0. error, return -1.(mprotect)
        //
        size_t size;
        {
            void *fptr = reinterpret_cast<void *>((byte *)ptr - alloc_info_size);
            manage mem(fptr, alloc_info_size);
            mem.readonly();
            const alloc_info *pinfo = reinterpret_cast<const alloc_info *>(fptr);
            size = pinfo->data.size;
        }
#if defined(WIN32)
        DWORD old;
        int ret = ::VirtualProtect(ptr, size, PAGE_READWRITE, &old) ? 0 : -1;
#else
        int ret = ::mprotect(ptr, size, PROT_READ | PORT_WRITE);
#endif
        if (ret != 0) {
            throw std::runtime_error("secure_mprotect_readwrite failure.");
        }
    }

    static void secure_randombytes_buf(unsigned char *data, size_t sizeIn) {
        if (::RAND_bytes(data, sizeIn) != 1) {
            throw std::runtime_error("Quantum_lib RAND_byte failure.");
        }
    }
};

//
// Hash Secure lib
//
namespace quantum_hash
{
    static void blake2_generichash(std::uint8_t *hash, size_t size_hash, const std::uint8_t *data, size_t size_data) {
        blake2s_state S;
        (void)::blake2s_init(&S, size_hash);
        static const size_t buffer_length = 32768;

        size_t remain = size_data;
        const std::uint8_t *p = data;
        const int count = size_data / buffer_length;
        int i = 0;
        do  // Note: ::blake2s_update has "return 0" only.
        {
            if (remain <= buffer_length) {
                (void)::blake2s_update(&S, p, remain);
                break;
            } else {
                (void)::blake2s_update(&S, p, buffer_length);
                remain -= buffer_length;
                p += buffer_length;
            }
        } while (i++ < count);
        if (::blake2s_final(&S, hash, size_hash) != 0) {
            throw std::runtime_error("blakek2_generichash final error.");
        }
    }
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
    CSecureSegmentRW(); // {}
    //CSecureSegmentRW &operator=(const CSecureSegmentRW &); // {}
    //CSecureSegmentRW &operator=(const CSecureSegmentRW &&); // {}

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
    ~CSecureSegmentRW() noexcept {
        lock();
    }

    void unlock() const noexcept {
        quantum_lib::secure_mprotect_readwrite(segment->get_addr());
    }
    void unlock_readonly() const noexcept {
        quantum_lib::secure_mprotect_readonly(segment->get_addr());
    }
    void lock() const noexcept {
        quantum_lib::secure_mprotect_noaccess(segment->get_addr());
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
    CSecureSegment(); // {}
    CSecureSegment(const CSecureSegment &); // {}
    CSecureSegment(const CSecureSegment &&); // {}
    CSecureSegment &operator=(const CSecureSegment &); // {}
    CSecureSegment &operator=(const CSecureSegment &&); // {}

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
    explicit CSecureSegment(size_t sizeIn) noexcept : size(0), data(nullptr) {
        data = static_cast<T *>(quantum_lib::secure_malloc(sizeIn));
        quantum_lib::secure_mprotect_noaccess(data);
        size = sizeIn;
    }
    ~CSecureSegment() noexcept {
        release();
    }

    void release() noexcept {
        if (data) {
            quantum_lib::secure_free(data);
        }
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

        void readonly() const noexcept {
            T *ptr = vec.data();
            quantum_lib::secure_mprotect_readonly(ptr);
        }
        void readwrite() const noexcept {
            T *ptr = vec.data();
            quantum_lib::secure_mprotect_readwrite(ptr);
        }
        void noaccess() const noexcept {
            T *ptr = vec.data();
            quantum_lib::secure_mprotect_noaccess(ptr);
        }
    public:
        vector() noexcept : vec() {
            noaccess();
        }
        explicit vector(const T *begin, const T *end) noexcept : vec(begin, end) {
            noaccess();
        }
        explicit vector(const typename vector_t::const_iterator &begin, const typename vector_t::const_iterator &end) noexcept : vec(begin, end) {
            noaccess();
        }

        vector(const vector &obj) noexcept {
            operator =(obj);
        }
        vector &operator =(const vector &obj) noexcept {
            readwrite();
            obj.readonly();
            this->vec = obj.vec;
            noaccess();
            obj.noaccess();
        }

        typename vector_t::const_iterator begin() const noexcept {
            readonly();
            return vec.begin();
        }
        typename vector_t::const_iterator end() const noexcept {
            return vec.end();
        }

        T &at(std::size_t n) noexcept {
            readwrite();
            return vec.at(n);
        }
        const T &at(std::size_t n) const noexcept {
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
    private:
        //util(); // {}
        //util(const util &); // {}
        //util(const util &&); // {}
        //util &operator =(const util &); // {}
        //util &operator =(const util &&); // {}
    protected:
        static void alloc(byte *&dest, const byte *dataIn, size_t size) {
            dest = new (std::nothrow) byte[size];
            if (! dest) {
                throw std::runtime_error("Lamport::util::alloc memory allocate failure.");
            }
            if (dataIn) {
                ::memcpy(dest, dataIn, size);
            }
        }
        static void alloc_secure_random(CSecureSegment<byte> *&secure, size_t kRandomNumbersCountIn, size_t kRandomNumberSizeIn) {
            secure = new (std::nothrow) CSecureSegment<byte>(kRandomNumbersCountIn * kRandomNumberSizeIn);
            if (! secure) {
                throw std::runtime_error("Lamport::util::alloc_secure memory allocate failure.");
            }
            CSecureSegmentRW<byte> guard = secure->unlockAndInitRW(false);

            byte *offset = guard.get_addr();
            for (size_t i = 0; i < kRandomNumbersCountIn; ++i)
            {
                quantum_lib::secure_randombytes_buf(offset, kRandomNumberSizeIn);
                offset += kRandomNumberSizeIn;
            }
        }
        static void alloc_secure(CSecureSegment<byte> *&secure, const byte *dataIn, size_t sizeIn) {
            secure = new (std::nothrow) CSecureSegment<byte>(sizeIn);
            if (! secure) {
                throw std::runtime_error("Lamport::util::alloc_secure memory allocate failure.");
            }
            CSecureSegmentRW<byte> guard = secure->unlockAndInitRW(false);

            byte *offset = guard.get_addr();
            ::memcpy(offset, dataIn, sizeIn);
        }
        static void release(byte *&data) noexcept {
            if (data) {
                delete[] data;
            }
            data = nullptr;
        }
        static void release(CSecureSegment<byte> *&secure) noexcept {
            if (secure) {
                delete secure;
            }
            secure = nullptr;
        }
    };

    class CKeyBase : protected util
    {
    private:
        CKeyBase(const CKeyBase &); // {}
        CKeyBase(const CKeyBase &&); // {}
        CKeyBase &operator=(const CKeyBase &); // {}
        CKeyBase &operator=(const CKeyBase &&); // {}
    protected:
        //
        // Secure(count * size) + Random
        //
        explicit CKeyBase(size_t kRandomNumbersCountIn, size_t kRandomNumberSizeIn) noexcept : data(nullptr), secure(nullptr) {
            alloc_secure_random(secure, kRandomNumbersCountIn, kRandomNumberSizeIn);
        }

        //
        // Alloc only
        //
        explicit CKeyBase(size_t sizeIn) noexcept : data(nullptr), secure(nullptr) {
            alloc(data, nullptr, sizeIn);
        }

        //
        // Copy
        //
        explicit CKeyBase(const byte *dataIn, bool isSecure) noexcept : data(nullptr), secure(nullptr) {
            if (isSecure) {
                alloc_secure(secure, dataIn, get_size());
            }
            else {
                alloc(data, dataIn, get_size());
            }
        }

        virtual ~CKeyBase() noexcept {
            release(data);
            release(secure);
        }

        byte *data;
        CSecureSegment<byte> *secure;
    public:
        //
        // Key size
        // * @returns size if bytes of Lamport Key.
        // * Both PrivateKey and PublicKey are 16K long.
        //
        const size_t get_size() const noexcept {
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
        CPublicKey(); // {}
        CPublicKey(const CPublicKey &); // {}
        CPublicKey(const CPublicKey &&); // {}
        CPublicKey &operator=(const CPublicKey &); // {}
        CPublicKey &operator=(const CPublicKey &&); // {}
    public:
        explicit CPublicKey(size_t sizeIn) noexcept : CKeyBase(sizeIn) {}
        explicit CPublicKey(const byte *dataIn) noexcept : CKeyBase(dataIn, false) {}
        ~CPublicKey() noexcept {}
    };

    class CPrivateKey : public CKeyBase
    {
        friend class CSignature;
    private:
        CPrivateKey(const CPrivateKey &); // {}
        CPrivateKey(const CPrivateKey &&); // {}
        CPrivateKey &operator=(const CPrivateKey &); // {}
        CPrivateKey &operator=(const CPrivateKey &&); // {}
        bool isCropped;
    public:
        CPrivateKey() noexcept : isCropped(false), CKeyBase(kRandomNumbersCount, kRandomNumberSize) {}
        explicit CPrivateKey(byte *dataIn) noexcept : isCropped(false), CKeyBase(dataIn, true) {}
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
        std::shared_ptr<CPublicKey> derivePublicKey() const noexcept {
            CSecureSegmentRW<byte> guard = secure->unlockAndInitRW(true);
            std::shared_ptr<CPublicKey> generatedKey = std::make_shared<CPublicKey>(kRandomNumbersCount * kRandomNumberSize);

            //
            // Numbers buffers initialisation via hashing private key numbers.
            //
            const unsigned char *source = static_cast<const unsigned char *>(guard.get_addr()); // Note: Segment(gurde) Read OK
            unsigned char *destination = static_cast<unsigned char *>(generatedKey->get_addr());

            for (size_t i = 0; i < kRandomNumbersCount; ++i)
            {
                quantum_hash::blake2_generichash(destination, kRandomNumberSize, source, kRandomNumberSize);
                source += kRandomNumberSize;
                destination += kRandomNumberSize;
            }
            return generatedKey; // Note: Segment(gurde) Called destructor => Read Lock
        }
    };

    /**
    * BLAKE2KeyHash implements container for storing, serialization and deserialization
    * of hashes of private and public keys.
    */
    class BLAKE2KeyHash
    {
    public:
        static const size_t kBytesSize = 32;
    private:
        BLAKE2KeyHash(); // {}
        BLAKE2KeyHash(const BLAKE2KeyHash &); // {}
        BLAKE2KeyHash(const BLAKE2KeyHash &&); // {}
        BLAKE2KeyHash &operator=(const BLAKE2KeyHash &); // {}
        BLAKE2KeyHash &operator=(const BLAKE2KeyHash &&); // {}

        // Todo: [Dima Chizhevsky, Mykola Ilashchuk]: Think about heap usage here.
        byte data[BLAKE2KeyHash::kBytesSize];
    public:
        explicit BLAKE2KeyHash(const CPrivateKey &key) noexcept {
            CSecureSegmentRW<byte> guard = key.get_secure()->unlockAndInitRW(true);
            quantum_hash::blake2_generichash(data, BLAKE2KeyHash::kBytesSize, guard.get_addr(), key.get_size());
        }
        explicit BLAKE2KeyHash(std::shared_ptr<CPrivateKey> key) noexcept {
            CSecureSegmentRW<byte> guard = key->get_secure()->unlockAndInitRW(true);
            quantum_hash::blake2_generichash(data, BLAKE2KeyHash::kBytesSize, guard.get_addr(), key->get_size());
        }
        explicit BLAKE2KeyHash(std::shared_ptr<CPublicKey> key) noexcept {
            quantum_hash::blake2_generichash(data, BLAKE2KeyHash::kBytesSize, key->get_addr(), key->get_size());
        }
        explicit BLAKE2KeyHash(byte *buffer) noexcept {
            ::memcpy(data, buffer, kBytesSize);
        }

        const byte *get_addr() const noexcept {
            return data;
        }
        friend bool operator ==(const BLAKE2KeyHash &kh1, const BLAKE2KeyHash &kh2) {
            return ::memcmp(kh1.data, kh2.data, BLAKE2KeyHash::kBytesSize) == 0;
        }
        friend bool operator !=(const BLAKE2KeyHash &kh1, const BLAKE2KeyHash &kh2) {
            return !(kh1 == kh2);
        }
    };

    class CSignature : public util
    {
    private:
        static const size_t hashSize = kRandomNumberSize;
        static const size_t hashCount = kRandomNumbersCount;
        static const size_t kSize = hashSize * hashCount / 2;
        static const int bitsInByte = 8;
        byte data[kSize];
    private:
        CSignature(const CSignature &); // {}
        CSignature(const CSignature &&); // {}
        CSignature operator=(const CSignature &); // {}
        CSignature operator=(const CSignature &&); // {}
        void collectSignature(byte *signature, const byte *key, const byte *messageHash) const noexcept {
            byte *signatureOffset = signature;
            const byte *numbersPairOffset = key;

            for (size_t i = 0; i < hashSize; ++i)
            {
                std::bitset<bitsInByte> byteOfMessageHash(messageHash[i]);

                for (size_t b = 0; b < bitsInByte; ++b)
                {
                    const byte *source = numbersPairOffset + hashSize;
                    if (byteOfMessageHash.test(b)) {
                        source = numbersPairOffset;
                    }

                    ::memcpy(signatureOffset, source, hashSize);
                    numbersPairOffset += hashSize * 2;
                    signatureOffset += hashSize;
                }
            }
        }
    public:
        CSignature() noexcept {}
        explicit CSignature(const byte *dataIn) noexcept {
            ::memcpy(data, dataIn, get_size());
        }
        virtual ~CSignature() noexcept {}

        std::shared_ptr<CPublicKey> derivePublicKey(const byte *dataIn, size_t dataSize, CPrivateKey *pKey) noexcept {
            if (pKey->is_ok()) {
                std::shared_ptr<CPublicKey> nullKey = nullptr;
                return nullKey;
            }

            //
            // 1, Create publicKey
            //
            std::shared_ptr<CPublicKey> pubKey = pKey->derivePublicKey();

            //
            // 2, hashed Signature data
            //
            byte messageHash[hashSize];
            quantum_hash::blake2_generichash(messageHash, hashSize, dataIn, dataSize);
            CSecureSegmentRW<byte> guard = pKey->get_secure()->unlockAndInitRW(true);
            collectSignature(data, guard.get_addr(), messageHash);

            //
            // 3, Cropping the private key.
            // This is needed to prevent it reuse.
            //
            pKey->set_cropped();

            return pubKey;
        }
        bool check(const byte *dataIn, size_t dataSize, std::shared_ptr<const CPublicKey> pubKey) const noexcept {
            if (dataIn == nullptr || dataSize == 0 || pubKey == nullptr) {
                return false;
            }

            //
            // Collecting hashed dataIn signature.
            //
            byte messageHash[hashSize];
            quantum_hash::blake2_generichash(messageHash, hashSize, dataIn, dataSize);

            //
            // Collecting pub key signature.
            //
            byte pubKeySignature[kSize];
            collectSignature(pubKeySignature, pubKey->get_addr(), messageHash);

            //
            // Collecting hashed signature.
            //
            byte hashedSignature[kSize];
            const byte *originalSignatureOffset = data;
            byte *hashedSignatureOffset = hashedSignature;
            for (size_t i = 0; i < hashCount / 2; ++i)
            {
                quantum_hash::blake2_generichash(hashedSignatureOffset, hashSize, originalSignatureOffset, hashSize);
                originalSignatureOffset += hashSize;
                hashedSignatureOffset += hashSize;
            }

            //
            // Comparing results.
            //
            return (::memcmp(pubKeySignature, hashedSignature, kSize) == 0) ? true : false;
        }

        size_t get_size() const noexcept {
            // signature has 8KB
            return kSize;
        }
        const byte *get_addr() const noexcept {
            return data;
        }
    };

    class CLamport : public CSignature
    {
    private:
        CPrivateKey privKey;
        CLamport(const CLamport &); // {}
        CLamport(const CLamport &&); // {}
        CLamport &operator=(const CLamport &); // {}
        CLamport &operator=(const CLamport &&); // {}
    public:
        CLamport() noexcept : privKey(), CSignature() {}
        ~CLamport() {}

        std::shared_ptr<CPublicKey> create_pubkey(const std::uint8_t *dataIn, size_t dataSize) noexcept {
            //
            // std::shared_ptr<CPublicKey> debugKey = privKey.derivePublicKey();
            // Note: Call to CSignature::derivePublicKey
            //
            return this->derivePublicKey(dataIn, dataSize, &privKey);
        }
    };

} // namespace Lamport

#endif // USE_QUANTUM
#endif // SORACHANCOIN_QUANTUM_HEADER
