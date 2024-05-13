// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_QUANTUM_H
#define SORACHANCOIN_QUANTUM_H

#include <stdexcept>
#include <memory>
#include <assert.h>
#include <cstdint>
#include <vector>
#include <cstring>
#include <crypto/blake2.h>
#include <const/attributes.h>
#include <uint256.h>
#include <allocator/allocators.h>
#include <prevector/prevector.h>
#include <util/strencodings.h>

#ifdef WIN32
# include <compat/compat.h>
# include <wincrypt.h>
#else
# include <unistd.h>
#endif

/*
** Reference:
*/
// MEMORY   libsodium:         https://github.com/jedisct1/libsodium
// LAMPORT  Lamport Signature: https://github.com/GEO-Protocol/lib-crypto-lamport
//

namespace latest_crypto {

//
// Secure library
//
class quantum_lib
{
    quantum_lib()=delete;
    quantum_lib(const quantum_lib &)=delete;
    quantum_lib(quantum_lib &&)=delete;
    quantum_lib &operator=(const quantum_lib &)=delete;
    quantum_lib &operator=(quantum_lib &&)=delete;

private:
    using byte = std::uint8_t;
    enum secure_type
    {
        LOCK_UNLOCK,
        LOCK_UNLOCK_DUMMY
    };

#pragma pack(push, 1)
    typedef union _tag_alloc_info
    {
        int32_t type;
        int32_t size;
        int32_t fMemoryLocked;
    } alloc_info;
#pragma pack(pop)

    static constexpr size_t alloc_info_size = sizeof(alloc_info);

private:
    class manage
    {
        manage()=delete;
        manage(const manage &)=delete;
        manage(manage &&)=delete;
        manage &operator=(const manage &)=delete;
        manage &operator=(manage &&)=delete;
    public:
        explicit manage(void *ptrIn, size_t sizeIn)  : ptr(ptrIn), size(sizeIn), fUnlock(false) {}
        bool readonly() const;
        bool readwrite() const;
        bool noaccess() const;
        ~manage();
    private:
        void *ptr;
        size_t size;
        mutable bool fUnlock;
    };
public:
    static void *secure_malloc(size_t sizeIn);
    static void secure_free(void *ptr, bool fRandom = false);
    static void secure_memzero(void *ptr, size_t sizeIn);
    static void secure_memrandom(void *ptr, size_t sizeIn);
    static void secure_stackzero(const size_t sizeIn);
    static void secure_stackrandom(const size_t sizeIn);
    NODISCARD static bool secure_mprotect_noaccess(const void *ptr);
    NODISCARD static bool secure_mprotect_readonly(const void *ptr);
    NODISCARD static bool secure_mprotect_readwrite(void *ptr);
    static void secure_randombytes_buf(unsigned char *data, size_t sizeIn);
};

//
// Hash Secure lib
//
namespace quantum_hash
{
    void blake2_generichash(std::uint8_t *hash, size_t size_hash, const std::uint8_t *data, size_t size_data) ;
    void blake2_hash(std::uint8_t hash[CBLAKE2S::Size()], const std::uint8_t *data, size_t size_data) ;
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
    //explicit CSecureSegmentRW(CSecureSegment<T> &obj, bool readonly)  : segment(&obj) {
    //    readonly ? unlock_readonly(): unlock();
    //}
    explicit CSecureSegmentRW(const CSecureSegment<T> *p, bool readonly)  : segment(nullptr) {
        segment = const_cast<CSecureSegment<T> *>(p);
        readonly ? unlock_readonly() : unlock();
    }
    CSecureSegmentRW(const CSecureSegmentRW<T> &obj)  : segment(nullptr) {
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

    size_t get_size() const  {
        return segment->get_size();
    }
    const T *get_addr() const  {
        return segment->get_addr();
    }
    T *get_addr()  {
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
    CSecureSegment(CSecureSegment &&)=delete;
    CSecureSegment &operator=(const CSecureSegment &)=delete;
    CSecureSegment &operator=(CSecureSegment &&)=delete;

    size_t size;
    T *data;
    size_t get_size() const  {
        return size;
    }
    const T *get_addr() const  {
        return data;
    }
    T *get_addr()  {
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

    void release()  {
        if (data) quantum_lib::secure_free(data);
        data = nullptr;
        size = 0;
    }

    //
    // access to memory.
    //
    CSecureSegmentRW<T> unlockAndInitRW(bool readonly) const  {
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
        secure_protect_allocator()  {}
        secure_protect_allocator(const secure_protect_allocator &)  {}

#ifdef _MSC_VER
        pointer allocate(size_type sizeIn) {
#else
        pointer allocate(size_type sizeIn, const_pointer inp = nullptr) {
#endif
            void *ptr = quantum_lib::secure_malloc(sizeIn);
            return static_cast<pointer>(ptr);
        }
        void deallocate(pointer ptr, size_type)  {
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
        vector()  : vec() {
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

    constexpr int compactpubkey = 2; // front 2 bytes pubkey (2 * 512 = 1024 bytes)

    constexpr size_t kRandomNumbersCount = 256 * 2;
    constexpr size_t kRandomNumberSize = 256 / 8;
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
        static void release(byte *&data) ;
        static void release(CSecureSegment<byte> *&secure) ;
    };

    class CKeyBase : protected util
    {
    private:
        // CKeyBase(const CKeyBase &)=delete;
        // CKeyBase(CKeyBase &&)=delete;
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
                std::memcpy(data, obj.data, get_size());
            if(secure && obj.secure) {
                CSecureSegmentRW<byte> dest = secure->unlockAndInitRW(false);
                CSecureSegmentRW<byte> src  = obj.secure->unlockAndInitRW(true);
                std::memcpy(dest.get_addr(), src.get_addr(), dest.get_size());
            }
            return *this;
        }

        CKeyBase &operator=(CKeyBase &&obj) {
            return operator=((const CKeyBase &)obj);
        }

        //
        // cmp
        //
        bool operator==(const CKeyBase &obj) const {
            if(data && obj.data)
                return (std::memcmp(data, obj.data, get_size()) == 0);
            if(secure && obj.secure) {
                CSecureSegmentRW<byte> src1 = secure->unlockAndInitRW(true);
                CSecureSegmentRW<byte> src2 = obj.secure->unlockAndInitRW(true);
                return (std::memcmp(src1.get_addr(), src2.get_addr(), src1.get_size()) == 0);
            }
            return false;
        }

        CKeyBase(const CKeyBase &obj) {
            *this = obj;
        }

        CKeyBase(CKeyBase &&obj) {
            *this = obj;
        }

        //
        // Key size
        // * @returns size if bytes of Lamport Key.
        // * Both PrivateKey and PublicKey are 16K long.
        //
        static constexpr size_t get_size()  {
            return Lamport::kRandomNumbersCount * Lamport::kRandomNumberSize;
        }

        //
        // Normal memory
        //
        const byte *get_addr() const {
            return data;
        }
        byte *get_addr() {
            return data;
        }

        //
        // Secure memory
        //
        const CSecureSegment<byte> *get_secure() const {
            return secure;
        }
        CSecureSegment<byte> *get_secure() {
            return secure;
        }
    };

    class CPublicKey : public CKeyBase
    {
        friend class CSignature;
        //CPublicKey()=delete;
        //CPublicKey(const CPublicKey &)=delete;
        //CPublicKey(CPublicKey &&)=delete;
        //CPublicKey &operator=(const CPublicKey &)=delete;
        //CPublicKey &operator=(CPublicKey &&)=delete;

    public:
        //
        // Copy and cmp
        //
        CPublicKey(const CPublicKey &obj) : CKeyBase(obj.get_size()) {
            CKeyBase::operator=(obj);
        }
        CPublicKey(CPublicKey &&obj) : CKeyBase(obj.get_size()) {
            CKeyBase::operator=(obj);
        }

        CPublicKey &operator=(const CPublicKey &obj) {
            CKeyBase::operator=(obj);
            return *this;
        }
        bool operator==(const CPublicKey &obj) const {
            return (*(CKeyBase *)this == (const CKeyBase &)obj);
        }

        const byte *get_addr() const {
            assert(CKeyBase::get_addr());
            return CKeyBase::get_addr();
        }

        byte *get_addr() {
            assert(CKeyBase::get_addr());
            return CKeyBase::get_addr();
        }

        // pubkey is NO secure.
        CPublicKey() : CKeyBase(get_size()) {}
        explicit CPublicKey(size_t _size_check_) : CKeyBase(_size_check_) {}
        explicit CPublicKey(const byte *dataIn, size_t _size_check_) : CKeyBase(dataIn, _size_check_, false) {} // Note: disable secure_alloc (dataIn, _size_check_, false).
        ~CPublicKey() {}
    };

    class CPrivateKey : public CKeyBase
    {
        friend class CSignature;
        CPrivateKey(const CPrivateKey &)=delete;
        CPrivateKey(CPrivateKey &&)=delete;
        //CPrivateKey &operator=(const CPrivateKey &)=delete;
        //CPrivateKey &operator=(CPrivateKey &&)=delete;
        bool isCropped;

    public:
        //
        // Copy and cmp
        //
        CPrivateKey &operator=(const CPrivateKey &obj) {
            CKeyBase::operator=(obj);
            return *this;
        }
        bool operator==(const CPrivateKey &obj) const {
            return *(CKeyBase *)this == (const CKeyBase &)obj;
        }

        CPrivateKey() : isCropped(false), CKeyBase(kRandomNumbersCount, kRandomNumberSize) {} // Note: generate random private key and enable secure_alloc.
        explicit CPrivateKey(const byte *dataIn, size_t _size_check_) : isCropped(false), CKeyBase(dataIn, _size_check_, true) {} // Note: enable secure_alloc (dataIn, _size_check_, true).
        bool is_ok() const  {
            return isCropped;
        }
        void set_cropped()  {
            isCropped = true;
        }

        std::shared_ptr<CPublicKey> derivePublicKey() const;
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
        BLAKE2KeyHash(BLAKE2KeyHash &&)=delete;
        BLAKE2KeyHash &operator=(const BLAKE2KeyHash &)=delete;
        BLAKE2KeyHash &operator=(BLAKE2KeyHash &&)=delete;
        byte data[BLAKE2KeyHash::kBytesSize];
    public:
        constexpr static size_t Size() {return kBytesSize;}
        explicit BLAKE2KeyHash(const CPrivateKey &key) ;
        explicit BLAKE2KeyHash(std::shared_ptr<CPrivateKey> key);
        explicit BLAKE2KeyHash(std::shared_ptr<CPublicKey> key);
        explicit BLAKE2KeyHash(byte *buffer);
        const byte *get_addr() const  {
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
        CSignature(const CSignature &)=delete;
        CSignature(CSignature &&)=delete;
        //CSignature &operator=(const CSignature &)=delete;
        //CSignature &operator=(CSignature &&)=delete;

    private:
        static constexpr size_t hashSize = kRandomNumberSize;
        static constexpr size_t hashCount = kRandomNumbersCount;
        static constexpr size_t kSize = hashSize * hashCount / 2;
        static constexpr int bitsInByte = 8;
        byte _signatured[kSize];

        static void collectSignature(byte *signature, const byte *key, const byte *messageHash);

    public:
        CSignature &operator=(const CSignature &obj) {
            std::memcpy(this->_signatured, obj._signatured, GetSize());
            return *this;
        }

        CSignature &operator=(CSignature &&obj) {
            std::memcpy(this->_signatured, obj._signatured, GetSize());
            return *this;
        }

        CSignature() {
            std::memset(_signatured, 0x00, GetSize());
        }

        explicit CSignature(const byte *dataIn, size_t _size_check_) {
            assert(_size_check_==GetSize());
            std::memcpy(_signatured, dataIn, GetSize());
        }

        virtual ~CSignature() {}

        size_t GetSize() const { // signature has 8KB
            return kSize;
        }

        const byte *GetSignatured() const {
            return _signatured;
        }

        //byte *GetSignatured() {
        //    return _signatured;
        //}

        void Clean() {
            quantum_lib::secure_memzero(_signatured, GetSize());
        }

        static void Sign(const byte *data, size_t size, const CPrivateKey &pKey, byte *signatured);
        static bool Verify(const byte *data, size_t size, const CPublicKey &pubKey, const byte *signatured);
        static bool VerifyQai(const byte *data, size_t size, const CPublicKey &pubKey, const byte *signatured);

        bool Verify(const byte *data, size_t size, std::shared_ptr<const CPublicKey> pubKey);

    protected:
        std::shared_ptr<CPublicKey> derivePublicKey(const byte *dataIn, size_t dataSize, CPrivateKey *pKey);

        void createHash(const byte *dataIn, size_t dataSize, CPrivateKey *pKey);
    };

    class CLamport : public CSignature
    {
        //CLamport(const CLamport &)=delete;
        //CLamport(CLamport &&)=delete;
        //CLamport &operator=(const CLamport &)=delete;
        //CLamport &operator=(CLamport &&)=delete;

    public:
        CLamport(const CLamport &obj);
        CLamport &operator=(const CLamport &obj);
        ~CLamport();

        // Automatically, set random to privKey.
        CLamport();

        // Manually, set 16KBytes random to privKey, note that must _size_check_ is 16Kbytes.
        explicit CLamport(const byte *dataIn);

        // preserve singed signature, and create pubkey.
        std::shared_ptr<CPublicKey> CreatePubKey(const unsigned char *data, size_t size);

        // pubkey and privkey.
        CPublicKey GetPubKey() const;
        CPublicKey GetPubKeyQai() const;
        bool CmpPrivKey(const CLamport &obj) const;
        const CSecureSegment<byte> *GetPrivKey() const;

        // Sign (data to signatured)
        void Sign(const byte *data, size_t size, byte *signatured) const; // signatured size is 8KB

        void create_hashonly(const std::uint8_t *dataIn, size_t dataSize);

    private:
        CPrivateKey _privkey;
    };

} // namespace Lamport

} // namespace latest_crypto

/////////////////////////////////////////////////////////////////////////////////////////////////
// quantum resist CqKey and CqPubKey
/////////////////////////////////////////////////////////////////////////////////////////////////

//using CqPrivKey = std::vector<unsigned char, secure_allocator<unsigned char> >; // der encording
using CqSecretKey = std::vector<unsigned char, secure_allocator<unsigned char> >;
using CqKeyID = std::string;

# ifdef CSCRIPT_PREVECTOR_ENABLE
using qkey_vector = prevector<PREVECTOR_N, uint8_t>;
# else
using qkey_vector = std::vector<uint8_t>;
# endif

/* depend on data, therefore pubkey must be useful 1024 bytes.
constexpr int qpubkey_compress_offset[] = {
0,8,20,28,32,44,48,56,68,72,80,92,96,108,112,120,
128,136,144,156,164,172,176,184,196,200,208,220,224,236,240,252,
260,268,276,284,292,300,308,312,324,328,336,344,352,364,372,376,
388,392,404,412,416,428,436,440,448,460,468,472,480,492,500,508,
512,524,528,540,548,552,560,572,576,588,592,604,612,616,624,636,
640,648,660,668,672,684,692,696,704,712,720,728,736,744,752,764,
768,776,784,796,800,808,816,828,836,840,852,860,864,876,880,892,
896,904,916,920,928,940,948,952,960,972,980,988,992,1004,1008,1020,
1028,1032,1040,1052,1060,1068,1076,1084,1092,1096,1104,1112,1120,1132,1136,1148,
1156,1160,1172,1180,1188,1196,1200,1208,1216,1228,1232,1240,1248,1260,1268,1276,
1284,1288,1296,1308,1312,1324,1332,1336,1348,1352,1360,1368,1380,1388,1392,1404,
1408,1416,1424,1432,1440,1452,1456,1464,1472,1484,1488,1500,1508,1516,1520,1528,
1540,1544,1556,1564,1572,1576,1584,1592,1604,1608,1620,1624,1632,1644,1648,1656,
1664,1672,1680,1688,1700,1704,1716,1724,1728,1740,1744,1752,1760,1768,1776,1784,
1792,1804,1812,1820,1828,1832,1840,1848,1860,1868,1876,1884,1892,1900,1904,1912,
1924,1932,1940,1944,1952,1960,1972,1980,1984,1992,2004,2012,2016,2028,2036,2040};
*/

class CqPubKey : public latest_crypto::Lamport::CPublicKey {
public:
    constexpr static int FULLY_PUBLIC_KEY_SIZE = 16384;
    constexpr static int COMPRESSED_PUBLIC_KEY_SIZE = 1024;
    constexpr static int QAI_PUBLIC_KEY_SIZE = 256;

    CqPubKey() : _valid(false) {}

    CqPubKey(const latest_crypto::Lamport::CPublicKey &obj) {
        *static_cast<latest_crypto::Lamport::CPublicKey *>(this) = obj;
        _valid = true;
    }

    CqPubKey &operator=(const CqPubKey &obj) {
        *static_cast<latest_crypto::Lamport::CPublicKey *>(this) = static_cast<const latest_crypto::Lamport::CPublicKey &>(obj);
        _valid = true;
        return *this;
    }

    CqPubKey &operator=(const latest_crypto::Lamport::CPublicKey &obj) {
        *static_cast<latest_crypto::Lamport::CPublicKey *>(this) = obj;
        _valid = true;
        return *this;
    }

    bool operator==(const CqPubKey &obj) const {
        if(! _valid)
            return false;

        return *static_cast<const latest_crypto::Lamport::CPublicKey *>(this) == static_cast<const latest_crypto::Lamport::CPublicKey &>(obj);
    }

    bool operator!=(const CqPubKey &obj) const {
        return !(*static_cast<const latest_crypto::Lamport::CPublicKey *>(this) == static_cast<const latest_crypto::Lamport::CPublicKey &>(obj));
    }

    // verify can by "data" and "signatured" then ... "pubkey".
    bool Verify(const qkey_vector &data, const qkey_vector &vchSig) const;
    bool Verify(const uint256 &data, const qkey_vector &vchSig) const;
    bool VerifyQai(const uint256 &data, const qkey_vector &vchSig) const;

    bool IsFullyValid_BIP66() const;
    bool IsCompressed() const;
    bool RecoverCompact(const qkey_vector &vchSig);
    bool RecoverCompact(const CqKeyID &pubkeyid);

    uint256 GetHash() const;
    qkey_vector GetVch() const;
    CqKeyID GetID() const;
    qkey_vector GetQaiHash() const;
    bool CmpQaiHash(const qkey_vector &hashvch) const;
    static bool IsQaiHash(const qkey_vector &hashvch);
    static qkey_vector GetRandHash();
    static bool IsRandHash(const qkey_vector &randvch);

private:
    bool _valid;
};

class CqKey {
    CqKey() = delete;

public:
    CqKey(const CqSecretKey &seed);

    bool IsValid() const {
        return _valid;
    }

    CqPubKey GetPubKey(bool fCompact = true) const;
    CqPubKey GetPubKeyQai() const;
    CqSecretKey GetSecret() const;

    // data signed by "privkey", output to signatured.
    void Sign(const qkey_vector &data, qkey_vector &vchSig) const;
    void Sign(const uint256 &hash, qkey_vector &vchSig) const;
    void SignQai(const uint256 &hash, qkey_vector &vchSig) const;

    // check this privkey's pubkey
    bool VerifyPubKey(const CqPubKey &pubkey) const;

    CqKey(const CqKey &obj) {
        assert(_valid && obj._valid);
        if(_lamport && obj._lamport)
            *_lamport = *obj._lamport;
    }

    CqKey(CqKey &&obj) {
        assert(_valid && obj._valid);
        if(_lamport && obj._lamport)
            *_lamport = *obj._lamport;
    }

    CqKey &operator=(const CqKey &obj) {
        assert(_valid && obj._valid);
        if(_lamport && obj._lamport)
            *_lamport = *obj._lamport;
        return *this;
    }

    bool operator==(const CqKey &obj) const {
        //assert(_valid && obj._valid);
        if(_lamport)
            return _lamport->CmpPrivKey(*obj._lamport);
        else
            return false;
    }

    bool operator!=(const CqKey &obj) const {
        //assert(_valid && obj._valid);
        if(_lamport)
            return !(_lamport->CmpPrivKey(*obj._lamport));
        else
            return true;
    }

    ~CqKey() {
        if(_lamport)
            delete _lamport;
    }

private:
    bool _valid;
    latest_crypto::Lamport::CLamport *_lamport; // instance includes secure_free (SecureAllocator)
};

#endif // SORACHANCOIN_QUANTUM_HEADER
