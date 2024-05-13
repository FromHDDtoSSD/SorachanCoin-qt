// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitset>
#include <thread>
#include <quantum/quantum.h>
#include <prevector/prevector.h>
#include <prevector/prevector_s.h>
#include <crypto/sha512.h>
#include <pbkdf2.h>
#include <compat/sanity.h>
#include <const/macro.h>
#include <random/random.h>
#include <cleanse/cleanse.h>
#include <util/args.h>
#include <crypto/blake2.h>
#include <hash.h>
#ifndef WIN32
# define MAP_NOCORE 0
#endif

namespace latest_crypto {

bool quantum_lib::manage::readonly() const {
#if defined(WIN32)
    DWORD old;
    fUnlock = ::VirtualProtect(ptr, size, PAGE_READONLY, &old) ? true: false;
#else
    fUnlock = (::mprotect(ptr, size, PROT_READ) == 0) ? true: false;
#endif
    return fUnlock;
}

bool quantum_lib::manage::readwrite() const {
#if defined(WIN32)
    DWORD old;
    fUnlock = ::VirtualProtect(ptr, size, PAGE_READWRITE, &old) ? true: false;
#else
    fUnlock = (::mprotect(ptr, size, PROT_READ | PROT_WRITE) == 0) ? true: false;
#endif
    return fUnlock;
}

bool quantum_lib::manage::noaccess() const {
    if(! fUnlock) return true;
#if defined(WIN32)
    DWORD old;
    fUnlock = ::VirtualProtect(ptr, size, PAGE_NOACCESS, &old) ? false: true;
#else
    fUnlock = (::mprotect(ptr, size, PROT_NONE) == 0) ? false: true;
#endif
    return !fUnlock;
}

quantum_lib::manage::~manage() {
    noaccess();
}

void *quantum_lib::secure_malloc(size_t sizeIn) {
#if defined(WIN32)
    void *ptr = ::VirtualAlloc(nullptr, sizeIn + alloc_info_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    void *ptr = nullptr;
    if ((ptr = ::mmap(nullptr, sizeIn + alloc_info_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_NOCORE, -1, 0)) == MAP_FAILED) {
        ptr = nullptr;
    }
#endif
    if (! ptr) throw std::runtime_error("quantumlib::secure_alloc memory allocate failure.");

    bool lock_ret = false;
#if defined(WIN32)
    lock_ret = (::VirtualLock(ptr, sizeIn + alloc_info_size) != FALSE) ? true : false;
#else
    lock_ret = (::mlock(ptr, sizeIn + alloc_info_size) == 0) ? true : false;
#endif

    if (! lock_ret) {
        // args_bool::fMemoryLockPermissive
        // default setting is false (enable lock, readonly, readwrite)
        // throw std::runtime_error("quantumlib::secure_alloc virtual lock failure.");
        args_bool::fMemoryLockPermissive = true;
    }

    alloc_info *pinfo = reinterpret_cast<alloc_info *>(ptr);
    pinfo->type = LOCK_UNLOCK;
    pinfo->size = (int32_t)sizeIn;
    pinfo->fMemoryLocked = lock_ret;
    return reinterpret_cast<void *>((byte *)ptr + alloc_info_size);
}

void quantum_lib::secure_free(void *ptr, bool fRandom /*= false*/) {
    void *fptr = reinterpret_cast<void *>((byte *)ptr - alloc_info_size);
    size_t size;
    //bool fMemoryLocked;
    {
        manage mem(fptr, alloc_info_size);
        if(! mem.readonly())
            throw std::runtime_error("quantum_lib::secure_free readonly failure");
        const alloc_info *pinfo = reinterpret_cast<const alloc_info *>(fptr);
        size = pinfo->size;
        //fMemoryLocked = pinfo->fMemoryLocked;
        if(! mem.noaccess())
            throw std::runtime_error("quantum_lib::secure_free noaccess failure");
    }
    {
        manage mem(fptr, size + alloc_info_size);
        if(! mem.readwrite())
            throw std::runtime_error("quantum_lib::secure_free readonly failure");
        fRandom ? secure_memrandom(fptr, size + alloc_info_size) : secure_memzero(fptr, size + alloc_info_size);
        /* unused
        if(fMemoryLocked) {
#if defined(WIN32)
            if(! ::VirtualUnlock(fptr, size + alloc_info_size))
                throw std::runtime_error("quantum_lib::secure_free VirtualUnlock failure");
#else
            if(::munlock(fptr, size + alloc_info_size)!=0)
                throw std::runtime_error("quantum_lib::secure_free munlock failure");
#endif
        }
        */
        if(! mem.noaccess())
            throw std::runtime_error("quantum_lib::secure_free noaccess failure");
    }

#if defined(WIN32)
    if(! ::VirtualFree(fptr, 0U, MEM_RELEASE))
        throw std::runtime_error("quantum_lib::secure_free munmap failure");
#else
    if(::munmap(fptr, size + alloc_info_size)!=0)
        throw std::runtime_error("quantum_lib::secure_free munmap failure");
#endif
}

void quantum_lib::secure_memzero(void *ptr, size_t sizeIn) {
    cleanse::memory_cleanse(ptr, sizeIn);
}

void quantum_lib::secure_memrandom(void *ptr, size_t sizeIn) {
    unsigned char *volatile pnt_ = (unsigned char *volatile)ptr;
    unsigned char buf[1024];
    latest_crypto::random::GetStrongRandBytes(buf, ARRAYLEN(buf));
    size_t i = (size_t)0U;
    while (i < sizeIn) {
        pnt_[i] = buf[i & (sizeof(buf) / sizeof(buf[0]) - 1)];
        ++i;
    }
}

void quantum_lib::secure_stackzero(const size_t sizeIn) {
#ifndef _MSC_VER
    unsigned char dummy[sizeIn];
    secure_memzero(dummy, sizeIn);
#endif
}

void quantum_lib::secure_stackrandom(const size_t sizeIn) {
#ifndef _MSC_VER
    unsigned char dummy[sizeIn];
    secure_memrandom(dummy, sizeIn);
#endif
}

bool quantum_lib::secure_mprotect_noaccess(const void *ptr) {
    if(args_bool::fMemoryLockPermissive)
        return true;

    size_t size;
    //bool fMemoryLocked;
    void *__ptr = const_cast<void *>(ptr);
    {
        void *fptr = reinterpret_cast<void *>((byte *)__ptr - alloc_info_size);
        manage mem(fptr, alloc_info_size);
        if(! mem.readonly())
            throw std::runtime_error("quantum_lib::secure_mprotect_noaccess readonly failure");
        const alloc_info *pinfo = reinterpret_cast<const alloc_info *>(fptr);
        size = pinfo->size;
        //fMemoryLocked = pinfo->fMemoryLocked;
        if(! mem.noaccess())
            throw std::runtime_error("quantum_lib::secure_mprotect_noaccess noaccess failure");
    }
#if defined(WIN32)
    DWORD old;
    int ret = ::VirtualProtect(__ptr, size, PAGE_NOACCESS, &old) ? 0 : -1;
#else
    int ret = ::mprotect(__ptr, size, PROT_NONE);
#endif

    return ret == 0;
}

bool quantum_lib::secure_mprotect_readonly(const void *ptr) {
    if(args_bool::fMemoryLockPermissive)
        return true;

    size_t size;
    //bool fMemoryLocked;
    void *__ptr = const_cast<void *>(ptr);
    {
        void *fptr = reinterpret_cast<void *>((byte *)__ptr - alloc_info_size);
        manage mem(fptr, alloc_info_size);
        if(! mem.readonly())
            throw std::runtime_error("quantum_lib::secure_mprotect_readonly readonly failure");
        const alloc_info *pinfo = reinterpret_cast<const alloc_info *>(fptr);
        size = pinfo->size;
        //fMemoryLocked = pinfo->fMemoryLocked;
        if(! mem.noaccess())
            throw std::runtime_error("quantum_lib::secure_mprotect_readonly noaccess failure");
    }
#if defined(WIN32)
    DWORD old;
    int ret = ::VirtualProtect(__ptr, size, PAGE_READONLY, &old) ? 0 : -1;
#else
    int ret = ::mprotect(__ptr, size, PROT_READ);
#endif

    return ret == 0;
}

bool quantum_lib::secure_mprotect_readwrite(void *ptr) {
    if(args_bool::fMemoryLockPermissive)
        return true;

    int32_t size;
    //bool fMemoryLocked;
    {
        void *fptr = reinterpret_cast<void *>((byte *)ptr - alloc_info_size);
        manage mem(fptr, alloc_info_size);
        if(! mem.readonly())
            throw std::runtime_error("quantum_lib::secure_mprotect_readwrite readonly failure");
        const alloc_info *pinfo = reinterpret_cast<const alloc_info *>(fptr);
        size = pinfo->size;
        //fMemoryLocked = pinfo->fMemoryLocked;
        if(! mem.noaccess())
            throw std::runtime_error("quantum_lib::secure_mprotect_readwrite noaccess failure");
    }
#if defined(WIN32)
    DWORD old;
    int ret = ::VirtualProtect(ptr, size, PAGE_READWRITE, &old) ? 0 : -1;
#else
    int ret = ::mprotect(ptr, size, PROT_READ | PROT_WRITE);
#endif

    return ret == 0;
}

void quantum_lib::secure_randombytes_buf(unsigned char *data, size_t sizeIn) {
    latest_crypto::random::GetStrongRandBytes(data, sizeIn);
}

namespace quantum_hash {
void blake2_generichash(std::uint8_t *hash, size_t size_hash, const std::uint8_t *data, size_t size_data)  {
    static constexpr size_t buffer_length = 32768;
    blake2s_hash::blake2s_state S;
    blake2s_hash::blake2s_init(&S, size_hash);
    size_t remain = size_data;
    const std::uint8_t *p = data;
    const int count = size_data / buffer_length;
    int i = 0;
    do {
        if (remain <= buffer_length) {
            blake2s_hash::blake2s_update(&S, p, remain);
            break;
        } else {
            blake2s_hash::blake2s_update(&S, p, buffer_length);
            remain -= buffer_length;
            p += buffer_length;
        }
    } while (i++ < count);
    blake2s_hash::blake2s_final(&S, hash, size_hash);
}

void blake2_hash(std::uint8_t hash[CBLAKE2S::Size()], const std::uint8_t *data, size_t size_data)  {
    assert(latest_crypto::Lamport::BLAKE2KeyHash::Size()==CBLAKE2S::Size());
    CBLAKE2S ctx;
    ctx.Write(data, size_data);
    ctx.Finalize(hash);
}
} // quantum_hash

namespace Lamport {

void util::alloc(byte *&dest, const byte *dataIn, size_t size) {
    dest = new (std::nothrow) byte[size];
    if (! dest) throw std::runtime_error("Lamport::util::alloc memory allocate failure.");
    if (dataIn) std::memcpy(dest, dataIn, size);
}

void util::alloc_secure_random(CSecureSegment<byte> *&secure, size_t kRandomNumbersCountIn, size_t kRandomNumberSizeIn) {
    secure = new (std::nothrow) CSecureSegment<byte>(kRandomNumbersCountIn * kRandomNumberSizeIn);
    if (! secure) throw std::runtime_error("Lamport::util::alloc_secure memory allocate failure.");
    CSecureSegmentRW<byte> guard = secure->unlockAndInitRW(false);
    byte *offset = guard.get_addr();
    for (size_t i = 0; i < kRandomNumbersCountIn; ++i) {
        quantum_lib::secure_randombytes_buf(offset, kRandomNumberSizeIn);
        offset += kRandomNumberSizeIn;
    }
}

void util::alloc_secure(CSecureSegment<byte> *&secure, const byte *dataIn, size_t sizeIn) {
    secure = new (std::nothrow) CSecureSegment<byte>(sizeIn);
    if(! secure) throw std::runtime_error("Lamport::util::alloc_secure memory allocate failure.");
    if(! dataIn) return;
    CSecureSegmentRW<byte> guard = secure->unlockAndInitRW(false);
    byte *offset = guard.get_addr();
    std::memcpy(offset, dataIn, sizeIn);
}

void util::release(byte *&data) {
    if (data) delete[] data;
    data = nullptr;
}

void util::release(CSecureSegment<byte> *&secure) {
    if (secure) delete secure;
    secure = nullptr;
}

std::shared_ptr<CPublicKey> CPrivateKey::derivePublicKey() const {
    CSecureSegmentRW<byte> guard = secure->unlockAndInitRW(true);
    try {
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

    } catch (std::bad_alloc &) {
        return std::shared_ptr<CPublicKey>(nullptr);
    }
}

BLAKE2KeyHash::BLAKE2KeyHash(const CPrivateKey &key) {
    CSecureSegmentRW<byte> guard = key.get_secure()->unlockAndInitRW(true);
    quantum_hash::blake2_hash(data, guard.get_addr(), key.get_size());
}

BLAKE2KeyHash::BLAKE2KeyHash(std::shared_ptr<CPrivateKey> key) {
    CSecureSegmentRW<byte> guard = key->get_secure()->unlockAndInitRW(true);
    quantum_hash::blake2_hash(data, guard.get_addr(), key->get_size());
}

BLAKE2KeyHash::BLAKE2KeyHash(std::shared_ptr<CPublicKey> key) {
    quantum_hash::blake2_hash(data, key->get_addr(), key->get_size());
}

BLAKE2KeyHash::BLAKE2KeyHash(byte *buffer) {
    std::memcpy(data, buffer, kBytesSize);
}

void CSignature::collectSignature(byte *signature, const byte *key, const byte *messageHash) {
    byte *signatureOffset = signature;
    const byte *numbersPairOffset = key;
    for (size_t i = 0; i < hashSize; ++i) {
        std::bitset<bitsInByte> byteOfMessageHash(messageHash[i]);
        for (size_t b = 0; b < bitsInByte; ++b) {
            const byte *source = numbersPairOffset + hashSize;
            if (byteOfMessageHash.test(b)) source = numbersPairOffset;
            std::memcpy(signatureOffset, source, hashSize);
            numbersPairOffset += hashSize * 2;
            signatureOffset += hashSize;
        }
    }
}

// static method (Sign) signatured size is 8KB
void CSignature::Sign(const byte *data, size_t size, const CPrivateKey &pKey, byte *signatured) {
    //
    // hashed Signature data
    //
    assert(pKey.get_secure());
    byte messageHash[hashSize];
    quantum_hash::blake2_generichash(messageHash, hashSize, data, size);
    CSecureSegmentRW<byte> guard = pKey.get_secure()->unlockAndInitRW(true);
    collectSignature(signatured, guard.get_addr(), messageHash);
}

// static method (Verify) signatured size is 8KB
bool CSignature::Verify(const byte *data, size_t size, const CPublicKey &pubKey, const byte *signatured) {
    //
    // Collecting hashed data signature.
    //
    byte messageHash[hashSize]; // 32 bytes
    quantum_hash::blake2_generichash(messageHash, hashSize, data, size);

    //
    // Collecting pub key signature.
    //
    byte pubKeySignature[kSize]; // 32 * 512 / 2 = 8192 bytes
    collectSignature(pubKeySignature, pubKey.get_addr(), messageHash);

    // test OK
    // compact pubkey
    /*
    byte pubKeySignature2[kSize];
    CPublicKey pubKey2 = pubKey;
    for(int i=0; i < pubKey2.get_size(); i+=32) {
        std::memset(pubKey2.get_addr() + i + compactpubkey, 0x00, 32 - compactpubkey);
    }
    collectSignature(pubKeySignature2, pubKey2.get_addr(), messageHash);
    */

    //
    // Collecting hashed signature.
    //
    byte hashedSignature[kSize]; // 32 * 512 / 2 = 8192 bytes
    const byte *originalSignatureOffset = signatured;
    byte *hashedSignatureOffset = hashedSignature;
    for (size_t i = 0; i < hashCount / 2; ++i) {
        quantum_hash::blake2_generichash(hashedSignatureOffset, hashSize, originalSignatureOffset, hashSize);
        originalSignatureOffset += hashSize;
        hashedSignatureOffset += hashSize;
    }

    //
    // if compact pubkey, Comparing results.
    //
    bool compact_compare = true;
    for(int i=0; i < kSize; i+=32) {
        if(std::memcmp(pubKeySignature + i, hashedSignature + i, compactpubkey) != 0) {
            compact_compare = false;
            break;
        }
    }
    if(compact_compare) {
        return true; // OK, compact pubkey.
    }

    //
    // if fully pubkey, Comparing results.
    //
    return (std::memcmp(pubKeySignature, hashedSignature, kSize) == 0) ? true : false;
}

// static method (Verify) signatured size is 128bytes (for blockchain)
bool CSignature::VerifyQai(const byte *data, size_t size, const CPublicKey &pubKey, const byte *signatured) {
    //
    // Collecting hashed data signature.
    //
    byte messageHash[hashSize]; // 32 bytes
    quantum_hash::blake2_generichash(messageHash, hashSize, data, size);

    //
    // Collecting pub key signature.
    //
    byte pubKeySignature[kSize]; // 32 * 512 / 2 = 8192 bytes
    collectSignature(pubKeySignature, pubKey.get_addr(), messageHash);

    //
    // Collecting hashed signature.
    //
    qkey_vector sigOrg;
    sigOrg.resize(kSize);
    ::memset(&sigOrg.front(), 0x00, sigOrg.size());
    ::memcpy(&sigOrg.front(), signatured, 128);
    byte hashedSignature[kSize]; // 32 * 512 / 2 = 8192 bytes
    const byte *originalSignatureOffset = sigOrg.data();
    byte *hashedSignatureOffset = hashedSignature;
    for (size_t i = 0; i < hashCount / 2; ++i) {
        quantum_hash::blake2_generichash(hashedSignatureOffset, hashSize, originalSignatureOffset, hashSize);
        originalSignatureOffset += hashSize;
        hashedSignatureOffset += hashSize;
    }

    if(std::memcmp(pubKeySignature, hashedSignature, 128) == 0) {
        if(std::memcmp(pubKeySignature, hashedSignature, 129) != 0) {
            debugcs::instance() << "Signature invalid check OK" << debugcs::endl();
        }
        debugcs::instance() << "qpubkey 264 bytes:\n" << strenc::HexStr(qkey_vector(pubKey.get_addr(), pubKey.get_addr() + 264)).c_str() << debugcs::endl();
        debugcs::instance() << "qpubkey sig 136 bytes:\n" << strenc::HexStr(qkey_vector(BEGIN(pubKeySignature), END(pubKeySignature))).substr(0, 136).c_str() << debugcs::endl();
        debugcs::instance() << "hashed sig 136 bytes" << strenc::HexStr(qkey_vector(BEGIN(hashedSignature), END(hashedSignature))).substr(0, 136).c_str() << debugcs::endl();
    }

    //
    // Comparing results.
    //
    return (std::memcmp(pubKeySignature, hashedSignature, 128) == 0) ? true: false; // address space is 2 ^ (128 * 8)
}

bool CSignature::Verify(const byte *dataIn, size_t dataSize, std::shared_ptr<const CPublicKey> pubKey) {
    if (dataIn == nullptr || dataSize == 0 || pubKey == nullptr)
        return false;

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
    const byte *originalSignatureOffset = _signatured;
    byte *hashedSignatureOffset = hashedSignature;
    for (size_t i = 0; i < hashCount / 2; ++i) {
        quantum_hash::blake2_generichash(hashedSignatureOffset, hashSize, originalSignatureOffset, hashSize);
        originalSignatureOffset += hashSize;
        hashedSignatureOffset += hashSize;
    }

    //
    // Comparing results.
    //
    return (::memcmp(pubKeySignature, hashedSignature, kSize) == 0) ? true : false;
}

std::shared_ptr<CPublicKey> CSignature::derivePublicKey(const byte *dataIn, size_t dataSize, CPrivateKey *pKey) {
    if(pKey->is_ok())
        return std::shared_ptr<CPublicKey>(nullptr);

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
    collectSignature(_signatured, guard.get_addr(), messageHash);

    //
    // 3, Cropping the private key.
    // This is needed to prevent it reuse.
    //
    pKey->set_cropped();

    return pubKey;
}

void CSignature::createHash(const byte *dataIn, size_t dataSize, CPrivateKey *pKey) {
    using pbkdf5 = pbkdf2_impl<latest_crypto::CSHA512>;

    byte previous[sizeof(_signatured)];
    std::memcpy(previous, _signatured, sizeof(_signatured));

    byte messageHash[hashSize];
    quantum_hash::blake2_generichash(messageHash, hashSize, dataIn, dataSize);
    CSecureSegmentRW<byte> guard = pKey->get_secure()->unlockAndInitRW(true);
    collectSignature(_signatured, guard.get_addr(), messageHash);

    auto is_memzero = [&](const byte *p) {
        static byte cmp[sizeof(_signatured)] = {'\0'};
        return (::memcmp(p, cmp, sizeof(cmp))==0)? true: false;
    };
    if(! is_memzero(previous)) {
        debugcs::instance() << "LAMPORT WRITE PBKDF2 count: 1" << debugcs::endl();
        pbkdf5::PBKDF2_HASH(previous, kSize, messageHash, hashSize, 1, _signatured, sizeof(_signatured));
    } else {
        debugcs::instance() << "LAMPORT WRITE FIRST" << debugcs::endl();
    }
}

//
// CLamport
//

CLamport::CLamport(const CLamport &obj) : _privkey(obj._privkey.get_addr(), obj._privkey.get_size()) {
    *(CSignature *)this = (const CSignature &)obj;
}

CLamport &CLamport::operator=(const CLamport &obj) {
    _privkey.operator=(obj._privkey);
    *(CSignature *)this = (const CSignature &)obj;
    return *this;
}

CLamport::CLamport() : _privkey(), CSignature() {}

CLamport::CLamport(const byte *dataIn) : _privkey(dataIn, 16 * 1024), CSignature() {}

CLamport::~CLamport() {}

std::shared_ptr<CPublicKey> CLamport::CreatePubKey(const unsigned char *data, size_t size) {
    return derivePublicKey(data, size, &_privkey);
}

CPublicKey CLamport::GetPubKey() const {
    std::shared_ptr<CPublicKey> pubKey = _privkey.derivePublicKey();
    return *pubKey.get();
}

CPublicKey CLamport::GetPubKeyQai() const {
    std::shared_ptr<CPublicKey> pubKey = _privkey.derivePublicKey();
    CPublicKey pubkey = *pubKey.get();
    std::memset(pubkey.get_addr() + CqPubKey::QAI_PUBLIC_KEY_SIZE, 0x00, pubkey.get_size() - CqPubKey::QAI_PUBLIC_KEY_SIZE);
    return pubkey;
}

bool CLamport::CmpPrivKey(const CLamport &obj) const {
    return this->_privkey == obj._privkey;
}

const CSecureSegment<byte> *CLamport::GetPrivKey() const {
    return this->_privkey.get_secure();
}

void CLamport::Sign(const byte *data, size_t size, byte *signatured) const {
    CSignature::Sign(data, size, _privkey, signatured);
}

void CLamport::create_hashonly(const std::uint8_t *dataIn, size_t dataSize) {
    this->createHash(dataIn, dataSize, &_privkey);
}

}} // latest_crypto and Lamport



//
// quantum resist key
//

CqKey::CqKey(const CqSecretKey &seed) : _lamport(nullptr), _valid(false) { // must be seed size is "16 * 1024"
    if(seed.size()!=16 * 1024)
        return;

    _lamport = new (std::nothrow) latest_crypto::Lamport::CLamport(seed.data());
    if(_lamport)
        _valid = true;
}

CqPubKey CqKey::GetPubKey(bool fCompact /*= true*/) const {
    if(! _valid)
        throw std::runtime_error("CqKey::GetPubKey invalid.");
    latest_crypto::Lamport::CPublicKey pubkey = _lamport->GetPubKey();
    if(fCompact) {
        for(int i=0; i < pubkey.get_size(); i+=32) {
            std::memset(pubkey.get_addr() + i + latest_crypto::Lamport::compactpubkey, 0x00, 30);
        }
    }

/* [OK]
#ifdef DEBUG
    std::vector<unsigned char> vchpubkey;
    vchpubkey.resize(pubkey.get_size());
    ::memcpy(&vchpubkey.front(), pubkey.get_addr(), pubkey.get_size());
    std::string debug_str = strenc::HexStr(vchpubkey);
    ::printf("CqKey GetPubKey: %s\n", debug_str.c_str());
#endif
*/
    return pubkey;
}

CqPubKey CqKey::GetPubKeyQai() const {
    if(! _valid)
        throw std::runtime_error("CqKey::GetPubKeyQai invalid.");
    latest_crypto::Lamport::CPublicKey pubkey = _lamport->GetPubKeyQai();
    assert(pubkey.get_size() == 16384);
    return pubkey;
}

CqSecretKey CqKey::GetSecret() const {
    if(! _valid)
        throw std::runtime_error("CqKey::GetSecret invalid.");
    const latest_crypto::CSecureSegment<unsigned char> *secure = _lamport->GetPrivKey();
    const latest_crypto::CSecureSegmentRW<unsigned char> obj = secure->unlockAndInitRW(true);
    CqSecretKey qkey;
    qkey.resize(obj.get_size());
    std::memcpy(&qkey.front(), obj.get_addr(), obj.get_size());
    return qkey;
}

bool CqPubKey::Verify(const qkey_vector &data, const qkey_vector &vchSig) const {
    return latest_crypto::Lamport::CLamport::Verify(data.data(), data.size(), *this, vchSig.data());
}

bool CqPubKey::Verify(const uint256 &data, const qkey_vector &vchSig) const {
    assert(sizeof(uint256)==32);
    return latest_crypto::Lamport::CLamport::Verify(data.begin(), sizeof(uint256), *this, vchSig.data());
}

bool CqPubKey::VerifyQai(const uint256 &data, const qkey_vector &vchSig) const {
    assert(sizeof(uint256)==32);
    if(vchSig.size() != 128)
        return false;

    return latest_crypto::Lamport::CLamport::VerifyQai(data.begin(), sizeof(uint256), *this, vchSig.data());
}

qkey_vector CqPubKey::GetVch() const { // qai: 256 bytes, compact: 1024 bytes, fully: 16384 bytes
    unsigned char qaicmp[32];
    ::memset(qaicmp, 0x00, 32);
    latest_crypto::Lamport::CPublicKey pubkey = *(static_cast<const latest_crypto::Lamport::CPublicKey *>(this));
    if(::memcmp(pubkey.get_addr() + QAI_PUBLIC_KEY_SIZE, qaicmp, 32) == 0) {
        qkey_vector vchqai;
        vchqai.resize(QAI_PUBLIC_KEY_SIZE);
        ::memcpy(&vchqai.front(), pubkey.get_addr(), QAI_PUBLIC_KEY_SIZE);
        return vchqai;
    }

    bool fCompact = true;
    const unsigned char objnull[32 - latest_crypto::Lamport::compactpubkey] = {0};
    qkey_vector compact;
    compact.resize((pubkey.get_size()/32) * latest_crypto::Lamport::compactpubkey);
    for(int i=0, k=0; i < pubkey.get_size(); i+=32) {
        std::memcpy(&compact.front() + ((uintptr_t)k++ * latest_crypto::Lamport::compactpubkey), pubkey.get_addr() + i, latest_crypto::Lamport::compactpubkey);
        if(std::memcmp(pubkey.get_addr() + i + latest_crypto::Lamport::compactpubkey, objnull, 32 - latest_crypto::Lamport::compactpubkey) != 0) {
            fCompact = false;
            break;
        }
    }
    if(fCompact) {
        return compact;
    }

    qkey_vector vchpub;
    vchpub.resize(pubkey.get_size());
    ::memcpy(&vchpub.front(), pubkey.get_addr(), pubkey.get_size());
    return vchpub;
}

CqKeyID CqPubKey::GetID() const {
    return CqKeyID(strenc::HexStr(GetVch()));
}

bool CqPubKey::IsFullyValid_BIP66() const {
    return _valid;
}

bool CqPubKey::IsCompressed() const {
    if(! _valid)
        return false;
    CqKeyID id = GetID();
    return ((id.size() / 2) == COMPRESSED_PUBLIC_KEY_SIZE);
}

bool CqPubKey::RecoverCompact(const qkey_vector &vchSig) {
    //::printf("RecoverCompact size: %d\n", (int)vchSig.size());
    if(vchSig.size() == QAI_PUBLIC_KEY_SIZE) {
        qkey_vector vchSig2;
        vchSig2.resize(FULLY_PUBLIC_KEY_SIZE, 0x00);
        const unsigned char *psig = vchSig.data();

        ::memcpy(&vchSig2.front(), psig, QAI_PUBLIC_KEY_SIZE);
        this->operator=(latest_crypto::Lamport::CPublicKey(vchSig2.data(), vchSig2.size()));
        _valid = true;
        return true;
    } else if(vchSig.size() == COMPRESSED_PUBLIC_KEY_SIZE) {
        qkey_vector vchSig2;
        vchSig2.resize(FULLY_PUBLIC_KEY_SIZE, 0x00);
        const unsigned char *psig = vchSig.data();

        for(int i=0; i < FULLY_PUBLIC_KEY_SIZE; i += 32) {
            for (int k=0; k < latest_crypto::Lamport::compactpubkey; ++k) {
                vchSig2[i + k] = *psig++;
            }
        }

        this->operator=(latest_crypto::Lamport::CPublicKey(vchSig2.data(), vchSig2.size()));
        _valid = true;
        return true;
    } else if (vchSig.size() == FULLY_PUBLIC_KEY_SIZE) {
        this->operator=(latest_crypto::Lamport::CPublicKey(vchSig.data(), vchSig.size()));
        _valid = true;
        return true;
    }
    _valid = false;
    return false;
}

bool CqPubKey::RecoverCompact(const CqKeyID &pubkeyid) {
    return RecoverCompact(strenc::ParseHex(pubkeyid));
}

uint256 CqPubKey::GetHash() const {
    qkey_vector qvch = GetVch();
    uint256 hash;
    latest_crypto::CHash256().Write((const unsigned char *)qvch.data(), qvch.size()).Finalize(hash.begin());
    return hash;
}

qkey_vector CqPubKey::GetQaiHash() const {
    qkey_vector qvch = GetVch();
    uint160 hash;
    latest_crypto::CHash160().Write((const unsigned char *)qvch.data(), qvch.size()).Finalize(hash.begin());

    //uint256 hash256;
    //uint160 hash160;
    //latest_crypto::CSHA256().Write((const unsigned char *)qvch.data(), qvch.size()).Finalize(hash256.begin());
    //latest_crypto::CRIPEMD160().Write((const unsigned char *)hash256.begin(), hash256.size()).Finalize(hash160.begin());
    //assert(hash == hash160);

    qkey_vector qhash;
    qhash.resize(33); // size is CPubKey::COMPRESSED_PUBLIC_KEY_SIZE
    ::memset(&qhash.front(), 0x00, 33);
    qhash[0] = 0x02;
    ::memcpy(&qhash.front() + 1, hash.begin(), sizeof(uint160));
    return qhash;
}

bool CqPubKey::CmpQaiHash(const qkey_vector &hashvch) const {
    return (GetQaiHash() == hashvch);
}

bool CqPubKey::IsQaiHash(const qkey_vector &hashvch) {
    if(hashvch.size() != 33)
        return false;

    for(int i=21; i < 33; ++i) { // [0] 0x02, [1] - [20] uint160, [21] - [32] 0x00
        if(hashvch[i] != 0x00)
            return false;
    }
    return true;
}

static unsigned char QaiVersion = (unsigned char)0x01;
qkey_vector CqPubKey::GetRandHash() {
    qkey_vector buf;
    buf.resize(33); // size is CPubKey::COMPRESSED_PUBLIC_KEY_SIZE
    ::memset(&buf.front(), 0xFF, 33);
    buf[0] = 0x02;
    buf[1] = QaiVersion;
    if(!map_arg::GetBoolArg(std::string("-restorehdwallet"))) {
        latest_crypto::random::GetStrongRandBytes(&buf[2], 20);
    }
    return buf;
}

bool CqPubKey::IsRandHash(const qkey_vector &randvch) {
    if(randvch.size() != 33)
        return false;

    for(int i=22; i < 33; ++i) { // [0] 0x02, [1] version, [2] - [21] rand, [22] - [32] 0xFF
        if(randvch[i] != 0xFF)
            return false;
    }
    return true;
}

void CqKey::Sign(const qkey_vector &data, qkey_vector &vchSig) const {
    vchSig.resize(_lamport->GetSize());
    _lamport->Sign(data.data(), data.size(), &vchSig.front());
}

void CqKey::Sign(const uint256 &hash, qkey_vector &vchSig) const {
    vchSig.resize(_lamport->GetSize());
    assert(sizeof(uint256)==32);
    _lamport->Sign(hash.begin(), sizeof(uint256), &vchSig.front());
}

void CqKey::SignQai(const uint256 &hash, qkey_vector &vchSig) const {
    assert(sizeof(uint256)==32);
    qkey_vector vchOrg;
    vchOrg.resize(_lamport->GetSize());
    _lamport->Sign(hash.begin(), sizeof(uint256), &vchOrg.front());
    assert(vchOrg.size() == 8192);
    vchSig.resize(_lamport->GetSize() / 64); // vchSig is 128bytes
    ::memcpy(&vchSig.front(), vchOrg.data(), _lamport->GetSize() / 64);
}

bool CqKey::VerifyPubKey(const CqPubKey &pubkey) const {
    unsigned char rnd[8];
    std::string str = "SorachanCoin key verification\n";
    latest_crypto::random::GetRandBytes(rnd, sizeof(rnd));
    uint256 hash;
    latest_crypto::CHash256().Write((unsigned char *)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash.begin());
    qkey_vector vchSig;
    Sign(hash, vchSig);
    bool ret = pubkey.Verify(hash, vchSig);
    cleanse::OPENSSL_cleanse(rnd, sizeof(rnd));
    cleanse::OPENSSL_cleanse(&hash, sizeof(uint256));
    cleanse::OPENSSL_cleanse(vchSig.data(), vchSig.size() * sizeof(unsigned char));
    return ret;
}

//
// TEST: runtime.
//
#ifdef DEBUG_RUNTIME_TEST
# define SANITY_TEST
#endif

//
// CHECK: prevector, aes, memory, hash, json
//
#ifdef DEBUG_ALGO_CHECK
# define PREVECTOR_CHECK
# define AES_CHECK
# define MEMORY_CHECK
# define HASH_CHECK
//# define JSON_CHECK // note: univalue is checking ... (still failure)
#endif

#include <util/tinyformat.h>

class Quantum_startup
{
private:
    static constexpr int _test_count = 1;
private:
    typedef std::uint8_t byte;
    static Quantum_startup q_startup;

    static void sanity_check()  {
        bool a = test_sanity::glibc_sanity_test();
        bool b = test_sanity::glibcxx_sanity_test();
        assert(a && b);
        debugcs::instance() << "[OK] SorachanCoin sanity_check()" << debugcs::endl();
    }

    template <int rsv, typename T>
    static void prevector_check(int n, int m)  {
        debugcs::instance() << "[[[BEGIN]]] SorachanCoin the vector testing ..." << debugcs::endl();

        _bench_func("[vector] prevector_check() Des Tri", &check_prevector::PrevectorDestructorTrivial, 3, 3);
        _bench_func("[vector] prevector_check() Des Nontri", &check_prevector::PrevectorDestructorNontrivial, 3, 3);
        _bench_func("[vector] prevector_check() Cle Tri", &check_prevector::PrevectorClearTrivial, 3, 3);
        _bench_func("[vector] prevector_check() Cle Nontri", &check_prevector::PrevectorClearNontrivial, 3, 3);
        _bench_func("[vector] prevector_check() Res Tri", &check_prevector::PrevectorResizeTrivial, 3, 3);
        _bench_func("[vector] prevector_check() Res Nontri", &check_prevector::PrevectorResizeNontrivial, 3, 3);
        _bench_func("[vector] prevector_check() Deseria Tri", &check_prevector::PrevectorDeserializeTrivial, 3, 3);
        _bench_func("[vector] prevector_check() Deseria Nontri", &check_prevector::PrevectorDeserializeNontrivial, 3, 3);

        _bench_func("[vector] std_check() Des Tri", &check_prevector::StdvectorDestructorTrivial, 3, 3);
        _bench_func("[vector] std_check() Des Nontri", &check_prevector::StdvectorDestructorNontrivial, 3, 3);
        _bench_func("[vector] std_check() Cle Tri", &check_prevector::StdvectorClearTrivial, 3, 3);
        _bench_func("[vector] std_check() Cle Nontri", &check_prevector::StdvectorClearNontrivial, 3, 3);
        _bench_func("[vector] std_check() Res Tri", &check_prevector::StdvectorResizeTrivial, 3, 3);
        _bench_func("[vector] std_check() Res Nontri", &check_prevector::StdvectorResizeNontrivial, 3, 3);
        _bench_func("[vector] std_check() Deseria Tri", &check_prevector::StdvectorDeserializeTrivial, 3, 3);
        _bench_func("[vector] std_check() Deseria Nontri", &check_prevector::StdvectorDeserializeNontrivial, 3, 3);

        _bench_func("[vector] prevector_s_check() Des Tri", &check_prevector::Prevector_s_DestructorTrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Des Nontri", &check_prevector::Prevector_s_DestructorNontrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Cle Tri", &check_prevector::Prevector_s_ClearTrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Cle Nontri", &check_prevector::Prevector_s_ClearNontrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Res Tri", &check_prevector::Prevector_s_ResizeTrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Res Nontri", &check_prevector::Prevector_s_ResizeNontrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Deseria Tri", &check_prevector::Prevector_s_DeserializeTrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Deseria Nontri", &check_prevector::Prevector_s_DeserializeNontrivial, 1, 1);

        _bench_func("[vector] prevector_check() Assertcheck Tri", &check_prevector::PrevectorAssertcheckTrivial, 1, 1);
        _bench_func("[vector] prevector_check() Assertcheck Nontri", &check_prevector::PrevectorAssertcheckNontrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Assertcheck Tri", &check_prevector::Prevector_s_AssertcheckTrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Assertcheck Nontri", &check_prevector::Prevector_s_AssertcheckNontrivial, 1, 1);

        _bench_func("[secure vector] secure_vector_check() Assertcheck Tri", &check_prevector::SecurevectorAssertcheckTrivial);
        _bench_func("[secure vector] secure_vector_check() Assertcheck Nontri", &check_prevector::SecurevectorAssertcheckNontrivial);

        debugcs::instance() << "[[[OK]]] SorachanCoin the checked vector" << debugcs::endl();
    }

    static void aes_check()  {
        debugcs::instance() << "[[[BEGIN]]] SorachanCoin the crypto testing ..." << debugcs::endl();

        _bench_func("[crypto] AES128_check()", &latest_crypto::bench_AES128, 1, 1);
        _bench_func("[crypto] AES192_check()", &latest_crypto::bench_AES192, 1, 1);
        _bench_func("[crypto] AES256_check()", &latest_crypto::bench_AES256, 1, 1);
        latest_crypto::check_all_aes();

        debugcs::instance() << "[[[OK]]] SorachanCoin the checked crypto" << debugcs::endl();
    }

    static void memory_check()  {
        debugcs::instance() << "[[[BEGIN]]] SorachanCoin the memory testing ..." << debugcs::endl();

        assert(1);

        debugcs::instance() << "[[[OK]]] SorachanCoin the checked memory" << debugcs::endl();
    }

    static void hash_check()  {
        debugcs::instance() << "[[[BEGIN]]] SorachanCoin the hash testing ..." << debugcs::endl();

        _bench_func("[hash] Ripemd160_check()", &latest_crypto::Ripemd160Assertcheck);
        _bench_func("[hash] SHA256_check()", &latest_crypto::SHA256Assertcheck);
        _bench_func("[hash] SHA512_check()", &latest_crypto::SHA512Assertcheck);
        _bench_func("[hash] blake2_check()", &latest_crypto::Blake2Assertcheck);
        _bench_func("[hash] lamport_check() Assertcheck", &latest_crypto::LamportAssertcheck);

        debugcs::instance() << "[[[OK]]] SorachanCoin the checked blake2 and lamport" << debugcs::endl();
    }

    static void json_check()  {
        debugcs::instance() << "[[[BEGIN]]] SorachanCoin the JSON testing ..." << debugcs::endl();

        _bench_func("[JSON] json_check()", &latest_json::JsonAssertcheck, 1, 1);

        debugcs::instance() << "[[[OK]]] SorachanCoin the checked JSON" << debugcs::endl();
    }

#ifdef WIN32
    static unsigned int __stdcall benchmark(void *)  {
        for(int i = 0; i < _test_count; ++i)
        {
#ifdef SANITY_TEST
            sanity_check();
#endif
#ifdef PREVECTOR_CHECK
            prevector_check<PREVECTOR_N, uint8_t>(10, 300);
#endif
#if defined(AES_CHECK)
            aes_check();
#endif
#ifdef MEMORY_CHECK
            memory_check();
#endif
#if defined(HASH_CHECK)
            hash_check();
#endif
#ifdef JSON_CHECK
            json_check();
#endif
        }
        return 1;
    }
#endif
private:
    Quantum_startup()  {
#if defined(DEBUG)
        //
        // Lamport benchmark [Thread Safe]
        //
        std::thread th1(&Quantum_startup::benchmark, nullptr);
        std::thread th2(&Quantum_startup::benchmark, nullptr);
        th1.join();
        th2.join();

        //
        // tiny format test
        //
        /*
        int64_t num = 0x1000000000000;
        std::string tny1 = tfm::format("%d", num);
        std::string tny2 = tfm::format("%u", num);
        //std::string tny3 = tfm::format("%", num); // NG
        std::string tny4 = tfm::format("%x", num);
        debugcs::instance() << "tny1: " << tny1.c_str()
                            << " tny2: " << tny2.c_str()
                            //<< " tny3: " << tny3.c_str()
                            << " tny4: " << tny4.c_str()
                            << debugcs::endl();
        assert(tny1==tny2); // d == u, I64d == d, x(16), %(NG)
        */
#endif
    }
    ~Quantum_startup() {}
};
//Quantum_startup Quantum_startup::q_startup;
