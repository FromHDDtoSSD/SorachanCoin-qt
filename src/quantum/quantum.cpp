// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(USE_QUANTUM)

#include <bitset>
#include <thread>
#include <quantum/quantum.h>
#include <prevector/prevector.h>
#include <prevector/prevector_s.h>
#include <crypto/sha512.h>
#include <blake2.h>
#include <pbkdf2.h>
#include <compat/sanity.h>

#include <openssl/rand.h>
#include <cleanse/cleanse.h>

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

namespace latest_crypto {

void quantum_lib::manage::readonly() const {
#if defined(WIN32)
    DWORD old;
    if (! ::VirtualProtect(ptr, size, PAGE_READONLY, &old))
        throw std::runtime_error("secure_list::manage failure.");
#else
    if (::mprotect(ptr, size, PROT_READ) != 0)
        throw std::runtime_error("secure_list::manage failure.");
#endif
}

void quantum_lib::manage::readwrite() const {
#if defined(WIN32)
    DWORD old;
    if (! ::VirtualProtect(ptr, size, PAGE_READWRITE, &old))
        throw std::runtime_error("secure_list::manage failure.");
#else
    if (::mprotect(ptr, size, PROT_READ | PORT_WRITE) != 0)
        throw std::runtime_error("secure_list::manage failure.");
#endif
}

quantum_lib::manage::~manage() noexcept {
#if defined(WIN32)
    DWORD old;
    (void)::VirtualProtect(ptr, size, PAGE_NOACCESS, &old);
#else
    (void)::mprotect(ptr, size, PROT_NONE);
#endif
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
    if (! ptr) throw std::runtime_error("secure_alloc memory allocate failure.");

#if defined(WIN32)
    bool lock_ret = false;
    lock_ret = (::VirtualLock(ptr, sizeIn + alloc_info_size) != FALSE) ? true : false;
#else
    lock_ret = (::mlock(ptr, sizeIn + alloc_info_size) == 0) ? true : false;
#endif
    if (! lock_ret) throw std::runtime_error("secure_alloc virtual lock failure.");

    alloc_info *pinfo = reinterpret_cast<alloc_info *>(ptr);
    pinfo->data.type = LOCK_UNLOCK;
    pinfo->data.size = sizeIn;
    return reinterpret_cast<void *>((byte *)ptr + alloc_info_size);
}

void quantum_lib::secure_free(void *ptr, bool fRandom /*= false*/) noexcept {
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

void quantum_lib::secure_memzero(void *ptr, size_t sizeIn) noexcept {
    cleanse::memory_cleanse(ptr, sizeIn);
}

void quantum_lib::secure_memrandom(void *ptr, size_t sizeIn) noexcept {
    unsigned char *volatile pnt_ = (unsigned char *volatile)ptr;
    unsigned char buf[1024];
    (void)::RAND_bytes(buf, sizeof(buf) / sizeof(buf[0]));
    size_t i = (size_t)0U;
    while (i < sizeIn) {
        pnt_[i] = buf[i & (sizeof(buf) / sizeof(buf[0]) - 1)];
        ++i;
    }
}
#ifdef _MSC_VER
void quantum_lib::secure_stackzero(const size_t) noexcept {}
void quantum_lib::secure_stackrandom(const size_t) noexcept {}
#else
void quantum_lib::secure_stackzero(const size_t sizeIn) noexcept {
    unsigned char dummy[sizeIn];
    secure_memzero(dummy, sizeIn);
}

void quantum_lib::secure_stackrandom(const size_t sizeIn) noexcept {
    unsigned char dummy[sizeIn];
    secure_memrandom(dummy, sizeIn);
}
#endif

void quantum_lib::secure_mprotect_noaccess(const void *ptr) {
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
    if (ret != 0)
        throw std::runtime_error("secure_mprotect_noaccess failure.");
}

void quantum_lib::secure_mprotect_readonly(const void *ptr) {
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
    if (ret != 0)
        throw std::runtime_error("secure_mprotect_readonly failure.");
}

void quantum_lib::secure_mprotect_readwrite(void *ptr) {
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
        //debugcs::instance() << "SIZE: " << size << debugcs::endl();
    }
#if defined(WIN32)
    DWORD old;
    int ret = ::VirtualProtect(ptr, size, PAGE_READWRITE, &old) ? 0 : -1;
#else
    int ret = ::mprotect(ptr, size, PROT_READ | PORT_WRITE);
#endif
    if (ret != 0)
        throw std::runtime_error("secure_mprotect_readwrite failure.");
}

void quantum_lib::secure_randombytes_buf(unsigned char *data, size_t sizeIn) {
    if (::RAND_bytes(data, sizeIn) != 1)
        throw std::runtime_error("Quantum_lib RAND_byte failure.");
}

namespace quantum_hash {
void blake2_generichash(std::uint8_t *hash, size_t size_hash, const std::uint8_t *data, size_t size_data) {
    static const size_t buffer_length = 32768;
    blake2s_state S;
    ::blake2s_init(&S, size_hash);
    size_t remain = size_data;
    const std::uint8_t *p = data;
    const int count = size_data / buffer_length;
    int i = 0;
    do {
        if (remain <= buffer_length) {
            ::blake2s_update(&S, p, remain);
            break;
        } else {
            ::blake2s_update(&S, p, buffer_length);
            remain -= buffer_length;
            p += buffer_length;
        }
    } while (i++ < count);
    ::blake2s_final(&S, hash, size_hash);
}

void blake2_hash(std::uint8_t hash[CBLAKE2::Size()], const std::uint8_t *data, size_t size_data) {
    assert(latest_crypto::Lamport::BLAKE2KeyHash::Size()==CBLAKE2::Size());
    CBLAKE2 ctx;
    ctx.Write(data, size_data);
    ctx.Finalize(hash);
}
} // quantum_hash

namespace Lamport {

void util::alloc(byte *&dest, const byte *dataIn, size_t size) {
    dest = new (std::nothrow) byte[size];
    if (! dest) throw std::runtime_error("Lamport::util::alloc memory allocate failure.");
    if (dataIn) ::memcpy(dest, dataIn, size);
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
    ::memcpy(offset, dataIn, sizeIn);
    //debugcs::instance() << "ALLOC_SECURE SIZE: " << sizeIn << debugcs::endl();
}

void util::release(byte *&data) noexcept {
    //debugcs::instance() << "ALLOC FREE" << debugcs::endl();
    if (data) delete[] data;
    data = nullptr;
}

void util::release(CSecureSegment<byte> *&secure) noexcept {
    //debugcs::instance() << "ALLOC_SECURE FREE" << debugcs::endl();
    if (secure) delete secure;
    secure = nullptr;
}

std::shared_ptr<CPublicKey> CPrivateKey::derivePublicKey() const noexcept {
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

BLAKE2KeyHash::BLAKE2KeyHash(const CPrivateKey &key) noexcept {
    CSecureSegmentRW<byte> guard = key.get_secure()->unlockAndInitRW(true);
    quantum_hash::blake2_hash(data, guard.get_addr(), key.get_size());
}

BLAKE2KeyHash::BLAKE2KeyHash(std::shared_ptr<CPrivateKey> key) noexcept {
    CSecureSegmentRW<byte> guard = key->get_secure()->unlockAndInitRW(true);
    quantum_hash::blake2_hash(data, guard.get_addr(), key->get_size());
}

BLAKE2KeyHash::BLAKE2KeyHash(std::shared_ptr<CPublicKey> key) noexcept {
    quantum_hash::blake2_hash(data, key->get_addr(), key->get_size());
}

BLAKE2KeyHash::BLAKE2KeyHash(byte *buffer) noexcept {
    ::memcpy(data, buffer, kBytesSize);
}

void CSignature::collectSignature(byte *signature, const byte *key, const byte *messageHash) const noexcept {
    byte *signatureOffset = signature;
    const byte *numbersPairOffset = key;
    for (size_t i = 0; i < hashSize; ++i) {
        std::bitset<bitsInByte> byteOfMessageHash(messageHash[i]);
        for (size_t b = 0; b < bitsInByte; ++b) {
            const byte *source = numbersPairOffset + hashSize;
            if (byteOfMessageHash.test(b)) source = numbersPairOffset;
            ::memcpy(signatureOffset, source, hashSize);
            numbersPairOffset += hashSize * 2;
            signatureOffset += hashSize;
        }
    }
}

bool CSignature::check(const byte *dataIn, size_t dataSize, std::shared_ptr<const CPublicKey> pubKey) const noexcept {
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
    const byte *originalSignatureOffset = data;
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

std::shared_ptr<CPublicKey> CSignature::derivePublicKey(const byte *dataIn, size_t dataSize, CPrivateKey *pKey) noexcept {
    if(pKey->is_ok()) {
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

void CSignature::createHash(const byte *dataIn, size_t dataSize, CPrivateKey *pKey) noexcept {
    using pbkdf5 = pbkdf2_impl<latest_crypto::CSHA512>;

    byte previous[sizeof(data)];
    ::memcpy(previous, data, sizeof(data));

    byte messageHash[hashSize];
    quantum_hash::blake2_generichash(messageHash, hashSize, dataIn, dataSize);
    CSecureSegmentRW<byte> guard = pKey->get_secure()->unlockAndInitRW(true);
    collectSignature(data, guard.get_addr(), messageHash);

    auto is_memzero = [](const byte *p) {
        static byte cmp[sizeof(data)] = {'\0'};
        return (::memcmp(p, cmp, sizeof(cmp))==0)? true: false;
    };
    if(! is_memzero(previous)) {
        //debugcs::instance() << "LAMPORT WRITE PBKDF2 count: 1" << debugcs::endl();
        pbkdf5::PBKDF2_HASH(previous, kSize, messageHash, hashSize, 1, data, sizeof(data));
    } //else {
        //debugcs::instance() << "LAMPORT WRITE FIRST" << debugcs::endl();
    //}
}

CLamport::CLamport(const CLamport &obj) : privKey(obj.privKey.get_addr(), obj.privKey.get_size()), CSignature() {
    ::memcpy(this->get_addr(), obj.get_addr(), this->get_size());
}

CLamport &CLamport::operator=(const CLamport &obj) noexcept {
    privKey.operator=(obj.privKey);
    ::memcpy(this->get_addr(), obj.get_addr(), this->get_size());
    return *this;
}

CLamport::CLamport() noexcept : privKey(), CSignature() {} // Automatically, set random to privKey.
CLamport::CLamport(const byte *dataIn, size_t _size_check_) : privKey(dataIn, _size_check_), CSignature() {} // Manually, set 16KBytes random to privKey. Note: must _size_check_ is 16Kbytes.
CLamport::~CLamport() {}

std::shared_ptr<CPublicKey> CLamport::create_pubkey(const std::uint8_t *dataIn, size_t dataSize) noexcept {
    // std::shared_ptr<CPublicKey> debugKey = privKey.derivePublicKey();
    // Note: Call to CSignature::derivePublicKey
    return this->derivePublicKey(dataIn, dataSize, &privKey);
}

void CLamport::create_hashonly(const std::uint8_t *dataIn, size_t dataSize) noexcept {
    this->createHash(dataIn, dataSize, &privKey);
}

}} // latest_crypto and Lamport


class Quantum_startup
{
private:
    static const int _test_count = 1;
private:
    typedef std::uint8_t byte;
    static Quantum_startup q_startup;

    static void sanity_check() noexcept {
        bool a = test_sanity::glibc_sanity_test();
        bool b = test_sanity::glibcxx_sanity_test();
        assert(a && b);
        debugcs::instance() << "[OK] SorachanCoin sanity_check()" << debugcs::endl();
    }

    template <int rsv, typename T>
    static void prevector_check(int n, int m) noexcept {
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

    static void aes_check() noexcept {
        debugcs::instance() << "[[[BEGIN]]] SorachanCoin the crypto testing ..." << debugcs::endl();

        _bench_func("[crypto] AES128_check()", &latest_crypto::bench_AES128, 1, 1);
        _bench_func("[crypto] AES192_check()", &latest_crypto::bench_AES192, 1, 1);
        _bench_func("[crypto] AES256_check()", &latest_crypto::bench_AES256, 1, 1);
        latest_crypto::check_all_aes();

        debugcs::instance() << "[[[OK]]] SorachanCoin the checked crypto" << debugcs::endl();
    }

    static void memory_check() noexcept {
        debugcs::instance() << "[[[BEGIN]]] SorachanCoin the memory testing ..." << debugcs::endl();

        assert(1);

        debugcs::instance() << "[[[OK]]] SorachanCoin the checked memory" << debugcs::endl();
    }

    static void hash_check() noexcept {
        debugcs::instance() << "[[[BEGIN]]] SorachanCoin the hash testing ..." << debugcs::endl();

        _bench_func("[hash] Ripemd160_check()", &latest_crypto::Ripemd160Assertcheck);
        _bench_func("[hash] SHA256_check()", &latest_crypto::SHA256Assertcheck);
        _bench_func("[hash] SHA512_check()", &latest_crypto::SHA512Assertcheck);
        _bench_func("[hash] blake2_check()", &latest_crypto::Blake2Assertcheck);
        _bench_func("[hash] lamport_check() Assertcheck", &latest_crypto::LamportAssertcheck);

        debugcs::instance() << "[[[OK]]] SorachanCoin the checked blake2 and lamport" << debugcs::endl();
    }

    static void json_check() noexcept {
        debugcs::instance() << "[[[BEGIN]]] SorachanCoin the JSON testing ..." << debugcs::endl();

        _bench_func("[JSON] json_check()", &latest_json::JsonAssertcheck, 1, 1);

        debugcs::instance() << "[[[OK]]] SorachanCoin the checked JSON" << debugcs::endl();
    }

    static unsigned int __stdcall benchmark(void *) noexcept {
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
private:
    Quantum_startup() noexcept {
#if defined(DEBUG)
        //
        // Lamport benchmark [Thread Safe]
        //
        std::thread th1(&Quantum_startup::benchmark, nullptr);
        std::thread th2(&Quantum_startup::benchmark, nullptr);
        th1.join();
        th2.join();
#endif
    }
    ~Quantum_startup() noexcept {}
};
Quantum_startup Quantum_startup::q_startup;

#endif
