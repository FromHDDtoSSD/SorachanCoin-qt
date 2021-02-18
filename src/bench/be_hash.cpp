// Copyright (c) 2018-2020 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <memory>
#include <prevector/prevector.h>
#include <bench/bench.h>
#include <compat/sanity.h>
#include <hash.h>
#include <crypto/hmac_qhash65536.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <random/random.h>

static const std::string bench_source = "We hope that the infectious diseases will converge as possible early.";

namespace latest_crypto {
    typedef std::uint8_t byte;

    class hash_basis_org : private no_instance    // bitcoin SHA256
    {
    public:
        template<typename T1>
        static uint256 Hash(const T1 pbegin, const T1 pend) {
            static unsigned char pblank[1] = { 0 };
            uint256 hash1;
            ::SHA256((pbegin == pend ? pblank : (unsigned char *)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char *)&hash1);
            uint256 hash2;
            ::SHA256((unsigned char *)&hash1, sizeof(hash1), (unsigned char *)&hash2);
            return hash2;
        }

        template<typename T1, typename T2>
        static uint256 Hash(const T1 p1begin, const T1 p1end,
            const T2 p2begin, const T2 p2end) {
            static unsigned char pblank[1] = { 0 };
            uint256 hash1;
            SHA256_CTX ctx;
            ::SHA256_Init(&ctx);
            ::SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char *)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
            ::SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char *)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
            ::SHA256_Final((unsigned char *)&hash1, &ctx);
            uint256 hash2;
            ::SHA256((unsigned char *)&hash1, sizeof(hash1), (unsigned char *)&hash2);
            return hash2;
        }

        template<typename T1, typename T2, typename T3>
        static uint256 Hash(const T1 p1begin, const T1 p1end,
            const T2 p2begin, const T2 p2end,
            const T3 p3begin, const T3 p3end) {
            static unsigned char pblank[1] = { 0 };
            uint256 hash1;
            SHA256_CTX ctx;
            ::SHA256_Init(&ctx);
            ::SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char *)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
            ::SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char *)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
            ::SHA256_Update(&ctx, (p3begin == p3end ? pblank : (unsigned char *)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0]));
            ::SHA256_Final((unsigned char *)&hash1, &ctx);
            uint256 hash2;
            ::SHA256((unsigned char *)&hash1, sizeof(hash1), (unsigned char *)&hash2);
            return hash2;
        }

        template<typename T>
        static uint256 SerializeHash(const T &obj, int nType=SER_GETHASH, int nVersion=version::PROTOCOL_VERSION) {
            //CHashWriter ss(nType, nVersion);
            CHashWriter ss;
            ss << obj;
            return ss.GetHash();
        }

        template<typename T1>
        static uint160 Hash160(const T1 pbegin, const T1 pend) {
            static unsigned char pblank[1] = { 0 };
            uint256 hash1;
            ::SHA256((pbegin == pend ? pblank : (unsigned char *)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char *)&hash1);
            uint160 hash2;
            ::RIPEMD160((unsigned char *)&hash1, sizeof(hash1), (unsigned char *)&hash2);
            return hash2;
        }

        static uint160 Hash160(const std::vector<uint8_t> &vch) {
            return hash_basis_org::Hash160(vch.begin(), vch.end());
        }
    };

static void Ripemd160Assertcheck_(benchmark::State& state)
{
    prevector<PREVECTOR_N, unsigned char> random_value((uint32_t)512, (uint8_t)0x00);
    while(state.KeepRunning()) {
        uint160 latest = hash_basis::Hash160(std::begin(bench_source), std::end(bench_source));
        uint160 old = hash_basis_org::Hash160(std::begin(bench_source), std::end(bench_source));
        assert(latest == old);

        latest_crypto::random::GetStrongRandBytes(random_value.data(), random_value.size());
        uint160 _latest = hash_basis::Hash160(random_value.begin(), random_value.end());
        uint160 _old = hash_basis_org::Hash160(random_value.begin(), random_value.end());
        assert(_latest == _old);
    }
}

static void SHA256Assertcheck_(benchmark::State& state)
{
    prevector<PREVECTOR_N, unsigned char> random_value((uint32_t)512, (uint8_t)0x00);
    while(state.KeepRunning()) {
        uint256 latest1 = hash_basis::Hash(std::begin(bench_source), std::end(bench_source));
        uint256 old1 = hash_basis_org::Hash(std::begin(bench_source), std::end(bench_source));
        assert(latest1 == old1);

        latest_crypto::random::GetStrongRandBytes(random_value.data(), random_value.size());
        uint256 _latest1 = hash_basis::Hash(random_value.begin(), random_value.end());
        uint256 _old1 = hash_basis_org::Hash(random_value.begin(), random_value.end());
        assert(_latest1 == _old1);

        uint256 latest2 = hash_basis::Hash(std::begin(bench_source), std::end(bench_source), std::begin(bench_source), std::end(bench_source));
        uint256 old2 = hash_basis_org::Hash(std::begin(bench_source), std::end(bench_source), std::begin(bench_source), std::end(bench_source));
        assert(latest2 == old2);

        latest_crypto::random::GetStrongRandBytes(random_value.data(), random_value.size());
        uint256 _latest2 = hash_basis::Hash(random_value.begin(), random_value.end(), random_value.begin(), random_value.end());
        uint256 _old2 = hash_basis_org::Hash(random_value.begin(), random_value.end(), random_value.begin(), random_value.end());
        assert(_latest2 == _old2);

        uint256 latest3 = hash_basis::Hash(std::begin(bench_source), std::end(bench_source), std::begin(bench_source), std::end(bench_source), std::begin(bench_source), std::end(bench_source));
        uint256 old3 = hash_basis_org::Hash(std::begin(bench_source), std::end(bench_source), std::begin(bench_source), std::end(bench_source), std::begin(bench_source), std::end(bench_source));
        assert(latest3 == old3);

        latest_crypto::random::GetStrongRandBytes(random_value.data(), random_value.size());
        uint256 _latest3 = hash_basis::Hash(random_value.begin(), random_value.end(), random_value.begin(), random_value.end(), random_value.begin(), random_value.end());
        uint256 _old3 = hash_basis_org::Hash(random_value.begin(), random_value.end(), random_value.begin(), random_value.end(), random_value.begin(), random_value.end());
        assert(_latest3 == _old3);
    }
}

    namespace openssl {
        template<typename T1>
        uint512 sha512(const T1 pbegin, const T1 pend) {
            SHA512_CTX ctx;
            ::SHA512_Init(&ctx);
            ::SHA512_Update(&ctx, (const char *)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]));
            uint512 hash1;
            ::SHA512_Final((unsigned char *)&hash1, &ctx);

            ::SHA512_Init(&ctx);
            ::SHA512_Update(&ctx, (const char *)&hash1, sizeof(hash1));
            uint512 hash2;
            ::SHA512_Final((unsigned char *)&hash2, &ctx);
            return hash2;
        }
        template<typename T1, typename T2>
        uint512 sha512_2(const T1 p1begin, const T1 p1end, const T2 p2begin, const T2 p2end) {
            SHA512_CTX ctx;
            ::SHA512_Init(&ctx);
            ::SHA512_Update(&ctx, (const char *)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]));
            ::SHA512_Update(&ctx, (const char *)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]));
            uint512 hash1;
            ::SHA512_Final((unsigned char *)&hash1, &ctx);

            ::SHA512_Init(&ctx);
            ::SHA512_Update(&ctx, (const char *)&hash1, sizeof(hash1));
            uint512 hash2;
            ::SHA512_Final((unsigned char *)&hash2, &ctx);
            return hash2;
        }
        template<typename T1, typename T2, typename T3>
        uint512 sha512_3(const T1 p1begin, const T1 p1end, const T2 p2begin, const T2 p2end, const T3 p3begin, const T3 p3end) {
            SHA512_CTX ctx;
            ::SHA512_Init(&ctx);
            ::SHA512_Update(&ctx, (const char *)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]));
            ::SHA512_Update(&ctx, (const char *)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]));
            ::SHA512_Update(&ctx, (const char *)&p3begin[0], (p3end - p3begin) * sizeof(p3begin[0]));
            uint512 hash1;
            ::SHA512_Final((unsigned char *)&hash1, &ctx);

            ::SHA512_Init(&ctx);
            ::SHA512_Update(&ctx, (const char *)&hash1, sizeof(hash1));
            uint512 hash2;
            ::SHA512_Final((unsigned char *)&hash2, &ctx);
            return hash2;
        }
    }

static void SHA512Assertcheck_(benchmark::State& state)
{
    prevector<PREVECTOR_N, unsigned char> random_value((uint32_t)512, (uint8_t)0x00);
    while(state.KeepRunning()) {
        uint512 latest1 = hash_basis::Hash512(std::begin(bench_source), std::end(bench_source));
        uint512 old1 = openssl::sha512(std::begin(bench_source), std::end(bench_source));
        assert(latest1 == old1);

        latest_crypto::random::GetStrongRandBytes(random_value.data(), random_value.size());
        uint512 _latest1 = hash_basis::Hash512(random_value.begin(), random_value.end());
        uint512 _old1 = openssl::sha512(random_value.begin(), random_value.end());
        assert(_latest1 == _old1);

        uint512 latest2 = hash_basis::Hash512(std::begin(bench_source), std::end(bench_source), std::begin(bench_source), std::end(bench_source));
        uint512 old2 = openssl::sha512_2(std::begin(bench_source), std::end(bench_source), std::begin(bench_source), std::end(bench_source));
        assert(latest2 == old2);

        latest_crypto::random::GetStrongRandBytes(random_value.data(), random_value.size());
        uint512 _latest2 = hash_basis::Hash512(random_value.begin(), random_value.end(), random_value.begin(), random_value.end());
        uint512 _old2 = openssl::sha512_2(random_value.begin(), random_value.end(), random_value.begin(), random_value.end());
        assert(_latest2 == _old2);

        uint512 latest3 = hash_basis::Hash512(std::begin(bench_source), std::end(bench_source), std::begin(bench_source), std::end(bench_source), std::begin(bench_source), std::end(bench_source));
        uint512 old3 = openssl::sha512_3(std::begin(bench_source), std::end(bench_source), std::begin(bench_source), std::end(bench_source), std::begin(bench_source), std::end(bench_source));
        assert(latest3 == old3);

        latest_crypto::random::GetStrongRandBytes(random_value.data(), random_value.size());
        uint512 _latest3 = hash_basis::Hash512(random_value.begin(), random_value.end(), random_value.begin(), random_value.end(), random_value.begin(), random_value.end());
        uint512 _old3 = openssl::sha512_3(random_value.begin(), random_value.end(), random_value.begin(), random_value.end(), random_value.begin(), random_value.end());
        assert(_latest3 == _old3);
    }
}

static void Blake2Assertcheck_(benchmark::State& state)
{
    prevector<PREVECTOR_N, unsigned char> random_value((uint32_t)Lamport::CKeyBase::get_size(), (uint8_t)0x00);
    while(state.KeepRunning()) {
        // Blake2
        for (int i=0; i < 1000; ++i) {
            latest_crypto::random::GetStrongRandBytes(random_value.data(), random_value.size());
            Lamport::CPrivateKey pKey(random_value.data(), random_value.size());
            Lamport::BLAKE2KeyHash h(pKey);

            byte referenceHash[Lamport::BLAKE2KeyHash::kBytesSize];
            CSecureSegmentRW<byte> guard = pKey.get_secure()->unlockAndInitRW(true);
            quantum_hash::blake2_generichash(referenceHash, Lamport::BLAKE2KeyHash::kBytesSize, guard.get_addr(), guard.get_size());
            assert(::memcmp(h.get_addr(), referenceHash, Lamport::BLAKE2KeyHash::kBytesSize) == 0);
        }

        // HMAC_LAMPORT_PRIVATE_HASH
        for (int i=0; i < 500; ++i) {
            uint131072 data = HMAC_LAMPORT_PRIVATE_HASH::CalculateDigest(random_value.data(), random_value.size());
            assert(0 < data);
        }
    }
}

static void LamportAssertcheck_(benchmark::State& state)
{
    while(state.KeepRunning()) {
        const size_t buf_size = PREVECTOR_N;

        quantum_lib::secure_stackzero(buf_size);
        prevector<PREVECTOR_N, byte> vdata;
        vdata.resize(buf_size, 0x00);
        byte *data = &vdata.at(0);

        latest_crypto::random::GetStrongRandBytes(data, buf_size);
        Lamport::CLamport lamport; // Note: generate private key (ramdom).
        std::shared_ptr<Lamport::CPublicKey> pubKey = lamport.create_pubkey(data, buf_size);
        assert(lamport.check(data, buf_size, pubKey) == true);

        assert(lamport.get_size() == 8192);
        assert(pubKey->get_size() == 16384);

        byte tmp = data[0];
        if(tmp - (data[0] = 0xFF))
            assert(lamport.check(data, buf_size, pubKey) == false); // Although data is of changing(insert 0xFF), no changed to pubkey.
        else
            assert(lamport.check(data, buf_size, pubKey) == true); // If data is no change, it can be checking again and again.

        std::shared_ptr<Lamport::CPublicKey> pubKey2 = lamport.create_pubkey(data, buf_size);
        assert(lamport.check(data, buf_size, pubKey2) == false); // Note: lamport object is used limit once. lamport object prevent reuse.

        {
            Lamport::CLamport lamport3;
            std::shared_ptr<Lamport::CPublicKey> pubKey3 = lamport3.create_pubkey(data, buf_size);
            assert(lamport3.check(data, buf_size, pubKey3) == true); // OK. new privKey.
        }

        {
            CQHASH65536 lamhash;
            uint65536 hash;
            lamhash.Write(data, buf_size);
            lamhash.Finalize((unsigned char *)&hash);

            CQHASH65536 lamhash2;
            uint65536 hash2;
            lamhash2.Write(data, buf_size);
            lamhash2.Write(data, buf_size);
            lamhash2.Finalize((unsigned char *)&hash2);
            assert(hash != hash2);

            CQHASH65536 lamhash3;
            uint65536 hash3;
            lamhash3.Write(data, buf_size);
            lamhash3.Write(data, buf_size);
            lamhash3.Finalize((unsigned char *)&hash3);
            assert(hash2 == hash3);
        }

#ifdef LAMPORT_RESULT_VIEW
        const byte *offset = pubKey->get_addr();
        const size_t size = pubKey->get_size();
        for (size_t i = 0; i < size; ++i)
        {
            char buf[8] = { 0 };
            ::sprintf_s(buf, 8, "%X", offset[i]);
            debugcs::instance() << buf << debugcs::endl();
        }
        debugcs::instance() << debugcs::endl() << "--------------------------------" << debugcs::endl() << debugcs::endl();
#endif
    }
}

#define HASH_TEST(name, iter)                            \
    void name ## Assertcheck(benchmark::State& state) {  \
        name ## Assertcheck_(state);                     \
    }                                                    \
    BENCHMARK(name ## Assertcheck, iter);

HASH_TEST(Blake2, 50000)
HASH_TEST(Lamport, 50000)
HASH_TEST(Ripemd160, 50000)
HASH_TEST(SHA256, 50000)
HASH_TEST(SHA512, 50000)

} // namespace check_hash
