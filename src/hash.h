// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2018-2020 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

#include "serialize.h"
#include "uint256.h"
#include "version.h"

#include <vector>

#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include <debugcs/debugcs.h>

#if defined(USE_QUANTUM) && defined(LATEST_CRYPTO_ENABLE)
# include <quantum/quantum.h>
# include <crypto/ripemd160.h>
# include <crypto/sha256.h>
# include <crypto/sha512.h>
# include <cryptopp/shake.h>
#endif

class CHashWriter
{
private:
    CHashWriter(); // {}
    CHashWriter(const CHashWriter &); // {}
    CHashWriter &operator=(const CHashWriter &); // {}

    SHA256_CTX ctx;
    int nType;
    int nVersion;

public:
    void Init() {
        SHA256_Init(&ctx);
    }

    CHashWriter(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {
        Init();
    }

    CHashWriter &write(const char *pch, size_t size) {
        SHA256_Update(&ctx, pch, size);
        return *this;
    }

    // invalidates the object
    uint256 GetHash() {
        uint256 hash1;
        SHA256_Final((unsigned char *)&hash1, &ctx);
        uint256 hash2;
        SHA256((unsigned char *)&hash1, sizeof(hash1), (unsigned char *)&hash2);
        return hash2;
    }

    // Serialize to this stream
    template<typename T>
    CHashWriter &operator<<(const T &obj) {
        ::Serialize(*this, obj);
        return *this;
    }
};

#if defined(USE_QUANTUM) && defined(LATEST_CRYPTO_ENABLE)
template<typename CTX, typename UINTOBJ>
class CHashWriter_q
{
private:
    CHashWriter_q(const CHashWriter_q &); // {}
    CHashWriter_q(const CHashWriter_q &&); // {}
    CHashWriter_q &operator=(const CHashWriter_q &); // {}
    CHashWriter_q &operator=(const CHashWriter_q &&); // {}

    CTX ctx;

public:
    CHashWriter_q() {}

    CHashWriter_q &write(const char *pch, size_t size) {
        ctx.Write((const unsigned char *)pch, size);
        return *this;
    }

    // invalidates the object
    UINTOBJ GetHash() {
        UINTOBJ hash1;
        ctx.Finalize((unsigned char *)&hash1);
        ctx.Reset();
        ctx.Write((const unsigned char *)&hash1, sizeof(hash1));
        UINTOBJ hash2;
        ctx.Finalize((unsigned char *)&hash2);
        return hash2;
    }

    // Serialize to this stream
    template<typename T>
    CHashWriter_q &operator<<(const T &obj) {
        ::Serialize(*this, obj);
        return *this;
    }
};
typedef CHashWriter_q<latest_crypto::CSHA256, uint256> CHashWriter_q256;
typedef CHashWriter_q<latest_crypto::CSHA512, uint512> CHashWriter_q512;
#endif



#ifdef CSCRIPT_PREVECTOR_ENABLE
typedef prevector<PREVECTOR_N, uint8_t> hashbasis_vector;
#else
typedef std::vector<uint8_t> hashbasis_vector;
#endif

class hash_basis : private no_instance    // bitcoin SHA256
{
public:
    template<typename T1>
    static uint256 Hash(const T1 pbegin, const T1 pend) {
        static unsigned char pblank[1] = { 0 };
        uint256 hash1;
        SHA256((pbegin == pend ? pblank : (unsigned char *)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char *)&hash1);
        uint256 hash2;
        SHA256((unsigned char *)&hash1, sizeof(hash1), (unsigned char *)&hash2);
        return hash2;
    }

    template<typename T1, typename T2>
    static uint256 Hash(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end) {
        static unsigned char pblank[1] = { 0 };
        uint256 hash1;
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char *)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
        SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char *)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
        SHA256_Final((unsigned char *)&hash1, &ctx);
        uint256 hash2;
        SHA256((unsigned char *)&hash1, sizeof(hash1), (unsigned char *)&hash2);
        return hash2;
    }

    template<typename T1, typename T2, typename T3>
    static uint256 Hash(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end,
        const T3 p3begin, const T3 p3end) {
        static unsigned char pblank[1] = { 0 };
        uint256 hash1;
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char *)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
        SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char *)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
        SHA256_Update(&ctx, (p3begin == p3end ? pblank : (unsigned char *)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0]));
        SHA256_Final((unsigned char *)&hash1, &ctx);
        uint256 hash2;
        SHA256((unsigned char *)&hash1, sizeof(hash1), (unsigned char *)&hash2);
        return hash2;
    }

    template<typename T>
    static uint256 SerializeHash(const T &obj, int nType = SER_GETHASH, int nVersion = version::PROTOCOL_VERSION) {
        CHashWriter ss(nType, nVersion);
        ss << obj;
        return ss.GetHash();
    }

    template<typename T1>
    static uint160 Hash160(const T1 pbegin, const T1 pend) {
        static unsigned char pblank[1] = { 0 };
        uint256 hash1;
        SHA256((pbegin == pend ? pblank : (unsigned char *)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char *)&hash1);
        uint160 hash2;
        RIPEMD160((unsigned char *)&hash1, sizeof(hash1), (unsigned char *)&hash2);
        return hash2;
    }

    static uint160 Hash160(const hashbasis_vector &vch) {
        return hash_basis::Hash160(vch.begin(), vch.end());
    }
};

#if defined(USE_QUANTUM) && defined(LATEST_CRYPTO_ENABLE)
class hash_q : private no_instance // SorachanCoin Lamport
{
private:
    template<typename CTX, typename UINTOBJ, typename T1>
    static inline UINTOBJ Hash_impl(const T1 p1begin, const T1 p1end) {
        unsigned char pblank[1] = { 0 };
        CTX ctx;
        ctx.Write(p1begin == p1end ? pblank : (const unsigned char *)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]));
        UINTOBJ hash1;
        ctx.Finalize((unsigned char *)&hash1);
        ctx.Reset();
        ctx.Write((const unsigned char *)&hash1, sizeof(hash1));
        UINTOBJ hash2;
        ctx.Finalize((unsigned char *)&hash2);
        return hash2;
    }

    template<typename CTX, typename UINTOBJ, typename T1, typename T2>
    static inline UINTOBJ Hash_impl(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end) {
        unsigned char pblank[1] = { 0 };
        CTX ctx;
        ctx.Write(p1begin == p1end ? pblank : (const unsigned char *)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]));
        ctx.Write(p2begin == p2end ? pblank : (const unsigned char *)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]));
        UINTOBJ hash1;
        ctx.Finalize((unsigned char *)&hash1);
        ctx.Reset();
        ctx.Write((const unsigned char *)&hash1, sizeof(hash1));
        UINTOBJ hash2;
        ctx.Finalize((unsigned char *)&hash2);
        return hash2;
    }

    template<typename CTX, typename UINTOBJ, typename T1, typename T2, typename T3>
    static inline UINTOBJ Hash_impl(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end,
        const T3 p3begin, const T3 p3end) {
        unsigned char pblank[1] = { 0 };
        CTX ctx;
        ctx.Write(p1begin == p1end ? pblank : (const unsigned char *)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]));
        ctx.Write(p2begin == p2end ? pblank : (const unsigned char *)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]));
        ctx.Write(p3begin == p3end ? pblank : (const unsigned char *)&p3begin[0], (p3end - p3begin) * sizeof(p3begin[0]));
        UINTOBJ hash1;
        ctx.Finalize((unsigned char *)&hash1);
        ctx.Reset();
        ctx.Write((const unsigned char *)&hash1, sizeof(hash1));
        UINTOBJ hash2;
        ctx.Finalize((unsigned char *)&hash2);
        return hash2;
    }

public:
    template<typename T1>
    static uint256 Hash(const T1 p1begin, const T1 p1end) {
        //debugcs::instance() << "Called: hash_q::Hash pbegin(1)" << debugcs::endl();
        uint256 hash = Hash_impl<latest_crypto::CSHA256, uint256, T1>(p1begin, p1end);
        //assert(hash_basis::Hash(p1begin, p1end) == hash);
        return hash;
    }

    template<typename T1, typename T2>
    static uint256 Hash(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end) {
        //debugcs::instance() << "Called: hash_q::Hash pbegin(2)" << debugcs::endl();
        uint256 hash = Hash_impl<latest_crypto::CSHA256, uint256, T1, T2>(p1begin, p1end, p2begin, p2end);
        //assert(hash_basis::Hash(p1begin, p1end, p2begin, p2end) == hash);
        return hash;
    }

    template<typename T1, typename T2, typename T3>
    static uint256 Hash(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end,
        const T3 p3begin, const T3 p3end) {
        //debugcs::instance() << "Called: hash_q::Hash pbegin(3)" << debugcs::endl();
        uint256 hash = Hash_impl<latest_crypto::CSHA256, uint256, T1, T2, T3>(p1begin, p1end, p2begin, p2end, p3begin, p3end);
        //assert(hash_basis::Hash(p1begin, p1end, p2begin, p2end, p3begin, p3end) == hash);
        return hash;
    }

    template<typename T>
    static uint256 SerializeHash(const T &obj, int=0, int=0) {
        //debugcs::instance() << "Called: hash_q::SerializeHash" << debugcs::endl();
        CHashWriter_q256 ss;
        ss << obj;
        //assert(hash_basis::SerializeHash(obj) == ss.GetHash());
        return ss.GetHash();
    }

    template<typename T1>
    static uint512 Hash512(const T1 p1begin, const T1 p1end) {
        //debugcs::instance() << "Called: hash_q::Hash512 pbegin(1)" << debugcs::endl();
        uint512 hash = Hash_impl<latest_crypto::CSHA512, uint512, T1>(p1begin, p1end);
        return hash;
    }

    template<typename T1, typename T2>
    static uint512 Hash512(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end) {
        //debugcs::instance() << "Called: hash_q::Hash512 pbegin(2)" << debugcs::endl();
        uint512 hash = Hash_impl<latest_crypto::CSHA512, uint512, T1, T2>(p1begin, p1end, p2begin, p2end);
        return hash;
    }

    template<typename T1, typename T2, typename T3>
    static uint512 Hash512(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end,
        const T3 p3begin, const T3 p3end) {
        //debugcs::instance() << "Called: hash_q::Hash512 pbegin(3)" << debugcs::endl();
        uint512 hash = Hash_impl<latest_crypto::CSHA512, uint512, T1, T2, T3>(p1begin, p1end, p2begin, p2end, p3begin, p3end);
        return hash;
    }

    template<typename T1>
    static uint160 Hash160(const T1 pbegin, const T1 pend) {
        //debugcs::instance() << "Called: hash_q::Hash160 pbegin" << debugcs::endl();
        unsigned char pblank[1] = { 0 };
        latest_crypto::CSHA256 ctx;
        ctx.Write(pbegin == pend ? pblank : (const unsigned char *)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]));
        uint256 hash1;
        ctx.Finalize((unsigned char *)&hash1);

        latest_crypto::CRIPEMD160 cpi;
        cpi.Write((const unsigned char *)&hash1, sizeof(hash1));
        uint160 hash2;
        cpi.Finalize((unsigned char *)&hash2);
        //assert(hash_basis::Hash160(pbegin, pend) == hash2);
        return hash2;
    }

    static uint160 Hash160(const hashbasis_vector &vch) {
        //debugcs::instance() << "Called: hash_q::Hash160 vch" << debugcs::endl();
        return hash_q::Hash160(vch.begin(), vch.end());
    }
};
# define hash_basis hash_q

//
// Crypto++ 8.1
// https://cryptopp.com/
// Note: CRYPTOPP_NO_ASSIGN_TO_INTEGER
//
NAMESPACE_BEGIN(CryptoPP)
template<unsigned int T_Strength>
class SHAKE_BASE : public SHAKE
{
public:
    CRYPTOPP_CONSTANT(DIGESTSIZE = (T_Strength / 8))
    CRYPTOPP_CONSTANT(BLOCKSIZE = 1088 / 8)
    SHAKE_BASE(unsigned int outputSize = DIGESTSIZE) : SHAKE(outputSize) {}
    unsigned int BlockSize() const { return BLOCKSIZE; }
private:
};
class SHAKE_HASH : public SHAKE_BASE<131072>
{
public:
    SHAKE_HASH() {}
    SHAKE_HASH(unsigned int outputSize) : SHAKE_BASE<131072>(outputSize) {}
};
NAMESPACE_END

namespace latest_crypto {
class CQHASH65536
{
private:
    static const size_t OUTPUT_SIZE = 8192;

    unsigned char memory[sizeof(Lamport::CLamport)];
    Lamport::CLamport *plamport;

public:
    CQHASH65536() : plamport(nullptr) { Reset(); }
    CQHASH65536& Write(const unsigned char* data, size_t len) {
        assert(OUTPUT_SIZE == plamport->get_size());
        if(!plamport) {
            CryptoPP::SHAKE_HASH shake;
            uint131072 key;
            shake.CalculateDigest((CryptoPP::byte *)&key, data, len);
            plamport = new (memory) Lamport::CLamport((const Lamport::byte *)&key, sizeof(uint131072));
        }
        plamport->create_hashonly(data, len);
        return *this;
    }
    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        //assert(OUTPUT_SIZE == plamport->get_size());
        ::memcpy(hash, plamport->get_addr(), plamport->get_size());
    }
    CQHASH65536& Reset() {
        if(plamport) {
            plamport->~CLamport();
            plamport = nullptr;
        }
        return *this;
    }
};
} // namespace latest_crypto
#endif

#endif // BITCOIN_HASH_H
