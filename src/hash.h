// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

#include <serialize.h>
#include <uint256.h>
#include <version.h>
#include <vector>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <debugcs/debugcs.h>
#include <quantum/quantum.h>
#include <crypto/ripemd160.h>
#include <crypto/sha256.h>
#include <crypto/qhash65536.h>

// BIP32
# include <crypto/hmac_sha512.h>
using ChainCode = uint256;
namespace bip32 {
    inline void BIP32Hash(const ChainCode &chainCode, unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64]) {
        unsigned char num[4];
        num[0] = (nChild >> 24) & 0xFF;
        num[1] = (nChild >> 16) & 0xFF;
        num[2] = (nChild >>  8) & 0xFF;
        num[3] = (nChild >>  0) & 0xFF;
        latest_crypto::CHMAC_SHA512(chainCode.begin(), chainCode.size()).Write(&header, 1).Write(data, 32).Write(num, 4).Finalize(output);
    }
} // bip32

template<typename CTX, typename UINTOBJ>
class CHashWriter_q
{
private:
    CHashWriter_q()=delete;
    CHashWriter_q(const CHashWriter_q &)=delete;
    CHashWriter_q(CHashWriter_q &&)=delete;
    CHashWriter_q &operator=(const CHashWriter_q &)=delete;
    CHashWriter_q &operator=(CHashWriter_q &&)=delete;
    CTX ctx;
    const int nType;
    const int nVersion; // witness
public:
    CHashWriter_q(int _nType, int _nVersion) : nType(_nType), nVersion(_nVersion) {}
    int GetType() const {return nType;}
    int GetVersion() const {return nVersion;}

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

#ifdef CSCRIPT_PREVECTOR_ENABLE
typedef prevector<PREVECTOR_N, uint8_t> hashbasis_vector;
#else
typedef std::vector<uint8_t> hashbasis_vector;
#endif

typedef CHashWriter_q<latest_crypto::CSHA256, uint256> CHashWriter;
typedef CHashWriter_q<latest_crypto::CSHA256, uint256> CHashWriter_q256;
typedef CHashWriter_q<latest_crypto::CSHA512, uint512> CHashWriter_q512;
typedef CHashWriter_q<latest_crypto::CQHASH65536, uint65536> CHashWriter_q65536;

class hash_basis : private no_instance // SorachanCoin Lamport
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
        return Hash_impl<latest_crypto::CSHA256, uint256, T1>(p1begin, p1end);
    }

    template<typename T1, typename T2>
    static uint256 Hash(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end) {
        return Hash_impl<latest_crypto::CSHA256, uint256, T1, T2>(p1begin, p1end, p2begin, p2end);
    }

    template<typename T1, typename T2, typename T3>
    static uint256 Hash(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end,
        const T3 p3begin, const T3 p3end) {
        return Hash_impl<latest_crypto::CSHA256, uint256, T1, T2, T3>(p1begin, p1end, p2begin, p2end, p3begin, p3end);
    }

    template<typename T>
    static uint256 SerializeHash(const T &obj, int nType=0, int nVersion=0) {
        CHashWriter_q256 ss(nType, nVersion);
        ss << obj;
        return ss.GetHash();
    }

    template<typename T>
    static uint65536 SerializeHash65536(const T &obj, int nType=0, int nVersion=0) {
        CHashWriter_q65536 ss(nType, nVersion);
        ss << obj;
        return ss.GetHash();
    }

    template<typename T1>
    static uint512 Hash512(const T1 p1begin, const T1 p1end) {
        return Hash_impl<latest_crypto::CSHA512, uint512, T1>(p1begin, p1end);
    }

    template<typename T1, typename T2>
    static uint512 Hash512(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end) {
        return Hash_impl<latest_crypto::CSHA512, uint512, T1, T2>(p1begin, p1end, p2begin, p2end);
    }

    template<typename T1, typename T2, typename T3>
    static uint512 Hash512(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end,
        const T3 p3begin, const T3 p3end) {
        return Hash_impl<latest_crypto::CSHA512, uint512, T1, T2, T3>(p1begin, p1end, p2begin, p2end, p3begin, p3end);
    }

    template<typename T1>
    static uint65536 Hash65536(const T1 p1begin, const T1 p1end) {
        return Hash_impl<latest_crypto::CQHASH65536, uint65536, T1>(p1begin, p1end);
    }

    template<typename T1, typename T2>
    static uint65536 Hash65536(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end) {
        return Hash_impl<latest_crypto::CQHASH65536, uint65536, T1, T2>(p1begin, p1end, p2begin, p2end);
    }

    template<typename T1, typename T2, typename T3>
    static uint65536 Hash65536(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end,
        const T3 p3begin, const T3 p3end) {
        return Hash_impl<latest_crypto::CQHASH65536, uint65536, T1, T2, T3>(p1begin, p1end, p2begin, p2end, p3begin, p3end);
    }

    template<typename T1>
    static uint256 Hash65536to256(const T1 p1begin, const T1 p1end) {
        uint65536 v = Hash_impl<latest_crypto::CQHASH65536, uint65536, T1>(p1begin, p1end);
        return Hash(v.begin(), v.end());
    }

    template<typename T1, typename T2>
    static uint256 Hash65536to256(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end) {
        uint65536 v = Hash_impl<latest_crypto::CQHASH65536, uint65536, T1, T2>(p1begin, p1end, p2begin, p2end);
        return Hash(v.begin(), v.end());
    }

    template<typename T1, typename T2, typename T3>
    static uint256 Hash65536to256(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end,
        const T3 p3begin, const T3 p3end) {
        uint65536 v = Hash_impl<latest_crypto::CQHASH65536, uint65536, T1, T2, T3>(p1begin, p1end, p2begin, p2end, p3begin, p3end);
        return Hash(v.begin(), v.end());
    }

    template<typename T1>
    static uint160 Hash160(const T1 pbegin, const T1 pend) {
        unsigned char pblank[1] = { 0 };
        latest_crypto::CSHA256 ctx;
        ctx.Write(pbegin == pend ? pblank : (const unsigned char *)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]));
        uint256 hash1;
        ctx.Finalize((unsigned char *)&hash1);
        latest_crypto::CRIPEMD160 cpi;
        cpi.Write((const unsigned char *)&hash1, sizeof(hash1));
        uint160 hash2;
        cpi.Finalize((unsigned char *)&hash2);
        return hash2;
    }

    static uint160 Hash160(const hashbasis_vector &vch) {
        return hash_basis::Hash160(vch.begin(), vch.end());
    }
};

//
// latest core hash class
//
namespace latest_crypto {

/** A hasher class for Bitcoin's 256-bit hash (double SHA-256). */
class CHash256 {
private:
    CSHA256 sha;
public:
    static constexpr size_t OUTPUT_SIZE = CSHA256::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char buf[CSHA256::OUTPUT_SIZE];
        sha.Finalize(buf);
        sha.Reset().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(hash);
    }

    CHash256& Write(const unsigned char *data, size_t len) {
        sha.Write(data, len);
        return *this;
    }

    CHash256& Reset() {
        sha.Reset();
        return *this;
    }
};

} // namespace latest_crypto

#endif // BITCOIN_HASH_H
