// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2018-2025 The SorachanCoin developers
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
#include <crypto/ripemd160.h>
#include <crypto/sha256.h>
#include <crypto/keccak256.h>
#include <crypto/common.h>
#include <crypto/hmac_sha512.h>
#include <crypto/sha3_256.h>
#include <crypto/hmac_sha3_512.h>

#ifdef CSCRIPT_PREVECTOR_ENABLE
typedef prevector<PREVECTOR_N, uint8_t> hashbasis_vector;
#else
typedef std::vector<uint8_t> hashbasis_vector;
#endif

// Bitcoin's 256-bit hash (SHA-256D)
class CHash256B {
private:
    CSHA256 sha;
public:
    static constexpr size_t OUTPUT_SIZE = CSHA256::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char buf[CSHA256::OUTPUT_SIZE];
        sha.Finalize(buf);
        sha.Reset().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(hash);
    }

    CHash256B& Write(const unsigned char *data, size_t len) {
        sha.Write(data, len);
        return *this;
    }

    CHash256B& Reset() {
        sha.Reset();
        return *this;
    }
};

// A hasher class for new hash: SHA-3(SHA-3)
class CHash3B {
private:
    CSHA3_256 sha;
public:
    static constexpr size_t OUTPUT_SIZE = CSHA3_256::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char buf[CSHA3_256::OUTPUT_SIZE];
        sha.Finalize(buf);
        sha.Reset().Write(buf, CSHA3_256::OUTPUT_SIZE).Finalize(hash);
    }

    CHash3B& Write(const unsigned char *data, size_t len) {
        sha.Write(data, len);
        return *this;
    }

    CHash3B& Reset() {
        sha.Reset();
        return *this;
    }
};

// A hasher class for new hash: SHA-3(SHA-256D)
class CHash3B256 {
private:
    CSHA256 sha256;
    CSHA3_256 sha3;
public:
    static constexpr size_t OUTPUT_SIZE = CSHA3_256::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char buf[CSHA256::OUTPUT_SIZE];
        sha256.Finalize(buf);
        unsigned char buf2[CSHA256::OUTPUT_SIZE];
        sha256.Reset().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(buf2);
        sha3.Reset().Write(buf2, CSHA256::OUTPUT_SIZE).Finalize(hash);
    }

    CHash3B256& Write(const unsigned char *data, size_t len) {
        sha256.Write(data, len);
        return *this;
    }

    CHash3B256& Reset() {
        sha256.Reset();
        sha3.Reset();
        return *this;
    }
};

/** A hasher class for Bitcoin's 256-bit hash (double SHA-256 or SHA-3(SHA-256D)). */
class CHash256 {
private:
    CHash256B hash256;
    CHash3B256 sha3b256;
public:
    static constexpr size_t OUTPUT_SIZE = 32;

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        if(args_bool::fTestNet)
            sha3b256.Finalize(hash);
        else
            hash256.Finalize(hash);
    }

    CHash256& Write(const unsigned char *data, size_t len) {
        if(args_bool::fTestNet)
            sha3b256.Write(data, len);
        else
            hash256.Write(data, len);

        return *this;
    }

    CHash256& Reset() {
        if(args_bool::fTestNet)
            sha3b256.Reset();
        else
            hash256.Reset();

        return *this;
    }
};

/** A hasher class for Bitcoin PublicKey Address (RIPEMD160(SHA-256)). */
class CHash160 {
private:
    CSHA256 sha;
    CRIPEMD160 rip;
public:
    static constexpr size_t OUTPUT_SIZE = CRIPEMD160::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char buf[CSHA256::OUTPUT_SIZE];
        sha.Finalize(buf);
        rip.Reset().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(hash);
    }

    CHash160& Write(const unsigned char *data, size_t len) {
        sha.Write(data, len);
        return *this;
    }

    CHash160& Reset() {
        sha.Reset();
        rip.Reset();
        return *this;
    }
};

/** A hasher class for Eth 160-bit hash (keccak256). */
class CHashEth {
private:
    CKECCAK256 keccak;
public:
    static constexpr size_t OUTPUT_SIZE = 20;

    void Finalize(unsigned char hash[CHashEth::OUTPUT_SIZE]) {
        unsigned char buf[CKECCAK256::OUTPUT_SIZE];
        keccak.Finalize((unsigned char *)&buf[0]);
        ::memcpy(hash, &buf[0] + 12, 20);
    }

    CHashEth& Write(const unsigned char *data, size_t len) {
        keccak.Write(data, len);
        return *this;
    }

    CHashEth& Reset() {
        keccak.Reset();
        return *this;
    }
};

class CHashWriter {
    CHashWriter()=delete;
    CHashWriter(const CHashWriter &)=delete;
    CHashWriter(CHashWriter &&)=delete;
    CHashWriter &operator=(const CHashWriter &)=delete;
    CHashWriter &operator=(CHashWriter &&)=delete;

private:
    CHash256 ctx;
    const int nType;
    const int nVersion;

public:
    CHashWriter(int _nType, int _nVersion) : nType(_nType), nVersion(_nVersion) {}
    int GetType() const {return nType;}
    int GetVersion() const {return nVersion;}

    CHashWriter &write(const char *pch, size_t size) {
        ctx.Write((const unsigned char *)pch, size);
        return *this;
    }

    // Bitcoin's Double hash
    uint256 GetHash() {
        uint256 hash;
        ctx.Finalize(hash.begin());
        return hash;
    }

    // Returns the first 64 bits from the resulting hash
    inline uint64_t GetCheapHash() {
        uint256 result = GetHash();
        return ReadLE64(result.begin());
    }

    // Serialize to this stream
    template<typename T>
    CHashWriter &operator<<(const T &obj) {
        ::Serialize(*this, obj);
        return *this;
    }
};

namespace hash_basis {

    uint256 Hash_impl(const unsigned char *p1begin, const unsigned char *p1end);
    template<typename T1>
    inline uint256 Hash(const T1 p1begin, const T1 p1end) {
        return Hash_impl((const unsigned char *)&p1begin[0], (const unsigned char *)&p1begin[0] + (p1end - p1begin) * sizeof(unsigned char));
    }

    // merkle_tree
    uint256 Hash_impl(const unsigned char *p1begin, const unsigned char *p1end,
                      const unsigned char *p2begin, const unsigned char *p2end);
    template<typename T1, typename T2>
    inline uint256 Hash(const T1 p1begin, const T1 p1end,
        const T2 p2begin, const T2 p2end) {
        return Hash_impl((const unsigned char *)&p1begin[0], (const unsigned char *)&p1begin[0] + (p1end - p1begin) * sizeof(unsigned char),
                         (const unsigned char *)&p2begin[0], (const unsigned char *)&p2begin[0] + (p2end - p2begin) * sizeof(unsigned char));
    }

    template<typename T>
    inline uint256 SerializeHash(const T &obj, int nType=0, int nVersion=0) {
        CHashWriter ss(nType, nVersion);
        ss << obj;
        return ss.GetHash();
    }

    uint160 Hash160_impl(const unsigned char *pbegin, const unsigned char *pend);
    template<typename T1>
    inline uint160 Hash160(const T1 pbegin, const T1 pend) {
        return Hash160_impl((const unsigned char *)&pbegin[0], (const unsigned char *)&pbegin[0] + (pend - pbegin) * sizeof(unsigned char));
    }

    inline uint160 Hash160(const hashbasis_vector &vch) {
        return hash_basis::Hash160(vch.begin(), vch.end());
    }

} // namespace hash_basis

using ChainCode = uint256;
namespace bip32 {
    inline void BIP32Hash(const ChainCode &chainCode, unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64]) {
        unsigned char num[4];
        num[0] = (nChild >> 24) & 0xFF;
        num[1] = (nChild >> 16) & 0xFF;
        num[2] = (nChild >>  8) & 0xFF;
        num[3] = (nChild >>  0) & 0xFF;
        if(args_bool::fTestNet)
            CHMAC_SHA3_512(chainCode.begin(), chainCode.size()).Write(&header, 1).Write(data, 32).Write(num, 4).Finalize(output);
        else
            CHMAC_SHA512(chainCode.begin(), chainCode.size()).Write(&header, 1).Write(data, 32).Write(num, 4).Finalize(output);
    }
} // namespace bip32

#endif // BITCOIN_HASH_H
