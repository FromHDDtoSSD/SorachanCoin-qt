// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
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
        ::Serialize(*this, obj, nType, nVersion);
        return *this;
    }
};

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
    static uint256 SerializeHash(const T &obj, int nType=SER_GETHASH, int nVersion = version::PROTOCOL_VERSION) {
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

    static uint160 Hash160(const std::vector<unsigned char> &vch) {
        return hash_basis::Hash160(vch.begin(), vch.end());
    }

    // unsigned int MurmurHash3(unsigned int nHashSeed, const std::vector<unsigned char> &vDataToHash);
};

/**
typedef struct
{
    SHA512_CTX ctxInner;
    SHA512_CTX ctxOuter;
} HMAC_SHA512_CTX;

int HMAC_SHA512_Init(HMAC_SHA512_CTX *pctx, const void *pkey, size_t len);
int HMAC_SHA512_Update(HMAC_SHA512_CTX *pctx, const void *pdata, size_t len);
int HMAC_SHA512_Final(unsigned char *pmd, HMAC_SHA512_CTX *pctx);
**/

#endif
//@
