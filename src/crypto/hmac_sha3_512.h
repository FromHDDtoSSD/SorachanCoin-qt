// Copyright (c) 2026 The SORA developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_HMAC_SHA3_512_H
#define BITCOIN_CRYPTO_HMAC_SHA3_512_H

#include <crypto/sha3_512.h>
#include <cstring>

class CHMAC_SHA3_512 {
private:
    static constexpr size_t BITS = 512;
    CSHA3_512 outer;
    CSHA3_512 inner;
public:
    static constexpr size_t OUTPUT_SIZE = BITS / 8;
    static constexpr size_t BUFFER_SIZE = BITS / 4;

    CHMAC_SHA3_512() {}
    CHMAC_SHA3_512(const unsigned char *key, size_t keylen) {
        Init(key, keylen);
    }

    void Init(const unsigned char *key, size_t keylen) {
        unsigned char rkey[BUFFER_SIZE];
        if (keylen <= BUFFER_SIZE) {
            std::memcpy(rkey, key, keylen);
            std::memset(rkey + keylen, 0, BUFFER_SIZE - keylen);
        } else {
            CSHA3_512().Write(key, keylen).Finalize(rkey);
            std::memset(rkey + BUFFER_SIZE / 2, 0, BUFFER_SIZE / 2);
        }

        for (int n = 0; n < BUFFER_SIZE; n++)
            rkey[n] ^= 0x5c;
        outer.Write(rkey, BUFFER_SIZE);

        for (int n = 0; n < BUFFER_SIZE; n++)
            rkey[n] ^= 0x5c ^ 0x36;
        inner.Write(rkey, BUFFER_SIZE);
    }

    CHMAC_SHA3_512 &Write(const unsigned char *data, size_t len) {
        inner.Write(data, len);
        return *this;
    }

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char temp[BUFFER_SIZE / 2];
        inner.Finalize(temp);
        outer.Write(temp, BUFFER_SIZE / 2).Finalize(hash);
    }
};

#endif // BITCOIN_CRYPTO_HMAC_SHA3_512_H
