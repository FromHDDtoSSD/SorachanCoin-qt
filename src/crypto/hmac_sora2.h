// Copyright (c) 2018-2025 The SorachanCoin developers
// Copyright (c) 2025 The SS256 SORA2 developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SORA2_HMAC_H
#define BITCOIN_CRYPTO_SORA2_HMAC_H

#include <crypto/sora2.h>
#include <cstring>

template <uint32_t BITS>
class CHMAC_SORA2 {
private:
    CSORA2<BITS> outer;
    CSORA2<BITS> inner;
public:
    static constexpr size_t OUTPUT_SIZE = BITS / 8;
    static constexpr size_t BUFFER_SIZE = BITS / 4;

    CHMAC_SORA2() {}
    CHMAC_SORA2(const unsigned char *key, size_t keylen) {
        Init(key, keylen);
    }

    void Init(const unsigned char *key, size_t keylen) {
        unsigned char rkey[BUFFER_SIZE];
        if (keylen <= BUFFER_SIZE) {
            std::memcpy(rkey, key, keylen);
            std::memset(rkey + keylen, 0, BUFFER_SIZE - keylen);
        } else {
            CSORA2<BITS>().Write(key, keylen).Finalize(rkey);
            std::memset(rkey + BUFFER_SIZE / 2, 0, BUFFER_SIZE / 2);
        }

        for (int n = 0; n < BUFFER_SIZE; n++)
            rkey[n] ^= 0x5c;
        outer.Write(rkey, BUFFER_SIZE);

        for (int n = 0; n < BUFFER_SIZE; n++)
            rkey[n] ^= 0x5c ^ 0x36;
        inner.Write(rkey, BUFFER_SIZE);
    }

    CHMAC_SORA2 &Write(const unsigned char *data, size_t len) {
        inner.Write(data, len);
        return *this;
    }

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char temp[BUFFER_SIZE / 2];
        inner.Finalize(temp);
        outer.Write(temp, BUFFER_SIZE / 2).Finalize(hash);
    }
};

using CHMAC_SORA2_256 = CHMAC_SORA2<256>;
using CHMAC_SORA2_512 = CHMAC_SORA2<512>;

#endif // BITCOIN_CRYPTO_SORA2_HMAC_H
