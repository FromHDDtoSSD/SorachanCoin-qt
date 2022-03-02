// Copyright (c) 2014-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/hmac_sha256.h>
#include <string.h>
#include <cstring>

namespace latest_crypto {

CHMAC_SHA256::CHMAC_SHA256(const unsigned char *key, size_t keylen) {
    Init(key, keylen);
}

void CHMAC_SHA256::Init(const unsigned char *key, size_t keylen) {
    unsigned char rkey[64];
    if (keylen <= 64) {
        std::memcpy(rkey, key, keylen);
        std::memset(rkey + keylen, 0, 64 - keylen);
    } else {
        CSHA256().Write(key, keylen).Finalize(rkey);
        std::memset(rkey + 32, 0, 32);
    }

    for (int n = 0; n < 64; n++)
        rkey[n] ^= 0x5c;
    outer.Write(rkey, 64);

    for (int n = 0; n < 64; n++)
        rkey[n] ^= 0x5c ^ 0x36;
    inner.Write(rkey, 64);
}

void CHMAC_SHA256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    unsigned char temp[32];
    inner.Finalize(temp);
    outer.Write(temp, 32).Finalize(hash);
}

} // namespace latest_crypto
