// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SHA512_H
#define BITCOIN_CRYPTO_SHA512_H

#ifdef LATEST_CRYPTO_ENABLE

#include <stdint.h>
#include <stdlib.h>
#include <openssl/crypto.h> // for OPENSSL_cleanse()

namespace latest_crypto {

/** A hasher class for SHA-512. */
class CSHA512
{
private:
    uint64_t s[8];
    unsigned char buf[128];
    uint64_t bytes;

public:
    static const size_t OUTPUT_SIZE = 64;

    CSHA512();
    CSHA512& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CSHA512& Reset();

    static constexpr size_t Size() {return OUTPUT_SIZE;}
    void Clean() {
        ::OPENSSL_cleanse(s, sizeof(s));
        ::OPENSSL_cleanse(buf, sizeof(buf));
    }
};

} // namespace latest_crypto

#endif // LATEST_CRYPTO_ENABLE

#endif // BITCOIN_CRYPTO_SHA512_H
