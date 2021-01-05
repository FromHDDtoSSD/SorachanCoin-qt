// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SHA512_H
#define BITCOIN_CRYPTO_SHA512_H

#include <stdint.h>
#include <stdlib.h>
#include <cleanse/cleanse.h>

namespace latest_crypto {

/** A hasher class for SHA-512. */
class CSHA512
{
private:
    uint64_t s[8];
    unsigned char buf[128];
    uint64_t bytes;
public:
    static constexpr size_t OUTPUT_SIZE = 64;

    CSHA512() noexcept;
    CSHA512& Write(const unsigned char* data, size_t len) noexcept;
    void Finalize(unsigned char hash[OUTPUT_SIZE]) noexcept;
    CSHA512& Reset() noexcept;

    static constexpr size_t Size() noexcept {return OUTPUT_SIZE;}
    void Clean() noexcept {
        cleanse::OPENSSL_cleanse(s, sizeof(s));
        cleanse::OPENSSL_cleanse(buf, sizeof(buf));
    }
};

} // namespace latest_crypto

#endif // BITCOIN_CRYPTO_SHA512_H
