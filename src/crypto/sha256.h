// Copyright (c) 2014-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SHA256_H
#define BITCOIN_CRYPTO_SHA256_H

#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <cleanse/cleanse.h>

namespace latest_crypto {

/** A hasher class for SHA-256. */
class CSHA256
{
private:
    uint32_t s[8];
    unsigned char buf[64];
    uint64_t bytes;
public:
    static constexpr size_t OUTPUT_SIZE = 32;

    CSHA256() noexcept;
    CSHA256& Write(const unsigned char* data, size_t len) noexcept;
    void Finalize(unsigned char hash[OUTPUT_SIZE]) noexcept;
    CSHA256& Reset() noexcept;

    static constexpr size_t Size() noexcept {return OUTPUT_SIZE;}
    void Clean() noexcept {
        cleanse::OPENSSL_cleanse(s, sizeof(s));
        cleanse::OPENSSL_cleanse(buf, sizeof(buf));
    }
};

/** Autodetect the best available SHA256 implementation.
 *  Returns the name of the implementation.
 */
std::string SHA256AutoDetect();

/** Compute multiple double-SHA256's of 64-byte blobs.
 *  output:  pointer to a blocks*32 byte output buffer
 *  input:   pointer to a blocks*64 byte input buffer
 *  blocks:  the number of hashes to compute.
 */
void SHA256D64(unsigned char* output, const unsigned char* input, size_t blocks) noexcept;

} // namespace latest_crypto

#endif // BITCOIN_CRYPTO_SHA256_H
