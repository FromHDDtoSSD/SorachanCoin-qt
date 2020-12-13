// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_RIPEMD160_H
#define BITCOIN_CRYPTO_RIPEMD160_H

#include <stdint.h>
#include <stdlib.h>

namespace latest_crypto {

/** A hasher class for RIPEMD-160. */
class CRIPEMD160
{
private:
    uint32_t s[5];
    unsigned char buf[64];
    uint64_t bytes;
public:
    static constexpr size_t OUTPUT_SIZE = 20;

    CRIPEMD160() noexcept;
    CRIPEMD160& Write(const unsigned char* data, size_t len) noexcept;
    void Finalize(unsigned char hash[OUTPUT_SIZE]) noexcept;
    CRIPEMD160& Reset() noexcept;
};

} // namespace latest_crypto

#endif // BITCOIN_CRYPTO_RIPEMD160_H
