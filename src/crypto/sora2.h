// Copyright (c) 2018-2025 The SorachanCoin developers
// Copyright (c) 2025 The SS256 SORA2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SORA2_H
#define BITCOIN_CRYPTO_SORA2_H

#include <openssl/bn.h>
#include <vector>
#include <string>

/** A hasher class for SORA2. */
// under development
template<uint32_t BITS>
class CSORA2 {
public:
    static constexpr uint32_t OUTPUT_SIZE = BITS / 8;
    static constexpr uint32_t Size() { return OUTPUT_SIZE; }

    CSORA2() {}

    ~CSORA2() {}

    CSORA2 &Write(const unsigned char *data, uint64_t len) { return *this; }

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {}

    CSORA2 &Reset() { return *this; }

    void Clean() {}
};

using CSORA2_64 = CSORA2<64>;
using CSORA2_160 = CSORA2<160>;
using CSORA2_256 = CSORA2<256>;
using CSORA2_512 = CSORA2<512>;

#endif // BITCOIN_CRYPTO_SORA2_H
