// Copyright (c) 2026 The SORA developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SHA3_256_H
#define BITCOIN_CRYPTO_SHA3_256_H

#include <cstdint>
#include <stdexcept>
#include <vector>
#include <cleanse/cleanse.h>

class CSHA3_256 {
private:
    bool finalized_ = false;
    bool squeezing_ = false;

    size_t rateBytes_ = 0;
    uint8_t domain_ = 0;
    size_t fixedOutLen_ = 0;

    uint64_t st_[25];
    std::vector<uint8_t> buffer_;
    size_t bufferUsed_ = 0;

    void absorbBlock(const uint8_t *block);
    void padAndSwitchToSqueeze();
    std::vector<uint8_t> squeezeBytes(size_t outLen);

public:
    static constexpr uint32_t OUTPUT_SIZE = 32;
    static constexpr uint32_t Size() { return OUTPUT_SIZE; }

    CSHA3_256();
    ~CSHA3_256();
    CSHA3_256 &Write(const unsigned char *data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CSHA3_256 &Reset();
    void Clean() {
        cleanse::OPENSSL_cleanse(st_, sizeof(st_));
        if(buffer_.size() > 0)
            cleanse::OPENSSL_cleanse(&buffer_.front(), buffer_.size());
    }
};

#endif // BITCOIN_CRYPTO_SHA3_256_H
