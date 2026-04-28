#ifndef SCRYPT_MINE_H
#define SCRYPT_MINE_H

#include <stdint.h>
#include <stdlib.h>
#include <uint256.h>

namespace bitmining {
    // Scrypt: LTC mining
    uint256 scrypt_hash(const void *input, size_t inputlen);
    uint256 scrypt_blockhash(const void *input);

    // SHA-256D: BTC mining
    uint256 sha256d_hash(const void *input, size_t inputlen);
    uint256 sha256d_blockhash(const void *input);

    // SORA2: SS256 SORA mining
    //uint256 sora2_hash(const void *input, size_t inputlen);
    //uint256 sora2_blockhash(const void *input);

    // SHA-3D: mining
    uint256 sha3d_hash(const void *input, size_t inputlen);
    uint256 sha3d_blockhash(const void *input);
} // namespace bitmining

#endif
