#ifndef BITCOIN_CRYPTO_KECCAK256_H
#define BITCOIN_CRYPTO_KECCAK256_H

#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <array>
#include <cleanse/cleanse.h>

// https://github.com/jluuM2/sha3/blob/master/sha3/sha3.cpp
namespace keccak256_lib {

#define HASH_ERR_BAD_PARAMETER 1
#define HASH_SUCCESS 0
#include <cstdint>
#include <cstdlib>

#define decsha3(bits) \
    int sha3_##bits(uint8_t*, size_t, uint8_t const*, size_t);

    decsha3(256)
        decsha3(512)

        static inline void SHA3_256(uint8_t* ret, const uint8_t * data, size_t const size)
    {
        sha3_256(ret, 32, data, size);
    }

class Keccak {
private:
    uint8_t output[32];
    char outputHex[65];

public:
    Keccak() {Init();}
    int Init();
    int Update(const void *data, size_t len);
    int Finalize(void *hash);
    int Reset();

    void Clean() {
        cleanse::OPENSSL_cleanse(output, sizeof(output));
        cleanse::OPENSSL_cleanse(outputHex, sizeof(outputHex));
    }
};

} // namespace keccak256_lib

namespace latest_crypto {

/** A hasher class for KECCAK256. */
class CKECCAK256
{
private:
    keccak256_lib::Keccak keccak;

public:
    static constexpr size_t OUTPUT_SIZE = 32;

    CKECCAK256();
    CKECCAK256& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CKECCAK256& Reset();

    static constexpr size_t Size() {return OUTPUT_SIZE;}
    void Clean() {
        keccak.Clean();
    }
};

} // namespace latest_crypto

#endif // BITCOIN_CRYPTO_KECCAK256_H
