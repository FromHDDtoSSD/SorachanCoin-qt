// Copyright (c) 2017 The Bitcoin Core developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_CHACHA20_H
#define BITCOIN_CRYPTO_CHACHA20_H

#include <stdint.h>
#include <stdlib.h>
#include <uint256.h>
#include <allocator/allocators.h>

namespace latest_crypto {

/** SORA-QAI for CChaCha20. */
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CChaCha20Secret;
class CChaCha20
{
public:
    CChaCha20() = delete;
    CChaCha20(const unsigned char *key, uint32_t size);
    CChaCha20 &Reset(const unsigned char *key, uint32_t size);
    CChaCha20 &Encrypt(const unsigned char *data, uint32_t size);
    CChaCha20 &Decrypt(const unsigned char *data, uint32_t size);
    void Finalize(std::pair<std::vector<unsigned char>, bool> &out);

private:
    CChaCha20Secret secret;
    std::vector<unsigned char> buffer;
    bool fcheck;
    constexpr static uint32_t nsize = 12;
    constexpr static uint32_t defcounter = 1;
    constexpr static uint32_t rounds = 20;
    constexpr static uint32_t chashsize = sizeof(uint160);
    unsigned char nonce[nsize];
    struct CheckHash {
        unsigned char c[chashsize];
        CheckHash() {
            ::memset(c, 0x00, chashsize);
        }
        bool operator==(const CheckHash &a) const {
            return ::memcmp(a.c, this->c, chashsize) == 0;
        }
        bool operator!=(const CheckHash &a) const {
            return !operator==(a);
        }
    } checkhash;

    struct CHACHA20_CTX {
        uint32_t state[16];
    };

    static void chacha20_round(uint32_t x[], uint32_t a, uint32_t b, uint32_t c, uint32_t d);
    static void chacha20_block(CHACHA20_CTX *ctx, unsigned char output[64]);
    static void chacha20_init(CHACHA20_CTX *ctx, const unsigned char key[32], const unsigned char nonce[12], uint32_t counter = defcounter);
    static void chacha20_compute(CHACHA20_CTX *ctx, const unsigned char *input, unsigned char *output, uint32_t size);
    static uint256_cleanse getkeyhash(const CChaCha20Secret &key);
    const unsigned char *createnonce();
    static CheckHash checking(const unsigned char *data, uint32_t data_len);
    CChaCha20 &err();
};

/** A PRNG class for ChaCha20. */
class ChaCha20
{
private:
    uint32_t input[16];
public:
    ChaCha20();
    ChaCha20(const unsigned char* key, size_t keylen);
    void SetKey(const unsigned char* key, size_t keylen);
    void SetIV(uint64_t iv);
    void Seek(uint64_t pos);
    void Output(unsigned char* output, size_t bytes);
};

} // namespace latest_crypto

#endif // BITCOIN_CRYPTO_CHACHA20_H
