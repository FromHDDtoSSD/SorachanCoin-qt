// Copyright (c) 2017 The Bitcoin Core developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Based on the public domain implementation 'merged' by D. J. Bernstein
// See https://cr.yp.to/chacha.html.

#include <crypto/common.h>
#include <crypto/chacha20.h>
#include <string.h>
#include <random/random.h>
#include <hash.h>

namespace latest_crypto {

void CChaCha20::chacha20_round(uint32_t x[], uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    auto rotL32 = [](uint32_t v, uint32_t n) {
        return ((v << n) | (v >> (32 - n)));
    };
    x[a] += x[b]; x[d] = rotL32(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotL32(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotL32(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = rotL32(x[b] ^ x[c], 7);
}

void CChaCha20::chacha20_block(CHACHA20_CTX *ctx, unsigned char output[64]) {
    uint32_t x[16];
    memcpy(x, ctx->state, sizeof(x));
    for (uint32_t i = 0; i < rounds; i += 2) {
        chacha20_round(x, 0, 4, 8, 12);
        chacha20_round(x, 1, 5, 9, 13);
        chacha20_round(x, 2, 6, 10, 14);
        chacha20_round(x, 3, 7, 11, 15);
        chacha20_round(x, 0, 5, 10, 15);
        chacha20_round(x, 1, 6, 11, 12);
        chacha20_round(x, 2, 7, 8, 13);
        chacha20_round(x, 3, 4, 9, 14);
    }
    for (uint32_t i = 0; i < 16; ++i) {
        x[i] += ctx->state[i];
        ((uint32_t *)output)[i] = x[i];
    }
}

void CChaCha20::chacha20_init(CHACHA20_CTX *ctx, const unsigned char key[32], const unsigned char nonce[12], uint32_t counter /*= defcounter*/) {
    static const char *constants = "expand 32-byte k";
    ctx->state[0]  = ((uint32_t *)constants)[0];
    ctx->state[1]  = ((uint32_t *)constants)[1];
    ctx->state[2]  = ((uint32_t *)constants)[2];
    ctx->state[3]  = ((uint32_t *)constants)[3];
    for (uint32_t i = 0; i < 8; ++i)
        ctx->state[4 + i] = ((uint32_t *)key)[i];
    ctx->state[12] = counter;
    ctx->state[13] = ((uint32_t *)nonce)[0];
    ctx->state[14] = ((uint32_t *)nonce)[1];
    ctx->state[15] = ((uint32_t *)nonce)[2];
}

void CChaCha20::chacha20_compute(CHACHA20_CTX *ctx, const unsigned char *input, unsigned char *output, uint32_t size) {
    uint8_t block[64];
    uint32_t i, j;
    for (i = 0; i < size; i += 64) {
        chacha20_block(ctx, block);
        ctx->state[12]++;
        for (j = 0; j < 64 && i + j < size; ++j)
            output[i + j] = input[i + j] ^ block[j];
    }
}

uint256_cleanse CChaCha20::getkeyhash(const CChaCha20Secret &key) {
    uint256_cleanse hash;
    CHash256().Write(key.data(), key.size()).Finalize(hash.begin());
    return hash;
}

const unsigned char *CChaCha20::createnonce() {
    random::GetStrongRandBytes(nonce, nsize);
    return nonce;
}

CChaCha20::CheckHash CChaCha20::checking(const unsigned char *data, uint32_t data_len) {
    uint160 hash;
    latest_crypto::CHash160().Write(data, data_len).Finalize(hash.begin());
    CheckHash chash;
    for (uint32_t i=0; i < chashsize; ++i)
        chash.c[i] = *(hash.begin() + i);
    return chash;
}

CChaCha20 &CChaCha20::err() {
    buffer.clear();
    fcheck = false;
    return *this;
}

CChaCha20::CChaCha20(const unsigned char *key, uint32_t size) : fcheck(false) {
    Reset(key, size);
}

CChaCha20 &CChaCha20::Reset(const unsigned char *key, uint32_t size) {
    assert(key && size >= 16);
    secret.resize(size);
    ::memcpy(&secret.front(), key, size);
    fcheck = false;
    return *this;
}

CChaCha20 &CChaCha20::Encrypt(const unsigned char *data, uint32_t size) {
    if(!data || size == 0)
        return err();
    CHACHA20_CTX ctx;
    chacha20_init(&ctx, getkeyhash(secret).begin(), createnonce());
    buffer.resize(size + chashsize + nsize);
    CheckHash chash = checking(data, size);
    chacha20_compute(&ctx, data, &buffer.front(), size);
    for(int i=0; i < chashsize; ++i)
        buffer[size + i] = chash.c[i];
    for(int i=0; i < nsize; ++i)
        buffer[size + chashsize + i] = nonce[i];
    fcheck = true;
    return *this;
}

CChaCha20 &CChaCha20::Decrypt(const unsigned char *data, uint32_t size) {
    if(!data || size <= (nsize + chashsize))
        return err();
    CheckHash chash;
    for(int i=0; i < chashsize; ++i)
        chash.c[i] = data[size - (chashsize + nsize) + i];
    for(int i=0; i < nsize; ++i)
        nonce[i] = data[size - nsize + i];
    CHACHA20_CTX ctx;
    chacha20_init(&ctx, getkeyhash(secret).begin(), nonce);
    buffer.resize(size - (chashsize + nsize));
    chacha20_compute(&ctx, data, &buffer.front(), size - (chashsize + nsize));
    CheckHash chashdec = checking(buffer.data(), buffer.size());
    if(chash != chashdec)
        return err();
    fcheck = true;
    return *this;
}

void CChaCha20::Finalize(std::pair<std::vector<unsigned char>, bool> &out) {
    out = std::make_pair(std::move(buffer), fcheck);
}

constexpr static inline uint32_t rotl32(uint32_t v, int c) { return (v << c) | (v >> (32 - c)); }

#define QUARTERROUND(a,b,c,d) \
  a += b; d = rotl32(d ^ a, 16); \
  c += d; b = rotl32(b ^ c, 12); \
  a += b; d = rotl32(d ^ a, 8); \
  c += d; b = rotl32(b ^ c, 7);

static const unsigned char sigma[] = "expand 32-byte k";
static const unsigned char tau[] = "expand 16-byte k";

void ChaCha20::SetKey(const unsigned char* k, size_t keylen)
{
    const unsigned char *constants;

    input[4] = ReadLE32(k + 0);
    input[5] = ReadLE32(k + 4);
    input[6] = ReadLE32(k + 8);
    input[7] = ReadLE32(k + 12);
    if (keylen == 32) { /* recommended */
        k += 16;
        constants = sigma;
    } else { /* keylen == 16 */
        constants = tau;
    }
    input[8] = ReadLE32(k + 0);
    input[9] = ReadLE32(k + 4);
    input[10] = ReadLE32(k + 8);
    input[11] = ReadLE32(k + 12);
    input[0] = ReadLE32(constants + 0);
    input[1] = ReadLE32(constants + 4);
    input[2] = ReadLE32(constants + 8);
    input[3] = ReadLE32(constants + 12);
    input[12] = 0;
    input[13] = 0;
    input[14] = 0;
    input[15] = 0;
}

ChaCha20::ChaCha20()
{
    std::memset(input, 0, sizeof(input));
}

ChaCha20::ChaCha20(const unsigned char* k, size_t keylen)
{
    SetKey(k, keylen);
}

void ChaCha20::SetIV(uint64_t iv)
{
    input[14] = iv;
    input[15] = iv >> 32;
}

void ChaCha20::Seek(uint64_t pos)
{
    input[12] = pos;
    input[13] = pos >> 32;
}

void ChaCha20::Output(unsigned char* c, size_t bytes)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
    uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
    unsigned char *ctarget = nullptr;
    unsigned char tmp[64];
    unsigned int i;

    if (!bytes) return;

    j0 = input[0];
    j1 = input[1];
    j2 = input[2];
    j3 = input[3];
    j4 = input[4];
    j5 = input[5];
    j6 = input[6];
    j7 = input[7];
    j8 = input[8];
    j9 = input[9];
    j10 = input[10];
    j11 = input[11];
    j12 = input[12];
    j13 = input[13];
    j14 = input[14];
    j15 = input[15];

    for (;;) {
        if (bytes < 64) {
            ctarget = c;
            c = tmp;
        }
        x0 = j0;
        x1 = j1;
        x2 = j2;
        x3 = j3;
        x4 = j4;
        x5 = j5;
        x6 = j6;
        x7 = j7;
        x8 = j8;
        x9 = j9;
        x10 = j10;
        x11 = j11;
        x12 = j12;
        x13 = j13;
        x14 = j14;
        x15 = j15;
        for (i = 20;i > 0;i -= 2) {
            QUARTERROUND( x0, x4, x8,x12)
            QUARTERROUND( x1, x5, x9,x13)
            QUARTERROUND( x2, x6,x10,x14)
            QUARTERROUND( x3, x7,x11,x15)
            QUARTERROUND( x0, x5,x10,x15)
            QUARTERROUND( x1, x6,x11,x12)
            QUARTERROUND( x2, x7, x8,x13)
            QUARTERROUND( x3, x4, x9,x14)
        }
        x0 += j0;
        x1 += j1;
        x2 += j2;
        x3 += j3;
        x4 += j4;
        x5 += j5;
        x6 += j6;
        x7 += j7;
        x8 += j8;
        x9 += j9;
        x10 += j10;
        x11 += j11;
        x12 += j12;
        x13 += j13;
        x14 += j14;
        x15 += j15;

        ++j12;
        if (!j12) ++j13;

        WriteLE32(c + 0, x0);
        WriteLE32(c + 4, x1);
        WriteLE32(c + 8, x2);
        WriteLE32(c + 12, x3);
        WriteLE32(c + 16, x4);
        WriteLE32(c + 20, x5);
        WriteLE32(c + 24, x6);
        WriteLE32(c + 28, x7);
        WriteLE32(c + 32, x8);
        WriteLE32(c + 36, x9);
        WriteLE32(c + 40, x10);
        WriteLE32(c + 44, x11);
        WriteLE32(c + 48, x12);
        WriteLE32(c + 52, x13);
        WriteLE32(c + 56, x14);
        WriteLE32(c + 60, x15);

        if (bytes <= 64) {
            if (bytes < 64) {
                for (i = 0;i < bytes;++i) ctarget[i] = c[i];
            }
            input[12] = j12;
            input[13] = j13;
            return;
        }
        bytes -= 64;
        c += 64;
    }
}

} // namespace latest_crypto
