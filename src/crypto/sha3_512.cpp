// Copyright (c) 2026 The SORA developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sha3_512.h>
#include <algorithm>
#include <cstring>

static uint64_t rotl64(uint64_t x, unsigned n) {
    return (x << n) | (x >> (64 - n));
}

static uint64_t load64_le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

static void store64_le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        p[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

static void keccak_f1600(uint64_t st[25]) {
    static const uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL,
        0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL,
        0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL,
        0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL,
        0x0000000080000001ULL, 0x8000000080008008ULL
    };

    static const unsigned R[25] = {
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14
    };

    for (int round = 0; round < 24; ++round)
    {
        uint64_t C[5], D[5], B[25];

        for (int x = 0; x < 5; ++x)
            C[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];

        for (int x = 0; x < 5; ++x)
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);

        for (int y = 0; y < 5; ++y)
            for (int x = 0; x < 5; ++x)
                st[x + 5 * y] ^= D[x];

        for (int y = 0; y < 5; ++y)
        {
            for (int x = 0; x < 5; ++x)
            {
                int idx = x + 5 * y;
                int nx = y;
                int ny = (2 * x + 3 * y) % 5;
                B[nx + 5 * ny] = rotl64(st[idx], R[idx]);
            }
        }

        for (int y = 0; y < 5; ++y)
        {
            for (int x = 0; x < 5; ++x)
            {
                st[x + 5 * y] =
                    B[x + 5 * y] ^
                    ((~B[((x + 1) % 5) + 5 * y]) & B[((x + 2) % 5) + 5 * y]);
            }
        }

        st[0] ^= RC[round];
    }
}

CSHA3_512 &CSHA3_512::Reset() {
    std::fill(std::begin(st_), std::end(st_), 0);
    buffer_.clear();
    finalized_ = false;
    squeezing_ = false;

    rateBytes_ = 576 / 8;
    domain_ = 0x06;
    fixedOutLen_ = 64;

    buffer_.assign(rateBytes_, 0);
    bufferUsed_ = 0;

    return *this;
}

void CSHA3_512::absorbBlock(const uint8_t *block) {
    for (size_t i = 0; i < rateBytes_ / 8; ++i)
        st_[i] ^= load64_le(block + i * 8);

    keccak_f1600(st_);
}

void CSHA3_512::padAndSwitchToSqueeze() {
    buffer_[bufferUsed_] ^= domain_;
    buffer_[rateBytes_ - 1] ^= 0x80;

    for (size_t i = 0; i < rateBytes_ / 8; ++i)
        st_[i] ^= load64_le(buffer_.data() + i * 8);

    keccak_f1600(st_);

    std::fill(buffer_.begin(), buffer_.end(), 0);
    bufferUsed_ = 0;

    finalized_ = true;
    squeezing_ = true;
}

std::vector<uint8_t> CSHA3_512::squeezeBytes(size_t outLen) {
    std::vector<uint8_t> out;
    out.reserve(outLen);

    while (out.size() < outLen)
    {
        std::vector<uint8_t> tmp(rateBytes_);
        for (size_t i = 0; i < rateBytes_ / 8; ++i)
            store64_le(tmp.data() + i * 8, st_[i]);

        size_t take = std::min(rateBytes_, outLen - out.size());
        out.insert(out.end(), tmp.begin(), tmp.begin() + take);

        if (out.size() < outLen)
            keccak_f1600(st_);
    }

    return out;
}

CSHA3_512::CSHA3_512() {
    Reset();
}

CSHA3_512::~CSHA3_512() {}

CSHA3_512 &CSHA3_512::Write(const unsigned char *data, size_t len) {
    const uint8_t *p = static_cast<const uint8_t *>(data);
    while (len > 0)
    {
        size_t take = std::min(len, rateBytes_ - bufferUsed_);
        std::memcpy(buffer_.data() + bufferUsed_, p, take);
        bufferUsed_ += take;
        p += take;
        len -= take;

        if (bufferUsed_ == rateBytes_) {
            absorbBlock(buffer_.data());
            std::fill(buffer_.begin(), buffer_.end(), 0);
            bufferUsed_ = 0;
        }
    }

    return *this;
}

void CSHA3_512::Finalize(unsigned char hash[OUTPUT_SIZE]) {
    if (! finalized_)
        padAndSwitchToSqueeze();

    std::memcpy(hash, squeezeBytes(fixedOutLen_).data(), OUTPUT_SIZE);
}
