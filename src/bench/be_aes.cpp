/*********************************************************************
* Copyright (c) 2016 Pieter Wuille                                   *
* Distributed under the MIT software license, see the accompanying   *
* file COPYING or http://www.opensource.org/licenses/mit-license.php.*
**********************************************************************/

// Copyright (c) 2018-2020 The SorachanCoin developers

#ifdef LATEST_CRYPTO_ENABLE

#include <stdio.h>
#include <math.h>
#include <crypto/ctaes/ctaes.h>
#include <bench/bench.h>
#include <compat/sanity.h>

namespace latest_crypto {

static void bench_AES128_init(void* data) {
    AES128_ctx* ctx = (AES128_ctx*)data;
    int i;
    for(i = 0; i < 50000; i++) {
        AES128_init(ctx, (unsigned char*)ctx);
    }
}

static void bench_AES128_encrypt_setup(void* data) {
    AES128_ctx* ctx = (AES128_ctx*)data;
    static const unsigned char key[16] = { 0 };
    AES128_init(ctx, key);
}

static void bench_AES128_encrypt(void* data) {
    const AES128_ctx* ctx = (const AES128_ctx*)data;
    unsigned char scratch[16] = { 0 };
    int i;
    for(i = 0; i < 4000000 / 16; i++) {
        AES128_encrypt(ctx, 1, scratch, scratch);
    }
}

static void bench_AES128_decrypt(void* data) {
    const AES128_ctx* ctx = (const AES128_ctx*)data;
    unsigned char scratch[16] = { 0 };
    int i;
    for(i = 0; i < 4000000 / 16; i++) {
        AES128_decrypt(ctx, 1, scratch, scratch);
    }
}

static void bench_AES192_init(void* data) {
    AES192_ctx* ctx = (AES192_ctx*)data;
    int i;
    for(i = 0; i < 50000; i++) {
        AES192_init(ctx, (unsigned char*)ctx);
    }
}

static void bench_AES192_encrypt_setup(void* data) {
    AES192_ctx* ctx = (AES192_ctx*)data;
    static const unsigned char key[16] = { 0 };
    AES192_init(ctx, key);
}

static void bench_AES192_encrypt(void* data) {
    const AES192_ctx* ctx = (const AES192_ctx*)data;
    unsigned char scratch[16] = { 0 };
    int i;
    for(i = 0; i < 4000000 / 16; i++) {
        AES192_encrypt(ctx, 1, scratch, scratch);
    }
}

static void bench_AES192_decrypt(void* data) {
    const AES192_ctx* ctx = (const AES192_ctx*)data;
    unsigned char scratch[16] = { 0 };
    int i;
    for(i = 0; i < 4000000 / 16; i++) {
        AES192_decrypt(ctx, 1, scratch, scratch);
    }
}

static void bench_AES256_init(void* data) {
    AES256_ctx* ctx = (AES256_ctx*)data;
    int i;
    for(i = 0; i < 50000; i++) {
        AES256_init(ctx, (unsigned char*)ctx);
    }
}

static void bench_AES256_encrypt_setup(void* data) {
    AES256_ctx* ctx = (AES256_ctx*)data;
    static const unsigned char key[16] = { 0 };
    AES256_init(ctx, key);
}

static void bench_AES256_encrypt(void* data) {
    const AES256_ctx* ctx = (const AES256_ctx*)data;
    unsigned char scratch[16] = { 0 };
    int i;
    for(i = 0; i < 4000000 / 16; i++) {
        AES256_encrypt(ctx, 1, scratch, scratch);
    }
}

static void bench_AES256_decrypt(void* data) {
    const AES256_ctx* ctx = (const AES256_ctx*)data;
    unsigned char scratch[16] = { 0 };
    int i;
    for(i = 0; i < 4000000 / 16; i++) {
        AES256_decrypt(ctx, 1, scratch, scratch);
    }
}



static void __bench_AES128(benchmark::State& state)
{
    while(state.KeepRunning()) {
        {
            AES128_ctx data;
            bench_AES128_init(&data);
            bench_AES128_encrypt(&data);
            bench_AES128_encrypt_setup(&data);
        }
        {
            AES128_ctx data;
            bench_AES128_init(&data);
            bench_AES128_decrypt(&data);
            bench_AES128_encrypt_setup(&data);
        }
    }
}

static void __bench_AES192(benchmark::State& state)
{
    while(state.KeepRunning()) {
        {
            AES192_ctx data;
            bench_AES192_init(&data);
            bench_AES192_encrypt(&data);
            bench_AES192_encrypt_setup(&data);
        }
        {
            AES192_ctx data;
            bench_AES192_init(&data);
            bench_AES192_decrypt(&data);
            bench_AES192_encrypt_setup(&data);
        }
    }
}

static void __bench_AES256(benchmark::State& state)
{
    while(state.KeepRunning()) {
        {
            AES256_ctx data;
            bench_AES256_init(&data);
            bench_AES256_encrypt(&data);
            bench_AES256_encrypt_setup(&data);
        }
        {
            AES256_ctx data;
            bench_AES256_init(&data);
            bench_AES256_decrypt(&data);
            bench_AES256_encrypt_setup(&data);
        }
    }
}

#define AES_TEST(name, iter)                           \
    void bench_ ## name(benchmark::State& state) {     \
        __bench_ ## name(state);                       \
    }                                                  \
    BENCHMARK(bench_ ## name, iter);

AES_TEST(AES128, 50000)
AES_TEST(AES192, 50000)
AES_TEST(AES256, 50000)

} // namespace latest_crypto

#endif // LATEST_CRYPTO_ENABLE
