// Copyright (c) 2013 NovaCoin Developers
// Copyright (c) 2018-2021 SorachanCoin developers

#ifndef PBKDF2_H
#define PBKDF2_H

#include <cleanse/cleanse.h>
#include <stdint.h>

# if defined(USE_QUANTUM)
template <typename T>
class pbkdf2_impl
{
protected:
    typedef struct HMAC_Context {
        T ictx;
        T octx;
        struct HMAC_Context &operator=(const struct HMAC_Context &obj) {
            ictx=obj.ictx;
            octx=obj.octx;
            return *this;
        }
        void cleanse() {
            ictx.Clean();
            octx.Clean();
        }
    } HMAC_CTX;
    static uint32_t be32dec(const void *pp) {
        const uint8_t *p = (uint8_t const *)pp;
        return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
               ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
    }
    static void be32enc(void *pp, uint32_t x) {
        uint8_t * p = (uint8_t *)pp;
        p[3] = x & 0xff;
        p[2] = (x >> 8) & 0xff;
        p[1] = (x >> 16) & 0xff;
        p[0] = (x >> 24) & 0xff;
    }
    /**
     ** Initialize an HMAC-HASH operation with the given key.
     */
    static void HMAC_HASH_Init(HMAC_CTX *ctx, const void *_K, size_t Klen) {
        const size_t hsize = T::Size();
        unsigned char pad[hsize*2];
        unsigned char khash[hsize];
        const unsigned char *K = (const unsigned char *)_K;

        /* If Klen > 64(hsize*2), the key is really HASH(K). */
        if (Klen > hsize*2) {
            ctx->ictx.Reset();
            ctx->ictx.Write(K, Klen);
            ctx->ictx.Finalize(khash);
            K = khash;
            Klen = hsize;
        }

        /* Inner HASH operation is HASH(K xor [block of 0x36] || data). */
        ctx->ictx.Reset();
        ::memset(pad, 0x36, hsize*2);
        for (size_t i = 0; i < Klen; ++i) pad[i] ^= K[i];
        ctx->ictx.Write(pad, 64);

        /* Outer HASH operation is HASH(K xor [block of 0x5c] || hash). */
        ctx->octx.Reset();
        ::memset(pad, 0x5c, hsize*2);
        for (size_t i = 0; i < Klen; ++i) pad[i] ^= K[i];
        ctx->octx.Write(pad, hsize*2);

        /* Clean the stack. */
        cleanse::OPENSSL_cleanse(khash, sizeof(khash));
    }
    /* Add bytes to the HMAC-HASH operation. */
    static void HMAC_HASH_Update(HMAC_CTX *ctx, const void *in, size_t len) {
        /* Feed data to the inner HASH operation. */
        ctx->ictx.Write((const unsigned char *)in, len);
    }
    /* Finish an HMAC-HASH operation. */
    static void HMAC_HASH_Final(unsigned char digest[T::Size()], HMAC_CTX *ctx) {
        const size_t hsize = T::Size();
        unsigned char ihash[hsize];

        /* Finish the inner HASH operation. */
        ctx->ictx.Finalize(ihash);

        /* Feed the inner hash to the outer HASH operation. */
        ctx->octx.Write(ihash, hsize);

        /* Finish the outer HASH operation. */
        ctx->octx.Finalize(digest);

        /* Clean the stack. */
        cleanse::OPENSSL_cleanse(ihash, sizeof(ihash));
    }
public:
    /**
     * PBKDF2_HASH(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
     * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-HASH as the PRF, and
     * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
     */
    static void PBKDF2_HASH(const uint8_t *passwd, size_t passwdlen, const uint8_t *salt, size_t saltlen, uint64_t c, uint8_t *buf, size_t dkLen) {
        const size_t hsize = T::Size();
        HMAC_CTX PShctx, hctx;
        uint8_t ivec[hsize/8];
        uint8_t U[hsize];
        uint8_t Y[hsize];

        /* Compute HMAC state after processing P and S. */
        HMAC_HASH_Init(&PShctx, passwd, passwdlen);
        HMAC_HASH_Update(&PShctx, salt, saltlen);

        /* Iterate through the blocks. */
        for (size_t i = 0; i * hsize < dkLen; ++i) {
            /* Generate INT(i + 1). */
            for(size_t j=0; j<sizeof(ivec); j+=sizeof(uint32_t))
                be32enc(ivec+j*sizeof(uint32_t), (uint32_t)(i + 1));

            /* Compute U_1 = PRF(P, S || INT(i)). */
            hctx = PShctx;
            HMAC_HASH_Update(&hctx, ivec, hsize/8);
            HMAC_HASH_Final(U, &hctx);

            /* Y_i = U_1 ... */
            ::memcpy(Y, U, hsize);

            for (uint64_t j = 2; j <= c; ++j) {
                /* Compute U_j. */
                HMAC_HASH_Init(&hctx, passwd, passwdlen);
                HMAC_HASH_Update(&hctx, U, hsize);
                HMAC_HASH_Final(U, &hctx);

                /* ... xor U_j ... */
                for (int k = 0; k < hsize; ++k) Y[k] ^= U[k];
            }

            /* Copy as many bytes as necessary into buf. */
            size_t clen = dkLen - i * hsize;
            if (clen > hsize) clen = hsize;
            ::memcpy(&buf[i * hsize], Y, clen);
        }

        /* Clean PShctx, since we never called _Final on it. */
        PShctx.cleanse();
    }
};
# else
#include <openssl/sha.h>
class pbkdf2
{
private:
    typedef struct HMAC_SHA256Context {
        SHA256_CTX ictx;
        SHA256_CTX octx;
    } HMAC_SHA256_CTX;
    static uint32_t be32dec(const void *pp);
    static void be32enc(void *pp, uint32_t x);
    static void HMAC_HASH_Init(HMAC_SHA256_CTX *ctx, const void *_K, size_t Klen);
    static void HMAC_HASH_Update(HMAC_SHA256_CTX *ctx, const void *in, size_t len);
    static void HMAC_HASH_Final(unsigned char digest[32], HMAC_SHA256_CTX *ctx);
public:
    static void PBKDF2_HASH(const uint8_t *passwd, size_t passwdlen, const uint8_t *salt, size_t saltlen, uint64_t c, uint8_t *buf, size_t dkLen);
};
# endif

#endif // PBKDF2_H
