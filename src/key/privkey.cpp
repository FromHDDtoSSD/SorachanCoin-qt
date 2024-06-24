// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/hmac_sha256.h>
#include <crypto/common.h>
#include <key/privkey.h>
#include <random/random.h>
#include <hash.h>
#include <uint256.h>
#include <cleanse/cleanse.h>

#ifdef VERIFY // pubkey.h
# define VERIFY_CHECK(cond) do { assert(cond); } while(0)
# define CHECK(cond) VERIFY_CHECK(cond)
#else
# define VERIFY_CHECK(cond) do { (void)(cond); } while(0)
# define CHECK(cond) VERIFY_CHECK(cond)
#endif

#define ARG_CHECK(cond) ARG_CHECK_FUNC(cond, nullptr)
#define ARG_CHECK_FUNC(cond, func) do { if(!(cond)) return CFirmKey::PrivKey_ERROR_callback((func)); } while(0)
#define ARG_BOOL_CHECK(cond) ARG_BOOL_CHECK_FUNC(cond, nullptr)
#define ARG_BOOL_CHECK_FUNC(cond, func) do { if(!(cond)) {CFirmKey::PrivKey_ERROR_callback((func)); return false;} } while(0)

bool CFirmKey::ecmult::secp256k1_gej_add_var(CPubKey::ecmult::secp256k1_gej *r, const CPubKey::ecmult::secp256k1_gej *a, const CPubKey::ecmult::secp256k1_gej *b, CPubKey::ecmult::secp256k1_fe *rzr) {
    /* Operations: 12 mul, 4 sqr, 2 normalize, 12 mul_int/add/negate */
    CPubKey::ecmult::secp256k1_fe z22, z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;

    if (a->infinity) {
        ARG_BOOL_CHECK(rzr == nullptr);
        *r = *b;
        return true;
    }

    if (b->infinity) {
        if (rzr != nullptr) {
            CPubKey::ecmult::secp256k1_fe_set_int(rzr, 1);
        }
        *r = *a;
        return true;
    }

    r->infinity = 0;
    CPubKey::ecmult::secp256k1_fe_sqr(&z22, &b->z);
    CPubKey::ecmult::secp256k1_fe_sqr(&z12, &a->z);
    CPubKey::ecmult::secp256k1_fe_mul(&u1, &a->x, &z22);
    CPubKey::ecmult::secp256k1_fe_mul(&u2, &b->x, &z12);
    CPubKey::ecmult::secp256k1_fe_mul(&s1, &a->y, &z22); CPubKey::ecmult::secp256k1_fe_mul(&s1, &s1, &b->z);
    CPubKey::ecmult::secp256k1_fe_mul(&s2, &b->y, &z12); CPubKey::ecmult::secp256k1_fe_mul(&s2, &s2, &a->z);
    CPubKey::ecmult::secp256k1_fe_negate(&h, &u1, 1); CPubKey::ecmult::secp256k1_fe_add(&h, &u2);
    CPubKey::ecmult::secp256k1_fe_negate(&i, &s1, 1); CPubKey::ecmult::secp256k1_fe_add(&i, &s2);
    if (CPubKey::ecmult::secp256k1_fe_normalizes_to_zero_var(&h)) {
        if (CPubKey::ecmult::secp256k1_fe_normalizes_to_zero_var(&i)) {
            CPubKey::ecmult::secp256k1_gej_double_var(r, a, rzr);
        } else {
            if (rzr != nullptr) {
                CPubKey::ecmult::secp256k1_fe_set_int(rzr, 0);
            }
            r->infinity = 1;
        }
        return true;
    }
    CPubKey::ecmult::secp256k1_fe_sqr(&i2, &i);
    CPubKey::ecmult::secp256k1_fe_sqr(&h2, &h);
    CPubKey::ecmult::secp256k1_fe_mul(&h3, &h, &h2);
    CPubKey::ecmult::secp256k1_fe_mul(&h, &h, &b->z);
    if (rzr != nullptr) {
        *rzr = h;
    }
    CPubKey::ecmult::secp256k1_fe_mul(&r->z, &a->z, &h);
    CPubKey::ecmult::secp256k1_fe_mul(&t, &u1, &h2);
    r->x = t; CPubKey::ecmult::secp256k1_fe_mul_int(&r->x, 2); CPubKey::ecmult::secp256k1_fe_add(&r->x, &h3); CPubKey::ecmult::secp256k1_fe_negate(&r->x, &r->x, 3); CPubKey::ecmult::secp256k1_fe_add(&r->x, &i2);
    CPubKey::ecmult::secp256k1_fe_negate(&r->y, &r->x, 5); CPubKey::ecmult::secp256k1_fe_add(&r->y, &t); CPubKey::ecmult::secp256k1_fe_mul(&r->y, &r->y, &i);
    CPubKey::ecmult::secp256k1_fe_mul(&h3, &h3, &s1); CPubKey::ecmult::secp256k1_fe_negate(&h3, &h3, 1);
    CPubKey::ecmult::secp256k1_fe_add(&r->y, &h3);
    return true;
}

void CFirmKey::ecmult::secp256k1_gej_neg(CPubKey::ecmult::secp256k1_gej *r, const CPubKey::ecmult::secp256k1_gej *a) {
    r->infinity = a->infinity;
    r->x = a->x;
    r->y = a->y;
    r->z = a->z;
    CPubKey::ecmult::secp256k1_fe_normalize_weak(&r->y);
    CPubKey::ecmult::secp256k1_fe_negate(&r->y, &r->y, 1);
}

bool CFirmKey::ecmult::secp256k1_ge_set_all_gej_var(CPubKey::ecmult::secp256k1_ge *r, const CPubKey::ecmult::secp256k1_gej *a, size_t len) {
    auto secp256k1_fe_inv_all_var = [](CPubKey::ecmult::secp256k1_fe *r, const CPubKey::ecmult::secp256k1_fe *a, size_t len) {
        if (len < 1) return true;
        ARG_BOOL_CHECK((&r[0] + len <= &a[0]) || (&a[0] + len <= &r[0]));
        r[0] = a[0];

        size_t i = 0;
        while (++i < len) {
            CPubKey::ecmult::secp256k1_fe_mul(&r[i], &r[i - 1], &a[i]);
        }

        CPubKey::ecmult::secp256k1_fe u;
        CPubKey::ecmult::secp256k1_fe_inv_var(&u, &r[--i]);
        while (i > 0) {
            size_t j = i--;
            CPubKey::ecmult::secp256k1_fe_mul(&r[j], &r[i], &u);
            CPubKey::ecmult::secp256k1_fe_mul(&u, &u, &a[j]);
        }

        r[0] = u;

        return true;
    };

    std::unique_ptr<CPubKey::ecmult::secp256k1_fe[]> az(new (std::nothrow) CPubKey::ecmult::secp256k1_fe[len]);
    if(! az.get())
        return false;
    size_t count = 0;
    for (size_t i = 0; i < len; ++i) {
        if (! a[i].infinity) {
            az[count++] = a[i].z;
        }
    }

    std::unique_ptr<CPubKey::ecmult::secp256k1_fe[]> azi(new (std::nothrow) CPubKey::ecmult::secp256k1_fe[count]);
    if(! azi.get())
        return false;
    if(! secp256k1_fe_inv_all_var(azi.get(), az.get(), count))
        return false;

    count = 0;
    for (size_t i = 0; i < len; ++i) {
        r[i].infinity = a[i].infinity;
        if (! a[i].infinity) {
            CPubKey::ecmult::secp256k1_ge_set_gej_zinv(&r[i], &a[i], &azi[count++]);
        }
    }
    return true;
}

// hash
void CFirmKey::hash::secp256k1_sha256_initialize(secp256k1_sha256 *hash) {
    hash->Reset();
}

void CFirmKey::hash::secp256k1_sha256_write(secp256k1_sha256 *hash, const unsigned char *data, size_t size) {
    hash->Write(data, size);
}

void CFirmKey::hash::secp256k1_sha256_finalize(secp256k1_sha256 *hash, unsigned char *out32) {
    hash->Finalize(out32);
}

void CFirmKey::hash::secp256k1_hmac_sha256_initialize(secp256k1_hmac_sha256 *hash, const unsigned char *key, size_t size) {
    hash->Init(key, size);
}

void CFirmKey::hash::secp256k1_hmac_sha256_write(secp256k1_hmac_sha256 *hash, const unsigned char *data, size_t size) {
    hash->Write(data, size);
}

void CFirmKey::hash::secp256k1_hmac_sha256_finalize(secp256k1_hmac_sha256 *hash, unsigned char *out32) {
    hash->Finalize(out32);
}

void CFirmKey::hash::secp256k1_rfc6979_hmac_sha256_initialize(secp256k1_rfc6979_hmac_sha256_t *rng, const unsigned char *key, size_t keylen) {
    latest_crypto::CHMAC_SHA256 hmac;
    static constexpr unsigned char zero[1] = {0x00};
    static constexpr unsigned char one[1] = {0x01};

    std::memset(rng->v, 0x01, 32); /* RFC6979 3.2.b. */
    std::memset(rng->k, 0x00, 32); /* RFC6979 3.2.c. */

    /* RFC6979 3.2.d. */
    secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32);
    secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
    secp256k1_hmac_sha256_write(&hmac, zero, 1);
    secp256k1_hmac_sha256_write(&hmac, key, keylen);
    secp256k1_hmac_sha256_finalize(&hmac, rng->k);
    secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32);
    secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
    secp256k1_hmac_sha256_finalize(&hmac, rng->v);

    /* RFC6979 3.2.f. */
    secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32);
    secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
    secp256k1_hmac_sha256_write(&hmac, one, 1);
    secp256k1_hmac_sha256_write(&hmac, key, keylen);
    secp256k1_hmac_sha256_finalize(&hmac, rng->k);
    secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32);
    secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
    secp256k1_hmac_sha256_finalize(&hmac, rng->v);
    rng->retry = 0;
}

void CFirmKey::hash::secp256k1_rfc6979_hmac_sha256_generate(secp256k1_rfc6979_hmac_sha256_t *rng, unsigned char *out, size_t outlen) {
    /* RFC6979 3.2.h. */
    static constexpr unsigned char zero[1] = {0x00};
    if (rng->retry) {
        latest_crypto::CHMAC_SHA256 hmac;
        secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32);
        secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
        secp256k1_hmac_sha256_write(&hmac, zero, 1);
        secp256k1_hmac_sha256_finalize(&hmac, rng->k);
        secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32);
        secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
        secp256k1_hmac_sha256_finalize(&hmac, rng->v);
    }

    while (outlen > 0) {
        latest_crypto::CHMAC_SHA256 hmac;
        int now = outlen;
        secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32);
        secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
        secp256k1_hmac_sha256_finalize(&hmac, rng->v);
        if (now > 32) {
            now = 32;
        }
        std::memcpy(out, rng->v, now);
        out += now;
        outlen -= now;
    }

    rng->retry = 1;
}

void CFirmKey::hash::secp256k1_rfc6979_hmac_sha256_finalize(secp256k1_rfc6979_hmac_sha256_t *rng) {
    //std::memset(rng->k, 0, 32);
    //std::memset(rng->v, 0, 32);
    cleanse::memory_cleanse(rng->k, 32);
    cleanse::memory_cleanse(rng->v, 32);
    rng->retry = 0;
}

void CFirmKey::ecmult::secp256k1_fe_storage_cmov(CPubKey::ecmult::secp256k1_fe_storage *r, const CPubKey::ecmult::secp256k1_fe_storage *a, int flag) {
    uint32_t mask0, mask1;
    mask0 = flag + ~((uint32_t)0);
    mask1 = ~mask0;
    r->n[0] = (r->n[0] & mask0) | (a->n[0] & mask1);
    r->n[1] = (r->n[1] & mask0) | (a->n[1] & mask1);
    r->n[2] = (r->n[2] & mask0) | (a->n[2] & mask1);
    r->n[3] = (r->n[3] & mask0) | (a->n[3] & mask1);
    r->n[4] = (r->n[4] & mask0) | (a->n[4] & mask1);
    r->n[5] = (r->n[5] & mask0) | (a->n[5] & mask1);
    r->n[6] = (r->n[6] & mask0) | (a->n[6] & mask1);
    r->n[7] = (r->n[7] & mask0) | (a->n[7] & mask1);
}

void CFirmKey::ecmult::secp256k1_ge_storage_cmov(CPubKey::ecmult::secp256k1_ge_storage *r, const CPubKey::ecmult::secp256k1_ge_storage *a, int flag) {
    CFirmKey::ecmult::secp256k1_fe_storage_cmov(&r->x, &a->x, flag);
    CFirmKey::ecmult::secp256k1_fe_storage_cmov(&r->y, &a->y, flag);
}

void CFirmKey::ecmult::secp256k1_fe_cmov(CPubKey::ecmult::secp256k1_fe *r, const CPubKey::ecmult::secp256k1_fe *a, int flag) {
    uint32_t mask0, mask1;
    mask0 = flag + ~((uint32_t)0);
    mask1 = ~mask0;
    r->n[0] = (r->n[0] & mask0) | (a->n[0] & mask1);
    r->n[1] = (r->n[1] & mask0) | (a->n[1] & mask1);
    r->n[2] = (r->n[2] & mask0) | (a->n[2] & mask1);
    r->n[3] = (r->n[3] & mask0) | (a->n[3] & mask1);
    r->n[4] = (r->n[4] & mask0) | (a->n[4] & mask1);
    r->n[5] = (r->n[5] & mask0) | (a->n[5] & mask1);
    r->n[6] = (r->n[6] & mask0) | (a->n[6] & mask1);
    r->n[7] = (r->n[7] & mask0) | (a->n[7] & mask1);
    r->n[8] = (r->n[8] & mask0) | (a->n[8] & mask1);
    r->n[9] = (r->n[9] & mask0) | (a->n[9] & mask1);
#ifdef VERIFY
    if (a->magnitude > r->magnitude) {
        r->magnitude = a->magnitude;
    }
    r->normalized &= a->normalized;
#endif
}

bool CFirmKey::ecmult::secp256k1_gej_add_ge(CPubKey::ecmult::secp256k1_gej *r, const CPubKey::ecmult::secp256k1_gej *a, const CPubKey::ecmult::secp256k1_ge *b) {
    /* Operations: 7 mul, 5 sqr, 4 normalize, 21 mul_int/add/negate/cmov */
    static constexpr CPubKey::ecmult::secp256k1_fe fe_1 = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1);
    CPubKey::ecmult::secp256k1_fe zz, u1, u2, s1, s2, t, tt, m, n, q, rr;
    CPubKey::ecmult::secp256k1_fe m_alt, rr_alt;
    int infinity, degenerate;
    ARG_BOOL_CHECK(!b->infinity);
    ARG_BOOL_CHECK(a->infinity == 0 || a->infinity == 1);

    /** In:
     *    Eric Brier and Marc Joye, Weierstrass Elliptic Curves and Side-Channel Attacks.
     *    In D. Naccache and P. Paillier, Eds., Public Key Cryptography, vol. 2274 of Lecture Notes in Computer Science, pages 335-345. Springer-Verlag, 2002.
     *  we find as solution for a unified addition/doubling formula:
     *    lambda = ((x1 + x2)^2 - x1 * x2 + a) / (y1 + y2), with a = 0 for secp256k1's curve equation.
     *    x3 = lambda^2 - (x1 + x2)
     *    2*y3 = lambda * (x1 + x2 - 2 * x3) - (y1 + y2).
     *
     *  Substituting x_i = Xi / Zi^2 and yi = Yi / Zi^3, for i=1,2,3, gives:
     *    U1 = X1*Z2^2, U2 = X2*Z1^2
     *    S1 = Y1*Z2^3, S2 = Y2*Z1^3
     *    Z = Z1*Z2
     *    T = U1+U2
     *    M = S1+S2
     *    Q = T*M^2
     *    R = T^2-U1*U2
     *    X3 = 4*(R^2-Q)
     *    Y3 = 4*(R*(3*Q-2*R^2)-M^4)
     *    Z3 = 2*M*Z
     *  (Note that the paper uses xi = Xi / Zi and yi = Yi / Zi instead.)
     *
     *  This formula has the benefit of being the same for both addition
     *  of distinct points and doubling. However, it breaks down in the
     *  case that either point is infinity, or that y1 = -y2. We handle
     *  these cases in the following ways:
     *
     *    - If b is infinity we simply bail by means of a VERIFY_CHECK.
     *
     *    - If a is infinity, we detect this, and at the end of the
     *      computation replace the result (which will be meaningless,
     *      but we compute to be constant-time) with b.x : b.y : 1.
     *
     *    - If a = -b, we have y1 = -y2, which is a degenerate case.
     *      But here the answer is infinity, so we simply set the
     *      infinity flag of the result, overriding the computed values
     *      without even needing to cmov.
     *
     *    - If y1 = -y2 but x1 != x2, which does occur thanks to certain
     *      properties of our curve (specifically, 1 has nontrivial cube
     *      roots in our field, and the curve equation has no x coefficient)
     *      then the answer is not infinity but also not given by the above
     *      equation. In this case, we cmov in place an alternate expression
     *      for lambda. Specifically (y1 - y2)/(x1 - x2). Where both these
     *      expressions for lambda are defined, they are equal, and can be
     *      obtained from each other by multiplication by (y1 + y2)/(y1 + y2)
     *      then substitution of x^3 + 7 for y^2 (using the curve equation).
     *      For all pairs of nonzero points (a, b) at least one is defined,
     *      so this covers everything.
     */

    CPubKey::ecmult::secp256k1_fe_sqr(&zz, &a->z);                       /* z = Z1^2 */
    u1 = a->x; CPubKey::ecmult::secp256k1_fe_normalize_weak(&u1);        /* u1 = U1 = X1*Z2^2 (1) */
    CPubKey::ecmult::secp256k1_fe_mul(&u2, &b->x, &zz);                  /* u2 = U2 = X2*Z1^2 (1) */
    s1 = a->y; CPubKey::ecmult::secp256k1_fe_normalize_weak(&s1);        /* s1 = S1 = Y1*Z2^3 (1) */
    CPubKey::ecmult::secp256k1_fe_mul(&s2, &b->y, &zz);                  /* s2 = Y2*Z1^2 (1) */
    CPubKey::ecmult::secp256k1_fe_mul(&s2, &s2, &a->z);                  /* s2 = S2 = Y2*Z1^3 (1) */
    t = u1; CPubKey::ecmult::secp256k1_fe_add(&t, &u2);                  /* t = T = U1+U2 (2) */
    m = s1; CPubKey::ecmult::secp256k1_fe_add(&m, &s2);                  /* m = M = S1+S2 (2) */
    CPubKey::ecmult::secp256k1_fe_sqr(&rr, &t);                          /* rr = T^2 (1) */
    CPubKey::ecmult::secp256k1_fe_negate(&m_alt, &u2, 1);                /* Malt = -X2*Z1^2 */
    CPubKey::ecmult::secp256k1_fe_mul(&tt, &u1, &m_alt);                 /* tt = -U1*U2 (2) */
    CPubKey::ecmult::secp256k1_fe_add(&rr, &tt);                         /* rr = R = T^2-U1*U2 (3) */
    /** If lambda = R/M = 0/0 we have a problem (except in the "trivial"
     *  case that Z = z1z2 = 0, and this is special-cased later on). */
    degenerate = CPubKey::ecmult::secp256k1_fe_normalizes_to_zero(&m) &
                 CPubKey::ecmult::secp256k1_fe_normalizes_to_zero(&rr);
    /* This only occurs when y1 == -y2 and x1^3 == x2^3, but x1 != x2.
     * This means either x1 == beta*x2 or beta*x1 == x2, where beta is
     * a nontrivial cube root of one. In either case, an alternate
     * non-indeterminate expression for lambda is (y1 - y2)/(x1 - x2),
     * so we set R/M equal to this. */
    rr_alt = s1;
    CPubKey::ecmult::secp256k1_fe_mul_int(&rr_alt, 2);                   /* rr = Y1*Z2^3 - Y2*Z1^3 (2) */
    CPubKey::ecmult::secp256k1_fe_add(&m_alt, &u1);                      /* Malt = X1*Z2^2 - X2*Z1^2 */

    CFirmKey::ecmult::secp256k1_fe_cmov(&rr_alt, &rr, !degenerate);
    CFirmKey::ecmult::secp256k1_fe_cmov(&m_alt, &m, !degenerate);
    /* Now Ralt / Malt = lambda and is guaranteed not to be 0/0.
     * From here on out Ralt and Malt represent the numerator
     * and denominator of lambda; R and M represent the explicit
     * expressions x1^2 + x2^2 + x1x2 and y1 + y2. */
    CPubKey::ecmult::secp256k1_fe_sqr(&n, &m_alt);                       /* n = Malt^2 (1) */
    CPubKey::ecmult::secp256k1_fe_mul(&q, &n, &t);                       /* q = Q = T*Malt^2 (1) */
    /* These two lines use the observation that either M == Malt or M == 0,
     * so M^3 * Malt is either Malt^4 (which is computed by squaring), or
     * zero (which is "computed" by cmov). So the cost is one squaring
     * versus two multiplications. */
    CPubKey::ecmult::secp256k1_fe_sqr(&n, &n);
    CFirmKey::ecmult::secp256k1_fe_cmov(&n, &m, degenerate);             /* n = M^3 * Malt (2) */
    CPubKey::ecmult::secp256k1_fe_sqr(&t, &rr_alt);                      /* t = Ralt^2 (1) */
    CPubKey::ecmult::secp256k1_fe_mul(&r->z, &a->z, &m_alt);             /* r->z = Malt*Z (1) */
    infinity = CPubKey::ecmult::secp256k1_fe_normalizes_to_zero(&r->z) * (1 - a->infinity);
    CPubKey::ecmult::secp256k1_fe_mul_int(&r->z, 2);                     /* r->z = Z3 = 2*Malt*Z (2) */
    CPubKey::ecmult::secp256k1_fe_negate(&q, &q, 1);                     /* q = -Q (2) */
    CPubKey::ecmult::secp256k1_fe_add(&t, &q);                           /* t = Ralt^2-Q (3) */
    CPubKey::ecmult::secp256k1_fe_normalize_weak(&t);
    r->x = t;                                                            /* r->x = Ralt^2-Q (1) */
    CPubKey::ecmult::secp256k1_fe_mul_int(&t, 2);                        /* t = 2*x3 (2) */
    CPubKey::ecmult::secp256k1_fe_add(&t, &q);                           /* t = 2*x3 - Q: (4) */
    CPubKey::ecmult::secp256k1_fe_mul(&t, &t, &rr_alt);                  /* t = Ralt*(2*x3 - Q) (1) */
    CPubKey::ecmult::secp256k1_fe_add(&t, &n);                           /* t = Ralt*(2*x3 - Q) + M^3*Malt (3) */
    CPubKey::ecmult::secp256k1_fe_negate(&r->y, &t, 3);                  /* r->y = Ralt*(Q - 2x3) - M^3*Malt (4) */
    CPubKey::ecmult::secp256k1_fe_normalize_weak(&r->y);
    CPubKey::ecmult::secp256k1_fe_mul_int(&r->x, 4);                     /* r->x = X3 = 4*(Ralt^2-Q) */
    CPubKey::ecmult::secp256k1_fe_mul_int(&r->y, 4);                     /* r->y = Y3 = 4*Ralt*(Q - 2x3) - 4*M^3*Malt (4) */

    /** In case a->infinity == 1, replace r with (b->x, b->y, 1). */
    CFirmKey::ecmult::secp256k1_fe_cmov(&r->x, &b->x, a->infinity);
    CFirmKey::ecmult::secp256k1_fe_cmov(&r->y, &b->y, a->infinity);
    CFirmKey::ecmult::secp256k1_fe_cmov(&r->z, &fe_1, a->infinity);
    r->infinity = infinity;

    return true;
}

void CFirmKey::ecmult::secp256k1_gej_clear(CPubKey::ecmult::secp256k1_gej *r) {
    r->infinity = 0;
    CPubKey::ecmult::secp256k1_fe_clear(&r->x);
    CPubKey::ecmult::secp256k1_fe_clear(&r->y);
    CPubKey::ecmult::secp256k1_fe_clear(&r->z);
}

bool CFirmKey::ecmult::secp256k1_gej_rescale(CPubKey::ecmult::secp256k1_gej *r, const CPubKey::ecmult::secp256k1_fe *s) {
    /* Operations: 4 mul, 1 sqr */
    CPubKey::ecmult::secp256k1_fe zz;
    ARG_BOOL_CHECK(! CPubKey::ecmult::secp256k1_fe_is_zero(s));
    CPubKey::ecmult::secp256k1_fe_sqr(&zz, s);
    CPubKey::ecmult::secp256k1_fe_mul(&r->x, &r->x, &zz);                /* r->x *= s^2 */
    CPubKey::ecmult::secp256k1_fe_mul(&r->y, &r->y, &zz);
    CPubKey::ecmult::secp256k1_fe_mul(&r->y, &r->y, s);                  /* r->y *= s^3 */
    CPubKey::ecmult::secp256k1_fe_mul(&r->z, &r->z, s);                  /* r->z *= s   */
    return true;
}

// gen_context
bool CFirmKey::ecmult::secp256k1_gen_context::secp256k1_ecmult_gen(CPubKey::ecmult::secp256k1_gej *r, const CPubKey::secp256k1_scalar *gn) const {
    CPubKey::ecmult::secp256k1_ge add;
    CPubKey::ecmult::secp256k1_ge_storage adds;
    CPubKey::secp256k1_scalar gnb;
    int bits;
    int i, j;
    std::memset(&adds, 0, sizeof(adds));
    *r = initial_;
    /* Blind scalar/point multiplication by computing (n-b)G + bG instead of nG. */
    CPubKey::secp256k1_scalar_add(&gnb, gn, &blind_);
    add.infinity = 0;
    for (j = 0; j < 64; ++j) {
        bits = CPubKey::secp256k1_scalar_get_bits(&gnb, j * 4, 4);
        for (i = 0; i < 16; ++i) {
            /** This uses a conditional move to avoid any secret data in array indexes.
             *   _Any_ use of secret indexes has been demonstrated to result in timing
             *   sidechannels, even when the cache-line access patterns are uniform.
             *  See also:
             *   "A word of warning", CHES 2013 Rump Session, by Daniel J. Bernstein and Peter Schwabe
             *    (https://cryptojedi.org/peter/data/chesrump-20130822.pdf) and
             *   "Cache Attacks and Countermeasures: the Case of AES", RSA 2006,
             *    by Dag Arne Osvik, Adi Shamir, and Eran Tromer
             *    (http://www.tau.ac.il/~tromer/papers/cache.pdf)
             */
            CFirmKey::ecmult::secp256k1_ge_storage_cmov(&adds, &(*prec_)[j][i], i == bits);
        }
        CPubKey::ecmult::secp256k1_ge_from_storage(&add, &adds);
        if(! CFirmKey::ecmult::secp256k1_gej_add_ge(r, r, &add))
            return false;
    }
    bits = 0;
    CPubKey::ecmult::secp256k1_ge_clear(&add);
    CFirmKey::secp256k1_scalar_clear(&gnb);
    return true;
}

/* Setup blinding values for secp256k1_ecmult_gen. */
bool CFirmKey::ecmult::secp256k1_gen_context::secp256k1_ecmult_gen_blind(const unsigned char *seed32) {
    if(!seed32) return false;
    CPubKey::secp256k1_scalar b;
    CPubKey::ecmult::secp256k1_gej gb;
    CPubKey::ecmult::secp256k1_fe s;
    unsigned char nonce32[32];
    CFirmKey::hash::secp256k1_rfc6979_hmac_sha256_t rng;
    CPubKey::ecmult::secp256k1_gej_set_ge(&initial_, CPubKey::ecmult::secp256k1_get_ge_const_g());
    CFirmKey::ecmult::secp256k1_gej_neg(&initial_, &initial_);
    CPubKey::secp256k1_scalar_set_int(&blind_, 1);

    /* The prior blinding value (if not reset) is chained forward by including it in the hash. */
    CPubKey::secp256k1_scalar_get_b32(nonce32, &blind_);
    /** Using a CSPRNG allows a failure free interface, avoids needing large amounts of random data,
     *   and guards against weak or adversarial seeds.  This is a simpler and safer interface than
     *   asking the caller for blinding values directly and expecting them to retry on failure.
     */
    {
        unsigned char keydata[64] = {0};
        std::memcpy(keydata, nonce32, 32);
        std::memcpy(keydata + 32, seed32, 32);
        CFirmKey::hash::secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, 64);
        cleanse::memory_cleanse(keydata, sizeof(keydata));
    }

    /* Retry for out of range results to achieve uniformity. */
    int retry;
    do {
        CFirmKey::hash::secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
        retry = !CPubKey::ecmult::secp256k1_fe_set_b32(&s, nonce32);
        retry |= CPubKey::ecmult::secp256k1_fe_is_zero(&s);
    } while (retry); /* This branch true is cryptographically unreachable. Requires sha256_hmac output > Fp. */
    /* Randomize the projection to defend against multiplier sidechannels. */
    if(! CFirmKey::ecmult::secp256k1_gej_rescale(&initial_, &s))
        return false;

    CPubKey::ecmult::secp256k1_fe_clear(&s);
    do {
        CFirmKey::hash::secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
        CPubKey::secp256k1_scalar_set_b32(&b, nonce32, &retry);
        /* A blinding value of 0 works, but would undermine the projection hardening. */
        retry |= CPubKey::secp256k1_scalar_is_zero(&b);
    } while (retry); /* This branch true is cryptographically unreachable. Requires sha256_hmac output > order. */

    if(! secp256k1_ecmult_gen(&gb, &b))
        return false;

    CPubKey::secp256k1_scalar_negate(&b, &b);
    blind_ = b;
    initial_ = gb;
    cleanse::memory_cleanse(&b, sizeof(b));
    cleanse::memory_cleanse(&gb, sizeof(gb));
    return true;
}

CFirmKey::ecmult::secp256k1_gen_context::secp256k1_gen_context() {
    init();
}

void CFirmKey::ecmult::secp256k1_gen_context::init() {
    CFirmKey::secp256k1_scalar_clear(&blind_);
    CFirmKey::ecmult::secp256k1_gej_clear(&initial_);
    prec_ = nullptr;
}

bool CFirmKey::ecmult::secp256k1_gen_context::build() {
    if (prec_ != nullptr) return true;

#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    prec_ = (CPubKey::ecmult::secp256k1_ge_storage (*)[64][16])::malloc(sizeof(*prec_));
    if(! prec_) return false;

    /* get the generator */
    CPubKey::ecmult::secp256k1_gej gj;
    CPubKey::ecmult::secp256k1_gej_set_ge(&gj, CPubKey::ecmult::secp256k1_get_ge_const_g());

    CPubKey::ecmult::secp256k1_gej nums_gej;
    /* Construct a group element with no known corresponding scalar (nothing up my sleeve). */
    {
        static constexpr unsigned char nums_b32[33] = "The scalar for this x is unknown";
        CPubKey::ecmult::secp256k1_fe nums_x;
        CPubKey::ecmult::secp256k1_ge nums_ge;
        {
            int r;
            r = CPubKey::ecmult::secp256k1_fe_set_b32(&nums_x, nums_b32);
            ARG_BOOL_CHECK(r);
            r = CPubKey::ecmult::secp256k1_ge_set_xo_var(&nums_ge, &nums_x, 0);
            ARG_BOOL_CHECK(r);
        }
        CPubKey::ecmult::secp256k1_gej_set_ge(&nums_gej, &nums_ge);
        /* Add G to make the bits in x uniformly distributed. */
        CPubKey::ecmult::secp256k1_gej_add_ge_var(&nums_gej, &nums_gej, CPubKey::ecmult::secp256k1_get_ge_const_g(), nullptr);
    }

    CPubKey::ecmult::secp256k1_ge _prec[1024];
    /* compute prec. */
    {
        CPubKey::ecmult::secp256k1_gej _precj[1024]; /* Jacobian versions of prec. */
        CPubKey::ecmult::secp256k1_gej gbase;
        CPubKey::ecmult::secp256k1_gej numsbase;
        gbase = gj; /* 16^j * G */
        numsbase = nums_gej; /* 2^j * nums. */
        for (int j = 0; j < 64; ++j) {
            /* Set precj[j*16 .. j*16+15] to (numsbase, numsbase + gbase, ..., numsbase + 15*gbase). */
            _precj[j*16] = numsbase;
            for (int i = 1; i < 16; ++i) {
                if(! CFirmKey::ecmult::secp256k1_gej_add_var(&_precj[j*16 + i], &_precj[j*16 + i - 1], &gbase, nullptr))
                    return false;
            }
            /* Multiply gbase by 16. */
            for (int i = 0; i < 4; ++i) {
                CPubKey::ecmult::secp256k1_gej_double_var(&gbase, &gbase, nullptr);
            }
            /* Multiply numbase by 2. */
            CPubKey::ecmult::secp256k1_gej_double_var(&numsbase, &numsbase, nullptr);
            if (j == 62) {
                /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
                CFirmKey::ecmult::secp256k1_gej_neg(&numsbase, &numsbase);
                CFirmKey::ecmult::secp256k1_gej_add_var(&numsbase, &numsbase, &nums_gej, nullptr);
            }
        }
        if(! CFirmKey::ecmult::secp256k1_ge_set_all_gej_var(_prec, _precj, 1024))
            return false;
    }
    for (int j = 0; j < 64; ++j) {
        for (int i = 0; i < 16; ++i) {
            CPubKey::ecmult::secp256k1_ge_to_storage(&(*prec_)[j][i], &_prec[j*16 + i]);
        }
    }
#else
    prec_ = (CPubKey::ecmult::secp256k1_ge_storage (*)[64][16])secp256k1_ecmult_static_context;
#endif

    debugcs::instance() << "CFirmKey: called prevent side channel attack" << debugcs::endl();
    unsigned char seed32[32];
    latest_crypto::random::GetStrongRandBytes(seed32, 32);
    bool ret = secp256k1_ecmult_gen_blind(seed32);
    cleanse::memory_cleanse(seed32, sizeof(seed32));
    return ret;
}

void CFirmKey::ecmult::secp256k1_gen_context::clear() {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    if(prec_) {
        cleanse::memory_cleanse(prec_, sizeof(*prec_));
        ::free(prec_);
    }
#endif
    init();
}

CFirmKey::ecmult::secp256k1_gen_context::~secp256k1_gen_context() {
    debugcs::instance() << "CFirmKey: cleanse prevent side channel attack " << sizeof(initial_) << ":" << sizeof(blind_) << debugcs::endl();
    clear();
    cleanse::memory_cleanse(&initial_, sizeof(initial_));
    cleanse::memory_cleanse(&blind_, sizeof(blind_));
}



void CFirmKey::secp256k1_scalar_clear(CPubKey::secp256k1_scalar *r) {
    //! if used -03, the above process will be eliminated.
    cleanse::memory_cleanse(r, sizeof(CPubKey::secp256k1_scalar));
    r->d[0] = 0;
    r->d[1] = 0;
    r->d[2] = 0;
    r->d[3] = 0;
    r->d[4] = 0;
    r->d[5] = 0;
    r->d[6] = 0;
    r->d[7] = 0;
    VERIFY_CHECK((*(uint256 *)r) == 0);
}

int CFirmKey::secp256k1_ec_seckey_verify(const unsigned char *seckey) {
    CPubKey::secp256k1_scalar sec;
    int overflow;
    //VERIFY_CHECK(ctx != nullptr);
    ARG_CHECK(seckey != nullptr);

    CPubKey::secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    int ret = !overflow && !CPubKey::secp256k1_scalar_is_zero(&sec);
    secp256k1_scalar_clear(&sec); // Note: should be used ::OPENSSL_Cleanse
    return ret;
}

bool CFirmKey::Check(const unsigned char *vch) {
    return secp256k1_ec_seckey_verify(vch);
}

void CFirmKey::MakeNewKey(bool fCompressedIn) {
    do {
        latest_crypto::random::GetStrongRandBytes(keydata_.data(), keydata_.size());
    } while (! Check(keydata_.data()));
    fValid_ = true;
    fCompressed_ = fCompressedIn;
}

bool CFirmKey::ecmult::secp256k1_gen_context::secp256k1_ecmult_gen_context_is_built(const CFirmKey::ecmult::secp256k1_gen_context &gen_ctx) {
    return gen_ctx.prec_ != nullptr;
}

int CFirmKey::secp256k1_ec_pubkey_create(CFirmKey::ecmult::secp256k1_gen_context &gen_ctx, CPubKey::secp256k1_pubkey *pubkey, const unsigned char *seckey) {
    CPubKey::secp256k1_scalar sec;
    //VERIFY_CHECK(ctx != nullptr);
    ARG_CHECK(pubkey != nullptr);
    std::memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(CFirmKey::ecmult::secp256k1_gen_context::secp256k1_ecmult_gen_context_is_built(gen_ctx));
    ARG_CHECK(seckey != nullptr);

    int overflow;
    CPubKey::secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    int ret = (!overflow) & (!CPubKey::secp256k1_scalar_is_zero(&sec));
    if (ret) {
        CPubKey::ecmult::secp256k1_gej pj;
        CPubKey::ecmult::secp256k1_ge p;
        ARG_CHECK(gen_ctx.secp256k1_ecmult_gen(&pj, &sec));
        CPubKey::ecmult::secp256k1_ge_set_gej(&p, &pj);
        CPubKey::secp256k1_pubkey_save(pubkey, &p);
    }
    CFirmKey::secp256k1_scalar_clear(&sec);
    return ret;
}

/**
 * This serializes to a DER encoding of the ECPrivateKey type from section C.4 of SEC 1
 * <http://www.secg.org/sec1-v2.pdf>. The optional parameters and publicKey fields are
 * included.
 *
 * privkey must point to an output buffer of length at least CFirmKey::PRIVATE_KEY_SIZE bytes.
 * privkeylen must initially be set to the size of the privkey buffer. Upon return it
 * will be set to the number of bytes used in the buffer.
 * key32 must point to a 32-byte raw private key.
 */
int CFirmKey::ec_privkey_export_der(CFirmKey::ecmult::secp256k1_gen_context &gen_ctx, unsigned char *privkey, size_t *privkeylen, const unsigned char *key32, bool compressed) {
    ARG_CHECK(*privkeylen >= CFirmKey::PRIVATE_KEY_SIZE);
    CPubKey::secp256k1_pubkey pubkey;
    size_t pubkeylen = 0;
    if (! CFirmKey::secp256k1_ec_pubkey_create(gen_ctx, &pubkey, key32)) {
        *privkeylen = 0;
        return 0;
    }

    if (compressed) {
        static constexpr unsigned char begin[] = {
            0x30,0x81,0xD3,0x02,0x01,0x01,0x04,0x20
        };
        static constexpr unsigned char middle[] = {
            0xA0,0x81,0x85,0x30,0x81,0x82,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x21,0x02,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x24,0x03,0x22,0x00
        };
        unsigned char *ptr = privkey;
        std::memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        std::memcpy(ptr, key32, 32); ptr += 32;
        std::memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = CPubKey::COMPRESSED_PUBLIC_KEY_SIZE;
        unsigned char ser_pubkey[CPubKey::PUBLIC_KEY_SIZE];
        ARG_CHECK(CPubKey::secp256k1_ec_pubkey_serialize(ser_pubkey, &pubkeylen, &pubkey, CPubKey::SECP256K1_EC_COMPRESSED));
        std::memcpy(ptr, ser_pubkey, pubkeylen);
        cleanse::OPENSSL_cleanse(ser_pubkey, sizeof(ser_pubkey));
        ptr += pubkeylen;
        *privkeylen = ptr - privkey;
        ARG_CHECK(*privkeylen == CFirmKey::COMPRESSED_PRIVATE_KEY_SIZE);
    } else {
        static constexpr unsigned char begin[] = {
            0x30,0x82,0x01,0x13,0x02,0x01,0x01,0x04,0x20
        };
        static constexpr unsigned char middle[] = {
            0xA0,0x81,0xA5,0x30,0x81,0xA2,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x41,0x04,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,
            0x08,0xA8,0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,
            0xD4,0xB8,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x44,0x03,0x42,0x00
        };
        unsigned char *ptr = privkey;
        std::memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        std::memcpy(ptr, key32, 32); ptr += 32;
        std::memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = CPubKey::PUBLIC_KEY_SIZE;
        unsigned char ser_pubkey[CPubKey::PUBLIC_KEY_SIZE];
        ARG_CHECK(CPubKey::secp256k1_ec_pubkey_serialize(ser_pubkey, &pubkeylen, &pubkey, CPubKey::SECP256K1_EC_UNCOMPRESSED));
        std::memcpy(ptr, ser_pubkey, pubkeylen);
        cleanse::OPENSSL_cleanse(ser_pubkey, sizeof(ser_pubkey));
        ptr += pubkeylen;
        *privkeylen = ptr - privkey;
        ARG_CHECK(*privkeylen == CFirmKey::PRIVATE_KEY_SIZE);
    }
    return 1;
}

CPrivKey CFirmKey::GetPrivKey() const {
    assert(fValid_);
    CPrivKey privkey;
    size_t privkeylen;
    privkey.resize(PRIVATE_KEY_SIZE);
    privkeylen = PRIVATE_KEY_SIZE;
    CFirmKey::ecmult::secp256k1_gen_context gen_ctx;
    if(! gen_ctx.build()) {
        throw key_error("CFirmKey::GetPrivKey() : gen_ctx failed");
    }
    if(! ec_privkey_export_der(gen_ctx, privkey.data(), &privkeylen, begin(), fCompressed_)) {
        throw key_error("CFirmKey::GetPrivKey() : ec_privkey_export_der failed");
    }

    privkey.resize(privkeylen);
    return privkey;
}

CPubKey CFirmKey::GetPubKey() const {
    assert(fValid_);
    CPubKey::secp256k1_pubkey pubkey;
    size_t clen = CPubKey::PUBLIC_KEY_SIZE;
    CPubKey result;
    CFirmKey::ecmult::secp256k1_gen_context gen_ctx;
    if(! gen_ctx.build()) {
        throw key_error("CFirmKey::GetPubKey() : gen_ctx build failed");
    }

    int ret = CFirmKey::secp256k1_ec_pubkey_create(gen_ctx, &pubkey, begin());
    if(! ret) {
        throw key_error("CFirmKey::GetPubKey() : secp256k1_ec_pubkey_create failed");
    }

    unsigned char ser_pubkey[CPubKey::PUBLIC_KEY_SIZE];
    if(! CPubKey::secp256k1_ec_pubkey_serialize(ser_pubkey, &clen, &pubkey, fCompressed_ ? CPubKey::SECP256K1_EC_COMPRESSED : CPubKey::SECP256K1_EC_UNCOMPRESSED)) {
        throw key_error("CFirmKey::GetPubKey() : secp256k1_ec_pubkey_serialize failed");
    }

    result.Set(&ser_pubkey[0], &ser_pubkey[0] + clen);
    if(result.size() != clen) {
        throw key_error("CFirmKey::GetPubKey() : publickey size failed");
    }
    if(! result.IsFullyValid_BIP66()) {
        throw key_error("CFirmKey::GetPubKey() : publickey valid failed");
    }

    return result;
}

XOnlyPubKey CFirmKey::GetXOnlyPubKey() const {
    CPubKey pubkey = GetPubKey();
    pubkey.Compress();
    return XOnlyPubKey(Span<const unsigned char>(pubkey.data() + 1, 32));
}

CSecret CFirmKey::GetSecret(bool &fCompressed) const {
    CSecret ret(keydata_.begin(), keydata_.end());
    fCompressed = fCompressed_;
    return ret;
}

int CFirmKey::nonce::nonce_function_rfc6979(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
   unsigned char keydata[112];
   int keylen = 64;
   CFirmKey::hash::secp256k1_rfc6979_hmac_sha256_t rng;
   /* We feed a byte array to the PRNG as input, consisting of:
    * - the private key (32 bytes) and message (32 bytes), see RFC 6979 3.2d.
    * - optionally 32 extra bytes of data, see RFC 6979 3.6 Additional Data.
    * - optionally 16 extra bytes with the algorithm name.
    * Because the arguments have distinct fixed lengths it is not possible for
    *  different argument mixtures to emulate each other and result in the same
    *  nonces.
    */
   std::memcpy(keydata, key32, 32);
   std::memcpy(keydata + 32, msg32, 32);
   if (data != nullptr) {
       std::memcpy(keydata + 64, data, 32);
       keylen = 96;
   }
   if (algo16 != nullptr) {
       std::memcpy(keydata + keylen, algo16, 16);
       keylen += 16;
   }
   CFirmKey::hash::secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, keylen);
   std::memset(keydata, 0, sizeof(keydata));
   for (unsigned int i = 0; i <= counter; ++i) {
       CFirmKey::hash::secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
   }
   CFirmKey::hash::secp256k1_rfc6979_hmac_sha256_finalize(&rng);
   return 1;
}

int CFirmKey::secp256k1_ecdsa_sig_sign(const CFirmKey::ecmult::secp256k1_gen_context *gen_ctx, CPubKey::secp256k1_scalar *sigr, CPubKey::secp256k1_scalar *sigs, const CPubKey::secp256k1_scalar *seckey, const CPubKey::secp256k1_scalar *message, const CPubKey::secp256k1_scalar *nonce, int *recid) {
    unsigned char b[32];
    CPubKey::ecmult::secp256k1_gej rp;
    CPubKey::ecmult::secp256k1_ge r;
    CPubKey::secp256k1_scalar n;
    int overflow = 0;

    gen_ctx->secp256k1_ecmult_gen(&rp, nonce);
    CPubKey::ecmult::secp256k1_ge_set_gej(&r, &rp);
    CPubKey::ecmult::secp256k1_fe_normalize(&r.x);
    CPubKey::ecmult::secp256k1_fe_normalize(&r.y);
    CPubKey::ecmult::secp256k1_fe_get_b32(b, &r.x);
    CPubKey::secp256k1_scalar_set_b32(sigr, b, &overflow);
    /* These two conditions should be checked before calling */
    ARG_CHECK(!CPubKey::secp256k1_scalar_is_zero(sigr));
    ARG_CHECK(overflow == 0);

    if (recid) {
        /* The overflow condition is cryptographically unreachable as hitting it requires finding the discrete log
         * of some P where P.x >= order, and only 1 in about 2^127 points meet this criteria.
         */
        *recid = (overflow ? 2 : 0) | (CPubKey::ecmult::secp256k1_fe_is_odd(&r.y) ? 1 : 0);
    }
    CPubKey::secp256k1_scalar_mul(&n, sigr, seckey);
    CPubKey::secp256k1_scalar_add(&n, &n, message);
    CPubKey::secp256k1_scalar_inverse(sigs, nonce);
    CPubKey::secp256k1_scalar_mul(sigs, sigs, &n);
    CFirmKey::secp256k1_scalar_clear(&n);
    CFirmKey::ecmult::secp256k1_gej_clear(&rp);
    CPubKey::ecmult::secp256k1_ge_clear(&r);
    if (CPubKey::secp256k1_scalar_is_zero(sigs)) {
        return 0;
    }
    if (CPubKey::secp256k1_scalar_is_high(sigs)) {
        CPubKey::secp256k1_scalar_negate(sigs, sigs);
        if (recid) {
            *recid ^= 1;
        }
    }
    return 1;
}

int CFirmKey::secp256k1_ecdsa_sign(const CFirmKey::ecmult::secp256k1_gen_context *gen_ctx, CPubKey::secp256k1_signature *signature, const unsigned char *msg32, const unsigned char *seckey, CFirmKey::secp256k1_nonce_function noncefp, const void *noncedata) {
    CPubKey::secp256k1_scalar r, s;
    CPubKey::secp256k1_scalar sec, non, msg;
    int ret = 0;
    ARG_CHECK(gen_ctx != nullptr);
    ARG_CHECK(CFirmKey::ecmult::secp256k1_gen_context::secp256k1_ecmult_gen_context_is_built(*gen_ctx));
    ARG_CHECK(msg32 != nullptr);
    ARG_CHECK(signature != nullptr);
    ARG_CHECK(seckey != nullptr);
    if (noncefp == nullptr) {
        noncefp = CFirmKey::nonce::nonce_function_rfc6979;
    }

    int overflow = 0;
    CPubKey::secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (!overflow && !CPubKey::secp256k1_scalar_is_zero(&sec)) {
        unsigned char nonce32[32];
        unsigned int count = 0;
        CPubKey::secp256k1_scalar_set_b32(&msg, msg32, nullptr);
        for(;;) {
            ret = noncefp(nonce32, msg32, seckey, nullptr, (void *)noncedata, count);
            if (! ret)
                break;
            CPubKey::secp256k1_scalar_set_b32(&non, nonce32, &overflow);
            if (!overflow && !CPubKey::secp256k1_scalar_is_zero(&non)) {
                CFirmKey::ecmult::secp256k1_gen_context gen_ctx;
                ARG_CHECK(gen_ctx.build());
                if (CFirmKey::secp256k1_ecdsa_sig_sign(&gen_ctx, &r, &s, &sec, &msg, &non, nullptr)) {
                    break;
                }
            }
            ++count;
        }
        std::memset(nonce32, 0, 32);
        CFirmKey::secp256k1_scalar_clear(&msg);
        CFirmKey::secp256k1_scalar_clear(&non);
        CFirmKey::secp256k1_scalar_clear(&sec);
    }
    if (ret) {
        CPubKey::secp256k1_ecdsa_signature_save(signature, &r, &s);
    } else {
        std::memset(signature, 0, sizeof(*signature));
    }
    return ret;
}

int CFirmKey::secp256k1_ecdsa_signature_serialize_compact(unsigned char *output64, const CPubKey::secp256k1_signature *sig) {
    CPubKey::secp256k1_scalar r, s;

    //VERIFY_CHECK(ctx != nullptr);
    ARG_CHECK(output64 != nullptr);
    ARG_CHECK(sig != nullptr);

    CPubKey::secp256k1_ecdsa_signature_load(&r, &s, sig);
    CPubKey::secp256k1_scalar_get_b32(&output64[0], &r);
    CPubKey::secp256k1_scalar_get_b32(&output64[32], &s);
    return 1;
}

// Check that the sig has a low R value and will be less than 71 bytes
bool CFirmKey::SigHasLowR(const CPubKey::secp256k1_signature *sig) {
    unsigned char compact_sig[64];
    CFirmKey::secp256k1_ecdsa_signature_serialize_compact(compact_sig, sig);

    // In DER serialization, all values are interpreted as big-endian, signed integers. The highest bit in the integer indicates
    // its signed-ness; 0 is positive, 1 is negative. When the value is interpreted as a negative integer, it must be converted
    // to a positive value by prepending a 0x00 byte so that the highest bit is 0. We can avoid this prepending by ensuring that
    // our highest bit is always 0, and thus we must check that the first byte is less than 0x80.
    return compact_sig[0] < 0x80;
}

int CFirmKey::secp256k1_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const CPubKey::secp256k1_scalar *ar, const CPubKey::secp256k1_scalar *as) {
    unsigned char r[33] = {0}, s[33] = {0};
    unsigned char *rp = r, *sp = s;
    size_t lenR = 33, lenS = 33;
    CPubKey::secp256k1_scalar_get_b32(&r[1], ar);
    CPubKey::secp256k1_scalar_get_b32(&s[1], as);
    while (lenR > 1 && rp[0] == 0 && rp[1] < 0x80) { lenR--; rp++; }
    while (lenS > 1 && sp[0] == 0 && sp[1] < 0x80) { lenS--; sp++; }
    if (*size < 6+lenS+lenR) {
        *size = 6 + lenS + lenR;
        return 0;
    }
    *size = 6 + lenS + lenR;
    sig[0] = 0x30;
    sig[1] = 4 + lenS + lenR;
    sig[2] = 0x02;
    sig[3] = lenR;
    std::memcpy(sig+4, rp, lenR);
    sig[4+lenR] = 0x02;
    sig[5+lenR] = lenS;
    std::memcpy(sig+lenR+6, sp, lenS);
    return 1;
}

int CFirmKey::secp256k1_ecdsa_signature_serialize_der(unsigned char *output, size_t *outputlen, const CPubKey::secp256k1_signature *sig) {
    CPubKey::secp256k1_scalar r, s;

    //VERIFY_CHECK(ctx != nullptr);
    ARG_CHECK(output != nullptr);
    ARG_CHECK(outputlen != nullptr);
    ARG_CHECK(sig != nullptr);

    CPubKey::secp256k1_ecdsa_signature_load(&r, &s, sig);
    return CFirmKey::secp256k1_ecdsa_sig_serialize(output, outputlen, &r, &s);
}

bool CFirmKey::Sign(const uint256 &hash, key_vector &vchSig, bool grind, uint32_t test_case) const {
    ARG_BOOL_CHECK(fValid_);
    vchSig.resize(CPubKey::SIGNATURE_SIZE);
    size_t nSigLen = CPubKey::SIGNATURE_SIZE;
    unsigned char extra_entropy[32] = {0};
    latest_crypto::WriteLE32(extra_entropy, test_case);
    CPubKey::secp256k1_signature sig;
    uint32_t counter = 0;
    CFirmKey::ecmult::secp256k1_gen_context gen_ctx;
    ARG_BOOL_CHECK(gen_ctx.build());
    int ret = CFirmKey::secp256k1_ecdsa_sign(&gen_ctx, &sig, hash.begin(), begin(), CFirmKey::nonce::nonce_function_rfc6979, (!grind && test_case) ? extra_entropy : nullptr);

    // Grind for low R
    while (ret && !SigHasLowR(&sig) && grind) {
        latest_crypto::WriteLE32(extra_entropy, ++counter);
        ret = CFirmKey::secp256k1_ecdsa_sign(&gen_ctx, &sig, hash.begin(), begin(), CFirmKey::nonce::nonce_function_rfc6979, extra_entropy);
    }
    ARG_BOOL_CHECK(ret);
    ARG_BOOL_CHECK(CFirmKey::secp256k1_ecdsa_signature_serialize_der(vchSig.data(), &nSigLen, &sig));
    vchSig.resize(nSigLen);
    return true;
}

int CFirmKey::secp256k1_ecdsa_sign_recoverable(const CFirmKey::ecmult::secp256k1_gen_context *gen_ctx, CPubKey::secp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void *noncedata) {
    CPubKey::secp256k1_scalar r, s;
    CPubKey::secp256k1_scalar sec, non, msg;
    int recid;
    int ret = 0;
    int overflow = 0;
    //VERIFY_CHECK(ctx != nullptr);
    ARG_CHECK(CFirmKey::ecmult::secp256k1_gen_context::secp256k1_ecmult_gen_context_is_built(*gen_ctx));
    ARG_CHECK(msg32 != nullptr);
    ARG_CHECK(signature != nullptr);
    ARG_CHECK(seckey != nullptr);
    if (noncefp == nullptr) {
        noncefp = CFirmKey::nonce::nonce_function_rfc6979;
    }

    CPubKey::secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (!overflow && !CPubKey::secp256k1_scalar_is_zero(&sec)) {
        unsigned char nonce32[32];
        unsigned int count = 0;
        CPubKey::secp256k1_scalar_set_b32(&msg, msg32, nullptr);
        for(;;) {
            ret = noncefp(nonce32, msg32, seckey, NULL, (void*)noncedata, count);
            if (! ret) {
                break;
            }
            CPubKey::secp256k1_scalar_set_b32(&non, nonce32, &overflow);
            if (!CPubKey::secp256k1_scalar_is_zero(&non) && !overflow) {
                if (CFirmKey::secp256k1_ecdsa_sig_sign(gen_ctx, &r, &s, &sec, &msg, &non, &recid)) {
                    break;
                }
            }
            ++count;
        }
        std::memset(nonce32, 0, 32);
        CFirmKey::secp256k1_scalar_clear(&msg);
        CFirmKey::secp256k1_scalar_clear(&non);
        CFirmKey::secp256k1_scalar_clear(&sec);
    }
    if (ret) {
        CPubKey::secp256k1_ecdsa_recoverable_signature_save(signature, &r, &s, recid);
    } else {
        std::memset(signature, 0, sizeof(*signature));
    }
    return ret;
}

int CFirmKey::secp256k1_ecdsa_recoverable_signature_serialize_compact(unsigned char *output64, int *recid, const CPubKey::secp256k1_ecdsa_recoverable_signature *sig) {
    CPubKey::secp256k1_scalar r, s;

    ARG_CHECK(output64 != nullptr);
    ARG_CHECK(sig != nullptr);
    ARG_CHECK(recid != nullptr);

    CPubKey::secp256k1_ecdsa_recoverable_signature_load(&r, &s, recid, sig);
    CPubKey::secp256k1_scalar_get_b32(&output64[0], &r);
    CPubKey::secp256k1_scalar_get_b32(&output64[32], &s);
    return 1;
}

bool CFirmKey::SignCompact(const uint256 &hash, key_vector &vchSig) const {
    ARG_BOOL_CHECK(fValid_);
    vchSig.resize(CPubKey::COMPACT_SIGNATURE_SIZE);
    int rec = -1;
    CPubKey::secp256k1_ecdsa_recoverable_signature sig;
    CFirmKey::ecmult::secp256k1_gen_context gen_ctx;
    ARG_BOOL_CHECK(gen_ctx.build());
    int ret = secp256k1_ecdsa_sign_recoverable(&gen_ctx, &sig, hash.begin(), begin(), CFirmKey::nonce::nonce_function_rfc6979, nullptr);
    ARG_BOOL_CHECK(ret);
    ret = CFirmKey::secp256k1_ecdsa_recoverable_signature_serialize_compact(&vchSig[1], &rec, &sig);
    ARG_BOOL_CHECK(ret);
    ARG_BOOL_CHECK(rec != -1);
    vchSig[0] = 27 + rec + (fCompressed_ ? 4 : 0);
    return true;
}

int CFirmKey::secp256k1_eckey_privkey_tweak_add(CPubKey::secp256k1_scalar *key, const CPubKey::secp256k1_scalar *tweak) {
    CPubKey::secp256k1_scalar_add(key, key, tweak);
    return CPubKey::secp256k1_scalar_is_zero(key)? 0: 1;
}

int CFirmKey::secp256k1_ec_privkey_tweak_add(unsigned char *seckey, const unsigned char *tweak) {
    CPubKey::secp256k1_scalar term;
    CPubKey::secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    //VERIFY_CHECK(ctx != nullptr);
    ARG_CHECK(seckey != nullptr);
    ARG_CHECK(tweak != nullptr);

    CPubKey::secp256k1_scalar_set_b32(&term, tweak, &overflow);
    CPubKey::secp256k1_scalar_set_b32(&sec, seckey, nullptr);

    ret = !overflow && CFirmKey::secp256k1_eckey_privkey_tweak_add(&sec, &term);
    std::memset(seckey, 0, 32);
    if (ret)
        CPubKey::secp256k1_scalar_get_b32(seckey, &sec);

    CFirmKey::secp256k1_scalar_clear(&sec);
    CFirmKey::secp256k1_scalar_clear(&term);
    return ret;
}

bool CFirmKey::Derive(CFirmKey &keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode &cc) const {
    ARG_BOOL_CHECK(IsValid());
    ARG_BOOL_CHECK(IsCompressed());
    std::vector<unsigned char, secure_allocator<unsigned char> > vout(64);
    if ((nChild >> 31) == 0) {
        CPubKey pubkey = GetPubKey();
        ARG_BOOL_CHECK(pubkey.size() == CPubKey::COMPRESSED_PUBLIC_KEY_SIZE);
        bip32::BIP32Hash(cc, nChild, *pubkey.begin(), pubkey.begin()+1, vout.data());
    } else {
        ARG_BOOL_CHECK(size() == 32);
        bip32::BIP32Hash(cc, nChild, 0, begin(), vout.data());
    }
    std::memcpy(ccChild.begin(), vout.data()+32, 32);
    std::memcpy((unsigned char *)keyChild.begin(), begin(), 32);
    bool ret = secp256k1_ec_privkey_tweak_add((unsigned char *)keyChild.begin(), vout.data());
    keyChild.fCompressed_ = true;
    keyChild.fValid_ = ret;
    return ret;
}

bool CFirmKey::VerifyPubKey(const CPubKey &pubkey) const {
    if (pubkey.IsCompressed() != fCompressed_)
        return false;
    unsigned char rnd[8];
    std::string str = "Bitcoin key verification\n";
    latest_crypto::random::GetRandBytes(rnd, sizeof(rnd));
    uint256 hash;
    latest_crypto::CHash256().Write((unsigned char *)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash.begin());
    key_vector vchSig;
    Sign(hash, vchSig);
    bool ret = pubkey.Verify_BIP66(hash, vchSig);
    cleanse::OPENSSL_cleanse(rnd, sizeof(rnd));
    cleanse::OPENSSL_cleanse(&hash, sizeof(uint256));
    cleanse::OPENSSL_cleanse(vchSig.data(), vchSig.size() * sizeof(unsigned char));
    return ret;
}

/**
 * This parses a format loosely based on a DER encoding of the ECPrivateKey type from
 * section C.4 of SEC 1 <http://www.secg.org/sec1-v2.pdf>, with the following caveats:
 *
 * * The octet-length of the SEQUENCE must be encoded as 1 or 2 octets. It is not
 *   required to be encoded as one octet if it is less than 256, as DER would require.
 * * The octet-length of the SEQUENCE must not be greater than the remaining
 *   length of the key encoding, but need not match it (i.e. the encoding may contain
 *   junk after the encoded SEQUENCE).
 * * The privateKey OCTET STRING is zero-filled on the left to 32 octets.
 * * Anything after the encoding of the privateKey OCTET STRING is ignored, whether
 *   or not it is validly encoded DER.
 *
 * out32 must point to an output buffer of length at least 32 bytes.
 */
int CFirmKey::ec_privkey_import_der(unsigned char *out32, const unsigned char *privkey, size_t privkeylen) {
    const unsigned char *end = privkey + privkeylen;
    std::memset(out32, 0, 32);
    /* sequence header */
    if (end - privkey < 1 || *privkey != 0x30u) {
        return 0;
    }
    privkey++;
    /* sequence length constructor */
    if (end - privkey < 1 || !(*privkey & 0x80u)) {
        return 0;
    }
    ptrdiff_t lenb = *privkey & ~0x80u; privkey++;
    if (lenb < 1 || lenb > 2) {
        return 0;
    }
    if (end - privkey < lenb) {
        return 0;
    }
    /* sequence length */
    ptrdiff_t len = privkey[lenb-1] | (lenb > 1 ? privkey[lenb-2] << 8 : 0u);
    privkey += lenb;
    if (end - privkey < len) {
        return 0;
    }
    /* sequence element 0: version number (=1) */
    if (end - privkey < 3 || privkey[0] != 0x02u || privkey[1] != 0x01u || privkey[2] != 0x01u) {
        return 0;
    }
    privkey += 3;
    /* sequence element 1: octet string, up to 32 bytes */
    if (end - privkey < 2 || privkey[0] != 0x04u) {
        return 0;
    }
    ptrdiff_t oslen = privkey[1];
    privkey += 2;
    if (oslen > 32 || end - privkey < oslen) {
        return 0;
    }
    std::memcpy(out32 + (32 - oslen), privkey, oslen);
    if (! secp256k1_ec_seckey_verify(out32)) {
        std::memset(out32, 0, 32);
        return 0;
    }
    return 1;
}

bool CFirmKey::Load(const CPrivKey &privkey, const CPubKey &vchPubKey, bool fSkipCheck=false) {
    if (! ec_privkey_import_der((unsigned char *)begin(), privkey.data(), privkey.size()))
        return false;
    fCompressed_ = vchPubKey.IsCompressed();
    fValid_ = true;
    if (fSkipCheck)
        return true;

    return VerifyPubKey(vchPubKey);
}

bool CFirmKey::SetPrivKey(const CPrivKey &privkey) {
    if(!(privkey.size() == CFirmKey::COMPRESSED_PRIVATE_KEY_SIZE || privkey.size() == CFirmKey::PRIVATE_KEY_SIZE))
        return false;
    if (ec_privkey_import_der((unsigned char *)begin(), privkey.data(), privkey.size()) == 0)
        return false;
    fCompressed_ = privkey.size() == CFirmKey::COMPRESSED_PRIVATE_KEY_SIZE ? true: false;
    if(fCompressed_) {
        key_vector pubvch;
        pubvch.resize(CPubKey::COMPRESSED_PUBLIC_KEY_SIZE);
        ::memcpy(&pubvch.front(), privkey.data() + 181, CPubKey::COMPRESSED_PUBLIC_KEY_SIZE);
        fValid_ = true;
        CPubKey pubkey;
        pubkey.Set(pubvch);
        debugcs::instance() << strenc::HexStr(pubkey.GetPubVch()) << debugcs::endl();
        debugcs::instance() << strenc::HexStr(this->GetPubKey().GetPubVch()) << debugcs::endl();
        if(!VerifyPubKey(pubkey)) {
            fValid_ = false;
            return false;
        }
    } else {
        key_vector pubvch;
        pubvch.resize(CPubKey::PUBLIC_KEY_SIZE);
        ::memcpy(&pubvch.front(), privkey.data() + 214, CPubKey::PUBLIC_KEY_SIZE);
        fValid_ = true;
        CPubKey pubkey;
        pubkey.Set(pubvch);
        debugcs::instance() << strenc::HexStr(pubkey.GetPubVch()) << debugcs::endl();
        debugcs::instance() << strenc::HexStr(this->GetPubKey().GetPubVch()) << debugcs::endl();
        if(!VerifyPubKey(pubkey)) {
            fValid_ = false;
            return false;
        }
    }

    return true;
}

bool CFirmKey::WritePEM(const std::string &fileName, const SecureString &strPassKey) const {
    CSecret secret = GetSecret();
    CKey key;
    key.SetSecret(secret, IsCompressed());

    BIO *pemOut = BIO_new_file(fileName.c_str(), "w");
    if (pemOut == nullptr) {
        return logging::error("GetPEM() : failed to create file %s\n", fileName.c_str());
    }
    bool ret = key.WritePEM(pemOut, strPassKey);
    BIO_free(pemOut);
    return ret;
}

void CFirmKey::DecryptData(const key_vector &encrypted, key_vector &data) const {
    CSecret secret = GetSecret();
    CKey key;
    key.SetSecret(secret, IsCompressed());
    key.DecryptData(encrypted, data);
}

/////////////////////////////////////////////////////////////////////////////////
// BIP340
/////////////////////////////////////////////////////////////////////////////////

namespace bip340_tagged {
    /* Initializes a sha256 struct and writes the 64 byte string
     * SHA256(tag)||SHA256(tag) into it. */
    void secp256k1_sha256_initialize_tagged(CFirmKey::hash::secp256k1_sha256* hash, const unsigned char* tag, size_t taglen)
    {
        unsigned char buf[32];
        CFirmKey::hash::secp256k1_sha256_initialize(hash);
        CFirmKey::hash::secp256k1_sha256_write(hash, tag, taglen);
        CFirmKey::hash::secp256k1_sha256_finalize(hash, buf);

        CFirmKey::hash::secp256k1_sha256_initialize(hash);
        CFirmKey::hash::secp256k1_sha256_write(hash, buf, 32);
        CFirmKey::hash::secp256k1_sha256_write(hash, buf, 32);
    }

    /* Initializes SHA256 with fixed midstate. This midstate was computed by applying
     * SHA256 to SHA256("BIP0340/nonce")||SHA256("BIP0340/nonce"). */
    void secp256k1_nonce_function_bip340_sha256_tagged(CFirmKey::hash::secp256k1_sha256* sha)
    {
        uint32_t d[8];
        d[0] = 0x46615b35ul;
        d[1] = 0xf4bfbff7ul;
        d[2] = 0x9f8dc671ul;
        d[3] = 0x83627ab3ul;
        d[4] = 0x60217180ul;
        d[5] = 0x57358661ul;
        d[6] = 0x21a29e54ul;
        d[7] = 0x68b07b4cul;

        CFirmKey::hash::secp256k1_sha256_initialize(sha);
        sha->InitSet(d, 64);
    }

    /* Initializes SHA256 with fixed midstate. This midstate was computed by applying
     * SHA256 to SHA256("BIP0340/aux")||SHA256("BIP0340/aux"). */
    void secp256k1_nonce_function_bip340_sha256_tagged_aux(CFirmKey::hash::secp256k1_sha256* sha)
    {
        uint32_t d[8];
        d[0] = 0x24dd3219ul;
        d[1] = 0x4eba7e70ul;
        d[2] = 0xca0fabb9ul;
        d[3] = 0x0fa3166dul;
        d[4] = 0x3afbe4b1ul;
        d[5] = 0x4c44df97ul;
        d[6] = 0x4aac2739ul;
        d[7] = 0x249e850aul;

        CFirmKey::hash::secp256k1_sha256_initialize(sha);
        sha->InitSet(d, 64);
    }

    /* algo16 argument for nonce_function_bip340 to derive the nonce exactly as stated in BIP-340
     * by using the correct tagged hash function. */
    static const unsigned char bip340_algo16[16] = {'B','I','P','0','3','4','0','/','n','o','n','c','e','\0','\0','\0'};

    int nonce_function_bip340(unsigned char* nonce32, const unsigned char* msg32, const unsigned char* key32, const unsigned char* xonly_pk32, const unsigned char* algo16, void* data)
    {
        CFirmKey::hash::secp256k1_sha256 sha;
        unsigned char masked_key[32];
        int i;

        if (algo16 == NULL) {
            return 0;
        }

        if (data != NULL) {
            secp256k1_nonce_function_bip340_sha256_tagged_aux(&sha);
            CFirmKey::hash::secp256k1_sha256_write(&sha, (const unsigned char *)data, 32);
            CFirmKey::hash::secp256k1_sha256_finalize(&sha, masked_key);
            for (i = 0; i < 32; i++) {
                masked_key[i] ^= key32[i];
            }
        }

        /* Tag the hash with algo16 which is important to avoid nonce reuse across
         * algorithms. If this nonce function is used in BIP-340 signing as defined
         * in the spec, an optimized tagging implementation is used. */
        if (secp256k1_util::secp256k1_memcmp_var(algo16, bip340_algo16, 16) == 0) {
            secp256k1_nonce_function_bip340_sha256_tagged(&sha);
        } else {
            int algo16_len = 16;
            /* Remove terminating null bytes */
            while (algo16_len > 0 && !algo16[algo16_len - 1]) {
                algo16_len--;
            }
            secp256k1_sha256_initialize_tagged(&sha, algo16, algo16_len);
        }

        /* Hash (masked-)key||pk||msg using the tagged hash as per the spec */
        if (data != NULL) {
            CFirmKey::hash::secp256k1_sha256_write(&sha, masked_key, 32);
        } else {
            CFirmKey::hash::secp256k1_sha256_write(&sha, key32, 32);
        }
        CFirmKey::hash::secp256k1_sha256_write(&sha, xonly_pk32, 32);
        CFirmKey::hash::secp256k1_sha256_write(&sha, msg32, 32);
        CFirmKey::hash::secp256k1_sha256_finalize(&sha, nonce32);
        return 1;
    }
} // namespace bip340_tagged

/** Schnorr Signature Aggregation (priv aggregation, nonce randomness)
 */
int XOnlyKeys::secp256k1_schnorrsig_aggregation(Span<const CSecret> secrets, CSecret *agg_secret)
{
    if(secrets.size() == 0 || agg_secret == NULL)
        return 0;

    // CSecret
    {
        CPubKey::secp256k1_scalar ret;
        CPubKey::secp256k1_scalar_set_int(&ret, 0);
        CPubKey::secp256k1_scalar tmp;
        for(const auto &d: secrets) {
            int overflow;
            CPubKey::secp256k1_scalar_set_b32(&tmp, d.data(), &overflow);
            if(overflow) {
                cleanse::memory_cleanse(&ret, sizeof(ret));
                cleanse::memory_cleanse(&tmp, sizeof(tmp));
                return 0;
            }
            CPubKey::secp256k1_scalar_add(&ret, &ret, &tmp);
            if(CPubKey::secp256k1_scalar_is_zero(&ret)) {
                cleanse::memory_cleanse(&ret, sizeof(ret));
                cleanse::memory_cleanse(&tmp, sizeof(tmp));
                return 0;
            }
        }
        cleanse::memory_cleanse(&tmp, sizeof(tmp));
        agg_secret->resize(32);
        unsigned char *buf = &agg_secret->front();
        CPubKey::secp256k1_scalar_get_b32(buf, &ret);
        cleanse::memory_cleanse(&ret, sizeof(ret));
    }

    return 1;
}

/** Create a Schnorr signature.
 *
 * Returns 1 on success, 0 on failure.
 *  Args:    ctx: pointer to the secp256k1_gen_ctx (can be NULL)
 *  Out:     sig: pointer to the returned signature (cannot be NULL)
 *       nonce_is_negated: a pointer to an integer indicates if signing algorithm negated the
 *                nonce (can be NULL)
 *  In:    msg32: the 32-byte message hash being signed (cannot be NULL)
 *        seckey: pointer to a 32-byte secret key (cannot be NULL)
 *       noncefp: pointer to a nonce generation function. If NULL, secp256k1_nonce_and_random_function_schnorr is used
 *         ndata: pointer to arbitrary data used by the nonce generation function (can be NULL)
 */
int XOnlyKey::secp256k1_schnorrsig_sign(CFirmKey::ecmult::secp256k1_gen_context *ctx, secp256k1_schnorrsig *sig, int *nonce_is_negated, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, void *ndata)
{
    ARG_CHECK(sig != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(seckey != NULL);

    // get secret key (from seckey to x)
    CPubKey::secp256k1_scalar x;
    int overflow;
    CPubKey::secp256k1_scalar_set_b32(&x, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (overflow || CPubKey::secp256k1_scalar_is_zero(&x)) {
        cleanse::memory_cleanse(sig->data, sizeof(sig->data));
        cleanse::memory_cleanse(&x, sizeof(x));
        return 0;
    }

    // get public key (pubkey = x * G)
    CPubKey::ecmult::secp256k1_gej pkj;
    CPubKey::ecmult::secp256k1_ge pk;
    CFirmKey::ecmult::secp256k1_gen_context ctxobj;
    if(ctx == NULL) {
        ctx = &ctxobj;
        if(!ctx->build()) {
            cleanse::memory_cleanse(sig->data, sizeof(sig->data));
            cleanse::memory_cleanse(&x, sizeof(x));
            return 0;
        }
    }
    if(!ctx->secp256k1_ecmult_gen(&pkj, &x)) {
        cleanse::memory_cleanse(sig->data, sizeof(sig->data));
        cleanse::memory_cleanse(&x, sizeof(x));
        return 0;
    }
    CPubKey::ecmult::secp256k1_ge_set_gej(&pk, &pkj);

    // get nonce k (random number for signature)
    unsigned char buf[32];
    if (noncefp == NULL)
        noncefp = schnorr_nonce::secp256k1_nonce_and_random_function_schnorr;
    if (!noncefp(buf, msg32, seckey, NULL, (void*)ndata, 0)) {
        cleanse::memory_cleanse(sig->data, sizeof(sig->data));
        cleanse::memory_cleanse(&x, sizeof(x));
        return 0;
    }
    CPubKey::secp256k1_scalar k;
    CPubKey::secp256k1_scalar_set_b32(&k, buf, NULL);
    if (CPubKey::secp256k1_scalar_is_zero(&k)) {
        cleanse::memory_cleanse(sig->data, sizeof(sig->data));
        cleanse::memory_cleanse(&x, sizeof(x));
        cleanse::memory_cleanse(&k, sizeof(k));
        return 0;
    }

    // get and check r = k*G (if r.y cannot get sqrt, compute negate k)
    CPubKey::secp256k1_scalar one;
    CPubKey::secp256k1_scalar_set_int(&one, 1);
    CPubKey::ecmult::secp256k1_ge r;
    do {
        CPubKey::ecmult::secp256k1_gej rj;
        if(!ctx->secp256k1_ecmult_gen(&rj, &k)) {
            cleanse::memory_cleanse(sig->data, sizeof(sig->data));
            cleanse::memory_cleanse(&x, sizeof(x));
            cleanse::memory_cleanse(&k, sizeof(k));
            return 0;
        }
        CPubKey::ecmult::secp256k1_ge_set_gej(&r, &rj);
        CPubKey::ecmult::secp256k1_fe_normalize_var(&r.y); // Check r.y is odd
        if(CPubKey::ecmult::secp256k1_fe_is_odd(&r.y)) {
            if(CPubKey::secp256k1_scalar_add(&k, &k, &one) == 1) { // if r.y is odd, k is added 1
                // Fail if k is overflow
                cleanse::memory_cleanse(sig->data, sizeof(sig->data));
                cleanse::memory_cleanse(&x, sizeof(x));
                cleanse::memory_cleanse(&k, sizeof(k));
                return 0;
            }
        } else {
            break;
        }
    } while(true);
    if (nonce_is_negated != NULL)
        *nonce_is_negated = 0;
    if (!CPubKey::ecmult::secp256k1_fe_is_quad_var(&r.y)) {
        CPubKey::secp256k1_scalar_negate(&k, &k);
        if (nonce_is_negated != NULL)
            *nonce_is_negated = 1;
    }

    // store signature [(r.x) | s]
    CPubKey::ecmult::secp256k1_fe_normalize(&r.x);
    CPubKey::ecmult::secp256k1_fe_get_b32(&sig->data[0], &r.x);

    /* Compute e. */
    CPubKey::secp256k1_scalar e;
    unsigned char pub_buf[CPubKey::COMPRESSED_PUBLIC_KEY_SIZE];
    size_t pub_buflen;
    CPubKey::secp256k1_eckey_pubkey_serialize(&pk, pub_buf, &pub_buflen, 1);
    if(pub_buflen != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE) {
        cleanse::memory_cleanse(sig->data, sizeof(sig->data));
        cleanse::memory_cleanse(&x, sizeof(x));
        cleanse::memory_cleanse(&k, sizeof(k));
        return 0;
    }
    schnorr_e_hash::secp256k1_schnorrsig_challenge(&e, &sig->data[0], msg32, pub_buf + 1);

    // generate s = k + e * privkey
    // if pub_y is even: s = k + e * privkey
    // if pub_y is odd: s = k + negate(e) * privkey
    CPubKey::secp256k1_scalar s;
    if (pub_buf[0] == CPubKey::SECP256K1_TAG_PUBKEY_ODD)
        CPubKey::secp256k1_scalar_negate(&e, &e);
    CPubKey::secp256k1_scalar_mul(&e, &e, &x);
    CPubKey::secp256k1_scalar_add(&s, &e, &k);

    // store signature [r.x | (s)]
    CPubKey::secp256k1_scalar_get_b32(&sig->data[32], &s);

    cleanse::memory_cleanse(&k, sizeof(k));
    cleanse::memory_cleanse(&x, sizeof(x));
    return 1;
}

bool XOnlyKey::SignSchnorr(const uint256 &msg, std::vector<unsigned char> &sigbytes) const {
    secp256k1_schnorrsig sig;
    bool fret = (secp256k1_schnorrsig_sign(NULL, &sig, NULL, msg.begin(), m_secret.data(), NULL, NULL) == 1) ? true: false;
    if(fret) {
        sigbytes.resize(64);
        XOnlyPubKey::secp256k1_schnorrsig_serialize(&sigbytes.front(), &sig);
        return true;
    } else {
        sigbytes.clear();
        return false;
    }
}

bool XOnlyKeys::SignSchnorr(const uint256 &msg, std::vector<unsigned char> &sigbytes) const {
    CSecret agg_secret;
    if(!aggregation(&agg_secret))
        return false;

    secp256k1_schnorrsig sig;
    bool fret = (XOnlyKey::secp256k1_schnorrsig_sign(NULL, &sig, NULL, msg.begin(), agg_secret.data(), NULL, NULL) == 1) ? true: false;
    if(fret) {
        sigbytes.resize(64);
        XOnlyPubKey::secp256k1_schnorrsig_serialize(&sigbytes.front(), &sig);
        return true;
    } else {
        sigbytes.clear();
        return false;
    }
}

/////////////////////////////////////////////////////////////////////////////////
// BIP32
/////////////////////////////////////////////////////////////////////////////////

bool CExtKey::Encode(unsigned char code[CExtKey::BIP32_EXTKEY_SIZE]) const  {
    if(! privkey_.IsValid())
        return false;

    code[0] = nDepth_;
    std::memcpy(code+1, vchFingerprint_, 4);
    code[5] = (nChild_ >> 24) & 0xFF; code[6] = (nChild_ >> 16) & 0xFF;
    code[7] = (nChild_ >>  8) & 0xFF; code[8] = (nChild_ >>  0) & 0xFF;
    std::memcpy(code+9, chaincode_.begin(), 32);
    code[41] = 0;
    assert(privkey_.size() == 32);
    std::memcpy(code+42, privkey_.begin(), 32);
    return true;
}

CExtSecret CExtKey::GetExtSecret() const {
    CPrivKey vch;
    vch.resize(CExtKey::BIP32_EXTKEY_SIZE);
    unsigned char *code = &vch.front();
    code[0] = nDepth_;
    std::memcpy(code+1, vchFingerprint_, 4);
    code[5] = (nChild_ >> 24) & 0xFF; code[6] = (nChild_ >> 16) & 0xFF;
    code[7] = (nChild_ >>  8) & 0xFF; code[8] = (nChild_ >>  0) & 0xFF;
    std::memcpy(code+9, chaincode_.begin(), 32);
    code[41] = 0;
    assert(privkey_.size() == 32);
    std::memcpy(code+42, privkey_.begin(), 32);
    return vch;
}

CSecret CExtKey::GetSecret() const {
    return privkey_.GetSecret();
}

bool CExtKey::Decode(const unsigned char code[CExtKey::BIP32_EXTKEY_SIZE], bool fCompressed) {
    nDepth_ = code[0];
    std::memcpy(vchFingerprint_, code+1, 4);
    nChild_ = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    std::memcpy(chaincode_.begin(), code+9, 32);
    privkey_.Set(code+42, code+CExtKey::BIP32_EXTKEY_SIZE, fCompressed);
    return privkey_.IsValid();
}

bool CExtKey::Derive(CExtKey &out, unsigned int _nChild) const {
    out.nDepth_ = nDepth_ + 1;
    CKeyID id = privkey_.GetPubKey().GetID();
    std::memcpy(&out.vchFingerprint_[0], &id, 4);
    out.nChild_ = _nChild;
    return privkey_.Derive(out.privkey_, out.chaincode_, _nChild, chaincode_);
}

CExtPubKey CExtKey::Neuter() const {
    CExtPubKey ret;
    ret.nDepth_ = nDepth_;
    std::memcpy(&ret.vchFingerprint_[0], &vchFingerprint_[0], 4);
    ret.nChild_ = nChild_;
    ret.pubkey_ = privkey_.GetPubKey();
    if(! ret.pubkey_.IsCompressed())
        ret.pubkey_.Compress();
    ret.chaincode_ = chaincode_;
    return ret;
}

bool CExtKey::SetSeed(const unsigned char *seed, unsigned int nSeedLen) {
    static const unsigned char hashkey[] = {'F','r','o','m','H','D','D','t','o','S','S','D'};
    std::vector<unsigned char, secure_allocator<unsigned char> > vout(64);
    latest_crypto::CHMAC_SHA512(hashkey, sizeof(hashkey)).Write(seed, nSeedLen).Finalize(vout.data());
    privkey_.Set(vout.data(), vout.data() + 32, true);
    if(! privkey_.IsValid())
        return false;

    std::memcpy(chaincode_.begin(), vout.data() + 32, 32);
    nDepth_ = 0;
    nChild_ = 0;
    std::memset(vchFingerprint_, 0, sizeof(vchFingerprint_));
    return true;
}
