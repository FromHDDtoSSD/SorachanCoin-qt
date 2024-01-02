// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin developers
// Copyright (c) 2017 The Zcash developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key/pubkey.h>
#include <ies.h>
#include <crypter.h>
#include <init.h>
#include <checkpoints.h>

#ifdef VERIFY
# include <debugcs/debugcs.h>
# define DEBUGCS_CHECK(str) do { debugcs::instance() << __func__ << ": " << (str) << debugcs::endl(); } while(0)
#else
# define DEBUGCS_CHECK(str) do { (void)(str); } while(0)
#endif

bool CPubKey::IsValid() const {
    //DEBUGCS_CHECK("by size check only");
    return size() > 0;
}

bool CPubKey::IsFullyValid() const {
    //DEBUGCS_CHECK("by OpenSSL");
    const unsigned char *pbegin = &vch_[0];
    EC_KEY *pkey = ::EC_KEY_new_by_curve_name(NID_secp256k1);
    if (::o2i_ECPublicKey(&pkey, &pbegin, size())) {
        ::EC_KEY_free(pkey);
        return true;
    }
    return false;
}

bool CPubKey::IsFullyValid_BIP66() const {
    //DEBUGCS_CHECK("by secp256k1");
    if (! IsValid())
        return false;
    secp256k1_pubkey pubkey;
    return secp256k1_ec_pubkey_parse(&pubkey, vch_, size());
}

bool CPubKey::Verify(const uint256 &hash, const key_vector &vchSig) const {
    auto bip66 = [this, &hash, &vchSig]() {
        return Verify_BIP66(hash, vchSig);
    };
    auto openssl = [this, &hash, &vchSig]() {
        DEBUGCS_CHECK("by OpenSSL");
        if (vchSig.empty() || !IsValid())
            return false;

        EC_KEY *pkey = ::EC_KEY_new_by_curve_name(NID_secp256k1);
        if(! pkey) return false;
        ECDSA_SIG *norm_sig = ::ECDSA_SIG_new();
        if(! norm_sig) {
            ::EC_KEY_free(pkey);
            return false;
        }

        bool ret = false;
        do {
            uint8_t *norm_der = nullptr;
            const uint8_t *pbegin = &vch_[0];
            const uint8_t *sigptr = &vchSig[0];

            // Trying to parse public key
            if (! ::o2i_ECPublicKey(&pkey, &pbegin, size()))
                break;

            // New versions of OpenSSL are rejecting a non-canonical DER signatures, de/re-serialize first.
            if (::d2i_ECDSA_SIG(&norm_sig, &sigptr, vchSig.size()) == nullptr)
                break;

            int derlen = 0;
            if ((derlen = ::i2d_ECDSA_SIG(norm_sig, &norm_der)) <= 0)
                break;

            // -1 = error, 0 = bad sig, 1 = good
            ret = ::ECDSA_verify(0, (const unsigned char *)&hash, sizeof(hash), norm_der, derlen, pkey) == 1;
            OPENSSL_free(norm_der);
        } while(false);

        ::ECDSA_SIG_free(norm_sig);
        ::EC_KEY_free(pkey);
        return ret;
    };

    //static CCriticalSection cs;
    //LOCK(cs);
    //debugcs::instance() << "CPubKey " << __func__ << " Bip66 mode: " << entry::b66mode << debugcs::endl();
    //debugcs::instance() << "BlockHeight " << __func__ << " height: " << block_info::nBestHeight << debugcs::endl();
    static int sw_blockheight = 0;
    if(sw_blockheight==0) {
        const MapCheckpoints &ckpoints = args_bool::fTestNet ? Checkpoints::manage::getMapCheckpointsTestnet(): Checkpoints::manage::getMapCheckpoints();
        for(auto ite: ckpoints) {
            if(sw_blockheight<ite.first)
                sw_blockheight = ite.first;
        }
    }
    debugcs::instance() << "CPubKey Verify sw_blockheight " << __func__ << " sw_blockheight: " << sw_blockheight << debugcs::endl();
    if(sw_blockheight<block_info::nBestHeight) {
        if(entry::b66mode == entry::Bip66_STRICT) {
            return bip66() && openssl();
        } else if (entry::b66mode == entry::Bip66_ADVISORY) {
            return bip66();
        } else if (entry::b66mode == entry::Bip66_PERMISSIVE) {
            return openssl();
        } else
            return false;
    } else {
        if(entry::b66mode == entry::Bip66_STRICT) {
            return bip66();
        } else if (entry::b66mode == entry::Bip66_ADVISORY) {
            return openssl();
            /*
            if(bip66())
                return true;
            else {
                logging::LogPrintf("bip66 false, recheck openssl\n");
                return openssl();
            }
            */
        } else if (entry::b66mode == entry::Bip66_PERMISSIVE) {
            return openssl();
        } else
            return false;
    }
}

bool CPubKey::Verify_BIP66(const uint256 &hash, const key_vector &vchSig) const {
    //DEBUGCS_CHECK("by libsecp256k1");
    if (! IsValid())
        return false;
    secp256k1_pubkey pubkey;
    secp256k1_signature sig;
    if (! secp256k1_ec_pubkey_parse(&pubkey, vch_, size()))
        return false;
    if (! ecdsa_signature_parse_der_lax(&sig, vchSig.data(), vchSig.size()))
        return false;

    /* libsecp256k1's ECDSA verification requires lower-S signatures, which have
     * not historically been enforced in Bitcoin, so normalize them first. */
    secp256k1_ecdsa_signature_normalize(&sig, &sig);
    return secp256k1_ecdsa_verify(&sig, hash.begin(), &pubkey);
}

// Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
// recid selects which key is recovered
// if check is non-zero, additional checks are performed
int CPubKey::ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check) {
    if (! eckey) return 0;

    int ret = 0;
    BN_CTX *ctx = nullptr;
    BIGNUM *x = nullptr;
    BIGNUM *e = nullptr;
    BIGNUM *order = nullptr;
    BIGNUM *sor = nullptr;
    BIGNUM *eor = nullptr;
    BIGNUM *field = nullptr;
    EC_POINT *R = nullptr;
    EC_POINT *O = nullptr;
    EC_POINT *Q = nullptr;
    BIGNUM *rr = nullptr;
    BIGNUM *zero = nullptr;
    int n = 0;
    int i = recid / 2;

    do {
        const EC_GROUP *group = ::EC_KEY_get0_group(eckey);
        if ((ctx = ::BN_CTX_new()) == nullptr) { ret = -1; break; }

        ::BN_CTX_start(ctx);
        order = ::BN_CTX_get(ctx);
        if (! ::EC_GROUP_get_order(group, order, ctx)) { ret = -2; break; }

        x = ::BN_CTX_get(ctx);
        if (! ::BN_copy(x, order)) { ret = -1; break; }
        if (! ::BN_mul_word(x, i)) { ret = -1; break; }
        if (! ::BN_add(x, x, ecsig->r)) { ret = -1; break; }

        field = ::BN_CTX_get(ctx);
        if (! ::EC_GROUP_get_curve_GFp(group, field, nullptr, nullptr, ctx)) { ret = -2; break; }
        if (::BN_cmp(x, field) >= 0) { ret = 0; break; }
        if ((R = ::EC_POINT_new(group)) == nullptr) { ret = -2; break; }
        if (! ::EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret = 0; break; }

        if (check) {
            if ((O = ::EC_POINT_new(group)) == nullptr) { ret = -2; break; }
            if (! ::EC_POINT_mul(group, O, nullptr, R, order, ctx)) { ret = -2; break; }
            if (! ::EC_POINT_is_at_infinity(group, O)) { ret = 0; break; }
        }

        if ((Q = ::EC_POINT_new(group)) == nullptr) { ret = -2; break; }
        n = ::EC_GROUP_get_degree(group);
        e = ::BN_CTX_get(ctx);
        if (! ::BN_bin2bn(msg, msglen, e)) { ret = -1; break; }
        if (8 * msglen > n) { ::BN_rshift(e, e, 8 - (n & 7)); }
        zero = ::BN_CTX_get(ctx);
        if (! BN_zero(zero)) { ret = -1; break; }
        if (! ::BN_mod_sub(e, zero, e, order, ctx)) { ret = -1; break; }
        rr = ::BN_CTX_get(ctx);
        if (! ::BN_mod_inverse(rr, ecsig->r, order, ctx)) { ret = -1; break; }
        sor = ::BN_CTX_get(ctx);
        if (! ::BN_mod_mul(sor, ecsig->s, rr, order, ctx)) { ret = -1; break; }
        eor = ::BN_CTX_get(ctx);
        if (! ::BN_mod_mul(eor, e, rr, order, ctx)) { ret = -1; break; }
        if (! ::EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret = -2; break; }
        if (! ::EC_KEY_set_public_key(eckey, Q)) { ret = -2; break; }

        ret = 1;
    } while(false);

    if (ctx) {
        ::BN_CTX_end(ctx);
        ::BN_CTX_free(ctx);
    }
    if (R != nullptr) { ::EC_POINT_free(R); }
    if (O != nullptr) { ::EC_POINT_free(O); }
    if (Q != nullptr) { ::EC_POINT_free(Q); }
    return ret;
}

std::string CPubKey::ToString() const {
    char psz[sizeof(vch_) * 2 + 1]; psz[sizeof(vch_) * 2] = '\0';
    for (unsigned int i=0; i<sizeof(vch_); ++i)
        ::sprintf(psz + i * 2, "%02x", ((unsigned char *)vch_)[i]);
    return psz;
}

// reconstruct public key from a compact signature
// This is only slightly more CPU intensive than just verifying it.
// If this function succeeds, the recovered public key is guaranteed to be valid
// (the signature is a valid signature of the given data for that key)
//#define DEBUG_LIBSECP256K1
bool CPubKey::SetCompactSignature(const uint256 &hash, const key_vector &vchSig) {
    bool ret_libsecp256k1 = RecoverCompact(hash, vchSig);
    if(ret_libsecp256k1)
        return true;

    // if ret_libsecp256k1 == false, below: old core, OPENSSL recheck
    if (vchSig.size() != 65)
        return false;
    int nV = vchSig[0];
    if (nV < 27 || nV >= 35)
        return false;

    ECDSA_SIG *sig = ::ECDSA_SIG_new();
    if(! sig)
        return false;
    ::BN_bin2bn(&vchSig[1], 32, sig->r);
    ::BN_bin2bn(&vchSig[33], 32, sig->s);

    bool fSuccessful = false;
    EC_KEY *pkey = ::EC_KEY_new_by_curve_name(NID_secp256k1);
    if(! pkey) {
        ::ECDSA_SIG_free(sig);
        return false;
    }
    if (nV >= 31) {
        nV -= 4;
        ::EC_KEY_set_conv_form(pkey, POINT_CONVERSION_COMPRESSED);
    }

    do {
        if (ECDSA_SIG_recover_key_GFp(pkey, sig, (unsigned char *)&hash, sizeof(hash), nV - 27, 0) != 1)
            break;
        int nSize = ::i2o_ECPublicKey(pkey, nullptr);
        if (! nSize)
            break;

        std::vector<unsigned char> vchPubKey(nSize, 0);
        unsigned char *pbegin = &vchPubKey[0];
        if (::i2o_ECPublicKey(pkey, &pbegin) != nSize)
            break;

        Set(vchPubKey.begin(), vchPubKey.end());
        fSuccessful = IsValid();
    } while (false);

    ::ECDSA_SIG_free(sig);
    ::EC_KEY_free(pkey);
    if (! fSuccessful)
        Invalidate();

#ifdef DEBUG_LIBSECP256K1
    CPubKey __cmp;
    __cmp.RecoverCompact(hash, vchSig);
    assert(*this == __cmp);
    debugcs::instance() << "[SetCompactSignature: OpenSSL]" << this->ToString().c_str() << debugcs::endl();
    debugcs::instance() << "[RecoverCompact: LIBSECP256K1]" << __cmp.ToString().c_str() << debugcs::endl();
#endif
    return fSuccessful;
}

bool CPubKey::ReserealizeSignature(key_vector &vchSig) {
    if (vchSig.empty())
        return false;

    unsigned char *pos = &vchSig[0];
    ECDSA_SIG *sig = ::d2i_ECDSA_SIG(nullptr, (const unsigned char **)&pos, vchSig.size());
    if (sig == nullptr)
        return false;

    bool ret = false;
    int nSize = i2d_ECDSA_SIG(sig, nullptr);
    if (nSize > 0) {
        vchSig.resize(nSize); // grow or shrink as needed

        pos = &vchSig[0];
        ::i2d_ECDSA_SIG(sig, &pos);

        ret = true;
    }

    ::ECDSA_SIG_free(sig);
    return ret;
}

/**
 *  Supported violations include negative integers, excessive padding, garbage
 *  at the end, and overly long length descriptors. This is safe to use in
 *  Bitcoin because since the activation of BIP66, signatures are verified to be
 *  strict DER before being passed to this module, and we know it supports all
 *  violations present in the blockchain before that point.
 */

#ifdef VERIFY
# define VERIFY_CHECK(cond) do { assert(cond); } while(0)
# define CHECK(cond) VERIFY_CHECK(cond)
#else
# define VERIFY_CHECK(cond) do { (void)(cond); } while(0)
# define CHECK(cond) VERIFY_CHECK(cond)
#endif

#define ARG_CHECK(cond) ARG_CHECK_FUNC(cond, nullptr)
#define ARG_CHECK_FUNC(cond, func) do { if(!(cond)) return CPubKey::PubKey_ERROR_callback((func)); } while(0)

#ifdef VERIFY
# define VERIFY_BITS(x, n) VERIFY_CHECK(((x) >> (n)) == 0)
#else
# define VERIFY_BITS(x, n) do { } while(0)
#endif

#define SECP256K1_GE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), 0}
#define SECP256K1_SCALAR_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {{(d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7)}}

/** Add a*b to the number defined by (c0,c1). c1 must never overflow. */
#define muladd_fast(a,b) { \
    uint32_t tl, th; \
    { \
        uint64_t t = (uint64_t)a * b; \
        th = t >> 32;         /* at most 0xFFFFFFFE */ \
        tl = t; \
    } \
    c0 += tl;                 /* overflow is handled on the next line */ \
    th += (c0 < tl) ? 1 : 0;  /* at most 0xFFFFFFFF */ \
    c1 += th;                 /* never overflows by contract (verified in the next line) */ \
    VERIFY_CHECK(c1 >= th); \
}

/** Extract the lowest 32 bits of (c0,c1,c2) into n, and left shift the number 32 bits. c2 is required to be zero. */
#define extract_fast(n) { \
    (n) = c0; \
    c0 = c1; \
    c1 = 0; \
    VERIFY_CHECK(c2 == 0); \
}

/** Add 2*a*b to the number defined by (c0,c1,c2). c2 must never overflow. */
#define muladd2(a,b) { \
    uint32_t tl, th, th2, tl2; \
    { \
        uint64_t t = (uint64_t)a * b; \
        th = t >> 32;               /* at most 0xFFFFFFFE */ \
        tl = t; \
    } \
    th2 = th + th;                  /* at most 0xFFFFFFFE (in case th was 0x7FFFFFFF) */ \
    c2 += (th2 < th) ? 1 : 0;       /* never overflows by contract (verified the next line) */ \
    VERIFY_CHECK((th2 >= th) || (c2 != 0)); \
    tl2 = tl + tl;                  /* at most 0xFFFFFFFE (in case the lowest 63 bits of tl were 0x7FFFFFFF) */ \
    th2 += (tl2 < tl) ? 1 : 0;      /* at most 0xFFFFFFFF */ \
    c0 += tl2;                      /* overflow is handled on the next line */ \
    th2 += (c0 < tl2) ? 1 : 0;      /* second overflow is handled on the next line */ \
    c2 += (c0 < tl2) & (th2 == 0);  /* never overflows by contract (verified the next line) */ \
    VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); \
    c1 += th2;                      /* overflow is handled on the next line */ \
    c2 += (c1 < th2) ? 1 : 0;       /* never overflows by contract (verified the next line) */ \
    VERIFY_CHECK((c1 >= th2) || (c2 != 0)); \
}

/** Extract the lowest 32 bits of (c0,c1,c2) into n, and left shift the number 32 bits. */
#define extract(n) { \
    (n) = c0; \
    c0 = c1; \
    c1 = c2; \
    c2 = 0; \
}

/** Add a*b to the number defined by (c0,c1,c2). c2 must never overflow. */
#define muladd(a,b) { \
    uint32_t tl, th; \
    { \
        uint64_t t = (uint64_t)a * b; \
        th = t >> 32;         /* at most 0xFFFFFFFE */ \
        tl = t; \
    } \
    c0 += tl;                 /* overflow is handled on the next line */ \
    th += (c0 < tl) ? 1 : 0;  /* at most 0xFFFFFFFF */ \
    c1 += th;                 /* overflow is handled on the next line */ \
    c2 += (c1 < th) ? 1 : 0;  /* never overflows by contract (verified in the next line) */ \
    VERIFY_CHECK((c1 >= th) || (c2 != 0)); \
}

/** Add a to the number defined by (c0,c1). c1 must never overflow, c2 must be zero. */
#define sumadd_fast(a) { \
    c0 += (a);                 /* overflow is handled on the next line */ \
    c1 += (c0 < (a)) ? 1 : 0;  /* never overflows by contract (verified the next line) */ \
    VERIFY_CHECK((c1 != 0) | (c0 >= (a))); \
    VERIFY_CHECK(c2 == 0); \
}

/** Add a to the number defined by (c0,c1,c2). c2 must never overflow. */
#define sumadd(a) { \
    unsigned int over; \
    c0 += (a);                  /* overflow is handled on the next line */ \
    over = (c0 < (a)) ? 1 : 0; \
    c1 += over;                 /* overflow is handled on the next line */ \
    c2 += (c1 < over) ? 1 : 0;  /* never overflows by contract */ \
}

/** The number of entries a table with precomputed multiples needs to have. */
#define ECMULT_TABLE_SIZE(w) (1 << ((w)-2))
/* optimal for 128-bit and 256-bit exponents. */
#define WINDOW_A 5
/** One table for window size 16: 1.375 MiB. */
#define WINDOW_G 16

/** The following two macro retrieves a particular odd multiple from a table
 *  of precomputed multiples. */
#define ECMULT_TABLE_GET_GE(r,pre,n,w) do { \
    VERIFY_CHECK(((n) & 1) == 1); \
    VERIFY_CHECK((n) >= -((1 << ((w)-1)) - 1)); \
    VERIFY_CHECK((n) <=  ((1 << ((w)-1)) - 1)); \
    if ((n) > 0) { \
        *(r) = (pre)[((n)-1)/2]; \
    } else { \
        ecmult::secp256k1_ge_neg((r), &(pre)[(-(n)-1)/2]); \
    } \
} while(0)

#define ECMULT_TABLE_GET_GE_STORAGE(r,pre,n,w) do { \
    VERIFY_CHECK(((n) & 1) == 1); \
    VERIFY_CHECK((n) >= -((1 << ((w)-1)) - 1)); \
    VERIFY_CHECK((n) <=  ((1 << ((w)-1)) - 1)); \
    if ((n) > 0) { \
        ecmult::secp256k1_ge_from_storage((r), &(pre)[((n)-1)/2]); \
    } else { \
        ecmult::secp256k1_ge_from_storage((r), &(pre)[(-(n)-1)/2]); \
        ecmult::secp256k1_ge_neg((r), (r)); \
    } \
} while(0)

static constexpr CPubKey::ecmult::secp256k1_fe secp256k1_ecdsa_const_p_minus_order = SECP256K1_FE_CONST(
    0, 0, 0, 1, 0x45512319UL, 0x50B75FC4UL, 0x402DA172UL, 0x2FC9BAEEUL
);

static constexpr CPubKey::ecmult::secp256k1_fe secp256k1_ecdsa_const_order_as_fe = SECP256K1_FE_CONST(
    0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL,
    0xBAAEDCE6UL, 0xAF48A03BUL, 0xBFD25E8CUL, 0xD0364141UL
);

int CPubKey::secp256k1_scalar_check_overflow(const secp256k1_unit *a) {
    int yes = 0;
    int no = 0;
    no |= (a->d[7] < SECP256K1_N_7); /* No need for a > check. */
    no |= (a->d[6] < SECP256K1_N_6); /* No need for a > check. */
    no |= (a->d[5] < SECP256K1_N_5); /* No need for a > check. */
    no |= (a->d[4] < SECP256K1_N_4);
    yes |= (a->d[4] > SECP256K1_N_4) & ~no;
    no |= (a->d[3] < SECP256K1_N_3) & ~yes;
    yes |= (a->d[3] > SECP256K1_N_3) & ~no;
    no |= (a->d[2] < SECP256K1_N_2) & ~yes;
    yes |= (a->d[2] > SECP256K1_N_2) & ~no;
    no |= (a->d[1] < SECP256K1_N_1) & ~yes;
    yes |= (a->d[1] > SECP256K1_N_1) & ~no;
    yes |= (a->d[0] >= SECP256K1_N_0) & ~no;
    return yes;
}

uint32_t CPubKey::secp256k1_scalar_reduce(secp256k1_unit *r, uint32_t overflow) {
    uint64_t t;
    t = (uint64_t)r->d[0] + overflow * SECP256K1_N_C_0;
    r->d[0] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)r->d[1] + overflow * SECP256K1_N_C_1;
    r->d[1] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)r->d[2] + overflow * SECP256K1_N_C_2;
    r->d[2] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)r->d[3] + overflow * SECP256K1_N_C_3;
    r->d[3] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)r->d[4] + overflow * SECP256K1_N_C_4;
    r->d[4] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)r->d[5];
    r->d[5] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)r->d[6];
    r->d[6] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)r->d[7];
    r->d[7] = t & 0xFFFFFFFFUL;
    return overflow;
}

void CPubKey::secp256k1_scalar_set_be32(secp256k1_unit *r, const unsigned char *b32, int *overflow) {
    int over;
    r->d[0] = (uint32_t)b32[31] | (uint32_t)b32[30] << 8 | (uint32_t)b32[29] << 16 | (uint32_t)b32[28] << 24;
    r->d[1] = (uint32_t)b32[27] | (uint32_t)b32[26] << 8 | (uint32_t)b32[25] << 16 | (uint32_t)b32[24] << 24;
    r->d[2] = (uint32_t)b32[23] | (uint32_t)b32[22] << 8 | (uint32_t)b32[21] << 16 | (uint32_t)b32[20] << 24;
    r->d[3] = (uint32_t)b32[19] | (uint32_t)b32[18] << 8 | (uint32_t)b32[17] << 16 | (uint32_t)b32[16] << 24;
    r->d[4] = (uint32_t)b32[15] | (uint32_t)b32[14] << 8 | (uint32_t)b32[13] << 16 | (uint32_t)b32[12] << 24;
    r->d[5] = (uint32_t)b32[11] | (uint32_t)b32[10] << 8 | (uint32_t)b32[9] << 16 | (uint32_t)b32[8] << 24;
    r->d[6] = (uint32_t)b32[7] | (uint32_t)b32[6] << 8 | (uint32_t)b32[5] << 16 | (uint32_t)b32[4] << 24;
    r->d[7] = (uint32_t)b32[3] | (uint32_t)b32[2] << 8 | (uint32_t)b32[1] << 16 | (uint32_t)b32[0] << 24;
    over = secp256k1_scalar_reduce(r, secp256k1_scalar_check_overflow(r));
    if (overflow)
        *overflow = over;
}

void CPubKey::secp256k1_scalar_get_be32(unsigned char *bin, const secp256k1_unit *a) {
    bin[0] = a->d[7] >> 24; bin[1] = a->d[7] >> 16; bin[2] = a->d[7] >> 8; bin[3] = a->d[7];
    bin[4] = a->d[6] >> 24; bin[5] = a->d[6] >> 16; bin[6] = a->d[6] >> 8; bin[7] = a->d[6];
    bin[8] = a->d[5] >> 24; bin[9] = a->d[5] >> 16; bin[10] = a->d[5] >> 8; bin[11] = a->d[5];
    bin[12] = a->d[4] >> 24; bin[13] = a->d[4] >> 16; bin[14] = a->d[4] >> 8; bin[15] = a->d[4];
    bin[16] = a->d[3] >> 24; bin[17] = a->d[3] >> 16; bin[18] = a->d[3] >> 8; bin[19] = a->d[3];
    bin[20] = a->d[2] >> 24; bin[21] = a->d[2] >> 16; bin[22] = a->d[2] >> 8; bin[23] = a->d[2];
    bin[24] = a->d[1] >> 24; bin[25] = a->d[1] >> 16; bin[26] = a->d[1] >> 8; bin[27] = a->d[1];
    bin[28] = a->d[0] >> 24; bin[29] = a->d[0] >> 16; bin[30] = a->d[0] >> 8; bin[31] = a->d[0];
}

void CPubKey::secp256k1_ecdsa_signature_save(secp256k1_signature *sig, const secp256k1_unit *r, const secp256k1_unit *s) {
    VERIFY_CHECK(sizeof(secp256k1_unit)==32);
    std::memcpy(&sig->data[0], r, 32);
    std::memcpy(&sig->data[32], s, 32);
    // otherwise (sizeof(secp256k1_unit)!=32))
    //secp256k1_scalar_get_be32(&sig->data[0], r);
    //secp256k1_scalar_get_be32(&sig->data[32], s);
}

void CPubKey::secp256k1_ecdsa_signature_load(secp256k1_unit *r, secp256k1_unit *s, const secp256k1_signature *sig) {
    VERIFY_CHECK(sizeof(secp256k1_unit)==32);
    std::memcpy(r, &sig->data[0], 32);
    std::memcpy(s, &sig->data[32], 32);
    // otherwise (sizeof(secp256k1_unit)!=32)
    //secp256k1_scalar_set_be32(r, &sig->data[0], nullptr);
    //secp256k1_scalar_set_be32(s, &sig->data[32], nullptr);
}

int CPubKey::secp256k1_ecdsa_signature_parse_compact(secp256k1_signature *sig, unsigned char *input64) {
    secp256k1_unit r, s;
    int ret = 1;
    int overflow = 0;

    //VERIFY_CHECK(ctx != nullptr);
    ARG_CHECK(sig != nullptr);
    ARG_CHECK(input64 != nullptr);

    secp256k1_scalar_set_be32(&r, &input64[0], &overflow);
    ret &= !overflow;
    secp256k1_scalar_set_be32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret)
        secp256k1_ecdsa_signature_save(sig, &r, &s);
    else
        std::memset(sig, 0, sizeof(*sig));

    return ret;
}

/** This function is taken from the libsecp256k1 distribution and implements
 *  DER parsing for ECDSA signatures, while supporting an arbitrary subset of
 *  format violations.
 *
 *  Supported violations include negative integers, excessive padding, garbage
 *  at the end, and overly long length descriptors. This is safe to use in
 *  Bitcoin because since the activation of BIP66, signatures are verified to be
 *  strict DER before being passed to this module, and we know it supports all
 *  violations present in the blockchain before that point.
 */
// Bitcoin: ecdsa_signature_parse_der_lax
int CPubKey::ecdsa_signature_parse_der_lax(secp256k1_signature *sig, const unsigned char *input, size_t inputlen) {
    auto SIG_clear = [](secp256k1_signature *sig) {
        cleanse::memory_cleanse(sig->data, sizeof(sig->data));
    };

    size_t pos = 0;
    unsigned char tmpsig[64] = {0};
    int overflow = 0;

    SIG_clear(sig);

    /* Sequence tag byte */
    if (pos == inputlen || input[pos] != 0x30)
        return 0;
    ++pos;

    /* Sequence length bytes */
    if (pos == inputlen)
        return 0;
    size_t lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos)
            return 0;
        pos += lenbyte;
    }

    /* Integer tag byte for R */
    if (pos == inputlen || input[pos] != 0x02)
        return 0;
    ++pos;

    /* Integer length for R */
    size_t rlen = 0;
    if (pos == inputlen)
        return 0;
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos)
            return 0;
        while (lenbyte > 0 && input[pos] == 0) {
            ++pos;
            --lenbyte;
        }
        static_assert(sizeof(size_t) >= 4, "size_t too small");
        if (lenbyte >= 4)
            return 0;
        rlen = 0;
        while (lenbyte > 0) {
            rlen = (rlen << 8) + input[pos];
            ++pos;
            --lenbyte;
        }
    } else
        rlen = lenbyte;

    if (rlen > inputlen - pos)
        return 0;
    size_t rpos = pos;
    pos += rlen;

    /* Integer tag byte for S */
    if (pos == inputlen || input[pos] != 0x02)
        return 0;
    ++pos;

    /* Integer length for S */
    size_t slen = 0;
    if (pos == inputlen)
        return 0;
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos)
            return 0;
        while (lenbyte > 0 && input[pos] == 0) {
            ++pos;
            --lenbyte;
        }
        static_assert(sizeof(size_t) >= 4, "size_t too small");
        if (lenbyte >= 4)
            return 0;
        slen = 0;
        while (lenbyte > 0) {
            slen = (slen << 8) + input[pos];
            ++pos;
            --lenbyte;
        }
    } else
        slen = lenbyte;

    if (slen > inputlen - pos)
        return 0;
    size_t spos = pos;

    /* Ignore leading zeroes in R */
    while (rlen > 0 && input[rpos] == 0) {
        --rlen;
        ++rpos;
    }
    /* Copy R value */
    if (rlen > 32)
        overflow = 1;
    else
        std::memcpy(tmpsig + 32 - rlen, input + rpos, rlen);

    /* Ignore leading zeroes in S */
    while (slen > 0 && input[spos] == 0) {
        --slen;
        ++spos;
    }
    /* Copy S value */
    if (slen > 32)
        overflow = 1;
    else
        std::memcpy(tmpsig + 64 - slen, input + spos, slen);

    if (! overflow)
        overflow = !secp256k1_ecdsa_signature_parse_compact(sig, tmpsig);
    if (overflow) {
        /* Overwrite the result again with a correctly-parsed but invalid
           signature if parsing failed. */
        SIG_clear(sig);
    }
    return 1;
}

int CPubKey::secp256k1_scalar_is_high(const secp256k1_unit *a) {
    constexpr uint32_t SECP256K1_N_H_0 = (uint32_t)0x681B20A0UL;
    constexpr uint32_t SECP256K1_N_H_1 = (uint32_t)0xDFE92F46UL;
    constexpr uint32_t SECP256K1_N_H_2 = (uint32_t)0x57A4501DUL;
    constexpr uint32_t SECP256K1_N_H_3 = (uint32_t)0x5D576E73UL;
    constexpr uint32_t SECP256K1_N_H_4 = (uint32_t)0xFFFFFFFFUL;
    constexpr uint32_t SECP256K1_N_H_5 = (uint32_t)0xFFFFFFFFUL;
    constexpr uint32_t SECP256K1_N_H_6 = (uint32_t)0xFFFFFFFFUL;
    constexpr uint32_t SECP256K1_N_H_7 = (uint32_t)0x7FFFFFFFUL;
    int yes = 0;
    int no = 0;
    no |= (a->d[7] < SECP256K1_N_H_7);
    yes |= (a->d[7] > SECP256K1_N_H_7) & ~no;
    no |= (a->d[6] < SECP256K1_N_H_6) & ~yes; /* No need for a > check. */
    no |= (a->d[5] < SECP256K1_N_H_5) & ~yes; /* No need for a > check. */
    no |= (a->d[4] < SECP256K1_N_H_4) & ~yes; /* No need for a > check. */
    no |= (a->d[3] < SECP256K1_N_H_3) & ~yes;
    yes |= (a->d[3] > SECP256K1_N_H_3) & ~no;
    no |= (a->d[2] < SECP256K1_N_H_2) & ~yes;
    yes |= (a->d[2] > SECP256K1_N_H_2) & ~no;
    no |= (a->d[1] < SECP256K1_N_H_1) & ~yes;
    yes |= (a->d[1] > SECP256K1_N_H_1) & ~no;
    yes |= (a->d[0] > SECP256K1_N_H_0) & ~no;
    return yes;
}

int CPubKey::secp256k1_scalar_is_zero(const secp256k1_unit *a) {
    return (a->d[0] | a->d[1] | a->d[2] | a->d[3] | a->d[4] | a->d[5] | a->d[6] | a->d[7]) == 0;
}

int CPubKey::secp256k1_ecdsa_signature_normalize(const secp256k1_signature *sigin) {
    secp256k1_unit r, s;

    //VERIFY_CHECK(ctx != nullptr);
    //ARG_CHECK(sigin != nullptr);
    VERIFY_CHECK(sigin != nullptr);

    secp256k1_ecdsa_signature_load(&r, &s, sigin);
    return secp256k1_scalar_is_high(&s);
}

int CPubKey::secp256k1_ecdsa_signature_normalize(secp256k1_signature *sigout, const secp256k1_signature *sigin) {
    secp256k1_unit r, s;

    //VERIFY_CHECK(ctx != nullptr);
    //ARG_CHECK(sigin != nullptr);
    VERIFY_CHECK(sigin != nullptr);

    secp256k1_ecdsa_signature_load(&r, &s, sigin);
    int ret = secp256k1_scalar_is_high(&s);
    if (sigout != nullptr) {
        if (ret)
            secp256k1_scalar_negate(&s, &s);
        secp256k1_ecdsa_signature_save(sigout, &r, &s);
    }
    return ret;
}

bool CPubKey::CheckLowS(const key_vector &vchSig) {
    secp256k1_signature sig;
    if (! ecdsa_signature_parse_der_lax(&sig, vchSig.data(), vchSig.size()))
        return false;

    return (! secp256k1_ecdsa_signature_normalize(&sig));
}

void CPubKey::secp256k1_ecdsa_recoverable_signature_save(secp256k1_ecdsa_recoverable_signature *sig, const secp256k1_unit *r, const secp256k1_unit *s, int recid) {
    VERIFY_CHECK(sizeof(secp256k1_unit)==32);
    std::memcpy(&sig->data[0], r, 32);
    std::memcpy(&sig->data[32], s, 32);

    // otherwise (sizeof(secp256k1_unit)!=32)
    //secp256k1_scalar_get_be32(&sig->data[0], r);
    //secp256k1_scalar_get_be32(&sig->data[32], s);

    sig->data[64] = recid;
}

void CPubKey::secp256k1_ecdsa_recoverable_signature_load(secp256k1_unit *r, secp256k1_unit *s, int *recid, const secp256k1_ecdsa_recoverable_signature *sig) {
    VERIFY_CHECK(sizeof(secp256k1_unit)==32);
    std::memcpy(r, &sig->data[0], 32);
    std::memcpy(s, &sig->data[32], 32);

    // otherwise (sizeof(secp256k1_unit!=32))
    //secp256k1_scalar_set_be32(r, &sig->data[0], nullptr);
    //secp256k1_scalar_set_be32(s, &sig->data[32], nullptr);

    *recid = sig->data[64];
}

int CPubKey::secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ecdsa_recoverable_signature *sig, const unsigned char *input64, int recid) {
    secp256k1_unit r, s;
    int ret = 1;
    int overflow = 0;
    ARG_CHECK(sig != nullptr);
    ARG_CHECK(input64 != nullptr);
    ARG_CHECK(recid >= 0 && recid <= 3);

    secp256k1_scalar_set_be32(&r, &input64[0], &overflow);
    ret &= !overflow;
    secp256k1_scalar_set_be32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret)
        secp256k1_ecdsa_recoverable_signature_save(sig, &r, &s, recid);
    else
        std::memset(sig, 0, sizeof(*sig));

    return ret;
}

#ifdef VERIFY
void CPubKey::ecmult::secp256k1_fe_verify(const secp256k1_fe *a) {
    const uint32_t *d = a->n;
    int m = a->normalized ? 1 : 2 * a->magnitude, r = 1;
    r &= (d[0] <= 0x3FFFFFFUL * m);
    r &= (d[1] <= 0x3FFFFFFUL * m);
    r &= (d[2] <= 0x3FFFFFFUL * m);
    r &= (d[3] <= 0x3FFFFFFUL * m);
    r &= (d[4] <= 0x3FFFFFFUL * m);
    r &= (d[5] <= 0x3FFFFFFUL * m);
    r &= (d[6] <= 0x3FFFFFFUL * m);
    r &= (d[7] <= 0x3FFFFFFUL * m);
    r &= (d[8] <= 0x3FFFFFFUL * m);
    r &= (d[9] <= 0x03FFFFFUL * m);
    r &= (a->magnitude >= 0);
    r &= (a->magnitude <= 32);
    if (a->normalized) {
        r &= (a->magnitude <= 1);
        if (r && (d[9] == 0x03FFFFFUL)) {
            uint32_t mid = d[8] & d[7] & d[6] & d[5] & d[4] & d[3] & d[2];
            if (mid == 0x3FFFFFFUL) {
                r &= ((d[1] + 0x40UL + ((d[0] + 0x3D1UL) >> 26)) <= 0x3FFFFFFUL);
            }
        }
    }
    VERIFY_CHECK(r == 1);
}
#endif

int CPubKey::ecmult::secp256k1_fe_set_be32(secp256k1_fe *r, const unsigned char *a) {
    r->n[0] = (uint32_t)a[31] | ((uint32_t)a[30] << 8) | ((uint32_t)a[29] << 16) | ((uint32_t)(a[28] & 0x3) << 24);
    r->n[1] = (uint32_t)((a[28] >> 2) & 0x3f) | ((uint32_t)a[27] << 6) | ((uint32_t)a[26] << 14) | ((uint32_t)(a[25] & 0xf) << 22);
    r->n[2] = (uint32_t)((a[25] >> 4) & 0xf) | ((uint32_t)a[24] << 4) | ((uint32_t)a[23] << 12) | ((uint32_t)(a[22] & 0x3f) << 20);
    r->n[3] = (uint32_t)((a[22] >> 6) & 0x3) | ((uint32_t)a[21] << 2) | ((uint32_t)a[20] << 10) | ((uint32_t)a[19] << 18);
    r->n[4] = (uint32_t)a[18] | ((uint32_t)a[17] << 8) | ((uint32_t)a[16] << 16) | ((uint32_t)(a[15] & 0x3) << 24);
    r->n[5] = (uint32_t)((a[15] >> 2) & 0x3f) | ((uint32_t)a[14] << 6) | ((uint32_t)a[13] << 14) | ((uint32_t)(a[12] & 0xf) << 22);
    r->n[6] = (uint32_t)((a[12] >> 4) & 0xf) | ((uint32_t)a[11] << 4) | ((uint32_t)a[10] << 12) | ((uint32_t)(a[9] & 0x3f) << 20);
    r->n[7] = (uint32_t)((a[9] >> 6) & 0x3) | ((uint32_t)a[8] << 2) | ((uint32_t)a[7] << 10) | ((uint32_t)a[6] << 18);
    r->n[8] = (uint32_t)a[5] | ((uint32_t)a[4] << 8) | ((uint32_t)a[3] << 16) | ((uint32_t)(a[2] & 0x3) << 24);
    r->n[9] = (uint32_t)((a[2] >> 2) & 0x3f) | ((uint32_t)a[1] << 6) | ((uint32_t)a[0] << 14);

    if (r->n[9] == 0x3FFFFFUL && (r->n[8] & r->n[7] & r->n[6] & r->n[5] & r->n[4] & r->n[3] & r->n[2]) == 0x3FFFFFFUL && (r->n[1] + 0x40UL + ((r->n[0] + 0x3D1UL) >> 26)) > 0x3FFFFFFUL)
        return 0;
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verify(r);
#endif
    return 1;
}

int CPubKey::ecmult::secp256k1_fe_cmp(const secp256k1_fe *a, const secp256k1_fe *b) {
    int i;
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    VERIFY_CHECK(b->normalized);
    secp256k1_fe_verify(a);
    secp256k1_fe_verify(b);
#endif
    for (i = 9; i >= 0; i--) {
        if (a->n[i] > b->n[i]) {
            return 1;
        }
        if (a->n[i] < b->n[i]) {
            return -1;
        }
    }
    return 0;
}

int CPubKey::ecmult::secp256k1_fe_cmp_var(const secp256k1_fe *a, const secp256k1_fe *b) {
    return secp256k1_fe_cmp(a, b);
}

void CPubKey::ecmult::secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a) {
#ifdef VERIFY
    secp256k1_fe_verify(a);
#endif
    r->n[0] += a->n[0];
    r->n[1] += a->n[1];
    r->n[2] += a->n[2];
    r->n[3] += a->n[3];
    r->n[4] += a->n[4];
    r->n[5] += a->n[5];
    r->n[6] += a->n[6];
    r->n[7] += a->n[7];
    r->n[8] += a->n[8];
    r->n[9] += a->n[9];
#ifdef VERIFY
    r->magnitude += a->magnitude;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

void CPubKey::ecmult::secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a) {
    auto secp256k1_fe_sqr_inner = [](uint32_t *r, const uint32_t *a) {
        uint64_t c, d;
        uint64_t u0, u1, u2, u3, u4, u5, u6, u7, u8;
        uint32_t t9, t0, t1, t2, t3, t4, t5, t6, t7;
        const uint32_t M = 0x3FFFFFFUL, R0 = 0x3D10UL, R1 = 0x400UL;

        VERIFY_BITS(a[0], 30);
        VERIFY_BITS(a[1], 30);
        VERIFY_BITS(a[2], 30);
        VERIFY_BITS(a[3], 30);
        VERIFY_BITS(a[4], 30);
        VERIFY_BITS(a[5], 30);
        VERIFY_BITS(a[6], 30);
        VERIFY_BITS(a[7], 30);
        VERIFY_BITS(a[8], 30);
        VERIFY_BITS(a[9], 26);

        /** [... a b c] is a shorthand for ... + a<<52 + b<<26 + c<<0 mod n.
         *  px is a shorthand for sum(a[i]*a[x-i], i=0..x).
         *  Note that [x 0 0 0 0 0 0 0 0 0 0] = [x*R1 x*R0].
         */

        d  = (uint64_t)(a[0]*2) * a[9]
           + (uint64_t)(a[1]*2) * a[8]
           + (uint64_t)(a[2]*2) * a[7]
           + (uint64_t)(a[3]*2) * a[6]
           + (uint64_t)(a[4]*2) * a[5];
        /* VERIFY_BITS(d, 64); */
        /* [d 0 0 0 0 0 0 0 0 0] = [p9 0 0 0 0 0 0 0 0 0] */
        t9 = d & M; d >>= 26;
        VERIFY_BITS(t9, 26);
        VERIFY_BITS(d, 38);
        /* [d t9 0 0 0 0 0 0 0 0 0] = [p9 0 0 0 0 0 0 0 0 0] */

        c  = (uint64_t)a[0] * a[0];
        VERIFY_BITS(c, 60);
        /* [d t9 0 0 0 0 0 0 0 0 c] = [p9 0 0 0 0 0 0 0 0 p0] */
        d += (uint64_t)(a[1]*2) * a[9]
           + (uint64_t)(a[2]*2) * a[8]
           + (uint64_t)(a[3]*2) * a[7]
           + (uint64_t)(a[4]*2) * a[6]
           + (uint64_t)a[5] * a[5];
        VERIFY_BITS(d, 63);
        /* [d t9 0 0 0 0 0 0 0 0 c] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
        u0 = d & M; d >>= 26; c += u0 * R0;
        VERIFY_BITS(u0, 26);
        VERIFY_BITS(d, 37);
        VERIFY_BITS(c, 61);
        /* [d u0 t9 0 0 0 0 0 0 0 0 c-u0*R0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
        t0 = c & M; c >>= 26; c += u0 * R1;
        VERIFY_BITS(t0, 26);
        VERIFY_BITS(c, 37);
        /* [d u0 t9 0 0 0 0 0 0 0 c-u0*R1 t0-u0*R0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
        /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */

        c += (uint64_t)(a[0]*2) * a[1];
        VERIFY_BITS(c, 62);
        /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p10 p9 0 0 0 0 0 0 0 p1 p0] */
        d += (uint64_t)(a[2]*2) * a[9]
           + (uint64_t)(a[3]*2) * a[8]
           + (uint64_t)(a[4]*2) * a[7]
           + (uint64_t)(a[5]*2) * a[6];
        VERIFY_BITS(d, 63);
        /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
        u1 = d & M; d >>= 26; c += u1 * R0;
        VERIFY_BITS(u1, 26);
        VERIFY_BITS(d, 37);
        VERIFY_BITS(c, 63);
        /* [d u1 0 t9 0 0 0 0 0 0 0 c-u1*R0 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
        t1 = c & M; c >>= 26; c += u1 * R1;
        VERIFY_BITS(t1, 26);
        VERIFY_BITS(c, 38);
        /* [d u1 0 t9 0 0 0 0 0 0 c-u1*R1 t1-u1*R0 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
        /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */

        c += (uint64_t)(a[0]*2) * a[2]
           + (uint64_t)a[1] * a[1];
        VERIFY_BITS(c, 62);
        /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
        d += (uint64_t)(a[3]*2) * a[9]
           + (uint64_t)(a[4]*2) * a[8]
           + (uint64_t)(a[5]*2) * a[7]
           + (uint64_t)a[6] * a[6];
        VERIFY_BITS(d, 63);
        /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
        u2 = d & M; d >>= 26; c += u2 * R0;
        VERIFY_BITS(u2, 26);
        VERIFY_BITS(d, 37);
        VERIFY_BITS(c, 63);
        /* [d u2 0 0 t9 0 0 0 0 0 0 c-u2*R0 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
        t2 = c & M; c >>= 26; c += u2 * R1;
        VERIFY_BITS(t2, 26);
        VERIFY_BITS(c, 38);
        /* [d u2 0 0 t9 0 0 0 0 0 c-u2*R1 t2-u2*R0 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
        /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */

        c += (uint64_t)(a[0]*2) * a[3]
           + (uint64_t)(a[1]*2) * a[2];
        VERIFY_BITS(c, 63);
        /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
        d += (uint64_t)(a[4]*2) * a[9]
           + (uint64_t)(a[5]*2) * a[8]
           + (uint64_t)(a[6]*2) * a[7];
        VERIFY_BITS(d, 63);
        /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
        u3 = d & M; d >>= 26; c += u3 * R0;
        VERIFY_BITS(u3, 26);
        VERIFY_BITS(d, 37);
        /* VERIFY_BITS(c, 64); */
        /* [d u3 0 0 0 t9 0 0 0 0 0 c-u3*R0 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
        t3 = c & M; c >>= 26; c += u3 * R1;
        VERIFY_BITS(t3, 26);
        VERIFY_BITS(c, 39);
        /* [d u3 0 0 0 t9 0 0 0 0 c-u3*R1 t3-u3*R0 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
        /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */

        c += (uint64_t)(a[0]*2) * a[4]
           + (uint64_t)(a[1]*2) * a[3]
           + (uint64_t)a[2] * a[2];
        VERIFY_BITS(c, 63);
        /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
        d += (uint64_t)(a[5]*2) * a[9]
           + (uint64_t)(a[6]*2) * a[8]
           + (uint64_t)a[7] * a[7];
        VERIFY_BITS(d, 62);
        /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
        u4 = d & M; d >>= 26; c += u4 * R0;
        VERIFY_BITS(u4, 26);
        VERIFY_BITS(d, 36);
        /* VERIFY_BITS(c, 64); */
        /* [d u4 0 0 0 0 t9 0 0 0 0 c-u4*R0 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
        t4 = c & M; c >>= 26; c += u4 * R1;
        VERIFY_BITS(t4, 26);
        VERIFY_BITS(c, 39);
        /* [d u4 0 0 0 0 t9 0 0 0 c-u4*R1 t4-u4*R0 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
        /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */

        c += (uint64_t)(a[0]*2) * a[5]
           + (uint64_t)(a[1]*2) * a[4]
           + (uint64_t)(a[2]*2) * a[3];
        VERIFY_BITS(c, 63);
        /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
        d += (uint64_t)(a[6]*2) * a[9]
           + (uint64_t)(a[7]*2) * a[8];
        VERIFY_BITS(d, 62);
        /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
        u5 = d & M; d >>= 26; c += u5 * R0;
        VERIFY_BITS(u5, 26);
        VERIFY_BITS(d, 36);
        /* VERIFY_BITS(c, 64); */
        /* [d u5 0 0 0 0 0 t9 0 0 0 c-u5*R0 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
        t5 = c & M; c >>= 26; c += u5 * R1;
        VERIFY_BITS(t5, 26);
        VERIFY_BITS(c, 39);
        /* [d u5 0 0 0 0 0 t9 0 0 c-u5*R1 t5-u5*R0 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
        /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */

        c += (uint64_t)(a[0]*2) * a[6]
           + (uint64_t)(a[1]*2) * a[5]
           + (uint64_t)(a[2]*2) * a[4]
           + (uint64_t)a[3] * a[3];
        VERIFY_BITS(c, 63);
        /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
        d += (uint64_t)(a[7]*2) * a[9]
           + (uint64_t)a[8] * a[8];
        VERIFY_BITS(d, 61);
        /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
        u6 = d & M; d >>= 26; c += u6 * R0;
        VERIFY_BITS(u6, 26);
        VERIFY_BITS(d, 35);
        /* VERIFY_BITS(c, 64); */
        /* [d u6 0 0 0 0 0 0 t9 0 0 c-u6*R0 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
        t6 = c & M; c >>= 26; c += u6 * R1;
        VERIFY_BITS(t6, 26);
        VERIFY_BITS(c, 39);
        /* [d u6 0 0 0 0 0 0 t9 0 c-u6*R1 t6-u6*R0 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
        /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */

        c += (uint64_t)(a[0]*2) * a[7]
           + (uint64_t)(a[1]*2) * a[6]
           + (uint64_t)(a[2]*2) * a[5]
           + (uint64_t)(a[3]*2) * a[4];
        /* VERIFY_BITS(c, 64); */
        VERIFY_CHECK(c <= 0x8000007C00000007ULL);
        /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
        d += (uint64_t)(a[8]*2) * a[9];
        VERIFY_BITS(d, 58);
        /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
        u7 = d & M; d >>= 26; c += u7 * R0;
        VERIFY_BITS(u7, 26);
        VERIFY_BITS(d, 32);
        /* VERIFY_BITS(c, 64); */
        VERIFY_CHECK(c <= 0x800001703FFFC2F7ULL);
        /* [d u7 0 0 0 0 0 0 0 t9 0 c-u7*R0 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
        t7 = c & M; c >>= 26; c += u7 * R1;
        VERIFY_BITS(t7, 26);
        VERIFY_BITS(c, 38);
        /* [d u7 0 0 0 0 0 0 0 t9 c-u7*R1 t7-u7*R0 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
        /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */

        c += (uint64_t)(a[0]*2) * a[8]
           + (uint64_t)(a[1]*2) * a[7]
           + (uint64_t)(a[2]*2) * a[6]
           + (uint64_t)(a[3]*2) * a[5]
           + (uint64_t)a[4] * a[4];
        /* VERIFY_BITS(c, 64); */
        VERIFY_CHECK(c <= 0x9000007B80000008ULL);
        /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        d += (uint64_t)a[9] * a[9];
        VERIFY_BITS(d, 57);
        /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        u8 = d & M; d >>= 26; c += u8 * R0;
        VERIFY_BITS(u8, 26);
        VERIFY_BITS(d, 31);
        /* VERIFY_BITS(c, 64); */
        VERIFY_CHECK(c <= 0x9000016FBFFFC2F8ULL);
        /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 t4 t3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

        r[3] = t3;
        VERIFY_BITS(r[3], 26);
        /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 t4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[4] = t4;
        VERIFY_BITS(r[4], 26);
        /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[5] = t5;
        VERIFY_BITS(r[5], 26);
        /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[6] = t6;
        VERIFY_BITS(r[6], 26);
        /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[7] = t7;
        VERIFY_BITS(r[7], 26);
        /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

        r[8] = c & M; c >>= 26; c += u8 * R1;
        VERIFY_BITS(r[8], 26);
        VERIFY_BITS(c, 39);
        /* [d u8 0 0 0 0 0 0 0 0 t9+c-u8*R1 r8-u8*R0 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        /* [d 0 0 0 0 0 0 0 0 0 t9+c r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        c   += d * R0 + t9;
        VERIFY_BITS(c, 45);
        /* [d 0 0 0 0 0 0 0 0 0 c-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[9] = c & (M >> 4); c >>= 22; c += d * (R1 << 4);
        VERIFY_BITS(r[9], 22);
        VERIFY_BITS(c, 46);
        /* [d 0 0 0 0 0 0 0 0 r9+((c-d*R1<<4)<<22)-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        /* [d 0 0 0 0 0 0 0 -d*R1 r9+(c<<22)-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

        d    = c * (R0 >> 4) + t0;
        VERIFY_BITS(d, 56);
        /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1 d-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[0] = d & M; d >>= 26;
        VERIFY_BITS(r[0], 26);
        VERIFY_BITS(d, 30);
        /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1+d r0-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        d   += c * (R1 >> 4) + t1;
        VERIFY_BITS(d, 53);
        VERIFY_CHECK(d <= 0x10000003FFFFBFULL);
        /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 d-c*R1>>4 r0-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        /* [r9 r8 r7 r6 r5 r4 r3 t2 d r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[1] = d & M; d >>= 26;
        VERIFY_BITS(r[1], 26);
        VERIFY_BITS(d, 27);
        VERIFY_CHECK(d <= 0x4000000ULL);
        /* [r9 r8 r7 r6 r5 r4 r3 t2+d r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        d   += t2;
        VERIFY_BITS(d, 27);
        /* [r9 r8 r7 r6 r5 r4 r3 d r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[2] = d;
        VERIFY_BITS(r[2], 27);
        /* [r9 r8 r7 r6 r5 r4 r3 r2 r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    };
#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= 8);
    secp256k1_fe_verify(a);
#endif
    secp256k1_fe_sqr_inner(r->n, a->n);
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

void CPubKey::ecmult::secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe * SECP256K1_RESTRICT b) {
    auto secp256k1_fe_mul_inner = [](uint32_t *r, const uint32_t *a, const uint32_t * SECP256K1_RESTRICT b) {
        uint64_t c, d;
        uint64_t u0, u1, u2, u3, u4, u5, u6, u7, u8;
        uint32_t t9, t1, t0, t2, t3, t4, t5, t6, t7;
        const uint32_t M = 0x3FFFFFFUL, R0 = 0x3D10UL, R1 = 0x400UL;

        VERIFY_BITS(a[0], 30);
        VERIFY_BITS(a[1], 30);
        VERIFY_BITS(a[2], 30);
        VERIFY_BITS(a[3], 30);
        VERIFY_BITS(a[4], 30);
        VERIFY_BITS(a[5], 30);
        VERIFY_BITS(a[6], 30);
        VERIFY_BITS(a[7], 30);
        VERIFY_BITS(a[8], 30);
        VERIFY_BITS(a[9], 26);
        VERIFY_BITS(b[0], 30);
        VERIFY_BITS(b[1], 30);
        VERIFY_BITS(b[2], 30);
        VERIFY_BITS(b[3], 30);
        VERIFY_BITS(b[4], 30);
        VERIFY_BITS(b[5], 30);
        VERIFY_BITS(b[6], 30);
        VERIFY_BITS(b[7], 30);
        VERIFY_BITS(b[8], 30);
        VERIFY_BITS(b[9], 26);

        /** [... a b c] is a shorthand for ... + a<<52 + b<<26 + c<<0 mod n.
         *  px is a shorthand for sum(a[i]*b[x-i], i=0..x).
         *  Note that [x 0 0 0 0 0 0 0 0 0 0] = [x*R1 x*R0].
         */

        d  = (uint64_t)a[0] * b[9]
           + (uint64_t)a[1] * b[8]
           + (uint64_t)a[2] * b[7]
           + (uint64_t)a[3] * b[6]
           + (uint64_t)a[4] * b[5]
           + (uint64_t)a[5] * b[4]
           + (uint64_t)a[6] * b[3]
           + (uint64_t)a[7] * b[2]
           + (uint64_t)a[8] * b[1]
           + (uint64_t)a[9] * b[0];
        /* VERIFY_BITS(d, 64); */
        /* [d 0 0 0 0 0 0 0 0 0] = [p9 0 0 0 0 0 0 0 0 0] */
        t9 = d & M; d >>= 26;
        VERIFY_BITS(t9, 26);
        VERIFY_BITS(d, 38);
        /* [d t9 0 0 0 0 0 0 0 0 0] = [p9 0 0 0 0 0 0 0 0 0] */

        c  = (uint64_t)a[0] * b[0];
        VERIFY_BITS(c, 60);
        /* [d t9 0 0 0 0 0 0 0 0 c] = [p9 0 0 0 0 0 0 0 0 p0] */
        d += (uint64_t)a[1] * b[9]
           + (uint64_t)a[2] * b[8]
           + (uint64_t)a[3] * b[7]
           + (uint64_t)a[4] * b[6]
           + (uint64_t)a[5] * b[5]
           + (uint64_t)a[6] * b[4]
           + (uint64_t)a[7] * b[3]
           + (uint64_t)a[8] * b[2]
           + (uint64_t)a[9] * b[1];
        VERIFY_BITS(d, 63);
        /* [d t9 0 0 0 0 0 0 0 0 c] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
        u0 = d & M; d >>= 26; c += u0 * R0;
        VERIFY_BITS(u0, 26);
        VERIFY_BITS(d, 37);
        VERIFY_BITS(c, 61);
        /* [d u0 t9 0 0 0 0 0 0 0 0 c-u0*R0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
        t0 = c & M; c >>= 26; c += u0 * R1;
        VERIFY_BITS(t0, 26);
        VERIFY_BITS(c, 37);
        /* [d u0 t9 0 0 0 0 0 0 0 c-u0*R1 t0-u0*R0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
        /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */

        c += (uint64_t)a[0] * b[1]
           + (uint64_t)a[1] * b[0];
        VERIFY_BITS(c, 62);
        /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p10 p9 0 0 0 0 0 0 0 p1 p0] */
        d += (uint64_t)a[2] * b[9]
           + (uint64_t)a[3] * b[8]
           + (uint64_t)a[4] * b[7]
           + (uint64_t)a[5] * b[6]
           + (uint64_t)a[6] * b[5]
           + (uint64_t)a[7] * b[4]
           + (uint64_t)a[8] * b[3]
           + (uint64_t)a[9] * b[2];
        VERIFY_BITS(d, 63);
        /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
        u1 = d & M; d >>= 26; c += u1 * R0;
        VERIFY_BITS(u1, 26);
        VERIFY_BITS(d, 37);
        VERIFY_BITS(c, 63);
        /* [d u1 0 t9 0 0 0 0 0 0 0 c-u1*R0 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
        t1 = c & M; c >>= 26; c += u1 * R1;
        VERIFY_BITS(t1, 26);
        VERIFY_BITS(c, 38);
        /* [d u1 0 t9 0 0 0 0 0 0 c-u1*R1 t1-u1*R0 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
        /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */

        c += (uint64_t)a[0] * b[2]
           + (uint64_t)a[1] * b[1]
           + (uint64_t)a[2] * b[0];
        VERIFY_BITS(c, 62);
        /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
        d += (uint64_t)a[3] * b[9]
           + (uint64_t)a[4] * b[8]
           + (uint64_t)a[5] * b[7]
           + (uint64_t)a[6] * b[6]
           + (uint64_t)a[7] * b[5]
           + (uint64_t)a[8] * b[4]
           + (uint64_t)a[9] * b[3];
        VERIFY_BITS(d, 63);
        /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
        u2 = d & M; d >>= 26; c += u2 * R0;
        VERIFY_BITS(u2, 26);
        VERIFY_BITS(d, 37);
        VERIFY_BITS(c, 63);
        /* [d u2 0 0 t9 0 0 0 0 0 0 c-u2*R0 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
        t2 = c & M; c >>= 26; c += u2 * R1;
        VERIFY_BITS(t2, 26);
        VERIFY_BITS(c, 38);
        /* [d u2 0 0 t9 0 0 0 0 0 c-u2*R1 t2-u2*R0 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
        /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */

        c += (uint64_t)a[0] * b[3]
           + (uint64_t)a[1] * b[2]
           + (uint64_t)a[2] * b[1]
           + (uint64_t)a[3] * b[0];
        VERIFY_BITS(c, 63);
        /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
        d += (uint64_t)a[4] * b[9]
           + (uint64_t)a[5] * b[8]
           + (uint64_t)a[6] * b[7]
           + (uint64_t)a[7] * b[6]
           + (uint64_t)a[8] * b[5]
           + (uint64_t)a[9] * b[4];
        VERIFY_BITS(d, 63);
        /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
        u3 = d & M; d >>= 26; c += u3 * R0;
        VERIFY_BITS(u3, 26);
        VERIFY_BITS(d, 37);
        /* VERIFY_BITS(c, 64); */
        /* [d u3 0 0 0 t9 0 0 0 0 0 c-u3*R0 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
        t3 = c & M; c >>= 26; c += u3 * R1;
        VERIFY_BITS(t3, 26);
        VERIFY_BITS(c, 39);
        /* [d u3 0 0 0 t9 0 0 0 0 c-u3*R1 t3-u3*R0 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
        /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */

        c += (uint64_t)a[0] * b[4]
           + (uint64_t)a[1] * b[3]
           + (uint64_t)a[2] * b[2]
           + (uint64_t)a[3] * b[1]
           + (uint64_t)a[4] * b[0];
        VERIFY_BITS(c, 63);
        /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
        d += (uint64_t)a[5] * b[9]
           + (uint64_t)a[6] * b[8]
           + (uint64_t)a[7] * b[7]
           + (uint64_t)a[8] * b[6]
           + (uint64_t)a[9] * b[5];
        VERIFY_BITS(d, 62);
        /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
        u4 = d & M; d >>= 26; c += u4 * R0;
        VERIFY_BITS(u4, 26);
        VERIFY_BITS(d, 36);
        /* VERIFY_BITS(c, 64); */
        /* [d u4 0 0 0 0 t9 0 0 0 0 c-u4*R0 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
        t4 = c & M; c >>= 26; c += u4 * R1;
        VERIFY_BITS(t4, 26);
        VERIFY_BITS(c, 39);
        /* [d u4 0 0 0 0 t9 0 0 0 c-u4*R1 t4-u4*R0 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
        /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */

        c += (uint64_t)a[0] * b[5]
           + (uint64_t)a[1] * b[4]
           + (uint64_t)a[2] * b[3]
           + (uint64_t)a[3] * b[2]
           + (uint64_t)a[4] * b[1]
           + (uint64_t)a[5] * b[0];
        VERIFY_BITS(c, 63);
        /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
        d += (uint64_t)a[6] * b[9]
           + (uint64_t)a[7] * b[8]
           + (uint64_t)a[8] * b[7]
           + (uint64_t)a[9] * b[6];
        VERIFY_BITS(d, 62);
        /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
        u5 = d & M; d >>= 26; c += u5 * R0;
        VERIFY_BITS(u5, 26);
        VERIFY_BITS(d, 36);
        /* VERIFY_BITS(c, 64); */
        /* [d u5 0 0 0 0 0 t9 0 0 0 c-u5*R0 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
        t5 = c & M; c >>= 26; c += u5 * R1;
        VERIFY_BITS(t5, 26);
        VERIFY_BITS(c, 39);
        /* [d u5 0 0 0 0 0 t9 0 0 c-u5*R1 t5-u5*R0 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
        /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */

        c += (uint64_t)a[0] * b[6]
           + (uint64_t)a[1] * b[5]
           + (uint64_t)a[2] * b[4]
           + (uint64_t)a[3] * b[3]
           + (uint64_t)a[4] * b[2]
           + (uint64_t)a[5] * b[1]
           + (uint64_t)a[6] * b[0];
        VERIFY_BITS(c, 63);
        /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
        d += (uint64_t)a[7] * b[9]
           + (uint64_t)a[8] * b[8]
           + (uint64_t)a[9] * b[7];
        VERIFY_BITS(d, 61);
        /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
        u6 = d & M; d >>= 26; c += u6 * R0;
        VERIFY_BITS(u6, 26);
        VERIFY_BITS(d, 35);
        /* VERIFY_BITS(c, 64); */
        /* [d u6 0 0 0 0 0 0 t9 0 0 c-u6*R0 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
        t6 = c & M; c >>= 26; c += u6 * R1;
        VERIFY_BITS(t6, 26);
        VERIFY_BITS(c, 39);
        /* [d u6 0 0 0 0 0 0 t9 0 c-u6*R1 t6-u6*R0 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
        /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */

        c += (uint64_t)a[0] * b[7]
           + (uint64_t)a[1] * b[6]
           + (uint64_t)a[2] * b[5]
           + (uint64_t)a[3] * b[4]
           + (uint64_t)a[4] * b[3]
           + (uint64_t)a[5] * b[2]
           + (uint64_t)a[6] * b[1]
           + (uint64_t)a[7] * b[0];
        /* VERIFY_BITS(c, 64); */
        VERIFY_CHECK(c <= 0x8000007C00000007ULL);
        /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
        d += (uint64_t)a[8] * b[9]
           + (uint64_t)a[9] * b[8];
        VERIFY_BITS(d, 58);
        /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
        u7 = d & M; d >>= 26; c += u7 * R0;
        VERIFY_BITS(u7, 26);
        VERIFY_BITS(d, 32);
        /* VERIFY_BITS(c, 64); */
        VERIFY_CHECK(c <= 0x800001703FFFC2F7ULL);
        /* [d u7 0 0 0 0 0 0 0 t9 0 c-u7*R0 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
        t7 = c & M; c >>= 26; c += u7 * R1;
        VERIFY_BITS(t7, 26);
        VERIFY_BITS(c, 38);
        /* [d u7 0 0 0 0 0 0 0 t9 c-u7*R1 t7-u7*R0 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
        /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */

        c += (uint64_t)a[0] * b[8]
           + (uint64_t)a[1] * b[7]
           + (uint64_t)a[2] * b[6]
           + (uint64_t)a[3] * b[5]
           + (uint64_t)a[4] * b[4]
           + (uint64_t)a[5] * b[3]
           + (uint64_t)a[6] * b[2]
           + (uint64_t)a[7] * b[1]
           + (uint64_t)a[8] * b[0];
        /* VERIFY_BITS(c, 64); */
        VERIFY_CHECK(c <= 0x9000007B80000008ULL);
        /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        d += (uint64_t)a[9] * b[9];
        VERIFY_BITS(d, 57);
        /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        u8 = d & M; d >>= 26; c += u8 * R0;
        VERIFY_BITS(u8, 26);
        VERIFY_BITS(d, 31);
        /* VERIFY_BITS(c, 64); */
        VERIFY_CHECK(c <= 0x9000016FBFFFC2F8ULL);
        /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 t4 t3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

        r[3] = t3;
        VERIFY_BITS(r[3], 26);
        /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 t4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[4] = t4;
        VERIFY_BITS(r[4], 26);
        /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[5] = t5;
        VERIFY_BITS(r[5], 26);
        /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[6] = t6;
        VERIFY_BITS(r[6], 26);
        /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[7] = t7;
        VERIFY_BITS(r[7], 26);
        /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

        r[8] = c & M; c >>= 26; c += u8 * R1;
        VERIFY_BITS(r[8], 26);
        VERIFY_BITS(c, 39);
        /* [d u8 0 0 0 0 0 0 0 0 t9+c-u8*R1 r8-u8*R0 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        /* [d 0 0 0 0 0 0 0 0 0 t9+c r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        c   += d * R0 + t9;
        VERIFY_BITS(c, 45);
        /* [d 0 0 0 0 0 0 0 0 0 c-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[9] = c & (M >> 4); c >>= 22; c += d * (R1 << 4);
        VERIFY_BITS(r[9], 22);
        VERIFY_BITS(c, 46);
        /* [d 0 0 0 0 0 0 0 0 r9+((c-d*R1<<4)<<22)-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        /* [d 0 0 0 0 0 0 0 -d*R1 r9+(c<<22)-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

        d    = c * (R0 >> 4) + t0;
        VERIFY_BITS(d, 56);
        /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1 d-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[0] = d & M; d >>= 26;
        VERIFY_BITS(r[0], 26);
        VERIFY_BITS(d, 30);
        /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1+d r0-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        d   += c * (R1 >> 4) + t1;
        VERIFY_BITS(d, 53);
        VERIFY_CHECK(d <= 0x10000003FFFFBFULL);
        /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 d-c*R1>>4 r0-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        /* [r9 r8 r7 r6 r5 r4 r3 t2 d r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[1] = d & M; d >>= 26;
        VERIFY_BITS(r[1], 26);
        VERIFY_BITS(d, 27);
        VERIFY_CHECK(d <= 0x4000000ULL);
        /* [r9 r8 r7 r6 r5 r4 r3 t2+d r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        d   += t2;
        VERIFY_BITS(d, 27);
        /* [r9 r8 r7 r6 r5 r4 r3 d r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
        r[2] = d;
        VERIFY_BITS(r[2], 27);
        /* [r9 r8 r7 r6 r5 r4 r3 r2 r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    };
#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= 8);
    VERIFY_CHECK(b->magnitude <= 8);
    secp256k1_fe_verify(a);
    secp256k1_fe_verify(b);
    VERIFY_CHECK(r != b);
#endif
    secp256k1_fe_mul_inner(r->n, a->n, b->n);
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

void CPubKey::ecmult::secp256k1_fe_set_int(secp256k1_fe *r, int a) {
    r->n[0] = a;
    r->n[1] = r->n[2] = r->n[3] = r->n[4] = r->n[5] = r->n[6] = r->n[7] = r->n[8] = r->n[9] = 0;
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verify(r);
#endif
}

void CPubKey::ecmult::secp256k1_fe_negate(secp256k1_fe *r, const secp256k1_fe *a, int m) {
#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= m);
    secp256k1_fe_verify(a);
#endif
    r->n[0] = 0x3FFFC2FUL * 2 * (m + 1) - a->n[0];
    r->n[1] = 0x3FFFFBFUL * 2 * (m + 1) - a->n[1];
    r->n[2] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[2];
    r->n[3] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[3];
    r->n[4] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[4];
    r->n[5] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[5];
    r->n[6] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[6];
    r->n[7] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[7];
    r->n[8] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[8];
    r->n[9] = 0x03FFFFFUL * 2 * (m + 1) - a->n[9];
#ifdef VERIFY
    r->magnitude = m + 1;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

int CPubKey::ecmult::secp256k1_fe_normalizes_to_zero(const secp256k1_fe *r) {
    uint32_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4],
             t5 = r->n[5], t6 = r->n[6], t7 = r->n[7], t8 = r->n[8], t9 = r->n[9];

    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    uint32_t z0, z1;

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL; z0  = t0; z1  = t0 ^ 0x3D0UL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL; z0 |= t1; z1 &= t1 ^ 0x40UL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; z0 |= t3; z1 &= t3;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; z0 |= t4; z1 &= t4;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; z0 |= t5; z1 &= t5;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; z0 |= t6; z1 &= t6;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; z0 |= t7; z1 &= t7;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; z0 |= t8; z1 &= t8;
                                         z0 |= t9; z1 &= t9 ^ 0x3C00000UL;

    /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t9 >> 23 == 0);

    //DEBUGCS_CHECK((std::string("step1 z0, z1: ") + std::to_string(z0) + "," + std::to_string(z1)).c_str());
    return (z0 == 0) | (z1 == 0x3FFFFFFUL);
}

int CPubKey::ecmult::secp256k1_fe_equal(const secp256k1_fe *a, const secp256k1_fe *b) {
    secp256k1_fe na;
    secp256k1_fe_negate(&na, a, 1);
    secp256k1_fe_add(&na, b);
    return secp256k1_fe_normalizes_to_zero(&na);
}

int CPubKey::ecmult::secp256k1_fe_sqrt(secp256k1_fe *r, const secp256k1_fe *a) {
    /** Given that p is congruent to 3 mod 4, we can compute the square root of
     *  a mod p as the (p+1)/4'th power of a.
     *
     *  As (p+1)/4 is an even number, it will have the same result for a and for
     *  (-a). Only one of these two numbers actually has a square root however,
     *  so we test at the end by squaring and comparing to the input.
     *  Also because (p+1)/4 is an even number, the computed square root is
     *  itself always a square (a ** ((p+1)/4) is the square of a ** ((p+1)/8)).
     */
    secp256k1_fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
    int j;

    /** The binary representation of (p + 1)/4 has 3 blocks of 1s, with lengths in
     *  { 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
     *  1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
     */

    secp256k1_fe_sqr(&x2, a);
    secp256k1_fe_mul(&x2, &x2, a);

    secp256k1_fe_sqr(&x3, &x2);
    secp256k1_fe_mul(&x3, &x3, a);

    x6 = x3;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x6, &x6);
    }
    secp256k1_fe_mul(&x6, &x6, &x3);

    x9 = x6;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x9, &x9);
    }
    secp256k1_fe_mul(&x9, &x9, &x3);

    x11 = x9;
    for (j=0; j<2; j++) {
        secp256k1_fe_sqr(&x11, &x11);
    }
    secp256k1_fe_mul(&x11, &x11, &x2);

    x22 = x11;
    for (j=0; j<11; j++) {
        secp256k1_fe_sqr(&x22, &x22);
    }
    secp256k1_fe_mul(&x22, &x22, &x11);

    x44 = x22;
    for (j=0; j<22; j++) {
        secp256k1_fe_sqr(&x44, &x44);
    }
    secp256k1_fe_mul(&x44, &x44, &x22);

    x88 = x44;
    for (j=0; j<44; j++) {
        secp256k1_fe_sqr(&x88, &x88);
    }
    secp256k1_fe_mul(&x88, &x88, &x44);

    x176 = x88;
    for (j=0; j<88; j++) {
        secp256k1_fe_sqr(&x176, &x176);
    }
    secp256k1_fe_mul(&x176, &x176, &x88);

    x220 = x176;
    for (j=0; j<44; j++) {
        secp256k1_fe_sqr(&x220, &x220);
    }
    secp256k1_fe_mul(&x220, &x220, &x44);

    x223 = x220;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x223, &x223);
    }
    secp256k1_fe_mul(&x223, &x223, &x3);

    /* The final result is then assembled using a sliding window over the blocks. */

    t1 = x223;
    for (j=0; j<23; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, &x22);
    for (j=0; j<6; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, &x2);
    secp256k1_fe_sqr(&t1, &t1);
    secp256k1_fe_sqr(r, &t1);

    /* Check that a square root was actually calculated */

    secp256k1_fe_sqr(&t1, r);
    return secp256k1_fe_equal(&t1, a);
}

int CPubKey::ecmult::secp256k1_ge_set_xquad(secp256k1_ge *r, const secp256k1_fe *x) {
    secp256k1_fe x2, x3, c;
    r->x = *x;
    secp256k1_fe_sqr(&x2, x);
    secp256k1_fe_mul(&x3, x, &x2);
    r->infinity = 0;
    secp256k1_fe_set_int(&c, CURVE_B);
    secp256k1_fe_add(&c, &x3);
    //DEBUGCS_CHECK("step1");
    return secp256k1_fe_sqrt(&r->y, &c);
}

int CPubKey::ecmult::secp256k1_fe_is_odd(const secp256k1_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    secp256k1_fe_verify(a);
#endif
    return a->n[0] & 1;
}

int CPubKey::ecmult::secp256k1_ge_set_xo_var(secp256k1_ge *r, const secp256k1_fe *x, int odd) {
    if (! secp256k1_ge_set_xquad(r, x))
        return 0;

    secp256k1_fe_normalize_var(&r->y);
    if (secp256k1_fe_is_odd(&r->y) != odd)
        secp256k1_fe_negate(&r->y, &r->y, 1);

    return 1;
}

void CPubKey::ecmult::secp256k1_gej_set_ge(secp256k1_gej *r, const secp256k1_ge *a) {
   r->infinity = a->infinity;
   r->x = a->x;
   r->y = a->y;
   secp256k1_fe_set_int(&r->z, 1);
}

void CPubKey::secp256k1_scalar_sqr_512(uint32_t *l, const secp256k1_unit *a) {
    /* 96 bit accumulator. */
    uint32_t c0 = 0, c1 = 0, c2 = 0;

    /* l[0..15] = a[0..7]^2. */
    muladd_fast(a->d[0], a->d[0]);
    extract_fast(l[0]);
    muladd2(a->d[0], a->d[1]);
    extract(l[1]);
    muladd2(a->d[0], a->d[2]);
    muladd(a->d[1], a->d[1]);
    extract(l[2]);
    muladd2(a->d[0], a->d[3]);
    muladd2(a->d[1], a->d[2]);
    extract(l[3]);
    muladd2(a->d[0], a->d[4]);
    muladd2(a->d[1], a->d[3]);
    muladd(a->d[2], a->d[2]);
    extract(l[4]);
    muladd2(a->d[0], a->d[5]);
    muladd2(a->d[1], a->d[4]);
    muladd2(a->d[2], a->d[3]);
    extract(l[5]);
    muladd2(a->d[0], a->d[6]);
    muladd2(a->d[1], a->d[5]);
    muladd2(a->d[2], a->d[4]);
    muladd(a->d[3], a->d[3]);
    extract(l[6]);
    muladd2(a->d[0], a->d[7]);
    muladd2(a->d[1], a->d[6]);
    muladd2(a->d[2], a->d[5]);
    muladd2(a->d[3], a->d[4]);
    extract(l[7]);
    muladd2(a->d[1], a->d[7]);
    muladd2(a->d[2], a->d[6]);
    muladd2(a->d[3], a->d[5]);
    muladd(a->d[4], a->d[4]);
    extract(l[8]);
    muladd2(a->d[2], a->d[7]);
    muladd2(a->d[3], a->d[6]);
    muladd2(a->d[4], a->d[5]);
    extract(l[9]);
    muladd2(a->d[3], a->d[7]);
    muladd2(a->d[4], a->d[6]);
    muladd(a->d[5], a->d[5]);
    extract(l[10]);
    muladd2(a->d[4], a->d[7]);
    muladd2(a->d[5], a->d[6]);
    extract(l[11]);
    muladd2(a->d[5], a->d[7]);
    muladd(a->d[6], a->d[6]);
    extract(l[12]);
    muladd2(a->d[6], a->d[7]);
    extract(l[13]);
    muladd_fast(a->d[7], a->d[7]);
    extract_fast(l[14]);
    VERIFY_CHECK(c1 == 0);
    l[15] = c0;
}

void CPubKey::secp256k1_scalar_reduce_512(secp256k1_unit *r, const uint32_t *l) {
    uint64_t c;
    uint32_t n0 = l[8], n1 = l[9], n2 = l[10], n3 = l[11], n4 = l[12], n5 = l[13], n6 = l[14], n7 = l[15];
    uint32_t m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12;
    uint32_t p0, p1, p2, p3, p4, p5, p6, p7, p8;

    /* 96 bit accumulator. */
    uint32_t c0, c1, c2;

    /* Reduce 512 bits into 385. */
    /* m[0..12] = l[0..7] + n[0..7] * SECP256K1_N_C. */
    c0 = l[0]; c1 = 0; c2 = 0;
    muladd_fast(n0, SECP256K1_N_C_0);
    extract_fast(m0);
    sumadd_fast(l[1]);
    muladd(n1, SECP256K1_N_C_0);
    muladd(n0, SECP256K1_N_C_1);
    extract(m1);
    sumadd(l[2]);
    muladd(n2, SECP256K1_N_C_0);
    muladd(n1, SECP256K1_N_C_1);
    muladd(n0, SECP256K1_N_C_2);
    extract(m2);
    sumadd(l[3]);
    muladd(n3, SECP256K1_N_C_0);
    muladd(n2, SECP256K1_N_C_1);
    muladd(n1, SECP256K1_N_C_2);
    muladd(n0, SECP256K1_N_C_3);
    extract(m3);
    sumadd(l[4]);
    muladd(n4, SECP256K1_N_C_0);
    muladd(n3, SECP256K1_N_C_1);
    muladd(n2, SECP256K1_N_C_2);
    muladd(n1, SECP256K1_N_C_3);
    sumadd(n0);
    extract(m4);
    sumadd(l[5]);
    muladd(n5, SECP256K1_N_C_0);
    muladd(n4, SECP256K1_N_C_1);
    muladd(n3, SECP256K1_N_C_2);
    muladd(n2, SECP256K1_N_C_3);
    sumadd(n1);
    extract(m5);
    sumadd(l[6]);
    muladd(n6, SECP256K1_N_C_0);
    muladd(n5, SECP256K1_N_C_1);
    muladd(n4, SECP256K1_N_C_2);
    muladd(n3, SECP256K1_N_C_3);
    sumadd(n2);
    extract(m6);
    sumadd(l[7]);
    muladd(n7, SECP256K1_N_C_0);
    muladd(n6, SECP256K1_N_C_1);
    muladd(n5, SECP256K1_N_C_2);
    muladd(n4, SECP256K1_N_C_3);
    sumadd(n3);
    extract(m7);
    muladd(n7, SECP256K1_N_C_1);
    muladd(n6, SECP256K1_N_C_2);
    muladd(n5, SECP256K1_N_C_3);
    sumadd(n4);
    extract(m8);
    muladd(n7, SECP256K1_N_C_2);
    muladd(n6, SECP256K1_N_C_3);
    sumadd(n5);
    extract(m9);
    muladd(n7, SECP256K1_N_C_3);
    sumadd(n6);
    extract(m10);
    sumadd_fast(n7);
    extract_fast(m11);
    VERIFY_CHECK(c0 <= 1);
    m12 = c0;

    /* Reduce 385 bits into 258. */
    /* p[0..8] = m[0..7] + m[8..12] * SECP256K1_N_C. */
    c0 = m0; c1 = 0; c2 = 0;
    muladd_fast(m8, SECP256K1_N_C_0);
    extract_fast(p0);
    sumadd_fast(m1);
    muladd(m9, SECP256K1_N_C_0);
    muladd(m8, SECP256K1_N_C_1);
    extract(p1);
    sumadd(m2);
    muladd(m10, SECP256K1_N_C_0);
    muladd(m9, SECP256K1_N_C_1);
    muladd(m8, SECP256K1_N_C_2);
    extract(p2);
    sumadd(m3);
    muladd(m11, SECP256K1_N_C_0);
    muladd(m10, SECP256K1_N_C_1);
    muladd(m9, SECP256K1_N_C_2);
    muladd(m8, SECP256K1_N_C_3);
    extract(p3);
    sumadd(m4);
    muladd(m12, SECP256K1_N_C_0);
    muladd(m11, SECP256K1_N_C_1);
    muladd(m10, SECP256K1_N_C_2);
    muladd(m9, SECP256K1_N_C_3);
    sumadd(m8);
    extract(p4);
    sumadd(m5);
    muladd(m12, SECP256K1_N_C_1);
    muladd(m11, SECP256K1_N_C_2);
    muladd(m10, SECP256K1_N_C_3);
    sumadd(m9);
    extract(p5);
    sumadd(m6);
    muladd(m12, SECP256K1_N_C_2);
    muladd(m11, SECP256K1_N_C_3);
    sumadd(m10);
    extract(p6);
    sumadd_fast(m7);
    muladd_fast(m12, SECP256K1_N_C_3);
    sumadd_fast(m11);
    extract_fast(p7);
    p8 = c0 + m12;
    VERIFY_CHECK(p8 <= 2);

    /* Reduce 258 bits into 256. */
    /* r[0..7] = p[0..7] + p[8] * SECP256K1_N_C. */
    c = p0 + (uint64_t)SECP256K1_N_C_0 * p8;
    r->d[0] = c & 0xFFFFFFFFUL; c >>= 32;
    c += p1 + (uint64_t)SECP256K1_N_C_1 * p8;
    r->d[1] = c & 0xFFFFFFFFUL; c >>= 32;
    c += p2 + (uint64_t)SECP256K1_N_C_2 * p8;
    r->d[2] = c & 0xFFFFFFFFUL; c >>= 32;
    c += p3 + (uint64_t)SECP256K1_N_C_3 * p8;
    r->d[3] = c & 0xFFFFFFFFUL; c >>= 32;
    c += p4 + (uint64_t)p8;
    r->d[4] = c & 0xFFFFFFFFUL; c >>= 32;
    c += p5;
    r->d[5] = c & 0xFFFFFFFFUL; c >>= 32;
    c += p6;
    r->d[6] = c & 0xFFFFFFFFUL; c >>= 32;
    c += p7;
    r->d[7] = c & 0xFFFFFFFFUL; c >>= 32;

    /* Final reduction of r. */
    secp256k1_scalar_reduce(r, c + secp256k1_scalar_check_overflow(r));
}

void CPubKey::secp256k1_scalar_sqr(secp256k1_unit *r, const secp256k1_unit *a) {
    uint32_t l[16];
    secp256k1_scalar_sqr_512(l, a);
    secp256k1_scalar_reduce_512(r, l);
}

void CPubKey::secp256k1_scalar_mul_512(uint32_t *l, const secp256k1_unit *a, const secp256k1_unit *b) {
    /* 96 bit accumulator. */
    uint32_t c0 = 0, c1 = 0, c2 = 0;

    /* l[0..15] = a[0..7] * b[0..7]. */
    muladd_fast(a->d[0], b->d[0]);
    extract_fast(l[0]);
    muladd(a->d[0], b->d[1]);
    muladd(a->d[1], b->d[0]);
    extract(l[1]);
    muladd(a->d[0], b->d[2]);
    muladd(a->d[1], b->d[1]);
    muladd(a->d[2], b->d[0]);
    extract(l[2]);
    muladd(a->d[0], b->d[3]);
    muladd(a->d[1], b->d[2]);
    muladd(a->d[2], b->d[1]);
    muladd(a->d[3], b->d[0]);
    extract(l[3]);
    muladd(a->d[0], b->d[4]);
    muladd(a->d[1], b->d[3]);
    muladd(a->d[2], b->d[2]);
    muladd(a->d[3], b->d[1]);
    muladd(a->d[4], b->d[0]);
    extract(l[4]);
    muladd(a->d[0], b->d[5]);
    muladd(a->d[1], b->d[4]);
    muladd(a->d[2], b->d[3]);
    muladd(a->d[3], b->d[2]);
    muladd(a->d[4], b->d[1]);
    muladd(a->d[5], b->d[0]);
    extract(l[5]);
    muladd(a->d[0], b->d[6]);
    muladd(a->d[1], b->d[5]);
    muladd(a->d[2], b->d[4]);
    muladd(a->d[3], b->d[3]);
    muladd(a->d[4], b->d[2]);
    muladd(a->d[5], b->d[1]);
    muladd(a->d[6], b->d[0]);
    extract(l[6]);
    muladd(a->d[0], b->d[7]);
    muladd(a->d[1], b->d[6]);
    muladd(a->d[2], b->d[5]);
    muladd(a->d[3], b->d[4]);
    muladd(a->d[4], b->d[3]);
    muladd(a->d[5], b->d[2]);
    muladd(a->d[6], b->d[1]);
    muladd(a->d[7], b->d[0]);
    extract(l[7]);
    muladd(a->d[1], b->d[7]);
    muladd(a->d[2], b->d[6]);
    muladd(a->d[3], b->d[5]);
    muladd(a->d[4], b->d[4]);
    muladd(a->d[5], b->d[3]);
    muladd(a->d[6], b->d[2]);
    muladd(a->d[7], b->d[1]);
    extract(l[8]);
    muladd(a->d[2], b->d[7]);
    muladd(a->d[3], b->d[6]);
    muladd(a->d[4], b->d[5]);
    muladd(a->d[5], b->d[4]);
    muladd(a->d[6], b->d[3]);
    muladd(a->d[7], b->d[2]);
    extract(l[9]);
    muladd(a->d[3], b->d[7]);
    muladd(a->d[4], b->d[6]);
    muladd(a->d[5], b->d[5]);
    muladd(a->d[6], b->d[4]);
    muladd(a->d[7], b->d[3]);
    extract(l[10]);
    muladd(a->d[4], b->d[7]);
    muladd(a->d[5], b->d[6]);
    muladd(a->d[6], b->d[5]);
    muladd(a->d[7], b->d[4]);
    extract(l[11]);
    muladd(a->d[5], b->d[7]);
    muladd(a->d[6], b->d[6]);
    muladd(a->d[7], b->d[5]);
    extract(l[12]);
    muladd(a->d[6], b->d[7]);
    muladd(a->d[7], b->d[6]);
    extract(l[13]);
    muladd_fast(a->d[7], b->d[7]);
    extract_fast(l[14]);
    VERIFY_CHECK(c1 == 0);
    l[15] = c0;
}

void CPubKey::secp256k1_scalar_mul(secp256k1_unit *r, const secp256k1_unit *a, const secp256k1_unit *b) {
    uint32_t l[16];
    secp256k1_scalar_mul_512(l, a, b);
    secp256k1_scalar_reduce_512(r, l);
}

void CPubKey::secp256k1_scalar_inverse(secp256k1_unit *r, const secp256k1_unit *x) {
#if defined(EXHAUSTIVE_TEST_ORDER)
    int i;
    *r = 0;
    for (i = 0; i < EXHAUSTIVE_TEST_ORDER; i++) {
        if ((i * *x) % EXHAUSTIVE_TEST_ORDER == 1)
            *r = i;
    }
    /* If this VERIFY_CHECK triggers we were given a noninvertible scalar (and thus
     * have a composite group order; fix it in exhaustive_tests.c). */
    VERIFY_CHECK(*r != 0);
}
#else
    secp256k1_unit *t;
    int i;
    /* First compute xN as x ^ (2^N - 1) for some values of N,
     * and uM as x ^ M for some values of M. */
    secp256k1_unit x2, x3, x6, x8, x14, x28, x56, x112, x126;
    secp256k1_unit u2, u5, u9, u11, u13;

    secp256k1_scalar_sqr(&u2, x);
    secp256k1_scalar_mul(&x2, &u2,  x);
    secp256k1_scalar_mul(&u5, &u2, &x2);
    secp256k1_scalar_mul(&x3, &u5,  &u2);
    secp256k1_scalar_mul(&u9, &x3, &u2);
    secp256k1_scalar_mul(&u11, &u9, &u2);
    secp256k1_scalar_mul(&u13, &u11, &u2);

    secp256k1_scalar_sqr(&x6, &u13);
    secp256k1_scalar_sqr(&x6, &x6);
    secp256k1_scalar_mul(&x6, &x6, &u11);

    secp256k1_scalar_sqr(&x8, &x6);
    secp256k1_scalar_sqr(&x8, &x8);
    secp256k1_scalar_mul(&x8, &x8,  &x2);

    secp256k1_scalar_sqr(&x14, &x8);
    for (i = 0; i < 5; i++) {
        secp256k1_scalar_sqr(&x14, &x14);
    }
    secp256k1_scalar_mul(&x14, &x14, &x6);

    secp256k1_scalar_sqr(&x28, &x14);
    for (i = 0; i < 13; i++) {
        secp256k1_scalar_sqr(&x28, &x28);
    }
    secp256k1_scalar_mul(&x28, &x28, &x14);

    secp256k1_scalar_sqr(&x56, &x28);
    for (i = 0; i < 27; i++) {
        secp256k1_scalar_sqr(&x56, &x56);
    }
    secp256k1_scalar_mul(&x56, &x56, &x28);

    secp256k1_scalar_sqr(&x112, &x56);
    for (i = 0; i < 55; i++) {
        secp256k1_scalar_sqr(&x112, &x112);
    }
    secp256k1_scalar_mul(&x112, &x112, &x56);

    secp256k1_scalar_sqr(&x126, &x112);
    for (i = 0; i < 13; i++) {
        secp256k1_scalar_sqr(&x126, &x126);
    }
    secp256k1_scalar_mul(&x126, &x126, &x14);

    /* Then accumulate the final result (t starts at x126). */
    t = &x126;
    for (i = 0; i < 3; i++) {
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u5); /* 101 */
    for (i = 0; i < 4; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 4; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u5); /* 101 */
    for (i = 0; i < 5; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u11); /* 1011 */
    for (i = 0; i < 4; i++) {
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u11); /* 1011 */
    for (i = 0; i < 4; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 5; i++) { /* 00 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 6; i++) { /* 00 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u13); /* 1101 */
    for (i = 0; i < 4; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u5); /* 101 */
    for (i = 0; i < 3; i++) {
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 5; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u9); /* 1001 */
    for (i = 0; i < 6; i++) { /* 000 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u5); /* 101 */
    for (i = 0; i < 10; i++) { /* 0000000 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 4; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 9; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x8); /* 11111111 */
    for (i = 0; i < 5; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u9); /* 1001 */
    for (i = 0; i < 6; i++) { /* 00 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u11); /* 1011 */
    for (i = 0; i < 4; i++) {
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u13); /* 1101 */
    for (i = 0; i < 5; i++) {
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x2); /* 11 */
    for (i = 0; i < 6; i++) { /* 00 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u13); /* 1101 */
    for (i = 0; i < 10; i++) { /* 000000 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u13); /* 1101 */
    for (i = 0; i < 4; i++) {
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u9); /* 1001 */
    for (i = 0; i < 6; i++) { /* 00000 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, x); /* 1 */
    for (i = 0; i < 8; i++) { /* 00 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(r, t, &x6); /* 111111 */
}

#endif

void CPubKey::secp256k1_scalar_inverse_var(secp256k1_unit *r, const secp256k1_unit *x) {
#if defined(USE_SCALAR_INV_BUILTIN)
    secp256k1_scalar_inverse(r, x);
#elif defined(USE_SCALAR_INV_NUM)
    unsigned char b[32];
    secp256k1_num n, m;
    secp256k1_scalar t = *x;
    secp256k1_scalar_get_b32(b, &t);
    secp256k1_num_set_bin(&n, b, 32);
    secp256k1_scalar_order_get_num(&m);
    secp256k1_num_mod_inverse(&n, &n, &m);
    secp256k1_num_get_bin(b, 32, &n);
    secp256k1_scalar_set_b32(r, b, NULL);
    /* Verify that the inverse was computed correctly, without GMP code. */
    secp256k1_scalar_mul(&t, &t, r);
    CHECK(secp256k1_scalar_is_one(&t));
#else
#error "Please select scalar inverse implementation"
#endif
}

void CPubKey::secp256k1_scalar_negate(secp256k1_unit *r, const secp256k1_unit *a) {
    uint32_t nonzero = 0xFFFFFFFFUL * (secp256k1_scalar_is_zero(a) == 0);
    uint64_t t = (uint64_t)(~a->d[0]) + SECP256K1_N_0 + 1;
    r->d[0] = t & nonzero; t >>= 32;
    t += (uint64_t)(~a->d[1]) + SECP256K1_N_1;
    r->d[1] = t & nonzero; t >>= 32;
    t += (uint64_t)(~a->d[2]) + SECP256K1_N_2;
    r->d[2] = t & nonzero; t >>= 32;
    t += (uint64_t)(~a->d[3]) + SECP256K1_N_3;
    r->d[3] = t & nonzero; t >>= 32;
    t += (uint64_t)(~a->d[4]) + SECP256K1_N_4;
    r->d[4] = t & nonzero; t >>= 32;
    t += (uint64_t)(~a->d[5]) + SECP256K1_N_5;
    r->d[5] = t & nonzero; t >>= 32;
    t += (uint64_t)(~a->d[6]) + SECP256K1_N_6;
    r->d[6] = t & nonzero; t >>= 32;
    t += (uint64_t)(~a->d[7]) + SECP256K1_N_7;
    r->d[7] = t & nonzero;
}

unsigned int CPubKey::secp256k1_scalar_get_bits(const secp256k1_unit *a, unsigned int offset, unsigned int count) {
    VERIFY_CHECK((offset + count - 1) >> 5 == offset >> 5);
    return (a->d[offset >> 5] >> (offset & 0x1F)) & ((1 << count) - 1);
}

unsigned int CPubKey::secp256k1_scalar_get_bits_var(const secp256k1_unit *a, unsigned int offset, unsigned int count) {
    VERIFY_CHECK(count < 32);
    VERIFY_CHECK(offset + count <= 256);
    if ((offset + count - 1) >> 5 == offset >> 5)
        return secp256k1_scalar_get_bits(a, offset, count);
    else {
        VERIFY_CHECK((offset >> 5) + 1 < 8);
        return ((a->d[offset >> 5] >> (offset & 0x1F)) | (a->d[(offset >> 5) + 1] << (32 - (offset & 0x1F)))) & ((((uint32_t)1) << count) - 1);
    }
}

void CPubKey::ecmult::secp256k1_fe_mul_int(secp256k1_fe *r, int a) {
    r->n[0] *= a;
    r->n[1] *= a;
    r->n[2] *= a;
    r->n[3] *= a;
    r->n[4] *= a;
    r->n[5] *= a;
    r->n[6] *= a;
    r->n[7] *= a;
    r->n[8] *= a;
    r->n[9] *= a;
#ifdef VERIFY
    r->magnitude *= a;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

void CPubKey::ecmult::secp256k1_gej_double_var(secp256k1_gej *r, const secp256k1_gej *a, secp256k1_fe *rzr) {
    /* Operations: 3 mul, 4 sqr, 0 normalize, 12 mul_int/add/negate.
     *
     * Note that there is an implementation described at
     *     https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
     * which trades a multiply for a square, but in practice this is actually slower,
     * mainly because it requires more normalizations.
     */
    secp256k1_fe t1,t2,t3,t4;
    /** For secp256k1, 2Q is infinity if and only if Q is infinity. This is because if 2Q = infinity,
     *  Q must equal -Q, or that Q.y == -(Q.y), or Q.y is 0. For a point on y^2 = x^3 + 7 to have
     *  y=0, x^3 must be -7 mod p. However, -7 has no cube root mod p.
     *
     *  Having said this, if this function receives a point on a sextic twist, e.g. by
     *  a fault attack, it is possible for y to be 0. This happens for y^2 = x^3 + 6,
     *  since -6 does have a cube root mod p. For this point, this function will not set
     *  the infinity flag even though the point doubles to infinity, and the result
     *  point will be gibberish (z = 0 but infinity = 0).
     */
    r->infinity = a->infinity;
    if (r->infinity) {
        if (rzr != NULL) {
            secp256k1_fe_set_int(rzr, 1);
        }
        return;
    }

    if (rzr != NULL) {
        *rzr = a->y;
        secp256k1_fe_normalize_weak(rzr);
        secp256k1_fe_mul_int(rzr, 2);
    }

    secp256k1_fe_mul(&r->z, &a->z, &a->y);
    secp256k1_fe_mul_int(&r->z, 2);       /* Z' = 2*Y*Z (2) */
    secp256k1_fe_sqr(&t1, &a->x);
    secp256k1_fe_mul_int(&t1, 3);         /* T1 = 3*X^2 (3) */
    secp256k1_fe_sqr(&t2, &t1);           /* T2 = 9*X^4 (1) */
    secp256k1_fe_sqr(&t3, &a->y);
    secp256k1_fe_mul_int(&t3, 2);         /* T3 = 2*Y^2 (2) */
    secp256k1_fe_sqr(&t4, &t3);
    secp256k1_fe_mul_int(&t4, 2);         /* T4 = 8*Y^4 (2) */
    secp256k1_fe_mul(&t3, &t3, &a->x);    /* T3 = 2*X*Y^2 (1) */
    r->x = t3;
    secp256k1_fe_mul_int(&r->x, 4);       /* X' = 8*X*Y^2 (4) */
    secp256k1_fe_negate(&r->x, &r->x, 4); /* X' = -8*X*Y^2 (5) */
    secp256k1_fe_add(&r->x, &t2);         /* X' = 9*X^4 - 8*X*Y^2 (6) */
    secp256k1_fe_negate(&t2, &t2, 1);     /* T2 = -9*X^4 (2) */
    secp256k1_fe_mul_int(&t3, 6);         /* T3 = 12*X*Y^2 (6) */
    secp256k1_fe_add(&t3, &t2);           /* T3 = 12*X*Y^2 - 9*X^4 (8) */
    secp256k1_fe_mul(&r->y, &t1, &t3);    /* Y' = 36*X^3*Y^2 - 27*X^6 (1) */
    secp256k1_fe_negate(&t2, &t4, 2);     /* T2 = -8*Y^4 (3) */
    secp256k1_fe_add(&r->y, &t2);         /* Y' = 36*X^3*Y^2 - 27*X^6 - 8*Y^4 (4) */
}

void CPubKey::ecmult::secp256k1_ge_set_gej_zinv(secp256k1_ge *r, const secp256k1_gej *a, const secp256k1_fe *zi) {
    secp256k1_fe zi2;
    secp256k1_fe zi3;
    secp256k1_fe_sqr(&zi2, zi);
    secp256k1_fe_mul(&zi3, &zi2, zi);
    secp256k1_fe_mul(&r->x, &a->x, &zi2);
    secp256k1_fe_mul(&r->y, &a->y, &zi3);
    r->infinity = a->infinity;
}

int CPubKey::ecmult::secp256k1_fe_normalizes_to_zero_var(const secp256k1_fe *r) {
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
    uint32_t z0, z1;
    uint32_t x;

    t0 = r->n[0];
    t9 = r->n[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    x = t9 >> 22;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL;

    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    z0 = t0 & 0x3FFFFFFUL;
    z1 = z0 ^ 0x3D0UL;

    /* Fast return path should catch the majority of cases */
    if ((z0 != 0UL) & (z1 != 0x3FFFFFFUL)) {
        return 0;
    }

    t1 = r->n[1];
    t2 = r->n[2];
    t3 = r->n[3];
    t4 = r->n[4];
    t5 = r->n[5];
    t6 = r->n[6];
    t7 = r->n[7];
    t8 = r->n[8];

    t9 &= 0x03FFFFFUL;
    t1 += (x << 6);

    t1 += (t0 >> 26);
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL; z0 |= t1; z1 &= t1 ^ 0x40UL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; z0 |= t3; z1 &= t3;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; z0 |= t4; z1 &= t4;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; z0 |= t5; z1 &= t5;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; z0 |= t6; z1 &= t6;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; z0 |= t7; z1 &= t7;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; z0 |= t8; z1 &= t8;
                                         z0 |= t9; z1 &= t9 ^ 0x3C00000UL;

    /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t9 >> 23 == 0);

    return (z0 == 0) | (z1 == 0x3FFFFFFUL);
}

void CPubKey::ecmult::secp256k1_gej_add_ge_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, secp256k1_fe *rzr) {
    /* 8 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
    secp256k1_fe z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;
    if (a->infinity) {
        VERIFY_CHECK(rzr == NULL);
        secp256k1_gej_set_ge(r, b);
        return;
    }
    if (b->infinity) {
        if (rzr != NULL) {
            secp256k1_fe_set_int(rzr, 1);
        }
        *r = *a;
        return;
    }
    r->infinity = 0;

    secp256k1_fe_sqr(&z12, &a->z);
    u1 = a->x; secp256k1_fe_normalize_weak(&u1);
    secp256k1_fe_mul(&u2, &b->x, &z12);
    s1 = a->y; secp256k1_fe_normalize_weak(&s1);
    secp256k1_fe_mul(&s2, &b->y, &z12); secp256k1_fe_mul(&s2, &s2, &a->z);
    secp256k1_fe_negate(&h, &u1, 1); secp256k1_fe_add(&h, &u2);
    secp256k1_fe_negate(&i, &s1, 1); secp256k1_fe_add(&i, &s2);
    if (secp256k1_fe_normalizes_to_zero_var(&h)) {
        if (secp256k1_fe_normalizes_to_zero_var(&i)) {
            secp256k1_gej_double_var(r, a, rzr);
        } else {
            if (rzr != NULL) {
                secp256k1_fe_set_int(rzr, 0);
            }
            r->infinity = 1;
        }
        return;
    }
    secp256k1_fe_sqr(&i2, &i);
    secp256k1_fe_sqr(&h2, &h);
    secp256k1_fe_mul(&h3, &h, &h2);
    if (rzr != NULL) {
        *rzr = h;
    }
    secp256k1_fe_mul(&r->z, &a->z, &h);
    secp256k1_fe_mul(&t, &u1, &h2);
    r->x = t; secp256k1_fe_mul_int(&r->x, 2); secp256k1_fe_add(&r->x, &h3); secp256k1_fe_negate(&r->x, &r->x, 3); secp256k1_fe_add(&r->x, &i2);
    secp256k1_fe_negate(&r->y, &r->x, 5); secp256k1_fe_add(&r->y, &t); secp256k1_fe_mul(&r->y, &r->y, &i);
    secp256k1_fe_mul(&h3, &h3, &s1); secp256k1_fe_negate(&h3, &h3, 1);
    secp256k1_fe_add(&r->y, &h3);
}

/** Fill a table 'prej' with precomputed odd multiples of a. Prej will contain
 *  the values [1*a,3*a,...,(2*n-1)*a], so it space for n values. zr[0] will
 *  contain prej[0].z / a.z. The other zr[i] values = prej[i].z / prej[i-1].z.
 *  Prej's Z values are undefined, except for the last value.
 */
void CPubKey::secp256k1_ecmult_odd_multiples_table(int n, ecmult::secp256k1_gej *prej, ecmult::secp256k1_fe *zr, const ecmult::secp256k1_gej *a) {
    ecmult::secp256k1_gej d;
    ecmult::secp256k1_ge a_ge, d_ge;

    VERIFY_CHECK(!a->infinity);

    ecmult::secp256k1_gej_double_var(&d, a, nullptr);

    /*
     * Perform the additions on an isomorphism where 'd' is affine: drop the z coordinate
     * of 'd', and scale the 1P starting value's x/y coordinates without changing its z.
     */
    d_ge.x = d.x;
    d_ge.y = d.y;
    d_ge.infinity = 0;

    ecmult::secp256k1_ge_set_gej_zinv(&a_ge, a, &d.z);
    prej[0].x = a_ge.x;
    prej[0].y = a_ge.y;
    prej[0].z = a->z;
    prej[0].infinity = 0;

    zr[0] = d.z;
    for (int i = 1; i < n; ++i)
        ecmult::secp256k1_gej_add_ge_var(&prej[i], &prej[i-1], &d_ge, &zr[i]);

    /*
     * Each point in 'prej' has a z coordinate too small by a factor of 'd.z'. Only
     * the final point's z coordinate is actually used though, so just update that.
     */
    ecmult::secp256k1_fe_mul(&prej[n-1].z, &prej[n-1].z, &d.z);
}

void CPubKey::ecmult::secp256k1_ge_globalz_set_table_gej(size_t len, secp256k1_ge *r, secp256k1_fe *globalz, const secp256k1_gej *a, const secp256k1_fe *zr) {
    size_t i = len - 1;
    secp256k1_fe zs;

    if (len > 0) {
        /* The z of the final point gives us the "global Z" for the table. */
        r[i].x = a[i].x;
        r[i].y = a[i].y;
        *globalz = a[i].z;
        r[i].infinity = 0;
        zs = zr[i];

        /* Work our way backwards, using the z-ratios to scale the x/y values. */
        while (i > 0) {
            if (i != len - 1) {
                secp256k1_fe_mul(&zs, &zs, &zr[i]);
            }
            i--;
            secp256k1_ge_set_gej_zinv(&r[i], &a[i], &zs);
        }
    }
}

void CPubKey::ecmult::secp256k1_fe_clear(secp256k1_fe *a) {
    int i;
#ifdef VERIFY
    a->magnitude = 0;
    a->normalized = 1;
#endif
    for (i=0; i<10; i++) {
        a->n[i] = 0;
    }
}

void CPubKey::ecmult::secp256k1_gej_set_infinity(secp256k1_gej *r) {
    r->infinity = 1;
    secp256k1_fe_clear(&r->x);
    secp256k1_fe_clear(&r->y);
    secp256k1_fe_clear(&r->z);
}

void CPubKey::ecmult::secp256k1_fe_from_storage(secp256k1_fe *r, const secp256k1_fe_storage *a) {
    r->n[0] = a->n[0] & 0x3FFFFFFUL;
    r->n[1] = a->n[0] >> 26 | ((a->n[1] << 6) & 0x3FFFFFFUL);
    r->n[2] = a->n[1] >> 20 | ((a->n[2] << 12) & 0x3FFFFFFUL);
    r->n[3] = a->n[2] >> 14 | ((a->n[3] << 18) & 0x3FFFFFFUL);
    r->n[4] = a->n[3] >> 8 | ((a->n[4] << 24) & 0x3FFFFFFUL);
    r->n[5] = (a->n[4] >> 2) & 0x3FFFFFFUL;
    r->n[6] = a->n[4] >> 28 | ((a->n[5] << 4) & 0x3FFFFFFUL);
    r->n[7] = a->n[5] >> 22 | ((a->n[6] << 10) & 0x3FFFFFFUL);
    r->n[8] = a->n[6] >> 16 | ((a->n[7] << 16) & 0x3FFFFFFUL);
    r->n[9] = a->n[7] >> 10;
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
#endif
}

void CPubKey::ecmult::secp256k1_ge_neg(secp256k1_ge *r, const secp256k1_ge *a) {
    *r = *a;
    secp256k1_fe_normalize_weak(&r->y);
    secp256k1_fe_negate(&r->y, &r->y, 1);
}

void CPubKey::ecmult::secp256k1_ge_from_storage(secp256k1_ge *r, const secp256k1_ge_storage *a) {
    secp256k1_fe_from_storage(&r->x, &a->x);
    secp256k1_fe_from_storage(&r->y, &a->y);
    r->infinity = 0;
}

void CPubKey::ecmult::secp256k1_gej_add_zinv_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, const secp256k1_fe *bzinv) {
    /* 9 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
    secp256k1_fe az, z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;

    if (b->infinity) {
        *r = *a;
        return;
    }
    if (a->infinity) {
        secp256k1_fe bzinv2, bzinv3;
        r->infinity = b->infinity;
        secp256k1_fe_sqr(&bzinv2, bzinv);
        secp256k1_fe_mul(&bzinv3, &bzinv2, bzinv);
        secp256k1_fe_mul(&r->x, &b->x, &bzinv2);
        secp256k1_fe_mul(&r->y, &b->y, &bzinv3);
        secp256k1_fe_set_int(&r->z, 1);
        return;
    }
    r->infinity = 0;

    /** We need to calculate (rx,ry,rz) = (ax,ay,az) + (bx,by,1/bzinv). Due to
     *  secp256k1's isomorphism we can multiply the Z coordinates on both sides
     *  by bzinv, and get: (rx,ry,rz*bzinv) = (ax,ay,az*bzinv) + (bx,by,1).
     *  This means that (rx,ry,rz) can be calculated as
     *  (ax,ay,az*bzinv) + (bx,by,1), when not applying the bzinv factor to rz.
     *  The variable az below holds the modified Z coordinate for a, which is used
     *  for the computation of rx and ry, but not for rz.
     */
    secp256k1_fe_mul(&az, &a->z, bzinv);

    secp256k1_fe_sqr(&z12, &az);
    u1 = a->x; secp256k1_fe_normalize_weak(&u1);
    secp256k1_fe_mul(&u2, &b->x, &z12);
    s1 = a->y; secp256k1_fe_normalize_weak(&s1);
    secp256k1_fe_mul(&s2, &b->y, &z12); secp256k1_fe_mul(&s2, &s2, &az);
    secp256k1_fe_negate(&h, &u1, 1); secp256k1_fe_add(&h, &u2);
    secp256k1_fe_negate(&i, &s1, 1); secp256k1_fe_add(&i, &s2);
    if (secp256k1_fe_normalizes_to_zero_var(&h)) {
        if (secp256k1_fe_normalizes_to_zero_var(&i)) {
            secp256k1_gej_double_var(r, a, NULL);
        } else {
            r->infinity = 1;
        }
        return;
    }
    secp256k1_fe_sqr(&i2, &i);
    secp256k1_fe_sqr(&h2, &h);
    secp256k1_fe_mul(&h3, &h, &h2);
    r->z = a->z; secp256k1_fe_mul(&r->z, &r->z, &h);
    secp256k1_fe_mul(&t, &u1, &h2);
    r->x = t; secp256k1_fe_mul_int(&r->x, 2); secp256k1_fe_add(&r->x, &h3); secp256k1_fe_negate(&r->x, &r->x, 3); secp256k1_fe_add(&r->x, &i2);
    secp256k1_fe_negate(&r->y, &r->x, 5); secp256k1_fe_add(&r->y, &t); secp256k1_fe_mul(&r->y, &r->y, &i);
    secp256k1_fe_mul(&h3, &h3, &s1); secp256k1_fe_negate(&h3, &h3, 1);
    secp256k1_fe_add(&r->y, &h3);
}

#ifdef USE_ENDOMORPHISM
void CPubKey::secp256k1_scalar_cadd_bit(secp256k1_unit *r, unsigned int bit, int flag) {
    uint64_t t;
    VERIFY_CHECK(bit < 256);
    bit += ((uint32_t) flag - 1) & 0x100;  /* forcing (bit >> 5) > 7 makes this a noop */
    t = (uint64_t)r->d[0] + (((uint32_t)((bit >> 5) == 0)) << (bit & 0x1F));
    r->d[0] = t & 0xFFFFFFFFULL; t >>= 32;
    t += (uint64_t)r->d[1] + (((uint32_t)((bit >> 5) == 1)) << (bit & 0x1F));
    r->d[1] = t & 0xFFFFFFFFULL; t >>= 32;
    t += (uint64_t)r->d[2] + (((uint32_t)((bit >> 5) == 2)) << (bit & 0x1F));
    r->d[2] = t & 0xFFFFFFFFULL; t >>= 32;
    t += (uint64_t)r->d[3] + (((uint32_t)((bit >> 5) == 3)) << (bit & 0x1F));
    r->d[3] = t & 0xFFFFFFFFULL; t >>= 32;
    t += (uint64_t)r->d[4] + (((uint32_t)((bit >> 5) == 4)) << (bit & 0x1F));
    r->d[4] = t & 0xFFFFFFFFULL; t >>= 32;
    t += (uint64_t)r->d[5] + (((uint32_t)((bit >> 5) == 5)) << (bit & 0x1F));
    r->d[5] = t & 0xFFFFFFFFULL; t >>= 32;
    t += (uint64_t)r->d[6] + (((uint32_t)((bit >> 5) == 6)) << (bit & 0x1F));
    r->d[6] = t & 0xFFFFFFFFULL; t >>= 32;
    t += (uint64_t)r->d[7] + (((uint32_t)((bit >> 5) == 7)) << (bit & 0x1F));
    r->d[7] = t & 0xFFFFFFFFULL;
# ifdef VERIFY
    VERIFY_CHECK((t >> 32) == 0);
    VERIFY_CHECK(secp256k1_scalar_check_overflow(r) == 0);
# endif
}

void CPubKey::secp256k1_scalar_mul_shift_var(secp256k1_unit *r, const secp256k1_unit *a, const secp256k1_unit *b, unsigned int shift) {
    uint32_t l[16];
    VERIFY_CHECK(shift >= 256);
    secp256k1_scalar_mul_512(l, a, b);
    unsigned int shiftlimbs = shift >> 5;
    unsigned int shiftlow = shift & 0x1F;
    unsigned int shifthigh = 32 - shiftlow;
    r->d[0] = shift < 512 ? (l[0 + shiftlimbs] >> shiftlow | (shift < 480 && shiftlow ? (l[1 + shiftlimbs] << shifthigh) : 0)) : 0;
    r->d[1] = shift < 480 ? (l[1 + shiftlimbs] >> shiftlow | (shift < 448 && shiftlow ? (l[2 + shiftlimbs] << shifthigh) : 0)) : 0;
    r->d[2] = shift < 448 ? (l[2 + shiftlimbs] >> shiftlow | (shift < 416 && shiftlow ? (l[3 + shiftlimbs] << shifthigh) : 0)) : 0;
    r->d[3] = shift < 416 ? (l[3 + shiftlimbs] >> shiftlow | (shift < 384 && shiftlow ? (l[4 + shiftlimbs] << shifthigh) : 0)) : 0;
    r->d[4] = shift < 384 ? (l[4 + shiftlimbs] >> shiftlow | (shift < 352 && shiftlow ? (l[5 + shiftlimbs] << shifthigh) : 0)) : 0;
    r->d[5] = shift < 352 ? (l[5 + shiftlimbs] >> shiftlow | (shift < 320 && shiftlow ? (l[6 + shiftlimbs] << shifthigh) : 0)) : 0;
    r->d[6] = shift < 320 ? (l[6 + shiftlimbs] >> shiftlow | (shift < 288 && shiftlow ? (l[7 + shiftlimbs] << shifthigh) : 0)) : 0;
    r->d[7] = shift < 288 ? (l[7 + shiftlimbs] >> shiftlow)  : 0;
    secp256k1_scalar_cadd_bit(r, 0, (l[(shift - 1) >> 5] >> ((shift - 1) & 0x1f)) & 1);
}

int CPubKey::secp256k1_scalar_add(secp256k1_unit *r, const secp256k1_unit *a, const secp256k1_unit *b) {
    int overflow;
    uint64_t t = (uint64_t)a->d[0] + b->d[0];
    r->d[0] = t & 0xFFFFFFFFULL; t >>= 32;
    t += (uint64_t)a->d[1] + b->d[1];
    r->d[1] = t & 0xFFFFFFFFULL; t >>= 32;
    t += (uint64_t)a->d[2] + b->d[2];
    r->d[2] = t & 0xFFFFFFFFULL; t >>= 32;
    t += (uint64_t)a->d[3] + b->d[3];
    r->d[3] = t & 0xFFFFFFFFULL; t >>= 32;
    t += (uint64_t)a->d[4] + b->d[4];
    r->d[4] = t & 0xFFFFFFFFULL; t >>= 32;
    t += (uint64_t)a->d[5] + b->d[5];
    r->d[5] = t & 0xFFFFFFFFULL; t >>= 32;
    t += (uint64_t)a->d[6] + b->d[6];
    r->d[6] = t & 0xFFFFFFFFULL; t >>= 32;
    t += (uint64_t)a->d[7] + b->d[7];
    r->d[7] = t & 0xFFFFFFFFULL; t >>= 32;
    overflow = t + secp256k1_scalar_check_overflow(r);
    VERIFY_CHECK(overflow == 0 || overflow == 1);
    secp256k1_scalar_reduce(r, overflow);
    return overflow;
}
#endif

int CPubKey::secp256k1_ecmult(ecmult::secp256k1_gej *r, const ecmult::secp256k1_gej *a, const secp256k1_unit *na, const secp256k1_unit *ng) {
    auto secp256k1_ecmult_wnaf = [](int *wnaf, int len, const secp256k1_unit *a, int w) {
        secp256k1_unit s = *a;
        int last_set_bit = -1;
        int bit = 0;
        int sign = 1;
        int carry = 0;

        VERIFY_CHECK(wnaf != nullptr);
        VERIFY_CHECK(0 <= len && len <= 256);
        VERIFY_CHECK(a != nullptr);
        VERIFY_CHECK(2 <= w && w <= 31);

        std::memset(wnaf, 0, len * sizeof(wnaf[0]));

        if (secp256k1_scalar_get_bits(&s, 255, 1)) {
            secp256k1_scalar_negate(&s, &s);
            sign = -1;
        }

        while (bit < len) {
            int now;
            int word;
            if (secp256k1_scalar_get_bits(&s, bit, 1) == (unsigned int)carry) {
                ++bit;
                continue;
            }

            now = w;
            if (now > len - bit)
                now = len - bit;

            word = secp256k1_scalar_get_bits_var(&s, bit, now) + carry;
            carry = (word >> (w-1)) & 1;
            word -= carry << w;

            wnaf[bit] = sign * word;
            last_set_bit = bit;

            bit += now;
        }
#ifdef VERIFY
        CHECK(carry == 0);
        while (bit < 256) {
            CHECK(secp256k1_scalar_get_bits(&s, bit++, 1) == 0);
        }
#endif
        return last_set_bit + 1;
    };

    auto secp256k1_ecmult_odd_multiples_table_globalz_windowa = [](ecmult::secp256k1_ge *pre, ecmult::secp256k1_fe *globalz, const ecmult::secp256k1_gej *a) {
        ecmult::secp256k1_gej prej[ECMULT_TABLE_SIZE(WINDOW_A)];
        ecmult::secp256k1_fe zr[ECMULT_TABLE_SIZE(WINDOW_A)];

        /* Compute the odd multiples in Jacobian form. */
        secp256k1_ecmult_odd_multiples_table(ECMULT_TABLE_SIZE(WINDOW_A), prej, zr, a);
        /* Bring them to the same Z denominator. */
        ecmult::secp256k1_ge_globalz_set_table_gej(ECMULT_TABLE_SIZE(WINDOW_A), pre, globalz, prej, zr);
    };

#ifdef USE_ENDOMORPHISM
    auto secp256k1_scalar_split_128 = [](secp256k1_unit *r1, secp256k1_unit *r2, const secp256k1_unit *a) {
        r1->d[0] = a->d[0];
        r1->d[1] = a->d[1];
        r1->d[2] = a->d[2];
        r1->d[3] = a->d[3];
        r1->d[4] = 0;
        r1->d[5] = 0;
        r1->d[6] = 0;
        r1->d[7] = 0;
        r2->d[0] = a->d[4];
        r2->d[1] = a->d[5];
        r2->d[2] = a->d[6];
        r2->d[3] = a->d[7];
        r2->d[4] = 0;
        r2->d[5] = 0;
        r2->d[6] = 0;
        r2->d[7] = 0;
    };

    auto secp256k1_scalar_split_lambda = [](secp256k1_unit *r1, secp256k1_unit *r2, const secp256k1_unit *a) {
        secp256k1_unit c1, c2;
        constexpr secp256k1_unit minus_lambda = SECP256K1_SCALAR_CONST(
            0xAC9C52B3UL, 0x3FA3CF1FUL, 0x5AD9E3FDUL, 0x77ED9BA4UL,
            0xA880B9FCUL, 0x8EC739C2UL, 0xE0CFC810UL, 0xB51283CFUL
        );
        static constexpr secp256k1_unit minus_b1 = SECP256K1_SCALAR_CONST(
            0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
            0xE4437ED6UL, 0x010E8828UL, 0x6F547FA9UL, 0x0ABFE4C3UL
        );
        static constexpr secp256k1_unit minus_b2 = SECP256K1_SCALAR_CONST(
            0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL,
            0x8A280AC5UL, 0x0774346DUL, 0xD765CDA8UL, 0x3DB1562CUL
        );
        static constexpr secp256k1_unit g1 = SECP256K1_SCALAR_CONST(
            0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00003086UL,
            0xD221A7D4UL, 0x6BCDE86CUL, 0x90E49284UL, 0xEB153DABUL
        );
        static constexpr secp256k1_unit g2 = SECP256K1_SCALAR_CONST(
            0x00000000UL, 0x00000000UL, 0x00000000UL, 0x0000E443UL,
            0x7ED6010EUL, 0x88286F54UL, 0x7FA90ABFUL, 0xE4C42212UL
        );
        VERIFY_CHECK(r1 != a);
        VERIFY_CHECK(r2 != a);
        /* these _var calls are constant time since the shift amount is constant */
        secp256k1_scalar_mul_shift_var(&c1, a, &g1, 272);
        secp256k1_scalar_mul_shift_var(&c2, a, &g2, 272);
        secp256k1_scalar_mul(&c1, &c1, &minus_b1);
        secp256k1_scalar_mul(&c2, &c2, &minus_b2);
        secp256k1_scalar_add(r2, &c1, &c2);
        secp256k1_scalar_mul(r1, r2, &minus_lambda);
        secp256k1_scalar_add(r1, r1, a);
    };

    auto secp256k1_ge_mul_lambda = [](ecmult::secp256k1_ge *r, const ecmult::secp256k1_ge *a) {
        static constexpr ecmult::secp256k1_fe beta = SECP256K1_FE_CONST(
            0x7ae96a2bul, 0x657c0710ul, 0x6e64479eul, 0xac3434e9ul,
            0x9cf04975ul, 0x12f58995ul, 0xc1396c28ul, 0x719501eeul
        );
        *r = *a;
        ecmult::secp256k1_fe_mul(&r->x, &r->x, &beta);
    };
#endif

    ecmult::secp256k1_context ctx;
    ARG_CHECK(ctx.build() != false);

    ecmult::secp256k1_ge pre_a[ECMULT_TABLE_SIZE(WINDOW_A)];
    ecmult::secp256k1_ge tmpa;
    ecmult::secp256k1_fe Z;
#ifdef USE_ENDOMORPHISM
    ecmult::secp256k1_ge pre_a_lam[ECMULT_TABLE_SIZE(WINDOW_A)];
    secp256k1_unit na_1, na_lam;
    /* Splitted G factors. */
    secp256k1_unit ng_1, ng_128;
    int wnaf_na_1[130];
    int wnaf_na_lam[130];
    int bits_na_1;
    int bits_na_lam;
    int wnaf_ng_1[129];
    int bits_ng_1;
    int wnaf_ng_128[129];
    int bits_ng_128;
#else
    int wnaf_na[256];
    int bits_na;
    int wnaf_ng[256];
    int bits_ng;
#endif
    int i;
    int bits;

#ifdef USE_ENDOMORPHISM
    /* split na into na_1 and na_lam (where na = na_1 + na_lam*lambda, and na_1 and na_lam are ~128 bit) */
    secp256k1_scalar_split_lambda(&na_1, &na_lam, na);

    /* build wnaf representation for na_1 and na_lam. */
    bits_na_1   = secp256k1_ecmult_wnaf(wnaf_na_1,   130, &na_1,   WINDOW_A);
    bits_na_lam = secp256k1_ecmult_wnaf(wnaf_na_lam, 130, &na_lam, WINDOW_A);
    VERIFY_CHECK(bits_na_1 <= 130);
    VERIFY_CHECK(bits_na_lam <= 130);
    bits = bits_na_1;
    if (bits_na_lam > bits)
        bits = bits_na_lam;
#else
    /* build wnaf representation for na. */
    bits_na     = secp256k1_ecmult_wnaf(wnaf_na,     256, na,      WINDOW_A);
    bits = bits_na;
#endif

    /* Calculate odd multiples of a.
     * All multiples are brought to the same Z 'denominator', which is stored
     * in Z. Due to secp256k1' isomorphism we can do all operations pretending
     * that the Z coordinate was 1, use affine addition formulae, and correct
     * the Z coordinate of the result once at the end.
     * The exception is the precomputed G table points, which are actually
     * affine. Compared to the base used for other points, they have a Z ratio
     * of 1/Z, so we can use secp256k1_gej_add_zinv_var, which uses the same
     * isomorphism to efficiently add with a known Z inverse.
     */
    secp256k1_ecmult_odd_multiples_table_globalz_windowa(pre_a, &Z, a);

#ifdef USE_ENDOMORPHISM
    for (i = 0; i < ECMULT_TABLE_SIZE(WINDOW_A); ++i)
        secp256k1_ge_mul_lambda(&pre_a_lam[i], &pre_a[i]);

    /* split ng into ng_1 and ng_128 (where gn = gn_1 + gn_128*2^128, and gn_1 and gn_128 are ~128 bit) */
    secp256k1_scalar_split_128(&ng_1, &ng_128, ng);

    /* Build wnaf representation for ng_1 and ng_128 */
    bits_ng_1   = secp256k1_ecmult_wnaf(wnaf_ng_1,   129, &ng_1,   WINDOW_G);
    bits_ng_128 = secp256k1_ecmult_wnaf(wnaf_ng_128, 129, &ng_128, WINDOW_G);
    if (bits_ng_1 > bits)
        bits = bits_ng_1;
    if (bits_ng_128 > bits)
        bits = bits_ng_128;
#else
    bits_ng     = secp256k1_ecmult_wnaf(wnaf_ng,     256, ng,      WINDOW_G);
    if (bits_ng > bits) {
        bits = bits_ng;
    }
#endif

    ecmult::secp256k1_gej_set_infinity(r);

    for (i = bits - 1; i >= 0; --i) {
        int n;
        ecmult::secp256k1_gej_double_var(r, r, nullptr);
#ifdef USE_ENDOMORPHISM
        if (i < bits_na_1 && (n = wnaf_na_1[i])) {
            ECMULT_TABLE_GET_GE(&tmpa, pre_a, n, WINDOW_A);
            ecmult::secp256k1_gej_add_ge_var(r, r, &tmpa, nullptr);
        }
        if (i < bits_na_lam && (n = wnaf_na_lam[i])) {
            ECMULT_TABLE_GET_GE(&tmpa, pre_a_lam, n, WINDOW_A);
            ecmult::secp256k1_gej_add_ge_var(r, r, &tmpa, nullptr);
        }
        if (i < bits_ng_1 && (n = wnaf_ng_1[i])) {
            ECMULT_TABLE_GET_GE_STORAGE(&tmpa, *ctx.pre_g_, n, WINDOW_G);
            ecmult::secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
        }
        if (i < bits_ng_128 && (n = wnaf_ng_128[i])) {
            ECMULT_TABLE_GET_GE_STORAGE(&tmpa, *ctx.pre_g_128_, n, WINDOW_G);
            ecmult::secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
        }
#else
        if (i < bits_na && (n = wnaf_na[i])) {
            ECMULT_TABLE_GET_GE(&tmpa, pre_a, n, WINDOW_A);
            ecmult::secp256k1_gej_add_ge_var(r, r, &tmpa, nullptr);
        }
        if (i < bits_ng && (n = wnaf_ng[i])) {
            ECMULT_TABLE_GET_GE_STORAGE(&tmpa, *ctx.pre_g_, n, WINDOW_G);
            ecmult::secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
        }
#endif
    }

    if (! r->infinity)
        ecmult::secp256k1_fe_mul(&r->z, &r->z, &Z);

    return 1;
}

void CPubKey::ecmult::secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *a) {
    secp256k1_fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
    int j;

    /** The binary representation of (p - 2) has 5 blocks of 1s, with lengths in
     *  { 1, 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
     *  [1], [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
     */

    secp256k1_fe_sqr(&x2, a);
    secp256k1_fe_mul(&x2, &x2, a);

    secp256k1_fe_sqr(&x3, &x2);
    secp256k1_fe_mul(&x3, &x3, a);

    x6 = x3;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x6, &x6);
    }
    secp256k1_fe_mul(&x6, &x6, &x3);

    x9 = x6;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x9, &x9);
    }
    secp256k1_fe_mul(&x9, &x9, &x3);

    x11 = x9;
    for (j=0; j<2; j++) {
        secp256k1_fe_sqr(&x11, &x11);
    }
    secp256k1_fe_mul(&x11, &x11, &x2);

    x22 = x11;
    for (j=0; j<11; j++) {
        secp256k1_fe_sqr(&x22, &x22);
    }
    secp256k1_fe_mul(&x22, &x22, &x11);

    x44 = x22;
    for (j=0; j<22; j++) {
        secp256k1_fe_sqr(&x44, &x44);
    }
    secp256k1_fe_mul(&x44, &x44, &x22);

    x88 = x44;
    for (j=0; j<44; j++) {
        secp256k1_fe_sqr(&x88, &x88);
    }
    secp256k1_fe_mul(&x88, &x88, &x44);

    x176 = x88;
    for (j=0; j<88; j++) {
        secp256k1_fe_sqr(&x176, &x176);
    }
    secp256k1_fe_mul(&x176, &x176, &x88);

    x220 = x176;
    for (j=0; j<44; j++) {
        secp256k1_fe_sqr(&x220, &x220);
    }
    secp256k1_fe_mul(&x220, &x220, &x44);

    x223 = x220;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x223, &x223);
    }
    secp256k1_fe_mul(&x223, &x223, &x3);

    /* The final result is then assembled using a sliding window over the blocks. */

    t1 = x223;
    for (j=0; j<23; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, &x22);
    for (j=0; j<5; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, a);
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, &x2);
    for (j=0; j<2; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(r, a, &t1);
}

void CPubKey::ecmult::secp256k1_fe_inv_var(secp256k1_fe *r, const secp256k1_fe *a) {
#if defined(USE_FIELD_INV_BUILTIN)
    secp256k1_fe_inv(r, a);
#elif defined(USE_FIELD_INV_NUM)
#error "Please select field GMP implementation"
    secp256k1_num n, m;
    static constexpr secp256k1_fe negone = SECP256K1_FE_CONST(
        0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL,
        0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL, 0xFFFFFC2EUL
    );
    /* secp256k1 field prime, value p defined in "Standards for Efficient Cryptography" (SEC2) 2.7.1. */
    static constexpr unsigned char prime[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F
    };
    unsigned char b[32];
    int res;
    secp256k1_fe c = *a;
    secp256k1_fe_normalize_var(&c);
    secp256k1_fe_get_b32(b, &c);
    secp256k1_num_set_bin(&n, b, 32);
    secp256k1_num_set_bin(&m, prime, 32);
    secp256k1_num_mod_inverse(&n, &n, &m);
    secp256k1_num_get_bin(b, 32, &n);
    res = secp256k1_fe_set_b32(r, b);
    (void)res;
    VERIFY_CHECK(res);
    /* Verify the result is the (unique) valid inverse using non-GMP code. */
    secp256k1_fe_mul(&c, &c, r);
    secp256k1_fe_add(&c, &negone);
    CHECK(secp256k1_fe_normalizes_to_zero_var(&c));
#else
#error "Please select field inverse implementation"
#endif
}

void CPubKey::ecmult::secp256k1_ge_set_gej_var(secp256k1_ge *r, secp256k1_gej *a) {
    secp256k1_fe z2, z3;
    r->infinity = a->infinity;
    if (a->infinity) {
        return;
    }
    secp256k1_fe_inv_var(&a->z, &a->z);
    secp256k1_fe_sqr(&z2, &a->z);
    secp256k1_fe_mul(&z3, &a->z, &z2);
    secp256k1_fe_mul(&a->x, &a->x, &z2);
    secp256k1_fe_mul(&a->y, &a->y, &z3);
    secp256k1_fe_set_int(&a->z, 1);
    r->x = a->x;
    r->y = a->y;
}

int CPubKey::ecmult::secp256k1_gej_is_infinity(const secp256k1_gej *a) {
    return a->infinity;
}

int CPubKey::secp256k1_ecdsa_sig_recover(const secp256k1_unit *sigr, const secp256k1_unit *sigs, ecmult::secp256k1_ge *pubkey, const secp256k1_unit *message, int recid) {
    unsigned char brx[32];
    ecmult::secp256k1_fe fx;
    ecmult::secp256k1_ge x;
    ecmult::secp256k1_gej xj;
    secp256k1_unit rn, u1, u2;
    ecmult::secp256k1_gej qj;

    if (secp256k1_scalar_is_zero(sigr) || secp256k1_scalar_is_zero(sigs))
        return 0;
    //DEBUGCS_CHECK("step1");

    secp256k1_scalar_get_be32(brx, sigr);
    int r = ecmult::secp256k1_fe_set_be32(&fx, brx);
    (void)r;
    VERIFY_CHECK(r); /* brx comes from a scalar, so is less than the order; certainly less than p */
    if (recid & 2) {
        //DEBUGCS_CHECK("step2");
        if (ecmult::secp256k1_fe_cmp_var(&fx, &secp256k1_ecdsa_const_p_minus_order) >= 0)
            return 0;

        //DEBUGCS_CHECK("step3");
        ecmult::secp256k1_fe_add(&fx, &secp256k1_ecdsa_const_order_as_fe);
    }
    //DEBUGCS_CHECK("step4");
    if (! ecmult::secp256k1_ge_set_xo_var(&x, &fx, recid & 1))
        return 0;

    //DEBUGCS_CHECK("step5");
    ecmult::secp256k1_gej_set_ge(&xj, &x);
    secp256k1_scalar_inverse_var(&rn, sigr);
    secp256k1_scalar_mul(&u1, &rn, message);
    secp256k1_scalar_negate(&u1, &u1);
    secp256k1_scalar_mul(&u2, &rn, sigs);
    if(! secp256k1_ecmult(&qj, &xj, &u2, &u1))
        return 0;
    ecmult::secp256k1_ge_set_gej_var(pubkey, &qj);
    return !ecmult::secp256k1_gej_is_infinity(&qj);
}

void CPubKey::ecmult::secp256k1_fe_normalize(secp256k1_fe *r) {
    uint32_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4],
             t5 = r->n[5], t6 = r->n[6], t7 = r->n[7], t8 = r->n[8], t9 = r->n[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t m;
    uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; m = t2;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; m &= t3;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; m &= t4;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; m &= t5;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; m &= t6;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; m &= t7;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; m &= t8;

    /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t9 >> 23 == 0);

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t9 >> 22) | ((t9 == 0x03FFFFFUL) & (m == 0x3FFFFFFUL)
        & ((t1 + 0x40UL + ((t0 + 0x3D1UL) >> 26)) > 0x3FFFFFFUL));

    /* Apply the final reduction (for constant-time behaviour, we do it always) */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL;

    /* If t9 didn't carry to bit 22 already, then it should have after any final reduction */
    VERIFY_CHECK(t9 >> 22 == x);

    /* Mask off the possible multiple of 2^256 from the final reduction */
    t9 &= 0x03FFFFFUL;

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;
    r->n[5] = t5; r->n[6] = t6; r->n[7] = t7; r->n[8] = t8; r->n[9] = t9;

#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verify(r);
#endif
}

void CPubKey::ecmult::secp256k1_fe_normalize_var(secp256k1_fe *r) {
    uint32_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4],
             t5 = r->n[5], t6 = r->n[6], t7 = r->n[7], t8 = r->n[8], t9 = r->n[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t m;
    uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; m = t2;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; m &= t3;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; m &= t4;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; m &= t5;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; m &= t6;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; m &= t7;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; m &= t8;

    /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t9 >> 23 == 0);

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t9 >> 22) | ((t9 == 0x03FFFFFUL) & (m == 0x3FFFFFFUL)
        & ((t1 + 0x40UL + ((t0 + 0x3D1UL) >> 26)) > 0x3FFFFFFUL));

    if (x) {
        t0 += 0x3D1UL; t1 += (x << 6);
        t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
        t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
        t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL;
        t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL;
        t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL;
        t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL;
        t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL;
        t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL;
        t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL;

        /* If t9 didn't carry to bit 22 already, then it should have after any final reduction */
        VERIFY_CHECK(t9 >> 22 == x);

        /* Mask off the possible multiple of 2^256 from the final reduction */
        t9 &= 0x03FFFFFUL;
    }

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;
    r->n[5] = t5; r->n[6] = t6; r->n[7] = t7; r->n[8] = t8; r->n[9] = t9;

#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verify(r);
#endif
}

void CPubKey::ecmult::secp256k1_fe_normalize_weak(secp256k1_fe *r) {
    uint32_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4],
             t5 = r->n[5], t6 = r->n[6], t7 = r->n[7], t8 = r->n[8], t9 = r->n[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL;

    /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t9 >> 23 == 0);

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;
    r->n[5] = t5; r->n[6] = t6; r->n[7] = t7; r->n[8] = t8; r->n[9] = t9;

#ifdef VERIFY
    r->magnitude = 1;
    secp256k1_fe_verify(r);
#endif
}

void CPubKey::ecmult::secp256k1_fe_to_storage(secp256k1_fe_storage *r, const secp256k1_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
#endif
    r->n[0] = a->n[0] | a->n[1] << 26;
    r->n[1] = a->n[1] >> 6 | a->n[2] << 20;
    r->n[2] = a->n[2] >> 12 | a->n[3] << 14;
    r->n[3] = a->n[3] >> 18 | a->n[4] << 8;
    r->n[4] = a->n[4] >> 24 | a->n[5] << 2 | a->n[6] << 28;
    r->n[5] = a->n[6] >> 4 | a->n[7] << 22;
    r->n[6] = a->n[7] >> 10 | a->n[8] << 16;
    r->n[7] = a->n[8] >> 16 | a->n[9] << 10;
}

void CPubKey::ecmult::secp256k1_ge_to_storage(secp256k1_ge_storage *r, const secp256k1_ge *a) {
    secp256k1_fe x, y;
    VERIFY_CHECK(!a->infinity);
    x = a->x;
    secp256k1_fe_normalize(&x);
    y = a->y;
    secp256k1_fe_normalize(&y);
    secp256k1_fe_to_storage(&r->x, &x);
    secp256k1_fe_to_storage(&r->y, &y);
}

void CPubKey::secp256k1_pubkey_save(secp256k1_pubkey *pubkey, ecmult::secp256k1_ge *ge) {
    VERIFY_CHECK(sizeof(ecmult::secp256k1_ge_storage)==64);

    ecmult::secp256k1_ge_storage s;
    ecmult::secp256k1_ge_to_storage(&s, ge);
    std::memcpy(&pubkey->data[0], &s, 64);

    // otherwise (sizeof(ecmult::secp256k1_ge_storage)!=64)
    //VERIFY_CHECK(!ecmult::secp256k1_ge_is_infinity(ge));
    //ecmult::secp256k1_fe_normalize_var(&ge->x);
    //ecmult::secp256k1_fe_normalize_var(&ge->y);
    //ecmult::secp256k1_fe_get_be32(pubkey->data, &ge->x);
    //ecmult::secp256k1_fe_get_be32(pubkey->data + 32, &ge->y);
}

int CPubKey::secp256k1_ecdsa_recover(secp256k1_pubkey *pubkey, const secp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msg32) {
    ecmult::secp256k1_ge q;
    secp256k1_unit r, s;
    secp256k1_unit m;
    int recid;

    // SorachanCoin: CPubKey doesn't use ctx. instead of callback function.
    //VERIFY_CHECK(ctx != nullptr);
    //ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(msg32 != nullptr);
    ARG_CHECK(signature != nullptr);
    ARG_CHECK(pubkey != nullptr);

    secp256k1_ecdsa_recoverable_signature_load(&r, &s, &recid, signature);
    VERIFY_CHECK(recid >= 0 && recid < 4);  /* should have been caught in parse_compact */
    secp256k1_scalar_set_be32(&m, msg32, nullptr);
    //DEBUGCS_CHECK("step1");
    if (secp256k1_ecdsa_sig_recover(&r, &s, &q, &m, recid)) {
        //DEBUGCS_CHECK("step2");
        secp256k1_pubkey_save(pubkey, &q);
        return 1;
    } else {
        std::memset(pubkey, 0, sizeof(*pubkey));
        return 0;
    }
}

int CPubKey::ecmult::secp256k1_fe_is_zero(const secp256k1_fe *a) {
    const uint32_t *t = a->n;
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    secp256k1_fe_verify(a);
#endif
    return (t[0] | t[1] | t[2] | t[3] | t[4] | t[5] | t[6] | t[7] | t[8] | t[9]) == 0;
}

int CPubKey::secp256k1_pubkey_load(ecmult::secp256k1_ge *ge, const secp256k1_pubkey *pubkey) {
    VERIFY_CHECK(sizeof(ecmult::secp256k1_ge_storage)==64);

    ecmult::secp256k1_ge_storage s;
    std::memcpy(&s, &pubkey->data[0], 64);
    ecmult::secp256k1_ge_from_storage(ge, &s);

    /* Otherwise (sizeof(ecmult::secp256k1_ge_storage)!=64), fall back to 32-byte big endian for X and Y. */
    //ecmult::secp256k1_fe x, y;
    //ecmult::secp256k1_fe_set_be32(&x, pubkey->data);
    //ecmult::secp256k1_fe_set_be32(&y, pubkey->data + 32);
    //ecmult::secp256k1_ge_set_xy(ge, &x, &y);

    ARG_CHECK(!ecmult::secp256k1_fe_is_zero(&ge->x));
    return 1;
}

int CPubKey::ecmult::secp256k1_ge_is_infinity(const secp256k1_ge *a) {
    return a->infinity;
}

/** Convert a field element to a 32-byte big endian value. Requires the input to be normalized */
void CPubKey::ecmult::secp256k1_fe_get_be32(unsigned char *r, const secp256k1_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    secp256k1_fe_verify(a);
#endif
    r[0] = (a->n[9] >> 14) & 0xff;
    r[1] = (a->n[9] >> 6) & 0xff;
    r[2] = ((a->n[9] & 0x3F) << 2) | ((a->n[8] >> 24) & 0x3);
    r[3] = (a->n[8] >> 16) & 0xff;
    r[4] = (a->n[8] >> 8) & 0xff;
    r[5] = a->n[8] & 0xff;
    r[6] = (a->n[7] >> 18) & 0xff;
    r[7] = (a->n[7] >> 10) & 0xff;
    r[8] = (a->n[7] >> 2) & 0xff;
    r[9] = ((a->n[7] & 0x3) << 6) | ((a->n[6] >> 20) & 0x3f);
    r[10] = (a->n[6] >> 12) & 0xff;
    r[11] = (a->n[6] >> 4) & 0xff;
    r[12] = ((a->n[6] & 0xf) << 4) | ((a->n[5] >> 22) & 0xf);
    r[13] = (a->n[5] >> 14) & 0xff;
    r[14] = (a->n[5] >> 6) & 0xff;
    r[15] = ((a->n[5] & 0x3f) << 2) | ((a->n[4] >> 24) & 0x3);
    r[16] = (a->n[4] >> 16) & 0xff;
    r[17] = (a->n[4] >> 8) & 0xff;
    r[18] = a->n[4] & 0xff;
    r[19] = (a->n[3] >> 18) & 0xff;
    r[20] = (a->n[3] >> 10) & 0xff;
    r[21] = (a->n[3] >> 2) & 0xff;
    r[22] = ((a->n[3] & 0x3) << 6) | ((a->n[2] >> 20) & 0x3f);
    r[23] = (a->n[2] >> 12) & 0xff;
    r[24] = (a->n[2] >> 4) & 0xff;
    r[25] = ((a->n[2] & 0xf) << 4) | ((a->n[1] >> 22) & 0xf);
    r[26] = (a->n[1] >> 14) & 0xff;
    r[27] = (a->n[1] >> 6) & 0xff;
    r[28] = ((a->n[1] & 0x3f) << 2) | ((a->n[0] >> 24) & 0x3);
    r[29] = (a->n[0] >> 16) & 0xff;
    r[30] = (a->n[0] >> 8) & 0xff;
    r[31] = a->n[0] & 0xff;
}

int CPubKey::secp256k1_eckey_pubkey_serialize(ecmult::secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed) {
    if (ecmult::secp256k1_ge_is_infinity(elem))
        return 0;

    ecmult::secp256k1_fe_normalize_var(&elem->x);
    ecmult::secp256k1_fe_normalize_var(&elem->y);
    ecmult::secp256k1_fe_get_be32(&pub[1], &elem->x);
    if (compressed) {
        *size = COMPRESSED_PUBLIC_KEY_SIZE;
        pub[0] = ecmult::secp256k1_fe_is_odd(&elem->y) ? SECP256K1_TAG_PUBKEY_ODD : SECP256K1_TAG_PUBKEY_EVEN;
    } else {
        *size = PUBLIC_KEY_SIZE;
        pub[0] = SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
        ecmult::secp256k1_fe_get_be32(&pub[COMPRESSED_PUBLIC_KEY_SIZE], &elem->y);
    }
    return 1;
}

int CPubKey::secp256k1_ec_pubkey_serialize(unsigned char *output, size_t *outputlen, const secp256k1_pubkey *pubkey, unsigned int flags) {
    ecmult::secp256k1_ge Q;
    int ret = 0;

    //VERIFY_CHECK(ctx != nullptr);
    ARG_CHECK(outputlen != nullptr);
    *outputlen = 0;
    size_t len = (flags & SECP256K1_FLAGS_BIT_COMPRESSION) ? COMPRESSED_PUBLIC_KEY_SIZE : PUBLIC_KEY_SIZE;

    ARG_CHECK(output != nullptr);
    std::memset(output, 0, len);

    ARG_CHECK(pubkey != nullptr);
    ARG_CHECK((flags & SECP256K1_FLAGS_TYPE_MASK) == SECP256K1_FLAGS_TYPE_COMPRESSION);
    if (secp256k1_pubkey_load(&Q, pubkey)) {
        ret = secp256k1_eckey_pubkey_serialize(&Q, output, &len, flags & SECP256K1_FLAGS_BIT_COMPRESSION);
        if (ret) *outputlen = len;
    }

    return ret;
}

bool CPubKey::RecoverCompact(const uint256 &hash, const key_vector &vchSig) {
    if (vchSig.size() != COMPACT_SIGNATURE_SIZE)
        return false;

    int recid = (vchSig[0] - 27) & 3;
    bool fComp = ((vchSig[0] - 27) & 4) != 0;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recoverable_signature sig;
    if (! secp256k1_ecdsa_recoverable_signature_parse_compact(&sig, &vchSig[1], recid))
        return false;
    if (! secp256k1_ecdsa_recover(&pubkey, &sig, hash.begin()))
        return false;

    unsigned char pub[PUBLIC_KEY_SIZE];
    size_t publen;
    if(! secp256k1_ec_pubkey_serialize(pub, &publen, &pubkey, fComp ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED)) {
        Invalidate();
        return false; // if ge is infinity.
    }

    Set(pub, pub + publen);
    Compress();
    return true;
}

void CPubKey::ecmult::secp256k1_ge_set_xy(secp256k1_ge *r, const secp256k1_fe *x, const secp256k1_fe *y) {
    r->infinity = 0;
    r->x = *x;
    r->y = *y;
}

int CPubKey::ecmult::secp256k1_fe_equal_var(const secp256k1_fe *a, const secp256k1_fe *b) {
    secp256k1_fe na;
    secp256k1_fe_negate(&na, a, 1);
    secp256k1_fe_add(&na, b);
    return secp256k1_fe_normalizes_to_zero_var(&na);
}

int CPubKey::ecmult::secp256k1_ge_is_valid_var(const secp256k1_ge *a) {
    secp256k1_fe y2, x3, c;
    if (a->infinity)
        return 0;

    /* y^2 = x^3 + 7 */
    secp256k1_fe_sqr(&y2, &a->y);
    secp256k1_fe_sqr(&x3, &a->x); secp256k1_fe_mul(&x3, &x3, &a->x);
    secp256k1_fe_set_int(&c, CURVE_B);
    secp256k1_fe_add(&x3, &c);
    secp256k1_fe_normalize_weak(&x3);
    return secp256k1_fe_equal_var(&y2, &x3);
}

int CPubKey::secp256k1_eckey_pubkey_parse(ecmult::secp256k1_ge *elem, const unsigned char *pub, size_t size) {
    if (size == 33 && (pub[0] == SECP256K1_TAG_PUBKEY_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_ODD)) {
        ecmult::secp256k1_fe x;
        return ecmult::secp256k1_fe_set_be32(&x, pub+1) && ecmult::secp256k1_ge_set_xo_var(elem, &x, pub[0] == SECP256K1_TAG_PUBKEY_ODD);
    } else if (size == 65 && (pub[0] == 0x04 || pub[0] == 0x06 || pub[0] == 0x07)) {
        ecmult::secp256k1_fe x, y;
        if (!ecmult::secp256k1_fe_set_be32(&x, pub+1) || !ecmult::secp256k1_fe_set_be32(&y, pub+33))
            return 0;

        ecmult::secp256k1_ge_set_xy(elem, &x, &y);
        if ((pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD) &&
            ecmult::secp256k1_fe_is_odd(&y) != (pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD)) {
            return 0;
        }
        return ecmult::secp256k1_ge_is_valid_var(elem);
    } else
        return 0;
}

/*
int CPubKey::secp256k1_eckey_pubkey_parse_signed(ecmult::secp256k1_ge_signed *elem, const unsigned char *pub, size_t size) {
    if (size == 33 && (pub[0] == SECP256K1_TAG_PUBKEY_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_ODD)) {
        ecmult::secp256k1_fe_signed x;
        return ecmult::secp256k1_fe_set_be32(&x, pub+1) && ecmult::secp256k1_ge_set_xo_var(elem, &x, pub[0] == SECP256K1_TAG_PUBKEY_ODD);
    } else if (size == 65 && (pub[0] == 0x04 || pub[0] == 0x06 || pub[0] == 0x07)) {
        ecmult::secp256k1_fe_signed x, y;
        if (!ecmult::secp256k1_fe_set_be32(&x, pub+1) || !ecmult::secp256k1_fe_set_be32(&y, pub+33))
            return 0;

        ecmult::secp256k1_ge_set_xy(elem, &x, &y);
        if ((pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD) &&
            ecmult::secp256k1_fe_is_odd(&y) != (pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD)) {
            return 0;
        }
        return ecmult::secp256k1_ge_is_valid_var(elem);
    } else
        return 0;
}
*/

void CPubKey::ecmult::secp256k1_ge_clear(secp256k1_ge *r) {
    r->infinity = 0;
    secp256k1_fe_clear(&r->x);
    secp256k1_fe_clear(&r->y);
}

int CPubKey::secp256k1_ec_pubkey_parse(secp256k1_pubkey *pubkey, const unsigned char *input, size_t inputlen) {
    ecmult::secp256k1_ge Q;

    //VERIFY_CHECK(ctx != nullptr);
    ARG_CHECK(pubkey != nullptr);
    std::memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(input != nullptr);
    if (! secp256k1_eckey_pubkey_parse(&Q, input, inputlen))
        return 0;

    secp256k1_pubkey_save(pubkey, &Q);
    ecmult::secp256k1_ge_clear(&Q);
    return 1;
}

/*
int CPubKey::secp256k1_ec_pubkey_parse_signed(secp256k1_pubkey *pubkey, const unsigned char *input, size_t inputlen) {
    ecmult::secp256k1_ge Q;

    //VERIFY_CHECK(ctx != nullptr);
    ARG_CHECK(pubkey != nullptr);
    std::memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(input != nullptr);
    if (! secp256k1_eckey_pubkey_parse(&Q, input, inputlen))
        return 0;

    secp256k1_pubkey_save(pubkey, &Q);
    ecmult::secp256k1_ge_clear(&Q);
    return 1;
}
*/

bool CPubKey::Decompress() {
    if (! IsValid())
        return false;
    secp256k1_pubkey pubkey;
    if (! secp256k1_ec_pubkey_parse(&pubkey, vch_, size()))
        return false;

    unsigned char pub[PUBLIC_KEY_SIZE];
    size_t publen;
    if(! secp256k1_ec_pubkey_serialize(pub, &publen, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
        Invalidate();
        return false; // if ge is infinity.
    } else {
        Set(pub, pub + publen);
        return true;
    }
}

bool CPubKey::Compress() {
    if (! IsValid())
        return false;
    secp256k1_pubkey pubkey;
    if (! secp256k1_ec_pubkey_parse(&pubkey, vch_, size()))
        return false;

    unsigned char pub[COMPRESSED_PUBLIC_KEY_SIZE];
    size_t publen;
    if(! secp256k1_ec_pubkey_serialize(pub, &publen, &pubkey, SECP256K1_EC_COMPRESSED)) {
        Invalidate();
        return false; // if ge is infinity.
    } else {
        Set(pub, pub + publen);
        return true;
    }
}

void CPubKey::secp256k1_scalar_set_int(secp256k1_unit *r, unsigned int v) {
    r->d[0] = v;
    r->d[1] = 0;
    r->d[2] = 0;
    r->d[3] = 0;
    r->d[4] = 0;
    r->d[5] = 0;
    r->d[6] = 0;
    r->d[7] = 0;
}

void CPubKey::ecmult::secp256k1_ge_set_gej(secp256k1_ge *r, secp256k1_gej *a) {
    secp256k1_fe z2, z3;
    r->infinity = a->infinity;
    secp256k1_fe_inv(&a->z, &a->z);
    secp256k1_fe_sqr(&z2, &a->z);
    secp256k1_fe_mul(&z3, &a->z, &z2);
    secp256k1_fe_mul(&a->x, &a->x, &z2);
    secp256k1_fe_mul(&a->y, &a->y, &z3);
    secp256k1_fe_set_int(&a->z, 1);
    r->x = a->x;
    r->y = a->y;
}

int CPubKey::ecmult::secp256k1_gej_eq_x_var(const secp256k1_fe *x, const secp256k1_gej *a) {
    secp256k1_fe r, r2;
    VERIFY_CHECK(!a->infinity);
    secp256k1_fe_sqr(&r, &a->z); secp256k1_fe_mul(&r, &r, x);
    r2 = a->x; secp256k1_fe_normalize_weak(&r2);
    return secp256k1_fe_equal_var(&r, &r2);
}

int CPubKey::secp256k1_ecdsa_sig_verify(const secp256k1_unit *sigr, const secp256k1_unit *sigs, const ecmult::secp256k1_ge *pubkey, const secp256k1_unit *message) {
    unsigned char c[32];
    secp256k1_unit sn, u1, u2;
#if !defined(EXHAUSTIVE_TEST_ORDER)
    ecmult::secp256k1_fe xr;
#endif
    ecmult::secp256k1_gej pubkeyj;
    ecmult::secp256k1_gej pr;

    if (secp256k1_scalar_is_zero(sigr) || secp256k1_scalar_is_zero(sigs))
        return 0;

    secp256k1_scalar_inverse_var(&sn, sigs);
    secp256k1_scalar_mul(&u1, &sn, message);
    secp256k1_scalar_mul(&u2, &sn, sigr);
    ecmult::secp256k1_gej_set_ge(&pubkeyj, pubkey);
    if(! secp256k1_ecmult(&pr, &pubkeyj, &u2, &u1))
        return 0;
    if (ecmult::secp256k1_gej_is_infinity(&pr))
        return 0;

#if defined(EXHAUSTIVE_TEST_ORDER)
{
    secp256k1_uint computed_r;
    ecmult::secp256k1_ge pr_ge;
    ecmult::secp256k1_ge_set_gej(&pr_ge, &pr);
    secp256k1_fe_normalize(&pr_ge.x);

    ecmult::secp256k1_fe_get_be32(c, &pr_ge.x);
    secp256k1_scalar_set_be32(&computed_r, c, NULL);
    return secp256k1_scalar_eq(sigr, &computed_r);
}
#else
    secp256k1_scalar_get_be32(c, sigr);
    ecmult::secp256k1_fe_set_be32(&xr, c);

    /** We now have the recomputed R point in pr, and its claimed x coordinate (modulo n)
     *  in xr. Naively, we would extract the x coordinate from pr (requiring a inversion modulo p),
     *  compute the remainder modulo n, and compare it to xr. However:
     *
     *        xr == X(pr) mod n
     *    <=> exists h. (xr + h * n < p && xr + h * n == X(pr))
     *    [Since 2 * n > p, h can only be 0 or 1]
     *    <=> (xr == X(pr)) || (xr + n < p && xr + n == X(pr))
     *    [In Jacobian coordinates, X(pr) is pr.x / pr.z^2 mod p]
     *    <=> (xr == pr.x / pr.z^2 mod p) || (xr + n < p && xr + n == pr.x / pr.z^2 mod p)
     *    [Multiplying both sides of the equations by pr.z^2 mod p]
     *    <=> (xr * pr.z^2 mod p == pr.x) || (xr + n < p && (xr + n) * pr.z^2 mod p == pr.x)
     *
     *  Thus, we can avoid the inversion, but we have to check both cases separately.
     *  secp256k1_gej_eq_x implements the (xr * pr.z^2 mod p == pr.x) test.
     */
    if (ecmult::secp256k1_gej_eq_x_var(&xr, &pr)) {
        /* xr * pr.z^2 mod p == pr.x, so the signature is valid. */
        return 1;
    }
    if (ecmult::secp256k1_fe_cmp_var(&xr, &secp256k1_ecdsa_const_p_minus_order) >= 0) {
        /* xr + n >= p, so we can skip testing the second case. */
        return 0;
    }
    ecmult::secp256k1_fe_add(&xr, &secp256k1_ecdsa_const_order_as_fe);
    if (ecmult::secp256k1_gej_eq_x_var(&xr, &pr)) {
        /* (xr + n) * pr.z^2 mod p == pr.x, so the signature is valid. */
        return 1;
    }
    return 0;
#endif
}

int CPubKey::secp256k1_ecdsa_verify(const secp256k1_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pubkey) {
    ecmult::secp256k1_ge q;
    secp256k1_unit r, s;
    secp256k1_unit m;
    //VERIFY_CHECK(ctx != nullptr);
    //ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(msg32 != nullptr);
    ARG_CHECK(sig != nullptr);
    ARG_CHECK(pubkey != nullptr);

    secp256k1_scalar_set_be32(&m, msg32, nullptr);
    secp256k1_ecdsa_signature_load(&r, &s, sig);
    return (!secp256k1_scalar_is_high(&s) &&
            secp256k1_pubkey_load(&q, pubkey) &&
            secp256k1_ecdsa_sig_verify(&r, &s, &q, &m));
}

const CPubKey::ecmult::secp256k1_ge *CPubKey::ecmult::secp256k1_get_ge_const_g() {
    static constexpr secp256k1_ge secp256k1_ge_const_g = SECP256K1_GE_CONST(
        0x79BE667EUL, 0xF9DCBBACUL, 0x55A06295UL, 0xCE870B07UL,
        0x029BFCDBUL, 0x2DCE28D9UL, 0x59F2815BUL, 0x16F81798UL,
        0x483ADA77UL, 0x26A3C465UL, 0x5DA4FBFCUL, 0x0E1108A8UL,
        0xFD17B448UL, 0xA6855419UL, 0x9C47D08FUL, 0xFB10D4B8UL
    );
    return &secp256k1_ge_const_g;
}

// context
void CPubKey::ecmult::secp256k1_context::init() {
    pre_g_ = nullptr;
#ifdef USE_ENDOMORPHISM
    pre_g_128_ = nullptr;
#endif
}

bool CPubKey::ecmult::secp256k1_context::build() {
    if (pre_g_ != nullptr) return true;

    /* get the generator */
    secp256k1_gej gj;
    secp256k1_gej_set_ge(&gj, CPubKey::ecmult::secp256k1_get_ge_const_g());
    pre_g_ = (secp256k1_ge_storage (*)[])::malloc(sizeof((*pre_g_)[0]) * ECMULT_TABLE_SIZE(WINDOW_G));
    if(! pre_g_) return false;

    /* precompute the tables with odd multiples */
    secp256k1_ecmult_odd_multiples_table_storage_var(ECMULT_TABLE_SIZE(WINDOW_G), *pre_g_, &gj);

#ifdef USE_ENDOMORPHISM
    {
        pre_g_128_ = (secp256k1_ge_storage (*)[])::malloc(sizeof((*pre_g_128_)[0]) * ECMULT_TABLE_SIZE(WINDOW_G));
        if(! pre_g_128_) return false;

        /* calculate 2^128*generator */
        secp256k1_gej g_128j = gj;
        for (int i = 0; i < 128; ++i)
            secp256k1_gej_double_var(&g_128j, &g_128j, nullptr);
        secp256k1_ecmult_odd_multiples_table_storage_var(ECMULT_TABLE_SIZE(WINDOW_G), *pre_g_128_, &g_128j);
    }
#endif

    return true;
}

void CPubKey::ecmult::secp256k1_ge_set_table_gej_var(secp256k1_ge *r, const secp256k1_gej *a, const secp256k1_fe *zr, size_t len) {
    size_t i = len - 1;
    secp256k1_fe zi;

    if (len > 0) {
        /* Compute the inverse of the last z coordinate, and use it to compute the last affine output. */
        secp256k1_fe_inv(&zi, &a[i].z);
        secp256k1_ge_set_gej_zinv(&r[i], &a[i], &zi);

        /* Work out way backwards, using the z-ratios to scale the x/y values. */
        while (i > 0) {
            secp256k1_fe_mul(&zi, &zi, &zr[i]);
            i--;
            secp256k1_ge_set_gej_zinv(&r[i], &a[i], &zi);
        }
    }
}

bool CPubKey::ecmult::secp256k1_ecmult_odd_multiples_table_storage_var(int n, secp256k1_ge_storage *pre, const secp256k1_gej *a) {
    secp256k1_gej *prej = (secp256k1_gej*)::malloc(sizeof(secp256k1_gej) * n);
    secp256k1_ge *prea = (secp256k1_ge*)::malloc(sizeof(secp256k1_ge) * n);
    secp256k1_fe *zr = (secp256k1_fe*)::malloc(sizeof(secp256k1_fe) * n);
    if(! (prej && prea && zr)) {
        if(prea) ::free(prea);
        if(prej) ::free(prej);
        if(zr) ::free(zr);
        return false;
    }

    /* Compute the odd multiples in Jacobian form. */
    secp256k1_ecmult_odd_multiples_table(n, prej, zr, a);
    /* Convert them in batch to affine coordinates. */
    secp256k1_ge_set_table_gej_var(prea, prej, zr, n);
    /* Convert them to compact storage form. */
    for (int i = 0; i < n; ++i)
        secp256k1_ge_to_storage(&pre[i], &prea[i]);

    ::free(prea);
    ::free(prej);
    ::free(zr);
    return true;
}

CPubKey::ecmult::secp256k1_context::secp256k1_context() {
    init();
}

CPubKey::ecmult::secp256k1_context::~secp256k1_context() {
    clear();
}

void CPubKey::ecmult::secp256k1_context::clear() {
    ::free(pre_g_);
#ifdef USE_ENDOMORPHISM
    ::free(pre_g_128_);
#endif
    init();
}

int CPubKey::secp256k1_eckey_pubkey_tweak_add(ecmult::secp256k1_ge *key, const secp256k1_unit *tweak) {
    ecmult::secp256k1_gej pt;
    secp256k1_unit one;
    ecmult::secp256k1_gej_set_ge(&pt, key);
    secp256k1_scalar_set_int(&one, 1);
    if(! secp256k1_ecmult(&pt, &pt, &one, tweak))
        return 0;

    if (ecmult::secp256k1_gej_is_infinity(&pt))
        return 0;

    ecmult::secp256k1_ge_set_gej(key, &pt);
    return 1;
}

int CPubKey::secp256k1_ec_pubkey_tweak_add(secp256k1_pubkey *pubkey, const unsigned char *tweak) {
    ecmult::secp256k1_ge p;
    secp256k1_unit term;
    int ret = 0;
    int overflow = 0;
    //VERIFY_CHECK(ctx != nullptr);
    //ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkey != nullptr);
    ARG_CHECK(tweak != nullptr);

    secp256k1_scalar_set_be32(&term, tweak, &overflow);
    ret = !overflow && secp256k1_pubkey_load(&p, pubkey);
    std::memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        if (secp256k1_eckey_pubkey_tweak_add(&p, &term))
            secp256k1_pubkey_save(pubkey, &p);
        else
            ret = 0;
    }
    return ret;
}

bool CPubKey::Derive(CPubKey &pubkeyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode &cc) const {
    ARG_CHECK(IsValid());
    ARG_CHECK((nChild >> 31) == 0);
    ARG_CHECK(size() == COMPRESSED_PUBLIC_KEY_SIZE);
    unsigned char out[64];
    bip32::BIP32Hash(cc, nChild, *begin(), begin()+1, out);
    std::memcpy(ccChild.begin(), out+32, 32);
    secp256k1_pubkey pubkey;
    if (! secp256k1_ec_pubkey_parse(&pubkey, vch_, size()))
        return false;
    if (! secp256k1_ec_pubkey_tweak_add(&pubkey, out))
        return false;

    unsigned char pub[COMPRESSED_PUBLIC_KEY_SIZE];
    size_t publen;
    if(! secp256k1_ec_pubkey_serialize(pub, &publen, &pubkey, SECP256K1_EC_COMPRESSED)) {
        pubkeyChild.Invalidate();
        return false; // if ge is infinity.
    } else {
        assert(publen==COMPRESSED_PUBLIC_KEY_SIZE);
        pubkeyChild.Set(pub, pub + publen);
        return true;
    }
}

bool CPubKey::EncryptData(const key_vector &data, key_vector &encrypted) const {
    char error[1024] = "Unknown error";

    bool ret = false;
    EC_KEY *pkey = nullptr;
    ies_ctx_t *ctx = nullptr;
    cryptogram_t *cryptogram = nullptr;
    do {
        const unsigned char *pbegin = &vch_[0];
        pkey = ::EC_KEY_new_by_curve_name(NID_secp256k1);
        if (! pkey) break;
        if (! ::o2i_ECPublicKey(&pkey, &pbegin, size())) {
            //throw key_error("Unable to parse EC key");
            break;
        }

        ctx = cryptogram::create_context(pkey);
        if (! ::EC_KEY_get0_public_key(ctx->user_key)) {
            //throw key_error("Given EC key is not public key");
            break;
        }

        cryptogram = cryptogram::ecies_encrypt(ctx, (unsigned char *)&data[0], data.size(), error);
        if (cryptogram == nullptr) {
            //throw key_error(std::string("Error in encryption: %s") + error);
            break;
        }

        encrypted.resize(cryptogram::cryptogram_data_sum_length(cryptogram));
        const unsigned char *key_data = cryptogram::cryptogram_key_data(cryptogram);
        std::memcpy(&encrypted[0], key_data, encrypted.size());

        ret = true;
    } while(false);

    if(cryptogram) cryptogram::cryptogram_free(cryptogram);
    if(ctx) delete ctx;
    if(pkey) ::EC_KEY_free(pkey);

    return ret;
}

void CExtPubKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const {
    code[0] = nDepth;
    std::memcpy(code+1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;
    std::memcpy(code+9, chaincode.begin(), 32);
    assert(pubkey.size() == CPubKey::COMPRESSED_PUBLIC_KEY_SIZE);
    std::memcpy(code+41, pubkey.begin(), CPubKey::COMPRESSED_PUBLIC_KEY_SIZE);
}

void CExtPubKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE]) {
    nDepth = code[0];
    std::memcpy(vchFingerprint, code+1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    std::memcpy(chaincode.begin(), code+9, 32);
    pubkey.Set(code+41, code+BIP32_EXTKEY_SIZE);
}

bool CExtPubKey::Derive(CExtPubKey &out, unsigned int _nChild) const {
    out.nDepth = nDepth + 1;
    CKeyID id = pubkey.GetID();
    std::memcpy(&out.vchFingerprint[0], &id, 4);
    out.nChild = _nChild;
    return pubkey.Derive(out.pubkey, out.chaincode, _nChild, chaincode);
}

uint256 secp256k1_negate_ope::fe_get_uint256(const s256k1_fe *fe) { // fe (be normalized)
    uint256 value;
    CPubKey::ecmult::secp256k1_fe_get_be32((unsigned char *)&value, fe); // big endian
    auto le = [](uint32_t v) {
        uint32_t r=0;
        r |= (v & 0xFF000000UL) >> 24;
        r |= (v & 0x000000FFUL) << 24;
        r |= (v & 0x00FF0000UL) >> 8;
        r |= (v & 0x0000FF00UL) << 8;
        return r;
    };
    for(int i=0; i<4; ++i) {
        uint32_t t = *((uint32_t *)&value + i);
        *((uint32_t *)&value + i) = le(*((uint32_t *)&value + (7-i)));
        *((uint32_t *)&value + (7-i)) = le(t);
    }
    return value;
}

void secp256k1_negate_ope::fe_set_uint256(s256k1_fe *fe, const uint256 *lvalue) {
    uint256 bvalue = *lvalue;
    auto be = [](uint32_t v) {
        uint32_t r=0;
        r |= (v & 0xFF000000UL) >> 24;
        r |= (v & 0x000000FFUL) << 24;
        r |= (v & 0x00FF0000UL) >> 8;
        r |= (v & 0x0000FF00UL) << 8;
        return r;
    };
    for(int i=0; i<4; ++i) {
        uint32_t t = *((uint32_t *)&bvalue + i);
        *((uint32_t *)&bvalue + i) = be(*((uint32_t *)&bvalue + (7-i)));
        *((uint32_t *)&bvalue + (7-i)) = be(t);
    }
    CPubKey::ecmult::secp256k1_fe_set_be32(fe, (const unsigned char *)&bvalue);
}

std::string secp256k1_negate_ope::fe_ToString(const s256k1_fe *fe) { // fe (be normalized)
    return tfm::format("0x%s", fe_get_uint256(fe).ToString().c_str());
}

std::string secp256k1_negate_ope::fe_normalize_to_ToString(const s256k1_fe *fe) {
    CPubKey::ecmult::secp256k1_fe fe_str = *fe;
    CPubKey::ecmult::secp256k1_fe_normalize(&fe_str);
    return fe_ToString(&fe_str);
}

int secp256k1_negate_ope::fe_get_signed(const s256k1_fe *fe_na) { // negate[+fe_na] -: 0, +: 1
    CPubKey::ecmult::secp256k1_fe fe_check = *fe_na;
    CPubKey::ecmult::secp256k1_fe_normalize(&fe_check);
    return (fe_check.n[9]==0x3FFFFFUL) ? 0: 1;
}

int secp256k1_negate_ope::fe_get_negate(const s256k1_fe *fe_na) { // negate[+fe_na] -: 1, +: 0
    return fe_get_signed(fe_na)? 0: 1;
}

void secp256k1_negate_ope::fe_normalize_negative(s256k1_fe *fe_na) { // negate[-fe_na]
    static constexpr CPubKey::ecmult::secp256k1_fe fe_negone = SECP256K1_FE_CONST(
        0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL,
        0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL, 0xFFFFFC2EUL
    );

    CPubKey::ecmult::secp256k1_fe_add(fe_na, &fe_negone);
    CPubKey::ecmult::secp256k1_fe_normalize(fe_na);

    CPubKey::ecmult::secp256k1_fe fe_na_na;
    CPubKey::ecmult::secp256k1_fe_clear(&fe_na_na);
    CPubKey::ecmult::secp256k1_fe_negate(&fe_na_na, fe_na, 1);
    CPubKey::ecmult::secp256k1_fe_add(&fe_na_na, &fe_negone);
    CPubKey::ecmult::secp256k1_fe_normalize(&fe_na_na);
    *fe_na = fe_na_na;
}

int secp256k1_negate_ope::fe_normalize_to_cmp(s256k1_fe *fe1, s256k1_fe *fe2) { // fe1 cmp fe2
    CPubKey::ecmult::secp256k1_fe_normalize(fe1);
    CPubKey::ecmult::secp256k1_fe_normalize(fe2);
    return CPubKey::ecmult::secp256k1_fe_cmp(fe1, fe2);
}

int secp256k1_negate_ope::fe_add_to_negate(CPubKey::ecmult::secp256k1_fe *fe1, int fe1_negate, const CPubKey::ecmult::secp256k1_fe *fe2, int fe2_negate) { // fe1 = fe1 + fe2
    if(fe1_negate==fe2_negate) {
        CPubKey::ecmult::secp256k1_fe_add(fe1, fe2);
        return fe1_negate;
    } else if (fe1_negate==1&&fe2_negate==0) {
        CPubKey::ecmult::secp256k1_fe fe_na;
        CPubKey::ecmult::secp256k1_fe_negate(&fe_na, fe1, 1);
        CPubKey::ecmult::secp256k1_fe_add(&fe_na, fe2);
        int ne_sign = fe_get_negate(&fe_na);
        if(ne_sign==0)
            CPubKey::ecmult::secp256k1_fe_normalize(&fe_na);
        else
            fe_normalize_negative(&fe_na);
        *fe1 = fe_na;
        return ne_sign;
    } else {
        CPubKey::ecmult::secp256k1_fe fe_na;
        CPubKey::ecmult::secp256k1_fe_negate(&fe_na, fe2, 1);
        CPubKey::ecmult::secp256k1_fe_add(&fe_na, fe1);
        int ne_sign = fe_get_negate(&fe_na);
        if(ne_sign==0)
            CPubKey::ecmult::secp256k1_fe_normalize(&fe_na);
        else
            fe_normalize_negative(&fe_na);
        *fe1 = fe_na;
        return ne_sign;
    }
}

int secp256k1_negate_ope::fe_sub_to_negate(s256k1_fe *fe1, int fe1_negate, const s256k1_fe *fe2, int fe2_negate) { // fe1 = fe1 - fe2
    return fe_add_to_negate(fe1, fe1_negate, fe2, fe2_negate?0:1);
}

int secp256k1_negate_ope::fe_mul_to_negate(s256k1_fe *fe1, int fe1_negate, const s256k1_fe *fe2, int fe2_negate) { // fe1 = fe1 * fe2
    CPubKey::ecmult::secp256k1_fe fe_mul;
    CPubKey::ecmult::secp256k1_fe_mul(&fe_mul, fe1, fe2);
    CPubKey::ecmult::secp256k1_fe_normalize(&fe_mul);
    *fe1 = fe_mul;
    return ((fe1_negate^fe2_negate) & 0x01UL);
}

int secp256k1_negate_ope::fe_div_to_negate(s256k1_fe *fe1, int fe1_negate, const s256k1_fe *fe2, int fe2_negate) { // fe1 = fe1 / fe2
    if(CPubKey::ecmult::secp256k1_fe_cmp(fe1, fe2)==-1) {
        CPubKey::ecmult::secp256k1_fe_set_int(fe1, 0);
        return ((fe1_negate^fe2_negate) & 0x01UL);
    }

    CPubKey::ecmult::secp256k1_fe fe_div;
    CPubKey::ecmult::secp256k1_fe_inv(&fe_div, fe2);
    CPubKey::ecmult::secp256k1_fe fe_mul;
    CPubKey::ecmult::secp256k1_fe_mul(&fe_mul, &fe_div, fe1);
    CPubKey::ecmult::secp256k1_fe_normalize(&fe_mul);
    if(fe_mul.n[9] & 0x3FFFFFUL) {
        CPubKey::ecmult::secp256k1_fe fe_mod = *fe1;
        fe_mod_to_negate(&fe_mod, 0, fe2, 0);
        if(CPubKey::ecmult::secp256k1_fe_is_zero(&fe_mod)==1) {
            *fe1 = fe_mul;
            return ((fe1_negate^fe2_negate) & 0x01UL);
        }

        CPubKey::ecmult::secp256k1_fe fe_neg;
        CPubKey::ecmult::secp256k1_fe_negate(&fe_neg, &fe_mod, 1);
        CPubKey::ecmult::secp256k1_fe_add(&fe_neg, fe1);
        CPubKey::ecmult::secp256k1_fe_normalize(&fe_neg);
        int neg_sign = fe_div_to_negate(&fe_neg, fe1_negate, fe2, fe2_negate);
        *fe1 = fe_neg;
        return neg_sign;
    }

    *fe1 = fe_mul;
    return ((fe1_negate^fe2_negate) & 0x01UL);
}

int secp256k1_negate_ope::fe_mod_to_negate(s256k1_fe *fe1, int fe1_negate, const s256k1_fe *fe2, int fe2_negate) { // fe1 = fe1 % fe2
    (void)fe1_negate;
    (void)fe2_negate;
    if(CPubKey::ecmult::secp256k1_fe_cmp(fe1, fe2)==-1)
        return 0;
    CPubKey::ecmult::secp256k1_fe fe_1or2;
    CPubKey::ecmult::secp256k1_fe_set_int(&fe_1or2, 1);
    if(CPubKey::ecmult::secp256k1_fe_cmp(fe2, &fe_1or2)<=0) {
        CPubKey::ecmult::secp256k1_fe_set_int(fe1, 0);
        return 0;
    }
    CPubKey::ecmult::secp256k1_fe_set_int(&fe_1or2, 2);
    if(CPubKey::ecmult::secp256k1_fe_cmp(fe2, &fe_1or2)<=0) {
        if(CPubKey::ecmult::secp256k1_fe_is_odd(fe1)==1)
            CPubKey::ecmult::secp256k1_fe_set_int(fe1, 1);
        else
            CPubKey::ecmult::secp256k1_fe_set_int(fe1, 0);
        return 0;
    }
    CPubKey::ecmult::secp256k1_fe fe_div;
    CPubKey::ecmult::secp256k1_fe_inv(&fe_div, fe2);
    CPubKey::ecmult::secp256k1_fe fe_mul;
    CPubKey::ecmult::secp256k1_fe_mul(&fe_mul, &fe_div, fe1);
    CPubKey::ecmult::secp256k1_fe_normalize(&fe_mul);
    if(fe_mul.n[9] & 0x3FFFFFUL) {
        CPubKey::ecmult::secp256k1_fe fe_sqrv[1024];
        fe_sqrv[0] = *fe2;
        int sqrn_end = 1;
        for(;;) {
            CPubKey::ecmult::secp256k1_fe_mul(&fe_sqrv[sqrn_end], &fe_sqrv[sqrn_end-1], fe2);
            CPubKey::ecmult::secp256k1_fe_normalize(&fe_sqrv[sqrn_end]);
            if(CPubKey::ecmult::secp256k1_fe_cmp(fe1, &fe_sqrv[sqrn_end])<=0)
                break;
            ++sqrn_end;
        }
        CPubKey::ecmult::secp256k1_fe fe_neg;
        CPubKey::ecmult::secp256k1_fe fe_t1 = *fe1;
        int sqrn_ite = sqrn_end - 1;
        for(;;) {
            CPubKey::ecmult::secp256k1_fe_negate(&fe_neg, &fe_sqrv[sqrn_ite], 1);
            CPubKey::ecmult::secp256k1_fe_add(&fe_neg, &fe_t1);
            CPubKey::ecmult::secp256k1_fe_normalize(&fe_neg);
            if(CPubKey::ecmult::secp256k1_fe_cmp(&fe_neg, &fe_sqrv[sqrn_ite])<=0) {
                if(sqrn_ite==0)
                    break;
                else {
                    for(;;) {
                        --sqrn_ite;
                        if(CPubKey::ecmult::secp256k1_fe_cmp(&fe_neg, &fe_sqrv[sqrn_ite])>0) break;
                        if(sqrn_ite==0) break;
                    }
                    if(sqrn_ite==0) break;
                }
            }
            fe_t1 = fe_neg;
        }
        CPubKey::ecmult::secp256k1_fe fe_na = fe_neg;
        while(CPubKey::ecmult::secp256k1_fe_cmp(&fe_na, fe2)>0) {
            CPubKey::ecmult::secp256k1_fe_negate(&fe_na, fe2, 1);
            CPubKey::ecmult::secp256k1_fe_add(&fe_na, &fe_neg);
            CPubKey::ecmult::secp256k1_fe_normalize(&fe_na);
            fe_neg = fe_na;
        }
        if(CPubKey::ecmult::secp256k1_fe_cmp(&fe_na, fe2)==0)
            CPubKey::ecmult::secp256k1_fe_set_int(fe1, 0);
        else
            *fe1 = fe_na;
        return 0;
    } else {
        CPubKey::ecmult::secp256k1_fe_set_int(fe1, 0);
        return 0;
    }
}

int secp256k1_negate_ope::fe_pow_to_negate(s256k1_fe *fe1, int fe1_negate, unsigned int n) { // fe1^n (n>=0)
    if(n==0) {
        CPubKey::ecmult::secp256k1_fe_set_int(fe1, 1);
    } else {
        CPubKey::ecmult::secp256k1_fe fe_mul = *fe1;
        for(int i=0; i<n-1; ++i) {
            CPubKey::ecmult::secp256k1_fe fe_ret;
            CPubKey::ecmult::secp256k1_fe_mul(&fe_ret, &fe_mul, fe1);
            CPubKey::ecmult::secp256k1_fe_normalize(&fe_ret);
            fe_mul = fe_ret;
        }
        *fe1 = fe_mul;
    }
    if(fe1_negate==0)
        return 0;
    else
        return (n%2==0) ? 0: 1;
}
