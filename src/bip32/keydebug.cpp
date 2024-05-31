#include <key/pubkey.h>
#include <key/privkey.h>
#include <uint256.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#define VERIFY_CHECK(cond) do { (void)(cond); } while(0)

namespace schnorr_nonce {
    /* This nonce function is described in BIP-schnorr
     * (https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki) */
    int secp256k1_nonce_function_bipschnorr(unsigned char* nonce32, const unsigned char* msg32, const unsigned char* key32, const unsigned char* algo16, void* data, unsigned int counter) {
        CFirmKey::hash::secp256k1_sha256 sha;
        (void)data;
        (void)counter;
        VERIFY_CHECK(counter == 0);

        /* Hash x||msg as per the spec */
        CFirmKey::hash::secp256k1_sha256_initialize(&sha);
        CFirmKey::hash::secp256k1_sha256_write(&sha, key32, 32);
        CFirmKey::hash::secp256k1_sha256_write(&sha, msg32, 32);
        /* Hash in algorithm, which is not in the spec, but may be critical to
         * users depending on it to avoid nonce reuse across algorithms. */
        if (algo16 != NULL) {
            CFirmKey::hash::secp256k1_sha256_write(&sha, algo16, 16);
        }
        CFirmKey::hash::secp256k1_sha256_finalize(&sha, nonce32);
        return 1;
    }

    int secp256k1_nonce_and_random_function_schnorr(unsigned char* nonce32, const unsigned char* msg32, const unsigned char* key32, const unsigned char* algo16, void* data, unsigned int counter) {
        CFirmKey::hash::secp256k1_sha256 sha;
        (void)data;
        (void)counter;
        VERIFY_CHECK(counter == 0);

        unsigned char buf32[32];
        latest_crypto::random::GetStrongRandBytes(buf32, 32);

        /* Hash x||msg as per the spec */
        CFirmKey::hash::secp256k1_sha256_initialize(&sha);
        CFirmKey::hash::secp256k1_sha256_write(&sha, key32, 32);
        CFirmKey::hash::secp256k1_sha256_write(&sha, msg32, 32);
        CFirmKey::hash::secp256k1_sha256_write(&sha, buf32, 32);
        /* Hash in algorithm, which is not in the spec, but may be critical to
         * users depending on it to avoid nonce reuse across algorithms. */
        if (algo16 != NULL) {
            CFirmKey::hash::secp256k1_sha256_write(&sha, algo16, 16);
        }
        CFirmKey::hash::secp256k1_sha256_finalize(&sha, nonce32);
        return 1;
    }
} // schnorr_nonce

namespace schnorr_openssl {

int schnorr_sha256_standard(BIGNUM *e, const unsigned char *r32, const unsigned char *pub32, const unsigned char *mes32) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, r32, 32);
    SHA256_Update(&sha256, pub32, 32);
    SHA256_Update(&sha256, mes32, 32);
    SHA256_Final(hash, &sha256);
    if(!BN_bin2bn(hash, SHA256_DIGEST_LENGTH, e))
        return 0;

    return 1;
}

int schnorr_sha256_bitcoin(BIGNUM *e, const unsigned char *r32, const unsigned char *pub32, const unsigned char *mes32) {
    uint32_t d[8];
    d[0] = 0x9cecba11ul;
    d[1] = 0x23925381ul;
    d[2] = 0x11679112ul;
    d[3] = 0xd1627e0ful;
    d[4] = 0x97c87550ul;
    d[5] = 0x003cc765ul;
    d[6] = 0x90f61164ul;
    d[7] = 0x33e9b66aul;

    CFirmKey::hash::secp256k1_sha256 sha256;
    CFirmKey::hash::secp256k1_sha256_initialize(&sha256);
    sha256.InitSet(d, 64);

    CFirmKey::hash::secp256k1_sha256_write(&sha256, r32, 32);
    CFirmKey::hash::secp256k1_sha256_write(&sha256, pub32, 32);
    CFirmKey::hash::secp256k1_sha256_write(&sha256, mes32, 32);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    CFirmKey::hash::secp256k1_sha256_finalize(&sha256, &hash[0]);
    if(!BN_bin2bn(hash, SHA256_DIGEST_LENGTH, e))
        return 0;

    return 1;
}

int calculate_even_y_coordinate(const EC_GROUP *group, const BIGNUM *x, BIGNUM *y, BN_CTX *ctx) {
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *x3 = BN_new();
    BIGNUM *rhs = BN_new();
    BIGNUM *neg = BN_new();
    int fret = 0;

    do {
        if(!a || !b || !p || !x3 || !rhs)
            break;

        BN_zero(a);
        BN_set_word(b, 7);
        if (!EC_GROUP_get_curve_GFp(group, p, a, b, ctx))
            break;
        if (!BN_mod_sqr(x3, x, p, ctx))
            break;
        if (!BN_mod_mul(x3, x3, x, p, ctx))
            break;
        if (!BN_mod_add(rhs, x3, b, p, ctx))
            break;
        if (!BN_mod_sqrt(y, rhs, p, ctx))
            break;

        if(BN_is_odd(y)) {
            if(!BN_sub(neg, p, y))
                break;
            assert(!BN_is_odd(neg));
            if(!BN_copy(y, neg))
                break;
        }

        fret = 1;
    } while(false);

    BN_free(a);
    BN_free(b);
    BN_free(p);
    BN_free(x3);
    BN_free(rhs);
    BN_free(neg);

    return fret;
}

int BN_bn2bin_padded(const BIGNUM *bn, unsigned char *out, int size) {
    memset(out, 0, size);
    int num_bytes = BN_num_bytes(bn);
    if (num_bytes > size) {
        return 0;
    }

    BN_bn2bin(bn, out + size - num_bytes);
    return 1;
}

bool sign(const BIGNUM *privkey, const uint256 &hash, std::vector<unsigned char> &sig, bool *is_negated = nullptr) {
    // sig(fixed 64bytes) = [r_bytes(32bytes) | s(32bytes)]
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *order = BN_new();
    BIGNUM *k = BN_new();
    EC_POINT *R = EC_POINT_new(group);
    BIGNUM *e = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *pub_x = BN_new();
    BIGNUM *pub_y = BN_new();
    EC_POINT *pubkey = EC_POINT_new(group);
    BIGNUM *neg_one = BN_new();
    BIGNUM *R_y = BN_new();
    BIGNUM *sqrt_R_y = BN_new();

    bool fret = false;
    do {
        if(!group || !ctx || !order || !k || !R || !e || !s || !pub_x || !pub_y || !pubkey || !neg_one || !R_y || !sqrt_R_y)
            break;

        // get order (F_p mod)
        if(EC_GROUP_get_order(group, order, ctx) != 1)
            break;

        // get neg_one
        if(BN_set_word(neg_one, 1) != 1)
            break;
        if(BN_sub(neg_one, order, neg_one) != 1)
            break;

        // get public key
        if(EC_POINT_mul(group, pubkey, privkey, NULL, NULL, ctx) != 1)
            break;
        if(EC_POINT_get_affine_coordinates_GFp(group, pubkey, pub_x, pub_y, ctx) != 1)
            break;

        // generate random:nonce_function_bipschnorr k
        unsigned char nonce32[32];
        unsigned char key32[32];
        if(BN_bn2bin_padded(privkey, key32, 32) != 1)
            break;
        if(!schnorr_nonce::secp256k1_nonce_function_bipschnorr(nonce32, hash.begin(), key32, NULL, NULL, 0))
            break;
        if(!BN_bin2bn(nonce32, 32, k)) {
            OPENSSL_cleanse(nonce32, 32);
            OPENSSL_cleanse(key32, 32);
            break;
        }
        OPENSSL_cleanse(nonce32, 32);
        OPENSSL_cleanse(key32, 32);

        // R = k * G(EC base points)
        if(EC_POINT_mul(group, R, k, NULL, NULL, ctx) != 1)
            break;

        // if R_y cannot get sqrt, compute negate k
        if(!EC_POINT_get_affine_coordinates_GFp(group, R, NULL, R_y, ctx))
            break;
        if(is_negated)
            *is_negated = false;
        if(!BN_mod_sqrt(sqrt_R_y, R_y, order, ctx)) {
            if(BN_mod_mul(k, k, neg_one, order, ctx) != 1)
                break;
            if(is_negated)
                *is_negated = true;
        }

        unsigned char R_points[33];
        if(EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, R_points, sizeof(R_points), ctx) != sizeof(R_points))
            break;

        // e = sha256(R_points_xonly || pub_x || message)
        unsigned char R_points_xonly[32];
        ::memcpy(R_points_xonly, R_points + 1, 32);
        assert(hash.size() == 32);
        unsigned char pub_bin_x[32];
        if(BN_bn2bin_padded(pub_x, pub_bin_x, 32) != 1)
            break;
        if(schnorr_sha256_bitcoin(e, R_points_xonly, pub_bin_x, hash.begin()) != 1)
            break;

        // if pub_y is even: s = k + e * privkey
        // if pub_y is odd: s = k + invert(e) * privkey
        if(BN_is_odd(pub_y)) {
            if(!BN_sub(e, order, e)) // invert: sub from mod p
                break;
        }
        if(BN_mod_mul(s, e, privkey, order, ctx) != 1)
            break;
        if(BN_mod_add(s, s, k, order, ctx) != 1)
            break;

        // sig = [R_points_xonly | s]
        sig.resize(64);
        ::memcpy(&sig.front(), R_points_xonly, sizeof(R_points_xonly));
        if(BN_bn2bin_padded(s, &sig.front() + 32, 32) != 1)
            break;

        fret = true;
    } while(false);

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    BN_free(order);
    BN_clear_free(k);
    EC_POINT_free(R);
    BN_clear_free(e);
    BN_free(s);
    BN_free(pub_x);
    BN_free(pub_y);
    EC_POINT_free(pubkey);
    BN_free(neg_one);
    BN_free(R_y);
    BN_free(sqrt_R_y);

    return fret;
}

bool verify(const BIGNUM *pubkey_x, const uint256 &hash, const std::vector<unsigned char> &sig, bool fstrict = false) {
    // sig = [R_points_xonly | s]
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *order = BN_new();
    BIGNUM *R_x = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *e = BN_new();
    EC_POINT *lhs = EC_POINT_new(group);
    BIGNUM *pubkey_y = BN_new();
    EC_POINT *pubkey = EC_POINT_new(group);
    BIGNUM *R_y = BN_new();
    EC_POINT *R = EC_POINT_new(group);
    EC_POINT *e_mul_pubkey = EC_POINT_new(group);
    EC_POINT *rhs = EC_POINT_new(group);
    BIGNUM *neg_one = BN_new();
    EC_POINT *R2 = EC_POINT_new(group);
    BIGNUM *R2_x = BN_new();

    bool fret = false;
    do {
        if(!group || !ctx || !order || !R_x || !s || !e || !lhs || !pubkey_y || !pubkey || !R_y || !R || !e_mul_pubkey || !rhs || !neg_one || !R2 || !R2_x)
            break;

        // get order (F_p mod) and neg_one
        if(EC_GROUP_get_order(group, order, ctx) != 1)
            break;
        if(BN_set_word(neg_one, 1) != 1)
            break;
        if(BN_sub(neg_one, order, neg_one) != 1)
            break;

        // get R_x and s from sig
        if(!BN_bin2bn(sig.data(), 32, R_x))
            break;
        if(!BN_bin2bn(sig.data() + 32, 32, s))
            break;

        // e = sha256(R_points_xonly || pub_x || message)
        unsigned char R_points_xonly[32];
        ::memcpy(R_points_xonly, sig.data(), 32);
        assert(hash.size() == 32);
        unsigned char pub_bin_x[32] = {0};
        if(BN_bn2bin_padded(pubkey_x, pub_bin_x, 32) != 1)
            break;
        if(schnorr_sha256_bitcoin(e, R_points_xonly, pub_bin_x, hash.begin()) != 1)
            break;

        // lhs = s * G(EC base point)
        if(EC_POINT_mul(group, lhs, s, NULL, NULL, ctx) != 1)
            break;

        if(!fstrict) {
            // libsecp256k1: R2 = lhs - e * pubkey
            if(calculate_even_y_coordinate(group, pubkey_x, pubkey_y, ctx) != 1)
                break;
            if(EC_POINT_set_affine_coordinates_GFp(group, pubkey, pubkey_x, pubkey_y, ctx) != 1)
                break;
            if(calculate_even_y_coordinate(group, R_x, R_y, ctx) != 1)
                break;
            if(EC_POINT_set_affine_coordinates_GFp(group, R, R_x, R_y, ctx) != 1)
                break;
            if(EC_POINT_mul(group, e_mul_pubkey, NULL, pubkey, e, ctx) != 1)
                break;
            if(EC_POINT_mul(group, e_mul_pubkey, NULL, e_mul_pubkey, neg_one, ctx) != 1)
                break;
            if(EC_POINT_add(group, R2, lhs, e_mul_pubkey, ctx) != 1)
                break;
            if(EC_POINT_get_affine_coordinates_GFp(group, R2, R2_x, NULL, ctx) != 1)
                break;

            fret = BN_cmp(R_x, R2_x) == 0;
        } else {
            // schnorr strict mode: rhs = R + e * pubkey
            if(calculate_even_y_coordinate(group, pubkey_x, pubkey_y, ctx) != 1)
                break;
            if(EC_POINT_set_affine_coordinates_GFp(group, pubkey, pubkey_x, pubkey_y, ctx) != 1)
                break;
            if(calculate_even_y_coordinate(group, R_x, R_y, ctx) != 1)
                break;
            if(EC_POINT_set_affine_coordinates_GFp(group, R, R_x, R_y, ctx) != 1)
                break;
            if(EC_POINT_mul(group, e_mul_pubkey, NULL, pubkey, e, ctx) != 1)
                break;
            if(EC_POINT_add(group, rhs, R, e_mul_pubkey, ctx) != 1)
                break;

            BIGNUM *x1 = BN_new();
            BIGNUM *y1 = BN_new();
            EC_POINT_get_affine_coordinates_GFp(group, lhs, x1, y1, ctx);
            char *x1_str = BN_bn2hex(x1);
            char *y1_str = BN_bn2hex(y1);
            debugcs::instance() << __func__ << " schnorr strict mode lhs Coordinates:\nX: " << x1_str << "\nY: " << y1_str << debugcs::endl();
            BN_free(x1);
            BN_free(y1);
            OPENSSL_free(x1_str);
            OPENSSL_free(y1_str);

            BIGNUM *x2 = BN_new();
            BIGNUM *y2 = BN_new();
            EC_POINT_get_affine_coordinates_GFp(group, rhs, x2, y2, ctx);
            char *x2_str = BN_bn2hex(x2);
            char *y2_str = BN_bn2hex(y2);
            debugcs::instance() << __func__ << " schnorr strict mode rhs Coordinates:\nX: " << x2_str << "\nY: " << y2_str << debugcs::endl();
            BN_free(x2);
            BN_free(y2);
            OPENSSL_free(x2_str);
            OPENSSL_free(y2_str);

            fret = EC_POINT_cmp(group, lhs, rhs, ctx) == 0;
        }
    } while(false);

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    BN_free(order);
    BN_free(R_x);
    BN_free(s);
    BN_free(e);
    EC_POINT_free(lhs);
    BN_free(pubkey_y);
    EC_POINT_free(pubkey);
    BN_free(R_y);
    EC_POINT_free(R);
    EC_POINT_free(e_mul_pubkey);
    EC_POINT_free(rhs);
    BN_free(neg_one);
    EC_POINT_free(R2);
    BN_free(R2_x);

    return fret;
}

} // schnorr_openssl

# if !defined(SECP256K1_GNUC_PREREQ)
#  if defined(__GNUC__)&&defined(__GNUC_MINOR__)
#   define SECP256K1_GNUC_PREREQ(_maj,_min) \
 ((__GNUC__<<16)+__GNUC_MINOR__>=((_maj)<<16)+(_min))
#  else
#   define SECP256K1_GNUC_PREREQ(_maj,_min) 0
#  endif
# endif

/**Warning attributes
  * NONNULL is not used if SECP256K1_BUILD is set to avoid the compiler optimizing out
  * some paranoid null checks. */
# if defined(__GNUC__) && SECP256K1_GNUC_PREREQ(3, 4)
#  define SECP256K1_WARN_UNUSED_RESULT __attribute__ ((__warn_unused_result__))
# else
#  define SECP256K1_WARN_UNUSED_RESULT
# endif
# if !defined(SECP256K1_BUILD) && defined(__GNUC__) && SECP256K1_GNUC_PREREQ(3, 4)
#  define SECP256K1_ARG_NONNULL(_x)  __attribute__ ((__nonnull__(_x)))
# else
#  define SECP256K1_ARG_NONNULL(_x)
# endif

# if (!defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L) )
#  if SECP256K1_GNUC_PREREQ(2,7)
#   define SECP256K1_INLINE __inline__
#  elif (defined(_MSC_VER))
#   define SECP256K1_INLINE __inline
#  else
#   define SECP256K1_INLINE
#  endif
# else
#  define SECP256K1_INLINE inline
# endif

/** Opaque data structure that holds a parsed and valid "x-only" public key.
 *  An x-only pubkey encodes a point whose Y coordinate is even. It is
 *  serialized using only its X coordinate (32 bytes). See BIP-340 for more
 *  information about x-only pubkeys.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use secp256k1_xonly_pubkey_serialize and
 *  secp256k1_xonly_pubkey_parse.
 */
typedef struct {
    unsigned char data[64];
} secp256k1_xonly_pubkey; // X: 32bytes, Y: 32bytes = 64bytes

typedef struct {
    void (*fn)(const char *text, void* data);
    const void* data;
} secp256k1_callback;

static SECP256K1_INLINE void secp256k1_callback_call(const secp256k1_callback * const cb, const char * const text) {
    cb->fn(text, (void*)cb->data);
}

#ifdef HAVE_BUILTIN_EXPECT
#define EXPECT(x,c) __builtin_expect((x),(c))
#else
#define EXPECT(x,c) (x)
#endif

#define ARG_CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        return 0; \
    } \
} while(0)

#ifndef EXHAUSTIVE_TEST_ORDER
/* see group_impl.h for allowable values */
#define EXHAUSTIVE_TEST_ORDER 13
#define EXHAUSTIVE_TEST_LAMBDA 9   /* cube root of 1 mod 13 */
#endif

void Debug_secp256k1_print(const CPubKey::secp256k1_unit *d) {
    uint256 i256;
    CPubKey::secp256k1_scalar_get_be32(i256.begin(), d);
    debugcs::instance() << __func__ << " : " << i256.ToString() << debugcs::endl();
}

static void secp256k1_scalar_set_b32(CPubKey::secp256k1_unit *r, const unsigned char *b32, int *overflow) {
    int over;
    r->d[0] = (uint32_t)b32[31] | (uint32_t)b32[30] << 8 | (uint32_t)b32[29] << 16 | (uint32_t)b32[28] << 24;
    r->d[1] = (uint32_t)b32[27] | (uint32_t)b32[26] << 8 | (uint32_t)b32[25] << 16 | (uint32_t)b32[24] << 24;
    r->d[2] = (uint32_t)b32[23] | (uint32_t)b32[22] << 8 | (uint32_t)b32[21] << 16 | (uint32_t)b32[20] << 24;
    r->d[3] = (uint32_t)b32[19] | (uint32_t)b32[18] << 8 | (uint32_t)b32[17] << 16 | (uint32_t)b32[16] << 24;
    r->d[4] = (uint32_t)b32[15] | (uint32_t)b32[14] << 8 | (uint32_t)b32[13] << 16 | (uint32_t)b32[12] << 24;
    r->d[5] = (uint32_t)b32[11] | (uint32_t)b32[10] << 8 | (uint32_t)b32[9] << 16 | (uint32_t)b32[8] << 24;
    r->d[6] = (uint32_t)b32[7] | (uint32_t)b32[6] << 8 | (uint32_t)b32[5] << 16 | (uint32_t)b32[4] << 24;
    r->d[7] = (uint32_t)b32[3] | (uint32_t)b32[2] << 8 | (uint32_t)b32[1] << 16 | (uint32_t)b32[0] << 24;
    over = CPubKey::secp256k1_scalar_reduce(r, CPubKey::secp256k1_scalar_check_overflow(r));
    if (overflow) {
        *overflow = over;
    }
}

static int secp256k1_fe_is_quad_var(const CPubKey::ecmult::secp256k1_fe *a) {
#ifndef USE_NUM_NONE // using gmp
    unsigned char b[32];
    secp256k1_num n;
    secp256k1_num m;
    /* secp256k1 field prime, value p defined in "Standards for Efficient Cryptography" (SEC2) 2.7.1. */
    static const unsigned char prime[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F
    };

    secp256k1_fe c = *a;
    secp256k1_fe_normalize_var(&c);
    secp256k1_fe_get_b32(b, &c);
    secp256k1_num_set_bin(&n, b, 32);
    secp256k1_num_set_bin(&m, prime, 32);
    return secp256k1_num_jacobi(&n, &m) >= 0;
#else
    CPubKey::ecmult::secp256k1_fe r;
    return CPubKey::ecmult::secp256k1_fe_sqrt(&r, a);
#endif
}

/** Convert a field element to a 32-byte big endian value. Requires the input to be normalized */
static void secp256k1_fe_get_b32(unsigned char *r, const CPubKey::ecmult::secp256k1_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    CPubKey::ecmult::secp256k1_fe_verify(a);
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

static void secp256k1_scalar_get_b32(unsigned char *bin, const CPubKey::secp256k1_unit *a) {
    bin[0] = a->d[7] >> 24; bin[1] = a->d[7] >> 16; bin[2] = a->d[7] >> 8; bin[3] = a->d[7];
    bin[4] = a->d[6] >> 24; bin[5] = a->d[6] >> 16; bin[6] = a->d[6] >> 8; bin[7] = a->d[6];
    bin[8] = a->d[5] >> 24; bin[9] = a->d[5] >> 16; bin[10] = a->d[5] >> 8; bin[11] = a->d[5];
    bin[12] = a->d[4] >> 24; bin[13] = a->d[4] >> 16; bin[14] = a->d[4] >> 8; bin[15] = a->d[4];
    bin[16] = a->d[3] >> 24; bin[17] = a->d[3] >> 16; bin[18] = a->d[3] >> 8; bin[19] = a->d[3];
    bin[20] = a->d[2] >> 24; bin[21] = a->d[2] >> 16; bin[22] = a->d[2] >> 8; bin[23] = a->d[2];
    bin[24] = a->d[1] >> 24; bin[25] = a->d[1] >> 16; bin[26] = a->d[1] >> 8; bin[27] = a->d[1];
    bin[28] = a->d[0] >> 24; bin[29] = a->d[0] >> 16; bin[30] = a->d[0] >> 8; bin[31] = a->d[0];
}

static int secp256k1_fe_set_b32(CPubKey::ecmult::secp256k1_fe *r, const unsigned char *a) {
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

    if (r->n[9] == 0x3FFFFFUL && (r->n[8] & r->n[7] & r->n[6] & r->n[5] & r->n[4] & r->n[3] & r->n[2]) == 0x3FFFFFFUL && (r->n[1] + 0x40UL + ((r->n[0] + 0x3D1UL) >> 26)) > 0x3FFFFFFUL) {
        return 0;
    }
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    CPubKey::ecmult::secp256k1_fe_verify(r);
#endif
    return 1;
}

/* using gmp
static void secp256k1_scalar_inverse_var() {
    unsigned char b[32];
    secp256k1_num n, m;
    CPubKey::secp256k1_unit t = *x;
    secp256k1_scalar_get_b32(b, &t);
    secp256k1_num_set_bin(&n, b, 32);
    secp256k1_scalar_order_get_num(&m);
    secp256k1_num_mod_inverse(&n, &n, &m);
    secp256k1_num_get_bin(b, 32, &n);
    secp256k1_scalar_set_b32(r, b, NULL);
    CPubKey::secp256k1_scalar_mul(&t, &t, r);
    CHECK(secp256k1_scalar_is_one(&t));
}
*/

/*
static void default_illegal_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "[libsecp256k1] illegal argument: %s\n", str);
    abort();
}

static const secp256k1_callback default_illegal_callback = {
    default_illegal_callback_fn,
    NULL
};

static void default_error_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "[libsecp256k1] internal consistency check failed: %s\n", str);
    abort();
}

static const secp256k1_callback default_error_callback = {
    default_error_callback_fn,
    NULL
};
*/

/*
struct secp256k1_context_struct {
    CPubKey::ecmult::secp256k1_context ecmult_ctx;
    CFirmKey::ecmult::secp256k1_gen_context ecmult_gen_ctx;
    secp256k1_callback illegal_callback;
    secp256k1_callback error_callback;
};
*/

/** Opaque data structure that holds context information (precomputed tables etc.).
 *
 *  The purpose of context structures is to cache large precomputed data tables
 *  that are expensive to construct, and also to maintain the randomization data
 *  for blinding.
 *
 *  Do not create a new context object for each operation, as construction is
 *  far slower than all other API calls (~100 times slower than an ECDSA
 *  verification).
 *
 *  A constructed context can safely be used from multiple threads
 *  simultaneously, but API call that take a non-const pointer to a context
 *  need exclusive access to it. In particular this is the case for
 *  secp256k1_context_destroy and secp256k1_context_randomize.
 *
 *  Regarding randomization, either do it once at creation time (in which case
 *  you do not need any locking for the other calls), or use a read-write lock.
 */
//typedef struct secp256k1_context_struct secp256k1_context;

/** A pointer to a function to deterministically generate a nonce.
 *
 * Returns: 1 if a nonce was successfully generated. 0 will cause signing to fail.
 * Out:     nonce32:   pointer to a 32-byte array to be filled by the function.
 * In:      msg32:     the 32-byte message hash being verified (will not be NULL)
 *          key32:     pointer to a 32-byte secret key (will not be NULL)
 *          algo16:    pointer to a 16-byte array describing the signature
 *                     algorithm (will be NULL for ECDSA for compatibility).
 *          data:      Arbitrary data pointer that is passed through.
 *          attempt:   how many iterations we have tried to find a nonce.
 *                     This will almost always be 0, but different attempt values
 *                     are required to result in a different nonce.
 *
 * Except for test cases, this function should compute some cryptographic hash of
 * the message, the algorithm, the key and the attempt.
 */
typedef int (*secp256k1_nonce_function)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *algo16,
    void *data,
    unsigned int attempt
);

/** Opaque data structure that holds a parsed Schnorr signature.
  *
  *  The exact representation of data inside is implementation defined and not
  *  guaranteed to be portable between different platforms or versions. It is
  *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
  *  If you need to convert to a format suitable for storage, transmission, or
  *  comparison, use the `secp256k1_schnorrsig_serialize` and
  *  `secp256k1_schnorrsig_parse` functions.
  */
typedef struct {
    unsigned char data[64];
} secp256k1_schnorrsig;

static SECP256K1_INLINE void *checked_malloc(const secp256k1_callback* cb, size_t size) {
    void *ret = malloc(size);
    if (ret == NULL) {
        secp256k1_callback_call(cb, "Out of memory");
    }
    return ret;
}

static SECP256K1_INLINE void *checked_realloc(const secp256k1_callback* cb, void *ptr, size_t size) {
    void *ret = realloc(ptr, size);
    if (ret == NULL) {
        secp256k1_callback_call(cb, "Out of memory");
    }
    return ret;
}

/* Extract the sign of an int64, take the abs and return a uint64, constant time. */
SECP256K1_INLINE static int secp256k1_sign_and_abs64(uint64_t *out, int64_t in) {
    uint64_t mask0, mask1;
    int ret;
    ret = in < 0;
    mask0 = ret + ~((uint64_t)0);
    mask1 = ~mask0;
    *out = (uint64_t)in;
    *out = (*out & mask0) | ((~*out + 1) & mask1);
    return ret;
}

SECP256K1_INLINE static int secp256k1_clz64_var(uint64_t x) {
    int ret;
    if (!x) {
        return 64;
    }
# if defined(HAVE_BUILTIN_CLZLL)
    ret = __builtin_clzll(x);
# else
    /*FIXME: debruijn fallback. */
    for (ret = 0; ((x & (1ULL << 63)) == 0); x <<= 1, ret++);
# endif
    return ret;
}

/* Zero memory if flag == 1. Flag must be 0 or 1. Constant time. */
static SECP256K1_INLINE void memczero(void* s, size_t len, int flag)
{
    unsigned char* p = (unsigned char*)s;
    /* Access flag with a volatile-qualified lvalue.
       This prevents clang from figuring out (after inlining) that flag can
       take only be 0 or 1, which leads to variable time code. */
    volatile int vflag = flag;
    unsigned char mask = -(unsigned char)vflag;
    while (len) {
        *p &= ~mask;
        p++;
        len--;
    }
}

/** Semantics like memcmp. Variable-time.
 *
 * We use this to avoid possible compiler bugs with memcmp, e.g.
 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=95189
 */
static SECP256K1_INLINE int secp256k1_memcmp_var(const void* s1, const void* s2, size_t n)
{
    const unsigned char *p1 = (unsigned char *)s1, *p2 = (unsigned char *)s2;
    size_t i;

    for (i = 0; i < n; i++) {
        int diff = p1[i] - p2[i];
        if (diff != 0) {
            return diff;
        }
    }
    return 0;
}

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time.  Both *r and *a must be initialized and non-negative.*/
static SECP256K1_INLINE void secp256k1_int_cmov(int* r, const int* a, int flag)
{
    unsigned int mask0, mask1, r_masked, a_masked;
    /* Access flag with a volatile-qualified lvalue.
       This prevents clang from figuring out (after inlining) that flag can
       take only be 0 or 1, which leads to variable time code. */
    volatile int vflag = flag;

    /* Casting a negative int to unsigned and back to int is implementation defined behavior */
    VERIFY_CHECK(*r >= 0 && *a >= 0);

    mask0 = (unsigned int)vflag + ~0u;
    mask1 = ~mask0;
    r_masked = ((unsigned int)*r & mask0);
    a_masked = ((unsigned int)*a & mask1);

    *r = (int)(r_masked | a_masked);
}

/* Initializes a sha256 struct and writes the 64 byte string
 * SHA256(tag)||SHA256(tag) into it. */
static void secp256k1_sha256_initialize_tagged(CFirmKey::hash::secp256k1_sha256* hash, const unsigned char* tag, size_t taglen)
{
    unsigned char buf[32];
    CFirmKey::hash::secp256k1_sha256_initialize(hash);
    CFirmKey::hash::secp256k1_sha256_write(hash, tag, taglen);
    CFirmKey::hash::secp256k1_sha256_finalize(hash, buf);

    CFirmKey::hash::secp256k1_sha256_initialize(hash);
    CFirmKey::hash::secp256k1_sha256_write(hash, buf, 32);
    CFirmKey::hash::secp256k1_sha256_write(hash, buf, 32);
}

int secp256k1_schnorrsig_serialize(unsigned char *out64, const secp256k1_schnorrsig* sig) {
    ARG_CHECK(out64 != NULL);
    ARG_CHECK(sig != NULL);
    memcpy(out64, sig->data, 64);
    return 1;
}

int secp256k1_schnorrsig_parse(secp256k1_schnorrsig* sig, const unsigned char *in64) {
    ARG_CHECK(sig != NULL);
    ARG_CHECK(in64 != NULL);
    memcpy(sig->data, in64, 64);
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/nonce")||SHA256("BIP0340/nonce"). */
static void secp256k1_nonce_function_bip340_sha256_tagged(CFirmKey::hash::secp256k1_sha256* sha)
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
static void secp256k1_nonce_function_bip340_sha256_tagged_aux(CFirmKey::hash::secp256k1_sha256* sha)
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

static int nonce_function_bip340(unsigned char* nonce32, const unsigned char* msg32, const unsigned char* key32, const unsigned char* xonly_pk32, const unsigned char* algo16, void* data)
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
    if (secp256k1_memcmp_var(algo16, bip340_algo16, 16) == 0) {
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

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/challenge")||SHA256("BIP0340/challenge"). */
static void secp256k1_schnorrsig_sha256_tagged(CFirmKey::hash::secp256k1_sha256* sha)
{
    uint32_t d[8];
    d[0] = 0x9cecba11ul;
    d[1] = 0x23925381ul;
    d[2] = 0x11679112ul;
    d[3] = 0xd1627e0ful;
    d[4] = 0x97c87550ul;
    d[5] = 0x003cc765ul;
    d[6] = 0x90f61164ul;
    d[7] = 0x33e9b66aul;

    CFirmKey::hash::secp256k1_sha256_initialize(sha);
    sha->InitSet(d, 64);
}

static void secp256k1_schnorrsig_challenge(CPubKey::secp256k1_unit* e, const unsigned char* r32, const unsigned char* msg32, const unsigned char* pubkey32)
{
    unsigned char hash[32];
    CFirmKey::hash::secp256k1_sha256 sha;

    /* tagged hash(r.x, pk.x, msg32) */
    secp256k1_schnorrsig_sha256_tagged(&sha);
    CFirmKey::hash::secp256k1_sha256_write(&sha, r32, 32);
    CFirmKey::hash::secp256k1_sha256_write(&sha, pubkey32, 32);
    CFirmKey::hash::secp256k1_sha256_write(&sha, msg32, 32);
    CFirmKey::hash::secp256k1_sha256_finalize(&sha, hash);
    /* Set scalar e to the challenge hash modulo the curve order as per
     * BIP340. */
    secp256k1_scalar_set_b32(e, hash, NULL);
}

static void secp256k1_schnorrsig_standard(CPubKey::secp256k1_unit* e, const unsigned char* r32, const unsigned char* msg32, const unsigned char* pubkey32)
{
    unsigned char hash[32];
    CFirmKey::hash::secp256k1_sha256 sha;

    /* standard hash(r.x, pk.x, msg32) */
    CFirmKey::hash::secp256k1_sha256_initialize(&sha);
    CFirmKey::hash::secp256k1_sha256_write(&sha, r32, 32);
    CFirmKey::hash::secp256k1_sha256_write(&sha, pubkey32, 32);
    CFirmKey::hash::secp256k1_sha256_write(&sha, msg32, 32);
    CFirmKey::hash::secp256k1_sha256_finalize(&sha, hash);
    /* Set scalar e to the challenge hash modulo the curve order as per
     * BIP340. */
    secp256k1_scalar_set_b32(e, hash, NULL);
}

/** Create a Schnorr signature.
 *
 * Returns 1 on success, 0 on failure.
 *  Args:
 *  Out:     sig: pointer to the returned signature (cannot be NULL)
 *       nonce_is_negated: a pointer to an integer indicates if signing algorithm negated the
 *                nonce (can be NULL)
 *  In:    msg32: the 32-byte message hash being signed (cannot be NULL)
 *        seckey: pointer to a 32-byte secret key (cannot be NULL)
 *       noncefp: pointer to a nonce generation function. If NULL, secp256k1_nonce_function_bipschnorr is used
 *         ndata: pointer to arbitrary data used by the nonce generation function (can be NULL)
 */
static int secp256k1_schnorrsig_sign(secp256k1_schnorrsig *sig, int *nonce_is_negated, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, void *ndata) {
    ARG_CHECK(sig != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(seckey != NULL);

    // get secret key (from seckey to x)
    CPubKey::secp256k1_unit x;
    int overflow;
    secp256k1_scalar_set_b32(&x, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (overflow || CPubKey::secp256k1_scalar_is_zero(&x)) {
        cleanse::memory_cleanse(sig->data, sizeof(sig->data));
        return 0;
    }

    // get public key (pubkey = x * G)
    CPubKey::ecmult::secp256k1_gej pkj;
    CPubKey::ecmult::secp256k1_ge pk;
    CFirmKey::ecmult::secp256k1_gen_context ctx;
    if(!ctx.build())
        return 0;
    ctx.secp256k1_ecmult_gen(&pkj, &x);
    CPubKey::ecmult::secp256k1_ge_set_gej(&pk, &pkj);

    // get nonce k (random number for signature)
    CPubKey::secp256k1_unit k;
    unsigned char buf[32];
    if (noncefp == NULL)
        noncefp = schnorr_nonce::secp256k1_nonce_function_bipschnorr;
    if (!noncefp(buf, msg32, seckey, NULL, (void*)ndata, 0))
        return 0;
    secp256k1_scalar_set_b32(&k, buf, NULL);
    if (CPubKey::secp256k1_scalar_is_zero(&k))
        return 0;

    // get and check r = k*G (if r.y cannot get sqrt, compute negate k)
    CPubKey::ecmult::secp256k1_gej rj;
    CPubKey::ecmult::secp256k1_ge r;
    if(!ctx.secp256k1_ecmult_gen(&rj, &k))
        return 0;
    CPubKey::ecmult::secp256k1_ge_set_gej(&r, &rj);
    if (nonce_is_negated != NULL)
        *nonce_is_negated = 0;
    if (!secp256k1_fe_is_quad_var(&r.y)) {
        CPubKey::secp256k1_scalar_negate(&k, &k);
        if (nonce_is_negated != NULL)
            *nonce_is_negated = 1;
    }

    // store signature [(r.x) | s]
    CPubKey::ecmult::secp256k1_fe_normalize(&r.x);
    secp256k1_fe_get_b32(&sig->data[0], &r.x);

    /* Compute e. */
    CPubKey::secp256k1_unit e;
    unsigned char pub_buf[33];
    size_t pub_buflen;
    CPubKey::secp256k1_eckey_pubkey_serialize(&pk, pub_buf, &pub_buflen, 1);
    if(pub_buflen != 33)
        return 0;
    secp256k1_schnorrsig_challenge(&e, &sig->data[0], msg32, pub_buf + 1);

    // generate s = k + e * privkey
    CPubKey::secp256k1_scalar_mul(&e, &e, &x);
    CPubKey::secp256k1_scalar_add(&e, &e, &k);

    // store signature [r.x | (s)]
    secp256k1_scalar_get_b32(&sig->data[32], &e);

    // clean up
    CFirmKey::secp256k1_scalar_clear(&k);
    CFirmKey::secp256k1_scalar_clear(&x);
    cleanse::memory_cleanse(&k, sizeof(k));
    cleanse::memory_cleanse(&x, sizeof(x));

    return 1;
}

/* Helper function for verification and batch verification.
 * Computes R = sG - eP. */
static int secp256k1_schnorrsig_real_verify(CPubKey::ecmult::secp256k1_gej *rj, const CPubKey::secp256k1_unit *s, const CPubKey::secp256k1_unit *e, const CPubKey::secp256k1_pubkey *pk) {
    CPubKey::secp256k1_unit nege;
    CPubKey::ecmult::secp256k1_ge pkp;
    CPubKey::ecmult::secp256k1_gej pkj;

    CPubKey::secp256k1_scalar_negate(&nege, e);

    if (!CPubKey::secp256k1_pubkey_load(&pkp, pk)) {
        return 0;
    }
    CPubKey::ecmult::secp256k1_gej_set_ge(&pkj, &pkp);

    /* rj =  s*G + (-e)*pkj */
    CPubKey::secp256k1_ecmult(rj, &pkj, &nege, s);
    return 1;
}

static SECP256K1_INLINE int secp256k1_xonly_pubkey_load(CPubKey::ecmult::secp256k1_ge *ge, const secp256k1_xonly_pubkey *pubkey) {
    return CPubKey::secp256k1_pubkey_load(ge, (const CPubKey::secp256k1_pubkey *) pubkey);
}

static int secp256k1_schnorrsig_verify(const unsigned char* sig64, const unsigned char* msg32, const secp256k1_xonly_pubkey* pubkey)
{
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pubkey != NULL);

    // get R_x
    CPubKey::ecmult::secp256k1_fe rx;
    if (!secp256k1_fe_set_b32(&rx, &sig64[0]))
        return 0;

    // get s
    CPubKey::secp256k1_unit s;
    int overflow;
    secp256k1_scalar_set_b32(&s, &sig64[32], &overflow);
    if (overflow)
        return 0;

    // get pubkey (pk: affine X and Y)
    CPubKey::ecmult::secp256k1_ge pk;
    if (!secp256k1_xonly_pubkey_load(&pk, pubkey))
        return 0;

    /* Compute e. */
    CPubKey::secp256k1_unit e;
    unsigned char pub_x[32];
    secp256k1_fe_get_b32(pub_x, &pk.x);
    secp256k1_schnorrsig_challenge(&e, &sig64[0], msg32, pub_x);

    /* Compute rj =  s*G + (-e)*pkj */
    CPubKey::ecmult::secp256k1_gej pkj;
    CPubKey::ecmult::secp256k1_gej rj;
    CPubKey::ecmult::secp256k1_ge r;
    CPubKey::secp256k1_scalar_negate(&e, &e);
    CPubKey::ecmult::secp256k1_gej_set_ge(&pkj, &pk);
    if(!CPubKey::secp256k1_ecmult(&rj, &pkj, &e, &s))
        return 0;
    CPubKey::ecmult::secp256k1_ge_set_gej_var(&r, &rj);
    if(CPubKey::ecmult::secp256k1_ge_is_infinity(&r))
        return 0;

    CPubKey::ecmult::secp256k1_fe_normalize_var(&r.y);
    return !CPubKey::ecmult::secp256k1_fe_is_odd(&r.y) &&
           CPubKey::ecmult::secp256k1_fe_equal_var(&rx, &r.x);
}

EC_KEY *Create_pub_y_odd_eckey(const EC_GROUP *group, BN_CTX *ctx) {
    BIGNUM *privkey = BN_new();
    EC_POINT *pubkey = EC_POINT_new(group);
    BIGNUM *pub_y = BN_new();
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);

    do {
        bool fret = false;
        do {
            unsigned char r[32];
            latest_crypto::random::GetStrongRandBytes(r, 32);
            if(!BN_bin2bn(r, 32, privkey))
                break;
            OPENSSL_cleanse(r, 32);
            if(EC_POINT_mul(group, pubkey, privkey, NULL, NULL, ctx) != 1)
                continue;
            if(EC_POINT_get_affine_coordinates_GFp(group, pubkey, NULL, pub_y, ctx) != 1)
                continue;
            if(BN_is_odd(pub_y)) {
                fret = true;
                break;
            }
        } while(true);
        if(!fret) {
            EC_KEY_free(eckey);
            eckey = NULL;
            break;
        }

        if(EC_KEY_set_private_key(eckey, privkey) != 1)
            break;
        if(EC_KEY_set_public_key(eckey, pubkey) != 1)
            break;
    } while(false);

    BN_free(privkey);
    EC_POINT_free(pubkey);
    BN_free(pub_y);

    return eckey;
}

EC_KEY *Create_pub_y_even_eckey(const EC_GROUP *group, BN_CTX *ctx) {
    BIGNUM *privkey = BN_new();
    EC_POINT *pubkey = EC_POINT_new(group);
    BIGNUM *pub_y = BN_new();
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);

    do {
        bool fret = false;
        do {
            unsigned char r[32];
            latest_crypto::random::GetStrongRandBytes(r, 32);
            if(!BN_bin2bn(r, 32, privkey))
                break;
            OPENSSL_cleanse(r, 32);
            if(EC_POINT_mul(group, pubkey, privkey, NULL, NULL, ctx) != 1)
                continue;
            if(EC_POINT_get_affine_coordinates_GFp(group, pubkey, NULL, pub_y, ctx) != 1)
                continue;
            if(!BN_is_odd(pub_y)) {
                fret = true;
                break;
            }
        } while(true);
        if(!fret) {
            EC_KEY_free(eckey);
            eckey = NULL;
            break;
        }

        if(EC_KEY_set_private_key(eckey, privkey) != 1)
            break;
        if(EC_KEY_set_public_key(eckey, pubkey) != 1)
            break;
    } while(false);

    BN_free(privkey);
    EC_POINT_free(pubkey);
    BN_free(pub_y);

    return eckey;
}

// args: privkey is nullptr(this case is random) or must be public_y even
std::shared_ptr<CFirmKey> Create_pub_y_even_key(const unsigned char *privkey = nullptr) {
    std::shared_ptr<CFirmKey> key(new (std::nothrow) CFirmKey);
    if(!key.get())
        return key;
    do {
        CSecret secret;
        secret.resize(32);
        if(!privkey)
            latest_crypto::random::GetStrongRandBytes(&secret.front(), 32);
        else // privkey must be public_y even
            ::memcpy(&secret.front(), privkey, 32);
        key.get()->SetSecret(secret);
        CPubKey pubkey = key.get()->GetPubKey();
        pubkey.Compress();
        if(pubkey.data()[0] == 0x02)
            return key;
        else {
            // if exists privkey, this privkey must be even, therefore key is reset and return
            if(privkey) {
                key.reset();
                return key;
            }
        }
    } while(true);
}

uint256 Create_random_hash() {
    unsigned char buf[32];
    latest_crypto::random::GetStrongRandBytes(buf, 32);
    uint256 hash;
    latest_crypto::CSHA256().Write((const unsigned char *)buf, 32).Finalize(hash.begin());
    return hash;
}

void Print_hash_and_priv(const uint256 &hash, const BIGNUM *priv1, const CSecret &priv2) {
    debugcs::instance() << __func__ << " hash:" << hash.ToString() << debugcs::endl();
    debugcs::instance() << __func__ << " priv1:" << BN_bn2hex(priv1) << debugcs::endl();
    debugcs::instance() << __func__ << " priv2:" << strenc::HexStr(priv2) << debugcs::endl();
}

// called AppInit2
void Debug_checking_sign_verify() {
    uint256 v;
    v.SetHex(std::string("0x02"));
    debugcs::instance() << "uint256 v: " << v.ToString() << debugcs::endl();

    CPubKey::secp256k1_unit a;
    int overflow;
    CPubKey::secp256k1_scalar_set_be32(&a, v.begin(), &overflow);
    Debug_secp256k1_print(&a);

    CPubKey::secp256k1_unit b;
    CPubKey::secp256k1_scalar_inverse(&b, &a);
    Debug_secp256k1_print(&b);

    CPubKey::secp256k1_unit c;
    CPubKey::secp256k1_scalar_mul(&c, &a, &b);
    Debug_secp256k1_print(&c);

    std::string message = "hello schnorr and sora-qai and ai";
    uint256 hash1;
    latest_crypto::CSHA256().Write((const unsigned char *)message.data(), message.size()).Finalize(hash1.begin());

    // schnorr signature
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *xonly_pubkey1 = BN_new();
    BIGNUM *xonly_pubkey2 = BN_new();
    EC_KEY *key1 = NULL;
    EC_KEY *key2 = NULL;
    if(!group || !ctx || !xonly_pubkey1 || !xonly_pubkey2) {
        EC_GROUP_free(group);
        BN_free(xonly_pubkey1);
        BN_free(xonly_pubkey2);
        BN_CTX_free(ctx);
        return;
    }

    int checking = 0;
    do {
        EC_KEY_free(key1);
        EC_KEY_free(key2);
        key1 = Create_pub_y_even_eckey(group, ctx);
        key2 = Create_pub_y_odd_eckey(group, ctx);
        uint256 hash2 = Create_random_hash();

        // OpenSSL
        std::vector<unsigned char> sig1, sig2;
        const BIGNUM *privkey1 = EC_KEY_get0_private_key(key1);
        bool ret1 = schnorr_openssl::sign(privkey1, hash2, sig1);
        const BIGNUM *privkey2 = EC_KEY_get0_private_key(key2);
        bool ret2 = schnorr_openssl::sign(privkey2, hash2, sig2);
        if(ret1 && ret2) {
            const EC_POINT *pubkey1 = EC_KEY_get0_public_key(key1);
            if(!EC_POINT_get_affine_coordinates_GFp(group, pubkey1, xonly_pubkey1, NULL, ctx))
                break;

            const EC_POINT *pubkey2 = EC_KEY_get0_public_key(key2);
            if(!EC_POINT_get_affine_coordinates_GFp(group, pubkey2, xonly_pubkey2, NULL, ctx))
                break;

            bool valid1 = schnorr_openssl::verify(xonly_pubkey1, hash2, sig1); // valid
            bool valid2 = schnorr_openssl::verify(xonly_pubkey2, hash2, sig2); // valid
            bool valid3 = schnorr_openssl::verify(xonly_pubkey1, hash1, sig1); // invalid
            bool valid4 = schnorr_openssl::verify(xonly_pubkey2, hash2, sig1); // invalid
            debugcs::instance() << "Signature 1 valid: " << valid1 << debugcs::endl();
            debugcs::instance() << "Signature 2 valid: " << valid2 << debugcs::endl();
            debugcs::instance() << "Signature 3 valid: " << valid3 << debugcs::endl();
            debugcs::instance() << "Signature 4 valid: " << valid4 << debugcs::endl();
            assert(valid1 && valid2 && !valid3 && !valid4);
        } else {
            assert(!"failure schnorr sign");
        }

        // libsecp256k1
        secp256k1_schnorrsig sig;
        unsigned char priv_buf[32];
        if(BN_bn2bin(privkey1, priv_buf) != 32)
            break;
        std::shared_ptr<CFirmKey> secpkey = Create_pub_y_even_key(priv_buf);
        if(!secpkey.get())
            break;
        OPENSSL_cleanse(priv_buf, 32);
        CSecret secret = secpkey.get()->GetSecret();
        //Print_hash_and_priv(hash2, privkey1, secret);
        if(secp256k1_schnorrsig_sign(&sig, nullptr, hash2.begin(), secret.data(), nullptr, nullptr) == 1) {
            debugcs::instance() << __func__ << " OpenSSL sig1: " << strenc::HexStr(sig1) << debugcs::endl();
            debugcs::instance() << __func__ << " libsecp256k1 sig1: " << strenc::HexStr(std::vector<unsigned char>(BEGIN(sig.data), END(sig.data))) << debugcs::endl();

            CPubKey pubkey = secpkey->GetPubKey();
            secp256k1_xonly_pubkey pub_xy;
            pubkey.Decompress();
            ::memcpy(&pub_xy.data[0], pubkey.data() + 1, 64);
            if(secp256k1_schnorrsig_verify(&sig.data[0], hash2.begin(), &pub_xy))
                debugcs::instance() << __func__ << " secp256k1_schnorr valid" << debugcs::endl();
            else
                debugcs::instance() << __func__ << " secp256k1_schnorr invalid" << debugcs::endl();

            BIGNUM *pub_x_only = BN_new();
            BN_bin2bn(pubkey.data() + 1, 32, pub_x_only);
            std::vector<unsigned char> vchsig;
            vchsig.resize(64);
            ::memcpy(&vchsig.front(), &sig.data[0], 64);
            if(schnorr_openssl::verify(pub_x_only, hash2, vchsig))
                debugcs::instance() << __func__ << " schnorr_openssl valid" << debugcs::endl();
            else
                debugcs::instance() << __func__ << " schnorr_openssl invalid" << debugcs::endl();
            BN_free(pub_x_only);
        }

        ++checking;
    } while(checking < 50);

    checking = 0;
    do {
        std::shared_ptr<CFirmKey> secpkey = Create_pub_y_even_key();
        if(!secpkey.get())
            break;
        CSecret secret = secpkey.get()->GetSecret();
        secp256k1_schnorrsig sig;
        uint256 hash = Create_random_hash();
        if(secp256k1_schnorrsig_sign(&sig, nullptr, hash.begin(), secret.data(), schnorr_nonce::secp256k1_nonce_and_random_function_schnorr, nullptr) != 1) {
            assert(!"failure secp256k1_schnorrsig_sign");
            break;
        }

        CPubKey pubkey = secpkey->GetPubKey();
        pubkey.Compress();
        BIGNUM *pub_x_only = BN_new();
        assert(pubkey.data()[0] == 0x02);
        BN_bin2bn(pubkey.data() + 1, 32, pub_x_only);
        BIGNUM *pub_y = BN_new();
        schnorr_openssl::calculate_even_y_coordinate(group, pub_x_only, pub_y, ctx);
        pubkey.Decompress();
        BIGNUM *pub_y_check = BN_new();
        BN_bin2bn(pubkey.data() + 33, 32, pub_y_check);
        assert(BN_cmp(pub_y, pub_y_check) == 0);
        BN_free(pub_y);
        BN_free(pub_y_check);
        std::vector<unsigned char> vchsig;
        vchsig.resize(64);
        ::memcpy(&vchsig.front(), &sig.data[0], 64);
        if(schnorr_openssl::verify(pub_x_only, hash, vchsig))
            debugcs::instance() << __func__ << " verify strict mode(cmp both XY) valid" << debugcs::endl();
        else {
            debugcs::instance() << __func__ << " verify strict mode(cmp both XY) invalid" << debugcs::endl();
            assert(!"verify strict mode(cmp both XY) invalid");
            BN_free(pub_x_only);
            return;
        }
        BN_free(pub_x_only);

        ++checking;
    } while(checking < 50);

    EC_GROUP_free(group);
    EC_KEY_free(key1);
    EC_KEY_free(key2);
    BN_free(xonly_pubkey1);
    BN_free(xonly_pubkey2);
    BN_CTX_free(ctx);
}

// called AppInit2
void Debug_checking_sign_verify2() {}
