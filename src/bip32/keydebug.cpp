#include <key/pubkey.h>
#include <key/privkey.h>
#include <uint256.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

namespace schnorr_openssl {

std::vector<unsigned char> bitcoin_schnorr_sha256(const std::string &data) {
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
    CFirmKey::hash::secp256k1_sha256_write(&sha256, (const unsigned char *)data.c_str(), data.length());

    std::vector<unsigned char> hash;
    hash.resize(SHA256_DIGEST_LENGTH);
    CFirmKey::hash::secp256k1_sha256_finalize(&sha256, &hash.front());
    return hash;
}

bool calculate_y_coordinate(const EC_GROUP *group, const BIGNUM *x, BIGNUM *y, BN_CTX *ctx) {
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *x3 = BN_new();
    BIGNUM *rhs = BN_new();
    bool fret = false;

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

        fret = true;
    } while(false);

    BN_free(a);
    BN_free(b);
    BN_free(p);
    BN_free(x3);
    BN_free(rhs);
    return fret;
}

bool sign(const BIGNUM *privkey, const std::string &message, std::vector<unsigned char> &sig) {
    // sig(fixed 64bytes) = [r_bytes(32bytes) | s(32bytes)]
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *order = BN_new();
    BIGNUM *k = BN_new();
    EC_POINT *R = EC_POINT_new(group);
    BIGNUM *e = BN_new();
    BIGNUM *s = BN_new();

    bool fret = false;
    do {
        if(!group || !ctx || !order || !k || !R || !e || !s)
            break;

        // get order (F_p mod)
        EC_GROUP_get_order(group, order, ctx);

        //char *order_str = BN_bn2hex(order);
        //debugcs::instance() << __func__ << " order(F_p): " << order_str << debugcs::endl();

        // generate random k (BN_set_word(k, 1); // check G OK)
        BN_rand_range(k, order);

        // R = k * G(EC base points)
        if(EC_POINT_mul(group, R, k, NULL, NULL, ctx) != 1)
            break;

        //BIGNUM *x = BN_new();
        //BIGNUM *y = BN_new();
        //EC_POINT_get_affine_coordinates_GFp(group, R, x, y, ctx);
        //char *x_str = BN_bn2hex(x);
        //char *y_str = BN_bn2hex(y);
        //debugcs::instance() << __func__ << " R Coordinates:\nX: " << x_str << "\nY: " << y_str << debugcs::endl();

        unsigned char R_points[65];
        if(EC_POINT_point2oct(group, R, POINT_CONVERSION_UNCOMPRESSED, R_points, sizeof(R_points), ctx) != sizeof(R_points))
            break;

        // e = sha256(message || R_points_xonly)
        unsigned char R_points_xonly[32];
        ::memcpy(R_points_xonly, R_points + 1, 32);
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, (const unsigned char *)message.c_str(), message.length());
        SHA256_Update(&sha256, R_points_xonly, sizeof(R_points_xonly));
        SHA256_Final(hash, &sha256);
        BN_bin2bn(hash, SHA256_DIGEST_LENGTH, e);

        //char *e_bn_str = BN_bn2hex(e);
        //debugcs::instance() << __func__ << "   hash: " << e_bn_str << debugcs::endl();

        // s = k + e * privkey
        BN_mod_mul(s, e, privkey, order, ctx);
        BN_mod_add(s, s, k, order, ctx);

        // sig = [R_points_xonly | s]
        sig.resize(64);
        memcpy(&sig.front(), R_points_xonly, sizeof(R_points_xonly));

        //char *s_bn_str = BN_bn2hex(s);
        //debugcs::instance() << __func__ << "   s: " << s_bn_str << debugcs::endl();
        //BIGNUM *x_bn = BN_new();
        //BN_bin2bn(sig.data(), 32, x_bn);
        //char *x_bn_str = BN_bn2hex(x_bn);
        //debugcs::instance() << __func__ << " schnorr Coordinates:\nX_ONLY: " << x_bn_str << debugcs::endl();

        int s_len = BN_num_bytes(s);
        if(s_len != 32)
            break;
        BN_bn2bin(s, &sig.front() + 32);
        fret = true;
    } while(false);

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    BN_free(order);
    BN_free(k);
    EC_POINT_free(R);
    BN_free(e);
    BN_free(s);
    return fret;
}

bool verify(const BIGNUM *pubkey_x, const std::string &message, const std::vector<unsigned char> &sig) {
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
        if(!EC_GROUP_get_order(group, order, ctx))
            break;
        if(!BN_set_word(neg_one, 1))
            break;
        if(!BN_sub(neg_one, order, neg_one))
            break;

        // get R_x and s from sig
        if(!BN_bin2bn(sig.data(), 32, R_x))
            break;
        if(!BN_bin2bn(sig.data() + 32, 32, s))
            break;

        // e = sha256(message || R_points_xonly)
        unsigned char R_points_xonly[32];
        ::memcpy(R_points_xonly, sig.data(), 32);
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, (const unsigned char *)message.c_str(), message.length());
        SHA256_Update(&sha256, R_points_xonly, sizeof(R_points_xonly));
        SHA256_Final(hash, &sha256);
        BN_bin2bn(hash, SHA256_DIGEST_LENGTH, e);

        // lhs = s * G(EC base point)
        if(!EC_POINT_mul(group, lhs, s, NULL, NULL, ctx))
            break;

        // libsecp256k1: R2 = lhs - e * pubkey
        if(!calculate_y_coordinate(group, pubkey_x, pubkey_y, ctx))
            break;
        if(!EC_POINT_set_affine_coordinates_GFp(group, pubkey, pubkey_x, pubkey_y, ctx))
            break;
        if(!calculate_y_coordinate(group, R_x, R_y, ctx))
            break;
        if(!EC_POINT_set_affine_coordinates_GFp(group, R, R_x, R_y, ctx))
            break;
        if(!EC_POINT_mul(group, e_mul_pubkey, NULL, pubkey, e, ctx))
            break;
        if(!EC_POINT_mul(group, e_mul_pubkey, NULL, e_mul_pubkey, neg_one, ctx))
            break;
        if(!EC_POINT_add(group, R2, lhs, e_mul_pubkey, ctx))
            break;
        if(!EC_POINT_get_affine_coordinates_GFp(group, R2, R2_x, NULL, ctx))
            break;

        fret = BN_cmp(R_x, R2_x) == 0;

        // openssl + schnorr: rhs = R + e * pubkey
        /*
        if(!calculate_y_coordinate(group, pubkey_x, pubkey_y, ctx))
            break;
        if(!EC_POINT_set_affine_coordinates_GFp(group, pubkey, pubkey_x, pubkey_y, ctx))
            break;
        if(!calculate_y_coordinate(group, R_x, R_y, ctx))
            break;
        if(!EC_POINT_set_affine_coordinates_GFp(group, R, R_x, R_y, ctx))
            break;
        if(!EC_POINT_mul(group, e_mul_pubkey, NULL, pubkey, e, ctx))
            break;
        if(!EC_POINT_add(group, rhs, R, e_mul_pubkey, ctx))
            break;

        BIGNUM *x1 = BN_new();
        BIGNUM *y1 = BN_new();
        EC_POINT_get_affine_coordinates_GFp(group, lhs, x1, y1, ctx);
        char *x1_str = BN_bn2hex(x1);
        char *y1_str = BN_bn2hex(y1);
        debugcs::instance() << __func__ << " lhs Coordinates:\nX: " << x1_str << "\nY: " << y1_str << debugcs::endl();

        BIGNUM *x2 = BN_new();
        BIGNUM *y2 = BN_new();
        EC_POINT_get_affine_coordinates_GFp(group, rhs, x2, y2, ctx);
        char *x2_str = BN_bn2hex(x2);
        char *y2_str = BN_bn2hex(y2);
        debugcs::instance() << __func__ << " rhs Coordinates:\nX: " << x2_str << "\nY: " << y2_str << debugcs::endl();

        fret = BN_cmp(x1, x2) == 0;
        */
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

#define VERIFY_CHECK(cond) do { (void)(cond); } while(0)

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
} secp256k1_xonly_pubkey;

typedef struct {
    void (*fn)(const char *text, void* data);
    const void* data;
} secp256k1_callback;

/*
static SECP256K1_INLINE void secp256k1_callback_call(const secp256k1_callback * const cb, const char * const text) {
    cb->fn(text, (void*)cb->data);
}
*/

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

/* This nonce function is described in BIP-schnorr
 * (https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki) */
static int secp256k1_nonce_function_bipschnorr(unsigned char* nonce32, const unsigned char* msg32, const unsigned char* key32, const unsigned char* algo16, void* data, unsigned int counter) {
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

/** Create a Schnorr signature.
 *
 * Returns 1 on success, 0 on failure.
 *  Args:    ctx: pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     sig: pointer to the returned signature (cannot be NULL)
 *       nonce_is_negated: a pointer to an integer indicates if signing algorithm negated the
 *                nonce (can be NULL)
 *  In:    msg32: the 32-byte message hash being signed (cannot be NULL)
 *        seckey: pointer to a 32-byte secret key (cannot be NULL)
 *       noncefp: pointer to a nonce generation function. If NULL, secp256k1_nonce_function_bipschnorr is used
 *         ndata: pointer to arbitrary data used by the nonce generation function (can be NULL)
 */
static int secp256k1_schnorrsig_sign(secp256k1_schnorrsig *sig, int *nonce_is_negated, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, void *ndata) {
    CPubKey::secp256k1_unit x;
    CPubKey::secp256k1_unit e;
    CPubKey::secp256k1_unit k;
    CPubKey::ecmult::secp256k1_gej pkj;
    CPubKey::ecmult::secp256k1_gej rj;
    CPubKey::ecmult::secp256k1_ge pk;
    CPubKey::ecmult::secp256k1_ge r;
    CFirmKey::hash::secp256k1_sha256 sha;
    int overflow;
    unsigned char buf[33];
    size_t buflen = sizeof(buf);

    ARG_CHECK(sig != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(seckey != NULL);

    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_bipschnorr;
    }
    secp256k1_scalar_set_b32(&x, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (overflow || CPubKey::secp256k1_scalar_is_zero(&x)) {
        memset(sig, 0, sizeof(*sig));
        return 0;
    }

    CFirmKey::ecmult::secp256k1_gen_context ctx;
    ctx.secp256k1_ecmult_gen(&pkj, &x);
    CPubKey::ecmult::secp256k1_ge_set_gej(&pk, &pkj);

    if (!noncefp(buf, msg32, seckey, NULL, (void*)ndata, 0)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&k, buf, NULL);
    if (CPubKey::secp256k1_scalar_is_zero(&k)) {
        return 0;
    }

    ctx.secp256k1_ecmult_gen(&rj, &k);
    CPubKey::ecmult::secp256k1_ge_set_gej(&r, &rj);

    if (nonce_is_negated != NULL) {
        *nonce_is_negated = 0;
    }
    if (!secp256k1_fe_is_quad_var(&r.y)) {
        CPubKey::secp256k1_scalar_negate(&k, &k);
        if (nonce_is_negated != NULL) {
            *nonce_is_negated = 1;
        }
    }
    CPubKey::ecmult::secp256k1_fe_normalize(&r.x);
    secp256k1_fe_get_b32(&sig->data[0], &r.x);

    CFirmKey::hash::secp256k1_sha256_initialize(&sha);
    CFirmKey::hash::secp256k1_sha256_write(&sha, &sig->data[0], 32);
    CPubKey::secp256k1_eckey_pubkey_serialize(&pk, buf, &buflen, 1);
    CFirmKey::hash::secp256k1_sha256_write(&sha, buf, buflen);
    CFirmKey::hash::secp256k1_sha256_write(&sha, msg32, 32);
    CFirmKey::hash::secp256k1_sha256_finalize(&sha, buf);

    secp256k1_scalar_set_b32(&e, buf, NULL);
    CPubKey::secp256k1_scalar_mul(&e, &e, &x);
    CPubKey::secp256k1_scalar_add(&e, &e, &k);

    secp256k1_scalar_get_b32(&sig->data[32], &e);
    CFirmKey::secp256k1_scalar_clear(&k);
    CFirmKey::secp256k1_scalar_clear(&x);

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
    unsigned char buf[32];
    CFirmKey::hash::secp256k1_sha256 sha;

    /* tagged hash(r.x, pk.x, msg32) */
    secp256k1_schnorrsig_sha256_tagged(&sha);
    CFirmKey::hash::secp256k1_sha256_write(&sha, r32, 32);
    CFirmKey::hash::secp256k1_sha256_write(&sha, pubkey32, 32);
    CFirmKey::hash::secp256k1_sha256_write(&sha, msg32, 32);
    CFirmKey::hash::secp256k1_sha256_finalize(&sha, buf);
    /* Set scalar e to the challenge hash modulo the curve order as per
     * BIP340. */
    secp256k1_scalar_set_b32(e, buf, NULL);
}

static int secp256k1_schnorrsig_verify(const unsigned char* sig64, const unsigned char* msg32, const secp256k1_xonly_pubkey* pubkey)
{
    CPubKey::secp256k1_unit s;
    CPubKey::secp256k1_unit e;
    CPubKey::ecmult::secp256k1_gej rj;
    CPubKey::ecmult::secp256k1_ge pk;
    CPubKey::ecmult::secp256k1_gej pkj;
    CPubKey::ecmult::secp256k1_fe rx;
    CPubKey::ecmult::secp256k1_ge r;
    unsigned char buf[32];
    int overflow;

    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pubkey != NULL);

    if (!secp256k1_fe_set_b32(&rx, &sig64[0])) {
        return 0;
    }

    secp256k1_scalar_set_b32(&s, &sig64[32], &overflow);
    if (overflow) {
        return 0;
    }

    if (!secp256k1_xonly_pubkey_load(&pk, pubkey)) {
        return 0;
    }

    /* Compute e. */
    secp256k1_fe_get_b32(buf, &pk.x);
    secp256k1_schnorrsig_challenge(&e, &sig64[0], msg32, buf);

    /* Compute rj =  s*G + (-e)*pkj */
    CPubKey::secp256k1_scalar_negate(&e, &e);
    CPubKey::ecmult::secp256k1_gej_set_ge(&pkj, &pk);
    CPubKey::secp256k1_ecmult(&rj, &pkj, &e, &s);

    CPubKey::ecmult::secp256k1_ge_set_gej_var(&r, &rj);
    if (CPubKey::ecmult::secp256k1_ge_is_infinity(&r)) {
        return 0;
    }

    CPubKey::ecmult::secp256k1_fe_normalize_var(&r.y);
    return !CPubKey::ecmult::secp256k1_fe_is_odd(&r.y) &&
           CPubKey::ecmult::secp256k1_fe_equal_var(&rx, &r.x);
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

    // schnorr by OpenSSL
    std::string message = "hello schnorr and soraqai and ai";
    assert(message.size() == 32);
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_KEY *key1 = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY *key2 = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM *xonly_pubkey1 = BN_new();
    BIGNUM *xonly_pubkey2 = BN_new();

    do {
        if(!EC_KEY_generate_key(key1))
            break;
        if(!EC_KEY_generate_key(key2))
            break;

        std::vector<unsigned char> sig1, sig2;
        const BIGNUM *privkey1 = EC_KEY_get0_private_key(key1);
        bool ret1 = schnorr_openssl::sign(privkey1, message, sig1);
        const BIGNUM *privkey2 = EC_KEY_get0_private_key(key2);
        bool ret2 = schnorr_openssl::sign(privkey2, message, sig2);
        if(ret1 && ret2) {
            const EC_POINT *pubkey1 = EC_KEY_get0_public_key(key1);
            if(!EC_POINT_get_affine_coordinates_GFp(group, pubkey1, xonly_pubkey1, NULL, NULL))
                break;

            const EC_POINT *pubkey2 = EC_KEY_get0_public_key(key2);
            if(!EC_POINT_get_affine_coordinates_GFp(group, pubkey2, xonly_pubkey2, NULL, NULL))
                break;

            bool valid1 = schnorr_openssl::verify(xonly_pubkey1, message, sig1);
            bool valid2 = schnorr_openssl::verify(xonly_pubkey2, message, sig2);
            debugcs::instance() << "Signature 1 valid: " << valid1 << debugcs::endl();
            debugcs::instance() << "Signature 2 valid: " << valid2 << debugcs::endl();
        }
    } while(false);

    EC_GROUP_free(group);
    EC_KEY_free(key1);
    EC_KEY_free(key2);
    BN_free(xonly_pubkey1);
    BN_free(xonly_pubkey2);
}

// called AppInit2
void Debug_checking_sign_verify2() {}
