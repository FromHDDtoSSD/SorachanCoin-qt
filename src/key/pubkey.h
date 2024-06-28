// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SECP256K1: public key

#ifndef BITCOIN_PUBKEY_H
#define BITCOIN_PUBKEY_H

#include <prevector/prevector.h>
#include <uint256.h>
#include <hash.h>
#include <serialize.h>
#include <util/span.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <cleanse/cleanse.h>

class CKey;
class XOnlyPubKey;

#ifdef CSCRIPT_PREVECTOR_ENABLE
using key_vector = prevector<PREVECTOR_N, uint8_t>;
#else
using key_vector = std::vector<uint8_t>;
#endif

/** A reference to a CKey: the Hash160 of its serialized public key */
class CKeyID : public uint160
{
public:
    CKeyID() : uint160(0) {}
    CKeyID(const uint160 &in) : uint160(in) {}
};

/** A reference to a CEthID: the Hash160 of Eth style public key */
class CEthID : public uint160
{
public:
    CEthID() : uint160(0) {}
    CEthID(const uint160 &in) : uint160(in) {}
};

/**Warning attributes
  * NONNULL is not used if SECP256K1_BUILD is set to avoid the compiler optimizing out
  * some paranoid null checks. */
# if !defined(SECP256K1_GNUC_PREREQ)
#  if defined(__GNUC__)&&defined(__GNUC_MINOR__)
#   define SECP256K1_GNUC_PREREQ(_maj,_min) \
 ((__GNUC__<<16)+__GNUC_MINOR__>=((_maj)<<16)+(_min))
#  else
#   define SECP256K1_GNUC_PREREQ(_maj,_min) 0
#  endif
# endif

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

#ifdef HAVE_BUILTIN_EXPECT
#define EXPECT(x,c) __builtin_expect((x),(c))
#else
#define EXPECT(x,c) (x)
#endif

// An encapsulated libsecp256k1 Elliptic Curve key (public)
// The signature is 1 byte at the beginning. so 33Bytes or 65 Bytes.
// CoinAddress to use when sending coins is converted from CPubKey(65 Bytes) to CBitcoinAddress.
/** An encapsulated public key. */
// ref: src/secp256k1 secp256k1 library.
class CPubKey
{
    friend class CKey;
    friend class XOnlyPubKey;
public:
    //! secp256k1
    //structure: struct secp256k1_data {BIGNUM *r; BIGNUM *s;};
    //about size: header=>1 + r=>32 + s=>32 = 65 byte
    static constexpr unsigned int PUBLIC_KEY_SIZE             = 65;
    static constexpr unsigned int COMPRESSED_PUBLIC_KEY_SIZE  = 33;
    static constexpr unsigned int SIGNATURE_SIZE              = 72;
    static constexpr unsigned int COMPACT_SIGNATURE_SIZE      = 65;

    // see www.keylength.com
    // script supports up to 75 for single byte push
    static_assert(
        PUBLIC_KEY_SIZE >= COMPRESSED_PUBLIC_KEY_SIZE,
        "COMPRESSED_PUBLIC_KEY_SIZE is larger than PUBLIC_KEY_SIZE");

    // secp256k1_scalar
    // r and s, unsigned int array: 8x32
    //size: sizeof(uint32_t) * 8 = 32 byte
    struct secp256k1_unit {
        uint32_t d[8];
    };
    using secp256k1_scalar = secp256k1_unit;

    // signature unsigned char array
    struct secp256k1_signature {
        unsigned char data[PUBLIC_KEY_SIZE - 1];
    };

    // pubkey context
    struct secp256k1_pubkey {
        unsigned char data[PUBLIC_KEY_SIZE - 1];
    };

    // pubkey recoverable context
    struct secp256k1_ecdsa_recoverable_signature {
        unsigned char data[PUBLIC_KEY_SIZE];
    };

    // SorachanCoin (src/secp256k1): adopt Basic config
#define USE_NUM_NONE 1
#define USE_FIELD_INV_BUILTIN 1
#define USE_SCALAR_INV_BUILTIN 1
//#define USE_FIELD_10X26 1
//#define USE_SCALAR_8X32 1

    static constexpr int CURVE_B = 7;

    // ecmult (src/secp256k1) field: 10x26
    // secp256k1_scalar 8x32
#define SECP256K1_RESTRICT
#define USE_ENDOMORPHISM
#define VERIFY
    /* Unpacks a constant into a overlapping multi-limbed FE element. */
#define SECP256K1_FE_CONST_INNER(d7, d6, d5, d4, d3, d2, d1, d0) { \
    (d0) & 0x3FFFFFFUL, \
    (((uint32_t)d0) >> 26) | (((uint32_t)(d1) & 0xFFFFFUL) << 6), \
    (((uint32_t)d1) >> 20) | (((uint32_t)(d2) & 0x3FFFUL) << 12), \
    (((uint32_t)d2) >> 14) | (((uint32_t)(d3) & 0xFFUL) << 18), \
    (((uint32_t)d3) >> 8) | (((uint32_t)(d4) & 0x3UL) << 24), \
    (((uint32_t)d4) >> 2) & 0x3FFFFFFUL, \
    (((uint32_t)d4) >> 28) | (((uint32_t)(d5) & 0x3FFFFFUL) << 4), \
    (((uint32_t)d5) >> 22) | (((uint32_t)(d6) & 0xFFFFUL) << 10), \
    (((uint32_t)d6) >> 16) | (((uint32_t)(d7) & 0x3FFUL) << 16), \
    (((uint32_t)d7) >> 10) \
    }
#ifdef VERIFY
# define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0)), 1, 1}
#else
# define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0))}
#endif
    class ecmult {
    public:
        typedef struct {
            /* X = sum(i=0..9, elem[i]*2^26) mod n */
            uint32_t n[10];
#ifdef VERIFY
            int magnitude;
            int normalized;
#endif
        } secp256k1_fe;
        typedef struct {
            uint32_t n[8];
        } secp256k1_fe_storage;

        /** A group element of the secp256k1 curve, in affine coordinates. */
        typedef struct {
            secp256k1_fe x;
            secp256k1_fe y;
            int infinity; /* whether this represents the point at infinity */
        } secp256k1_ge;
        typedef struct {
            secp256k1_fe_storage x;
            secp256k1_fe_storage y;
        } secp256k1_ge_storage;

        /** A group element of the secp256k1 curve, in complex coordinates. */
        typedef struct {
            secp256k1_fe re;
            secp256k1_fe im;
            int re_negate;
            int im_negate;
        } secp256k1_gai;
        typedef struct {
            secp256k1_fe_storage re;
            secp256k1_fe_storage im;
            int re_negate;
            int im_negate;
        } secp256k1_gai_storage;

        /** A group element of the secp256k1 curve, in jacobian coordinates. */
        typedef struct {
            secp256k1_fe x; /* actual X: x/z^2 */
            secp256k1_fe y; /* actual Y: y/z^3 */
            secp256k1_fe z;
            int infinity; /* whether this represents the point at infinity */
        } secp256k1_gej;

        /** R^n */
        typedef struct {
            std::vector<secp256k1_fe> vfe; /* actual a,b,c ... */
            int infinity;
        } secp256k1_grn;

#ifdef VERIFY
        static void secp256k1_fe_verify(const secp256k1_fe *a);
#endif
        static void secp256k1_fe_clear(secp256k1_fe *a);
        static  int secp256k1_fe_set_b32(secp256k1_fe *r, const unsigned char *a);
        static void secp256k1_fe_get_b32(unsigned char *r, const secp256k1_fe *a);
        static void secp256k1_fe_from_storage(secp256k1_fe *r, const secp256k1_fe_storage *a);
        static void secp256k1_fe_to_storage(secp256k1_fe_storage *r, const secp256k1_fe *a);
        static void secp256k1_fe_set_int(secp256k1_fe *r, int a);

        static  int secp256k1_fe_is_odd(const secp256k1_fe *a);
        static  int secp256k1_fe_is_zero(const secp256k1_fe *a);
        static  int secp256k1_fe_is_quad_var(const secp256k1_fe *a);

        static void secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a);
        static void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe * SECP256K1_RESTRICT b);
        static void secp256k1_fe_mul_int(secp256k1_fe *r, int a);
        static void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a);
        static  int secp256k1_fe_sqrt(secp256k1_fe *r, const secp256k1_fe *a);

        static  int secp256k1_fe_cmp(const secp256k1_fe *a, const secp256k1_fe *b);
        static  int secp256k1_fe_cmp_var(const secp256k1_fe *a, const secp256k1_fe *b);
        static  int secp256k1_fe_equal(const secp256k1_fe *a, const secp256k1_fe *b);
        static  int secp256k1_fe_equal_var(const secp256k1_fe *a, const secp256k1_fe *b);

        static void secp256k1_fe_negate(secp256k1_fe *r, const secp256k1_fe *a, int m);
        static void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *a);
        static void secp256k1_fe_inv_var(secp256k1_fe *r, const secp256k1_fe *a);
        static void secp256k1_fe_normalize(secp256k1_fe *r);
        static void secp256k1_fe_normalize_weak(secp256k1_fe *r);
        static void secp256k1_fe_normalize_var(secp256k1_fe *r);
        static  int secp256k1_fe_normalizes_to_zero(const secp256k1_fe *r);
        static  int secp256k1_fe_normalizes_to_zero_var(const secp256k1_fe *r);

        static int secp256k1_ge_set_xo_var(secp256k1_ge *r, const secp256k1_fe *x, int odd);
        static int secp256k1_ge_set_xquad(secp256k1_ge *r, const secp256k1_fe *x);
        static void secp256k1_gej_set_ge(secp256k1_gej *r, const secp256k1_ge *a);
        static void secp256k1_gej_double_var(secp256k1_gej *r, const secp256k1_gej *a, secp256k1_fe *rzr);
        static void secp256k1_ge_set_gej_zinv(secp256k1_ge *r, const secp256k1_gej *a, const ecmult::secp256k1_fe *zi);
        static void secp256k1_gej_add_ge_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, ecmult::secp256k1_fe *rzr);
        static void secp256k1_ge_globalz_set_table_gej(size_t len, secp256k1_ge *r, secp256k1_fe *globalz, const secp256k1_gej *a, const secp256k1_fe *zr);
        static void secp256k1_gej_set_infinity(secp256k1_gej *r);
        static void secp256k1_ge_neg(secp256k1_ge *r, const secp256k1_ge *a);
        static void secp256k1_ge_from_storage(secp256k1_ge *r, const secp256k1_ge_storage *a);
        static void secp256k1_gej_add_zinv_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, const secp256k1_fe *bzinv);
        static void secp256k1_ge_set_gej_var(secp256k1_ge *r, secp256k1_gej *a);
        static int secp256k1_gej_is_infinity(const secp256k1_gej *a);
        static void secp256k1_ge_to_storage(secp256k1_ge_storage *r, const secp256k1_ge *a);
        static int secp256k1_ge_is_infinity(const secp256k1_ge *a);
        static void secp256k1_ge_set_xy(secp256k1_ge *r, const secp256k1_fe *x, const secp256k1_fe *y);
        static int secp256k1_ge_is_valid_var(const secp256k1_ge *a);
        static void secp256k1_ge_clear(secp256k1_ge *r);
        static void secp256k1_ge_set_gej(secp256k1_ge *r, secp256k1_gej *a);
        static bool secp256k1_ecmult_odd_multiples_table_storage_var(int n, secp256k1_ge_storage *pre, const secp256k1_gej *a);
        static void secp256k1_ge_set_table_gej_var(secp256k1_ge *r, const secp256k1_gej *a, const secp256k1_fe *zr, size_t len);
        static int secp256k1_gej_eq_x_var(const secp256k1_fe *x, const secp256k1_gej *a);
        static const secp256k1_ge *secp256k1_get_ge_const_g();

        // public key r = na * a + ng * G: context
        class secp256k1_context {
        public:
            secp256k1_ge_storage (*pre_g_)[];     /* odd multiples of the generator */
#ifdef USE_ENDOMORPHISM
            secp256k1_ge_storage (*pre_g_128_)[]; /* odd multiples of 2^128*generator */
#endif
            void init();
            bool build();
            void clear();
            secp256k1_context();
            secp256k1_context(const secp256k1_context &)=delete;
            secp256k1_context(secp256k1_context &&)=delete;
            secp256k1_context &operator=(const secp256k1_context &)=delete;
            secp256k1_context &operator=(secp256k1_context &&)=delete;
            ~secp256k1_context();
        };
    };

    static constexpr uint32_t SECP256K1_N_0 = (uint32_t)0xD0364141UL;
    static constexpr uint32_t SECP256K1_N_1 = (uint32_t)0xBFD25E8CUL;
    static constexpr uint32_t SECP256K1_N_2 = (uint32_t)0xAF48A03BUL;
    static constexpr uint32_t SECP256K1_N_3 = (uint32_t)0xBAAEDCE6UL;
    static constexpr uint32_t SECP256K1_N_4 = (uint32_t)0xFFFFFFFEUL;
    static constexpr uint32_t SECP256K1_N_5 = (uint32_t)0xFFFFFFFFUL;
    static constexpr uint32_t SECP256K1_N_6 = (uint32_t)0xFFFFFFFFUL;
    static constexpr uint32_t SECP256K1_N_7 = (uint32_t)0xFFFFFFFFUL;
    static constexpr uint32_t SECP256K1_N_C_0 = (~SECP256K1_N_0 + 1);
    static constexpr uint32_t SECP256K1_N_C_1 = ~SECP256K1_N_1;
    static constexpr uint32_t SECP256K1_N_C_2 = ~SECP256K1_N_2;
    static constexpr uint32_t SECP256K1_N_C_3 = ~SECP256K1_N_3;
    static constexpr uint32_t SECP256K1_N_C_4 = 1;

    /** All flags' lower 8 bits indicate what they're for. Do not use directly. */
    static constexpr unsigned int SECP256K1_FLAGS_TYPE_MASK = ((1 << 8) - 1);
    static constexpr unsigned int SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0);
    static constexpr unsigned int SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1);
    /** The higher bits contain the actual data. Do not use directly. */
    static constexpr unsigned int SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8);
    static constexpr unsigned int SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9);
    static constexpr unsigned int SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8);
    /** Flag to pass to secp256k1_ec_pubkey_serialize and secp256k1_ec_privkey_export. */
    static constexpr unsigned int SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION);
    static constexpr unsigned int SECP256K1_EC_UNCOMPRESSED = SECP256K1_FLAGS_TYPE_COMPRESSION;

    /** Prefix byte used to tag various encoded curvepoints for specific purposes */
    static constexpr unsigned char SECP256K1_TAG_PUBKEY_EVEN = 0x02;
    static constexpr unsigned char SECP256K1_TAG_PUBKEY_ODD = 0x03;
    static constexpr unsigned char SECP256K1_TAG_PUBKEY_UNCOMPRESSED = 0x04;
    static constexpr unsigned char SECP256K1_TAG_PUBKEY_HYBRID_EVEN = 0x06;
    static constexpr unsigned char SECP256K1_TAG_PUBKEY_HYBRID_ODD = 0x07;

    // BIP66 (src/secp256k1)
    static int secp256k1_scalar_check_overflow(const secp256k1_scalar *a);
    static uint32_t secp256k1_scalar_reduce(secp256k1_scalar *r, uint32_t overflow);
    static void secp256k1_scalar_set_b32(secp256k1_scalar *r, const unsigned char *b32, int *overflow);
    static void secp256k1_scalar_get_b32(unsigned char *bin, const secp256k1_scalar *a);
    static void secp256k1_ecdsa_signature_save(secp256k1_signature *sig, const secp256k1_scalar *r, const secp256k1_scalar *s);
    static void secp256k1_ecdsa_signature_load(secp256k1_scalar *r, secp256k1_scalar *s, const secp256k1_signature *sig);
    static int secp256k1_ecdsa_signature_parse_compact(secp256k1_signature *sig, unsigned char *input64);
    static int ecdsa_signature_parse_der_lax(secp256k1_signature *sig, const unsigned char *input, size_t inputlen);
    static int secp256k1_scalar_is_high(const secp256k1_scalar *a);
    static int secp256k1_scalar_is_zero(const secp256k1_scalar *a);
    static int secp256k1_ecdsa_signature_normalize(const secp256k1_signature *sigin);
    static int secp256k1_ecdsa_signature_normalize(secp256k1_signature *sigout, const secp256k1_signature *sigin);
    static void secp256k1_ecdsa_recoverable_signature_save(secp256k1_ecdsa_recoverable_signature *sig, const secp256k1_scalar *r, const secp256k1_scalar *s, int recid);
    static void secp256k1_ecdsa_recoverable_signature_load(secp256k1_scalar *r, secp256k1_scalar *s, int *recid, const secp256k1_ecdsa_recoverable_signature *sig);
    static int secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ecdsa_recoverable_signature *sig, const unsigned char *input64, int recid);
    static void secp256k1_scalar_negate(secp256k1_scalar *r, const secp256k1_scalar *a);
    static unsigned int secp256k1_scalar_get_bits(const secp256k1_scalar *a, unsigned int offset, unsigned int count);
    static unsigned int secp256k1_scalar_get_bits_var(const secp256k1_scalar *a, unsigned int offset, unsigned int count);
    static void secp256k1_ecmult_odd_multiples_table(int n, ecmult::secp256k1_gej *prej, ecmult::secp256k1_fe *zr, const ecmult::secp256k1_gej *a);
    static int secp256k1_ecmult(ecmult::secp256k1_gej *r, const ecmult::secp256k1_gej *a, const secp256k1_scalar *na, const secp256k1_scalar *ng);
    static int secp256k1_ecdsa_sig_recover(const secp256k1_scalar *sigr, const secp256k1_scalar *sigs, ecmult::secp256k1_ge *pubkey, const secp256k1_scalar *message, int recid);
    static void secp256k1_scalar_sqr_512(uint32_t *l, const secp256k1_scalar *a);
    static void secp256k1_scalar_reduce_512(secp256k1_scalar *r, const uint32_t *l);
    static void secp256k1_scalar_sqr(secp256k1_scalar *r, const secp256k1_scalar *a);
    static void secp256k1_scalar_mul_512(uint32_t *l, const secp256k1_scalar *a, const secp256k1_scalar *b);
    static void secp256k1_scalar_mul(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b);
    static void secp256k1_scalar_inverse(secp256k1_scalar *r, const secp256k1_scalar *x);
    static int secp256k1_scalar_is_even(const secp256k1_scalar *a);
    static int secp256k1_scalar_is_odd(const secp256k1_scalar *a);
    static void secp256k1_scalar_inverse_var(secp256k1_scalar *r, const secp256k1_scalar *x);
    static void secp256k1_pubkey_save(secp256k1_pubkey *pubkey, ecmult::secp256k1_ge *ge);
    static int secp256k1_ecdsa_recover(secp256k1_pubkey *pubkey, const secp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msg32);
    static int secp256k1_pubkey_load(ecmult::secp256k1_ge *ge, const secp256k1_pubkey *pubkey);
    static int secp256k1_eckey_pubkey_serialize(ecmult::secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed);
    static int secp256k1_ec_pubkey_serialize(unsigned char *output, size_t *outputlen, const secp256k1_pubkey *pubkey, unsigned int flags);
    static int secp256k1_ec_pubkey_parse(secp256k1_pubkey *pubkey, const unsigned char *input, size_t inputlen);
    static int secp256k1_eckey_pubkey_parse(ecmult::secp256k1_ge *elem, const unsigned char *pub, size_t size);
    static int secp256k1_ec_pubkey_tweak_add(secp256k1_pubkey *pubkey, const unsigned char *tweak);
    static int secp256k1_eckey_pubkey_tweak_add(ecmult::secp256k1_ge *key, const secp256k1_scalar *tweak);
    static void secp256k1_scalar_set_int(secp256k1_scalar *r, unsigned int v);
    static int secp256k1_ecdsa_verify(const secp256k1_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pubkey);
    static int secp256k1_ecdsa_sig_verify(const secp256k1_scalar *sigr, const secp256k1_scalar *sigs, const ecmult::secp256k1_ge *pubkey, const secp256k1_scalar *message);
#ifdef USE_ENDOMORPHISM
    static void secp256k1_scalar_cadd_bit(secp256k1_scalar *r, unsigned int bit, int flag);
    static void secp256k1_scalar_mul_shift_var(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b, unsigned int shift);
    static int secp256k1_scalar_add(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b);
#endif

    // Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields [OpenSSL from only sig to PubKey]
    static int ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check);

private:
    // Just store the serialized data.
    // Its length can very cheaply be computed from the first byte.
    unsigned char vch_[PUBLIC_KEY_SIZE];

    //! Compute the length of a pubkey with a given first byte.
    static unsigned int GetLen(unsigned char chHeader) {
        if (chHeader == 2 || chHeader == 3)
            return COMPRESSED_PUBLIC_KEY_SIZE;
        if (chHeader == 4 || chHeader == 6 || chHeader == 7)
            return PUBLIC_KEY_SIZE;
        return 0;
    }

    //! Set this key data to be invalid
    void Invalidate() {
        vch_[0] = 0xFF;
    }

public:
    static bool ValidSize(const key_vector &_vch) {
      return _vch.size() > 0 && GetLen(_vch[0]) == _vch.size();
    }

    //! Construct an invalid public key.
    CPubKey() {
        Invalidate();
    }

    //! Initialize a public key using begin/end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend) {
        int len = pend == pbegin ? 0 : CPubKey::GetLen(pbegin[0]);
        if (len && len == (pend - pbegin))
            std::memcpy(vch_, (unsigned char *)&pbegin[0], len);
        else
            Invalidate();
    }
    void Set(const key_vector &_vch) {
        Set(_vch.begin(), _vch.end());
    }

    //! Construct a public key using begin/end iterators to byte data.
    template <typename T>
    CPubKey(const T pbegin, const T pend) {
        Set(pbegin, pend);
    }

    //! Construct a public key from a byte vector.
    explicit CPubKey(const key_vector &_vch) {
        Set(_vch.begin(), _vch.end());
    }

    //! key_vector operator (wallet.cpp)
    bool operator!=(const key_vector &_vch) {
        CPubKey _cmp(_vch);
        return *this != _cmp;
    }

    //! Simple read-only vector-like interface to the pubkey data.
    unsigned int size() const { return CPubKey::GetLen(vch_[0]); }
    const unsigned char *data() const { return vch_; }
    const unsigned char *begin() const { return vch_; }
    const unsigned char *end() const { return vch_ + size(); }
    const unsigned char &operator[](unsigned int pos) const { return vch_[pos]; }

    //! Comparator implementation.
    friend bool operator==(const CPubKey &a, const CPubKey &b) {
        return a.vch_[0] == b.vch_[0] &&
               ::memcmp(a.vch_, b.vch_, a.size()) == 0;
    }
    friend bool operator!=(const CPubKey &a, const CPubKey &b) {
        return !(a == b);
    }
    friend bool operator<(const CPubKey &a, const CPubKey &b) {
        return a.vch_[0] < b.vch_[0] ||
               (a.vch_[0] == b.vch_[0] && ::memcmp(a.vch_, b.vch_, a.size()) < 0);
    }

    //! Implement serialization, as if this was a byte vector.
    unsigned int GetSerializeSize() const {
        return size() + 1;
    }
    template <typename Stream>
    void Serialize(Stream &s) const {
        const unsigned int len = size();
        compact_size::manage::WriteCompactSize(s, len);
        s.write((char *)vch_, len);
    }
    template <typename Stream>
    void Unserialize(Stream &s) {
        unsigned int len = compact_size::manage::ReadCompactSize(s);
        if (len <= PUBLIC_KEY_SIZE) {
            s.read((char *)vch_, len);
        } else {
            // invalid pubkey, skip available data
            char dummy;
            while(len--) {
                s.read(&dummy, sizeof(char));
                cleanse::OPENSSL_cleanse(&dummy, sizeof(char)); // Even if -O3, Unserialize operate exactly.
            }
            Invalidate();
        }
    }

    //! Get the KeyID of this public key (hash of its serialization)
    CKeyID GetID() const {
        return CKeyID(hash_basis::Hash160(begin(), end()));
    }

    //! Get the Bytes vector of this public key
    //! 33 bytes or 65 bytes public key
    key_vector GetPubVch() const {
        return key_vector(begin(), end());
    }

    //! Get the Bytes vector Eth type of thie public key
    //! 64 bytes only x and y decompress public key, then remove prefix flag
    key_vector GetPubEth() const {
        CPubKey pubtmp = *this;
        pubtmp.Decompress();
        key_vector vchEth(pubtmp.begin(), pubtmp.end());
        vchEth.erase(vchEth.begin()); // remove prefix flag
        return vchEth;
    }

    //! Get the 256-bit hash of this public key.
    uint256 GetHash() const {
        return hash_basis::Hash(begin(), end());
    }

    //! Check syntactic correctness.
    //  Note: this is consensus critical as CheckSig() calls it!
    bool IsValid() const;

    //! fully validate whether this is a valid public key (more expensive than IsValid()) [OpenSSL, libsecp256k1(BIP66)]
    bool IsFullyValid() const;
    bool IsFullyValid_BIP66() const;

    //! Check whether this is a compressed public key.
    bool IsCompressed() const {
        return size() == COMPRESSED_PUBLIC_KEY_SIZE;
    }

    //! Verify a DER signature (~72 bytes). [OpenSSL, libsecp256k1(BIP66)]
    // [OpenSSL] If this public key is not fully valid, the return value will be false.
    bool Verify(const uint256 &hash, const key_vector &vchSig) const;
    bool Verify_BIP66(const uint256 &hash, const key_vector &vchSig) const;

    // Check whether a signature is normalized (lower-S). [libsecp256k1]
    static bool CheckLowS(const key_vector &vchSig);

    //! Recover a public key from a compact signature. [libsecp256k1]
    bool RecoverCompact(const uint256 &hash, const key_vector &vchSig);

    //! Recover a public key from a compact signature. [libsecp256k1 and OpenSSL]
    bool SetCompactSignature(const uint256 &hash, const key_vector &vchSig);

    // Reserialize to DER [OpenSSL]
    static bool ReserealizeSignature(key_vector &vchSig);

    //! Turn this public key into an uncompressed public key. [libsecp256k1]
    bool Decompress();
    bool Compress();

    //! Derive BIP32 child pubkey. [for HD wallet] [libsecp256k1]
    bool Derive(CPubKey &pubkeyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode &cc) const;

    //! Encrypt data [for Random wallet] [OpenSSL ecies cryptogram]
    bool EncryptData(const key_vector &data, key_vector &encrypted) const;

    //! CPubKey Callback ERROR and Completion function [libsecp256k1]
    static int PubKey_ERROR_callback(void (*fn)()=nullptr) {if(fn) fn(); return 0;}
    static void PubKey_COMPLETION_callback(void (*fn)()) {fn();}

    //! vch_ to string
    std::string ToString() const;
};

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
} secp256k1_xonly_pubkey; // 0 - 31: X coordinate, 32 - 63: extend information

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

/*
 * The error callback function implemented in CPubKey is called by the ARG_CHECK, ARG_CHECK_FUNC macro.
 *
typedef struct {
    void (*fn)(const char *text, void* data);
    const void* data;
} secp256k1_callback;

static SECP256K1_INLINE void secp256k1_callback_call(const secp256k1_callback * const cb, const char * const text) {
    cb->fn(text, (void*)cb->data);
}
*/

namespace secp256k1_util {
    void *checked_malloc(void(*cb)(), size_t size);
    void *checked_realloc(void(*cb)(), void *ptr, size_t size);

    /* Extract the sign of an int64, take the abs and return a uint64, constant time. */
    int secp256k1_sign_and_abs64(uint64_t *out, int64_t in);
    int secp256k1_clz64_var(uint64_t x);

    /* Zero memory if flag == 1. Flag must be 0 or 1. Constant time. */
    void memczero(void* s, size_t len, int flag);

    /** Semantics like memcmp. Variable-time.
     *
     * We use this to avoid possible compiler bugs with memcmp, e.g.
     * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=95189
     */
    int secp256k1_memcmp_var(const void* s1, const void* s2, size_t n);
    int secp256k1_memcmp(const void* s1, const void* s2, size_t n);

    /** If flag is true, set *r equal to *a; otherwise leave it. Constant-time.  Both *r and *a must be initialized and non-negative.*/
    void secp256k1_int_cmov(int* r, const int* a, int flag);
}

namespace schnorr_nonce {
    int secp256k1_nonce_function_bipschnorr(unsigned char* nonce32, const unsigned char* msg32, const unsigned char* key32, const unsigned char* algo16, void* data, unsigned int counter);
    int secp256k1_nonce_and_random_function_schnorr(unsigned char* nonce32, const unsigned char* msg32, const unsigned char* key32, const unsigned char* algo16, void* data, unsigned int counter);
}

namespace schnorr_e_hash {
    /* Initializes SHA256 with fixed midstate. This midstate was computed by applying
     * SHA256 to SHA256("BIP0340/challenge")||SHA256("BIP0340/challenge"). */
    void secp256k1_schnorrsig_challenge(CPubKey::secp256k1_scalar *e, const unsigned char *r32, const unsigned char *msg32, const unsigned char *pubkey32);
    void secp256k1_schnorrsig_standard(CPubKey::secp256k1_scalar *e, const unsigned char *r32, const unsigned char *msg32, const unsigned char *pubkey32);
}

/*
 * Numeric output function for debug console.
 */
inline void print_secp256k1_fe(const char *mes, const CPubKey::ecmult::secp256k1_fe *v) {
    CPubKey::ecmult::secp256k1_fe v2 = *v;
    CPubKey::ecmult::secp256k1_fe_normalize(&v2);
    unsigned char buf[32];
    CPubKey::ecmult::secp256k1_fe_get_b32(buf, &v2);
    debugcs::instance() << mes << ": " << strenc::HexStr(key_vector(BEGIN(buf), END(buf))) << debugcs::endl();
}

inline void print_secp256k1_scalar(const char *mes, const CPubKey::secp256k1_scalar *s) {
    unsigned char buf[32];
    CPubKey::secp256k1_scalar_get_b32(buf, s);
    debugcs::instance() << mes << ": " << strenc::HexStr(key_vector(BEGIN(buf), END(buf))) << debugcs::endl();
}

inline void print_bytes(const char *mes, const unsigned char *buf, int size) {
    std::vector<unsigned char> vch;
    vch.resize(size);
    ::memcpy(&vch.front(), buf, size);
    debugcs::instance() << mes << ": " << strenc::HexStr(vch) << debugcs::endl();
}

template <typename T>
inline void print_num(const char *mes, T num) {
    debugcs::instance() << mes << ": " << num << debugcs::endl();
}

template <typename T>
inline void print_str(const char *mes, const T &str) {
    debugcs::instance() << mes << ": " << str.c_str() << debugcs::endl();
}

inline void print_bignum(const char *mes, BIGNUM *bn) {
    char *bn_str = BN_bn2hex(bn);
    if (bn_str) {
        debugcs::instance() << mes << ": " << bn_str << debugcs::endl();
        OPENSSL_free(bn_str);
    } else {
        debugcs::instance() << "Error converting BIGNUM to string" << debugcs::endl();
    }
}

inline void print_ecpoint(const EC_GROUP *group, const EC_POINT *point) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    do {
        if (!ctx || !x || !y)
            break;
        if (EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx) != 1)
            break;

        char *x_str = BN_bn2dec(x);
        char *y_str = BN_bn2dec(y);
        debugcs::instance() << "EC Point Coordinates:" << debugcs::endl();
        debugcs::instance() << "x: " << x_str << debugcs::endl();
        debugcs::instance() << "y: " << y_str << debugcs::endl();
        OPENSSL_free(x_str);
        OPENSSL_free(y_str);
    } while(false);

    BN_free(x);
    BN_free(y);
    BN_CTX_free(ctx);
}

/** SORA's Schnorr Signatures - Key Properties:
 *
 * 1. **Public Key Y-Coordinate Flexibility**
 *    - Removed the requirement for an even Y-coordinate for public keys as specified in BIP340.
 *    - Any public key is now acceptable.
 *
 * 2. **Enhanced Security**
 *    - Nonce is randomly generated.
 *    - Provides excellent security.
 *
 * 3. **Verification Accuracy**
 *    - Ensures complete match of both X and Y coordinates.
 *
 * 4. **Multi-Signature Aggregation Support**
 *    - Supports aggregation of multiple signatures.
 *    - Regardless of the number of signatures, the result is a single-size signature.
 *
 * The key verification process involved aggregating 100 randomly generated
 * ECDSA keys (with a mix of even and odd Y-coordinates) for Schnorr signatures.
 *
 * We conducted a continuous 48-hour test where each signature was signed and verified
 * against different message hashes, confirming zero errors.
 *
 * Additionally, we have completed the verification of key security differences
 * due to polynomial time (y = ax mod p) and exponential time (y = a^x mod p).
 *
 * Note: With the introduction of signature aggregation, OP_CHECKSIGADD is no longer necessary.
 * Instead, the new opcode OP_CHECKSIGAGG has been introduced to handle aggregated signature verification.
 */
class XOnlyPubKey
{
private:
    uint256 m_keydata;

public:
    static int secp256k1_schnorrsig_serialize(unsigned char *out64, const secp256k1_schnorrsig *sig);
    static int secp256k1_schnorrsig_parse(secp256k1_schnorrsig *sig, const unsigned char *in64);

    /* BIP-340: Helper function for verification and batch verification.
     * Computes R = sG - eP. */
    static int secp256k1_schnorrsig_real_verify(CPubKey::ecmult::secp256k1_gej *rj, const CPubKey::secp256k1_scalar *s, const CPubKey::secp256k1_scalar *e, const CPubKey::secp256k1_pubkey *pk);
    static int secp256k1_xonly_pubkey_load(CPubKey::ecmult::secp256k1_ge *ge, const secp256k1_xonly_pubkey *pubkey);
    static void secp256k1_xonly_pubkey_load(secp256k1_xonly_pubkey *pubkey, const uint256 *in);
    static void secp256k1_xonly_pubkey_save(uint256 *out, const secp256k1_xonly_pubkey *pubkey);

    /* Schnorr Signatures Verify
     */
    static int secp256k1_schnorrsig_verify(const unsigned char* sig64, const unsigned char* msg32, const secp256k1_xonly_pubkey* pubkey);

public:
    static constexpr unsigned int XONLY_PUBLIC_KEY_SIZE = 32;
    static constexpr unsigned int SCHNORR_SIGNATURE_SIZE = 64;

    XOnlyPubKey() = delete;

    /** Construct an x-only pubkey from exactly 32 bytes. */
    XOnlyPubKey(Span<const unsigned char> bytes) {
        assert(bytes.size() == XONLY_PUBLIC_KEY_SIZE);
        std::copy(bytes.begin(), bytes.end(), m_keydata.begin());
    }

    /** Verify a Schnorr signature against this public key.
     *
     * sigbytes must be exactly 64 bytes.
     */
    bool VerifySchnorr(const uint256& msg, Span<const unsigned char> sigbytes) const;
    //bool CheckPayToContract(const XOnlyPubKey& base, const uint256& hash, bool parity) const;

    //! Get the KeyID of this XOnlyPubKey. (CKeyID is uint160, 20 bytes)
    CKeyID GetID() const;

    //! Hash and verification methods used in SORA-QAI.
    qkey_vector GetSchnorrHash() const;
    bool CmpSchnorrHash(const qkey_vector &hashvch) const;

    //! Extract uint160 from qairand and store it in CKeyID(uint160).
    static CKeyID GetFromQairand(const qkey_vector &qairand);

    //! Provides a vector of XOnlyPubKey.
    key_vector GetPubVch() const;

    const unsigned char& operator[](int pos) const { return *(m_keydata.begin() + pos); }
    const unsigned char* data() const { return m_keydata.begin(); }
    size_t size() const { return m_keydata.size(); }
};

class XOnlyPubKeys
{
private:
    std::vector<CPubKey> m_vkeydata;

    bool aggregation(secp256k1_xonly_pubkey *agg_pubkey) const {
        return (secp256k1_schnorrsig_aggregation(Span<const CPubKey>(m_vkeydata), agg_pubkey) == 1) ? true: false;
    }

public:
    /** Schnorr Signature Aggregation (pub aggregation, nonce randomness)
     */
    static int secp256k1_schnorrsig_aggregation(Span<const CPubKey> pubkeys, secp256k1_xonly_pubkey *x_only_agg_pubkey);

public:
    XOnlyPubKeys() {}

    /** Verify a Schnorr signature against this public keys.
     *
     * sigbytes must be exactly 64 bytes.
     */
    bool VerifySchnorr(const uint256& msg, Span<const unsigned char> sigbytes) const;
    //bool CheckPayToContract(const XOnlyPubKey& base, const uint256& hash, bool parity) const;

    XOnlyPubKey GetXOnlyPubKey() const {
        secp256k1_xonly_pubkey xonly_publey;
        if(!aggregation(&xonly_publey)) {
            CPubKey pubkey; // invalid public key
            return XOnlyPubKey(Span<const unsigned char>(pubkey.data() + 1, 32));
        }

        uint256 data;
        XOnlyPubKey::secp256k1_xonly_pubkey_save(&data, &xonly_publey);
        return XOnlyPubKey(Span<const unsigned char>(data.begin(), 32));
    }

    const CPubKey& operator[](int pos) const { return m_vkeydata[pos]; }
    const CPubKey* data() const { return m_vkeydata.data(); }
    void push(CPubKey &&in) { m_vkeydata.emplace_back(in); }
    size_t size() const { return m_vkeydata.size(); }

    friend bool operator==(const XOnlyPubKeys &a, const XOnlyPubKeys &b) {
        return a.m_vkeydata == b.m_vkeydata;
    }

    unsigned int GetSerializeSize() const {
        return ::GetSerializeSize(m_vkeydata);
    }

    template <typename Stream>
    inline void Serialize(Stream &s) const {
        NCONST_PTR(this)->SerializationOp(s, CSerActionSerialize());
    }

    template <typename Stream>
    inline void Unserialize(Stream &s) {
        this->SerializationOp(s, CSerActionUnserialize());
    }

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(m_vkeydata);
    }
};

// for WalletDB
struct XOnlyKeys; // privkey.h
struct XOnlyAggWalletInfo {
    constexpr static int schnorr_version = 1;
    int nVersion;

    //! Manages aggregated XOnlyKey.
    constexpr static size_t DEF_AGG_XONLY_KEYS = 5000;
    size_t aggregated_size;

    //! uint160: Hash of the aggregated public key
    //! std::tuple: Derive _nChildIn begin, aggregation size, (Future reservation) std::vector<unsigned char>
    std::map<uint160, std::tuple<unsigned int, size_t, std::vector<unsigned char>>> Derive_info;

    //! Construction that enables the generation of the first aggregated xonly key.
    XOnlyAggWalletInfo() {
        nVersion = schnorr_version;
        aggregated_size = 0;
    }

    //! T is uint160 type-only allowed member function
    //! return type is std::pair<unsigned int, size_t>
    template<typename T>
    typename std::enable_if<std::is_same<T, uint160>::value, std::pair<unsigned int, size_t>>::type
    GetInfo(const T &hash) const {
        if(!Derive_info.count(hash))
            return std::make_pair(0, 0);
        return std::make_pair(std::get<0>(Derive_info.at(hash)), std::get<1>(Derive_info.at(hash)));
    }

    unsigned int size() const {
        return Derive_info.size();
    }

    //! Load from the wallet to this object
    bool LoadFromWalletInfo();

    //! Update to the wallet
    bool UpdateToWalletInfo() const;

    //! Construct objects for each aggregated key
    bool GetXOnlyKeys(const uint160 &hash, XOnlyPubKeys &xonly_pubkeys, XOnlyKeys &xonly_keys) const;
    bool GetXOnlyPubKeys(const uint160 &hash, XOnlyPubKeys &xonly_pubkeys) const;

    //! Construct objects for each aggregated key (StrictOrder)
    bool GetXOnlyKeysStrictOrder(const uint160 &hash, XOnlyPubKeys &xonly_pubkeys, XOnlyKeys &xonly_keys) const;
    bool GetXOnlyPubKeysStrictOrder(const uint160 &hash, XOnlyPubKeys &xonly_pubkeys) const;

    friend bool operator==(const XOnlyAggWalletInfo &a, const XOnlyAggWalletInfo &b) {
        return a.nVersion == b.nVersion && a.aggregated_size == b.aggregated_size && a.Derive_info == b.Derive_info;
    }

    //! Manually assign and store the hash in the map.
    bool push(const uint160 &hash, unsigned int begin_index, size_t agg_size);
    bool push_commit(const uint160 &hash, unsigned int begin_index, size_t agg_size);
    bool push(const uint160 &hash, std::tuple<unsigned int, size_t, std::vector<unsigned char>> &&obj);
    bool push_commit(const uint160 &hash, std::tuple<unsigned int, size_t, std::vector<unsigned char>> &&obj);

    //! Automatically compute and store the hash in the map.
    bool push_computehash(unsigned int begin_index, size_t agg_size, uint160 &hash);
    bool push_computehash_commit(unsigned int begin_index, size_t agg_size, uint160 &hash);
    bool push_computehash(std::tuple<unsigned int, size_t, std::vector<unsigned char>> &&obj, uint160 &hash);
    bool push_computehash_commit(std::tuple<unsigned int, size_t, std::vector<unsigned char>> &&obj, uint160 &hash);

    //! Generate a new XOnly key using a CExtKey.
    //! This class uses a stored counter to generate unique keys. The default aggregation count is 5,000.
    bool MakeNewKey(uint160 &hash, size_t agg_size = DEF_AGG_XONLY_KEYS);

    unsigned int GetSerializeSize() const {
        CSizeComputer s(nVersion);
        s << *this;
        return s.size();
    }

    template<typename Stream>
    void Serialize(Stream &s) const {
        CSerActionSerialize ser_action;
        unsigned int size = (unsigned int)Derive_info.size();
        READWRITE(nVersion);
        READWRITE(aggregated_size);
        READWRITE(size);
        for(auto &r: Derive_info) {
            READWRITE(r.first);
            READWRITE(std::get<0>(r.second));
            READWRITE(std::get<1>(r.second));
            READWRITE(std::get<2>(r.second));
        }
    }

    template<typename Stream>
    void Unserialize(Stream &s) {
        CSerActionUnserialize ser_action;
        unsigned int size = 0;
        READWRITE(nVersion);
        READWRITE(aggregated_size);
        READWRITE(size);
        for(unsigned int i=0; i < size; ++i) {
            uint160 hash;
            unsigned int a;
            size_t b;
            std::vector<unsigned char> c;
            READWRITE(hash);
            READWRITE(a);
            READWRITE(b);
            READWRITE(c);
            Derive_info.emplace(std::make_pair(hash, std::make_tuple(a, b, c)));
        }
    }
};

//! It is used when importing or exporting Schnorr keys from an external source.
struct XOnlyPubKeysAggInfo {
    constexpr static int schnorr_version = 1;
    int nVersion;
    std::vector<XOnlyPubKeys> agg_pubkeys;

    XOnlyPubKeysAggInfo() {
        nVersion = schnorr_version;
    }

    const XOnlyPubKeys &GetInfo(int index) const {
        return agg_pubkeys[index];
    }

    unsigned int size() const {
        return agg_pubkeys.size();
    }

    void push(XOnlyPubKeys &&obj) {
        agg_pubkeys.emplace_back(obj);
    }

    unsigned int GetSerializeSize() const {
        CSizeComputer s(nVersion);
        s << *this;
        return s.size();
    }

    template <typename Stream>
    inline void Serialize(Stream &s) const {
        NCONST_PTR(this)->SerializationOp(s, CSerActionSerialize());
    }

    template <typename Stream>
    inline void Unserialize(Stream &s) {
        this->SerializationOp(s, CSerActionUnserialize());
    }

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        if(ser_action.ForRead()) {
            unsigned int size = 0;
            READWRITE(nVersion);
            READWRITE(size);
            agg_pubkeys.clear();
            for(unsigned int i=0; i < size; ++i) {
                XOnlyPubKeys vpub;
                READWRITE(vpub);
                agg_pubkeys.emplace_back(vpub);
            }
        } else {
            unsigned int size = (unsigned int)agg_pubkeys.size();
            READWRITE(nVersion);
            READWRITE(size);
            for(unsigned int i=0; i < size; ++i) {
                READWRITE(agg_pubkeys[i]);
            }
        }
    }
};

// BIP32
struct CExtPubKey {
    static constexpr unsigned int BIP32_EXTKEY_SIZE = 74; // [nDepth(1) + Finger(4) + nChild(4) + chaincode_(32) + pub(33) = 74] serialized data
    unsigned char nDepth_;
    unsigned char vchFingerprint_[4];
    unsigned int nChild_;
    ChainCode chaincode_; // uint256
    CPubKey pubkey_; // code to compressed pubkey

    friend bool operator==(const CExtPubKey &a, const CExtPubKey &b)  {
        return a.nDepth_ == b.nDepth_ &&
               ::memcmp(&a.vchFingerprint_[0], &b.vchFingerprint_[0], sizeof(vchFingerprint_)) == 0 &&
               a.nChild_ == b.nChild_ &&
               a.chaincode_ == b.chaincode_ &&
               a.pubkey_ == b.pubkey_;
    }

    void Invalidate(unsigned char code[BIP32_EXTKEY_SIZE]) const  {
        code[0] = 0xFF;
    }

    bool IsValid() const {
        return pubkey_.IsFullyValid_BIP66();
    }

    CPubKey GetPubKey() const;
    bool Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const; // from extpubkey to code
    bool Decode(const unsigned char code[BIP32_EXTKEY_SIZE]);
    bool Derive(CExtPubKey &out, unsigned int _nChildIn) const; // out.pubkey_ is always compressed

    void Serialize(CSizeComputer &s) const {
        // Optimized implementation for ::GetSerializeSize that avoids copying.
        s.seek(BIP32_EXTKEY_SIZE + 1);
    }

    unsigned int GetSerializeSize() const {
        return BIP32_EXTKEY_SIZE + 1;
    }

    template <typename Stream>
    void Serialize(Stream &s) const {
        const unsigned int len = BIP32_EXTKEY_SIZE;
        compact_size::manage::WriteCompactSize(s, len);
        unsigned char code[BIP32_EXTKEY_SIZE];
        if(! Encode(code))
            throw std::runtime_error("Invalid CExtPubKey Encode");
        s.write((const char *)&code[0], len);
    }

    template <typename Stream>
    void Unserialize(Stream &s) {
        unsigned int len = compact_size::manage::ReadCompactSize(s);
        unsigned char code[BIP32_EXTKEY_SIZE];
        if (len != BIP32_EXTKEY_SIZE) {
            if(len <= 0) {
                Invalidate(code);
                return;
            }
            char dummy;
            while(len--) {
                s.read((char *)&dummy, sizeof(char));
                cleanse::OPENSSL_cleanse(&dummy, sizeof(char));
            }
            Invalidate(code);
        } else {
            s.read((char *)&code[0], len);
            if(! Decode(code))
                throw std::runtime_error("Invalid CExtPubKey Decode");
        }
    }
};

// secp256k1 signed negate operator
using s256k1_fe = CPubKey::ecmult::secp256k1_fe;
namespace secp256k1_negate_ope {
    // secp256k1 from fe to uint256, from uint256 to fe.
    uint256 fe_get_uint256(const s256k1_fe *fe); // fe (be normalized)
    void fe_set_uint256(s256k1_fe *fe, const uint256 *lvalue);

    // from secp256k1_fe to std::string
    std::string fe_ToString(const s256k1_fe *fe); // fe (be normalized)
    std::string fe_normalize_to_ToString(const s256k1_fe *fe);

    int fe_get_signed(const s256k1_fe *fe_na); // negate[+fe_na] -: 0, +: 1
    int fe_get_negate(const s256k1_fe *fe_na); // negate[+fe_na] -: 1, +: 0
    void fe_normalize_negative(s256k1_fe *fe_na); // negate[-fe_na]
    int fe_normalize_to_cmp(s256k1_fe *fe1, s256k1_fe *fe2); // [fe1] cmp [fe2]

    // secp256k1_fe signed operator [negate ret 0: +, ret 1: -]
    // [set f1, f2 are normalized]
    // [result fe1 is normalized]
    int fe_add_to_negate(s256k1_fe *fe1, int fe1_negate, const s256k1_fe *fe2, int fe2_negate); // fe1 = fe1 + fe2
    int fe_sub_to_negate(s256k1_fe *fe1, int fe1_negate, const s256k1_fe *fe2, int fe2_negate); // fe1 = fe1 - fe2
    int fe_mul_to_negate(s256k1_fe *fe1, int fe1_negate, const s256k1_fe *fe2, int fe2_negate); // fe1 = fe1 * fe2
    int fe_div_to_negate(s256k1_fe *fe1, int fe1_negate, const s256k1_fe *fe2, int fe2_negate); // fe1 = fe1 / fe2
    int fe_mod_to_negate(s256k1_fe *fe1, int fe1_negate, const s256k1_fe *fe2, int fe2_negate); // fe1 = fe1 % fe2
    int fe_pow_to_negate(s256k1_fe *fe1, int fe1_negate, unsigned int n); // fe1^n (n>=0)
}

#endif
