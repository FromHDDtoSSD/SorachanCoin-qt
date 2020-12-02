// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin developers
// Copyright (c) 2017 The Zcash developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PUBKEY_H
#define BITCOIN_PUBKEY_H

#include <prevector/prevector.h>
#include <uint256.h>
#include <hash.h>
#include <serialize.h>
#include <bip32/hdchain.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <cleanse/cleanse.h>

class CKey;

#ifdef CSCRIPT_PREVECTOR_ENABLE
typedef prevector<PREVECTOR_N, uint8_t> key_vector;
#else
typedef std::vector<uint8_t> key_vector;
#endif

/** A reference to a CKey: the Hash160 of its serialized public key */
class CKeyID : public uint160
{
public:
    CKeyID() noexcept : uint160(0) {}
    CKeyID(const uint160 &in) noexcept : uint160(in) {}
};

// An encapsulated OpenSSL Elliptic Curve key (public)
// 32Bytes or 32Bytes + 32Bytes PublicKey
// The signature is 1 byte at the beginning. so 33Bytes or 65 Bytes.
// CoinAddress to use when sending coins is converted from CPubKey(65 Bytes) to CBitcoinAddress.

/** An encapsulated public key. */
// ref: src/secp256k1 secp256k1 library.
class CPubKey
{
    friend class CKey;
public:
    enum key_mode {
        SECP256K1,
        LAMPORT,
    } mode_;

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
    struct secp256k1_shad {
        int32_t d[8];
    };

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
        /** A group element of the secp256k1 curve, in jacobian coordinates. */
        typedef struct {
            secp256k1_fe x; /* actual X: x/z^2 */
            secp256k1_fe y; /* actual Y: y/z^3 */
            secp256k1_fe z;
            int infinity; /* whether this represents the point at infinity */
        } secp256k1_gej;
#ifdef VERIFY
        static void secp256k1_fe_verify(const secp256k1_fe *a) noexcept;
#endif
        static int secp256k1_fe_set_be32(secp256k1_fe *r, const unsigned char *a) noexcept;
        static int secp256k1_fe_cmp_var(const secp256k1_fe *a, const secp256k1_fe *b) noexcept;
        static void secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a) noexcept;
        static int secp256k1_ge_set_xo_var(secp256k1_ge *r, const secp256k1_fe *x, int odd) noexcept;
        static int secp256k1_ge_set_xquad(secp256k1_ge *r, const secp256k1_fe *x) noexcept;
        static void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a) noexcept;
        static void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe * SECP256K1_RESTRICT b) noexcept;
        static void secp256k1_fe_set_int(secp256k1_fe *r, int a) noexcept;
        static int secp256k1_fe_sqrt(secp256k1_fe *r, const secp256k1_fe *a) noexcept;
        static int secp256k1_fe_equal(const secp256k1_fe *a, const secp256k1_fe *b) noexcept;
        static void secp256k1_fe_negate(secp256k1_fe *r, const secp256k1_fe *a, int m) noexcept;
        static int secp256k1_fe_normalizes_to_zero(const secp256k1_fe *r) noexcept;
        static void secp256k1_fe_normalize_var(secp256k1_fe *r) noexcept;
        static int secp256k1_fe_is_odd(const secp256k1_fe *a) noexcept;
        static void secp256k1_gej_set_ge(secp256k1_gej *r, const secp256k1_ge *a) noexcept;
        static void secp256k1_fe_normalize_weak(secp256k1_fe *r) noexcept;
        static void secp256k1_fe_mul_int(secp256k1_fe *r, int a) noexcept;
        static int secp256k1_fe_normalizes_to_zero_var(secp256k1_fe *r) noexcept;
        static void secp256k1_gej_double_var(secp256k1_gej *r, const secp256k1_gej *a, secp256k1_fe *rzr) noexcept;
        static void secp256k1_ge_set_gej_zinv(secp256k1_ge *r, const secp256k1_gej *a, const ecmult::secp256k1_fe *zi) noexcept;
        static void secp256k1_gej_add_ge_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, ecmult::secp256k1_fe *rzr) noexcept;
        static void secp256k1_ge_globalz_set_table_gej(size_t len, secp256k1_ge *r, secp256k1_fe *globalz, const secp256k1_gej *a, const secp256k1_fe *zr) noexcept;
        static void secp256k1_fe_clear(secp256k1_fe *a) noexcept;
        static void secp256k1_gej_set_infinity(secp256k1_gej *r) noexcept;
        static void secp256k1_ge_neg(secp256k1_ge *r, const secp256k1_ge *a) noexcept;
        static void secp256k1_fe_from_storage(secp256k1_fe *r, const secp256k1_fe_storage *a) noexcept;
        static void secp256k1_ge_from_storage(secp256k1_ge *r, const secp256k1_ge_storage *a) noexcept;
        static void secp256k1_gej_add_zinv_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, const secp256k1_fe *bzinv) noexcept;
        static void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *a) noexcept;
        static void secp256k1_fe_inv_var(secp256k1_fe *r, const secp256k1_fe *a) noexcept;
        static void secp256k1_ge_set_gej_var(secp256k1_ge *r, secp256k1_gej *a) noexcept;
        static int secp256k1_gej_is_infinity(const secp256k1_gej *a) noexcept;
        static void secp256k1_fe_normalize(secp256k1_fe *r) noexcept;
        static void secp256k1_fe_to_storage(secp256k1_fe_storage *r, const secp256k1_fe *a) noexcept;
        static void secp256k1_ge_to_storage(secp256k1_ge_storage *r, const secp256k1_ge *a) noexcept;
        static int secp256k1_ge_is_infinity(const secp256k1_ge *a) noexcept;
        static void secp256k1_fe_get_be32(unsigned char *r, const secp256k1_fe *a) noexcept;
        static void secp256k1_ge_set_xy(secp256k1_ge *r, const secp256k1_fe *x, const secp256k1_fe *y) noexcept;
        static int secp256k1_ge_is_valid_var(const secp256k1_ge *a) noexcept;
        static int secp256k1_fe_equal_var(const secp256k1_fe *a, const secp256k1_fe *b) noexcept;
        static void secp256k1_ge_clear(secp256k1_ge *r) noexcept;
        static void secp256k1_ge_set_gej(secp256k1_ge *r, secp256k1_gej *a) noexcept;
        static bool secp256k1_ecmult_odd_multiples_table_storage_var(int n, secp256k1_ge_storage *pre, const secp256k1_gej *a) noexcept;
        static void secp256k1_ge_set_table_gej_var(secp256k1_ge *r, const secp256k1_gej *a, const secp256k1_fe *zr, size_t len) noexcept;
        static int secp256k1_fe_is_zero(const secp256k1_fe *a) noexcept;
        static int secp256k1_gej_eq_x_var(const secp256k1_fe *x, const secp256k1_gej *a) noexcept;

        // context
        class secp256k1_context {
        public:
            secp256k1_ge_storage (*pre_g_)[];     /* odd multiples of the generator */
#ifdef USE_ENDOMORPHISM
            secp256k1_ge_storage (*pre_g_128_)[]; /* odd multiples of 2^128*generator */
#endif
            void init() noexcept;
            bool build() noexcept;
            void clear() noexcept;
            secp256k1_context() noexcept;
            secp256k1_context(const secp256k1_context &)=delete;
            secp256k1_context &operator=(const secp256k1_context &obj)=delete;
            secp256k1_context &operator=(const secp256k1_context &&obj)=delete;
            ~secp256k1_context() noexcept;
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
    static int secp256k1_scalar_check_overflow(const secp256k1_unit *a) noexcept;
    static uint32_t secp256k1_scalar_reduce(secp256k1_unit *r, uint32_t overflow) noexcept;
    static void secp256k1_scalar_set_be32(secp256k1_unit *r, const unsigned char *b32, int *overflow) noexcept;
    static void secp256k1_scalar_get_be32(unsigned char *bin, const secp256k1_unit *a) noexcept;
    static void secp256k1_ecdsa_signature_save(secp256k1_signature *sig, const secp256k1_unit *r, const secp256k1_unit *s) noexcept;
    static void secp256k1_ecdsa_signature_load(secp256k1_unit *r, secp256k1_unit *s, const secp256k1_signature *sig) noexcept;
    static int secp256k1_ecdsa_signature_parse_compact(secp256k1_signature *sig, unsigned char *input64) noexcept;
    static int ecdsa_signature_parse_der_lax(secp256k1_signature *sig, const unsigned char *input, size_t inputlen) noexcept;
    static int secp256k1_scalar_is_high(const secp256k1_unit *a) noexcept;
    static int secp256k1_scalar_is_zero(const secp256k1_unit *a) noexcept;
    static int secp256k1_ecdsa_signature_normalize(const secp256k1_signature *sigin) noexcept;
    static int secp256k1_ecdsa_signature_normalize(secp256k1_signature *sigout, const secp256k1_signature *sigin) noexcept;
    static void secp256k1_ecdsa_recoverable_signature_save(secp256k1_ecdsa_recoverable_signature *sig, const secp256k1_unit *r, const secp256k1_unit *s, int recid) noexcept;
    static void secp256k1_ecdsa_recoverable_signature_load(secp256k1_unit *r, secp256k1_unit *s, int *recid, const secp256k1_ecdsa_recoverable_signature *sig) noexcept;
    static int secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ecdsa_recoverable_signature *sig, const unsigned char *input64, int recid) noexcept;
    static void secp256k1_scalar_negate(secp256k1_unit *r, const secp256k1_unit *a) noexcept;
    static unsigned int secp256k1_scalar_get_bits(const secp256k1_unit *a, unsigned int offset, unsigned int count) noexcept;
    static unsigned int secp256k1_scalar_get_bits_var(const secp256k1_unit *a, unsigned int offset, unsigned int count) noexcept;
    static void secp256k1_ecmult_odd_multiples_table(int n, ecmult::secp256k1_gej *prej, ecmult::secp256k1_fe *zr, const ecmult::secp256k1_gej *a) noexcept;
    static int secp256k1_ecmult(ecmult::secp256k1_gej *r, const ecmult::secp256k1_gej *a, const secp256k1_unit *na, const secp256k1_unit *ng) noexcept;
    static int secp256k1_ecdsa_sig_recover(const secp256k1_unit *sigr, const secp256k1_unit *sigs, ecmult::secp256k1_ge *pubkey, const secp256k1_unit *message, int recid) noexcept;
    static void secp256k1_scalar_sqr_512(uint32_t *l, const secp256k1_unit *a) noexcept;
    static void secp256k1_scalar_reduce_512(secp256k1_unit *r, const uint32_t *l) noexcept;
    static void secp256k1_scalar_sqr(secp256k1_unit *r, const secp256k1_unit *a) noexcept;
    static void secp256k1_scalar_mul_512(uint32_t *l, const secp256k1_unit *a, const secp256k1_unit *b) noexcept;
    static void secp256k1_scalar_mul(secp256k1_unit *r, const secp256k1_unit *a, const secp256k1_unit *b) noexcept;
    static void secp256k1_scalar_inverse(secp256k1_unit *r, const secp256k1_unit *x) noexcept;
    // static int secp256k1_scalar_is_even(const secp256k1_unit *a) noexcept;
    static void secp256k1_scalar_inverse_var(secp256k1_unit *r, const secp256k1_unit *x) noexcept;
    static void secp256k1_pubkey_save(secp256k1_pubkey *pubkey, ecmult::secp256k1_ge *ge) noexcept;
    static int secp256k1_ecdsa_recover(secp256k1_pubkey *pubkey, const secp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msg32) noexcept;
    static int secp256k1_pubkey_load(ecmult::secp256k1_ge *ge, const secp256k1_pubkey *pubkey) noexcept;
    static int secp256k1_eckey_pubkey_serialize(ecmult::secp256k1_ge *elem, unsigned char (*pub)[PUBLIC_KEY_SIZE], size_t *size, int compressed) noexcept;
    static int secp256k1_ec_pubkey_serialize(unsigned char (*output)[PUBLIC_KEY_SIZE], size_t *outputlen, const secp256k1_pubkey *pubkey, unsigned int flags) noexcept;
    static int secp256k1_ec_pubkey_parse(secp256k1_pubkey *pubkey, const unsigned char *input, size_t inputlen) noexcept;
    static int secp256k1_eckey_pubkey_parse(ecmult::secp256k1_ge *elem, const unsigned char *pub, size_t size) noexcept;
    static int secp256k1_ec_pubkey_tweak_add(secp256k1_pubkey *pubkey, const unsigned char *tweak) noexcept;
    static int secp256k1_eckey_pubkey_tweak_add(ecmult::secp256k1_ge *key, const secp256k1_unit *tweak) noexcept;
    static void secp256k1_scalar_set_int(secp256k1_unit *r, unsigned int v) noexcept;
    static int secp256k1_ecdsa_verify(const secp256k1_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pubkey) noexcept;
    static int secp256k1_ecdsa_sig_verify(const secp256k1_unit *sigr, const secp256k1_unit *sigs, const ecmult::secp256k1_ge *pubkey, const secp256k1_unit *message) noexcept;
#ifdef USE_ENDOMORPHISM
    static void secp256k1_scalar_cadd_bit(secp256k1_unit *r, unsigned int bit, int flag) noexcept;
    static void secp256k1_scalar_mul_shift_var(secp256k1_unit *r, const secp256k1_unit *a, const secp256k1_unit *b, unsigned int shift) noexcept;
    static int secp256k1_scalar_add(secp256k1_unit *r, const secp256k1_unit *a, const secp256k1_unit *b) noexcept;
#endif

    // Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields [OpenSSL from only sig to PubKey]
    static int ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check) noexcept;

private:
    // Just store the serialized data.
    // Its length can very cheaply be computed from the first byte.
    unsigned char vch_[PUBLIC_KEY_SIZE];

    //! Compute the length of a pubkey with a given first byte.
    static unsigned int GetLen(unsigned char chHeader) noexcept {
        if (chHeader == 2 || chHeader == 3)
            return COMPRESSED_PUBLIC_KEY_SIZE;
        if (chHeader == 4 || chHeader == 6 || chHeader == 7)
            return PUBLIC_KEY_SIZE;
        return 0;
    }

    //! Set this key data to be invalid
    void Invalidate() noexcept {
        vch_[0] = 0xFF;
    }

public:
    static bool ValidSize(const std::vector<unsigned char> &_vch) noexcept {
      return _vch.size() > 0 && GetLen(_vch[0]) == _vch.size();
    }

    //! Construct an invalid public key.
    CPubKey() noexcept {
        Invalidate();
    }

    //! Initialize a public key using begin/end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend) noexcept {
        int len = pend == pbegin ? 0 : CPubKey::GetLen(pbegin[0]);
        if (len && len == (pend - pbegin))
            ::memcpy(vch_, (unsigned char *)&pbegin[0], len);
        else
            Invalidate();
    }
    void Set(const key_vector &_vch) noexcept {
        Set(_vch.begin(), _vch.end());
    }

    //! Construct a public key using begin/end iterators to byte data.
    template <typename T>
    CPubKey(const T pbegin, const T pend) noexcept {
        Set(pbegin, pend);
    }

    //! Construct a public key from a byte vector.
    explicit CPubKey(const key_vector &_vch) noexcept {
        Set(_vch.begin(), _vch.end());
    }

    //! key_vector operator (wallet.cpp)
    bool operator!=(const key_vector &_vch) noexcept {
        CPubKey _cmp(_vch);
        return *this != _cmp;
    }

    //! Simple read-only vector-like interface to the pubkey data.
    unsigned int size() const noexcept { return CPubKey::GetLen(vch_[0]); }
    const unsigned char *data() const noexcept { return vch_; }
    const unsigned char *begin() const noexcept { return vch_; }
    const unsigned char *end() const noexcept { return vch_ + size(); }
    const unsigned char &operator[](unsigned int pos) const noexcept { return vch_[pos]; }

    //! Comparator implementation.
    friend bool operator==(const CPubKey &a, const CPubKey &b) noexcept {
        return a.vch_[0] == b.vch_[0] &&
               ::memcmp(a.vch_, b.vch_, a.size()) == 0;
    }
    friend bool operator!=(const CPubKey &a, const CPubKey &b) noexcept {
        return !(a == b);
    }
    friend bool operator<(const CPubKey &a, const CPubKey &b) noexcept {
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
    CKeyID GetID() const noexcept {
        return CKeyID(hash_basis::Hash160(begin(), end()));
    }

    //! Get the 256-bit hash of this public key.
    uint256 GetHash() const noexcept {
        return hash_basis::Hash(begin(), end());
    }

    //! Check syntactic correctness.
    //  Note: this is consensus critical as CheckSig() calls it!
    bool IsValid() const noexcept;

    //! fully validate whether this is a valid public key (more expensive than IsValid()) [OpenSSL, libsecp256k1(BIP66)]
    bool IsFullyValid() const noexcept;
    bool IsFullyValid_BIP66() const noexcept;

    //! Check whether this is a compressed public key.
    bool IsCompressed() const noexcept {
        return size() == COMPRESSED_PUBLIC_KEY_SIZE;
    }

    //! Verify a DER signature (~72 bytes). [OpenSSL, libsecp256k1(BIP66)]
    // [OpenSSL] If this public key is not fully valid, the return value will be false.
    bool Verify(const uint256 &hash, const key_vector &vchSig) const noexcept;
    bool Verify_BIP66(const uint256 &hash, const key_vector &vchSig) const noexcept;

    // Check whether a signature is normalized (lower-S). [libsecp256k1]
    static bool CheckLowS(const std::vector<unsigned char> &vchSig) noexcept;

    //! Recover a public key from a compact signature. [libsecp256k1]
    bool RecoverCompact(const uint256 &hash, const std::vector<unsigned char> &vchSig) noexcept;

    //! Recover a public key from a compact signature. [OpenSSL]
    bool SetCompactSignature(const uint256 &hash, const std::vector<unsigned char> &vchSig) noexcept;

    // Reserialize to DER [OpenSSL]
    static bool ReserealizeSignature(key_vector &vchSig) noexcept;

    //! Turn this public key into an uncompressed public key. [libsecp256k1]
    bool Decompress() noexcept;

    //! Derive BIP32 child pubkey. [for HD wallet] [libsecp256k1]
    bool Derive(CPubKey &pubkeyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode &cc) const noexcept;

    //! Encrypt data [for Random wallet] [OpenSSL ecies cryptogram]
    bool EncryptData(const key_vector &data, key_vector &encrypted) const noexcept;

    //! CPubKey Callback ERROR and Completion function [libsecp256k1]
    static int PubKey_ERROR_callback(void (*fn)()=nullptr) noexcept {if(fn) fn(); return 0;}
    static void PubKey_COMPLETION_callback(void (*fn)()) noexcept {fn();}

    //! vch_ to string
    std::string ToString() const noexcept;
};

// BIP32
class CExtPubKey {
    CExtPubKey(const CExtPubKey &)=delete;
    CExtPubKey &operator=(const CExtPubKey &)=delete;
    CExtPubKey &operator=(const CExtPubKey &&)=delete;
public:
    static constexpr unsigned int BIP32_EXTKEY_SIZE = 74;
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    ChainCode chaincode;
    CPubKey pubkey;

    friend bool operator==(const CExtPubKey &a, const CExtPubKey &b) noexcept {
        return a.nDepth == b.nDepth &&
               ::memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], sizeof(vchFingerprint)) == 0 &&
               a.nChild == b.nChild &&
               a.chaincode == b.chaincode &&
               a.pubkey == b.pubkey;
    }

    void Invalidate(unsigned char (*code)[BIP32_EXTKEY_SIZE]) const noexcept {
        (*code)[0] = 0xFF;
    }
    void Encode(unsigned char (*code)[BIP32_EXTKEY_SIZE]) const noexcept;
    void Decode(const unsigned char (*code)[BIP32_EXTKEY_SIZE]) noexcept;
    bool Derive(CExtPubKey &out, unsigned int nChild) const noexcept;

    /*
    void Serialize(CSizeComputer &s) const {
        // Optimized implementation for ::GetSerializeSize that avoids copying.
        s.seek(BIP32_EXTKEY_SIZE + 1); // add one byte for the size (compact int)
    }
    */
    unsigned int GetSerializeSize() const {
        return BIP32_EXTKEY_SIZE + 1;
    }
    template <typename Stream>
    void Serialize(Stream &s) const {
        unsigned int len = BIP32_EXTKEY_SIZE;
        compact_size::manage::WriteCompactSize(s, len);
        unsigned char code[BIP32_EXTKEY_SIZE];
        Encode(&code);
        s.write((const char *)&code[0], len);
    }
    template <typename Stream>
    void Unserialize(Stream &s) {
        unsigned int len = compact_size::manage::ReadCompactSize(s);
        unsigned char code[BIP32_EXTKEY_SIZE];
        if (len != BIP32_EXTKEY_SIZE) {
            if(len <= 0) {
                Invalidate(&code);
                return;
            }
            char dummy;
            while(len--) {
                s.read((char *)&dummy, sizeof(char));
                cleanse::OPENSSL_cleanse(&dummy, sizeof(char));
            }
            Invalidate(&code);
        } else {
            s.read((char *)&code[0], len);
            Decode(&code);
        }
    }
};

#endif
