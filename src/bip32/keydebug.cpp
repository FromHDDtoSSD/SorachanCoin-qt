// Copyright (c) 2009-2021 The Bitcoin developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key/pubkey.h>
#include <key/privkey.h>
#include <uint256.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <init.h>
#include <sorara/aitx.h>
#include <allocator/allocators.h>
#include <thread/threadqai.h>
#if __cplusplus <= 201703L
# include <locale>
# include <codecvt>
#endif

// #define VERIFY_CHECK(cond) do { (void)(cond); } while(0)

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

int calculate_y_coordinate(const EC_GROUP *group, const BIGNUM *x, BIGNUM *y, BN_CTX *ctx) {
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *x3 = BN_new();
    BIGNUM *rhs = BN_new();
    int fret = 0;

    do {
        if(!a || !b || !p || !x3 || !rhs)
            break;
        if (EC_GROUP_get_curve_GFp(group, p, a, b, ctx) != 1)
            break;
        if (BN_mod_sqr(x3, x, p, ctx) != 1)
            break;
        if (BN_mod_mul(x3, x3, x, p, ctx) != 1)
            break;
        if (BN_mod_add(rhs, x3, b, p, ctx) != 1)
            break;
        if (!BN_mod_sqrt(y, rhs, p, ctx))
            break;

        fret = 1;
    } while(false);

    BN_free(a);
    BN_free(b);
    BN_free(p);
    BN_free(x3);
    BN_free(rhs);

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
            if(BN_sub(e, order, e) != 1) // invert: sub from mod p
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

bool verify(const BIGNUM *pubkey_x, const uint256 &hash, const std::vector<unsigned char> &sig) {
    // sig = [R_points_xonly | s]
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *order = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *R_x = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *e = BN_new();
    EC_POINT *lhs = EC_POINT_new(group);
    BIGNUM *pubkey_y = BN_new();
    EC_POINT *pubkey = EC_POINT_new(group);
    EC_POINT *e_mul_pubkey = EC_POINT_new(group);
    BIGNUM *neg_one = BN_new();
    EC_POINT *R2 = EC_POINT_new(group);
    BIGNUM *R2_x = BN_new();

    bool fret = false;
    do {
        if(!group || !ctx || !order || !p || !R_x || !s || !e || !lhs || !pubkey_y || !pubkey || !e_mul_pubkey || !neg_one || !R2 || !R2_x)
            break;

        // get order and p (F_p mod) and neg_one
        if(EC_GROUP_get_order(group, order, ctx) != 1)
            break;
        if(EC_GROUP_get_curve_GFp(group, p, NULL, NULL, ctx) != 1)
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

        // R2 = lhs - e * pubkey
        if(calculate_y_coordinate(group, pubkey_x, pubkey_y, ctx) != 1)
            break;
        if(BN_is_odd(pubkey_y)) {
            if(BN_sub(pubkey_y, p, pubkey_y) != 1)
                break;
        }
        if(EC_POINT_set_affine_coordinates_GFp(group, pubkey, pubkey_x, pubkey_y, ctx) != 1)
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
    } while(false);

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    BN_free(order);
    BN_free(p);
    BN_free(R_x);
    BN_free(s);
    BN_free(e);
    EC_POINT_free(lhs);
    BN_free(pubkey_y);
    EC_POINT_free(pubkey);
    EC_POINT_free(e_mul_pubkey);
    BN_free(neg_one);
    EC_POINT_free(R2);
    BN_free(R2_x);

    return fret;
}

} // schnorr_openssl

/*
#define ARG_CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        return 0; \
    } \
} while(0)
*/

#ifndef EXHAUSTIVE_TEST_ORDER
/* see group_impl.h for allowable values */
#define EXHAUSTIVE_TEST_ORDER 13
#define EXHAUSTIVE_TEST_LAMBDA 9   /* cube root of 1 mod 13 */
#endif

static SECP256K1_INLINE uint32_t secp256k1_check_overflow(uint32_t x, uint32_t y, uint32_t overflow) {
    volatile uint32_t mask = overflow - 1;
    return (x & mask) | (y & ~mask);
}

static SECP256K1_INLINE void secp256k1_scalar_memcpy(CPubKey::secp256k1_scalar *r, const CPubKey::secp256k1_scalar *a) {
    uint32_t overflow = CPubKey::secp256k1_scalar_is_high(a);
    uint32_t mask = secp256k1_check_overflow(0xFFFFFFFF, 0, overflow);
    for (int i = 0; i < 8; i++) {
        r->d[i] = secp256k1_check_overflow(a->d[i], 0, overflow & mask);
    }
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

std::shared_ptr<CFirmKey> Create_pub_y_key() {
    std::shared_ptr<CFirmKey> key(new (std::nothrow) CFirmKey);
    if(!key.get())
        return key;
    key.get()->MakeNewKey(true);
    return key;
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

std::shared_ptr<CFirmKey> Create_pub_y_odd_key(const unsigned char *privkey = nullptr) {
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
        if(pubkey.data()[0] == 0x03)
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

/*
void Print_hash_and_priv(const uint256 &hash, const BIGNUM *priv1, const CSecret &priv2) {
    debugcs::instance() << __func__ << " hash:" << hash.ToString() << debugcs::endl();
    debugcs::instance() << __func__ << " priv1:" << BN_bn2hex(priv1) << debugcs::endl();
    debugcs::instance() << __func__ << " priv2:" << strenc::HexStr(priv2) << debugcs::endl();
}
*/

// Checker
// 1, [OK checked] OpenSSL schnorr signature sign and verify: try pub_y with both odd and even values
bool OpenSSL_schnorr_sign_and_verify_pub_y_with_both_odd_and_even() {
    BIGNUM *privkey = BN_new();
    BIGNUM *pub_x_only = BN_new();
    BIGNUM *invalid_pub_x_only = BN_new();
    const int check_num = 8;

    bool fret = false;
    int checking = 0;
    do {
        if(!privkey || !pub_x_only || !invalid_pub_x_only)
            break;

        //std::shared_ptr<CFirmKey> secpkey = (checking % 2 == 0) ? Create_pub_y_odd_key(): Create_pub_y_even_key();
        std::shared_ptr<CFirmKey> secpkey = Create_pub_y_key();
        if(!secpkey.get())
            break;
        CSecret secret = secpkey->GetSecret();
        std::vector<unsigned char> vchsig;
        uint256 hash = Create_random_hash();
        if(!BN_bin2bn(secret.data(), 32, privkey))
            break;

        // sign
        if(!schnorr_openssl::sign(privkey, hash, vchsig))
            break;

        CPubKey pubkey = secpkey->GetPubKey();
        pubkey.Compress();
        if(!BN_bin2bn(pubkey.data() + 1, 32, pub_x_only))
            break;

        // valid verify
        if(schnorr_openssl::verify(pub_x_only, hash, vchsig))
            debugcs::instance() << __func__ << " ok schnorr_openssl::verify1 valid" << debugcs::endl();
        else {
            debugcs::instance() << __func__ << " failure schnorr_openssl::verify1 invalid" << debugcs::endl();
            break;
        }

        // invalid verify 1
        uint256 invalid_hash = hash;
        invalid_hash.begin()[2] = 0xFF;
        invalid_hash.begin()[3] = 0x55;
        if(schnorr_openssl::verify(pub_x_only, invalid_hash, vchsig)) {
            debugcs::instance() << __func__ << " failure schnorr_openssl::verify1 valid" << debugcs::endl();
            break;
        } else
            debugcs::instance() << __func__ << " ok schnorr_openssl::verify1 invalid" << debugcs::endl();

        // invalid verify 2
        if(!BN_copy(invalid_pub_x_only, pub_x_only))
            break;
        if(BN_add_word(invalid_pub_x_only, 88) != 1)
            break;
        if(schnorr_openssl::verify(invalid_pub_x_only, invalid_hash, vchsig)) {
            debugcs::instance() << __func__ << " failure schnorr_openssl::verify2 valid" << debugcs::endl();
            break;
        } else
            debugcs::instance() << __func__ << " ok schnorr_openssl::verify2 invalid" << debugcs::endl();

        ++checking;
    } while(checking < check_num);
    if(checking == check_num)
        fret = true;

    BN_clear_free(privkey);
    BN_free(pub_x_only);
    BN_free(invalid_pub_x_only);

    return fret;
}

// Checker
// 2, [OK checked] Libsecp256k1 schnorr signature sign and OpenSSL verify: try pub_y with both odd and even values
bool Libsecp256k1_schnorr_sign_and_openssl_verify_pub_y_with_both_odd_and_even() {
    BIGNUM *pub_x_only = BN_new();
    BIGNUM *invalid_pub_x_only = BN_new();
    const int check_num = 8;

    bool fret = false;
    int checking = 0;
    do {
        //std::shared_ptr<CFirmKey> secpkey = (checking % 2 == 0) ? Create_pub_y_odd_key(): Create_pub_y_even_key();
        std::shared_ptr<CFirmKey> secpkey = Create_pub_y_key();
        if(!secpkey.get())
            break;
        CSecret secret = secpkey->GetSecret();
        secp256k1_schnorrsig sig;
        uint256 hash = Create_random_hash();

        // sign
        if(XOnlyKey::secp256k1_schnorrsig_sign(NULL, &sig, nullptr, hash.begin(), secret.data(), schnorr_nonce::secp256k1_nonce_and_random_function_schnorr, nullptr) != 1)
            break;

        CPubKey pubkey = secpkey->GetPubKey();
        pubkey.Compress();
        if(!BN_bin2bn(pubkey.data() + 1, 32, pub_x_only))
            break;
        std::vector<unsigned char> vchsig;
        vchsig.resize(64);
        ::memcpy(&vchsig.front(), &sig.data[0], 64);

        // valid verify
        if(schnorr_openssl::verify(pub_x_only, hash, vchsig))
            debugcs::instance() << __func__ << " ok Libsecp256k1 sign, schnorr_openssl::verify valid" << debugcs::endl();
        else {
            debugcs::instance() << __func__ << " failure Libsecp256k1 sign, schnorr_openssl::verify invalid" << debugcs::endl();
            break;
        }

        // invalid verify 1
        uint256 invalid_hash = hash;
        invalid_hash.begin()[2] = 0xFF;
        invalid_hash.begin()[3] = 0x55;
        if(schnorr_openssl::verify(pub_x_only, invalid_hash, vchsig)) {
            debugcs::instance() << __func__ << " failure Libsecp256k1 sign, schnorr_openssl::verify invalid" << debugcs::endl();
            break;
        } else
            debugcs::instance() << __func__ << " ok Libsecp256k1 sign, schnorr_openssl::verify valid" << debugcs::endl();

        // invalid verify 2
        if(!BN_copy(invalid_pub_x_only, pub_x_only))
            break;
        if(BN_add_word(invalid_pub_x_only, 88) != 1)
            break;
        if(schnorr_openssl::verify(invalid_pub_x_only, invalid_hash, vchsig)) {
            debugcs::instance() << __func__ << " failure Libsecp256k1 sign, schnorr_openssl::verify invalid" << debugcs::endl();
            break;
        } else
            debugcs::instance() << __func__ << " ok Libsecp256k1 sign, schnorr_openssl::verify valid" << debugcs::endl();

        ++checking;
    } while(checking < check_num);
    if(checking == check_num)
        fret = true;

    BN_free(pub_x_only);
    BN_free(invalid_pub_x_only);

    return fret;
}

namespace schnorr_collect {

int aggregate_secret_keys(const std::vector<CSecret> &secrets, CSecret *aggregated_secret) {
    CPubKey::secp256k1_scalar ret;
    CPubKey::secp256k1_scalar_set_int(&ret, 0);
    for(int i=0; i < secrets.size(); ++i) {
        CPubKey::secp256k1_scalar tmp;
        int overflow;
        CPubKey::secp256k1_scalar_set_b32(&tmp, secrets[i].data(), &overflow);
        if(overflow) {
            cleanse::memory_cleanse(&ret, 32);
            cleanse::memory_cleanse(&tmp, 32);
            return 0;
        }
        CPubKey::secp256k1_scalar_add(&ret, &ret, &tmp);
        cleanse::memory_cleanse(&tmp, 32);
    }
    aggregated_secret->resize(32);
    unsigned char *buf = &aggregated_secret->front();
    CPubKey::secp256k1_scalar_get_b32(buf, &ret);
    cleanse::memory_cleanse(&ret, 32);
    return 1;
}

int aggregate_public_keys(const std::vector<CPubKey::secp256k1_pubkey> &pubkeys, CPubKey::secp256k1_pubkey *aggregated_pubkey) {
    CPubKey::ecmult::secp256k1_gej aggregated_point;
    CPubKey::ecmult::secp256k1_ge point;

    CPubKey::ecmult::secp256k1_gej_set_infinity(&aggregated_point);
    CPubKey::ecmult::secp256k1_fe rzr;
    CPubKey::ecmult::secp256k1_fe_clear(&rzr);
    for (size_t i = 0; i < pubkeys.size(); i++) {
        if (!CPubKey::secp256k1_pubkey_load(&point, &pubkeys[i]))
            return 0;
        if(aggregated_point.infinity)
            CPubKey::ecmult::secp256k1_gej_add_ge_var(&aggregated_point, &aggregated_point, &point, NULL);
        else
            CPubKey::ecmult::secp256k1_gej_add_ge_var(&aggregated_point, &aggregated_point, &point, &rzr);
    }

    CPubKey::ecmult::secp256k1_ge aggregated_ge;
    CPubKey::ecmult::secp256k1_ge_set_gej(&aggregated_ge, &aggregated_point);
    CPubKey::secp256k1_pubkey_save(aggregated_pubkey, &aggregated_ge);

    return 1;
}

int aggregate_signatures(const std::vector<CPubKey::secp256k1_signature> &signatures, CPubKey::secp256k1_signature *aggregated_signature) {
    CPubKey::ecmult::secp256k1_gej r_j;
    CPubKey::ecmult::secp256k1_gej_set_infinity(&r_j);
    CPubKey::secp256k1_scalar aggregated_s;
    CPubKey::secp256k1_scalar_set_int(&aggregated_s, 0);

    CPubKey::ecmult::secp256k1_fe rzr;
    CPubKey::ecmult::secp256k1_fe_clear(&rzr);
    for (size_t i = 0; i < signatures.size(); i++) {
        // r
        CPubKey::ecmult::secp256k1_fe r_x;
        CPubKey::ecmult::secp256k1_ge r_aff;
        CPubKey::ecmult::secp256k1_fe_set_b32(&r_x, &signatures[i].data[0]);
        //print_secp256k1_fe("agg_r_x", &r_x);
        CPubKey::ecmult::secp256k1_ge_set_xo_var(&r_aff, &r_x, 0);
        if(r_j.infinity)
            CPubKey::ecmult::secp256k1_gej_add_ge_var(&r_j, &r_j, &r_aff, NULL);
        else
            CPubKey::ecmult::secp256k1_gej_add_ge_var(&r_j, &r_j, &r_aff, &rzr);
        //print_secp256k1_fe("agg_r_y", &r_aff.y);

        // s
        CPubKey::secp256k1_scalar s;
        CPubKey::secp256k1_ecdsa_signature_load(NULL, &s, &signatures[i]);
        CPubKey::secp256k1_scalar_add(&aggregated_s, &aggregated_s, &s);
        //print_secp256k1_scalar("agg_s_1", &aggregated_s);
    }

    CPubKey::ecmult::secp256k1_ge r_ret;
    CPubKey::ecmult::secp256k1_ge_set_gej(&r_ret, &r_j);
    CPubKey::ecmult::secp256k1_fe_normalize(&r_ret.x);
    //print_secp256k1_fe("agg_r_2", &r_ret.x);
    CPubKey::ecmult::secp256k1_fe_get_b32(&aggregated_signature->data[0], &r_ret.x);

    //print_secp256k1_scalar("agg_s_2", &aggregated_s);
    CPubKey::secp256k1_scalar_get_b32(&aggregated_signature->data[32], &aggregated_s);

    return 1;
}

// openssl
bool aggregate_public_keys(const std::vector<CPubKey> &pubkeysIn, CPubKey &agg_pubkey) {
    assert(0 < pubkeysIn.size());
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX *ctx = BN_CTX_new();

    std::vector<CPubKey> pubkeys = pubkeysIn;
    EC_POINT *point = EC_POINT_new(group);
    EC_POINT *tmp = EC_POINT_new(group);

    unsigned char pub_points[33];
    bool fret = true;
    do {
        if(!group || !ctx || !point || !tmp)
            return false;

        if(!pubkeys[0].Compress()) {
            fret = false;
            break;
        }
        if(EC_POINT_oct2point(group, point, pubkeys[0].data(), 33, ctx) != 1) {
            fret = false;
            break;
        }

        for (int i = 1; i < pubkeys.size(); i++) {
            if(!pubkeys[i].Compress()) {
                fret = false;
                break;
            }
            if(EC_POINT_oct2point(group, tmp, pubkeys[i].data(), 33, ctx) != 1) {
                fret = false;
                break;
            }
            if(EC_POINT_add(group, point, point, tmp, ctx) != 1) {
                fret = false;
                break;
            }
        }
        if(!fret)
            break;

        if(EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, pub_points, sizeof(pub_points), ctx) != sizeof(pub_points)) {
            fret = false;
            break;
        }
    } while(false);

    EC_POINT_free(point);
    EC_POINT_free(tmp);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    if(!fret)
        return false;

    debugcs::instance() << __func__ << " agg_pubkeys:" << strenc::HexStr(key_vector(BEGIN(pub_points), END(pub_points))) << debugcs::endl();

    agg_pubkey.Set(key_vector(BEGIN(pub_points), END(pub_points)));
    return agg_pubkey.IsFullyValid_BIP66();
}

//openssl
bool aggregate_secret_keys(const std::vector<CSecret> &secrets, CSecret &agg_secret) {
    assert(0 < secrets.size());
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM *p = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *tmp = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    bool fret = true;
    do {
        if(!group || !p || !r || !tmp || !ctx) {
            fret = false;
            break;
        }
        if(!EC_GROUP_get_curve_GFp(group, p, NULL, NULL, ctx)) {
            fret = false;
            break;
        }

        if(BN_set_word(r, 0) != 1) {
            fret = false;
            break;
        }

        for(int i=0; i < secrets.size(); ++i) {
            if(!BN_bin2bn(secrets[i].data(), 32, tmp)) {
                fret = false;
                break;
            }
            if(BN_mod_add(r, r, tmp, p, ctx) != 1) {
                fret = false;
                break;
            }
        }

        agg_secret.resize(32);
        if(schnorr_openssl::BN_bn2bin_padded(r, &agg_secret.front(), 32) != 1) {
            fret = false;
            break;
        }
    } while(false);

    EC_GROUP_free(group);
    BN_free(p);
    BN_clear_free(r);
    BN_clear_free(tmp);
    BN_CTX_free(ctx);

    return fret;
}

//openssl
bool aggregate_signatures(const std::vector<secp256k1_schnorrsig> &signatures, secp256k1_schnorrsig &agg_sig) {
    assert(0 < signatures.size());
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *tmp = BN_new();

    EC_POINT *r_ret = EC_POINT_new(group);
    EC_POINT *r_point = EC_POINT_new(group);
    BIGNUM *r_x_point = BN_new();

    BIGNUM *p = BN_new();
    BIGNUM *s = BN_new();

    // r
    bool fret1 = true;
    do {
        if(!group || !ctx || !tmp || !r_ret || !r_point || !r_x_point) {
            fret1 = false;
            break;
        }

        if(!BN_bin2bn(&signatures[0].data[0], 32, tmp)) {
            fret1 = false;
            break;
        }
        if(EC_POINT_set_compressed_coordinates_GFp(group, r_ret, tmp, 0, ctx) != 1) {
            fret1 = false;
            break;
        }
        if(EC_POINT_is_on_curve(group, r_ret, ctx) != 1) {
            fret1 = false;
            break;
        }

        print_bignum("agg_r_x befor", tmp);

        for(int i = 1; i < signatures.size(); ++i) {
            if(!BN_bin2bn(&signatures[i].data[0], 32, tmp)) {
                fret1 = false;
                break;
            }
            if(EC_POINT_set_compressed_coordinates_GFp(group, r_point, tmp, 0, ctx) != 1) {
                fret1 = false;
                break;
            }
            if(EC_POINT_is_on_curve(group, r_point, ctx) != 1) {
                fret1 = false;
                break;
            }
            if(EC_POINT_add(group, r_ret, r_ret, r_point, ctx) != 1) {
                fret1 = false;
                break;
            }
        }
        if(!fret1)
            break;

        if(EC_POINT_get_affine_coordinates_GFp(group, r_ret, r_x_point, NULL, ctx) != 1) {
            fret1 = false;
            break;
        }
        if(schnorr_openssl::BN_bn2bin_padded(r_x_point, &agg_sig.data[0], 32) != 1) {
            fret1 = false;
            break;
        }
    } while(false);

    print_bignum("agg_r_x after", r_x_point);

    // s
    bool fret2 = true;
    do {
        if(!group || !ctx || !tmp || !p || !s) {
            fret2 = false;
            break;
        }
        if(!EC_GROUP_get_curve_GFp(group, p, NULL, NULL, ctx)) {
            fret2 = false;
            break;
        }
        if(!BN_bin2bn(&signatures[0].data[32], 32, s)) {
            fret2 = false;
            break;
        }

        print_bignum("agg_s1 before", s);

        for(int i = 1; i < signatures.size(); ++i) {
            if(!BN_bin2bn(&signatures[i].data[32], 32, tmp)) {
                fret2 = false;
                break;
            }
            if(BN_mod_add(s, s, tmp, p, ctx) != 1) {
                fret2 = false;
                break;
            }
        }
        if(!fret2)
            break;

        print_bignum("agg_s1  after", s);

        if(schnorr_openssl::BN_bn2bin_padded(s, &agg_sig.data[32], 32) != 1) {
            fret2 = false;
            break;
        }
    } while(false);

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    BN_free(tmp);
    EC_POINT_free(r_ret);
    EC_POINT_free(r_point);
    BN_free(r_x_point);
    BN_free(p);
    BN_free(s);

    return fret1 && fret2;
}

} // schnorr_collect

/*
class CSchnorrKey {
public:

    CSchnorrKey() {}
    ~CSchnorrKey() {}

    void collect_make_newkeys(int num) {
        assert(num > 0 || num < 80);
        keys.clear();
        keys.reserve(num);
        for(int i=0; i < num; ++i) {
            CFirmKey key;
            key.MakeNewKey(true);
            keys.emplace_back(key);
        }
    }

    bool collect_pubkey(CPubKey &agg_pubkey) const {
        assert(0 < keys.size());
        std::vector<CPubKey> pubkeys;
        for(const auto &key: keys) {
            CPubKey pubkey = key.GetPubKey();
            pubkeys.emplace_back(pubkey);
        }

        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        BN_CTX *ctx = BN_CTX_new();
        if(!group || !ctx) {
            EC_GROUP_free(group);
            BN_CTX_free(ctx);
            return false;
        }

        bool fret = schnorr_collect::aggregate_public_keys(pubkeys, agg_pubkey);
        EC_GROUP_free(group);
        BN_CTX_free(ctx);
        return fret;
    }

    const std::vector<CFirmKey> &get_keys() const {
        return keys;
    }

private:
    std::vector<CFirmKey> keys;
};
*/

/*
std::shared_ptr<CSchnorrKey> Create_collect_75_keys() {
    std::shared_ptr<CSchnorrKey> schnorr_keys(new (std::nothrow) CSchnorrKey);
    schnorr_keys->collect_make_newkeys(75);
    return schnorr_keys;
}
*/

// Checker
// 3, [OK checked] Libsecp256k1 schnorr signature sign and verify: try pub_y with both odd and even values
bool Libsecp256k1_schnorr_sign_and_verify_pub_y_with_both_odd_and_even() {
    const int check_num = 30;

    bool fret = false;
    int checking = 0;
    do {
        //std::shared_ptr<CFirmKey> secpkey = (checking % 2 == 0) ? Create_pub_y_odd_key(): Create_pub_y_even_key();
        std::shared_ptr<CFirmKey> secpkey = Create_pub_y_key();
        if(!secpkey.get())
            break;
        CSecret secret = secpkey->GetSecret();
        secp256k1_schnorrsig sig;
        uint256 hash = Create_random_hash();

        // sign
        if(XOnlyKey::secp256k1_schnorrsig_sign(NULL, &sig, nullptr, hash.begin(), secret.data(), schnorr_nonce::secp256k1_nonce_and_random_function_schnorr, nullptr) != 1)
            break;

        CPubKey pubkey = secpkey->GetPubKey();
        pubkey.Compress();
        secp256k1_xonly_pubkey x_only_pubkey;
        ::memset(x_only_pubkey.data, 0x00, 64);
        ::memcpy(x_only_pubkey.data, pubkey.data() + 1, 32);

        // valid verify
        if(XOnlyPubKey::secp256k1_schnorrsig_verify(&sig.data[0], hash.begin(), &x_only_pubkey))
            debugcs::instance() << __func__ << " ok Libsecp256k1 sign, verify valid" << debugcs::endl();
        else {
            debugcs::instance() << __func__ << " failure Libsecp256k1 sign, verify invalid" << debugcs::endl();
            break;
        }

        // invalid verify 1
        uint256 invalid_hash = hash;
        invalid_hash.begin()[2] = 0xFF;
        invalid_hash.begin()[3] = 0x55;
        if(XOnlyPubKey::secp256k1_schnorrsig_verify(&sig.data[0], invalid_hash.begin(), &x_only_pubkey)) {
            debugcs::instance() << __func__ << " failure Libsecp256k1 sign, verify1 invalid" << debugcs::endl();
            break;
        } else
            debugcs::instance() << __func__ << " ok Libsecp256k1 sign, verify1 invalid" << debugcs::endl();

        // invalid verify 2
        x_only_pubkey.data[0] += 0x7F;
        if(XOnlyPubKey::secp256k1_schnorrsig_verify(&sig.data[0], hash.begin(), &x_only_pubkey)) {
            debugcs::instance() << __func__ << " failure Libsecp256k1 sign, verify2 invalid" << debugcs::endl();
            break;
        } else
            debugcs::instance() << __func__ << " ok Libsecp256k1 sign, verify2 invalid" << debugcs::endl();

        ++checking;
    } while(checking < check_num);
    if(checking == check_num)
        fret = true;

    return fret;
}

// [Check OK]
void Check_agg_ecdsa() {
    for(int i=1; i < 100; ++i) {
        unsigned char num1[32];
        latest_crypto::random::GetStrongRandBytes(num1, 32);
        num1[31] = 0x00; // prevent overflow
        unsigned char num2[32];
        latest_crypto::random::GetStrongRandBytes(num2, 32);
        num2[31] = 0x00; // prevent overflow

        uint256 k1;
        ::memcpy(k1.begin(), num1, 32);
        uint256 k2;
        ::memcpy(k2.begin(), num2, 32);
        uint256 k3 = k1 + k2;
        debugcs::instance() << __func__ << " k1: " << k1.ToString() << debugcs::endl();
        debugcs::instance() << __func__ << " k2: " << k2.ToString() << debugcs::endl();
        debugcs::instance() << __func__ << " k3: " << k3.ToString() << debugcs::endl();
        CSecret secret1;
        secret1.resize(32);
        CSecret secret2;
        secret2.resize(32);
        CSecret secret3;
        secret3.resize(32);
        ::memcpy(&secret1.front(), k1.begin(), 32);
        ::memcpy(&secret2.front(), k2.begin(), 32);
        ::memcpy(&secret3.front(), k3.begin(), 32);

        CFirmKey key1;
        key1.SetSecret(secret1);
        CFirmKey key2;
        key2.SetSecret(secret2);
        CFirmKey key3;
        key3.SetSecret(secret3);

        CPubKey pub1 = key1.GetPubKey();
        pub1.Compress();
        CPubKey pub2 = key2.GetPubKey();
        pub2.Compress();
        CPubKey pub3 = key3.GetPubKey();
        pub3.Compress();
        print_bytes("pub1", pub1.data(), 33);
        print_bytes("pub2", pub2.data(), 33);
        print_bytes("pub3", pub3.data(), 33);

        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        BN_CTX *ctx = BN_CTX_new();
        EC_POINT *a = EC_POINT_new(group);
        EC_POINT *b = EC_POINT_new(group);
        EC_POINT_oct2point(group, a, pub1.data(), 33, ctx);
        EC_POINT_oct2point(group, b, pub2.data(), 33, ctx);
        EC_POINT *r = EC_POINT_new(group);
        EC_POINT_add(group, r, a, b, ctx);
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();
        EC_POINT_get_affine_coordinates_GFp(group, r, x, y, ctx);
        print_bignum("op pub1+pub2", x);
        unsigned char agg_buf[65];
        agg_buf[0] = 0x04;
        schnorr_openssl::BN_bn2bin_padded(x, &agg_buf[1], 32);
        schnorr_openssl::BN_bn2bin_padded(y, &agg_buf[33], 32);
        CPubKey pub12;
        pub12.Set(key_vector(BEGIN(agg_buf), END(agg_buf)));
        EC_POINT_free(a);
        EC_POINT_free(b);
        EC_POINT_free(r);
        BN_free(x);
        BN_free(y);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);

        CPubKey::ecmult::secp256k1_ge se_a;
        CPubKey::ecmult::secp256k1_ge se_b;
        CPubKey::ecmult::secp256k1_fe fe_x, fe_y;
        pub1.Decompress();
        CPubKey::ecmult::secp256k1_fe_set_b32(&fe_x, pub1.data() + 1);
        CPubKey::ecmult::secp256k1_fe_set_b32(&fe_y, pub1.data() + 33);
        CPubKey::ecmult::secp256k1_ge_set_xy(&se_a, &fe_x, &fe_y);
        pub2.Decompress();
        CPubKey::ecmult::secp256k1_fe_set_b32(&fe_x, pub2.data() + 1);
        CPubKey::ecmult::secp256k1_fe_set_b32(&fe_y, pub2.data() + 33);
        CPubKey::ecmult::secp256k1_ge_set_xy(&se_b, &fe_x, &fe_y);
        CPubKey::ecmult::secp256k1_gej sej_a;
        CPubKey::ecmult::secp256k1_gej_set_ge(&sej_a, &se_a);
        CPubKey::ecmult::secp256k1_gej sej_ab;
        CPubKey::ecmult::secp256k1_gej_add_ge_var(&sej_ab, &sej_a, &se_b, NULL);
        CPubKey::ecmult::secp256k1_ge se_ab;
        CPubKey::ecmult::secp256k1_ge_set_gej(&se_ab, &sej_ab);
        print_secp256k1_fe("se pub1+pub2", &se_ab.x);

        uint256 hash = Create_random_hash();
        key_vector vchsig1, vchsig2, vchsig3;
        key1.Sign(hash, vchsig1);
        key2.Sign(hash, vchsig2);
        key3.Sign(hash, vchsig3);

        // Aggregating ECDSA results in an invalid verification, causing the following assert to fail.
        // We confirmed that ECDSA cannot be aggregated due to its non-linear nature.
        assert(pub12.Verify_BIP66(hash, vchsig3));
    }
}

// Checker
// 4, [OK checked] Libsecp256k1 schnorr signature sign and verify and aggregation: try pub_y with both odd and even values
bool Libsecp256k1_schnorr_sign_and_verify_pub_y_with_both_odd_and_even_and_aggregation() {
    const int schnorr_agg_num = 100;
    const int check_num = 50;

    bool fret = false;
    int checking = 0;
    do {
        uint256 hash = Create_random_hash();
        std::vector<CSecret> secrets;
        secrets.reserve(schnorr_agg_num);
        std::vector<CPubKey> pubkeys;
        pubkeys.reserve(schnorr_agg_num);
        XOnlyKeys xonlykeys;
        XOnlyPubKeys xonlypubs;
        for(int i=0; i < schnorr_agg_num; ++i) {
            std::shared_ptr<CFirmKey> secpkey = Create_pub_y_key();
            if(!secpkey.get())
                return false;
            secrets.emplace_back(secpkey->GetSecret());
            xonlykeys.push(secpkey->GetSecret()); // move
            pubkeys.emplace_back(secpkey->GetPubKey());
            xonlypubs.push(secpkey->GetPubKey()); //move
        }

        // aggregate sign
        CSecret agg_secret;
        secp256k1_xonly_pubkey x_only_agg_pubkey;
        Span<const CSecret> sp_secrets(secrets);
        if(XOnlyKeys::secp256k1_schnorrsig_aggregation(sp_secrets, &agg_secret) != 1) {
            debugcs::instance() << "Failure Libsecp256k1 aggregate sign" << debugcs::endl();
            break;
        }
        Span<const CPubKey> sp_pubkeys(pubkeys);
        if(XOnlyPubKeys::secp256k1_schnorrsig_aggregation(sp_pubkeys, &x_only_agg_pubkey) != 1) {
            debugcs::instance() << "Failure Libsecp256k1 aggregate sign" << debugcs::endl();
            break;
        }
        secp256k1_schnorrsig sig;
        std::vector<unsigned char> sigbytes;
        if(!xonlykeys.SignSchnorr(hash, sigbytes))
            break;
        if(XOnlyKey::secp256k1_schnorrsig_sign(NULL, &sig, nullptr, hash.begin(), agg_secret.data(), schnorr_nonce::secp256k1_nonce_and_random_function_schnorr, nullptr) != 1)
            break;

        // valid agg verify
        if(xonlypubs.VerifySchnorr(hash, Span<const unsigned char>(sigbytes)))
            debugcs::instance() << "xonly OK Libsecp256k1 agg sign, verify valid" << debugcs::endl();
        else {
            debugcs::instance() << "xonly Failure Libsecp256k1 agg sign, verify invalid" << debugcs::endl();
            break;
        }
        if(XOnlyPubKey::secp256k1_schnorrsig_verify(&sig.data[0], hash.begin(), &x_only_agg_pubkey) == 1)
            debugcs::instance() << "OK Libsecp256k1 agg sign, verify valid" << debugcs::endl();
        else {
            debugcs::instance() << "Failure Libsecp256k1 agg sign, verify invalid" << debugcs::endl();
            break;
        }

        // invalid agg verify
        uint256 hash2 = hash;
        *hash2.begin() = 0x7E;
        *(hash2.begin() + 1) = 0x7E;
        if(!xonlypubs.VerifySchnorr(hash2, Span<const unsigned char>(sigbytes)))
            debugcs::instance() << "xonly OK Libsecp256k1 agg sign, verify invalid" << debugcs::endl();
        else {
            debugcs::instance() << "xonly Failure Libsecp256k1 agg sign, verify valid" << debugcs::endl();
            break;
        }
        if(XOnlyPubKey::secp256k1_schnorrsig_verify(&sig.data[0], hash2.begin(), &x_only_agg_pubkey) != 1)
            debugcs::instance() << "OK Libsecp256k1 agg sign, verify invalid" << debugcs::endl();
        else {
            debugcs::instance() << "Failure Libsecp256k1 agg sign, verify valid" << debugcs::endl();
            break;
        }

        ++checking;
    } while(checking < check_num);
    if(checking == check_num)
        fret = true;

    return fret;
}

// Checker
// 5, for schnorr keys
bool add_for_schnorr_hd_keys(unsigned int nSize) {
    if(nSize == 0 || 1024 <= nSize)
        return false;
    CWalletDB walletdb(entry::pwalletMain->strWalletFile, entry::pwalletMain->strWalletLevelDB, entry::pwalletMain->strWalletSqlFile);
    LOCK(entry::pwalletMain->cs_wallet);

    std::vector<CExtKey> nextkey;
    nextkey.resize(nSize);
    for(int i = 0; i < nSize; ++i) {
        if(!hd_wallet::get().get_nextkey(nextkey[i], *hd_wallet::get().pkeyseed))
            return false;
    }

    // CFirmKey
    for(int i = 0; i < nSize; ++i) {
        if(!nextkey[i].privkey_.IsValid())
            return false;

        CPubKey pubkey = nextkey[i].privkey_.GetPubKey();
        if(!pubkey.IsFullyValid_BIP66())
            return false;
        if(!entry::pwalletMain->AddKey(nextkey[i].privkey_))
            return false;
    }

    // CPubKey
    const size_t size = hd_wallet::get().reserved_pubkey.size() + nSize;
    if(hd_wallet::get()._child_offset == size) {
        hd_wallet::get().reserved_pubkey.reserve(size);
        for(int i = 0; i < nSize; ++i) {
            hd_wallet::get().reserved_pubkey.emplace_back(nextkey[i].privkey_.GetPubKey());
        }
        if(!walletdb.WriteReservedHDPubkeys(hd_wallet::get().reserved_pubkey))
            return false;

        debugcs::instance() << __func__ << " _child_offset: " << hd_wallet::get()._child_offset << debugcs::endl();
        if(!walletdb.WriteChildHDSeed(hd_wallet::get().pkeyseed->privkey_.GetPubKey(), size))
            return false;
    } else
        return false;

    return true;
}

bool cmp_for_schnorr_pubkeys() {
    if(!hd_wallet::get().enable || !hd_wallet::get().pkeyseed)
        return false;

    CExtKey extkeyseed = *hd_wallet::get().pkeyseed;
    CExtSecret buf;
    buf.resize(CExtKey::BIP32_EXTKEY_SIZE);
    if(!extkeyseed.Encode(&buf.front())) {
        assert(!"failure A cmp_for_schnorr_pubkeys");
        return false;
    }

    CFirmKey key;
    key.SetSecret(CSecret(buf.data() + 42, buf.data() + buf.size()));
    if(!key.IsValid()) {
        assert(!"failure B cmp_for_schnorr_pubkeys");
        return false;
    }

    CPubKey pubkey = key.GetPubKey();
    pubkey.Compress();
    unsigned char buf2[CExtPubKey::BIP32_EXTKEY_SIZE];
    ::memcpy(buf2, buf.data(), 41);
    ::memcpy(buf2 + 41, pubkey.data(), 33);

    CExtPubKey extpubseed;
    if(!extpubseed.Decode(buf2)) {
        assert(!"failure C cmp_for_schnorr_pubkeys");
        return false;
    }

    for(unsigned int i=0; i < hd_wallet::get().reserved_pubkey.size(); ++i) {
        CExtPubKey extpub;
        if(!extpubseed.Derive(extpub, i)) {
            assert(!"failure D cmp_for_schnorr_pubkeys");
            return false;
        }
        print_bytes("extpub", extpub.GetPubKey().data(), 33);
        print_bytes("pubkey", hd_wallet::get().reserved_pubkey[i].GetPubVch().data(), 33);
        assert(extpub.GetPubKey() == hd_wallet::get().reserved_pubkey[i]);
    }

    return true;
}

bool cmp_for_schnorr_pubkeys2() {
    if(entry::pwalletMain->IsLocked())
        return false;
    if(!hd_wallet::get().enable || !hd_wallet::get().pkeyseed)
        return false;

    CExtKey extkeyseed = *hd_wallet::get().pkeyseed;
    CExtPubKey extpubseed = extkeyseed.Neuter();
    for(unsigned int i=0; i < hd_wallet::get().reserved_pubkey.size(); ++i) {
        CExtPubKey extpub;
        if(!extpubseed.Derive(extpub, i)) {
            assert(!"failure D cmp_for_schnorr_pubkeys");
            return false;
        }
        print_bytes("extpub", extpub.GetPubKey().data(), 33);
        print_bytes("pubkey", hd_wallet::get().reserved_pubkey[i].GetPubVch().data(), 33);
        assert(extpub.GetPubKey() == hd_wallet::get().reserved_pubkey[i]);
    }

    return true;
}

// Derive: 0 - 499, ECDSA
//         after 500, schnorr agg signature
bool agg_schnorr_from_wallet_to_keys() {
    //! try: new schnorr agg key
    XOnlyAggWalletInfo xonly_wallet_info;
    if(!xonly_wallet_info.LoadFromWalletInfo())
        return false;

    std::vector<unsigned char> dummy = {0x56, 0x77, 0x89, 0x6f, 0x75, 0xFF, 0xFF, 0xEE};
    //const auto d = std::make_tuple(14601, 5780, dummy);
    //uint160 agg_hash;
    //if(!xonly_wallet_info.push_computehash_commit(d, agg_hash))
    //    return false;
    uint160 agg_hash;
    if(!xonly_wallet_info.push_computehash_commit(15387, 35000, agg_hash))
        return false;

    XOnlyPubKeys xonly_pubkeys;
    XOnlyKeys xonly_keys;
    if(!xonly_wallet_info.GetXOnlyKeys(agg_hash, xonly_pubkeys, xonly_keys))
        return false;

    XOnlyPubKeys xonly_pubkeys2;
    if(!xonly_wallet_info.GetXOnlyPubKeys(agg_hash, xonly_pubkeys2))
        return false;
    assert(xonly_pubkeys == xonly_pubkeys2);

    XOnlyPubKey xonly_pubkey = xonly_pubkeys.GetXOnlyPubKey();
    print_bytes("agg_xonly_pubkey", xonly_pubkey.data(), 32);
    print_bytes("dummy", dummy.data(), 5);
    print_bytes("schnorr keyid", agg_hash.begin(), 20);

    size_t agg_size = xonly_wallet_info.size();
    debugcs::instance() << "xonly_wallet_info nums: " << agg_size << debugcs::endl();
    debugcs::instance() << "xonly_wallet_info GetSerializeSize: " << xonly_wallet_info.GetSerializeSize() << debugcs::endl();
    debugcs::instance() << "xonly_pubkeys: " << xonly_pubkeys.size() << debugcs::endl();
    debugcs::instance() << "xonly_keys: " << xonly_keys.size() << debugcs::endl();
    for(const auto &d: xonly_wallet_info.Derive_info) {
        print_bytes("xonly_reserved", std::get<2>(d.second).data(), std::get<2>(d.second).size());
        print_bytes("hash", d.first.begin(), d.first.size());
    }

    uint256 hash = Create_random_hash();
    std::vector<unsigned char> sigbytes;
    if(!xonly_keys.SignSchnorr(hash, sigbytes))
        return false;
    if(!xonly_pubkeys.VerifySchnorr(hash, Span<const unsigned char>(sigbytes)))
        return false;

    uint256 hash2 = Create_random_hash();
    std::vector<unsigned char> sigbytes2;
    if(!xonly_keys.SignSchnorr(hash2, sigbytes2))
        return false;
    if(xonly_pubkeys.VerifySchnorr(hash, Span<const unsigned char>(sigbytes2))) // invalid check
        return false;

    return true;
}



constexpr static size_t HASH160_DIGEST_LENGTH = 20;
struct secp256k1_hash160 {
    unsigned char data[HASH160_DIGEST_LENGTH];
};

// Function to compute Hash160
void secp256k1_compute_hash160(const unsigned char *data, size_t len, unsigned char *hash) {
    latest_crypto::CHash160().Write(data, len).Finalize(hash);
}

// Function to build the Merkle tree and compute the Merkle root
int secp256k1_get_merkle_root(secp256k1_hash160 *r, unsigned char **hashes, size_t num_hashes) {
    if (!hashes || num_hashes == 0)
        return 0;

    // Copy the current level's hashes
    unsigned char **current_level = (unsigned char **)::malloc(num_hashes * sizeof(unsigned char *));
    if(!current_level)
        return 0;
    for (size_t i = 0; i < num_hashes; i++) {
        current_level[i] = (unsigned char *)::malloc(HASH160_DIGEST_LENGTH);
        if(!current_level[i]) {
            for (size_t k = 0; k < i; k++)
                ::free(current_level[k]);
            ::free(current_level);
            return 0;
        }
        ::memcpy(current_level[i], hashes[i], HASH160_DIGEST_LENGTH);
    }

    // Build the Merkle tree
    while (num_hashes > 1) {
        size_t new_num_hashes = (num_hashes + 1) / 2;
        unsigned char **next_level = (unsigned char **)::malloc(new_num_hashes * sizeof(unsigned char *));
        if(!next_level) {
            for (size_t k = 0; k < num_hashes; k++)
                ::free(current_level[k]);
            ::free(current_level);
            return 0;
        }

        for (size_t i = 0; i < new_num_hashes; i++) {
            next_level[i] = (unsigned char *)::malloc(HASH160_DIGEST_LENGTH);
            if(!next_level[i]) {
                for (size_t k = 0; k < i; k++)
                    ::free(next_level[k]);
                for (size_t k = 0; k < num_hashes; k++)
                    ::free(current_level[k]);
                ::free(current_level);
                return 0;
            }
            if (2 * i + 1 < num_hashes) {
                // Combine two child hashes and compute the parent hash
                unsigned char combined[2 * HASH160_DIGEST_LENGTH];
                ::memcpy(combined, current_level[2 * i], HASH160_DIGEST_LENGTH);
                ::memcpy(combined + HASH160_DIGEST_LENGTH, current_level[2 * i + 1], HASH160_DIGEST_LENGTH);
                secp256k1_compute_hash160(combined, 2 * HASH160_DIGEST_LENGTH, next_level[i]);
            } else {
                // Odd number of hashes, so copy the last hash
                ::memcpy(next_level[i], current_level[2 * i], HASH160_DIGEST_LENGTH);
            }
        }

        // Free the current level
        for (size_t i = 0; i < num_hashes; i++) {
            ::free(current_level[i]);
        }
        ::free(current_level);

        // Move to the next level
        current_level = next_level;
        num_hashes = new_num_hashes;
    }

    // The root hash is the only hash in the final level
    unsigned char *merkle_root = r->data;
    ::memcpy(merkle_root, current_level[0], HASH160_DIGEST_LENGTH);

    // Free the last level
    ::free(current_level[0]);
    ::free(current_level);

    return 1;
}

#if __cplusplus <= 201703L
uint32_t count_utf8_chars(const std::string &utf8_str) {
    std::wstring_convert<std::codecvt_utf8<char32_t>, char32_t> conv;
    std::u32string u32_str = conv.from_bytes(utf8_str);
    return u32_str.length();
}

std::string reverse_utf8_string(const std::string &utf8_str) {
    std::wstring_convert<std::codecvt_utf8<char32_t>, char32_t> conv;
    std::u32string u32_str = conv.from_bytes(utf8_str);
    std::reverse(u32_str.begin(), u32_str.end());
    return conv.to_bytes(u32_str);
}

std::wstring locale_to_wide(const std::string &str, const char *locale) {
    std::locale loc(std::locale(), new std::codecvt_byname<wchar_t, char, std::mbstate_t>(locale));
    std::vector<wchar_t> wstr(str.size());
    const char* from_next;
    wchar_t* to_next;
    std::mbstate_t state = std::mbstate_t();
    std::use_facet<std::codecvt<wchar_t, char, std::mbstate_t>>(loc).in(state,
        str.data(), str.data() + str.size(), from_next,
        wstr.data(), wstr.data() + wstr.size(), to_next);
    return std::wstring(wstr.data(), to_next);
}

std::string wide_to_utf8(const std::wstring &wide_str) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
    return conv.to_bytes(wide_str);
}
#else
    static_assert(__cplusplus > 201703L, "Using alternative method for C++20 and beyond");
#endif

bool agg_schnorr_ecdh_key_exchange() {
    std::string message = "I have heard that in a certain country, capitalism has partially collapsed, and people are forced to bear debts with an annual interest rate of up to 30 percent. Immediate improvement is necessary.";

    XOnlyAggWalletInfo xonly_wallet_info;
    if(!xonly_wallet_info.LoadFromWalletInfo())
        return false;

    uint160 bob_hash;
    if(!xonly_wallet_info.MakeNewKey(bob_hash))
        return false;
    XOnlyPubKeys xonly_bob_pubkeys;
    XOnlyKeys xonly_bob_keys;
    if(!xonly_wallet_info.GetXOnlyKeys(bob_hash, xonly_bob_pubkeys, xonly_bob_keys))
        return false;
    XOnlyPubKey bob_agg_pubkey = xonly_bob_pubkeys.GetXOnlyPubKey();
    CSecret bob_agg_secret;
    if(!xonly_bob_keys.GetSecret(bob_agg_secret))
        return false;

    uint160 alice_hash;
    if(!xonly_wallet_info.MakeNewKey(alice_hash))
        return false;
    XOnlyPubKeys xonly_alice_pubkeys;
    XOnlyKeys xonly_alice_keys;
    if(!xonly_wallet_info.GetXOnlyKeys(alice_hash, xonly_alice_pubkeys, xonly_alice_keys))
        return false;
    XOnlyPubKey alice_agg_pubkey = xonly_alice_pubkeys.GetXOnlyPubKey();
    CSecret alice_agg_secret;
    if(!xonly_alice_keys.GetSecret(alice_agg_secret))
        return false;

    /*
    uint160 carol_hash;
    if(!xonly_wallet_info.MakeNewKey(carol_hash))
        return false;
    XOnlyPubKeys xonly_carol_pubkeys;
    XOnlyKeys xonly_carol_keys;
    if(!xonly_wallet_info.GetXOnlyKeys(carol_hash, xonly_carol_pubkeys, xonly_carol_keys))
        return false;
    */

    secp256k1_symmetrickey symmetrickey1, symmetrickey2;
    // bob (bob secret * alice pubkey)
    SymmetricKey::secp256k1_schnorrsig_symmetrickey(NULL, bob_agg_secret.data(), alice_agg_pubkey.data(), &symmetrickey1);
    // alice (alice secret * bob pubkey)
    SymmetricKey::secp256k1_schnorrsig_symmetrickey(NULL, alice_agg_secret.data(), bob_agg_pubkey.data(), &symmetrickey2);

    SymmetricKey SKey1(symmetrickey1), SKey2(symmetrickey2);
    print_bytes("  bob symmetrickey", SKey1.data(), SKey1.size());
    print_bytes("alice symmetrickey", SKey2.data(), SKey2.size());
    assert(SKey1 == SKey2);

    SymmetricKey SKey3(bob_agg_secret, alice_agg_pubkey);
    assert(SKey3.is_valid());
    assert(SKey1 == SKey3);

    cleanse::memory_cleanse(symmetrickey1.data, sizeof(symmetrickey1.data));
    cleanse::memory_cleanse(symmetrickey2.data, sizeof(symmetrickey2.data));

    std::pair<CSecureBytes, bool> cipher;
    latest_crypto::CAES256CBCPKCS7(SKey1.data(), SKey1.size()).Encrypt((const unsigned char *)message.data(), message.size()).Finalize(cipher);
    assert(cipher.second);
    print_bytes("AES256 Encrypt", cipher.first.data(), cipher.first.size());

    std::pair<CSecureBytes, bool> plain;
    latest_crypto::CAES256CBCPKCS7(SKey1.data(), SKey1.size()).Decrypt((const unsigned char *)cipher.first.data(), cipher.first.size()).Finalize(plain);
    print_str("AES256 Decrypt", std::string(plain.first.begin(), plain.first.end()));
    assert(plain.second);
    assert(message.size() == plain.first.size());
    assert(message == std::string(plain.first.begin(), plain.first.end()));

    std::pair<CSecureBytes, bool> cipher2;
    latest_crypto::CAES256CBCPKCS7(SKey1.data(), SKey1.size()).Encrypt((const unsigned char *)message.data(), message.size()).Finalize(cipher2);
    assert(cipher2.second);
    print_bytes("AES256 Encrypt", cipher2.first.data(), cipher2.first.size());
    assert(cipher.first != cipher2.first); // CBC check
    //assert(cipher.first == cipher2.first); // non-CBC check

    std::pair<CSecureBytes, bool> cipher3;
    latest_crypto::CChaCha20(SKey1.data(), SKey1.size()).Encrypt((const unsigned char *)message.data(), message.size()).Finalize(cipher3);
    assert(cipher3.second);
    print_bytes("CChaCha20 Encrypt", cipher3.first.data(), cipher3.first.size());
    std::pair<CSecureBytes, bool> plain3;
    latest_crypto::CChaCha20(SKey1.data(), SKey1.size()).Decrypt(cipher3.first.data(), cipher3.first.size()).Finalize(plain3);
    assert(plain3.second);
    print_str("CChaCha20 Decrypt", std::string(plain3.first.begin(), plain3.first.end()));
    assert(message == std::string(plain3.first.begin(), plain3.first.end()));

    // invalid check
    SKey1.front() += 0x01;
    *(&SKey1.front() + 1) += 0x01;
    std::pair<CSecureBytes, bool> plain2;
    latest_crypto::CAES256CBCPKCS7(SKey1.data(), SKey1.size()).Decrypt((const unsigned char *)cipher2.first.data(), cipher2.first.size()).Finalize(plain2);
    print_str("AES256 Decrypt", std::string(plain2.first.begin(), plain2.first.end()));
    assert(plain2.second == false);
    std::pair<CSecureBytes, bool> plain4;
    latest_crypto::CAES256CBCPKCS7(SKey1.data(), SKey1.size()).Decrypt((const unsigned char *)cipher3.first.data(), cipher3.first.size()).Finalize(plain4);
    print_str("CChaCha20 Decrypt", std::string(plain4.first.begin(), plain4.first.end()));
    assert(plain4.second == false);

    unsigned char **hashes;
    hashes = (unsigned char **)::malloc(sizeof(unsigned char*) * 10);
    std::vector<uint160> vhashes;
    for(int i=0; i < 10; ++i) {
        unsigned char buf[32] = {0};
        buf[0] = (unsigned char)i;
        hashes[i] = (unsigned char *)::malloc(HASH160_DIGEST_LENGTH);
        secp256k1_compute_hash160(buf, 32, hashes[i]);
        uint160 hash160;
        secp256k1_compute_hash160(buf, 32, hash160.begin());
        vhashes.emplace_back(hash160);
    }

    secp256k1_hash160 merkle_top;
    //uint160 merkle_top2;
    secp256k1_get_merkle_root(&merkle_top, hashes, 10);
    print_bytes("merkle root1", merkle_top.data, sizeof(merkle_top.data));
    for(int i=0; i < 10; ++i)
        ::free(hashes[i]);
    ::free(hashes);
    //hash160_get_merkle_root(merkle_top2, vhashes);
    //print_bytes("merkle root2", merkle_top2.begin(), sizeof(merkle_top2.size()));

    // checking ChaCha20
    const std::string cha20_message = "Checking the implementation of ChaCha20 in cryptocurrency.";
    uint256 chacha20_key;
    latest_crypto::random::GetStrongRandBytes(chacha20_key.begin(), 32);
    latest_crypto::ChaCha20 cha20;
    cha20.SetKey(chacha20_key.begin(), 32);
    cha20.SetIV(5);
    cha20.Seek(0);
    std::vector<unsigned char> cha20_checking;
    cha20_checking.resize(cha20_message.size());
    cha20.Output(&cha20_checking.front(), cha20_checking.size());
    cha20.Output(&cha20_checking.front(), cha20_checking.size());
    print_str("chacha20 str", std::string(cha20_checking.begin(), cha20_checking.end()));

    latest_crypto::CChaCha20 ccha20(chacha20_key.begin(), 32);
    ccha20.Encrypt((const unsigned char *)cha20_message.data(), cha20_message.size());
    std::pair<CSecureBytes, bool> ccha20_checking;
    ccha20.Finalize(ccha20_checking);
    assert(ccha20_checking.second);
    ccha20.Decrypt(ccha20_checking.first.data(), ccha20_checking.first.size());
    assert(ccha20_checking.second);
    ccha20.Finalize(ccha20_checking);
    print_str("cchacha20 str", std::string(ccha20_checking.first.begin(), ccha20_checking.first.end()));

    // CAES256CBCPKCS7 [Check OK]
    for(int i=1; i <= 100; ++i) {
        size_t size = ::rand() % 8000;
        if(size == 0) size = 1;
        print_num("AES256 checking size", size);
        CSecureBytes data;
        data.resize(size);
        ::RAND_bytes(&data.front(), size);
        uint256 key;
        latest_crypto::random::GetStrongRandBytes(key.begin(), sizeof(uint256));
        std::pair<CSecureBytes, bool> cipher;
        latest_crypto::CAES256CBCPKCS7(key.begin(), key.size()).Encrypt(data.data(), data.size()).Finalize(cipher);
        assert(cipher.second);
        print_num("cipher size", cipher.first.size());
        std::pair<CSecureBytes, bool> plain;
        latest_crypto::CAES256CBCPKCS7(key.begin(), key.size()).Decrypt(cipher.first.data(), cipher.first.size()).Finalize(plain);
        assert(plain.second);
        print_bytes("data ", data.data(), data.size());
        print_bytes("plain", plain.first.data(), plain.first.size());
        assert(data == plain.first);

        std::pair<CSecureBytes, bool> plain2;
        *(key.begin() + 1) += 0x05;
        latest_crypto::CAES256CBCPKCS7(key.begin(), key.size()).Decrypt(cipher.first.data(), cipher.first.size()).Finalize(plain2);
        assert(!plain2.second);
        print_bytes("plain2", plain2.first.data(), plain2.first.size());
    }

    // CChaCha20 [Check OK]
    for(int i=1; i <= 100; ++i) {
        size_t size = ::rand() % 8000;
        if(size == 0) size = 1;
        print_num("ChaCha20 checking size", size);
        CSecureBytes data;
        data.resize(size);
        ::RAND_bytes(&data.front(), size);
        uint256 key;
        latest_crypto::random::GetStrongRandBytes(key.begin(), sizeof(uint256));
        std::pair<CSecureBytes, bool> cipher;
        latest_crypto::CChaCha20(key.begin(), key.size()).Encrypt(data.data(), data.size()).Finalize(cipher);
        assert(cipher.second);
        print_num("cipher size", cipher.first.size());
        std::pair<CSecureBytes, bool> plain;
        latest_crypto::CChaCha20(key.begin(), key.size()).Decrypt(cipher.first.data(), cipher.first.size()).Finalize(plain);
        assert(plain.second);
        print_bytes("data ", data.data(), data.size());
        print_bytes("plain", plain.first.data(), plain.first.size());
        assert(data == plain.first);

        std::pair<CSecureBytes, bool> plain2;
        *(key.begin() + 1) += 0x05;
        latest_crypto::CChaCha20(key.begin(), key.size()).Decrypt(cipher.first.data(), cipher.first.size()).Finalize(plain2);
        assert(!plain2.second);
        print_bytes("plain2", plain2.first.data(), plain2.first.size());
    }

    CAITransaction03 aitx;
    SecureString web3(std::string("This is a decentralized encrypted message. Let's ensure privacy with user-sovereign Web3!"));
    assert(!aitx.IsValid());
    for(int i=0; i < 100; ++i) {
        SecureString _web3 = web3 + std::to_string(i);
        aitx.PushTokenMessage(SKey1, _web3);
    }
    for(int i=0; i < aitx.SizeTokens(); ++i) {
        SecureString plain;
        CAIToken03 token = aitx[i];
        assert(token.GetTokenMessage(SKey1, plain));
        assert(plain == (web3 + SecureString::to_SecureString(i)));
        print_num("num", i);
        print_str("plain", plain);
    }
    assert(!aitx.IsValid());
    aitx.SetSchnorrAggregateKeyID(xonly_bob_pubkeys.GetXOnlyPubKey());
    assert(aitx.IsValid());
    std::pair<uint160, bool> merkle_root = aitx.GetMerkleRoot();
    assert(merkle_root.second);
    print_bytes("Merkle_root", merkle_root.first.begin(), merkle_root.first.size());

    // stream check
    CDataStream stream;
    stream << aitx;
    print_num("stream size", stream.size());
    CAITransaction03 aitx2;
    stream >> aitx2;
    int i2 = 0;
    for(const auto &token: aitx2) {
        SecureString plain;
        assert(token.GetTokenMessage(SKey1, plain));
        assert(plain == (web3 + SecureString::to_SecureString(i2)));
        print_num("num2", i2);
        print_str("plain2", plain);
        ++i2;
    }
    std::pair<qkey_vector, bool> qai_hash = aitx2.GetSchnorrHash();
    assert(qai_hash.second);
    print_bytes("SORA-QAI hash", qai_hash.first.data(), qai_hash.first.size());

    return true;
}

void th_func_test(std::shared_ptr<CDataStream> stream) {
   util::Sleep(2000);
   std::string str;
   *stream >> str;
   print_str("1st", str);
   *stream >> str;
   print_str("2nd", str);
   *stream >> str;
   print_str("3rd", str);
   util::Sleep(3000);
}

void wait_for_confirm_transaction(std::shared_ptr<CDataStream> stream) {
    if(!hd_wallet::get().enable)
        return;
    if(entry::pwalletMain->IsLocked())
        return;

    //! get the SORA-QAI cipher address qai_address ans account hash
    std::string qai_address;
    std::string acc_hash;
    double fee;
    try {
       (*stream) >> qai_address >> acc_hash >> fee;
    } catch (const std::exception &) {
        return;
    }

    print_str("confirm_transaction qai_address", qai_address);
    print_str("confirm_transaction acc_hash", acc_hash);

    {
        //! get the scriptPubKey
        CBitcoinAddress address(qai_address);
        CScript scriptPubKey;
        scriptPubKey.SetAddress(address);

        //! send to SORA-QAI cipher scriptPubKey in 0.5 coins
        CWalletTx wtx;
        wtx.strFromAccount = std::string("");
        double dAmount = fee;
        int64_t nAmount = util::roundint64(dAmount * util::COIN);
        std::string strError = entry::pwalletMain->SendMoney(scriptPubKey, nAmount, wtx);
        if (!strError.empty())
            return;

        const uint256 txid = wtx.GetHash();
        do {
            if(entry::pwalletMain->mapWallet.count(txid)) {
                const CWalletTx &new_wtx = entry::pwalletMain->mapWallet[txid];
                const int confirms = new_wtx.GetDepthInMainChain();
                if(confirms > 0)
                    break;
            }
            util::Sleep(300);
            if(args_bool::fShutdown)
                break;
        } while(true);
    }

    {
        //! get the reserved public key
        CPubKey reserved_pubkey = hd_wallet::get().reserved_pubkey[0];
        if(!reserved_pubkey.IsFullyValid_BIP66())
            return;

        //! get the scriptPubKey
        CBitcoinAddress address(reserved_pubkey.GetID());
        CScript scriptPubKey;
        scriptPubKey.SetAddress(address);

        //! send to reservedkey scriptPubKey in 0.5 coins
        CWalletTx wtx;
        wtx.strFromAccount = acc_hash;
        double dAmount = fee;
        int64_t nAmount = util::roundint64(dAmount * util::COIN);
        std::string strError = entry::pwalletMain->SendMoney(scriptPubKey, nAmount, wtx);
        if (!strError.empty())
            return;

        const uint256 txid = wtx.GetHash();
        do {
            if(entry::pwalletMain->mapWallet.count(txid)) {
                const CWalletTx &new_wtx = entry::pwalletMain->mapWallet[txid];
                const int confirms = new_wtx.GetDepthInMainChain();
                if(confirms > 0)
                    break;
            }
            util::Sleep(500);
            if(args_bool::fShutdown)
                break;
        } while(true);
    }

    print_str("confirm_transaction", std::string("OK"));
}

const std::string hrp_cipher_main = "cipher";
const std::string hrp_cipher_testnet = "ciphertest";
static std::string GetHrpCipher() {
    return args_bool::fTestNet ? hrp_cipher_testnet: hrp_cipher_main;
}

#include <rpc/bitcoinrpc.h>
bool check_cipher_transaction2() {
    uint160 rand_hash;
    unsigned char buf[32];
    latest_crypto::random::GetRandBytes(buf, sizeof(buf));
    latest_crypto::CHash160().Write(buf, sizeof(buf)).Finalize(rand_hash.begin());
    std::string acc_hash = "cipher_" + rand_hash.GetHex();

    json_spirit::Array obj;
    obj.push_back(acc_hash);
    json_spirit::Value qaiAddress;
    try {
        qaiAddress = CRPCTable::getnewschnorraddress(obj, false);
    } catch (json_spirit::Object &) {
        return false;
    } catch (std::exception &) {
        return false;
    }

    CThread thread;
    CDataStream stream;
    double fee = 0.2;
    stream << qaiAddress.get_str() << acc_hash << fee;
    CThread::THREAD_INFO info(&stream, wait_for_confirm_transaction);
    if(thread.BeginThread(info)) {
        thread.Detach();
        return true;
    } else
        return false;
}

bool check_cipher_transaction() {
    if(!hd_wallet::get().enable)
        return false;
    if(entry::pwalletMain->IsLocked())
        return false;

    CPubKey to_pubkey = hd_wallet::get().reserved_pubkey[0];
    if(!to_pubkey.IsFullyValid_BIP66())
        return false;

    CBitcoinAddress address(to_pubkey.GetID());
    //CBitcoinAddress address(std::string("21NnAzvt5ebKMCWWU6Et9YqVVikZEoLYUri"));
    CScript scriptPubKey;
    scriptPubKey.SetAddress(address);

    CWalletTx wtx;
    wtx.strFromAccount = std::string("reo2");

    double dAmount = 0.2;
    int64_t nAmount = util::roundint64(dAmount * util::COIN);

    CReserveKey keyChange(entry::pwalletMain);
    int index = 0;
    for(const auto &d: hd_wallet::get().reserved_pubkey) {
        if(d == keyChange.GetReservedKey())
            break;
        index++;
    }
    print_num("CReserveKey pos reserved_pubkey", index);

    std::string strError = entry::pwalletMain->SendMoney(scriptPubKey, nAmount, wtx);
    if (!strError.empty()) {
        print_str("check_cipher_transaction strError", strError);
        assert(!"Error: SendMoney");
        return false;
    }
    uint256 txid = wtx.GetHash();
    print_str("txid", txid.GetHex());

    CThread thread;
    for(int i=0; i < 10; ++i) {
        CDataStream stream;
        stream << std::string("dog") << std::string("cat") << std::string("coin");
        CThread::THREAD_INFO info(&stream, th_func_test);
        assert(thread.BeginThread(info));
    } // CDataStream stream object has been released.
    thread.WaitForMultipleThreads();

    return true;
}

bool agg_schnorr_from_makenewkey() {
    XOnlyAggWalletInfo xonly_wallet_info;
    if(!xonly_wallet_info.LoadFromWalletInfo())
        return false;

    uint160 agg_hash;
    if(!xonly_wallet_info.MakeNewKey(agg_hash))
        return false;

    XOnlyPubKeys xonly_pubkeys;
    XOnlyKeys xonly_keys;
    if(!xonly_wallet_info.GetXOnlyKeys(agg_hash, xonly_pubkeys, xonly_keys))
        return false;

    XOnlyPubKey xonly_pubkey = xonly_pubkeys.GetXOnlyPubKey();
    print_bytes("agg_xonly_pubkey", xonly_pubkey.data(), 32);
    print_bytes("schnorr keyid", agg_hash.begin(), 20);

    size_t agg_size = xonly_wallet_info.size();
    print_num("xonly_wallet_info nums", agg_size);
    print_num("xonly_wallet_info GetSerializeSize", xonly_wallet_info.GetSerializeSize());
    print_num("xonly_pubkeys", xonly_pubkeys.size());
    print_num("xonly_keys", xonly_keys.size());
    print_num("xonly_aggregated_size", xonly_wallet_info.aggregated_size);
    for(const auto &d: xonly_wallet_info.Derive_info) {
        print_num("xonly_begin", std::get<0>(d.second));
        print_num("xonly_agg_num", std::get<1>(d.second));
        print_bytes("xonly_reserved", std::get<2>(d.second).data(), std::get<2>(d.second).size());
        print_bytes("hash", d.first.begin(), d.first.size());
    }

    XOnlyPubKey xpubkey = xonly_pubkeys.GetXOnlyPubKey();
    print_num("XOnlyPubKey_size", xpubkey.size());
    print_bytes("CKeyID", xpubkey.GetID().begin(), 20);
    print_bytes("QAI_hash", xpubkey.GetSchnorrHash().data(), 33);

    std::vector<unsigned char> dummy_vch;
    dummy_vch.resize(32);
    ::memset(&dummy_vch.front(), 0xFF, 32);
    XOnlyPubKey xpubkey2 = XOnlyPubKey(Span<const unsigned char>(dummy_vch));
    print_num("XonlyPubKey2_size", xpubkey2.size());

    CPubKey::secp256k1_scalar tmp;
    print_num("secp256k1_scalar_size_check", sizeof(tmp));

    uint256 hash = Create_random_hash();
    std::vector<unsigned char> sigbytes;
    if(!xonly_keys.SignSchnorr(hash, sigbytes))
        return false;
    if(!xonly_pubkeys.VerifySchnorr(hash, Span<const unsigned char>(sigbytes)))
        return false;

    uint256 hash2 = Create_random_hash();
    std::vector<unsigned char> sigbytes2;
    if(!xonly_keys.SignSchnorr(hash2, sigbytes2))
        return false;
    if(xonly_pubkeys.VerifySchnorr(hash, Span<const unsigned char>(sigbytes2))) // invalid check
        return false;

    std::vector<unsigned char> sigbytes3 = sigbytes;
    sigbytes3[1] = 0xFF;
    sigbytes3[2] = 0xFF;
    sigbytes3[35] = 0xFF;
    if(xonly_pubkeys.VerifySchnorr(hash, Span<const unsigned char>(sigbytes3))) // invalid check
        return false;

    debugcs::instance() << "Schnorr aggregation signature Check OK" << debugcs::endl();

    XOnlyPubKeys xonly_pubkeys2;
    XOnlyKeys xonly_keys2;
    if(!xonly_wallet_info.GetXOnlyKeysStrictOrder(agg_hash, xonly_pubkeys2, xonly_keys2))
        return false;
    XOnlyPubKeys xonly_pubkeys3;
    if(!xonly_wallet_info.GetXOnlyPubKeysStrictOrder(agg_hash, xonly_pubkeys3))
        return false;
    assert(xonly_pubkeys2 == xonly_pubkeys3);
    assert(xonly_pubkeys != xonly_pubkeys2);

    return true;
}

// Checking the impact on the aggregation of Schnorr after key generation.
#include <rpc/bitcoinrpc.h>
bool agg_schnorr_from_makenewkey2() {
    debugcs::instance() << "_child1: " << hd_wallet::get()._child_offset << " _used_key1: " << hd_wallet::get()._usedkey_offset << debugcs::endl();

    /*
    {
        CWalletDB walletdb(entry::pwalletMain->strWalletFile, entry::pwalletMain->strWalletLevelDB, entry::pwalletMain->strWalletSqlFile);
        LOCK(entry::pwalletMain->cs_wallet);
        for(int64_t npool=1; npool < hd_wallet::get()._child_offset; ++npool) {
            CKeyPool keypool;
            print_num("pubkey index", npool);
            if(!walletdb.ReadPool(npool, keypool)) {
                print_str("pubkey invalid", std::string(""));
            } else {
                CPubKey pubkey = keypool.vchPubKey;
                print_bytes("pubkey", pubkey.GetPubVch().data(), pubkey.GetPubVch().size());
                print_str("BitcoinAddress", CBitcoinAddress(pubkey.GetID()).ToString());
            }
        }
    }
    */

    const unsigned int pool_add_size = hd_wallet::get()._child_offset - hd_wallet::get()._usedkey_offset;
    if(!entry::pwalletMain->AddKeyPool(pool_add_size))
        return false;
    debugcs::instance() << "_child2: " << hd_wallet::get()._child_offset << " _used_key2: " << hd_wallet::get()._usedkey_offset << debugcs::endl();

    std::map<std::string, int> check;
    for(int i=0; i < hd_wallet::get()._child_offset; ++i) {
        json_spirit::Array obj;
        obj.push_back(std::to_string(i));
        json_spirit::Value ret = CRPCTable::getnewaddress(obj, false);
        const auto finsert = check.emplace(std::make_pair(ret.get_str(), 0));
        print_str("new pubkey", ret.get_str());
        if(!finsert.second) {
            print_num("new address used index", i);
            assert(!"invalid new pubkey");
            return false;
        }
    }

    debugcs::instance() << "_child3: " << hd_wallet::get()._child_offset << " _used_key3: " << hd_wallet::get()._usedkey_offset << debugcs::endl();
    for(int i=0; i < hd_wallet::get()._child_offset; ++i) {
        print_num("pubkey index", i);
        const CPubKey &pubkey = hd_wallet::get().reserved_pubkey[i];
        std::string str = CBitcoinAddress(pubkey.GetID()).ToString();
        if(!check.count(str)) {
            assert(!"invalid pubkey");
            return false;
        }
    }

    if(hd_wallet::get()._child_offset == hd_wallet::get()._usedkey_offset) {
        if(!hd_wallet::get().add_keys())
            return false;
    }

    return true;
}

bool agg_schnorr_from_makenewkey3() {

    /*
    int index=0;
    for(const auto &d: hd_wallet::get().reserved_pubkey) {
        print_num("pubkey index", index++);
        print_bytes("pubkey", d.GetPubVch().data(), d.GetPubVch().size());
        print_str("BitcoinAddress", CBitcoinAddress(d.GetID()).ToString());
    }
    */

    /* [ok]
    std::map<std::string, int> check;
    for(int i=0; i < hd_wallet::get()._child_offset; ++i) {
        json_spirit::Array obj;
        obj.push_back(std::to_string(i));
        json_spirit::Value ret = CRPCTable::getnewaddress(obj, false);
        const auto finsert = check.emplace(std::make_pair(ret.get_str(), 0));
        if(!finsert.second) {
            return false;
        }
    }

    for(int i=0; i < hd_wallet::get()._child_offset; ++i) {
        const CPubKey &pubkey = hd_wallet::get().reserved_pubkey[i];
        std::string str = CBitcoinAddress(pubkey.GetID()).ToString();
        if(!check.count(str)) {
            return false;
        }
    }
    */

    print_num("_child", hd_wallet::get()._child_offset);
    print_num("_usedkey", hd_wallet::get()._usedkey_offset);
    print_num("reserved pubkeys", hd_wallet::get().reserved_pubkey.size());
    for(int i=0; i < hd_wallet::get()._child_offset; ++i) {
        json_spirit::Array obj;
        obj.push_back(std::to_string(i));
        json_spirit::Value ret = CRPCTable::getnewaddress(obj, false);
        print_str("pubkey", ret.get_str());
    }
    print_num("_child", hd_wallet::get()._child_offset);
    print_num("_usedkey", hd_wallet::get()._usedkey_offset);
    print_num("reserved pubkeys", hd_wallet::get().reserved_pubkey.size());

    return true;
}

// Checker
// 6, try schnorr from wallet keys
bool exists_keys_schnorr_agg_sign_verify() {
    for(int k=0; k < 1; ++k) {
        XOnlyPubKeys pubkeys;
        XOnlyKeys secrets;
        for(int i=0; i < 70; ++i) {
            CPubKey pubkey;
            entry::pwalletMain->GetKeyFromPool(pubkey, false);
            pubkeys.push(std::move(pubkey));
            print_bytes("wallet pubkeys", pubkey.GetPubVch().data(), pubkey.GetPubVch().size());
            CFirmKey key;
            if(!entry::pwalletMain->GetKey(pubkey.GetID(), key))
                return false;
            secrets.push(key.GetSecret());
        }

        XOnlyPubKeysAggInfo agg_pubkeys;
        agg_pubkeys.agg_pubkeys.push_back(pubkeys);
        CDataStream ss;
        ss << agg_pubkeys;
        XOnlyPubKeysAggInfo agg_pubkeys2;
        ss >> agg_pubkeys2;
        assert(pubkeys == agg_pubkeys2.agg_pubkeys[0]);

        uint256 hash = Create_random_hash();
        std::vector<unsigned char> sigbytes;
        if(!secrets.SignSchnorr(hash, sigbytes))
            return false;
        if(!pubkeys.VerifySchnorr(hash, Span<const unsigned char>(sigbytes)))
            return false;
    }

    return true;
}

// y = a * x mod p (solve x)
namespace solve_mod {

int extended_gcd(const BIGNUM *a, const BIGNUM *b, BIGNUM *x, BIGNUM *y, BN_CTX *ctx) {
    if (BN_is_zero(a)) {
        BN_zero(x);
        BN_one(y);
        return 1;
    }

    BIGNUM *x1 = BN_new();
    BIGNUM *y1 = BN_new();
    BIGNUM *b_mod_a = BN_new();
    BIGNUM *a_copy = BN_new();
    BIGNUM *b_copy = BN_new();
    BN_copy(a_copy, a);
    BN_copy(b_copy, b);

    BN_mod(b_mod_a, b_copy, a_copy, ctx);
    extended_gcd(b_mod_a, a, x1, y1, ctx);

    BIGNUM *b_div_a = BN_new();
    BN_div(b_div_a, NULL, b_copy, a_copy, ctx);

    BIGNUM *temp = BN_new();
    BN_mul(temp, b_div_a, x1, ctx);
    BN_sub(x, y1, temp);
    BN_copy(y, x1);

    BN_free(x1);
    BN_free(y1);
    BN_free(b_mod_a);
    BN_free(a_copy);
    BN_free(b_copy);
    BN_free(b_div_a);
    BN_free(temp);

    return 1;
}

// a*a^-1 is 1, mod p
int mod_inverse(BIGNUM *result, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx) {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *g = BN_new();

    extended_gcd(a, p, x, y, ctx);
    BN_gcd(g, a, p, ctx);
    if (!BN_is_one(g)) {
        BN_free(x);
        BN_free(y);
        BN_free(g);
        return 0;
    } else {
        BN_nnmod(result, x, p, ctx);
        BN_free(x);
        BN_free(y);
        BN_free(g);
        return 1;
    }
}

int solve_mod_equation(BIGNUM *x, const BIGNUM *a, const BIGNUM *y, const BIGNUM *p, BN_CTX *ctx) {
    BIGNUM *inv = BN_new();
    if (!mod_inverse(inv, a, p, ctx)) {
        debugcs::instance() << "no exists a*a^-1" << debugcs::endl();
        BN_free(inv);
        return 0;
    }

    BN_mod_mul(x, inv, y, p, ctx);
    BN_free(inv);
    return 1;
}

// y = a * x mod p, compute x (polynomial time)
void check_x(const BIGNUM *a, const BIGNUM *y, const BIGNUM *p) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x = BN_new();

    if (solve_mod_equation(x, a, y, p, ctx)) {
        char *result_str = BN_bn2dec(x);
        debugcs::instance() << "x is " << result_str << debugcs::endl();
        OPENSSL_free(result_str);
    }

    BN_free(x);
    BN_CTX_free(ctx);
}

} // solve_mod

void check_bignum_ecdsa() {
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *order = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *neg_one = BN_new();
    BIGNUM *s1 = BN_new();
    BIGNUM *s2 = BN_new();
    BIGNUM *k = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *neg_e = BN_new();
    BIGNUM *t = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *n = BN_new();
    EC_POINT *q1 = EC_POINT_new(group);
    BIGNUM *q1_x = BN_new();
    BIGNUM *q1_y = BN_new();
    EC_POINT *q2 = EC_POINT_new(group);
    BIGNUM *q2_x = BN_new();
    BIGNUM *q2_y = BN_new();
    EC_POINT *r1 = EC_POINT_new(group);
    EC_POINT *r2 = EC_POINT_new(group);
    EC_POINT *r3 = EC_POINT_new(group);
    EC_POINT *tmp = EC_POINT_new(group);

    do {
        // get order and p (F_p mod) and neg_one
        EC_GROUP_get_order(group, order, ctx);
        EC_GROUP_get_curve_GFp(group, p, NULL, NULL, ctx);

        // neg_one
        BN_set_word(neg_one, 1);
        BN_sub(neg_one, order, neg_one);

        // both k and t are secret
        BN_set_word(k, 1);
        BN_set_word(t, 1);

        // q1, q2
        EC_POINT_mul(group, q1, t, NULL, NULL, ctx);
        EC_POINT_get_affine_coordinates_GFp(group, q1, q1_x, q1_y, ctx);
        if(BN_is_odd(q1_y)) {
            debugcs::instance() << "q1 is from odd to even" << debugcs::endl();
            EC_POINT_invert(group, q1, ctx);
        }
        EC_POINT_mul(group, q2, t, NULL, NULL, ctx);
        EC_POINT_get_affine_coordinates_GFp(group, q2, q2_x, q2_y, ctx);
        if(!BN_is_odd(q2_y)) {
            debugcs::instance() << "q2 is from even to odd" << debugcs::endl();
            EC_POINT_invert(group, q2, ctx);
        }

        // s1 = k + e*t
        BN_set_word(e, 1);
        BN_mod_mul(s1, e, t, p, ctx);
        BN_mod_add(s1, k, s1, p, ctx);

        // s2 = k + negate(e)*t
        BN_set_word(neg_e, 1);
        BN_sub(neg_e, order, neg_e);
        BN_mod_mul(s2, neg_e, t, p, ctx);
        BN_mod_add(s2, k, s2, p, ctx);

        // r1 = k^G
        EC_POINT_mul(group, r1, k, NULL, NULL, ctx);

        // r2 = s1^G - e^q1 [q1: y is even]
        EC_POINT_mul(group, r2, s1, NULL, NULL, ctx);
        EC_POINT_mul(group, tmp, NULL, q1, e, ctx);
        EC_POINT_mul(group, tmp, NULL, tmp, neg_one, ctx);
        EC_POINT_add(group, r2, r2, tmp, ctx);

        // r3 = s2^G - neg_e^invert(q2) [q2: y is odd]
        EC_POINT_mul(group, r3, s2, NULL, NULL, ctx);
        EC_POINT_mul(group, tmp, NULL, q2, neg_e, ctx);
        EC_POINT_mul(group, tmp, NULL, tmp, neg_one, ctx);
        EC_POINT_add(group, r3, r3, tmp, ctx);

        print_ecpoint(group, r1);
        print_ecpoint(group, r2);
        print_ecpoint(group, r3);

        // r2.x = r3.x (r1.x = r2.x, r1.x = r3.x)
        // r2.y = m*r3.y mod p
        // r1.y = n*r3.y mod p

    } while(false);

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    BN_free(order);
    BN_free(p);
    BN_free(neg_one);
    BN_free(s1);
    BN_free(s2);
    BN_free(k);
    BN_free(e);
    BN_free(neg_e);
    BN_free(t);
    BN_free(m);
    BN_free(n);
    EC_POINT_free(q1);
    BN_free(q1_x);
    BN_free(q1_y);
    EC_POINT_free(q2);
    BN_free(q2_x);
    BN_free(q2_y);
    EC_POINT_free(r1);
    EC_POINT_free(r2);
    EC_POINT_free(r3);
    EC_POINT_free(tmp);
}

void Span_check() {
    std::vector<CSecret> keys;
    keys.reserve(64);
    for(int i = 0; i < 64; ++i) {
        CSecret obj;
        obj.assign(1, i+1);
        keys.emplace_back(obj);
    }
    Span<CSecret> sp_keys(keys.data(), 10);
    debugcs::instance() << __func__ << ": " << sp_keys.size() << debugcs::endl();
    for(auto d: sp_keys) {
        debugcs::instance() << __func__ << ": " << std::to_string((int)d[0]) << debugcs::endl();
    }
}

// called AppInit2
void Debug_checking_sign_verify() {
    // schnorr signature
    // 1, OpenSSL schnorr signature sign and Verify: try pub_y with both odd and even values
    //if(!OpenSSL_schnorr_sign_and_verify_pub_y_with_both_odd_and_even()) {
    //    assert(!"1: failure OpenSSL_schnorr_sign_and_verify");
    //}

    // 2, Libsecp256k1 schnorr signature sign and OpenSSL verify: try pub_y with both odd and even values
    //if(!Libsecp256k1_schnorr_sign_and_openssl_verify_pub_y_with_both_odd_and_even()) {
    //    assert(!"2: failure Libsecp256k1_schnorr_sign_and_openssl_verify");
    //}

    // 3, Libsecp256k1 schnorr signature sign and verify: try pub_y with both odd and even values
    //if(!Libsecp256k1_schnorr_sign_and_verify_pub_y_with_both_odd_and_even()) {
    //    assert(!"3: failure Libsecp256k1_schnorr_sign_and_verify");
    //}

    // check mod_inv
    //check_bignum_ecdsa();

    // Schnorr aggregation check
    //std::shared_ptr<CSchnorrKey> schnorr = Create_collect_75_keys();
    //CPubKey collect_pubkey;
    //if(schnorr->collect_pubkey(collect_pubkey))
    //    debugcs::instance() << __func__ << " : " << strenc::HexStr(collect_pubkey.GetPubVch()) << debugcs::endl();
    //else
    //    debugcs::instance() << __func__ << " pubkey collect failure" << debugcs::endl();

    // Schnorr aggregation sign and verify
    //if(!Libsecp256k1_schnorr_sign_and_verify_pub_y_with_both_odd_and_even_and_aggregation()) {
    //    assert(!"4: failure Libsecp256k1_schnorr_sign_and_verify_and_aggregation");
    //}

    // Exists keys aggregation sign and verify
    //if(!agg_schnorr_ecdh_key_exchange()) {
    //    assert(!"5: failure cmp_for_schnorr_pubkeys");
    //}
    //if(!exists_keys_schnorr_agg_sign_verify()) {
    //    assert(!"5: failure Exists keys aggregation sign and verify");
    //}

    // Check cipher transaction
    //if(!check_cipher_transaction2()) {
    //    assert(!"6: check_cipher_transaction");
    //}

    //Span_check();

    // Check_agg_ecdsa();
}

// called AppInit2
void Debug_checking_sign_verify2() {}
