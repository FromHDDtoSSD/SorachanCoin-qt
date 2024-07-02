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

class AiNftInfo {
public:
    constexpr static int32_t qai_nft_version = 0x03;
    int32_t qaiVersion;
    AiNftInfo() {
        qaiVersion = qai_nft_version;
    }
};

// Schnorr SymmetricKey
using secp256k1_symmetrickey = CPubKey::secp256k1_pubkey;
class SymmetricKey : private CPubKey::secp256k1_pubkey
{
public:
    SymmetricKey() = delete;

    explicit SymmetricKey(const secp256k1_symmetrickey &symkey) {
        ::memcpy(&front(), symkey.data, size());
    }

    const unsigned char *data() const {
        return ((const CPubKey::secp256k1_pubkey *)this)->data;
    }

    unsigned char &front() {
        return ((CPubKey::secp256k1_pubkey *)this)->data[0];
    }

    unsigned int size() const {
        return sizeof(((CPubKey::secp256k1_pubkey *)this)->data);
    }

    friend bool operator==(const SymmetricKey &a, const SymmetricKey &b) {
        return ::memcmp(a.data(), b.data(), a.size()) == 0;
    }
};

void secp256k1_symmetrickey_save(secp256k1_symmetrickey *symmetrickey, CPubKey::ecmult::secp256k1_ge *ge) {
    CPubKey::secp256k1_pubkey_save(symmetrickey, ge);
}

// Schnorr signature symmetrickey
int secp256k1_schnorrsig_symmetrickey(CFirmKey::ecmult::secp256k1_gen_context *ctx, const unsigned char *seckey, const unsigned char *xonlypubkey, secp256k1_symmetrickey *symmetrickey)
{
    /* y^2 = x^3 + 7 */
    CPubKey::ecmult::secp256k1_fe sc7;
    CPubKey::ecmult::secp256k1_fe_set_int(&sc7, 7);

    /* Get the pub_x */
    CPubKey::ecmult::secp256k1_fe px;
    if (!CPubKey::ecmult::secp256k1_fe_set_b32(&px, xonlypubkey))
        return 0;

    /* Compute the pub_y */
    CPubKey::ecmult::secp256k1_fe py;
    CPubKey::ecmult::secp256k1_fe_sqr(&py, &px);
    CPubKey::ecmult::secp256k1_fe_mul(&py, &py, &px);
    CPubKey::ecmult::secp256k1_fe_add(&py, &sc7);
    CPubKey::ecmult::secp256k1_fe_sqrt(&py, &py);
    CPubKey::ecmult::secp256k1_fe_normalize_var(&py);
    if(CPubKey::ecmult::secp256k1_fe_is_odd(&py))
        CPubKey::ecmult::secp256k1_fe_negate(&py, &py, 1);

    /* Get the pubkey */
    CPubKey::ecmult::secp256k1_ge pk;
    CPubKey::ecmult::secp256k1_ge_set_xy(&pk, &px, &py);

    /* Get the secret */
    CPubKey::secp256k1_scalar x;
    int overflow;
    CPubKey::secp256k1_scalar_set_b32(&x, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (overflow || CPubKey::secp256k1_scalar_is_zero(&x)) {
        cleanse::memory_cleanse(&x, sizeof(x));
        return 0;
    }

    /* Cumpute nonce (rand) */
    CPubKey::secp256k1_scalar nonce;
    do {
        unsigned char rand[32];
        latest_crypto::random::GetStrongRandBytes(rand, 32);
        CPubKey::secp256k1_scalar_set_b32(&nonce, rand, &overflow);
    } while (overflow);

    /* Compute rj = nonce*G + x*pub */
    CPubKey::ecmult::secp256k1_gej rj;
    {
        CPubKey::ecmult::secp256k1_gej pkj;
        CPubKey::ecmult::secp256k1_ge r;
        CPubKey::ecmult::secp256k1_gej_set_ge(&pkj, &pk);
        if(!CPubKey::secp256k1_ecmult(&rj, &pkj, &x, &nonce)) {
            cleanse::memory_cleanse(&x, sizeof(x));
            return 0;
        }
        CPubKey::ecmult::secp256k1_ge_set_gej_var(&r, &rj);
        if(CPubKey::ecmult::secp256k1_ge_is_infinity(&r)) {
            cleanse::memory_cleanse(&x, sizeof(x));
            return 0;
        }
    }

    /* Compute negnonce = (-nonce)*G */
    CPubKey::ecmult::secp256k1_ge negnonce;
    {
        CPubKey::ecmult::secp256k1_gej pkj;
        CPubKey::secp256k1_scalar neg;
        CFirmKey::ecmult::secp256k1_gen_context ctxobj;
        if(ctx == NULL) {
            ctx = &ctxobj;
            if(!ctx->build()) {
                cleanse::memory_cleanse(&x, sizeof(x));
                return 0;
            }
        }
        CPubKey::secp256k1_scalar_negate(&neg, &nonce);
        if(!ctx->secp256k1_ecmult_gen(&pkj, &neg)) {
            cleanse::memory_cleanse(&x, sizeof(x));
            return 0;
        }
        CPubKey::ecmult::secp256k1_ge_set_gej(&negnonce, &pkj);
    }

    /* Compute s = rj + negnonce */
    CPubKey::ecmult::secp256k1_gej sj;
    CPubKey::ecmult::secp256k1_ge s;
    CPubKey::ecmult::secp256k1_gej_add_ge_var(&sj, &rj, &negnonce, NULL);
    CPubKey::ecmult::secp256k1_ge_set_gej(&s, &sj);
    if(CPubKey::ecmult::secp256k1_ge_is_infinity(&s)) {
        cleanse::memory_cleanse(&x, sizeof(x));
        return 0;
    }
    CPubKey::ecmult::secp256k1_fe_normalize(&s.y);
    if(CPubKey::ecmult::secp256k1_fe_is_odd(&s.y))
        CPubKey::ecmult::secp256k1_fe_negate(&s.y, &s.y, 1);

    secp256k1_symmetrickey_save(symmetrickey, &s);
    cleanse::memory_cleanse(&x, sizeof(x));
    return 1;
}

#include <crypto/ctaes/ctaes.h>

namespace latest_crypto {

class CAES256 {
private:
    CHash256 hash256;
    AES256_ctx ctx;
    std::vector<unsigned char> buffer;

    void padding(unsigned char *data, uint32_t data_len) {
        const size_t pad_len = 16 - (data_len % 16);
        if(pad_len < 16) {
            for (size_t i = 0; i < pad_len; i++) {
                data[data_len + i] = 0xFF;
            }
        }
    }

public:
    CAES256() {}

    CAES256 &Init(const unsigned char *key, uint32_t size) {
        hash256.Reset().Write(key, size);
        uint256 hash;
        hash256.Finalize(hash.begin());
        AES256_init(&ctx, hash.begin());
        buffer.clear(); buffer.shrink_to_fit();
        return *this;
    }

    CAES256 &Encrypt(const unsigned char *data, uint32_t size) {
        const uint32_t blocks = (size / 16) + ((size % 16 > 0) ? 1: 0);
        const uint32_t padded_size = size + (16 - (size % 16));
        buffer.resize(padded_size + 4);
        std::vector<unsigned char> padded_data;
        padded_data.resize(padded_size);
        ::memcpy(&padded_data.front(), data, size);
        padding(&padded_data.front(), size);
        AES256_encrypt(&ctx, blocks, &buffer.front(), padded_data.data());
        const uint32_t le_size = endian::bc_le32toh(size);
        const unsigned char *ser_p = (const unsigned char *)&le_size;
        for(int i=0; i < 4; ++i)
            buffer.at(padded_size + i) = ser_p[i];
        return *this;
    }

    CAES256 &Decrypt(const unsigned char *data, uint32_t size) {
        uint32_t le_size;
        unsigned char *ser_p = (unsigned char *)&le_size;
        for(int i=0; i < 4; ++i)
            ser_p[i] = data[size - 4 + i];
        const uint32_t real_size = endian::bc_le32toh(le_size);
        const uint32_t blocks = (real_size / 16) + ((real_size % 16 > 0) ? 1: 0);
        const uint32_t padded_size = real_size + (16 - (real_size % 16));
        buffer.resize(padded_size);
        AES256_decrypt(&ctx, blocks, &buffer.front(), data);
        if(buffer.size() != real_size) {
            assert(buffer.size() > real_size);
            const uint32_t erase_size = buffer.size() - real_size;
            assert(erase_size < 16);
            buffer.erase(buffer.end() - erase_size, buffer.end());
        }
        return *this;
    }

    void Finalize(std::vector<unsigned char> &vch) {
        vch = std::move(buffer);
    }
};

} // latest_crypto

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
    secp256k1_schnorrsig_symmetrickey(NULL, bob_agg_secret.data(), alice_agg_pubkey.data(), &symmetrickey1);
    // alice (alice secret * bob pubkey)
    secp256k1_schnorrsig_symmetrickey(NULL, alice_agg_secret.data(), bob_agg_pubkey.data(), &symmetrickey2);

    SymmetricKey SKey1(symmetrickey1), SKey2(symmetrickey2);
    print_bytes("  bob symmetrickey", SKey1.data(), SKey1.size());
    print_bytes("alice symmetrickey", SKey2.data(), SKey2.size());
    assert(SKey1 == SKey2);

    std::vector<unsigned char> cipher;
    latest_crypto::CAES256().Init(SKey1.data(), SKey1.size()).Encrypt((const unsigned char *)message.data(), message.size()).Finalize(cipher);
    print_bytes("AES256 Encrypt", cipher.data(), cipher.size());

    std::vector<unsigned char> plain;
    latest_crypto::CAES256().Init(SKey1.data(), SKey1.size()).Decrypt((const unsigned char *)cipher.data(), cipher.size()).Finalize(plain);
    print_str("AES256 Decrypt", std::string(plain.begin(), plain.end()));
    assert(message.size() == plain.size());
    assert(message == std::string(plain.begin(), plain.end()));

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

    //Span_check();

    // Check_agg_ecdsa();
}

// called AppInit2
void Debug_checking_sign_verify2() {}
