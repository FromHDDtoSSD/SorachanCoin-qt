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
        if(XOnlyFirmKey::secp256k1_schnorrsig_sign(NULL, &sig, nullptr, hash.begin(), secret.data(), schnorr_nonce::secp256k1_nonce_and_random_function_schnorr, nullptr) != 1)
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
        if(XOnlyFirmKey::secp256k1_schnorrsig_sign(NULL, &sig, nullptr, hash.begin(), secret.data(), schnorr_nonce::secp256k1_nonce_and_random_function_schnorr, nullptr) != 1)
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
        XOnlyFirmKeys xonlykeys;
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
        if(XOnlyFirmKeys::secp256k1_schnorrsig_aggregation(sp_secrets, &agg_secret) != 1) {
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
        if(XOnlyFirmKey::secp256k1_schnorrsig_sign(NULL, &sig, nullptr, hash.begin(), agg_secret.data(), schnorr_nonce::secp256k1_nonce_and_random_function_schnorr, nullptr) != 1)
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

    //Span_check();

    // Check_agg_ecdsa();
}

// called AppInit2
void Debug_checking_sign_verify2() {}
