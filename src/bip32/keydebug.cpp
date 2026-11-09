// Copyright (c) 2009-2021 The Bitcoin developers
// Copyright (c) 2018-2025 The SorachanCoin developers
// Copyright (c) 2025 The SS256 SORA2 developers
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
#include <rpc/bitcoinrpc.h>
#include <crypto/chacha20.h>
#include <crypto/sora2.h>
#include <crypto/ripemd160.h>
#include <crypto/sha1.h>
#include <crypto/keccak256.h>
#include <crypto/sha3_256.h>
#include <crypto/sha3_512.h>
#include <crypto/hmac_sha3_256.h>
#include <crypto/hmac_sha3_512.h>
#include <quantum/mldsa_fips204/sign_fips204.h>
#include <quantum/quantum_fips204.h>

template <typename T>
class optional {
public:
    optional() : enable(false) {}
    optional(T _in) : enable(true) {value = _in;}
    ~optional() {}

    bool has_value() const {return enable;}

    const optional &operator=(const T &_in) {
        value = _in;
        enable = true;
        return *this;
    }

    T operator*() const {
        if(enable)
            return value;
        else
            throw std::runtime_error("Undefine value");
    }

private:
    bool enable;
    T value;
};

//#define DEBUG_CHECKE

#ifdef DEBUG_CHECKE

// called AppInit2
void Debug_checking_sign_verify() {
    unsigned char seed32[32];
    random::GetStrongRandBytes(seed32, 32);
    CqSecretKey seed;
    seed.resize(32);
    memcpy(&seed.front(), seed32, 32);
    CqKey_fips204 key(seed);
    CqPubKey_fips204 pubkey = key.GetPubKey();

    for(int i=0; i < 1000; ++i) {
        uint256 hash;
        random::GetStrongRandBytes(hash.begin(), 32);
        qkey_vector sig;
        bool ret1 = key.Sign(hash, sig);
        if(i == 555) {
            sig[0] ^= 1;
        }
        bool ret2 = pubkey.Verify(hash, sig);
        if(ret1 == false || ret2 == false) {
# ifdef WIN32
            MessageBoxA(nullptr, "Sign and Verify - Error", "mldsa - fips204 debug", MB_OK);
# endif
        }
    }
}

void Debug_checking_sign_verify_complete2() {

    /// checking mldsa - fips204 (Quantum Resistance)

    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];
    uint8_t message[] = "Hello, SORA!";
    const size_t message_len = sizeof(message) - 1; /* exclude NUL */
    const uint8_t context[] = "";
    size_t sig_len = 0;
    int result = 1;
    std::ostringstream ss;

    unsigned char seed32[32];
    random::GetStrongRandBytes(seed32, 32);

    /* 1. Key generation: pk = public key, sk = secret key. */
    if (crypto_sign_seed_keypair(pk, sk, seed32) != 0) goto cleanup;

    /* 2. Sign using the secret key. sig is a detached signature. */
    if (crypto_sign_signature(sig, &sig_len, message, message_len, context, 0, sk) != 0) goto cleanup;

    /* 3. Verify using only the public key. 0 = valid, -1 = invalid. */
    if (crypto_sign_verify(sig, sig_len, message, message_len, context, 0, pk) != 0) goto cleanup;

    ss << "Public key: " << sizeof(pk) << " bytes\n";
    ss << "Secret key: " << sizeof(sk) << " bytes\n";
    ss << "Signature : " << sig_len << " bytes\n";
    ss << "Verify original: OK";

    /* 4. A changed message must fail verification. */
    message[0] ^= 1;
    if (crypto_sign_verify(sig, sig_len, message, message_len, context, 0, pk) == 0) goto cleanup;
    ss << "Verify tampered: rejected (expected)";
    result = 0;

cleanup:
    /* Erases this caller-owned key buffer, not all internal temporaries. */
    {
        volatile uint8_t *wipe = sk;
        size_t i;
        for (i = 0; i < sizeof(sk); ++i) wipe[i] = 0;
    }
    if (result != 0)
        ss << "ML-DSA example failed.\n";

# ifdef WIN32
    MessageBoxA(nullptr, ss.str().c_str(), "mldsa - fips204 debug", MB_OK);
# endif
}

void Debug_checking_sign_verify_complete() {
    std::vector<uint8_t> data;
    data.resize(0);

    unsigned char hash[32] = {0};
    CSHA3_256().Write(data.data(), data.size()).Finalize(hash);
    std::string str = util::HexStr(std::begin(hash), std::end(hash));
    debugcs::instance() << "CSHA3_256: " << str << debugcs::endl();

    unsigned char hash2[64] = {0};
    CSHA3_512().Write(data.data(), data.size()).Finalize(hash2);
    std::string str2 = util::HexStr(std::begin(hash2), std::end(hash2));
    debugcs::instance() << "CSHA3_512: " << str2 << debugcs::endl();

    std::string key = "sora";

    unsigned char hash3[32] = {0};
    CHMAC_SHA3_256((const unsigned char *)key.c_str(), key.size()).Write(data.data(), data.size()).Finalize(hash3);
    std::string str3 = util::HexStr(std::begin(hash3), std::end(hash3));
    debugcs::instance() << "CHMAC_SHA3_256: " << str3 << debugcs::endl();

    unsigned char hash4[64] = {0};
    CHMAC_SHA3_512((const unsigned char *)key.c_str(), key.size()).Write(data.data(), data.size()).Finalize(hash4);
    std::string str4 = util::HexStr(std::begin(hash4), std::end(hash4));
    debugcs::instance() << "CHMAC_SHA3_512: " << str4 << debugcs::endl();

    unsigned char hash5[32] = {0};
    CHash256().Write(data.data(), data.size()).Finalize(hash5);
    std::string str5 = util::HexStr(std::begin(hash5), std::end(hash5));
    debugcs::instance() << "CHash256: " << str5 << debugcs::endl();

    data.resize(4);
    data[0] = 's'; data[1] = 'o'; data[2] = 'r'; data[3] = 'a';

    unsigned char hash6[32] = {0};
    CHash256().Write(data.data(), data.size()).Finalize(hash6);
    std::string str6 = util::HexStr(std::begin(hash6), std::end(hash6));
    uint256 hash7;
    if(args_bool::fTestNet)
        hash7 = bitmining::sha3d_hash(data.data(), data.size());
    else
        hash7 = bitmining::sha256d_hash(data.data(), data.size());
    std::string str7 = util::HexStr(std::begin(hash7), std::end(hash7));
    assert(str6 == str7);
    debugcs::instance() << "str6: " << str6 << debugcs::endl();
    debugcs::instance() << "str7: " << str7 << debugcs::endl();
}

// called AppInit2
void Debug_checking_sign_verify2() {}

#else

void Debug_checking_sign_verify() {}

void Debug_checking_sign_verify2() {}

#endif
