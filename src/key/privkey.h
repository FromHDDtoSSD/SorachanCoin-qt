// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SECP256k1: private key
// P2PKH: CKey
// other P2PKH: CFirmKey

#ifndef BITCOIN_PRIVKEY_H
#define BITCOIN_PRIVKEY_H

#include <hash.h>
#include <uint256.h>
#include <allocator/allocators.h>
#include <key/pubkey.h>
#include <key.h> // CKey, CPrivKey(279 vch), CSecret(32 vch)

namespace latest_crypto {
    class CHMAC_SHA256;
}

/**
 * secure_allocator is defined in allocators.h
 * CPrivKey is a serialized private key, with all parameters included
 * (PRIVATE_KEY_SIZE bytes)
 */
// using CPrivKey = std::vector<unsigned char, secure_allocator<unsigned char> >;
// using CSecretKey = std::vector<unsigned char, secure_allocator<unsigned char> >;

/** An encapsulated private key. */
class CFirmKey
{
public:
    //! secp256k1
    static constexpr unsigned int PRIVATE_BYTE_VECTOR_SIZE    = 32;
    static constexpr unsigned int PRIVATE_KEY_SIZE            = 279;
    static constexpr unsigned int COMPRESSED_PRIVATE_KEY_SIZE = 214;

    // see www.keylength.com
    // script supports up to 75 for single byte push
    static_assert(
        PRIVATE_KEY_SIZE >= COMPRESSED_PRIVATE_KEY_SIZE,
        "COMPRESSED_PRIVATE_KEY_SIZE is larger than PRIVATE_KEY_SIZE");

private:
    //! Whether this private key is valid. We check for correctness when modifying the key
    //! data, so fValid should always correspond to the actual state.
    bool fValid_;

    //! Whether the public key corresponding to this private key is (to be) compressed.
    bool fCompressed_;

    //! The actual byte data
    CPrivKey keydata_;

    //! Check whether the 32-byte(PRIVATE_BYTE_VECTOR_SIZE) array pointed to by vch is valid keydata.
    static bool Check(const unsigned char *vch);

    class hash {
    public:
        typedef struct {
            unsigned char v[32];
            unsigned char k[32];
            int retry;
        } secp256k1_rfc6979_hmac_sha256_t;
    private:
        static void secp256k1_hmac_sha256_initialize(latest_crypto::CHMAC_SHA256 *hash, const unsigned char *key, size_t size);
        static void secp256k1_hmac_sha256_write(latest_crypto::CHMAC_SHA256 *hash, const unsigned char *data, size_t size);
        static void secp256k1_hmac_sha256_finalize(latest_crypto::CHMAC_SHA256 *hash, unsigned char *out32);
    public:
        static void secp256k1_rfc6979_hmac_sha256_initialize(secp256k1_rfc6979_hmac_sha256_t *rng, const unsigned char *key, size_t keylen);
        static void secp256k1_rfc6979_hmac_sha256_generate(secp256k1_rfc6979_hmac_sha256_t *rng, unsigned char *out, size_t outlen);
        static void secp256k1_rfc6979_hmac_sha256_finalize(secp256k1_rfc6979_hmac_sha256_t *rng);
    };

    class nonce {
    public:
        static int nonce_function_rfc6979(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter);
    };
    typedef int (* secp256k1_nonce_function)(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter);

    class ecmult {
    public:
        //static void secp256k1_fe_inv_all_var(std::unique_ptr<CPubKey::ecmult::secp256k1_fe[]> &r, std::unique_ptr<CPubKey::ecmult::secp256k1_fe[]> &a, size_t len);
        static bool secp256k1_ge_set_all_gej_var(CPubKey::ecmult::secp256k1_ge *r, const CPubKey::ecmult::secp256k1_gej *a, size_t len);
        static void secp256k1_gej_neg(CPubKey::ecmult::secp256k1_gej *r, const CPubKey::ecmult::secp256k1_gej *a);
        static bool secp256k1_gej_add_var(CPubKey::ecmult::secp256k1_gej *r, const CPubKey::ecmult::secp256k1_gej *a, const CPubKey::ecmult::secp256k1_gej *b, CPubKey::ecmult::secp256k1_fe *rzr);
        static void secp256k1_fe_storage_cmov(CPubKey::ecmult::secp256k1_fe_storage *r, const CPubKey::ecmult::secp256k1_fe_storage *a, int flag);
        static void secp256k1_ge_storage_cmov(CPubKey::ecmult::secp256k1_ge_storage *r, const CPubKey::ecmult::secp256k1_ge_storage *a, int flag);
        static void secp256k1_fe_cmov(CPubKey::ecmult::secp256k1_fe *r, const CPubKey::ecmult::secp256k1_fe *a, int flag);
        static bool secp256k1_gej_add_ge(CPubKey::ecmult::secp256k1_gej *r, const CPubKey::ecmult::secp256k1_gej *a, const CPubKey::ecmult::secp256k1_ge *b);
        static void secp256k1_gej_clear(CPubKey::ecmult::secp256k1_gej *r);
        static bool secp256k1_gej_rescale(CPubKey::ecmult::secp256k1_gej *r, const CPubKey::ecmult::secp256k1_fe *s);
        class secp256k1_gen_context {
        private:
            bool secp256k1_ecmult_gen_blind(const unsigned char *seed32);
        public:
            static bool secp256k1_ecmult_gen_context_is_built(const CFirmKey::ecmult::secp256k1_gen_context &gen_ctx);

            /* For accelerating the computation of a*G:
             * To harden against timing attacks, use the following mechanism:
             * * Break up the multiplicand into groups of 4 bits, called n_0, n_1, n_2, ..., n_63.
             * * Compute sum(n_i * 16^i * G + U_i, i=0..63), where:
             *   * U_i = U * 2^i (for i=0..62)
             *   * U_i = U * (1-2^63) (for i=63)
             *   where U is a point with no known corresponding scalar. Note that sum(U_i, i=0..63) = 0.
             * For each i, and each of the 16 possible values of n_i, (n_i * 16^i * G + U_i) is
             * precomputed (call it prec(i, n_i)). The formula now becomes sum(prec(i, n_i), i=0..63).
             * None of the resulting prec group elements have a known scalar, and neither do any of
             * the intermediate sums while computing a*G.
             */
            CPubKey::ecmult::secp256k1_ge_storage (*prec_)[64][16]; /* prec[j][i] = 16^j * i * G + U_i */
            CPubKey::secp256k1_unit blind_;
            CPubKey::ecmult::secp256k1_gej initial_;

            bool secp256k1_ecmult_gen(CPubKey::ecmult::secp256k1_gej *r, const CPubKey::secp256k1_unit *gn) const;

            void init();
            bool build();
            void clear();
            secp256k1_gen_context();
            secp256k1_gen_context(const secp256k1_gen_context &)=delete;
            secp256k1_gen_context(secp256k1_gen_context &&)=delete;
            secp256k1_gen_context &operator=(const secp256k1_gen_context &)=delete;
            secp256k1_gen_context &operator=(secp256k1_gen_context &&)=delete;
            ~secp256k1_gen_context();
        };
    };

    // PrivateKey: libsecp256k1
    static void secp256k1_scalar_clear(CPubKey::secp256k1_unit *r);
    static int secp256k1_ec_seckey_verify(const unsigned char *seckey);
    static int secp256k1_ec_pubkey_create(CFirmKey::ecmult::secp256k1_gen_context &gen_ctx, CPubKey::secp256k1_pubkey *pubkey, const unsigned char *seckey);
    static int ec_privkey_export_der(CFirmKey::ecmult::secp256k1_gen_context &gen_ctx, unsigned char *privkey, size_t *privkeylen, const unsigned char *key32, bool compressed);
    static int secp256k1_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const CPubKey::secp256k1_unit *ar, const CPubKey::secp256k1_unit *as);
    static int secp256k1_ecdsa_signature_serialize_der(unsigned char *output, size_t *outputlen, const CPubKey::secp256k1_signature *sig);
    static int secp256k1_ecdsa_signature_serialize_compact(unsigned char *output64, const CPubKey::secp256k1_signature *sig);
    static bool SigHasLowR(const CPubKey::secp256k1_signature *sig);
    static int secp256k1_ecdsa_sig_sign(const CFirmKey::ecmult::secp256k1_gen_context *gen_ctx, CPubKey::secp256k1_unit *sigr, CPubKey::secp256k1_unit *sigs, const CPubKey::secp256k1_unit *seckey, const CPubKey::secp256k1_unit *message, const CPubKey::secp256k1_unit *nonce, int *recid);
    static int secp256k1_ecdsa_sign(const CFirmKey::ecmult::secp256k1_gen_context *gen_ctx, CPubKey::secp256k1_signature *signature, const unsigned char *msg32, const unsigned char *seckey, CFirmKey::secp256k1_nonce_function noncefp, const void *noncedata);
    static int secp256k1_ecdsa_recoverable_signature_serialize_compact(unsigned char *output64, int *recid, const CPubKey::secp256k1_ecdsa_recoverable_signature *sig);
    static int secp256k1_ecdsa_sign_recoverable(const CFirmKey::ecmult::secp256k1_gen_context *gen_ctx, CPubKey::secp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void *noncedata);
    static int secp256k1_eckey_privkey_tweak_add(CPubKey::secp256k1_unit *key, const CPubKey::secp256k1_unit *tweak);
    static int secp256k1_ec_privkey_tweak_add(unsigned char *seckey, const unsigned char *tweak);
    static int ec_privkey_import_der(unsigned char *out32, const unsigned char *privkey, size_t privkeylen);

public:
    //! Construct an invalid private key.
    CFirmKey() : fValid_(false), fCompressed_(false) {
        // Important: vch must be 32 bytes in length to not break serialization
        keydata_.resize(PRIVATE_BYTE_VECTOR_SIZE);
    }

    friend bool operator==(const CFirmKey &a, const CFirmKey &b) {
        return a.fCompressed_ == b.fCompressed_ &&
               a.size() == b.size() &&
               ::memcmp(a.keydata_.data(), b.keydata_.data(), a.size()) == 0;
    }

    //! Initialize using begin and end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend, bool fCompressedIn) {
        if (size_t(pend - pbegin) != keydata_.size())
            fValid_ = false;
        else if (Check(&pbegin[0])) {
            assert(keydata_.size()==PRIVATE_BYTE_VECTOR_SIZE);
            std::memcpy(keydata_.data(), (unsigned char *)&pbegin[0], keydata_.size());
            fValid_ = true;
            fCompressed_ = fCompressedIn;
        } else
            fValid_ = false;
    }

    void SetSecret(const CSecret &secret, bool fCompressedIn = true) {
        Set(secret.begin(), secret.end(), fCompressedIn);
    }

    void SetCompressedPubKey(bool fCompressedIn) {
        fCompressed_ = fCompressedIn;
    }

    //! Simple read-only vector-like interface.
    unsigned int size() const { return (fValid_ ? keydata_.size() : 0); }
    const unsigned char *begin() const { return keydata_.data(); }
    const unsigned char *end() const { return keydata_.data() + size(); }

    //! Check whether this private key is valid.
    bool IsValid() const { return fValid_; }

    //! Check whether the public key corresponding to this private key is (to be) compressed.
    bool IsCompressed() const { return fCompressed_; }

    //! Generate a new private key using a cryptographic PRNG.
    void MakeNewKey(bool fCompressedIn);

    //! Convert the private key to a CPrivKey (serialized OpenSSL private key data).
    CPrivKey GetPrivKey() const;

    //! Compute the public key from a private key.
    CPubKey GetPubKey() const;

    //! Compute the CSecret from a private key.
    CSecret GetSecret(bool &fCompressed) const;
    CSecret GetSecret() const {
        bool fCompressed;
        return GetSecret(fCompressed);
    }

    //! Create a DER-serialized signature.
    // The test_case parameter tweaks the deterministic nonce.
    bool Sign(const uint256 &hash, key_vector &vchSig, bool grind = true, uint32_t test_case = 0) const;

    /**
     * Create a compact signature (65 bytes), which allows reconstructing the used public key.
     * The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
     * The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
     *                  0x1D = second key with even y, 0x1E = second key with odd y,
     *                  add 0x04 for compressed keys.
     */
    bool SignCompact(const uint256 &hash, key_vector &vchSig) const;

    //! Derive BIP32 child key.
    bool Derive(CFirmKey &keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode &cc) const;

    /**
     * Verify thoroughly whether a private key and a public key match.
     * This is done using a different mechanism than just regenerating it.
     */
    bool VerifyPubKey(const CPubKey &vchPubKey) const;

    //! Load private key and check that public key matches.
    bool Load(const CPrivKey &privkey, const CPubKey &vchPubKey, bool fSkipCheck);

    //! Load private key
    bool SetPrivKey(const CPrivKey &privkey);

    //! from SecretKey to file
    bool WritePEM(const std::string &fileName, const SecureString &strPassKey) const;

    //! Decrypt data
    void DecryptData(const key_vector &encrypted, key_vector &data) const;

    //! PrivKey ERROR callback
    static int PrivKey_ERROR_callback(void (*fn)()=nullptr) {if(fn) fn(); return 0;}
};

// BIP32
struct CExtFirmKey {
    unsigned char nDepth_;
    unsigned char vchFingerprint_[4];
    unsigned int nChild_;
    ChainCode chaincode_; // uint256
    CFirmKey privkey_;

    friend bool operator==(const CExtFirmKey &a, const CExtFirmKey &b) {
        return a.nDepth_ == b.nDepth_ &&
               ::memcmp(&a.vchFingerprint_[0], &b.vchFingerprint_[0], sizeof(vchFingerprint_)) == 0 &&
               a.nChild_ == b.nChild_ &&
               a.chaincode_ == b.chaincode_ &&
               a.privkey_ == b.privkey_;
    }

    bool Encode(unsigned char code[CExtPubKey::BIP32_EXTKEY_SIZE]) const;
    CPrivKey GetPrivKeyVch() const;
    bool Decode(const unsigned char code[CExtPubKey::BIP32_EXTKEY_SIZE]);
    bool Set(const unsigned char code[CExtPubKey::BIP32_EXTKEY_SIZE], bool fCompressed=true);
    bool Derive(CExtFirmKey &out, unsigned int nChild) const;

    CExtPubKey Neuter() const;

    bool SetSeed(const unsigned char *seed, unsigned int nSeedLen);

    template <typename Stream>
    void Serialize(Stream &s) const {
        const unsigned int len = CExtPubKey::BIP32_EXTKEY_SIZE;
        ::WriteCompactSize(s, len);
        unsigned char code[CExtPubKey::BIP32_EXTKEY_SIZE];
        if(! Encode(code))
            throw std::runtime_error("Invalid CExtKey Encode\n");
        s.write((const char *)&code[0], len);
    }

    template <typename Stream>
    void Unserialize(Stream &s) {
        const unsigned int len = compact_size::manage::ReadCompactSize(s);
        unsigned char code[CExtPubKey::BIP32_EXTKEY_SIZE];
        if (len != CExtPubKey::BIP32_EXTKEY_SIZE)
            throw std::runtime_error("Invalid extended key size\n");
        s.read((char *)&code[0], len);
        //if(! Decode(code))
        //    throw std::runtime_error("Invalid CExtKey Decode\n");
        if(! Set(code))
            throw std::runtime_error("Invalid CExtKey Decode\n");
    }
};

#endif
