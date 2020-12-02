// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIVKEY_H
#define BITCOIN_PRIVKEY_H

#include <hash.h>
#include <uint256.h>
#include <allocator/allocators.h>
#include <key/pubkey.h>

/**
 * secure_allocator is defined in allocators.h
 * CPrivKey is a serialized private key, with all parameters included
 * (PRIVATE_KEY_SIZE bytes)
 */
using CPrivKey = std::vector<unsigned char, secure_allocator<unsigned char> >;

/** An encapsulated private key. */
class CKey
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
    static bool Check(const unsigned char *vch) noexcept;

    // libsecp256k1
    static void secp256k1_scalar_clear(CPubKey::secp256k1_unit *r) noexcept;
    static int secp256k1_ec_seckey_verify(const unsigned char *seckey) noexcept;

public:
    //! Construct an invalid private key.
    CKey() noexcept : fValid_(false), fCompressed_(false) {
        // Important: vch must be 32 bytes in length to not break serialization
        keydata_.resize(PRIVATE_BYTE_VECTOR_SIZE);
    }

    friend bool operator==(const CKey &a, const CKey &b) noexcept {
        return a.fCompressed_ == b.fCompressed_ &&
               a.size() == b.size() &&
               ::memcmp(a.keydata.data(), b.keydata.data(), a.size()) == 0;
    }

    //! Initialize using begin and end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend, bool fCompressedIn) noexcept {
        if (size_t(pend - pbegin) != keydata.size())
            fValid_ = false;
        else if (Check(&pbegin[0])) {
            assert(keydata_.size()==PRIVATE_BYTE_VECTOR_SIZE);
            ::memcpy(keydata_.data(), (unsigned char *)&pbegin[0], keydata.size());
            fValid_ = true;
            fCompressed_ = fCompressedIn;
        } else
            fValid_ = false;
    }

    //! Simple read-only vector-like interface.
    unsigned int size() const noexcept { return (fValid ? keydata_.size() : 0); }
    const unsigned char *begin() const noexcept { return keydata_.data(); }
    const unsigned char *end() const noexcept { return keydata_.data() + size(); }

    //! Check whether this private key is valid.
    bool IsValid() const noexcept { return fValid_; }

    //! Check whether the public key corresponding to this private key is (to be) compressed.
    bool IsCompressed() const noexcept { return fCompressed_; }

    //! Generate a new private key using a cryptographic PRNG.
    void MakeNewKey(bool fCompressedIn) noexcept;

    //! Convert the private key to a CPrivKey (serialized OpenSSL private key data).
    // This is expensive.
    CPrivKey GetPrivKey() const;

    //! Compute the public key from a private key.
    // This is expensive.
    CPubKey GetPubKey() const;

    //! Create a DER-serialized signature.
    // The test_case parameter tweaks the deterministic nonce.
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig, bool grind = true, uint32_t test_case = 0) const;

    /**
     * Create a compact signature (65 bytes), which allows reconstructing the used public key.
     * The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
     * The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
     *                  0x1D = second key with even y, 0x1E = second key with odd y,
     *                  add 0x04 for compressed keys.
     */
    bool SignCompact(const uint256& hash, std::vector<unsigned char>& vchSig) const;

    //! Derive BIP32 child key.
    bool Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const;

    /**
     * Verify thoroughly whether a private key and a public key match.
     * This is done using a different mechanism than just regenerating it.
     */
    bool VerifyPubKey(const CPubKey& vchPubKey) const;

    //! Load private key and check that public key matches.
    bool Load(const CPrivKey& privkey, const CPubKey& vchPubKey, bool fSkipCheck);

    //! PrivKey ERROR callback
    static int PrivKey_ERROR_callback(void (*fn)()=nullptr) noexcept {if(fn) fn(); return 0;}
};

#endif
