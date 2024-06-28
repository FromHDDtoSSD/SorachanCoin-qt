// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HDCHAIN_H
#define BITCOIN_HDCHAIN_H

#include <string>
#include <memory>
#include <allocator/allocators.h>
#include <crypto/hmac_sha256.h>
#include <crypto/aes.h>
#include <quantum/quantum.h>
#include <key/pubkey.h>

#ifdef DEBUG
# define __printf printf
#else
# define __printf nprintf
inline void nprintf(const char *, ...) {}
#endif

class CExtKey;
using CSeedSecret = std::vector<unsigned char, secure_allocator<unsigned char> >; // seed-phrase in secure allocator
namespace SeedCrypto {
    void CreateKeyToHash(const CSeedSecret &keydata, CSeedSecret &outkeysalt, unsigned char keyhash[latest_crypto::AES256_KEYSIZE]);
    void GetKeyToHash(const CSeedSecret &keydata, const CSeedSecret &keysalt, unsigned char keyhash[latest_crypto::AES256_KEYSIZE]);
    CSeedSecret DataAddSignature(const CSeedSecret &org);
    bool IsValidData(const CSeedSecret &data, CSeedSecret &out);
    bool IsValidDataPermitBlank(const CSeedSecret &data, CSeedSecret &out); // crypto memo
    bool Encrypto(const unsigned char key[latest_crypto::AES256_KEYSIZE], const unsigned char *data, size_t size, unsigned char *out, size_t *outsize);
    bool Decrypto(const unsigned char key[latest_crypto::AES256_KEYSIZE], const unsigned char *data, size_t size, unsigned char *out, size_t *outsize);
}

// HD keys param
constexpr int hdkeys_child_regenerate = 500;
constexpr int hdkeys_reserve_pubkey_to_pool = 200;
constexpr int hdkeys_called_reserve_pubkey_sub = 150;
constexpr int hdkeys_added_at_once = 200;

/***************************************************************************************
 * SorachanCoin Integrated Wallet
 * BIP32 HD WALLET + QKey management WALLET + random WALLET(for importprivethkey, etc)
****************************************************************************************/

class hd_wallet {
public:
    unsigned int _child_offset; // next generation key offset (therefore generated keys: _child_offset)
    unsigned int _usedkey_offset; // used key offset (when derive key always checking, _child_offset > _usedkey_offset)
    bool enable; // walletdb.cpp LoadWallet if HD Wallet, enabled is true
    CExtKey *pkeyseed; // walletdb.cpp LoadWallet instance (hdkeyseed), and when create_seed
    CSeedSecret cryptosalt; // wallet passphrase adding salt (wallet Encrypt and Decrypt)
    CSeedSecret vchextkey; // generated pkeyseed (Encode and Decode)
    bool fcryptoseed; // encrypted, true
    std::vector<CPubKey> reserved_pubkey; // when create_seed, reserved AddKey and get pubkeys

    bool get_nextkey(CExtKey &nextkey, const CExtKey &extkeyseed);
    bool create_seed(const CSeedSecret &seed, CSeedSecret &outvchextkey, std::vector<CPubKey> &outpubkeys); // no crypted: seed
    bool add_keys(unsigned int add = hdkeys_added_at_once);

    static hd_wallet &get() { // singleton instance
        static hd_wallet obj;
        return obj;
    }

    static bool IsEmptyRandomWallet();

    bool InValidKeyseed(); // to invalid privkey

    // quantum resistance
    CqSecretKey GetSecretKey();
    CqPubKey GetPubKey();
    CqPubKey GetPubKeyQai();
    CqKeyID GetKeyID();

private:
    hd_wallet() : pkeyseed(nullptr) {
        _child_offset = 0;
        _usedkey_offset = 0;
        enable = false;
        fcryptoseed = false;
        //reserved_pubkey.clear();
    }
    ~hd_wallet();
};

namespace hd_create {
    CSeedSecret CreateSeed(const std::vector<SecureString> &passphrase16);
    bool CreateHDWallet(bool fFirstcreation_wallet, const CSeedSecret &seedIn);
}

#endif
