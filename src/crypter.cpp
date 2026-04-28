// Copyright (c) 2009-2012 The Bitcoin Developers
// Copyright (c) 2018-2026 The SORA Developers
// Copyright (c) 2025 The SS256/SORA2 Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <cleanse/cleanse.h>
#include <vector>
#include <string>
//#include <crypto/sora2.h>
#include <crypto/sha3_512.h>
#include <crypter.h>
#include <debugcs/debugcs.h>
#ifdef WIN32
# include <windows.h>
#endif

/*
static int SORA2_512_BytesToKey(const unsigned char *salt, const unsigned char *data, int datal, int count, unsigned char *key, unsigned char *iv) {
    std::vector<unsigned char> vch;
    vch.resize(datal + 8);
    ::memcpy(&vch.front(), data, datal);
    ::memcpy(&vch.front() + datal, salt, 8);

    unsigned char hash[64];
    CSORA2_512().Write(vch.data(), vch.size()).Finalize(hash);
    for(int i=0; i < count; ++i) {
        unsigned char tmp[64];
        CSORA2_512().Write(hash, 64).Finalize(tmp);
        ::memcpy(hash, tmp, 64);
        cleanse::OPENSSL_cleanse(tmp, 64);
    }

    ::memcpy(key, hash, crypter_param::WALLET_CRYPTO_KEY_SIZE);
    ::memcpy(iv, hash + crypter_param::WALLET_CRYPTO_KEY_SIZE, crypter_param::WALLET_CRYPTO_KEY_SIZE);

    debugcs::instance() << __func__ << " hash: " << util::HexStr(BEGIN(hash), END(hash)) << debugcs::endl();
    debugcs::instance() << __func__ << " key: " << util::HexStr(key, key + 32) << debugcs::endl();
    debugcs::instance() << __func__ << " iv: " << util::HexStr(iv, iv + 32) << debugcs::endl();

    cleanse::OPENSSL_cleanse(hash, 64);
    return crypter_param::WALLET_CRYPTO_KEY_SIZE;
}
*/

static int SHA3_512_BytesToKey(const unsigned char *salt, const unsigned char *data, int datal, int count, unsigned char *key, unsigned char *iv) {
    std::vector<unsigned char> vch;
    vch.resize(datal + 8);
    ::memcpy(&vch.front(), data, datal);
    ::memcpy(&vch.front() + datal, salt, 8);

    unsigned char hash[64];
    CSHA3_512().Write(vch.data(), vch.size()).Finalize(hash);
    for(int i=0; i < count; ++i) {
        unsigned char tmp[64];
        CSHA3_512().Write(hash, 64).Finalize(tmp);
        ::memcpy(hash, tmp, 64);
        cleanse::OPENSSL_cleanse(tmp, 64);
    }

    ::memcpy(key, hash, crypter_param::WALLET_CRYPTO_KEY_SIZE);
    ::memcpy(iv, hash + crypter_param::WALLET_CRYPTO_KEY_SIZE, crypter_param::WALLET_CRYPTO_KEY_SIZE);

    debugcs::instance() << __func__ << " hash: " << util::HexStr(BEGIN(hash), END(hash)) << debugcs::endl();
    debugcs::instance() << __func__ << " key: " << util::HexStr(key, key + 32) << debugcs::endl();
    debugcs::instance() << __func__ << " iv: " << util::HexStr(iv, iv + 32) << debugcs::endl();

    cleanse::OPENSSL_cleanse(hash, 64);
    return crypter_param::WALLET_CRYPTO_KEY_SIZE;
}

bool CCrypter::SetKeyFromPassphrase(const SecureString &strKeyData, const std::vector<unsigned char> &chSalt, const unsigned int nRounds, const unsigned int nDerivationMethod)
{
    if (nRounds < 1 || chSalt.size() != crypter_param::WALLET_CRYPTO_SALT_SIZE) {
        return false;
    }

    int i = 0;
    if (nDerivationMethod == 0) {
        i = ::EVP_BytesToKey(::EVP_aes_256_cbc(), ::EVP_sha512(), &chSalt[0], (unsigned char *)&strKeyData[0], strKeyData.size(), nRounds, chKey, chIV);
    } else if (nDerivationMethod == 2) {
        i = SHA3_512_BytesToKey(&chSalt[0], (unsigned char *)&strKeyData[0], strKeyData.size(), nRounds, chKey, chIV);
    }

    if (i != (int)crypter_param::WALLET_CRYPTO_KEY_SIZE) {
        cleanse::OPENSSL_cleanse(&chKey, sizeof(chKey));
        cleanse::OPENSSL_cleanse(&chIV, sizeof(chIV));
        return false;
    }

    fKeySet = true;
    return true;
}

bool CCrypter::SetKey(const CKeyingMaterial &chNewKey, const std::vector<unsigned char> &chNewIV)
{
    if (chNewKey.size() != crypter_param::WALLET_CRYPTO_KEY_SIZE || chNewIV.size() != crypter_param::WALLET_CRYPTO_KEY_SIZE) {
        return false;
    }

    std::memcpy(&chKey[0], &chNewKey[0], sizeof(chKey));
    std::memcpy(&chIV[0], &chNewIV[0], sizeof(chIV));

    fKeySet = true;
    return true;
}

bool CCrypter::Encrypt(const CKeyingMaterial &vchPlaintext, std::vector<unsigned char> &vchCiphertext)
{
    if (! fKeySet) {
        return false;
    }

    //
    // max ciphertext len for a n bytes of plaintext is
    // n + AES_BLOCK_SIZE - 1 bytes
    //
    int nLen = vchPlaintext.size();
    int nCLen = nLen + AES_BLOCK_SIZE, nFLen = 0;
    vchCiphertext = std::vector<unsigned char>(nCLen);

    EVP_CIPHER_CTX ctx;
    bool fOk = true;
    ::EVP_CIPHER_CTX_init(&ctx);
    if (fOk) {
        fOk = ::EVP_EncryptInit_ex(&ctx, ::EVP_aes_256_cbc(), NULL, chKey, chIV) != 0;
    }
    if (fOk) {
        fOk = ::EVP_EncryptUpdate(&ctx, &vchCiphertext[0], &nCLen, &vchPlaintext[0], nLen) != 0;
    }
    if (fOk) {
        fOk = ::EVP_EncryptFinal_ex(&ctx, (&vchCiphertext[0]) + nCLen, &nFLen) != 0;
    }
    ::EVP_CIPHER_CTX_cleanup(&ctx);

    if (! fOk) {
        return false;
    }

    vchCiphertext.resize(nCLen + nFLen);
    return true;
}

bool CCrypter::Decrypt(const std::vector<unsigned char> &vchCiphertext, CKeyingMaterial &vchPlaintext)
{
    if (! fKeySet) {
        return false;
    }

    //
    // plaintext will always be equal to or lesser than length of ciphertext
    //
    int nLen = vchCiphertext.size();
    int nPLen = nLen, nFLen = 0;
    vchPlaintext = CKeyingMaterial(nPLen);

    EVP_CIPHER_CTX ctx;
    bool fOk = true;
    ::EVP_CIPHER_CTX_init(&ctx);
    if (fOk) {
        fOk = ::EVP_DecryptInit_ex(&ctx, ::EVP_aes_256_cbc(), NULL, chKey, chIV) != 0;
    }
    if (fOk) {
        fOk = ::EVP_DecryptUpdate(&ctx, &vchPlaintext[0], &nPLen, &vchCiphertext[0], nLen) != 0;
    }
    if (fOk) {
        fOk = ::EVP_DecryptFinal_ex(&ctx, (&vchPlaintext[0]) + nPLen, &nFLen) != 0;
    }
    ::EVP_CIPHER_CTX_cleanup(&ctx);

    if (! fOk) {
        return false;
    }

    vchPlaintext.resize(nPLen + nFLen);
    return true;
}

bool crypter::EncryptSecret(CKeyingMaterial& vMasterKey, const CSecret &vchPlaintext, const uint256& nIV, std::vector<unsigned char> &vchCiphertext)
{
    CCrypter cKeyCrypter;
    std::vector<unsigned char> chIV(crypter_param::WALLET_CRYPTO_KEY_SIZE);
    std::memcpy(&chIV[0], &nIV, crypter_param::WALLET_CRYPTO_KEY_SIZE);
    if(! cKeyCrypter.SetKey(vMasterKey, chIV)) {
        return false;
    }
    return cKeyCrypter.Encrypt((CKeyingMaterial)vchPlaintext, vchCiphertext);
}

bool crypter::DecryptSecret(const CKeyingMaterial &vMasterKey, const std::vector<unsigned char> &vchCiphertext, const uint256& nIV, CSecret &vchPlaintext)
{
    CCrypter cKeyCrypter;
    std::vector<unsigned char> chIV(crypter_param::WALLET_CRYPTO_KEY_SIZE);
    std::memcpy(&chIV[0], &nIV, crypter_param::WALLET_CRYPTO_KEY_SIZE);
    if(! cKeyCrypter.SetKey(vMasterKey, chIV)) {
        return false;
    }
    return cKeyCrypter.Decrypt(vchCiphertext, *((CKeyingMaterial*)&vchPlaintext));
}
