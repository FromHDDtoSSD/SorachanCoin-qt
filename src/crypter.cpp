// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <vector>
#include <string>

#include "crypter.h"

#ifdef WIN32
#include <windows.h>
#endif

bool CCrypter::SetKeyFromPassphrase(const SecureString &strKeyData, const std::vector<unsigned char> &chSalt, const unsigned int nRounds, const unsigned int nDerivationMethod)
{
	if (nRounds < 1 || chSalt.size() != crypter_param::WALLET_CRYPTO_SALT_SIZE) {
		return false;
	}

	int i = 0;
	if (nDerivationMethod == 0) {
        i = ::EVP_BytesToKey(::EVP_aes_256_cbc(), ::EVP_sha512(), &chSalt[0], (unsigned char *)&strKeyData[0], strKeyData.size(), nRounds, chKey, chIV);
	}

	if (i != (int)crypter_param::WALLET_CRYPTO_KEY_SIZE) {
        OPENSSL_cleanse(&chKey, sizeof(chKey));
        OPENSSL_cleanse(&chIV, sizeof(chIV));
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

    ::memcpy(&chKey[0], &chNewKey[0], sizeof(chKey));
    ::memcpy(&chIV[0], &chNewIV[0], sizeof(chIV));

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
	::memcpy(&chIV[0], &nIV, crypter_param::WALLET_CRYPTO_KEY_SIZE);
	if(! cKeyCrypter.SetKey(vMasterKey, chIV)) {
		return false;
	}
	return cKeyCrypter.Encrypt((CKeyingMaterial)vchPlaintext, vchCiphertext);
}

bool crypter::DecryptSecret(const CKeyingMaterial &vMasterKey, const std::vector<unsigned char> &vchCiphertext, const uint256& nIV, CSecret &vchPlaintext)
{
	CCrypter cKeyCrypter;
	std::vector<unsigned char> chIV(crypter_param::WALLET_CRYPTO_KEY_SIZE);
	::memcpy(&chIV[0], &nIV, crypter_param::WALLET_CRYPTO_KEY_SIZE);
	if(! cKeyCrypter.SetKey(vMasterKey, chIV)) {
		return false;
	}
	return cKeyCrypter.Decrypt(vchCiphertext, *((CKeyingMaterial*)&vchPlaintext));
}