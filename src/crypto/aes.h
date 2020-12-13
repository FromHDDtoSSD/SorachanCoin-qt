// Copyright (c) 2015-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// C++ wrapper around ctaes, a constant-time AES implementation

#ifndef BITCOIN_CRYPTO_AES_H
#define BITCOIN_CRYPTO_AES_H

extern "C" {
#include <crypto/ctaes/ctaes.h>
}

namespace latest_crypto {

static constexpr int AES_BLOCKSIZE = 16;
static constexpr int AES128_KEYSIZE = 16;
static constexpr int AES256_KEYSIZE = 32;

/** An encryption class for AES-128. */
class AES128Encrypt
{
private:
    AES128_ctx ctx;
public:
    explicit AES128Encrypt(const unsigned char key[16]) noexcept;
    ~AES128Encrypt();
    void Encrypt(unsigned char ciphertext[16], const unsigned char plaintext[16]) const noexcept;
};

/** A decryption class for AES-128. */
class AES128Decrypt
{
private:
    AES128_ctx ctx;
public:
    explicit AES128Decrypt(const unsigned char key[16]) noexcept;
    ~AES128Decrypt();
    void Decrypt(unsigned char plaintext[16], const unsigned char ciphertext[16]) const noexcept;
};

/** An encryption class for AES-256. */
class AES256Encrypt
{
private:
    AES256_ctx ctx;
public:
    explicit AES256Encrypt(const unsigned char key[32]) noexcept;
    ~AES256Encrypt();
    void Encrypt(unsigned char ciphertext[16], const unsigned char plaintext[16]) const noexcept;
};

/** A decryption class for AES-256. */
class AES256Decrypt
{
private:
    AES256_ctx ctx;
public:
    explicit AES256Decrypt(const unsigned char key[32]) noexcept;
    ~AES256Decrypt();
    void Decrypt(unsigned char plaintext[16], const unsigned char ciphertext[16]) const noexcept;
};

class AES256CBCEncrypt
{
public:
    AES256CBCEncrypt(const unsigned char key[AES256_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn) noexcept;
    ~AES256CBCEncrypt();
    int Encrypt(const unsigned char* data, int size, unsigned char* out) const noexcept;
private:
    const AES256Encrypt enc;
    const bool pad;
    unsigned char iv[AES_BLOCKSIZE];
};

class AES256CBCDecrypt
{
public:
    AES256CBCDecrypt(const unsigned char key[AES256_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn) noexcept;
    ~AES256CBCDecrypt();
    int Decrypt(const unsigned char* data, int size, unsigned char* out) const noexcept;
private:
    const AES256Decrypt dec;
    const bool pad;
    unsigned char iv[AES_BLOCKSIZE];
};

class AES128CBCEncrypt
{
public:
    AES128CBCEncrypt(const unsigned char key[AES128_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn) noexcept;
    ~AES128CBCEncrypt();
    int Encrypt(const unsigned char* data, int size, unsigned char* out) const noexcept;
private:
    const AES128Encrypt enc;
    const bool pad;
    unsigned char iv[AES_BLOCKSIZE];
};

class AES128CBCDecrypt
{
public:
    AES128CBCDecrypt(const unsigned char key[AES128_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn) noexcept;
    ~AES128CBCDecrypt();
    int Decrypt(const unsigned char* data, int size, unsigned char* out) const noexcept;
private:
    const AES128Decrypt dec;
    const bool pad;
    unsigned char iv[AES_BLOCKSIZE];
};

} // namespace latest_crypto

#endif // BITCOIN_CRYPTO_AES_H
