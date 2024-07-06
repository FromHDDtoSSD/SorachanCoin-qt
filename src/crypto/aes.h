// Copyright (c) 2015-2018 The Bitcoin Core developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// C++ wrapper around ctaes, a constant-time AES implementation

#ifndef BITCOIN_CRYPTO_AES_H
#define BITCOIN_CRYPTO_AES_H

extern "C" {
#include <crypto/ctaes/ctaes.h>
}
#include <hash.h>

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
    explicit AES128Encrypt(const unsigned char key[16]);
    ~AES128Encrypt();
    void Encrypt(unsigned char ciphertext[16], const unsigned char plaintext[16]) const;
};

/** A decryption class for AES-128. */
class AES128Decrypt
{
private:
    AES128_ctx ctx;
public:
    explicit AES128Decrypt(const unsigned char key[16]);
    ~AES128Decrypt();
    void Decrypt(unsigned char plaintext[16], const unsigned char ciphertext[16]) const;
};

/** An encryption class for AES-256. */
class AES256Encrypt
{
private:
    AES256_ctx ctx;
public:
    explicit AES256Encrypt(const unsigned char key[32]);
    ~AES256Encrypt();
    void Encrypt(unsigned char ciphertext[16], const unsigned char plaintext[16]) const;
};

/** A decryption class for AES-256. */
class AES256Decrypt
{
private:
    AES256_ctx ctx;
public:
    explicit AES256Decrypt(const unsigned char key[32]);
    ~AES256Decrypt();
    void Decrypt(unsigned char plaintext[16], const unsigned char ciphertext[16]) const;
};

class AES256CBCEncrypt
{
public:
    AES256CBCEncrypt(const unsigned char key[AES256_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn);
    ~AES256CBCEncrypt();
    int Encrypt(const unsigned char* data, int size, unsigned char* out) const;
private:
    const AES256Encrypt enc;
    const bool pad;
    unsigned char iv[AES_BLOCKSIZE];
};

class AES256CBCDecrypt
{
public:
    AES256CBCDecrypt(const unsigned char key[AES256_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn);
    ~AES256CBCDecrypt();
    int Decrypt(const unsigned char* data, int size, unsigned char* out) const;
private:
    const AES256Decrypt dec;
    const bool pad;
    unsigned char iv[AES_BLOCKSIZE];
};

class AES128CBCEncrypt
{
public:
    AES128CBCEncrypt(const unsigned char key[AES128_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn);
    ~AES128CBCEncrypt();
    int Encrypt(const unsigned char* data, int size, unsigned char* out) const;
private:
    const AES128Encrypt enc;
    const bool pad;
    unsigned char iv[AES_BLOCKSIZE];
};

class AES128CBCDecrypt
{
public:
    AES128CBCDecrypt(const unsigned char key[AES128_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn);
    ~AES128CBCDecrypt();
    int Decrypt(const unsigned char* data, int size, unsigned char* out) const;
private:
    const AES128Decrypt dec;
    const bool pad;
    unsigned char iv[AES_BLOCKSIZE];
};

// SORA-QAI: CAES256CBCPKCS7
// implement SecureAllocator
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CAESSecret;
class CAES256CBCPKCS7 {
public:
    CAES256CBCPKCS7() = delete;
    CAES256CBCPKCS7(const unsigned char *key, uint32_t size);

    CAES256CBCPKCS7 &Reset(const unsigned char *key, uint32_t size);
    CAES256CBCPKCS7 &Encrypt(const unsigned char *data, uint32_t size);
    CAES256CBCPKCS7 &Decrypt(const unsigned char *data, uint32_t size);
    void Finalize(std::pair<std::vector<unsigned char>, bool> &vch);

private:
    CAESSecret secret;
    std::vector<unsigned char> iv;
    std::vector<unsigned char> buffer;
    bool fcheck;
    constexpr static uint32_t chashsize = sizeof(uint256);
    constexpr static uint32_t bsize = latest_crypto::AES_BLOCKSIZE;
    struct CheckHash {
        unsigned char c[chashsize];
        CheckHash() {
            ::memset(c, 0x00, chashsize);
        }
        bool operator==(const CheckHash &a) const {
            return ::memcmp(a.c, this->c, chashsize) == 0;
        }
        bool operator!=(const CheckHash &a) const {
            return !operator==(a);
        }
    } checkhash;

    static void padding(unsigned char *data, uint32_t data_len);
    static bool padcheck(std::vector<unsigned char>::iterator end, uint32_t pad_num);
    static CheckHash checking(unsigned char *data, uint32_t data_len);
    CAES256CBCPKCS7 &err();
    static uint256_cleanse getkeyhash(const CAESSecret &key);
    unsigned char *createiv();
};

} // namespace latest_crypto

#endif // BITCOIN_CRYPTO_AES_H
