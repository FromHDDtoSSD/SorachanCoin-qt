// Copyright (c) 2016-2018 The Bitcoin Core developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/aes.h>
#include <crypto/common.h>
#include <assert.h>
#include <string.h>
#include <random/random.h>

extern "C" {
#include <crypto/ctaes/ctaes.c>
}

namespace latest_crypto {

AES128Encrypt::AES128Encrypt(const unsigned char key[16])
{
    AES128_init(&ctx, key);
}

AES128Encrypt::~AES128Encrypt()
{
    std::memset(&ctx, 0, sizeof(ctx));
}

void AES128Encrypt::Encrypt(unsigned char ciphertext[16], const unsigned char plaintext[16]) const
{
    AES128_encrypt(&ctx, 1, ciphertext, plaintext);
}

AES128Decrypt::AES128Decrypt(const unsigned char key[16])
{
    AES128_init(&ctx, key);
}

AES128Decrypt::~AES128Decrypt()
{
    std::memset(&ctx, 0, sizeof(ctx));
}

void AES128Decrypt::Decrypt(unsigned char plaintext[16], const unsigned char ciphertext[16]) const
{
    AES128_decrypt(&ctx, 1, plaintext, ciphertext);
}

AES256Encrypt::AES256Encrypt(const unsigned char key[32])
{
    AES256_init(&ctx, key);
}

AES256Encrypt::~AES256Encrypt()
{
    std::memset(&ctx, 0, sizeof(ctx));
}

void AES256Encrypt::Encrypt(unsigned char ciphertext[16], const unsigned char plaintext[16]) const
{
    AES256_encrypt(&ctx, 1, ciphertext, plaintext);
}

AES256Decrypt::AES256Decrypt(const unsigned char key[32])
{
    AES256_init(&ctx, key);
}

AES256Decrypt::~AES256Decrypt()
{
    std::memset(&ctx, 0, sizeof(ctx));
}

void AES256Decrypt::Decrypt(unsigned char plaintext[16], const unsigned char ciphertext[16]) const
{
    AES256_decrypt(&ctx, 1, plaintext, ciphertext);
}

namespace
{

template <typename T>
int CBCEncrypt(const T& enc, const unsigned char iv[AES_BLOCKSIZE], const unsigned char* data, int size, bool pad, unsigned char* out)
{
    int written = 0;
    int padsize = size % AES_BLOCKSIZE;
    unsigned char mixed[AES_BLOCKSIZE];

    if (!data || !size || !out)
        return 0;

    if (!pad && padsize != 0)
        return 0;

    std::memcpy(mixed, iv, AES_BLOCKSIZE);

    // Write all but the last block
    while (written + AES_BLOCKSIZE <= size) {
        for (int i = 0; i != AES_BLOCKSIZE; i++)
            mixed[i] ^= *data++;
        enc.Encrypt(out + written, mixed);
        std::memcpy(mixed, out + written, AES_BLOCKSIZE);
        written += AES_BLOCKSIZE;
    }
    if (pad) {
        // For all that remains, pad each byte with the value of the remaining
        // space. If there is none, pad by a full block.
        for (int i = 0; i != padsize; i++)
            mixed[i] ^= *data++;
        for (int i = padsize; i != AES_BLOCKSIZE; i++)
            mixed[i] ^= AES_BLOCKSIZE - padsize;
        enc.Encrypt(out + written, mixed);
        written += AES_BLOCKSIZE;
    }
    return written;
}

template <typename T>
int CBCDecrypt(const T& dec, const unsigned char iv[AES_BLOCKSIZE], const unsigned char* data, int size, bool pad, unsigned char* out)
{
    int written = 0;
    bool fail = false;
    const unsigned char* prev = iv;

    if (!data || !size || !out)
        return 0;

    if (size % AES_BLOCKSIZE != 0)
        return 0;

    // Decrypt all data. Padding will be checked in the output.
    while (written != size) {
        dec.Decrypt(out, data + written);
        for (int i = 0; i != AES_BLOCKSIZE; i++)
            *out++ ^= prev[i];
        prev = data + written;
        written += AES_BLOCKSIZE;
    }

    // When decrypting padding, attempt to run in constant-time
    if (pad) {
        // If used, padding size is the value of the last decrypted byte. For
        // it to be valid, It must be between 1 and AES_BLOCKSIZE.
        unsigned char padsize = *--out;
        fail = !padsize | (padsize > AES_BLOCKSIZE);

        // If not well-formed, treat it as though there's no padding.
        padsize *= !fail;

        // All padding must equal the last byte otherwise it's not well-formed
        for (int i = AES_BLOCKSIZE; i != 0; i--)
            fail |= ((i > AES_BLOCKSIZE - padsize) & (*out-- != padsize));

        written -= padsize;
    }
    return written * !fail;
}

} // namespace

AES256CBCEncrypt::AES256CBCEncrypt(const unsigned char key[AES256_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn)
    : enc(key), pad(padIn)
{
    std::memcpy(iv, ivIn, AES_BLOCKSIZE);
}

int AES256CBCEncrypt::Encrypt(const unsigned char* data, int size, unsigned char* out) const
{
    return CBCEncrypt(enc, iv, data, size, pad, out);
}

AES256CBCEncrypt::~AES256CBCEncrypt()
{
    std::memset(iv, 0, sizeof(iv));
}

AES256CBCDecrypt::AES256CBCDecrypt(const unsigned char key[AES256_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn)
    : dec(key), pad(padIn)
{
    std::memcpy(iv, ivIn, AES_BLOCKSIZE);
}


int AES256CBCDecrypt::Decrypt(const unsigned char* data, int size, unsigned char* out) const
{
    return CBCDecrypt(dec, iv, data, size, pad, out);
}

AES256CBCDecrypt::~AES256CBCDecrypt()
{
    std::memset(iv, 0, sizeof(iv));
}

AES128CBCEncrypt::AES128CBCEncrypt(const unsigned char key[AES128_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn)
    : enc(key), pad(padIn)
{
    std::memcpy(iv, ivIn, AES_BLOCKSIZE);
}

AES128CBCEncrypt::~AES128CBCEncrypt()
{
    std::memset(iv, 0, AES_BLOCKSIZE);
}

int AES128CBCEncrypt::Encrypt(const unsigned char* data, int size, unsigned char* out) const
{
    return CBCEncrypt(enc, iv, data, size, pad, out);
}

AES128CBCDecrypt::AES128CBCDecrypt(const unsigned char key[AES128_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn)
    : dec(key), pad(padIn)
{
    std::memcpy(iv, ivIn, AES_BLOCKSIZE);
}

AES128CBCDecrypt::~AES128CBCDecrypt()
{
    std::memset(iv, 0, AES_BLOCKSIZE);
}

int AES128CBCDecrypt::Decrypt(const unsigned char* data, int size, unsigned char* out) const
{
    return CBCDecrypt(dec, iv, data, size, pad, out);
}

/**
 * CAES256CBCPKCS7
 */
void CAES256CBCPKCS7::padding(unsigned char *data, uint32_t data_len) {
    const uint32_t pad_len = bsize - (data_len % bsize);
    for (uint32_t i = 0; i < pad_len; i++) {
        data[data_len + i] = (unsigned char)pad_len;
    }
}

bool CAES256CBCPKCS7::padcheck(std::vector<unsigned char>::iterator end, uint32_t pad_num) {
    if(pad_num == 0 || pad_num > bsize)
        return false;
    for(uint32_t i=0; i < pad_num; ++i) {
        if(*(end - 1 - i) != pad_num)
            return false;
    }
    return true;
}

CAES256CBCPKCS7::CheckHash CAES256CBCPKCS7::checking(unsigned char *data, uint32_t data_len) {
    uint256 hash;
    latest_crypto::CHash256().Write(data, data_len).Finalize(hash.begin());
    CheckHash chash;
    for (uint32_t i=0; i < chashsize; ++i)
        chash.c[i] = *(hash.begin() + i);
    return chash;
}

CAES256CBCPKCS7 &CAES256CBCPKCS7::err() {
    buffer.clear();
    fcheck = false;
    return *this;
}

uint256_cleanse CAES256CBCPKCS7::getkeyhash(const CAESSecret &key) {
    uint256_cleanse hash;
    CHash256().Write(key.data(), key.size()).Finalize(hash.begin());
    return hash;
}

unsigned char *CAES256CBCPKCS7::createiv() {
    iv.resize(bsize);
    random::GetStrongRandBytes(&iv.front(), iv.size());
    return iv.data();
}

CAES256CBCPKCS7::CAES256CBCPKCS7(const unsigned char *key, uint32_t size) : fcheck(false) {
    Reset(key, size);
}

CAES256CBCPKCS7 &CAES256CBCPKCS7::Reset(const unsigned char *key, uint32_t size) {
    assert(key && size >= 20);
    buffer.clear(); buffer.shrink_to_fit();
    secret.resize(size);
    ::memcpy(&secret.front(), key, size);
    fcheck = false;
    return *this;
}

CAES256CBCPKCS7 &CAES256CBCPKCS7::Encrypt(const unsigned char *data, uint32_t size) {
    AES256CBCEncrypt enc(getkeyhash(secret).begin(), createiv(), false);
    assert(iv.size() == bsize);
    if(!data || size == 0)
        return err();
    const uint32_t padded_size = size + (bsize - (size % bsize));
    buffer.resize(padded_size + chashsize + bsize);
    std::vector<unsigned char> padded_data;
    padded_data.resize(padded_size);
    ::memcpy(&padded_data.front(), data, size);
    padding(&padded_data.front(), size);
    CheckHash chash = checking(padded_data.data(), padded_data.size());
    const uint32_t written = (uint32_t)enc.Encrypt(padded_data.data(), padded_data.size(), &buffer.front());
    if(written != padded_size)
        return err();
    for(uint32_t i=0; i < chashsize; ++i)
        buffer.at(padded_size + i) = chash.c[i];
    for(uint32_t i=0; i < bsize; ++i)
        buffer.at(padded_size + chashsize + i) = iv[i];
    fcheck = true;
    return *this;
}

CAES256CBCPKCS7 &CAES256CBCPKCS7::Decrypt(const unsigned char *data, uint32_t size) {
    if(!data || size < bsize + (chashsize + bsize) || (size - (chashsize + bsize)) % bsize > 0)
        return err();
    iv.resize(bsize);
    for(uint32_t i=0; i < bsize; ++i)
        iv[i] = data[size - bsize + i];
    CheckHash chash;
    for(int i=0; i < chashsize; ++i)
        chash.c[i] = data[size - (bsize + chashsize) + i];
    const uint32_t padded_size = size - (bsize + chashsize);
    AES256CBCDecrypt dec(getkeyhash(secret).begin(), iv.data(), false);
    buffer.resize(padded_size);
    const uint32_t written = (uint32_t)dec.Decrypt(data, padded_size, &buffer.front());
    if(written != padded_size)
        return err();
    CheckHash chashdec = checking(buffer.data(), buffer.size());
    if(chash != chashdec)
        return err();
    const uint32_t erase_size = (uint32_t)buffer.back();
    if(erase_size > bsize)
        return err();
    if(!padcheck(buffer.end(), erase_size))
        return err();
    buffer.erase(buffer.end() - erase_size, buffer.end());
    fcheck = true;
    return *this;
}

void CAES256CBCPKCS7::Finalize(std::pair<std::vector<unsigned char>, bool> &vch) {
    vch = std::make_pair(std::move(buffer), fcheck);
}

} // namespace latest_crypto
