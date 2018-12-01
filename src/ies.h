/**
 * reference: ecies.h
 * cryptogram.cpp, ecies.cpp
 */


#ifndef _IES_H_
#define _IES_H_

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

typedef struct
{
    const EVP_CIPHER *cipher;
    const EVP_MD *md;             /* for mac tag */
    const EVP_MD *kdf_md;         /* for KDF */
    size_t stored_key_length;
    const EC_KEY *user_key;
} ies_ctx_t;
typedef unsigned char *cryptogram_t;

class cryptogram
{
private:
    cryptogram(); // {}
    cryptogram(const cryptogram &); // {}
    cryptogram &operator=(const cryptogram &); // {}

    typedef struct
    {
        struct {
            size_t key;
            size_t mac;
            size_t body;
        } length;
    } cryptogram_head_t;

    static const size_t HEADSIZE = sizeof(cryptogram_head_t);

    static int ECDH_KDF_X9_62(unsigned char *out, size_t outlen, const unsigned char *Z, size_t Zlen, const unsigned char *sinfo, size_t sinfolen, const EVP_MD *md);
    static size_t envelope_key_len(const ies_ctx_t *ctx);
    static EC_KEY *ecies_key_create(const EC_KEY *user, char *error);
    static unsigned char *prepare_envelope_key(const ies_ctx_t *ctx, cryptogram_t *cryptogram, char *error);
    static int store_cipher_body(const ies_ctx_t *ctx, const unsigned char *envelope_key, const unsigned char *data, size_t length, cryptogram_t *cryptogram, char *error);
    static int store_mac_tag(const ies_ctx_t *ctx, const unsigned char *envelope_key, cryptogram_t *cryptogram, char *error);
    static EC_KEY *ecies_key_create_public_octets(EC_KEY *user, unsigned char *octets, size_t length, char *error);

    static unsigned char *restore_envelope_key(const ies_ctx_t *ctx, const cryptogram_t *cryptogram, char *error);
    static int verify_mac(const ies_ctx_t *ctx, const cryptogram_t *cryptogram, const unsigned char *envelope_key, char *error);
    static unsigned char *decrypt_body(const ies_ctx_t *ctx, const cryptogram_t *cryptogram, const unsigned char *envelope_key, size_t *length, char *error);

public:
    static void cryptogram_free(cryptogram_t *cryptogram);
    static unsigned char *cryptogram_key_data(const cryptogram_t *cryptogram);
    static unsigned char *cryptogram_mac_data(const cryptogram_t *cryptogram);
    static unsigned char *cryptogram_body_data(const cryptogram_t *cryptogram);
    static size_t cryptogram_key_length(const cryptogram_t *cryptogram);
    static size_t cryptogram_mac_length(const cryptogram_t *cryptogram);
    static size_t cryptogram_body_length(const cryptogram_t *cryptogram);
    static size_t cryptogram_data_sum_length(const cryptogram_t *cryptogram);
    static size_t cryptogram_total_length(const cryptogram_t *cryptogram);
    static cryptogram_t *cryptogram_alloc(size_t key, size_t mac, size_t body);
    static cryptogram_t *ecies_encrypt(const ies_ctx_t *ctx, const unsigned char *data, size_t length, char *error);
    static unsigned char *ecies_decrypt(const ies_ctx_t *ctx, const cryptogram_t *cryptogram, size_t *length, char *error);
    static ies_ctx_t *create_context(EC_KEY *user_key);
};

#endif /* _IES_H_ */
//@
