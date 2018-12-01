/**
 * @file /cryptron/secure.c
 *
 * @brief Functions for handling the secure data type.
 *
 * $Author: Ladar Levison $
 * $Website: http://lavabit.com $
 *
 */

#include "ies.h"

size_t cryptogram::cryptogram_key_length(const cryptogram_t *cryptogram)
{
    cryptogram_head_t *head = (cryptogram_head_t *)cryptogram;
    return head->length.key;
}

size_t cryptogram::cryptogram_mac_length(const cryptogram_t *cryptogram)
{
    cryptogram_head_t *head = (cryptogram_head_t *)cryptogram;
    return head->length.mac;
}

size_t cryptogram::cryptogram_body_length(const cryptogram_t *cryptogram)
{
    cryptogram_head_t *head = (cryptogram_head_t *)cryptogram;
    return head->length.body;
}

size_t cryptogram::cryptogram_data_sum_length(const cryptogram_t *cryptogram)
{
    cryptogram_head_t *head = (cryptogram_head_t *)cryptogram;
    return (head->length.key + head->length.mac + head->length.body);
}

size_t cryptogram::cryptogram_total_length(const cryptogram_t *cryptogram)
{
    cryptogram_head_t *head = (cryptogram_head_t *)cryptogram;
    return HEADSIZE + (head->length.key + head->length.mac + head->length.body);
}

unsigned char *cryptogram::cryptogram_key_data(const cryptogram_t *cryptogram)
{
    return (unsigned char *)cryptogram + HEADSIZE;
}

unsigned char *cryptogram::cryptogram_mac_data(const cryptogram_t *cryptogram)
{
    cryptogram_head_t *head = (cryptogram_head_t *)cryptogram;
    return (unsigned char *)cryptogram + (HEADSIZE + head->length.key + head->length.body);
}

unsigned char *cryptogram::cryptogram_body_data(const cryptogram_t *cryptogram)
{
    cryptogram_head_t *head = (cryptogram_head_t *)cryptogram;
    return (unsigned char *)cryptogram + (HEADSIZE + head->length.key);
}

cryptogram_t *cryptogram::cryptogram_alloc(size_t key, size_t mac, size_t body)
{
    cryptogram_t *cryptogram = (cryptogram_t *)::malloc(HEADSIZE + key + mac + body);
    if(cryptogram == NULL) {
        return NULL;
    }

    cryptogram_head_t *head = (cryptogram_head_t *)cryptogram;
    head->length.key = key;
    head->length.mac = mac;
    head->length.body = body;
    return cryptogram;
}

void cryptogram::cryptogram_free(cryptogram_t *cryptogram)
{
    ::free(cryptogram);
}
