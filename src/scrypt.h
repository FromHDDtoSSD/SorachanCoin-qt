
#ifndef SCRYPT_MINE_H
#define SCRYPT_MINE_H

#include <stdint.h>
#include <stdlib.h>

#include "util.h"
#include "net.h"

class bitscrypt : private no_instance
{
private:
#if defined (OPTIMIZED_SALSA) && ( defined (__x86_64__) || defined (__i386__) || defined(__arm__) )
    extern "C" static void scrypt_core(unsigned int *X, unsigned int *V);
#else
    static void xor_salsa8(unsigned int B[16], const unsigned int Bx[16]);
    static void scrypt_core(unsigned int *X, unsigned int *V);
#endif

    static uint256 scrypt_nosalt(const void *input, size_t inputlen, void *scratchpad);
    static uint256 scrypt(const void *data, size_t datalen, const void *salt, size_t saltlen, void *scratchpad);
    static uint256 scrypt_hash(const void *input, size_t inputlen);
    static uint256 scrypt_salted_hash(const void *input, size_t inputlen, const void *salt, size_t saltlen);

    static uint256 scrypt_salted_multiround_hash(const void *input, size_t inputlen, const void *salt, size_t saltlen, const unsigned int nRounds);

public:
    static uint256 scrypt_blockhash(const void *input);    
};

#endif
//@
