// Copyright (c) 2014-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_COMMON_H
#define BITCOIN_CRYPTO_COMMON_H

//#if defined(HAVE_CONFIG_H)
//#include <config/bitcoin-config.h>
//#endif

#include <stdint.h>
#include <string.h>
#include <compat/endian.h>
#include <const/no_instance.h>

namespace latest_crypto {

uint16_t static inline ReadLE16(const unsigned char *ptr)
{
    uint16_t x;
    ::memcpy((char *)&x, ptr, 2);
    return endian::le16toh(x);
}

uint32_t static inline ReadLE32(const unsigned char *ptr)
{
    uint32_t x;
    ::memcpy((char *)&x, ptr, 4);
    return endian::le32toh(x);
}

uint64_t static inline ReadLE64(const unsigned char *ptr)
{
    uint64_t x;
    ::memcpy((char *)&x, ptr, 8);
    return endian::le64toh(x);
}

void static inline WriteLE16(unsigned char *ptr, uint16_t x)
{
    uint16_t v = endian::htole16(x);
    ::memcpy(ptr, (char *)&v, 2);
}

void static inline WriteLE32(unsigned char *ptr, uint32_t x)
{
    uint32_t v = endian::htole32(x);
    ::memcpy(ptr, (char *)&v, 4);
}

void static inline WriteLE64(unsigned char *ptr, uint64_t x)
{
    uint64_t v = endian::htole64(x);
    ::memcpy(ptr, (char *)&v, 8);
}

uint32_t static inline ReadBE32(const unsigned char *ptr)
{
    uint32_t x;
    ::memcpy((char *)&x, ptr, 4);
    return endian::be32toh(x);
}

uint64_t static inline ReadBE64(const unsigned char *ptr)
{
    uint64_t x;
    ::memcpy((char *)&x, ptr, 8);
    return endian::be64toh(x);
}

void static inline WriteBE32(unsigned char *ptr, uint32_t x)
{
    uint32_t v = endian::htobe32(x);
    ::memcpy(ptr, (char *)&v, 4);
}

void static inline WriteBE64(unsigned char *ptr, uint64_t x)
{
    uint64_t v = endian::htobe64(x);
    ::memcpy(ptr, (char *)&v, 8);
}

/** Return the smallest number n such that (x >> n) == 0 (or 64 if the highest bit in x is set. */
uint64_t static inline CountBits(uint64_t x)
{
#if HAVE_DECL___BUILTIN_CLZL
    if (sizeof(unsigned long) >= sizeof(uint64_t)) {
        return x ? 8 * sizeof(unsigned long) - __builtin_clzl(x) : 0;
    }
#endif
#if HAVE_DECL___BUILTIN_CLZLL
    if (sizeof(unsigned long long) >= sizeof(uint64_t)) {
        return x ? 8 * sizeof(unsigned long long) - __builtin_clzll(x) : 0;
    }
#endif
    int ret = 0;
    while (x) {
        x >>= 1;
        ++ret;
    }
    return ret;
}

// Lsb, Msb (32-bit)
using uindex_t = uint32_t;
class bitlsbmsb : private no_instance {
private:
    static uindex_t getnumbits_32(uindex_t val) {
        val=(val&0x55555555)+((val>>1)&0x55555555);
        val=(val&0x33333333)+((val>>2)&0x33333333);
        val=(val&0x0f0f0f0f)+((val>>4)&0x0f0f0f0f);
        val=(val&0x00ff00ff)+((val>>8)&0x00ff00ff);
        return (val&0x0000ffff)+((val>>16)&0x0000ffff);
    }
public:
    static uindex_t getLsb_32(uindex_t val) {
        uindex_t tmp=val;
        val|=(val<<1);
        val|=(val<<2);
        val|=(val<<4);
        val|=(val<<8);
        val|=(val<<16);
        return (tmp==0) ? 0: 32-getnumbits_32(val);
    }
    static uindex_t getMsb_32(uindex_t val) {
        uindex_t tmp=val;
        val|=(val>>1);
        val|=(val>>2);
        val|=(val>>4);
        val|=(val>>8);
        val|=(val>>16);
        return (tmp==0) ? 0: getnumbits_32(val)-1;
    }
};

} // namespace latest_crypto

#endif // BITCOIN_CRYPTO_COMMON_H
