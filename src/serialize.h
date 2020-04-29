// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2020 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef BITCOIN_SERIALIZE_H
#define BITCOIN_SERIALIZE_H

#include <compat/endian.h>

#include <string>
#include <vector>
#include <prevector/prevector.h>
#include <prevector/prevector_s.h>
#include <algorithm>
#include <map>
#include <set>
#include <cassert>
#include <limits>
#include <cstring>
#include <cstdio>

#if defined __USE_MINGW_ANSI_STDIO
# undef __USE_MINGW_ANSI_STDIO // This constant forces MinGW to conduct stupid behavior
#endif
#include <inttypes.h>

#include <allocators.h>
#include <version.h>

class CScript;
class CDataStream;
class CAutoFile;

//
// no instance
//
class no_instance
{
private:
    no_instance(); // {}
    no_instance(const no_instance &); // {}
    no_instance(const no_instance &&); // {}
};

//
// Used to bypass the rule against non-const reference to temporary
// where it makes sense with wrappers such as CFlatData or CTxDB
//
template<typename T>
inline T &REF(const T &val)
{
    return const_cast<T &>(val);
}

//
// Used to acquire a non-const pointer "this" to generate bodies
// of const serialization operations from a template
//
template<typename T>
inline T *NCONST_PTR(const T *val)
{
    return const_cast<T *>(val);
}

//! Safely convert odd char pointer types to standard ones.
inline char *CharCast(char *c) { return c; }
inline char *CharCast(unsigned char *c) { return (char *)c; }
inline const char *CharCast(const char *c) { return c; }
inline const char *CharCast(const unsigned char *c) { return (const char *)c; }

/*
* Lowest-level serialization and conversion.
* @note Sizes of these types are verified in the tests
*/
enum _CINV_MSG_TYPE : int;
class ser_data : private no_instance
{
private:
    static inline uint32_t float_to_uint32(float s) { union { float x; uint32_t y; } tmp; tmp.x = s; return tmp.y; }
    static inline uint64_t double_to_uint64(double s) { union { double x; uint64_t y; } tmp; tmp.x = s; return tmp.y; }
    static inline float uint32_to_float(uint32_t s) { union { float x; uint32_t y; } tmp; tmp.y = s; return tmp.x; }
    static inline double uint64_to_double(uint64_t s) { union { double x; uint64_t y; } tmp; tmp.y = s; return tmp.x; }

    static inline uint8_t _htole(uint8_t s) { return s; }
    static inline uint16_t _htole(uint16_t s) { return ::htole16(s); }
    static inline uint32_t _htole(uint32_t s) { return ::htole32(s); }
    static inline uint64_t _htole(uint64_t s) { return ::htole64(s); }
    static inline uint8_t _htole(int8_t s) { return (uint8_t)s; }
    static inline uint16_t _htole(int16_t s) { return ::htole16((uint16_t)s); }
    static inline uint32_t _htole(int32_t s) { return ::htole32((uint32_t)s); }
    static inline uint64_t _htole(int64_t s) { return ::htole64((uint64_t)s); }
    static inline _CINV_MSG_TYPE _htole(_CINV_MSG_TYPE s) { return (_CINV_MSG_TYPE)::htole32((uint32_t)s); }
    static inline uint32_t _htole(float s) { uint32_t tmp = float_to_uint32(s); return ::htole32(tmp); }
    static inline uint64_t _htole(double s) { uint64_t tmp = double_to_uint64(s); return ::htole64(tmp); }

    static inline uint8_t _htobe(uint8_t s) { return s; }
    static inline uint16_t _htobe(uint16_t s) { return ::htobe16(s); }
    static inline uint32_t _htobe(uint32_t s) { return ::htobe32(s); }
    static inline uint64_t _htobe(uint64_t s) { return ::htobe64(s); }
    static inline uint8_t _htobe(int8_t s) { return (uint8_t)s; }
    static inline uint16_t _htobe(int16_t s) { return ::htobe16((uint16_t)s); }
    static inline uint32_t _htobe(int32_t s) { return ::htobe32((uint32_t)s); }
    static inline uint64_t _htobe(int64_t s) { return ::htobe64((uint64_t)s); }
    static inline _CINV_MSG_TYPE _htobe(_CINV_MSG_TYPE s) { return (_CINV_MSG_TYPE)::htobe32((uint32_t)s); }
    static inline uint32_t _htobe(float s) { uint32_t tmp = float_to_uint32(s); return ::htobe32(tmp); }
    static inline uint64_t _htobe(double s) { uint64_t tmp = double_to_uint64(s); return ::htobe64(tmp); }

    static inline uint8_t _letoh(uint8_t s) { return s; }
    static inline uint16_t _letoh(uint16_t s) { return ::le16toh(s); }
    static inline uint32_t _letoh(uint32_t s) { return ::le32toh(s); }
    static inline uint64_t _letoh(uint64_t s) { return ::le64toh(s); }
    static inline uint8_t _letoh(int8_t s) { return (uint8_t)s; }
    static inline uint16_t _letoh(int16_t s) { return ::le16toh((uint16_t)s); }
    static inline uint32_t _letoh(int32_t s) { return ::le32toh((uint32_t)s); }
    static inline uint64_t _letoh(int64_t s) { return ::le64toh((uint64_t)s); }
    static inline _CINV_MSG_TYPE _letoh(_CINV_MSG_TYPE s) { return (_CINV_MSG_TYPE)::le32toh((uint32_t)s); }
    static inline float _letoh(uint32_t s, int) { uint32_t tmp = ::le32toh(s); return uint32_to_float(tmp); }
    static inline double _letoh(uint64_t s, int) { uint64_t tmp = ::le64toh(s); return uint64_to_double(tmp); }

    static inline uint8_t _betoh(uint8_t s) { return s; }
    static inline uint16_t _betoh(uint16_t s) { return ::be16toh(s); }
    static inline uint32_t _betoh(uint32_t s) { return ::be32toh(s); }
    static inline uint64_t _betoh(uint64_t s) { return ::be64toh(s); }
    static inline uint8_t _betoh(int8_t s) { return (uint8_t)s; }
    static inline uint16_t _betoh(int16_t s) { return ::be16toh((uint16_t)s); }
    static inline uint32_t _betoh(int32_t s) { return ::be32toh((uint32_t)s); }
    static inline uint64_t _betoh(int64_t s) { return ::be64toh((uint64_t)s); }
    static inline _CINV_MSG_TYPE _betoh(_CINV_MSG_TYPE s) { return (_CINV_MSG_TYPE)::be32toh((uint32_t)s); }
    static inline float _betoh(uint32_t s, int) { uint32_t tmp = ::be32toh(s); return uint32_to_float(tmp); }
    static inline double _betoh(uint64_t s, int) { uint64_t tmp = ::be64toh(s); return uint64_to_double(tmp); }

public:
    template<typename Stream, typename T> static inline void write(Stream &s, const T obj) {
        T tmp = _htole(obj);
        s.write((char *)&tmp, sizeof(T));
    }
    template<typename Stream, typename T> static inline void writebe(Stream &s, const T obj) {
        T tmp = _htobe(obj);
        s.write((char *)&tmp, sizeof(T));
    }
    template<typename Stream, typename T> static inline void read(Stream &s, T &obj) {
        T tmp;
        s.read((char *)&tmp, sizeof(T));
        obj = _letoh(tmp);
    }
    template<typename Stream, typename T> static inline void readbe(Stream &s, T &obj) {
        T tmp;
        s.read((char *)&tmp, sizeof(T));
        obj = _betoh(tmp);
    }

    //
    // _letoh(tmp, 0) or _betoh(tmp, 0): add dummy int type.
    // Note: conflict overload, float or double
    //
    template<typename Stream> static inline void read(Stream &s, float &obj) {
        uint32_t tmp;
        s.read((char *)&tmp, sizeof(uint32_t));
        obj = _letoh(tmp, 0);
    }
    template<typename Stream> static inline void readbe(Stream &s, float &obj) {
        uint32_t tmp;
        s.read((char *)&tmp, sizeof(uint32_t));
        obj = _betoh(tmp, 0);
    }
    template<typename Stream> static inline void read(Stream &s, double &obj) {
        uint64_t tmp;
        s.read((char *)&tmp, sizeof(uint64_t));
        obj = _letoh(tmp, 0);
    }
    template<typename Stream> static inline void readbe(Stream &s, double &obj) {
        uint64_t tmp;
        s.read((char *)&tmp, sizeof(uint64_t));
        obj = _betoh(tmp, 0);
    }
};

//
// Templates for serializing to anything that looks like a stream,
// i.e. anything that supports .read(char*, int) and .write(char*, int)
//
enum
{
    // primary actions
    SER_NETWORK = (1 << 0),
    SER_DISK = (1 << 1),
    SER_GETHASH = (1 << 2),

    // modifiers
    SER_SKIPSIG = (1 << 16),
    SER_BLOCKHEADERONLY = (1 << 17)
};

//
// Serialize types
//
#define WRITEDATA(s, obj)   ser_data::write(s, obj)
#define READDATA(s, obj)    ser_data::read(s, obj)

inline unsigned int GetSerializeSize(char a) { return sizeof(a); }
inline unsigned int GetSerializeSize(signed char a) { return sizeof(a); }
inline unsigned int GetSerializeSize(unsigned char a) { return sizeof(a); }
inline unsigned int GetSerializeSize(signed short a) { return sizeof(a); }
inline unsigned int GetSerializeSize(unsigned short a) { return sizeof(a); }
inline unsigned int GetSerializeSize(signed int a) { return sizeof(a); }
inline unsigned int GetSerializeSize(unsigned int a) { return sizeof(a); }
inline unsigned int GetSerializeSize(int64_t a) { return sizeof(a); }
inline unsigned int GetSerializeSize(uint64_t a) { return sizeof(a); }
inline unsigned int GetSerializeSize(float a) { return sizeof(a); }
inline unsigned int GetSerializeSize(double a) { return sizeof(a); }

template<typename Stream> inline void Serialize(Stream &s, char a) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream &s, signed char a) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream &s, unsigned char a) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream &s, signed short a) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream &s, unsigned short a) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream &s, signed int a) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream &s, unsigned int a) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream &s, int64_t a) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream &s, uint64_t a) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream &s, float a) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream &s, double a) { WRITEDATA(s, a); }

template<typename Stream> inline void Unserialize(Stream &s, char &a) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream &s, signed char &a) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream &s, unsigned char &a) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream &s, signed short &a) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream &s, unsigned short &a) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream &s, signed int &a) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream &s, unsigned int &a) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream &s, int64_t &a) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream &s, uint64_t &a) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream &s, float &a) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream &s, double &a) { READDATA(s, a); }

//
// other types of basic
//
inline unsigned int GetSerializeSize(_CINV_MSG_TYPE a) { return sizeof(a); }
template<typename Stream> inline void Serialize(Stream &s, _CINV_MSG_TYPE a) { WRITEDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream &s, _CINV_MSG_TYPE &a) { READDATA(s, a); }
inline unsigned int GetSerializeSize(bool a) { return sizeof(char); }
template<typename Stream> inline void Serialize(Stream &s, bool a) { char f = a; WRITEDATA(s, f); }
template<typename Stream> inline void Unserialize(Stream &s, bool &a) { char f; READDATA(s, f); a = f; }

//
// Forward declarations
//
#ifdef CSCRIPT_PREVECTOR_ENABLE
template<unsigned int N, typename T> inline unsigned int GetSerializeSize(const prevector<N, T> &v);
template<unsigned int N, typename Stream, typename T> inline void Serialize(Stream &os, const prevector<N, T> &v);
template<unsigned int N, typename Stream, typename T> inline void Unserialize(Stream &is, prevector<N, T> &v);

inline unsigned int GetSerializeSize(const CScript &v) { return ::GetSerializeSize((const prevector<PREVECTOR_N, uint8_t> &)v); }
template<typename Stream> inline void Serialize(Stream &os, const CScript &v) { ::Serialize(os, (const prevector<PREVECTOR_N, uint8_t> &)v); }
template<typename Stream> inline void Unserialize(Stream &is, CScript &v) { ::Unserialize(is, (prevector<PREVECTOR_N, uint8_t> &)v); }
#else
template<typename T, typename A> inline unsigned int GetSerializeSize(const std::vector<T, A> &v);
template<typename Stream, typename T, typename A> inline void Serialize(Stream &os, const std::vector<T, A> &v);
template<typename Stream, typename T, typename A> inline void Unserialize(Stream &is, std::vector<T, A> &v);

inline unsigned int GetSerializeSize(const CScript &v) { return ::GetSerializeSize((const std::vector<unsigned char> &)v); }
template<typename Stream> inline void Serialize(Stream &os, const CScript &v) { ::Serialize(os, (const std::vector<unsigned char> &)v); }
template<typename Stream> inline void Unserialize(Stream &is, CScript &v) { ::Unserialize(is, (std::vector<unsigned char> &)v); }
#endif

//
// Stream to Serialize or Unserialize
//
template<typename T> inline unsigned int GetSerializeSize(const T &a) { return a.GetSerializeSize(); }
template<typename Stream, typename T> inline void Serialize(Stream &os, const T &a) { a.Serialize(os); }
template<typename Stream, typename T> inline void Unserialize(Stream &is, T &a) { a.Unserialize(is); }


//
// Compact size
//  size <  253        -- 1 byte
//  size <= USHRT_MAX  -- 3 bytes  (253 + 2 bytes)
//  size <= UINT_MAX   -- 5 bytes  (254 + 4 bytes)
//  size >  UINT_MAX   -- 9 bytes  (255 + 8 bytes)
//
namespace compact_size
{
    const unsigned int MAX_SIZE = 0x02000000;

    class manage : private no_instance
    {
    public:
        static unsigned int GetSizeOfCompactSize(uint64_t nSize) {
            if(nSize < 253) {
                return sizeof(unsigned char);
            } else if(nSize <= (std::numeric_limits<unsigned short>::max)()) {
                return sizeof(unsigned char) + sizeof(unsigned short);
            } else if(nSize <= (std::numeric_limits<unsigned int>::max)()) {
                return sizeof(unsigned char) + sizeof(unsigned int);
            } else {
                return sizeof(unsigned char) + sizeof(uint64_t);
            }
        }

        template<typename Stream>
        static void WriteCompactSize(Stream &os, uint64_t nSize) {
            if(nSize < 253) {
                unsigned char chSize = (unsigned char)nSize;
                WRITEDATA(os, chSize);
            } else if(nSize <= (std::numeric_limits<unsigned short>::max)()) {
                unsigned char chSize = 253;
                unsigned short xSize = (unsigned short)nSize;
                WRITEDATA(os, chSize);
                WRITEDATA(os, xSize);
            } else if(nSize <= (std::numeric_limits<unsigned int>::max)()) {
                unsigned char chSize = 254;
                unsigned int xSize = (unsigned int)nSize;
                WRITEDATA(os, chSize);
                WRITEDATA(os, xSize);
            } else {
                unsigned char chSize = 255;
                uint64_t xSize = nSize;
                WRITEDATA(os, chSize);
                WRITEDATA(os, xSize);
            }
        }

        template<typename Stream>
        static uint64_t ReadCompactSize(Stream &is) {
            unsigned char chSize;
            READDATA(is, chSize);
            uint64_t nSizeRet = 0;
            if(chSize < 253) {
                nSizeRet = chSize;
            } else if(chSize == 253) {
                unsigned short xSize;
                READDATA(is, xSize);
                nSizeRet = xSize;
            } else if(chSize == 254) {
                unsigned int xSize;
                READDATA(is, xSize);
                nSizeRet = xSize;
            } else {
                uint64_t xSize;
                READDATA(is, xSize);
                nSizeRet = xSize;
            }
            if(nSizeRet > (uint64_t)MAX_SIZE) {
                throw std::ios_base::failure("compact_size::manage::ReadCompactSize() : size too large");
            }
            return nSizeRet;
        }
    };
}


//
// Wrapper for serializing arrays and POD.
//
class CFlatData
{
private:
    CFlatData(); // {}
    CFlatData(const CFlatData &); // {}
    CFlatData(const CFlatData &&); // {}
    CFlatData &operator=(const CFlatData &); // {}
    CFlatData &operator=(const CFlatData &&); // {}

    char *pbegin;
    const char *pend;
public:
    CFlatData(void *pbeginIn, void *pendIn) noexcept : pbegin((char *)pbeginIn), pend((const char *)pendIn) {}
    ~CFlatData() noexcept {}

    char *begin() noexcept { return pbegin; }
    const char *begin() const noexcept { return pbegin; }
    const char *end() const noexcept { return pend; }

    unsigned int GetSerializeSize() const noexcept {
        return (unsigned int)(pend - pbegin);
    }

    template<typename Stream>
    void Serialize(Stream &s) const noexcept {
        s.write(pbegin, (int)(pend - pbegin));
    }

    template<typename Stream>
    void Unserialize(Stream &s) noexcept {
        s.read(pbegin, pend - pbegin);
    }
};
#define FLATDATA(obj)  REF(CFlatData((char *)&(obj), (char *)&(obj) + sizeof(obj)))


//
// string, vector, prevector, pair, tuple, map, set Serialize types.
//

// string
template<typename C>
inline unsigned int GetSerializeSize(const std::basic_string<C> &str)
{
    return (unsigned int)(compact_size::manage::GetSizeOfCompactSize(str.size()) + str.size() * sizeof(str[0]));
}

template<typename Stream, typename C>
inline void Serialize(Stream &os, const std::basic_string<C> &str)
{
    //assert(sizeof(str[0]) == 1);
    compact_size::manage::WriteCompactSize(os, str.size() * sizeof(str[0]));
    if(!str.empty()) {
        os.write((char *)&str[0], (int)(str.size() * sizeof(str[0])));
    }
}

template<typename Stream, typename C>
inline void Unserialize(Stream &is, std::basic_string<C> &str)
{
    unsigned int nSize = (unsigned int)(compact_size::manage::ReadCompactSize(is));
    str.resize(nSize);
    if(nSize != 0) {
        is.read((char *)&str[0], nSize * sizeof(str[0]));
    }
}

// pair
template<typename K, typename T>
inline unsigned int GetSerializeSize(const std::pair<K, T> &item)
{
    return ::GetSerializeSize(item.first) + ::GetSerializeSize(item.second);
}

template<typename Stream, typename K, typename T>
inline void Serialize(Stream &os, const std::pair<K, T> &item)
{
    ::Serialize(os, item.first);
    ::Serialize(os, item.second);
}

template<typename Stream, typename K, typename T>
inline void Unserialize(Stream &is, std::pair<K, T> &item)
{
    ::Unserialize(is, item.first);
    ::Unserialize(is, item.second);
}

// vector
template<typename T, typename A>
inline unsigned int GetSerializeSize_impl(const std::vector<T, A> &v, const std::true_type &)
{
    return (unsigned int)(compact_size::manage::GetSizeOfCompactSize(v.size()) + v.size() * sizeof(T));
}

template<typename T, typename A>
inline unsigned int GetSerializeSize_impl(const std::vector<T, A> &v, const std::false_type &)
{
    unsigned int nSize = compact_size::manage::GetSizeOfCompactSize(v.size());
    for(typename std::vector<T, A>::const_iterator vi = v.begin(); vi != v.end(); ++vi)
    {
        nSize += ::GetSerializeSize((*vi));
    }
    return nSize;
}

template<typename T, typename A>
inline unsigned int GetSerializeSize(const std::vector<T, A> &v)
{
    return ::GetSerializeSize_impl(v, std::is_fundamental<T>());
}

template<typename Stream, typename T, typename A>
inline void Serialize_impl(Stream &os, const std::vector<T, A> &v, const std::true_type &)
{
    compact_size::manage::WriteCompactSize(os, v.size());
    if(!v.empty()) {
        os.write((char *)&v[0], (int)(v.size() * sizeof(T)));
    }
}

template<typename Stream, typename T, typename A>
inline void Serialize_impl(Stream &os, const std::vector<T, A> &v, const std::false_type &)
{
    compact_size::manage::WriteCompactSize(os, v.size());
    for(typename std::vector<T, A>::const_iterator vi = v.begin(); vi != v.end(); ++vi)
    {
        ::Serialize(os, (*vi));
    }
}

template<typename Stream, typename T, typename A>
inline void Serialize(Stream &os, const std::vector<T, A> &v)
{
    ::Serialize_impl(os, v, std::is_fundamental<T>());
}

template<typename Stream, typename T, typename A>
inline void Unserialize_impl(Stream &is, std::vector<T, A> &v, const std::true_type &)
{
    // Limit size per read so bogus size value won't cause out of memory
    v.clear();
    unsigned int nSize = (unsigned int)(compact_size::manage::ReadCompactSize(is));
    unsigned int i = 0;
    while(i < nSize)
    {
        unsigned int blk = (std::min)(nSize - i, (unsigned int)(1 + 4999999 / sizeof(T)));
        v.resize(i + blk);
        is.read((char *)&v[i], blk * sizeof(T));
        i += blk;
    }
}

template<typename Stream, typename T, typename A>
inline void Unserialize_impl(Stream &is, std::vector<T, A> &v, const std::false_type &)
{
    v.clear();
    unsigned int nSize = (unsigned int)(compact_size::manage::ReadCompactSize(is));
    unsigned int i = 0;
    unsigned int nMid = 0;
    while(nMid < nSize)
    {
        nMid += 5000000 / sizeof(T);
        if(nMid > nSize) {
            nMid = nSize;
        }
        v.resize(nMid);
        for(; i < nMid; ++i)
        {
            ::Unserialize(is, v[i]);
        }
    }
}

template<typename Stream, typename T, typename A>
inline void Unserialize(Stream &is, std::vector<T, A> &v)
{
    ::Unserialize_impl(is, v, std::is_fundamental<T>());
}

// prevector<N, T>
template<unsigned int N, typename T>
inline unsigned int GetSerializeSize_impl(const prevector<N, T> &v, const std::true_type &)
{
    return (unsigned int)(compact_size::manage::GetSizeOfCompactSize(v.size()) + v.size() * sizeof(T));
}

template<unsigned int N, typename T>
inline unsigned int GetSerializeSize_impl(const prevector<N, T> &v, const std::false_type &)
{
    unsigned int nSize = compact_size::manage::GetSizeOfCompactSize(v.size());
    for(typename prevector<N, T>::const_iterator vi = v.begin(); vi != v.end(); ++vi)
    {
        nSize += ::GetSerializeSize((*vi));
    }
    return nSize;
}

template<unsigned int N, typename T>
inline unsigned int GetSerializeSize(const prevector<N, T> &v)
{
    return ::GetSerializeSize_impl(v, std::is_fundamental<T>());
}

template<unsigned int N, typename Stream, typename T>
inline void Serialize_impl(Stream &os, const prevector<N, T> &v, const std::true_type &)
{
    compact_size::manage::WriteCompactSize(os, v.size());
    if(!v.empty()) {
        os.write((char *)&v[0], (int)(v.size() * sizeof(T)));
    }
}

template<unsigned int N, typename Stream, typename T>
inline void Serialize_impl(Stream &os, const prevector<N, T> &v, const std::false_type &)
{
    compact_size::manage::WriteCompactSize(os, v.size());
    for(typename prevector<N, T>::const_iterator vi = v.begin(); vi != v.end(); ++vi)
    {
        ::Serialize(os, (*vi));
    }
}

template<unsigned int N, typename Stream, typename T>
inline void Serialize(Stream &os, const prevector<N, T> &v)
{
    ::Serialize_impl(os, v, std::is_fundamental<T>());
}

template<unsigned int N, typename Stream, typename T>
inline void Unserialize_impl(Stream &is, prevector<N, T> &v, const std::true_type &)
{
    // Limit size per read so bogus size value won't cause out of memory
    v.clear();
    unsigned int nSize = (unsigned int)(compact_size::manage::ReadCompactSize(is));
    unsigned int i = 0;
    while(i < nSize)
    {
        unsigned int blk = (std::min)(nSize - i, (unsigned int)(1 + 4999999 / sizeof(T)));
        v.resize(i + blk);
        is.read((char *)&v[i], blk * sizeof(T));
        i += blk;
    }
}

template<unsigned int N, typename Stream, typename T>
inline void Unserialize_impl(Stream &is, prevector<N, T> &v, const std::false_type &)
{
    v.clear();
    unsigned int nSize = (unsigned int)(compact_size::manage::ReadCompactSize(is));
    unsigned int i = 0;
    unsigned int nMid = 0;
    while(nMid < nSize)
    {
        nMid += 5000000 / sizeof(T);
        if(nMid > nSize) {
            nMid = nSize;
        }
        v.resize(nMid);
        for(; i < nMid; ++i)
        {
            ::Unserialize(is, v[i]);
        }
    }
}

template<unsigned int N, typename Stream, typename T>
inline void Unserialize(Stream &is, prevector<N, T> &v)
{
    ::Unserialize_impl(is, v, std::is_fundamental<T>());
}

// prevector_s<N, T>
template<unsigned int N, typename T>
inline unsigned int GetSerializeSize_impl(const prevector_s<N, T> &v, const std::true_type &)
{
    return (unsigned int)(compact_size::manage::GetSizeOfCompactSize(v.size()) + v.size() * sizeof(T));
}

template<unsigned int N, typename T>
inline unsigned int GetSerializeSize_impl(const prevector_s<N, T> &v, const std::false_type &)
{
    unsigned int nSize = compact_size::manage::GetSizeOfCompactSize(v.size());
    for(typename prevector_s<N, T>::const_iterator vi = v.begin(); vi != v.end(); ++vi)
    {
        nSize += ::GetSerializeSize((*vi));
    }
    return nSize;
}

template<unsigned int N, typename T>
inline unsigned int GetSerializeSize(const prevector_s<N, T> &v)
{
    return ::GetSerializeSize_impl(v, std::is_fundamental<T>());
}

template<unsigned int N, typename Stream, typename T>
inline void Serialize_impl(Stream &os, const prevector_s<N, T> &v, const std::true_type &)
{
    compact_size::manage::WriteCompactSize(os, v.size());
    if(! v.empty()) {
        typename prevector_s<N, T>::const_raw_pointer ptr = v.data();
        os.write((const char *)((const T *)ptr), (int)(v.size() * sizeof(T)));
    }
}

template<unsigned int N, typename Stream, typename T>
inline void Serialize_impl(Stream &os, const prevector_s<N, T> &v, const std::false_type &)
{
    compact_size::manage::WriteCompactSize(os, v.size());
    for(typename prevector_s<N, T>::const_iterator vi = v.begin(); vi != v.end(); ++vi)
    {
        ::Serialize(os, (*vi));
    }
}

template<unsigned int N, typename Stream, typename T>
inline void Serialize(Stream &os, const prevector_s<N, T> &v)
{
    ::Serialize_impl(os, v, std::is_fundamental<T>());
}

template<unsigned int N, typename Stream, typename T>
inline void Unserialize_impl(Stream &is, prevector_s<N, T> &v, const std::true_type &)
{
    // Limit size per read so bogus size value won't cause out of memory
    v.clear();
    unsigned int nSize = (unsigned int)(compact_size::manage::ReadCompactSize(is));
    unsigned int i = 0;
    while(i < nSize)
    {
        unsigned int blk = (std::min)(nSize - i, (unsigned int)(1 + 4999999 / sizeof(T)));
        v.resize(i + blk);
        typename prevector_s<N, T>::raw_pointer ptr = v.data();
        is.read((char *)((T *)ptr + i), blk * sizeof(T));
        i += blk;
    }
}

template<unsigned int N, typename Stream, typename T>
inline void Unserialize_impl(Stream &is, prevector_s<N, T> &v, const std::false_type &)
{
    v.clear();
    unsigned int nSize = (unsigned int)(compact_size::manage::ReadCompactSize(is));
    unsigned int i = 0;
    unsigned int nMid = 0;
    while(nMid < nSize)
    {
        nMid += 5000000 / sizeof(T);
        if(nMid > nSize) {
            nMid = nSize;
        }
        v.resize(nMid);
        for(; i < nMid; ++i)
        {
            typename prevector_s<N, T>::raw_pointer ptr = v.data();
            ::Unserialize(is, *((T *)ptr + i));
        }
    }
}

template<unsigned int N, typename Stream, typename T>
inline void Unserialize(Stream &is, prevector_s<N, T> &v)
{
    ::Unserialize_impl(is, v, std::is_fundamental<T>());
}

// tuple<3>
template<typename T0, typename T1, typename T2>
inline unsigned int GetSerializeSize(const std::tuple<T0, T1, T2> &item)
{
    unsigned int nSize = 0;
    nSize += ::GetSerializeSize(std::get<0>(item));
    nSize += ::GetSerializeSize(std::get<1>(item));
    nSize += ::GetSerializeSize(std::get<2>(item));
    return nSize;
}

template<typename Stream, typename T0, typename T1, typename T2>
inline void Serialize(Stream &os, const std::tuple<T0, T1, T2> &item)
{
    ::Serialize(os, std::get<0>(item));
    ::Serialize(os, std::get<1>(item));
    ::Serialize(os, std::get<2>(item));
}

template<typename Stream, typename T0, typename T1, typename T2>
inline void Unserialize(Stream &is, std::tuple<T0, T1, T2> &item)
{
    ::Unserialize(is, std::get<0>(item));
    ::Unserialize(is, std::get<1>(item));
    ::Unserialize(is, std::get<2>(item));
}

// tuple<4>
template<typename T0, typename T1, typename T2, typename T3>
inline unsigned int GetSerializeSize(const std::tuple<T0, T1, T2, T3> &item)
{
    unsigned int nSize = 0;
    nSize += ::GetSerializeSize(std::get<0>(item));
    nSize += ::GetSerializeSize(std::get<1>(item));
    nSize += ::GetSerializeSize(std::get<2>(item));
    nSize += ::GetSerializeSize(std::get<3>(item));
    return nSize;
}

template<typename Stream, typename T0, typename T1, typename T2, typename T3>
inline void Serialize(Stream &os, const std::tuple<T0, T1, T2, T3> &item)
{
    ::Serialize(os, std::get<0>(item));
    ::Serialize(os, std::get<1>(item));
    ::Serialize(os, std::get<2>(item));
    ::Serialize(os, std::get<3>(item));
}

template<typename Stream, typename T0, typename T1, typename T2, typename T3>
inline void Unserialize(Stream &is, std::tuple<T0, T1, T2, T3> &item)
{
    ::Unserialize(is, std::get<0>(item));
    ::Unserialize(is, std::get<1>(item));
    ::Unserialize(is, std::get<2>(item));
    ::Unserialize(is, std::get<3>(item));
}

// map
template<typename K, typename T, typename Pred, typename A>
inline unsigned int GetSerializeSize(const std::map<K, T, Pred, A> &m)
{
    unsigned int nSize = compact_size::manage::GetSizeOfCompactSize(m.size());
    for(typename std::map<K, T, Pred, A>::const_iterator mi = m.begin(); mi != m.end(); ++mi)
    {
        nSize += ::GetSerializeSize((*mi));
    }
    return nSize;
}

template<typename Stream, typename K, typename T, typename Pred, typename A>
inline void Serialize(Stream &os, const std::map<K, T, Pred, A> &m)
{
    compact_size::manage::WriteCompactSize(os, m.size());
    for(typename std::map<K, T, Pred, A>::const_iterator mi = m.begin(); mi != m.end(); ++mi)
    {
        ::Serialize(os, (*mi));
    }
}

template<typename Stream, typename K, typename T, typename Pred, typename A>
inline void Unserialize(Stream &is, std::map<K, T, Pred, A> &m)
{
    m.clear();
    unsigned int nSize = (unsigned int)(compact_size::manage::ReadCompactSize(is));
    typename std::map<K, T, Pred, A>::iterator mi = m.begin();
    for(unsigned int i = 0; i < nSize; ++i)
    {
        std::pair<K, T> item;
        ::Unserialize(is, item);
        mi = m.insert(mi, item);
    }
}

// set
template<typename K, typename Pred, typename A>
inline unsigned int GetSerializeSize(const std::set<K, Pred, A> &m)
{
    unsigned int nSize = compact_size::manage::GetSizeOfCompactSize(m.size());
    for(typename std::set<K, Pred, A>::const_iterator it = m.begin(); it != m.end(); ++it)
    {
        nSize += ::GetSerializeSize((*it));
    }
    return nSize;
}

template<typename Stream, typename K, typename Pred, typename A>
inline void Serialize(Stream &os, const std::set<K, Pred, A> &m)
{
    compact_size::manage::WriteCompactSize(os, m.size());
    for(typename std::set<K, Pred, A>::const_iterator it = m.begin(); it != m.end(); ++it)
    {
        ::Serialize(os, (*it));
    }
}

template<typename Stream, typename K, typename Pred, typename A>
inline void Unserialize(Stream &is, std::set<K, Pred, A> &m)
{
    m.clear();
    unsigned int nSize = compact_size::manage::ReadCompactSize(is);
    typename std::set<K, Pred, A>::iterator it = m.begin();
    for(unsigned int i = 0; i < nSize; ++i)
    {
        K key;
        ::Unserialize(is, key);
        it = m.insert(it, key);
    }
}


//
// Support for nType and nVersion
//
class CTypeVersion
{
private:
    CTypeVersion(); // {}
    // CTypeVersion(const CTypeVersion &); // {}
    CTypeVersion &operator=(const CTypeVersion &); // {}
    CTypeVersion &operator=(const CTypeVersion &&); // {}

protected:
    int nType;
    int nVersion;
    explicit CTypeVersion(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {}
    ~CTypeVersion() {} // unused virtual

public:
    void SetType(int n) { nType = n; }
    void AddType(int n) { nType |= n; }
    int GetType() const { return nType; }
    void SetVersion(int n) { nVersion = n; }
    int GetVersion() const { return nVersion; }
};

class CTypeVersionBehave
{
public:
    CTypeVersionBehave() : nType(0), nVersion(0) {}
    int nType;
    int nVersion;
    void AddType(int) {}
    void SetType(int) {}
    void SetVersion(int) {}
};

//
// A, Support for IMPLEMENT_SERIALIZE and READWRITE macro
//
class CSerActionGetSerializeSize {};
class CSerActionSerialize {};
class CSerActionUnserialize {};

class CSerCtr {
    CSerCtr(); // {}
    CSerCtr(const CSerCtr &); // {}
    CSerCtr(const CSerCtr &&); // {}
    CSerCtr &operator=(const CSerCtr &); // {}
    CSerCtr &operator=(const CSerCtr &&); // {}
    const bool fGetSize;
    const bool fWrite;
    const bool fRead;
public:
    explicit CSerCtr(CSerActionGetSerializeSize) noexcept : fGetSize(true), fWrite(false), fRead(false) {}
    explicit CSerCtr(CSerActionSerialize) noexcept : fGetSize(false), fWrite(true), fRead(false) {}
    explicit CSerCtr(CSerActionUnserialize) noexcept : fGetSize(false), fWrite(false), fRead(true) {}
    bool isGetSize() const noexcept {
        return fGetSize;
    }
    bool isRead() const noexcept {
        return fRead;
    }
    bool isWrite() const noexcept {
        return fWrite;
    }
};

#define IMPLEMENT_SERIALIZE(statements)         \
public:                                         \
    unsigned int GetSerializeSize(int=0, int=0) const \
    {                                           \
        int nType=0, nVersion=0;                \
        assert(nType == 0 && nVersion == 0);    \
        CSerActionGetSerializeSize ser_action;  \
        CSerCtr ser_ctr(ser_action);            \
        unsigned int nSerSize = 0;              \
        struct ser_streamplaceholder {          \
            int unused;                         \
            ser_streamplaceholder():unused(0){} \
        } s;                                    \
        {statements}                            \
        return nSerSize;                        \
    }                                           \
    template<typename Stream>                   \
    void Serialize(Stream &s, int=0, int=0) const    \
    {                                           \
        int nType=0, nVersion=0;                \
        assert(nType == 0 && nVersion == 0);    \
        CSerActionSerialize ser_action;         \
        CSerCtr ser_ctr(ser_action);            \
        unsigned int nSerSize = 0;              \
        {statements}                            \
    }                                           \
    template<typename Stream>                   \
    void Unserialize(Stream &s, int=0, int=0)   \
    {                                           \
        int nType=0, nVersion=0;                \
        assert(nType == 0 && nVersion == 0);    \
        CSerActionUnserialize ser_action;       \
        CSerCtr ser_ctr(ser_action);            \
        unsigned int nSerSize = 0;              \
        {statements}                            \
    }

#define READWRITE(obj)      (nSerSize += imp_ser::manage::SerReadWrite(s, (obj), ser_action))

namespace imp_ser    // important
{
    class manage : private no_instance
    {
    public:
        template<typename Stream, typename T>
        static unsigned int SerReadWrite(Stream &s, const T &obj, CSerActionGetSerializeSize) {
            return ::GetSerializeSize(obj);
        }

        template<typename Stream, typename T>
        static unsigned int SerReadWrite(Stream &s, const T &obj, CSerActionSerialize) {
            ::Serialize(s, obj);
            return 0;
        }

        template<typename Stream, typename T>
        static unsigned int SerReadWrite(Stream &s, T &obj, CSerActionUnserialize) {
            ::Unserialize(s, obj);
            return 0;
        }
    };
}

//
// B, Double ended buffer combining vector and stream-like interfaces.
//
// >> and << read and write unformatted data using the above serialization templates.
// Fills with data in linear time; some stringstream implementations take N^2 time.
//
typedef std::vector<char, zero_after_free_allocator<char> > CSerializeData;

#ifdef CSCRIPT_PREVECTOR_ENABLE
typedef prevector<PREVECTOR_N, uint8_t> datastream_vector;
typedef prevector<PREVECTOR_N, int8_t> datastream_signed_vector;
#else
typedef std::vector<uint8_t> datastream_vector;
typedef std::vector<int8_t> datastream_signed_vector;
#endif

class CDataStream : public CTypeVersionBehave
{
private:
    CDataStream(); // {}
    // CDataStream(const CDataStream &); // {}
    // CDataStream &operator=(const CDataStream &); // {}
    // CDataStream &operator=(const CDataStream &&); // {}

    unsigned int nReadPos;
    short state;
    short exceptmask;

protected:
    typedef CSerializeData vector_type;
    vector_type vch;

public:
    typedef vector_type::allocator_type   allocator_type;
    typedef vector_type::size_type        size_type;
    typedef vector_type::difference_type  difference_type;
    typedef vector_type::reference        reference;
    typedef vector_type::const_reference  const_reference;
    typedef vector_type::value_type       value_type;
    typedef vector_type::iterator         iterator;
    typedef vector_type::const_iterator   const_iterator;
    typedef vector_type::reverse_iterator reverse_iterator;

    explicit CDataStream(int = 0, int = 0) noexcept {
        Init();
    }

    CDataStream(const_iterator pbegin, const_iterator pend, int = 0, int = 0) : vch(pbegin, pend) {
        Init();
    }

#if !defined(_MSC_VER) || _MSC_VER >= 1300
    CDataStream(const char *pbegin, const char *pend, int = 0, int = 0) : vch(pbegin, pend) {
        Init();
    }
#endif

    CDataStream(const vector_type &vchIn, int = 0, int = 0) : vch(vchIn.begin(), vchIn.end()) {
        Init();
    }

    CDataStream(const datastream_signed_vector &vchIn, int = 0, int = 0) : vch(vchIn.begin(), vchIn.end()) {
        Init();
    }

    CDataStream(const datastream_vector &vchIn, int = 0, int = 0) : vch(vchIn.begin(), vchIn.end()) {
        Init();
    }

    void Init(int = 0, int = 0) noexcept {
        nReadPos = 0;
        state = 0;
        exceptmask = std::ios::badbit | std::ios::failbit;
    }

    CDataStream &operator+=(const CDataStream &b) {
        vch.insert(this->vch.end(), b.begin(), b.end());
        return *this;
    }

    std::string str() const noexcept {
        return (std::string(begin(), end()));
    }

    //
    // Vector subset
    //
    void clear() noexcept { vch.clear(); nReadPos = 0; }
    const_iterator begin() const noexcept { return vch.begin() + nReadPos; }
    iterator begin() noexcept { return vch.begin() + nReadPos; }
    const_iterator end() const noexcept { return vch.end(); }
    iterator end() noexcept { return vch.end(); }
    size_type size() const noexcept { return vch.size() - nReadPos; }
    bool empty() const noexcept { return vch.size() == nReadPos; }
    void resize(size_type n, value_type c = 0) { vch.resize(n + nReadPos, c); }
    void reserve(size_type n) { vch.reserve(n + nReadPos); }
    const_reference operator[](size_type pos) const noexcept { return vch[pos + nReadPos]; }
    reference operator[](size_type pos) noexcept { return vch[pos + nReadPos]; }
    iterator insert(iterator it, const char &x = char()) { return vch.insert(it, x); }
    void insert(iterator it, size_type n, const char &x) { vch.insert(it, n, x); }

#ifdef _MSC_VER
    void insert(iterator it, const_iterator first, const_iterator last) noexcept {
        assert(last - first >= 0);
        if(it == vch.begin() + nReadPos && (unsigned int)(last - first) <= nReadPos) {
            // special case for inserting at the front when there's room
            nReadPos -= (unsigned int)(last - first);
            ::memcpy(&this->vch[nReadPos], &first[0], last - first);
        } else {
            vch.insert(it, first, last);
        }
    }
#else
    void insert(iterator it, std::vector<char>::const_iterator first, std::vector<char>::const_iterator last) noexcept {
        assert(last - first >= 0);
        if(it == vch.begin() + nReadPos && (unsigned int)(last - first) <= nReadPos) {
            // special case for inserting at the front when there's room
            nReadPos -= (last - first);
            ::memcpy(&vch[nReadPos], &first[0], last - first);
        } else {
            vch.insert(it, first, last);
        }
    }
#endif

#if !defined(_MSC_VER) || _MSC_VER >= 1300
    void insert(iterator it, const char *first, const char *last) noexcept {
        assert(last - first >= 0);
        if(it == vch.begin() + nReadPos && (unsigned int)(last - first) <= nReadPos) {
            // special case for inserting at the front when there's room
            nReadPos -= (unsigned int)(last - first);
            ::memcpy(&vch[nReadPos], &first[0], last - first);
        } else {
            vch.insert(it, first, last);
        }
    }
#endif

    iterator erase(iterator it) noexcept {
        if(it == vch.begin() + nReadPos) {
            // special case for erasing from the front
            if(++nReadPos >= vch.size()) {
                // whenever we reach the end, we take the opportunity to clear the buffer
                nReadPos = 0;
                return vch.erase(vch.begin(), vch.end());
            }
            return vch.begin() + nReadPos;
        } else {
            return vch.erase(it);
        }
    }

    iterator erase(iterator first, iterator last) noexcept {
        if(first == vch.begin() + nReadPos) {
            // special case for erasing from the front
            if(last == vch.end()) {
                nReadPos = 0;
                return vch.erase(vch.begin(), vch.end());
            } else {
                this->nReadPos = (unsigned int)(last - vch.begin());
                return last;
            }
        } else {
            return vch.erase(first, last);
        }
    }

    void Compact() noexcept {
        vch.erase(vch.begin(), vch.begin() + nReadPos);
        nReadPos = 0;
    }

    bool Rewind(size_type n) noexcept {
        // Rewind by n characters if the buffer hasn't been compacted yet
        if(n > nReadPos) {
            return false;
        }
        nReadPos -= (unsigned int)n;
        return true;
    }

    //
    // Stream subset
    //
    void setstate(short bits, const char *psz) {
        state |= bits;
        if(state & exceptmask) {
            throw std::ios_base::failure(psz);
        }
    }

    bool eof() const noexcept { return size() == 0; }
    bool fail() const noexcept { return (state & (std::ios::badbit | std::ios::failbit)) != 0; }
    bool good() const noexcept { return !eof() && (state == 0); }
    void clear(short n) noexcept { state = n; }  // name conflict with vector clear()
    short exceptions() noexcept { return exceptmask; }
    short exceptions(short mask) { short prev = exceptmask; exceptmask = mask; setstate(0, "CDataStream"); return prev; }
    CDataStream *rdbuf() noexcept { return this; }
    int in_avail() noexcept { return (int)(size()); }

    CDataStream &read(char *pch, int nSize) {
        // Read from the beginning of the buffer
        assert(nSize >= 0);
        unsigned int nReadPosNext = nReadPos + nSize;
        if(nReadPosNext >= vch.size()) {
            if(nReadPosNext > vch.size()) {
                pch ? setstate(std::ios::failbit, "CDataStream::read() : end of data") : setstate(std::ios::failbit, "CDataStream::ignore() : end of data");
                if(pch) {
                    ::memset(pch, 0, nSize);
                    nSize = (int)(vch.size() - nReadPos);
                }
            }
            pch ? ::memcpy(pch, &vch[nReadPos], nSize) : 0;
            nReadPos = 0;
            vch.clear();
        } else {
            pch ? ::memcpy(pch, &vch[nReadPos], nSize) : 0;
            nReadPos = nReadPosNext;
        }
        return *this;
    }

    CDataStream &ignore(int nSize) {
        // Ignore from the beginning of the buffer
        return read(nullptr, nSize);
    }

    CDataStream &write(const char *pch, int nSize) {
        // Write to the end of the buffer
        assert(nSize >= 0);
        vch.insert(vch.end(), pch, pch + nSize);
        return *this;
    }

    template<typename Stream>
    void Serialize(Stream &s) const noexcept {
        // Special case: stream << stream concatenates like stream += stream
        if(! vch.empty()) {
            s.write((char *)&vch[0], vch.size() * sizeof(vch[0]));
        }
    }

    template<typename T>
    unsigned int GetSerializeSize(const T &obj) noexcept {
        // Tells the size of the object if serialized to this stream
        return ::GetSerializeSize(obj);
    }

    //
    // << and >> write and read (Serialize, Unserialize)
    //
    template<typename T>
    CDataStream &operator<<(const T &obj) {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return *this;
    }

    template<typename T>
    CDataStream &operator >> (T &obj) {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return *this;
    }

    void GetAndClear(CSerializeData &data) noexcept {
        this->vch.swap(data);
        CSerializeData().swap(vch);
    }

    //
    // operator+ cp
    //
    friend CDataStream operator+(const CDataStream &a, const CDataStream &b) {
        debugcs::instance() << "cp CDataStream operator+(const CDataStream &a, const CDataStream &b)" << debugcs::endl();
        CDataStream ret(a);
        ret += b;
        return ret;
    }
};

//
// move stream by pointer.
//
// Note: Forming an object by "std::move" turned out to take a long time to process.
// For this reason, a pointers are used for move to an object.
//
class CMoveStream final : public CDataStream
{
private:
    CMoveStream(); // {}
    // CMoveStream(const CMoveStream &); // {}
    // CMoveStream(const CMoveStream &&); // {}
    CMoveStream &operator=(const CMoveStream &); // {}
    // CMoveStream &operator=(const CMoveStream &&); // {}

    typedef prevector<PREVECTOR_N, void *> move_vector;
    move_vector mch;

public:
    explicit CMoveStream(int = 0, int = 0) noexcept : CDataStream(0, 0) {
        Init();
    }

    CMoveStream(const_iterator pbegin, const_iterator pend, int = 0, int = 0) : CDataStream(pbegin, pend) {
        Init();
    }

#if !defined(_MSC_VER) || _MSC_VER >= 1300
    CMoveStream(const char *pbegin, const char *pend, int = 0, int = 0) : CDataStream(pbegin, pend) {
        Init();
    }
#endif

    CMoveStream(const vector_type &vchIn, int = 0, int = 0) : CDataStream(vchIn) {
        Init();
    }

    CMoveStream(const datastream_signed_vector &vchIn, int = 0, int = 0) : CDataStream(vchIn) {
        Init();
    }

    CMoveStream(const datastream_vector &vchIn, int = 0, int = 0) : CDataStream(vchIn) {
        Init();
    }

    void Init(int = 0, int = 0) noexcept {
        CDataStream::Init(0, 0);
    }

    //
    // << and >> write and read (Serialize, Unserialize)
    //
    template<typename T>
    CMoveStream &operator<<(const T &obj) {
        // Serialize to this stream
        // debugcs::instance() << "CMoveStream: CMoveStream &operator<<(const T &obj)" << debugcs::endl();
        CDataStream::operator<<(obj);
        return *this;
    }

    template<typename T>
    CMoveStream &operator<<(const T *&obj) {
        // Serialize to this stream by pointer
        mch.push_back((void *)obj);
        return *this;
    }

    template<typename T>
    CMoveStream &operator >> (T &obj) {
        // Unserialize from this stream
        CDataStream::operator >> (obj);
        return *this;
    }

    template<typename T>
    CMoveStream &operator >> (T *&obj) {
        // Unserialize from this stream by pointer
        obj = (T *)mch.front();
        mch.erase(mch.begin());
        return *this;
    }

    //
    // operator+ mv
    //
    friend CMoveStream operator+(const CMoveStream &&a, const CMoveStream &&b) {
        debugcs::instance() << "CMoveStream operator+(const CMoveStream &&a, const CMoveStream &&b)" << debugcs::endl();
        CMoveStream ret(std::move(a));
        ret += std::move(b);
        return ret;
    }
};

// replace from CDataStream to CMoveStream
#define CDataStream CMoveStream

//
// C, RAII wrapper for FILE *.
// D, Wrapper around a FILE * that implements a ring buffer to deserialize from.
// It guarantees the ability to rewind a given number of bytes.
//
// Will automatically close the file when it goes out of scope if not null.
// If you're returning the file pointer, return file.release().
// If you need to close the file early, use file.fclose() instead of fclose(file).
//
#ifdef BUFFER_PREVECTOR_ENABLE
typedef prevector<PREVECTOR_BUFFER_N, char> bufferedfile_vector;
#else
typedef std::vector<char> bufferedfile_vector;
#endif
class CBufferedFile
{
private:
    CBufferedFile(); // {}
    // CBufferedFile(const CBufferedFile &); // {}
    // CBufferedFile(const CBufferedFile &&); // {}
    // CBufferedFile &operator=(const CBufferedFile &); // {}
    // CBufferedFile &operator=(const CBufferedFile &&); // {}

    FILE *src;                  // source file
    uint64_t nSrcPos;           // how many bytes have been read from source
    uint64_t nReadPos;          // how many bytes have been read from this
    uint64_t nReadLimit;        // up to which position we're allowed to read
    uint64_t nRewind;           // how many bytes we guarantee to rewind
    bufferedfile_vector vchBuf; // the buffer

    short state;
    short exceptmask;

    void setstate(short bits, const char *psz) {
        state |= bits;
        if(state & exceptmask) {
            throw std::ios_base::failure(psz);
        }
    }

    // read data from the source to fill the buffer
    bool Fill() {
        unsigned int pos = (unsigned int)(nSrcPos % vchBuf.size());
        unsigned int readNow = (unsigned int)(vchBuf.size() - pos);
        unsigned int nAvail = (unsigned int)(vchBuf.size() - (nSrcPos - nReadPos) - nRewind);
        if(nAvail < readNow) {
            readNow = nAvail;
        }
        if(readNow == 0) {
            return false;
        }

        size_t read = ::fread((void *)&vchBuf[pos], sizeof(char), readNow, src) * sizeof(char);
        if(read == 0) {
            setstate(std::ios_base::failbit, feof(src) ? "CBufferedFile::Fill : end of file" : "CBufferedFile::Fill : fread failed");
            return false;
        } else {
            nSrcPos += read;
            return true;
        }
    }

public:
    CBufferedFile(FILE *fileIn, uint64_t nBufSize = PREVECTOR_BUFFER_N, uint64_t nRewindIn = 0) :
        src(fileIn), nSrcPos(0), nReadPos(0), nReadLimit((std::numeric_limits<uint64_t>::max)()), nRewind(nRewindIn), vchBuf(nBufSize, 0),
        state(0), exceptmask(std::ios_base::badbit | std::ios_base::failbit) {}

    // check whether no error occurred
    bool good() const noexcept {
        return state == 0;
    }

    // check whether we're at the end of the source file
    bool eof() const noexcept {
        return nReadPos == nSrcPos && ::feof(this->src);
    }

    // read a number of bytes
    CBufferedFile &read(char *pch, size_t nSize) {
        if(nSize + nReadPos > nReadLimit) {
            throw std::ios_base::failure("Read attempted past buffer limit");
        }
        if(nSize + nRewind > vchBuf.size()) {
            throw std::ios_base::failure("Read larger than buffer size");
        }

        while(nSize > 0)
        {
            if(nReadPos == nSrcPos) {
                Fill();
            }

            unsigned int pos = (unsigned int)(nReadPos % vchBuf.size());
            size_t nNow = nSize;
            if(nNow + pos > vchBuf.size()) {
                nNow = vchBuf.size() - pos;
            }
            if(nNow + nReadPos > nSrcPos) {
                nNow = (size_t)(nSrcPos - nReadPos);
            }
            ::memcpy(pch, &vchBuf[pos], nNow);
            nReadPos += nNow;
            pch += nNow;
            nSize -= nNow;
        }
        return *this;
    }

    // return the current reading position
    uint64_t GetPos() const noexcept {
        return nReadPos;
    }

    // rewind to a given reading position
    bool SetPos(uint64_t nPos) noexcept {
        nReadPos = nPos;
        if(nReadPos + nRewind < nSrcPos) {
            nReadPos = nSrcPos - nRewind;
            return false;
        } else if(nReadPos > nSrcPos) {
            nReadPos = nSrcPos;
            return false;
        } else {
            return true;
        }
    }

    bool Seek(uint64_t nPos) noexcept {
        long nLongPos = (long)nPos;
        if(nPos != (uint64_t)nLongPos) {    // If nPos variable type size is larger than long, it is invalid(false).
            return false;
        }

        if(::fseek(src, nLongPos, SEEK_SET)) {
            return false;
        }
        nLongPos = ::ftell(src);
        nSrcPos = nLongPos;
        nReadPos = nLongPos;
        state = 0;
        return true;
    }

    // prevent reading beyond a certain position
    // no argument removes the limit
    bool SetLimit(uint64_t nPos = (std::numeric_limits<uint64_t>::max)()) noexcept {
        if(nPos < nReadPos) {
            return false;
        }
        nReadLimit = nPos;
        return true;
    }

    // Unserialize from this stream
    template<typename T>
    CBufferedFile &operator >> (T &obj) {
        ::Unserialize(*this, obj);
        return *this;
    }

    // search for a given byte in the stream, and remain positioned on it
    void FindByte(char ch) noexcept {
        for( ; ; )
        {
            if(nReadPos == nSrcPos) {
                Fill();
            }
            if(vchBuf[nReadPos % vchBuf.size()] == ch) {
                break;
            }
            ++nReadPos;
        }
    }
};

class CAutoFile : public CTypeVersionBehave
{
private:
    CAutoFile(); // {}
    // CAutoFile(const CAutoFile &); // {}
    // CAutoFile(const CAutoFile &&); // {}
    // CAutoFile &operator=(const CAutoFile &); // {}
    // CAutoFile &operator=(const CAutoFile &&); // {}

    FILE *file;
    short state;
    short exceptmask;
    CBufferedFile buffer;

public:
    CAutoFile(FILE *filenew, int = 0, int = 0) noexcept : buffer(filenew) {
        file = filenew;
        state = 0;
        exceptmask = std::ios::badbit | std::ios::failbit;
    }

    ~CAutoFile() noexcept {
        fclose();
    }

    void fclose() noexcept {
        if(file != nullptr && file != stdin && file != stdout && file != stderr) {
            ::fclose(file);
        }
        file = nullptr;
    }

    FILE *release() noexcept { FILE *ret = file; file = nullptr; return ret; }
    operator FILE *() noexcept { return file; }
    FILE *operator->() noexcept { return file; }
    FILE &operator*() noexcept { return *file; }
    FILE **operator&() noexcept { return &file; }
    FILE *operator=(FILE *pnew) noexcept { return file = pnew; }
    bool operator!() noexcept { return (file == nullptr); }

    //
    // Stream subset
    //
    void setstate(short bits, const char *psz) {
        state |= bits;
        if(state & exceptmask) {
            throw std::ios_base::failure(psz);
        }
    }

    bool fail() const noexcept { return (state & (std::ios::badbit | std::ios::failbit)) != 0; }
    bool good() const noexcept { return state == 0; }
    void clear(short n = 0) noexcept { state = n; }
    short exceptions() const noexcept { return exceptmask; }
    short exceptions(short mask) noexcept { short prev = exceptmask; exceptmask = mask; setstate(0, "CAutoFile"); return prev; }

    CAutoFile &read(char *pch, size_t nSize) {
        // debugcs::instance() << "CAutoFile: CAutoFile &read(char *pch, size_t nSize) nSize: " << nSize << debugcs::endl();
        if(! file) {
            throw std::ios_base::failure("CAutoFile::read : file handle is nullptr");
        }
        size_t _nSize = nSize / sizeof(char);
        if(::fread(pch, sizeof(char), _nSize, file) != _nSize * sizeof(char)) {
            setstate(std::ios::failbit, ::feof(file) ? "CAutoFile::read : end of file" : "CAutoFile::read : fread failed");
        }
        return *this;
    }

    CAutoFile &write(const char *pch, size_t nSize) {
        if(! file) {
            throw std::ios_base::failure("CAutoFile::write : file handle is nullptr");
        }
        size_t _nSize = nSize / sizeof(char);
        if(::fwrite(pch, sizeof(char), _nSize, file) != _nSize * sizeof(char)) {
            setstate(std::ios::failbit, "CAutoFile::write : write failed");
        }
        return *this;
    }

    template<typename T>
    unsigned int GetSerializeSize(const T &obj) const noexcept {
        // Tells the size of the object if serialized to this stream
        return ::GetSerializeSize(obj);
    }

    template<typename T>
    CAutoFile &operator<<(const T &obj) {
        // Serialize to this stream
        if(! file) {
            throw std::ios_base::failure("CAutoFile::operator<< : file handle is nullptr");
        }
        ::Serialize(*this, obj);
        return *this;
    }

    template<typename T>
    CAutoFile &operator >> (T &obj) {
        // Unserialize from this stream
        if(! file) {
            throw std::ios_base::failure("CAutoFile::operator>> : file handle is nullptr");
        }
        ::Unserialize(*this, obj);
        return *this;
    }
};

#endif
