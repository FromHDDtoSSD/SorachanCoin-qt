// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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
#include <allocator/allocators.h>
#include <const/no_instance.h>
#include <file_operate/fs.h>

class CScript;
class CDataStream;
class CAutoFile;

/**
 * Dummy data type to identify deserializing constructors.
 *
 * By convention, a constructor of a type T with signature
 *
 *   template <typename Stream> T::T(deserialize_type, Stream& s)
 *
 * is a deserializing constructor, which builds the type by
 * deserializing it from s. If T contains const fields, this
 * is likely the only way to do so.
 */
struct deserialize_type {};
constexpr deserialize_type deserialize {};

// Used to bypass the rule against non-const reference to temporary
// where it makes sense with wrappers such as CFlatData or CTxDB
template<typename T>
inline T &REF(const T &val)
{
    return const_cast<T &>(val);
}

// Used to acquire a non-const pointer "this" to generate bodies
// of const serialization operations from a template
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

/**
 * Lowest-level serialization and conversion.
 * @note Sizes of these types are verified in the tests
 */
namespace ser {
template<typename Stream> inline void ser_writedata8(Stream &s, uint8_t obj)
{
    s.write((char *)&obj, 1);
}
template<typename Stream> inline void ser_writedata16(Stream &s, uint16_t obj)
{
    obj = endian::bc_htole16(obj);
    s.write((char *)&obj, 2);
}
template<typename Stream> inline void ser_writedata16be(Stream &s, uint16_t obj)
{
    obj = endian::bc_htobe16(obj);
    s.write((char *)&obj, 2);
}
template<typename Stream> inline void ser_writedata32(Stream &s, uint32_t obj)
{
    obj = endian::bc_htole32(obj);
    s.write((char *)&obj, 4);
}
template<typename Stream> inline void ser_writedata64(Stream &s, uint64_t obj)
{
    obj = endian::bc_htole64(obj);
    s.write((char *)&obj, 8);
}
template<typename Stream> inline uint8_t ser_readdata8(Stream &s)
{
    uint8_t obj;
    s.read((char *)&obj, 1);
    return obj;
}
template<typename Stream> inline uint16_t ser_readdata16(Stream &s)
{
    uint16_t obj;
    s.read((char *)&obj, 2);
    return endian::bc_le16toh(obj);
}
template<typename Stream> inline uint16_t ser_readdata16be(Stream &s)
{
    uint16_t obj;
    s.read((char *)&obj, 2);
    return endian::bc_be16toh(obj);
}
template<typename Stream> inline uint32_t ser_readdata32(Stream &s)
{
    uint32_t obj;
    s.read((char *)&obj, 4);
    return endian::bc_le32toh(obj);
}
template<typename Stream> inline uint64_t ser_readdata64(Stream &s)
{
    uint64_t obj;
    s.read((char *)&obj, 8);
    return endian::bc_le64toh(obj);
}
inline uint64_t ser_double_to_uint64(double x)
{
    union { double x; uint64_t y; } tmp;
    tmp.x = x;
    return tmp.y;
}
inline uint32_t ser_float_to_uint32(float x)
{
    union { float x; uint32_t y; } tmp;
    tmp.x = x;
    return tmp.y;
}
inline double ser_uint64_to_double(uint64_t y)
{
    union { double x; uint64_t y; } tmp;
    tmp.y = y;
    return tmp.x;
}
inline float ser_uint32_to_float(uint32_t y)
{
    union { float x; uint32_t y; } tmp;
    tmp.y = y;
    return tmp.x;
}
} // namespace ser

/**
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
    static inline uint16_t _htole(uint16_t s) { return endian::bc_htole16(s); }
    static inline uint32_t _htole(uint32_t s) { return endian::bc_htole32(s); }
    static inline uint64_t _htole(uint64_t s) { return endian::bc_htole64(s); }
    static inline uint8_t _htole(int8_t s) { return (uint8_t)s; }
    static inline uint16_t _htole(int16_t s) { return endian::bc_htole16((uint16_t)s); }
    static inline uint32_t _htole(int32_t s) { return endian::bc_htole32((uint32_t)s); }
    static inline uint64_t _htole(int64_t s) { return endian::bc_htole64((uint64_t)s); }
    static inline _CINV_MSG_TYPE _htole(_CINV_MSG_TYPE s) { return (_CINV_MSG_TYPE)endian::bc_htole32((uint32_t)s); }
    static inline uint32_t _htole(float s) { uint32_t tmp = float_to_uint32(s); return endian::bc_htole32(tmp); }
    static inline uint64_t _htole(double s) { uint64_t tmp = double_to_uint64(s); return endian::bc_htole64(tmp); }

    static inline uint8_t _htobe(uint8_t s) { return s; }
    static inline uint16_t _htobe(uint16_t s) { return endian::bc_htobe16(s); }
    static inline uint32_t _htobe(uint32_t s) { return endian::bc_htobe32(s); }
    static inline uint64_t _htobe(uint64_t s) { return endian::bc_htobe64(s); }
    static inline uint8_t _htobe(int8_t s) { return (uint8_t)s; }
    static inline uint16_t _htobe(int16_t s) { return endian::bc_htobe16((uint16_t)s); }
    static inline uint32_t _htobe(int32_t s) { return endian::bc_htobe32((uint32_t)s); }
    static inline uint64_t _htobe(int64_t s) { return endian::bc_htobe64((uint64_t)s); }
    static inline _CINV_MSG_TYPE _htobe(_CINV_MSG_TYPE s) { return (_CINV_MSG_TYPE)endian::bc_htobe32((uint32_t)s); }
    static inline uint32_t _htobe(float s) { uint32_t tmp = float_to_uint32(s); return endian::bc_htobe32(tmp); }
    static inline uint64_t _htobe(double s) { uint64_t tmp = double_to_uint64(s); return endian::bc_htobe64(tmp); }

    static inline uint8_t _letoh(uint8_t s) { return s; }
    static inline uint16_t _letoh(uint16_t s) { return endian::bc_le16toh(s); }
    static inline uint32_t _letoh(uint32_t s) { return endian::bc_le32toh(s); }
    static inline uint64_t _letoh(uint64_t s) { return endian::bc_le64toh(s); }
    static inline uint8_t _letoh(int8_t s) { return (uint8_t)s; }
    static inline uint16_t _letoh(int16_t s) { return endian::bc_le16toh((uint16_t)s); }
    static inline uint32_t _letoh(int32_t s) { return endian::bc_le32toh((uint32_t)s); }
    static inline uint64_t _letoh(int64_t s) { return endian::bc_le64toh((uint64_t)s); }
    static inline _CINV_MSG_TYPE _letoh(_CINV_MSG_TYPE s) { return (_CINV_MSG_TYPE)endian::bc_le32toh((uint32_t)s); }
    static inline float _letoh(uint32_t s, int) { uint32_t tmp = endian::bc_le32toh(s); return uint32_to_float(tmp); }
    static inline double _letoh(uint64_t s, int) { uint64_t tmp = endian::bc_le64toh(s); return uint64_to_double(tmp); }

    static inline uint8_t _betoh(uint8_t s) { return s; }
    static inline uint16_t _betoh(uint16_t s) { return endian::bc_be16toh(s); }
    static inline uint32_t _betoh(uint32_t s) { return endian::bc_be32toh(s); }
    static inline uint64_t _betoh(uint64_t s) { return endian::bc_be64toh(s); }
    static inline uint8_t _betoh(int8_t s) { return (uint8_t)s; }
    static inline uint16_t _betoh(int16_t s) { return endian::bc_be16toh((uint16_t)s); }
    static inline uint32_t _betoh(int32_t s) { return endian::bc_be32toh((uint32_t)s); }
    static inline uint64_t _betoh(int64_t s) { return endian::bc_be64toh((uint64_t)s); }
    static inline _CINV_MSG_TYPE _betoh(_CINV_MSG_TYPE s) { return (_CINV_MSG_TYPE)endian::bc_be32toh((uint32_t)s); }
    static inline float _betoh(uint32_t s, int) { uint32_t tmp = endian::bc_be32toh(s); return uint32_to_float(tmp); }
    static inline double _betoh(uint64_t s, int) { uint64_t tmp = endian::bc_be64toh(s); return uint64_to_double(tmp); }

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

    // _letoh(tmp, 0) or _betoh(tmp, 0): add dummy int type.
    // Note: conflict overload, float or double
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

// Templates for serializing to anything that looks like a stream,
// i.e. anything that supports .read(char*, int) and .write(char*, int)
enum {
    // primary actions
    SER_NETWORK = (1 << 0),
    SER_DISK = (1 << 1),
    SER_GETHASH = (1 << 2),

    // modifiers
    SER_SKIPSIG = (1 << 16),
    SER_BLOCKHEADERONLY = (1 << 17)
};

#define WRITEDATA(s, obj) ser_data::write(s, obj)
#define READDATA(s, obj)  ser_data::read(s, obj)

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
template<typename Stream> inline void Serialize(Stream &s, _CINV_MSG_TYPE a) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream &s, bool a) { char f = a; WRITEDATA(s, f); }

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
template<typename Stream> inline void Unserialize(Stream &s, _CINV_MSG_TYPE &a) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream &s, bool &a) { char f; READDATA(s, f); a = f; }

//! Forward declarations
#ifdef CSCRIPT_PREVECTOR_ENABLE
template<unsigned int N, typename Stream, typename T> inline void Serialize(Stream &os, const prevector<N, T> &v);
template<unsigned int N, typename Stream, typename T> inline void Unserialize(Stream &is, prevector<N, T> &v);

template<typename Stream> inline void Serialize(Stream &os, const CScript &v) { ::Serialize(os, (const prevector<PREVECTOR_N, uint8_t> &)v); }
template<typename Stream> inline void Unserialize(Stream &is, CScript &v) { ::Unserialize(is, (prevector<PREVECTOR_N, uint8_t> &)v); }
#else
template<typename Stream, typename T, typename A> inline void Serialize(Stream &os, const std::vector<T, A> &v);
template<typename Stream, typename T, typename A> inline void Unserialize(Stream &is, std::vector<T, A> &v);

template<typename Stream> inline void Serialize(Stream &os, const CScript &v) { ::Serialize(os, (const std::vector<unsigned char> &)v); }
template<typename Stream> inline void Unserialize(Stream &is, CScript &v) { ::Unserialize(is, (std::vector<unsigned char> &)v); }
#endif

/**
 * ::GetSerializeSize implementations
 *
 * Computing the serialized size of objects is done through a special stream
 * object of type CSizeComputer, which only records the number of bytes written
 * to it.
 *
 * If your Serialize or SerializationOp method has non-trivial overhead for
 * serialization, it may be worthwhile to implement a specialized version for
 * CSizeComputer, which uses the s.seek() method to record bytes that would
 * be written instead.
 */

//! Forward declarations
template<typename Stream, typename C>
inline void Serialize(Stream &os, const std::basic_string<C> &str);
template<typename Stream, typename K, typename T>
inline void Serialize(Stream &os, const std::pair<K, T> &item);
template<typename Stream, typename T, typename A>
inline void Serialize(Stream &os, const std::vector<T, A> &v);
template<unsigned int N, typename Stream, typename T>
inline void Serialize(Stream &os, const prevector<N, T> &v);
template<unsigned int N, typename Stream, typename T>
inline void Serialize(Stream &os, const latest_crypto::prevector_s<N, T> &v);
template<typename Stream, typename T0, typename T1, typename T2>
inline void Serialize(Stream &os, const std::tuple<T0, T1, T2> &item);
template<typename Stream, typename T0, typename T1, typename T2, typename T3>
inline void Serialize(Stream &os, const std::tuple<T0, T1, T2, T3> &item);
template<typename Stream, typename K, typename T, typename Pred, typename A>
inline void Serialize(Stream &os, const std::map<K, T, Pred, A> &m);
template<typename Stream, typename K, typename Pred, typename A>
inline void Serialize(Stream &os, const std::set<K, Pred, A> &m);
template<typename Stream, typename T>
inline void Serialize(Stream &os, const std::unique_ptr<const T> &p);
template<typename Stream, typename T>
inline void Serialize(Stream &os, const std::shared_ptr<const T> &p);

template<typename Stream, typename T>
inline void Serialize(Stream &os, const T &a) { a.Serialize(os); }
template<typename Stream, typename T>
inline void Unserialize(Stream &is, T &&a) { a.Unserialize(is); }

class CSizeComputer
{
protected:
    size_t nSize;
    const int nVersion;
public:
    explicit CSizeComputer(int nVersionIn) noexcept : nSize(0), nVersion(nVersionIn) {}

    void write(const char *psz, size_t _nSize) noexcept {
        (void)psz;
        this->nSize += _nSize;
    }

    /** Pretend _nSize bytes are written, without specifying them. */
    void seek(size_t _nSize) noexcept {
        this->nSize += _nSize;
    }

    template<typename T>
    CSizeComputer &operator<<(const T &obj) {
        ::Serialize(*this, obj);
        return (*this);
    }

    size_t size() const noexcept {
        return nSize;
    }

    int GetVersion() const noexcept { return nVersion; }
};

template <typename T>
inline size_t GetSerializeSize(const T &t, int nVersion = 0) {
    //debugcs::instance() << "called GetSerializeSize(const T&)" << debugcs::endl();
    return (CSizeComputer(nVersion) << t).size();
}

// Compact size
//  size <  253        -- 1 byte
//  size <= USHRT_MAX  -- 3 bytes  (253 + 2 bytes)
//  size <= UINT_MAX   -- 5 bytes  (254 + 4 bytes)
//  size >  UINT_MAX   -- 9 bytes  (255 + 8 bytes)
namespace compact_size
{
    constexpr unsigned int MAX_SIZE = 0x02000000;

    class manage : private no_instance
    {
    public:
        static unsigned int GetSizeOfCompactSize(uint64_t nSize) noexcept {
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
                if (nSizeRet < 253)
                    throw std::ios_base::failure("non-canonical ReadCompactSize()");
            } else if(chSize == 254) {
                unsigned int xSize;
                READDATA(is, xSize);
                nSizeRet = xSize;
                if (nSizeRet < 0x10000u)
                    throw std::ios_base::failure("non-canonical ReadCompactSize()");
            } else {
                uint64_t xSize;
                READDATA(is, xSize);
                nSizeRet = xSize;
                if (nSizeRet < 0x100000000ULL)
                    throw std::ios_base::failure("non-canonical ReadCompactSize()");
            }
            if(nSizeRet > (uint64_t)MAX_SIZE)
                throw std::ios_base::failure("compact_size::manage::ReadCompactSize() : size too large");
            return nSizeRet;
        }
    };
}

//! Wrapper for serializing arrays and POD.
class CFlatData
{
private:
    CFlatData()=delete;
    CFlatData(const CFlatData &)=delete;
    CFlatData(CFlatData &&)=delete;
    CFlatData &operator=(const CFlatData &)=delete;
    CFlatData &operator=(CFlatData &&)=delete;

    char *pbegin;
    const char *pend;
public:
    CFlatData(void *pbeginIn, void *pendIn) noexcept : pbegin((char *)pbeginIn), pend((const char *)pendIn) {}
    ~CFlatData() {}

    char *begin() noexcept { return pbegin; }
    const char *begin() const noexcept { return pbegin; }
    const char *end() const noexcept { return pend; }

    unsigned int GetSerializeSize() const noexcept {
        return (unsigned int)(pend - pbegin);
    }

    template<typename Stream>
    void Serialize(Stream &s) const {
        s.write(pbegin, (int)(pend - pbegin));
    }

    template<typename Stream>
    void Unserialize(Stream &s) {
        s.read(pbegin, pend - pbegin);
    }
};
#define FLATDATA(obj)  REF(CFlatData((char *)&(obj), (char *)&(obj) + sizeof(obj)))

/** Serialization wrapper class for big-endian integers.
 *
 * Use this wrapper around integer types that are stored in memory in native
 * byte order, but serialized in big endian notation. This is only intended
 * to implement serializers that are compatible with existing formats, and
 * its use is not recommended for new data structures.
 */
template<typename I>
class BigEndian
{
protected:
    I &m_val;
public:
    explicit BigEndian(I &val) : m_val(val) {
        static_assert(std::is_unsigned<I>::value, "BigEndian type must be unsigned integer");
        //static_assert(sizeof(I) == 2 && std::numeric_limits<I>::min() == 0 && std::numeric_limits<I>::max() == std::numeric_limits<uint16_t>::max(), "Unsupported BigEndian size");
        static_assert(std::numeric_limits<I>::min() == 0, "Unsupported BigEndian min size");
    }

    template<typename Stream>
    void Serialize(Stream &s) const {
        ser_data::writebe(s, m_val);
    }

    template<typename Stream>
    void Unserialize(Stream &s) {
        ser_data::readbe(s, m_val);
    }
};

inline void WriteCompactSize(CSizeComputer &os, uint64_t nSize);
class CCompactSize
{
protected:
    uint64_t &n;
public:
    explicit CCompactSize(uint64_t &nIn) : n(nIn) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        compact_size::manage::WriteCompactSize<Stream>(s, n);
    }

    template<typename Stream>
    void Unserialize(Stream &s) {
        n = compact_size::manage::ReadCompactSize<Stream>(s);
    }
};

template<size_t Limit>
class LimitedString
{
protected:
    std::string &string;
public:
    explicit LimitedString(std::string &_string) : string(_string) {}

    template<typename Stream>
    void Unserialize(Stream &s) {
        size_t size = compact_size::manage::ReadCompactSize(s);
        if (size > Limit) {
            throw std::ios_base::failure("String length limit exceeded");
        }
        string.resize(size);
        if (size != 0)
            s.read((char *)string.data(), size);
    }

    template<typename Stream>
    void Serialize(Stream &s) const {
        compact_size::manage::WriteCompactSize(s, string.size());
        if (! string.empty())
            s.write((char *)string.data(), string.size());
    }
};
#define LIMITED_STRING(obj, n) REF(LimitedString<n>(REF(obj)))

template<typename I>
BigEndian<I> WrapBigEndian(I &n) { return BigEndian<I>(n); }

// string, vector, prevector, pair, tuple, map, set, unique_ptr, shared_ptr Serialize types.
// string
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
template<unsigned int N, typename Stream, typename T>
inline void Serialize_impl(Stream &os, const latest_crypto::prevector_s<N, T> &v, const std::true_type &)
{
    compact_size::manage::WriteCompactSize(os, v.size());
    if(! v.empty()) {
        typename latest_crypto::prevector_s<N, T>::const_raw_pointer ptr = v.data();
        os.write((const char *)((const T *)ptr), (int)(v.size() * sizeof(T)));
    }
}

template<unsigned int N, typename Stream, typename T>
inline void Serialize_impl(Stream &os, const latest_crypto::prevector_s<N, T> &v, const std::false_type &)
{
    compact_size::manage::WriteCompactSize(os, v.size());
    for(typename latest_crypto::prevector_s<N, T>::const_iterator vi = v.begin(); vi != v.end(); ++vi)
    {
        ::Serialize(os, (*vi));
    }
}

template<unsigned int N, typename Stream, typename T>
inline void Serialize(Stream &os, const latest_crypto::prevector_s<N, T> &v)
{
    ::Serialize_impl(os, v, std::is_fundamental<T>());
}

template<unsigned int N, typename Stream, typename T>
inline void Unserialize_impl(Stream &is, latest_crypto::prevector_s<N, T> &v, const std::true_type &)
{
    // Limit size per read so bogus size value won't cause out of memory
    v.clear();
    unsigned int nSize = (unsigned int)(compact_size::manage::ReadCompactSize(is));
    unsigned int i = 0;
    while(i < nSize)
    {
        unsigned int blk = (std::min)(nSize - i, (unsigned int)(1 + 4999999 / sizeof(T)));
        v.resize(i + blk);
        typename latest_crypto::prevector_s<N, T>::raw_pointer ptr = v.data();
        is.read((char *)((T *)ptr + i), blk * sizeof(T));
        i += blk;
    }
}

template<unsigned int N, typename Stream, typename T>
inline void Unserialize_impl(Stream &is, latest_crypto::prevector_s<N, T> &v, const std::false_type &)
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
            typename latest_crypto::prevector_s<N, T>::raw_pointer ptr = v.data();
            ::Unserialize(is, *((T *)ptr + i));
        }
    }
}

template<unsigned int N, typename Stream, typename T>
inline void Unserialize(Stream &is, latest_crypto::prevector_s<N, T> &v)
{
    ::Unserialize_impl(is, v, std::is_fundamental<T>());
}

// tuple<3>
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

// unique_ptr
template<typename Stream, typename T>
inline void Serialize(Stream &os, const std::unique_ptr<const T> &p)
{
    ::Serialize(os, *p);
}

template<typename Stream, typename T>
inline void Unserialize(Stream &is, std::unique_ptr<const T> &p)
{
    p.reset(new T(deserialize, is));
}

// shared_ptr
template<typename Stream, typename T>
inline void Serialize(Stream &os, const std::shared_ptr<const T> &p)
{
    ::Serialize(os, *p);
}

template<typename Stream, typename T>
inline void Unserialize(Stream &is, std::shared_ptr<const T> &p)
{
    p = std::make_shared<const T>(deserialize, is);
}

// Support for nType and nVersion
class CTypeVersion
{
private:
    CTypeVersion()=delete;
    //CTypeVersion(const CTypeVersion &)=delete;
    //CTypeVersion(CTypeVersion &&)=delete;
    //CTypeVersion &operator=(const CTypeVersion &)=delete;
    //CTypeVersion &operator=(CTypeVersion &&)=delete;
    int nType;
    int nVersion;
protected:
    explicit CTypeVersion(int nTypeIn, int nVersionIn) noexcept : nType(nTypeIn), nVersion(nVersionIn) {}
    ~CTypeVersion() {}
public:
    void SetType(int n) noexcept { nType = n; }
    void AddType(int n) noexcept { nType |= n; }
    int GetType() const noexcept { return nType; }
    void SetVersion(int n) noexcept { nVersion = n; }
    int GetVersion() const noexcept { return nVersion; }
};

class CTypeVersionBehave
{
public:
    CTypeVersionBehave() noexcept : nType(0), nVersion(0) {}
    int nType;
    int nVersion;
    void AddType(int) noexcept {}
    void SetType(int) noexcept {}
    void SetVersion(int) noexcept {}
};

/**
 * Variable-length integers: bytes are a MSB base-128 encoding of the number.
 * The high bit in each byte signifies whether another digit follows. To make
 * sure the encoding is one-to-one, one is subtracted from all but the last digit.
 * Thus, the byte sequence a[] with length len, where all but the last byte
 * has bit 128 set, encodes the number:
 *
 *  (a[len-1] & 0x7F) + sum(i=1..len-1, 128^i*((a[len-i-1] & 0x7F)+1))
 *
 * Properties:
 * * Very small (0-127: 1 byte, 128-16511: 2 bytes, 16512-2113663: 3 bytes)
 * * Every integer has exactly one encoding
 * * Encoding does not depend on size of original integer type
 * * No redundancy: every (infinite) byte sequence corresponds to a list
 *   of encoded integers.
 *
 * 0:         [0x00]  256:        [0x81 0x00]
 * 1:         [0x01]  16383:      [0xFE 0x7F]
 * 127:       [0x7F]  16384:      [0xFF 0x00]
 * 128:  [0x80 0x00]  16511:      [0xFF 0x7F]
 * 255:  [0x80 0x7F]  65535: [0x82 0xFE 0x7F]
 * 2^32:           [0x8E 0xFE 0xFE 0xFF 0x00]
 */

/**
 * Mode for encoding VarInts.
 *
 * Currently there is no support for signed encodings. The default mode will not
 * compile with signed values, and the legacy "nonnegative signed" mode will
 * accept signed values, but improperly encode and decode them if they are
 * negative. In the future, the DEFAULT mode could be extended to support
 * negative numbers in a backwards compatible way, and additional modes could be
 * added to support different varint formats (e.g. zigzag encoding).
 */
namespace varint {
enum class VarIntMode { DEFAULT, NONNEGATIVE_SIGNED };

template <VarIntMode Mode, typename I>
struct CheckVarIntMode {
    constexpr CheckVarIntMode() {
        static_assert(Mode != VarIntMode::DEFAULT || std::is_unsigned<I>::value, "Unsigned type required with mode DEFAULT.");
        static_assert(Mode != VarIntMode::NONNEGATIVE_SIGNED || std::is_signed<I>::value, "Signed type required with mode NONNEGATIVE_SIGNED.");
    }
};

template<VarIntMode Mode, typename I>
static inline unsigned int GetSizeOfVarInt(I n) {
    CheckVarIntMode<Mode, I>();
    int nRet = 0;
    while(true) {
        nRet++;
        if (n <= 0x7F)
            break;
        n = (n >> 7) - 1;
    }
    return nRet;
}

template<typename I>
inline void WriteVarInt(CSizeComputer &os, I n);

template<typename Stream, VarIntMode Mode, typename I>
static inline void WriteVarInt(Stream &os, I n) {
    CheckVarIntMode<Mode, I>();
    unsigned char tmp[(sizeof(n)*8+6)/7];
    int len=0;
    while(true) {
        tmp[len] = (n & 0x7F) | (len ? 0x80 : 0x00);
        if (n <= 0x7F)
            break;
        n = (n >> 7) - 1;
        len++;
    }
    do {
        ser::ser_writedata8(os, tmp[len]);
    } while(len--);
}

template<typename Stream, VarIntMode Mode, typename I>
static inline I ReadVarInt(Stream &is) {
    CheckVarIntMode<Mode, I>();
    I n = 0;
    while(true) {
        unsigned char chData = ser::ser_readdata8(is);
        if (n > (std::numeric_limits<I>::max() >> 7)) {
           throw std::ios_base::failure("ReadVarInt(): size too large");
        }
        n = (n << 7) | (chData & 0x7F);
        if (chData & 0x80) {
            if (n == std::numeric_limits<I>::max()) {
                throw std::ios_base::failure("ReadVarInt(): size too large");
            }
            n++;
        } else {
            return n;
        }
    }
}
} // namespace varint

template<varint::VarIntMode Mode, typename I>
class CVarInt
{
protected:
    I &n;
public:
    explicit CVarInt(I &nIn) : n(nIn) {}

    unsigned int GetSerializeSize(int, int) const {
        return varint::GetSizeOfVarInt<Mode, I>(n);
    }

    template<typename Stream>
    void Serialize(Stream &s) const {
        varint::WriteVarInt<Stream, Mode, I>(s, n);
    }

    template<typename Stream>
    void Unserialize(Stream &s) {
        n = varint::ReadVarInt<Stream, Mode, I>(s);
    }
};

template<varint::VarIntMode Mode=varint::VarIntMode::DEFAULT, typename I>
static inline CVarInt<Mode, I> WrapVarUInt(I &n) { return CVarInt<Mode, I>(n); }
#define VARUINT(obj) REF(WrapVarUInt(REF(obj)))

template<varint::VarIntMode Mode=varint::VarIntMode::NONNEGATIVE_SIGNED, typename I>
static inline CVarInt<Mode, I> WrapVarInt(I &n) { return CVarInt<Mode, I>(n); }
#define VARINT(obj) REF(WrapVarInt(REF(obj)))

/**
 * Support for ADD_SERIALIZE_METHODS
 */
struct CSerActionGetSerializeSize {};
struct CSerActionSerialize {
    constexpr bool ForRead() const { return false; }
};
struct CSerActionUnserialize {
    constexpr bool ForRead() const { return true; }
};

/**
 * variable template many serialize
 */
template<typename Stream>
void SerializeMany(Stream &s) {(void)s;}
template<typename Stream>
inline void UnserializeMany(Stream &s) {(void)s;}

template<typename Stream, typename Arg, typename... Args>
void SerializeMany(Stream &s, const Arg &arg, const Args&... args) {
    ::Serialize(s, arg);
    ::SerializeMany(s, args...);
}
template<typename Stream, typename Arg, typename... Args>
inline void UnserializeMany(Stream &s, Arg &&arg, Args&&... args) {
    ::Unserialize(s, arg);
    ::UnserializeMany(s, args...);
}

template<typename Stream, typename... Args>
inline void SerReadWriteMany(Stream &s, CSerActionSerialize ser_action, const Args&... args) {
    ::SerializeMany(s, args...);
}
template<typename Stream, typename... Args>
inline void SerReadWriteMany(Stream &s, CSerActionUnserialize ser_action, Args&&... args) {
    ::UnserializeMany(s, args...);
}

template<typename I>
inline void WriteVarInt(CSizeComputer &s, I n) {
    s.seek(varint::GetSizeOfVarInt<I>(n));
}

inline void WriteCompactSize(CSizeComputer &s, uint64_t nSize) {
    s.seek(compact_size::manage::GetSizeOfCompactSize(nSize));
}

template <typename... T>
size_t GetSerializeSizeMany(int nVersion, const T&... t) {
    CSizeComputer sc(nVersion);
    ::SerializeMany(sc, t...);
    return sc.size();
}

//! ADD_SERIALIZE_METHODS:
//  Convert the reference base type to X, without changing constness or reference type.
template<typename X> X &ReadWriteAsHelper(X &x) { return x; }
template<typename X> const X &ReadWriteAsHelper(const X &x) { return x; }
#define READWRITE(...) (::SerReadWriteMany(s, ser_action, __VA_ARGS__))
#define READWRITEAS(type, obj) (::SerReadWriteMany(s, ser_action, ReadWriteAsHelper<type>(obj)))

/**
 * Implement three methods for serializable objects. These are actually wrappers over
 * "SerializationOp" template, which implements the body of each class' serialization
 * code. Adding "ADD_SERIALIZE_METHODS" in the body of the class causes these wrappers to be
 * added as members.
 */
#define ADD_SERIALIZE_METHODS                                         \
public:                                                               \
    template<typename Stream>                                         \
    void Serialize(Stream &s) const {                                 \
        NCONST_PTR(this)->SerializationOp(s, CSerActionSerialize());  \
    }                                                                 \
    template<typename Stream>                                         \
    void Unserialize(Stream &s) {                                     \
        SerializationOp(s, CSerActionUnserialize());                  \
    }

//! Double ended buffer combining vector and stream-like interfaces.
// >> and << read and write unformatted data using the above serialization templates.
// Fills with data in linear time; some stringstream implementations take N^2 time.
using CSerializeData = std::vector<char, zero_after_free_allocator<char> >;
#ifdef DATASTREAM_PREVECTOR_ENABLE
using datastream_vector = prevector<PREVECTOR_DATASTREAM_N, uint8_t>;
using datastream_signed_vector = prevector<PREVECTOR_DATASTREAM_N, int8_t>;
#else
using datastream_vector = std::vector<uint8_t>;
using datastream_signed_vector = std::vector<int8_t>;
#endif
class CDataStream : public CTypeVersion
{
private:
    // CDataStream()=delete;
    // CDataStream(const CDataStream &)=delete;
    // CDataStream(CDataStream &)=delete;
    // CDataStream &operator=(const CDataStream &)=delete;
    // CDataStream &operator=(CDataStream &&)=delete;

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

    CDataStream(int nType=0, int nVersion=0) noexcept : CTypeVersion(nType, nVersion) {
        Init();
    }

    CDataStream(const CDataStream &obj) : CTypeVersion(obj.GetType(), obj.GetVersion()) {
        *this = obj;
    }

    //CDataStream(const CFlatData &obj, int nType=0, int nVersion=0) : CTypeVersion(nType, nVersion) {
    //    *this << obj;
    //}

    CDataStream(const_iterator pbegin, const_iterator pend, int nType=0, int nVersion=0) : vch(pbegin, pend), CTypeVersion(nType, nVersion) {
        Init();
    }

#if !defined(_MSC_VER) || _MSC_VER >= 1300
    CDataStream(const char *pbegin, const char *pend, int nType=0, int nVersion=0) : vch(pbegin, pend), CTypeVersion(nType, nVersion) {
        Init();
    }
#endif

    CDataStream(const vector_type &vchIn, int nType=0, int nVersion=0) : vch(vchIn.begin(), vchIn.end()), CTypeVersion(nType, nVersion) {
        Init();
    }

#ifdef DATASTREAM_PREVECTOR_ENABLE
    CDataStream(const std::vector<char> &vchIn, int nType=0, int nVersion=0) : vch(vchIn.begin(), vchIn.end()), CTypeVersion(nType, nVersion) {
        Init();
    }
    CDataStream(const std::vector<unsigned char> &vchIn, int nType=0, int nVersion=0) : vch(vchIn.begin(), vchIn.end()), CTypeVersion(nType, nVersion) {
        Init();
    }
#endif

    CDataStream(const datastream_signed_vector &vchIn, int nType=0, int nVersion=0) : vch(vchIn.begin(), vchIn.end()), CTypeVersion(nType, nVersion) {
        Init();
    }

    CDataStream(const datastream_vector &vchIn, int nType=0, int nVersion=0) : vch(vchIn.begin(), vchIn.end()), CTypeVersion(nType, nVersion) {
        Init();
    }

    void Init() noexcept {
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

    // Vector subset
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
            std::memcpy(&this->vch[nReadPos], &first[0], last - first);
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
            std::memcpy(&vch[nReadPos], &first[0], last - first);
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
            std::memcpy(&vch[nReadPos], &first[0], last - first);
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
                    std::memset(pch, 0, nSize);
                    nSize = (int)(vch.size() - nReadPos);
                }
            }
            pch ? std::memcpy(pch, &vch[nReadPos], nSize) : 0;
            nReadPos = 0;
            vch.clear();
        } else {
            pch ? std::memcpy(pch, &vch[nReadPos], nSize) : 0;
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
        return ::GetSerializeSize(obj, GetVersion());
    }

    // << and >> write and read (Serialize, Unserialize)
    template<typename T>
    CDataStream &operator<<(const T &obj) {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return *this;
    }

    template<typename T>
    CDataStream &operator>>(T &obj) {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return *this;
    }

    void GetAndClear(CSerializeData &data) noexcept {
        this->vch.swap(data);
        CSerializeData().swap(vch);
    }

    // operator+ cp
    friend CDataStream operator+(const CDataStream &a, const CDataStream &b) {
        //debugcs::instance() << "cp CDataStream operator+(const CDataStream &a, const CDataStream &b)" << debugcs::endl();
        CDataStream ret(a);
        ret += b;
        return ret;
    }

    //
    // port to latest core
    //

    // XOR the contents of this stream with a certain key.
    // @param[in] key    The key used to XOR the data in this stream.
    void Xor(const datastream_vector &key) {
        if (key.size() == 0)
            return;
        for (size_type i = 0, j = 0; i != size(); ++i) {
            vch[i] ^= key[j++];

            // This potentially acts on very many bytes of data, so it's
            // important that we calculate `j`, i.e. the `key` index in this
            // way instead of doing a %, which would effectively be a division
            // for each byte Xor'd -- much slower than need be.
            if (j == key.size())
                j = 0;
        }
    }

    template <typename... Args>
    CDataStream(int nTypeIn, int nVersionIn, Args&&... args) : CTypeVersion(nTypeIn, nVersionIn) {
        Init();
        ::SerializeMany(*this, std::forward<Args>(args)...);
    }
};

// RAII wrapper for FILE *.
// Wrapper around a FILE * that implements a ring buffer to deserialize from.
// It guarantees the ability to rewind a given number of bytes.
//
// Will automatically close the file when it goes out of scope if not null.
// If you're returning the file pointer, return file.release().
// If you need to close the file early, use file.fclose() instead of fclose(file).
#ifdef BUFFER_PREVECTOR_ENABLE
using bufferedfile_vector = prevector<PREVECTOR_BUFFER_N, char>;
#else
using bufferedfile_vector = std::vector<char>;
#endif
class CBufferedFile
{
private:
    CBufferedFile()=delete;
    // CBufferedFile(const CBufferedFile &)=delete;
    // CBufferedFile(CBufferedFile &&)=delete;
    // CBufferedFile &operator=(const CBufferedFile &)=delete;
    // CBufferedFile &operator=(CBufferedFile &&)=delete;

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

    //CBufferedFile(uint64_t nBufSize = PREVECTOR_BUFFER_N, uint64_t nRewindIn = 0) :
    //    src(nullptr), nSrcPos(0), nReadPos(0), nReadLimit((std::numeric_limits<uint64_t>::max)()), nRewind(nRewindIn), vchBuf(nBufSize, 0),
    //    state(0), exceptmask(std::ios_base::badbit | std::ios_base::failbit) {}

    void setfile(FILE *fileIn) {
        if(src)
            throw std::ios_base::failure("setfile only using if the src is nullptr");
        src = fileIn;
    }

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
            std::memcpy(pch, &vchBuf[pos], nNow);
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

class CAutoFile final : public CTypeVersion
{
private:
    CAutoFile()=delete;
    //CAutoFile(const CAutoFile &)=delete;
    //CAutoFile(CAutoFile &&)=delete;
    //CAutoFile &operator=(const CAutoFile &)=delete;
    //CAutoFile &operator=(CAutoFile &&)=delete;
    FILE *file;
    short state;
    short exceptmask;
    CBufferedFile buffer;

    // if require file size,
    // using CAutoFile(const fs::path &, char, int, int)
    std::string path;
    size_t size;
public:
    CAutoFile(FILE *filenew, int nType=0, int nVersion=0) noexcept : buffer(filenew), CTypeVersion(nType, nVersion) {
        file = filenew;
        state = 0;
        exceptmask = std::ios::badbit | std::ios::failbit;
        path = "";
        size = 0;
    }

    CAutoFile(const fs::path &pathIn, const char *mode, int nType=0, int nVersion=0) noexcept : buffer(nullptr), CTypeVersion(nType, nVersion) {
        path = pathIn.string();
        file = ::fopen(path.c_str(), mode);
        if(! file) return;
        buffer.setfile(file);
        state = 0;
        exceptmask = std::ios::badbit | std::ios::failbit;
        if(! fsbridge::file_size(path.c_str(), &size)) {
            size = 0;
        }
    }

    ~CAutoFile() {
        fclose();
    }

    const std::string &getpath() const noexcept {
        return path;
    }

    size_t getfilesize() const {
        if(path == "") {
            throw std::ios_base::failure("CAutoFile: getfilesize path empty");
        }
        return size;
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
    bool operator!() {
        if(path == "")
            return (file == nullptr);
        else
            return !(file && 0 < size);
    }

    // Stream subset
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
