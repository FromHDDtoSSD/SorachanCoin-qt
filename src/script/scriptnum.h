// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The Sora neko developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_NUM_H
#define BITCOIN_SCRIPT_NUM_H

#include <prevector/prevector.h>
#include <limits>
#include <uint256.h>

// Sora neko  ^   ^
// CNekoNum  ( >.< )
//            [   ]

//
// CBigNum: for OpenSSL (memory: heap, digit: infinite)
// CScriptNum: for Bitcoin Script (memory: stack, digit: 2^64)
// CNekoNum: for a Cat (memory: stack, digit: 2^2040)
//

class CScriptNum
{
/**
 * Numeric opcodes (OP_1ADD, etc) are restricted to operating on 4-byte integers.
 * The semantics are subtle, though: operands must be in the range [-2^31 +1...2^31 -1],
 * but results may overflow (and are valid as long as they are not used in a subsequent
 * numeric operation). CScriptNum enforces those semantics by storing results as
 * an int64 and allowing out-of-range values to be returned as a vector of bytes but
 * throwing an exception if arithmetic is done or the result is interpreted as an integer.
 */
public:
#ifdef CSCRIPT_PREVECTOR_ENABLE
using script_vector = prevector<PREVECTOR_N, unsigned char>;
#else
using script_vector = std::vector<unsigned char>;
#endif

    explicit CScriptNum(const int64_t &n) {
        m_value = n;
    }

    static constexpr size_t nDefaultMaxNumSize = 4;
    explicit CScriptNum(const script_vector &vch, bool fRequireMinimal,
                        const size_t nMaxNumSize = nDefaultMaxNumSize);

    inline bool operator==(const int64_t& rhs) const    { return m_value == rhs; }
    inline bool operator!=(const int64_t& rhs) const    { return m_value != rhs; }
    inline bool operator<=(const int64_t& rhs) const    { return m_value <= rhs; }
    inline bool operator< (const int64_t& rhs) const    { return m_value <  rhs; }
    inline bool operator>=(const int64_t& rhs) const    { return m_value >= rhs; }
    inline bool operator> (const int64_t& rhs) const    { return m_value >  rhs; }

    inline bool operator==(const CScriptNum& rhs) const { return operator==(rhs.m_value); }
    inline bool operator!=(const CScriptNum& rhs) const { return operator!=(rhs.m_value); }
    inline bool operator<=(const CScriptNum& rhs) const { return operator<=(rhs.m_value); }
    inline bool operator< (const CScriptNum& rhs) const { return operator< (rhs.m_value); }
    inline bool operator>=(const CScriptNum& rhs) const { return operator>=(rhs.m_value); }
    inline bool operator> (const CScriptNum& rhs) const { return operator> (rhs.m_value); }

    inline CScriptNum operator+(   const int64_t& rhs)    const { return CScriptNum(m_value + rhs);}
    inline CScriptNum operator-(   const int64_t& rhs)    const { return CScriptNum(m_value - rhs);}
    inline CScriptNum operator+(   const CScriptNum& rhs) const { return operator+(rhs.m_value);   }
    inline CScriptNum operator-(   const CScriptNum& rhs) const { return operator-(rhs.m_value);   }

    inline CScriptNum& operator+=( const CScriptNum& rhs)       { return operator+=(rhs.m_value);  }
    inline CScriptNum& operator-=( const CScriptNum& rhs)       { return operator-=(rhs.m_value);  }

    inline CScriptNum operator&(   const int64_t& rhs)    const { return CScriptNum(m_value & rhs);}
    inline CScriptNum operator&(   const CScriptNum& rhs) const { return operator&(rhs.m_value);   }

    inline CScriptNum& operator&=( const CScriptNum& rhs)       { return operator&=(rhs.m_value);  }

    inline CScriptNum operator-()                         const {
        assert(m_value != std::numeric_limits<int64_t>::min());
        return CScriptNum(-m_value);
    }

    inline CScriptNum& operator=( const int64_t& rhs) {
        m_value = rhs;
        return *this;
    }

    inline CScriptNum& operator+=( const int64_t& rhs) {
        assert(rhs == 0 || (rhs > 0 && m_value <= std::numeric_limits<int64_t>::max() - rhs) ||
                           (rhs < 0 && m_value >= std::numeric_limits<int64_t>::min() - rhs));
        m_value += rhs;
        return *this;
    }

    inline CScriptNum& operator-=( const int64_t& rhs) {
        assert(rhs == 0 || (rhs > 0 && m_value >= std::numeric_limits<int64_t>::min() + rhs) ||
                           (rhs < 0 && m_value <= std::numeric_limits<int64_t>::max() + rhs));
        m_value -= rhs;
        return *this;
    }

    inline CScriptNum& operator&=( const int64_t& rhs) {
        m_value &= rhs;
        return *this;
    }

    // CScriptNum Method
    int getint() const;
    int64_t getint64() const;
    script_vector getvch() const;

    // script.h
    static script_vector serialize(const int64_t &value);
    static int64_t unserialize(const script_vector &vch);

private:
    int64_t m_value;
};

// CNekoNum: BIGNUM struct
struct BIGNUM_NEKONABE {
    constexpr static size_t size = 4 + sizeof(uint256)*8 - 1; // 4 bytes + 255 bytes
    uint8_t d[size];
    bool overflow;
    int64_t numModifier;
    BIGNUM_NEKONABE() {
        SetNull();
    }
    void SetNull() {
        std::memset(d, 0x00, sizeof(d));
        overflow=false;
        numModifier=0;
    }
    void set_int32(const int32_t &n) {
        std::memset(d, 0x00, sizeof(d));
        for(int i=3; i >= 0; --i)
            d[size-i-1] = ((n>>i*8)&0xff);
    }
    void set_int64(const int64_t &n) {
        std::memset(d, 0x00, sizeof(d));
        for(int i=7; i >= 0; --i)
            d[size-i-1] = ((n>>i*8)&0xff);
    }
    int32_t get_int32() const {
        return ( ((int32_t)(d[size-4])<<24)|((int32_t)(d[size-3])<<16)|((int32_t)(d[size-2])<<8)|(int32_t)(d[size-1]) );
    }
    int64_t get_int64() const {
        return ( ((int64_t)(d[size-8])<<56)|((int64_t)(d[size-7])<<48)|((int64_t)(d[size-6])<<40)|((int64_t)(d[size-5])<<32)|
                 ((int64_t)(d[size-4])<<24)|((int64_t)(d[size-3])<<16)|((int64_t)(d[size-2])<<8)|(int64_t)(d[size-1]) );
    }
    bool is_equal(const BIGNUM_NEKONABE &neko) const {
        return std::memcmp(this->d, neko.d, sizeof(d)) == 0;
    }
    bool is_lt(const BIGNUM_NEKONABE &neko) const {
        return std::memcmp(this->d, neko.d, sizeof(d)) < 0;
    }
    bool is_elt(const BIGNUM_NEKONABE &neko) const {
        return std::memcmp(this->d, neko.d, sizeof(d)) <= 0;
    }
};

class CNekoNum : public BIGNUM_NEKONABE
{
public:
    CNekoNum() {
        SetNull();
    }

    explicit CNekoNum(const int64_t &n) {
        SetNull();
        set_int64(n);
    }

    inline bool operator==(const int64_t& rhs) const { return get_int64() == rhs; }
    inline bool operator!=(const int64_t& rhs) const { return get_int64() != rhs; }
    inline bool operator<=(const int64_t& rhs) const { return get_int64() <= rhs; }
    inline bool operator< (const int64_t& rhs) const { return get_int64() <  rhs; }
    inline bool operator>=(const int64_t& rhs) const { return get_int64() >= rhs; }
    inline bool operator> (const int64_t& rhs) const { return get_int64() >  rhs; }

    inline bool operator==(const CNekoNum& rhs) const { return is_equal(static_cast<const BIGNUM_NEKONABE &>(rhs)); }
    inline bool operator!=(const CNekoNum& rhs) const { return !operator==(rhs); }
    inline bool operator<=(const CNekoNum& rhs) const { return is_elt(static_cast<const BIGNUM_NEKONABE &>(rhs)); }
    inline bool operator< (const CNekoNum& rhs) const { return is_lt(static_cast<const BIGNUM_NEKONABE &>(rhs)); }
    inline bool operator>=(const CNekoNum& rhs) const { return !operator<(rhs); }
    inline bool operator> (const CNekoNum& rhs) const { return !operator<=(rhs); }

    // CNekoNum method
    int getint() const;
    uint32_t getuint32() const;
    int64_t getint64() const;
    uint64_t getuint64() const;
    uint256 getuint256() const;
    CNekoNum &SetCompact(uint32_t nCompact);
    uint32_t GetCompact() const;
};

#endif
