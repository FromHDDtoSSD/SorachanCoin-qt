// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The Sora neko developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/scriptnum.h>
#include <uint256.h>
#include <stdexcept>

//
// CScriptNum
//

namespace {

class scriptnum_error : public std::runtime_error
{
public:
    explicit scriptnum_error(const std::string &str) : std::runtime_error(str) {}
};

} // namespace

CScriptNum::CScriptNum(const script_vector &vch, bool fRequireMinimal,
                                const size_t nMaxNumSize /*= nDefaultMaxNumSize*/)
{
    if (vch.size() > nMaxNumSize)
        throw scriptnum_error("script number overflow");

    if (fRequireMinimal && vch.size() > 0) {
        // Check that the number is encoded with the minimum possible
        // number of bytes.
        //
        // If the most-significant-byte - excluding the sign bit - is zero
        // then we're not minimal. Note how this test also rejects the
        // negative-zero encoding, 0x80.
        if ((vch.back() & 0x7f) == 0) {
            // One exception: if there's more than one byte and the most
            // significant bit of the second-most-significant-byte is set
            // it would conflict with the sign bit. An example of this case
            // is +-255, which encode to 0xff00 and 0xff80 respectively.
            // (big-endian).
            if (vch.size() <= 1 || (vch[vch.size() - 2] & 0x80) == 0)
                throw scriptnum_error("non-minimally encoded script number");
        }
    }
    m_value = unserialize(vch);
}

int CScriptNum::getint() const {
    if (m_value > std::numeric_limits<int>::max())
        return std::numeric_limits<int>::max();
    else if (m_value < std::numeric_limits<int>::min())
        return std::numeric_limits<int>::min();
    return m_value;
}

int64_t CScriptNum::getint64() const {
    return m_value;
}

CScriptNum::script_vector CScriptNum::getvch() const {
    return std::move(serialize(m_value));
}

CScriptNum::script_vector CScriptNum::serialize(const int64_t &value) {
    if(value == 0)
        return script_vector();

    script_vector result;
    const bool neg = value < 0;
    uint64_t absvalue = neg ? -value : value;

    while(absvalue)
    {
        result.push_back(absvalue & 0xff);
        absvalue >>= 8;
    }

    // - If the most significant byte is >= 0x80 and the value is positive, push a
    // new zero-byte to make the significant byte < 0x80 again.
    // - If the most significant byte is >= 0x80 and the value is negative, push a
    // new 0x80 byte that will be popped off when converting to an integral.
    // - If the most significant byte is < 0x80 and the value is negative, add
    // 0x80 to it, since it will be subtracted and interpreted as a negative when
    // converting to an integral.
    if (result.back() & 0x80)
        result.push_back(neg ? 0x80 : 0);
    else if (neg)
        result.back() |= 0x80;

    return std::move(result);
}

int64_t CScriptNum::unserialize(const script_vector &vch) {
    if (vch.empty())
        return 0;

    int64_t result = 0;
    for (size_t i = 0; i != vch.size(); ++i)
        result |= static_cast<int64_t>(vch[i]) << 8*i;

    // If the input vector's most significant byte is 0x80, remove it from
    // the result's msb and return a negative.
    if (vch.back() & 0x80)
        return -((int64_t)(result & ~(0x80ULL << (8 * (vch.size() - 1)))));

    return result;
}

//
// CNekoNum
//

namespace {

class nekonum_error : public std::runtime_error
{
public:
    explicit nekonum_error(const std::string &str) : std::runtime_error(str) {}
};

// Note that, size: header + data's size (total size)
void SN_mpi2bn(const unsigned char *in, size_t size, BIGNUM_NEKONABE *p) {
    if(size > sizeof(BIGNUM_NEKONABE::d))
        throw scriptnum_error("SN_mpi2bn size error");
    int zero=0;
    if(in[4]==0) ++zero;
    for(int i=4+zero, j=4; i <= 6; ++i)
        p->d[j++] = in[i];
    p->d[3] = (uint8_t)(size-zero-4);
}

size_t SN_bn2mpi(const BIGNUM_NEKONABE *in, unsigned char *p) { // if p == nullptr, return is size.
    const size_t size = (size_t)in->d[3];
    if(4 > size || size > sizeof(BIGNUM_NEKONABE::d)) {
        throw scriptnum_error(std::string("SN_bn2mpi size error, size: ") + std::to_string(size));
        return size;
    }
    if(p==nullptr)
        return size+4;
    p[3] = (uint8_t)size;
    for(int i=4; i < size; ++i)
        p[i] = in->d[i];
    return size;
}
} // namespace

int CNekoNum::getint() const {
    int32_t n = get_int32();
    if (n > std::numeric_limits<int>::max())
        return std::numeric_limits<int>::max();
    else if (n < std::numeric_limits<int>::min())
        return std::numeric_limits<int>::min();
    return n;
}

uint32_t CNekoNum::getuint32() const {
    int ret = getint();
    if(ret < 0) {
        throw nekonum_error("neko nagative");
        return 0;
    }
    return (uint32_t)ret;
}

int64_t CNekoNum::getint64() const {
    return get_int64();
}

uint64_t CNekoNum::getuint64() const {
    int64_t ret = getint64();
    if(ret < 0) {
        throw nekonum_error("neko nagative");
        return 0;
    }
    return (uint64_t)ret;
}

uint256 CNekoNum::getuint256() const {
    unsigned int nSize = SN_bn2mpi(static_cast<const BIGNUM_NEKONABE *>(this), nullptr);
    if (nSize < 4) {
        return 0;
    }

    std::vector<uint8_t> vch(nSize);
    SN_bn2mpi(static_cast<const BIGNUM_NEKONABE *>(this), &vch[0]);
    if (vch.size() > 4) {
        vch[4] &= 0x7f;
    }

    uint256 n = 0;
    for (size_t i = 0, j = vch.size() - 1; i < sizeof(n) && j >= 4; i++, j--)
        ((uint8_t *)&n)[i] = vch[j];

    return n;
}

CNekoNum &CNekoNum::SetCompact(uint32_t nCompact) {
    SetNull();
    uint32_t nSize = nCompact >> 24;
    std::vector<uint8_t> vch(4 + nSize);
    assert(vch.size()==4+nSize);
    vch[3] = nSize;

    if (nSize >= 1) { vch[4] = (nCompact >> 16) & 0xff; }
    if (nSize >= 2) { vch[5] = (nCompact >> 8) & 0xff; }
    if (nSize >= 3) { vch[6] = (nCompact >> 0) & 0xff; }
    SN_mpi2bn(&vch[0], vch.size(), static_cast<BIGNUM_NEKONABE *>(this));
    return *this;
}

uint32_t CNekoNum::GetCompact() const {
    uint32_t nSize = SN_bn2mpi(static_cast<const BIGNUM_NEKONABE *>(this), nullptr);
    if(4 > nSize) {
        throw nekonum_error("neko overflow");
        return 0;
    }
    std::vector<uint8_t> vch(nSize);
    nSize -= 4;
    SN_bn2mpi(static_cast<const BIGNUM_NEKONABE *>(this), &vch[0]);
    uint32_t nCompact = nSize << 24;

    if (nSize >= 1) { nCompact |= (vch[4] << 16); }
    if (nSize >= 2) { nCompact |= (vch[5] << 8); }
    if (nSize >= 3) { nCompact |= (vch[6] << 0); }
    return nCompact;
}
