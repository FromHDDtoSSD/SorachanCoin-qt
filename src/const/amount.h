// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// About CAmount
// old core: minimum unit, 100 sat (util::COIN)
// latest core: minimum unit, 1 sat (latest_amount::COIN)

#ifndef BITCOIN_AMOUNT_H
#define BITCOIN_AMOUNT_H

#include <serialize.h>
#include <util.h>
#include <util/tinyformat.h>

/** Amount in satoshis (Can be negative) */
using CAmount = int64_t;
namespace CAmountUnit {
    static constexpr int64_t COIN = util::COIN;
}

/** Type-safe wrapper class to for fee rates
 * (how much to pay based on transaction size)
 */
class CFeeRate
{
private:
    CAmount nSatoshisPerK; // unit is satoshis-per-1,000-bytes
public:
    CFeeRate() : nSatoshisPerK(0) {}
    explicit CFeeRate(const CAmount &_nSatoshisPerK) : nSatoshisPerK(_nSatoshisPerK) {}
    CFeeRate(const CAmount &nFeePaid, size_t nSize) {
        if (nSize > 0)
            nSatoshisPerK = nFeePaid * 1000 / nSize;
        else
            nSatoshisPerK = 0;
    }
    CFeeRate(const CFeeRate &other) { nSatoshisPerK = other.nSatoshisPerK; }

    CAmount GetFee(size_t nSize) const {               // unit returned is satoshis
        CAmount nFee = nSatoshisPerK * nSize / 1000;

        if (nFee == 0 && nSatoshisPerK > 0)
            nFee = nSatoshisPerK;

        return nFee;
    }
    CAmount GetFeePerK() const { return GetFee(1000); } // satoshis-per-1000-bytes

    friend bool operator<(const CFeeRate &a, const CFeeRate &b) { return a.nSatoshisPerK < b.nSatoshisPerK; }
    friend bool operator>(const CFeeRate &a, const CFeeRate &b) { return a.nSatoshisPerK > b.nSatoshisPerK; }
    friend bool operator==(const CFeeRate &a, const CFeeRate &b) { return a.nSatoshisPerK == b.nSatoshisPerK; }
    friend bool operator<=(const CFeeRate &a, const CFeeRate &b) { return a.nSatoshisPerK <= b.nSatoshisPerK; }
    friend bool operator>=(const CFeeRate &a, const CFeeRate &b) { return a.nSatoshisPerK >= b.nSatoshisPerK; }
    std::string ToString() const {
        return tinyformat::format("%d.%08d PIV/kB", nSatoshisPerK / CAmountUnit::COIN, nSatoshisPerK % CAmountUnit::COIN);
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action, int nType=0, int nVersion=0) {
        READWRITE(nSatoshisPerK);
    }
};

namespace latest_amount {
static constexpr CAmount COIN = 100000000;

/** No amount larger than this (in satoshi) is valid.
 *
 * Note that this constant is *not* the total money supply, which in Bitcoin
 * currently happens to be less than 21,000,000 BTC for various reasons, but
 * rather a sanity check. As this sanity check is used by consensus-critical
 * validation code, the exact value of the MAX_MONEY constant is consensus
 * critical; in unusual circumstances like a(nother) overflow bug that allowed
 * for the creation of coins out of thin air modification could lead to a fork.
 * */
static constexpr CAmount MAX_MONEY = 8000000 * COIN;
inline bool MoneyRange(const CAmount &nValue) { return (nValue >= 0 && nValue <= latest_amount::MAX_MONEY); }
} // namespace latest_amount

#endif //  BITCOIN_AMOUNT_H
