// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DIFF_H
#define BITCOIN_DIFF_H

#include <bignum.h>
#include <uint256.h>

template<typename T> class CBlockIndex_impl;
using CBlockIndex = CBlockIndex_impl<uint256>;

template<typename T> class CBlockHeader_impl;

// PoW / PoS difficulty
namespace diff
{
    namespace testnet
    {
        const CBigNum bnProofOfWorkLimit(~uint256(0) >> 16);                // 16 bits PoW target limit for testnet
    }
    namespace mainnet
    {
        const CBigNum bnProofOfWorkLimit(~uint256(0) >> 20);                // "standard" scrypt target limit for proof of work, results with 0.000244140625 proof of work difficulty
    }
    extern CBigNum bnProofOfWorkLimit;// = mainnet::bnProofOfWorkLimit;

    const CBigNum bnProofOfStakeLimit(~uint256(0) >> 27);                   // 0.03125  proof of stake difficulty
    const uint256 nPoWBase = uint256("0x00000000ffff0000000000000000000000000000000000000000000000000000"); // difficulty-1 target

    // minimum amount of work that could possibly be required nTime after
    class amount : private no_instance
    {
    private:
        static unsigned int ComputeMaxBits(CBigNum bnTargetLimit, unsigned int nBase, int64_t nTime);
        static CBigNum GetProofOfStakeLimit(int nHeight, unsigned int nTime);
    public:
        static unsigned int ComputeMinWork(unsigned int nBase, int64_t nTime);
        static unsigned int ComputeMinStake(unsigned int nBase, int64_t nTime, unsigned int nBlockTime);
    };

    // check range and proof-of matches claimed amount
    class check : private no_instance
    {
    public:
        static bool CheckProofOfWork(uint256 hash, unsigned int nBits); // [only compare nBits] old_chain(v1,v2,v3) or registered after mapBlockLyraHeight(ReadFromDisk and CheckDisk)
        static bool CheckProofOfWork2(int32_t height, int32_t nonce_zero_value, const CBlockHeader_impl<uint256> &header, int &type); // [confirm type and compare nBits] new_chain(after v4)
    };

    //  miner's coin reward based on nBits
    class reward : private no_instance
    {
    public:
        static int64_t GetProofOfWorkReward(unsigned int nBits, int64_t nFees = 0);
        static int64_t GetProofOfStakeReward(int64_t nCoinAge, unsigned int nBits, int64_t nTime, bool bCoinYearOnly = false);
    };

    // get proof of work blocks max spacing according to hard-coded conditions
    class spacing : private no_instance
    {
    private:
        static int64_t GetTargetSpacingWorkMax(int nHeight, unsigned int nTime);
    public:
        static const CBlockIndex *GetLastBlockIndex(const CBlockIndex *pindex, bool fProofOfStake);
        static unsigned int GetNextTargetRequired(const CBlockIndex *pindexLast, bool fProofOfStake);
    };
}

#endif // BITCOIN_DIFF_H
