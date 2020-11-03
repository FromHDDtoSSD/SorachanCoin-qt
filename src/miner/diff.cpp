// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <miner/diff.h>
#include <const/block_param.h>
#include <block/block.h>
#include <block/block_check.h>
#include <timestamps.h>

CBigNum diff::bnProofOfWorkLimit = diff::mainnet::bnProofOfWorkLimit;

// maximum nBits value could possible be required nTime after
unsigned int diff::amount::ComputeMaxBits(CBigNum bnTargetLimit, unsigned int nBase, int64_t nTime)
{
    CBigNum bnResult;
    bnResult.SetCompact(nBase);
    bnResult *= 2;
    while (nTime > 0 && bnResult < bnTargetLimit) {
        bnResult *= 2;        // Maximum 200% adjustment per day...
        nTime -= util::nOneDay;
    }
    if (bnResult > bnTargetLimit)
        bnResult = bnTargetLimit;
    return bnResult.GetCompact();
}

// select stake target limit according to hard-coded conditions
CBigNum diff::amount::GetProofOfStakeLimit(int nHeight, unsigned int nTime)
{
    if(args_bool::fTestNet)
        return diff::bnProofOfStakeLimit;
    else {
        if(nTime > timestamps::TARGETS_SWITCH_WORK) return diff::bnProofOfStakeLimit;
        return diff::bnProofOfWorkLimit; // return bnProofOfWorkLimit(PoW_Limit) of none matched
    }
}

// minimum amount of work that could possibly be required nTime after
// minimum proof-of-work required was nBase
unsigned int diff::amount::ComputeMinWork(unsigned int nBase, int64_t nTime)
{
    return diff::amount::ComputeMaxBits(diff::bnProofOfWorkLimit, nBase, nTime);
}

// minimum amount of stake that could possibly be required nTime after
// minimum proof-of-stake required was nBase
unsigned int diff::amount::ComputeMinStake(unsigned int nBase, int64_t nTime, unsigned int nBlockTime)
{
    return diff::amount::ComputeMaxBits(diff::amount::GetProofOfStakeLimit(0, nBlockTime), nBase, nTime);
}

bool diff::check::CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    // Check range
    if (bnTarget <= 0 || bnTarget > diff::bnProofOfWorkLimit)
        return print::error("diff::check::CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget.getuint256())
        return print::error("diff::check::CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

// miner's coin base reward based on nBits
int64_t diff::reward::GetProofOfWorkReward(unsigned int nBits, int64_t nFees /*= 0*/)
{
    int64_t nSubsidy = block_param::MAX_MINT_PROOF_OF_WORK;
    if (block_info::nBestHeight == 0)
        nSubsidy = block_param::COIN_PREMINE;
    else {
        for(std::list<std::pair<int, int64_t> >::const_iterator it = blockreward::POW_REWARD_BLOCK.begin(); it != blockreward::POW_REWARD_BLOCK.end(); ++it) {
            std::pair<int, int64_t> data1 = *it;
            nSubsidy = data1.second;
            std::list<std::pair<int, int64_t> >::const_iterator next = it; ++next;
            if(next == blockreward::POW_REWARD_BLOCK.end())
                break;

            std::pair<int, int64_t> data2 = *next;
            if(data1.first <= block_info::nBestHeight && block_info::nBestHeight < data2.first)
                break;
        }
    }
    //printf("diff::reward::GetProofOfWork nSubsidy_%" PRId64 "\n", nSubsidy);

    if (args_bool::fDebug && map_arg::GetBoolArg("-printcreation"))
        printf("diff::reward::GetProofOfWorkReward() : create=%s nSubsidy=%" PRId64 "\n", bitstr::FormatMoney(nSubsidy).c_str(), nSubsidy);

    return nSubsidy + nFees;
}

// miner's coin stake reward based on nBits and coin age spent (coin-days)
int64_t diff::reward::GetProofOfStakeReward(int64_t nCoinAge, unsigned int nBits, int64_t nTime, bool bCoinYearOnly /*= false*/)
{
    int64_t nReward = block_param::COIN_YEAR_REWARD;
    int64_t bTime = bitsystem::GetTime();
    for(std::list<std::pair<unsigned int, int64_t> >::const_iterator it = blockreward::POS_REWARD_BLOCK.begin(); it != blockreward::POS_REWARD_BLOCK.end(); ++it) {
        std::pair<unsigned int, int64_t> data1 = *it;
        nReward = data1.second;
        std::list<std::pair<unsigned int, int64_t> >::const_iterator next = it; ++next;
        if(next == blockreward::POS_REWARD_BLOCK.end())
            break;

        std::pair<unsigned int, int64_t> data2 = *next;
        if(data1.first <= bTime && bTime < data2.first)
            break;
    }
    //printf("diff::reward::GetProofOfStakeReward nReward_%" PRId64 "\n", nReward);

    int64_t nSubsidy = nCoinAge * nReward * 33 / (365 * 33 + 8);

    if (args_bool::fDebug && map_arg::GetBoolArg("-printcreation"))
        printf("diff::reward::GetProofOfStakeReward(): create=%s nCoinAge=%" PRId64 "\n", bitstr::FormatMoney(nSubsidy).c_str(), nCoinAge);

    return nSubsidy;
}

// get proof of work blocks max spacing according to hard-coded conditions
int64_t diff::spacing::GetTargetSpacingWorkMax(int nHeight, unsigned int nTime)
{
    if(nTime < timestamps::TARGETS_SWITCH_WORK)
        return 3 * block_check::nPowTargetSpacing;
    if(args_bool::fTestNet)
        return 1 * block_check::nPowTargetSpacing;
    else
        return 2 * block_check::nPowTargetSpacing;
}

// ppcoin: find last block index up to pindex
const CBlockIndex *diff::spacing::GetLastBlockIndex(const CBlockIndex *pindex, bool fProofOfStake)
{
    while (pindex && pindex->get_pprev() && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->get_pprev();
    return pindex;
}

unsigned int diff::spacing::GetNextTargetRequired(const CBlockIndex *pindexLast, bool fProofOfStake)
{
    CBigNum bnTargetLimit = fProofOfStake ? diff::bnProofOfStakeLimit : diff::bnProofOfWorkLimit;
    if (pindexLast == nullptr)
        return bnTargetLimit.GetCompact();        // genesis block

    const CBlockIndex *pindexPrev = diff::spacing::GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->get_pprev() == nullptr)
        return bnTargetLimit.GetCompact();        // first block

    const CBlockIndex *pindexPrevPrev = diff::spacing::GetLastBlockIndex(pindexPrev->get_pprev(), fProofOfStake);
    if (pindexPrevPrev->get_pprev() == nullptr)
        return bnTargetLimit.GetCompact();        // second block

    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    CBigNum bnNew;
    bnNew.SetCompact(pindexPrev->get_nBits());
    int64_t nTargetSpacing = fProofOfStake ? block_check::nStakeTargetSpacing :
                                            std::min( diff::spacing::GetTargetSpacingWorkMax(pindexLast->get_nHeight(), pindexLast->get_nTime()), (int64_t)block_check::nStakeTargetSpacing * (1 + pindexLast->get_nHeight() - pindexPrev->get_nHeight()) );

    int64_t nInterval = block_check::nTargetTimespan / nTargetSpacing;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);
    if (bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
}
