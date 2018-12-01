// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013 The NovaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef NOVACOIN_MINER_H
#define NOVACOIN_MINER_H

#include "main.h"
#include "wallet.h"

class miner : private no_instance
{
private:
    //
    // Precalculated SHA256 contexts and metadata
    // (txid, vout.n) => (kernel, (tx.nTime, nAmount))
    //
    typedef std::map<std::pair<uint256, unsigned int>, std::pair<std::vector<unsigned char>, std::pair<uint32_t, uint64_t> > > MidstateMap;

    static const unsigned int pSHA256InitState[8];
    static unsigned int nMaxStakeSearchInterval;

    //
    // From buffer(binary) to hash
    //
    static int FormatHashBlocks(void *pbuffer, unsigned int len);

    //
    // Check mined proof-of-stake block
    //
    static bool CheckStake(CBlock *pblock, CWallet &wallet);

    //
    // Base sha256 mining transform
    //
    static void SHA256Transform(void *pstate, void *pinput, const void *pinit);

    //
    // Fill the inputs map with precalculated contexts and metadata
    //
    static bool FillMap(CWallet *pwallet, uint32_t nUpperTime, MidstateMap &inputsMap);

    //
    // Scan inputs map in order to find a solution
    //
    static bool ScanMap(const MidstateMap &inputsMap, uint32_t nBits, MidstateMap::key_type &LuckyInput, std::pair<uint256, uint32_t> &solution);

public:
    static int64_t nReserveBalance;
    static uint64_t nStakeInputsMapSize;

    //
    // Generate a new block, without valid proof-of-work/with provided proof-of-stake
    //
    static CBlock *CreateNewBlock(CWallet *pwallet, CTransaction *txAdd = NULL);

    //
    // Modify the extranonce in a block
    //
    static void IncrementExtraNonce(CBlock *pblock, CBlockIndex *pindexPrev, unsigned int &nExtraNonce);

    //
    // Do mining precalculation
    //
    static void FormatHashBuffers(CBlock *pblock, char *pmidstate, char *pdata, char *phash1);

    //
    // Check mined proof-of-work block
    //
    static bool CheckWork(CBlock *pblock, CWallet &wallet, CReserveKey &reservekey);

    //
    // Stake miner thread
    //
    static void ThreadStakeMiner(void *parg);
};

#endif // NOVACOIN_MINER_H
//@
