// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_CHECK_H
#define BITCOIN_BLOCK_CHECK_H

#include <stdint.h>
#include <util.h>
#include <block/transaction.h>

namespace block_check
{
    namespace testnet
    {
        const unsigned int nStakeMinAge = 2 * util::nOneHour;       // test net min age is 2 hours
        const unsigned int nModifierInterval = 3 * 60;              // test modifier interval is 3 minutes
        const unsigned int nStakeTargetSpacing = 1 * 60;            // test block spacing is 1 minutes
        const unsigned int nPowTargetSpacing = 60;
    }
    namespace mainnet
    {
        const unsigned int nStakeMinAge = 8 * util::nOneHour;
        const unsigned int nModifierInterval = 10 * 60;             // main modifier 10 minutes
        const unsigned int nStakeTargetSpacing = 6 * 60;
        const unsigned int nPowTargetSpacing = 3 * 60;
    }

    extern unsigned int nStakeMinAge;// = mainnet::nStakeMinAge;
    const unsigned int nStakeMaxAge = 90 * util::nOneDay;

    extern unsigned int nStakeTargetSpacing;// = mainnet::nStakeTargetSpacing;
    extern unsigned int nPowTargetSpacing; // = mainnet::nPowTargetSpacing;
    extern unsigned int nModifierInterval;// = mainnet::nModifierInterval;
    const int64_t nTargetTimespan = 7 * util::nOneDay;

    class manage : private no_instance
    {
    public:
        static void InvalidChainFound(CBlockIndex *pindexNew);
        static bool VerifySignature(const CTransaction &txFrom, const CTransaction &txTo, unsigned int nIn, unsigned int flags, int nHashType);

        static bool Reorganize(CTxDB &txdb, CBlockIndex *pindexNew);

        static int64_t PastDrift(int64_t nTime) {    // up to 2 hours from the past
            return nTime - 2 * util::nOneHour;
        }
        static int64_t FutureDrift(int64_t nTime) {  // up to 2 hours from the future
            return nTime + 2 * util::nOneHour;
        }
    };

    class thread : private no_instance
    {
    public:
        static CCheckQueue<CScriptCheck> scriptcheckqueue;
        static void ThreadScriptCheck(void *);
        static void ThreadScriptCheckQuit();
    };
}

#endif
