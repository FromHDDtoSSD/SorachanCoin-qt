// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2025 The SorachanCoin developers
// Copyright (c) 2025 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_INFO_H
#define BITCOIN_BLOCK_INFO_H

#include <set>
#include <unordered_map>
#include <uint256.h>
#include <version.h>
#include <block/block_chain.h>
#include <block/block_keyhasher.h>
#include <serialize.h>
#include <script/script.h>
#include <checkpoints/checkpoints_type.h>

class CBlockIndex;
class COutPoint;
class CWallet;

using BlockMap = std::unordered_map<uint256, CBlockIndex *, CCoinsKeyHasher>;

// BLOCK HASH functions
namespace block_hash_func {
    extern uint256 GetPoW_Scrypt(const char *data);
    extern uint256 GetPoW_Sha3d(const char *data);
    //extern uint256 GetPoW_Sora2(const char *data);
}

namespace block_info
{
    extern CScript COINBASE_FLAGS;

    extern CChain_impl<uint256> chainActive;
    extern BlockMap mapBlockIndex;

    extern std::set<std::pair<COutPoint, unsigned int> > setStakeSeen;
    extern CBlockIndex *pindexGenesisBlock;// = nullptr;

    const std::string strMessageMagic = strCoinName " Signed Message:\n";

    extern int64_t nTimeBestReceived;// = 0;
    extern std::set<CWallet *> setpwalletRegistered;

    extern uint64_t nLastBlockTx;// = 0;
    extern uint64_t nLastBlockSize;// = 0;
    extern uint32_t nLastCoinStakeSearchInterval;// = 0;

    extern int nBestHeight;// = -1; ///// []
    extern uint256 nBestChainTrust;// = 0;
    extern uint256 nBestInvalidTrust;// = 0;
    extern uint256 hashBestChain;// = 0;
    extern CBlockIndex *pindexBest;// = nullptr;
    extern unsigned int nTransactionsUpdated;// = 0;

    // Settings
    extern int64_t nTransactionFee;// = block_params::MIN_TX_FEE;
    extern int64_t nMinimumInputValue;// = block_params::MIN_TXOUT_AMOUNT;
    extern int nScriptCheckThreads;// = 0;

    extern unsigned char gpchMessageStart[4];// = { 0xe4, 0xe8, 0xe9, 0xe5 };
}

#endif
