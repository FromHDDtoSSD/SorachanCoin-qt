// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_INFO_H
#define BITCOIN_BLOCK_INFO_H

#include <map>
#include <set>
#include <uint256.h>
#include <version.h>

template <typename T> class CBlockIndex_impl;
using CBlockIndex = CBlockIndex_impl<uint256>;
template <typename T> class COutPoint_impl;
using COutPoint = COutPoint_impl<uint256>;

class CWallet;
class CScript;

// mainchain
namespace block_info
{
    extern CScript COINBASE_FLAGS;

    extern std::map<uint256, CBlockIndex_impl<uint256> *> mapBlockIndex;
    extern std::set<std::pair<COutPoint_impl<uint256>, unsigned int>> setStakeSeen;
    extern CBlockIndex_impl<uint256> *pindexGenesisBlock;// = nullptr;

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
    extern CBlockIndex_impl<uint256> *pindexBest;// = nullptr;
    extern unsigned int nTransactionsUpdated;// = 0;

    // Settings
    extern int64_t nTransactionFee;// = block_params::MIN_TX_FEE;
    extern int64_t nMinimumInputValue;// = block_params::MIN_TXOUT_AMOUNT;
    extern int nScriptCheckThreads;// = 0;

    extern unsigned char gpchMessageStart[4];// = { 0xe4, 0xe8, 0xe9, 0xe5 };
}

// finexdrivechain
namespace block_info2
{
    extern CScript COINBASE_FLAGS;

    extern std::map<uint65536, CBlockIndex_impl<uint65536> *> mapBlockIndex;
    extern std::set<std::pair<COutPoint_impl<uint65536>, unsigned int>> setStakeSeen;
    extern CBlockIndex_impl<uint65536> *pindexGenesisBlock;// = nullptr;

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
    extern CBlockIndex_impl<uint65536> *pindexBest;// = nullptr;
    extern unsigned int nTransactionsUpdated;// = 0;

    // Settings
    extern int64_t nTransactionFee;// = block_params::MIN_TX_FEE;
    extern int64_t nMinimumInputValue;// = block_params::MIN_TXOUT_AMOUNT;
    extern int nScriptCheckThreads;// = 0;

    extern unsigned char gpchMessageStart[4];// = { 0xe4, 0xe8, 0xe9, 0xe5 };
}

#endif
