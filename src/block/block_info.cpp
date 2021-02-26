// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <block/block_info.h>
#include <block/transaction.h>

CScript block_info::COINBASE_FLAGS;
std::map<uint256, CBlockIndex_impl<uint256> *> block_info::mapBlockIndex;
std::set<std::pair<COutPoint_impl<uint256>, unsigned int> > block_info::setStakeSeen;
CBlockIndex_impl<uint256> *block_info::pindexGenesisBlock = nullptr;
int64_t block_info::nTimeBestReceived = 0;
std::set<CWallet *> block_info::setpwalletRegistered;
uint64_t block_info::nLastBlockTx = 0;
uint64_t block_info::nLastBlockSize = 0;
uint32_t block_info::nLastCoinStakeSearchInterval = 0;
int block_info::nBestHeight = -1;
uint256 block_info::nBestChainTrust = 0;
uint256 block_info::nBestInvalidTrust = 0;
uint256 block_info::hashBestChain = 0;
CBlockIndex_impl<uint256> *block_info::pindexBest = nullptr;
unsigned int block_info::nTransactionsUpdated = 0;
int64_t block_info::nTransactionFee = block_params::MIN_TX_FEE;
int64_t block_info::nMinimumInputValue = block_params::MIN_TXOUT_AMOUNT;
int block_info::nScriptCheckThreads = 0;
unsigned char block_info::gpchMessageStart[4] = { 0xe4, 0xe8, 0xe9, 0xe5 };

CScript block_info2::COINBASE_FLAGS;
std::map<uint65536, CBlockIndex_impl<uint65536> *> block_info2::mapBlockIndex;
std::set<std::pair<COutPoint_impl<uint65536>, unsigned int> > block_info2::setStakeSeen;
CBlockIndex_impl<uint65536> *block_info2::pindexGenesisBlock = nullptr;
int64_t block_info2::nTimeBestReceived = 0;
std::set<CWallet *> block_info2::setpwalletRegistered;
uint64_t block_info2::nLastBlockTx = 0;
uint64_t block_info2::nLastBlockSize = 0;
uint32_t block_info2::nLastCoinStakeSearchInterval = 0;
int block_info2::nBestHeight = -1;
uint65536 block_info2::nBestChainTrust = 0;
uint65536 block_info2::nBestInvalidTrust = 0;
uint65536 block_info2::hashBestChain = 0;
CBlockIndex_impl<uint65536> *block_info2::pindexBest = nullptr;
unsigned int block_info2::nTransactionsUpdated = 0;
int64_t block_info2::nTransactionFee = block_params::MIN_TX_FEE;
int64_t block_info2::nMinimumInputValue = block_params::MIN_TXOUT_AMOUNT;
int block_info2::nScriptCheckThreads = 0;
unsigned char block_info2::gpchMessageStart[4] = { 0xe4, 0xe8, 0xe9, 0xe6 };
