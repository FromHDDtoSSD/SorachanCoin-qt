// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <block/block.h>
#include <block/block_info.h>
#include <block/transaction.h>
#include <Lyra2RE/Lyra2RE.h>

// T == uint256
CScript block_info::COINBASE_FLAGS;
CChain_impl<uint256> block_info::chainActive;
BlockMap block_info::mapBlockIndex;
BlockHeight block_info::mapBlockLyraHeight;
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

// BLOCK_HASH_MODOFIER
unsigned char block_hash_modifier_info::gpchMessageStart[4] = { 0xfe, 0xf8, 0xf5, 0xf1 };

BLOCK_HASH_MODIFIER_MUTABLE<uint256> block_hash_modifier_genesis::create_block_hash_modifier_genesis() {
    BLOCK_HASH_MODIFIER_MUTABLE<uint256> bhm;
    bhm.nVersion = block_hash_modifier_genesis::nVersion;
    bhm.prevHash = hash_basis::Hash(block_hash_modifier_genesis::szStr.begin(), block_hash_modifier_genesis::szStr.end());
    bhm.type = block_hash_modifier_genesis::type;
    bhm.nFlags = block_hash_modifier_genesis::nFlags;
    bhm.nHeight = args_bool::fTestNet ? SWITCH_LYRE2RE_BLOCK_TESTNET-1: SWITCH_LYRE2RE_BLOCK-1;
    bhm.workModifierL = block_hash_modifier_genesis::workModifierLH;
    bhm.workModifierH = block_hash_modifier_genesis::workModifierLH;
    bhm.workChecksum = block_hash_modifier_genesis::workChecksum;
    bhm.nTime = args_bool::fTestNet ? block_hash_modifier_genesis::testnet_timestamp: block_hash_modifier_genesis::mainnet_timestamp;
    bhm.unused1 = 0;
    bhm.unused2 = 0;
    bhm.unused3 = 0;
    bhm.unused4 = 0;
    return bhm;
}

template <typename T>
T BLOCK_HASH_MODIFIER<T>::GetBlockModifierHash() const {
    T hash;
    lyra2re2_hash((const char *)this, BEGIN(hash));
    logging::LogPrintf("BLOCK_HASH_MODIFIER::GetBlockModifierHash hash:%s info:%s\n", hash.ToString().c_str(), this->ToString().c_str());
    return hash;
}

/*
template <typename T>
T BLOCK_HASH_MODIFIER<T>::GetBlockModifierHash(int32_t height) const {
    const int32_t sw_height=args_bool::fTestNet ? SWITCH_LYRE2RE_BLOCK_TESTNET: SWITCH_LYRE2RE_BLOCK;
    if(height >= sw_height) {
        T hash;
        lyra2re2_hash((const char *)this, BEGIN(hash));
        return hash;
    } else {
        BLOCK_HASH_MODIFIER_MUTABLE<T> bhm = block_hash_modifier_genesis::create_block_hash_modifier_genesis();
        T hash;
        lyra2re2_hash((const char *)&bhm, BEGIN(hash));
        return hash;
    }
}
*/

template class BLOCK_HASH_MODIFIER<uint256>;
