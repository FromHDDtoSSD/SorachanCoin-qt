// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <block/block.h>
#include <block/block_info.h>
#include <block/transaction.h>
#include <Lyra2RE/Lyra2RE.h>
#include <crypto/sha256.h>
#include <crypto/sha512.h>
#include <crypto/blake2.h>

CScript block_info::COINBASE_FLAGS;
CChain_impl<uint256> block_info::chainActive;
BlockMap block_info::mapBlockIndex;
BlockHeight block_info::mapBlockLyraHeight;
std::set<std::pair<COutPoint, unsigned int> > block_info::setStakeSeen;
CBlockIndex *block_info::pindexGenesisBlock = nullptr;
int64_t block_info::nTimeBestReceived = 0;
std::set<CWallet *> block_info::setpwalletRegistered;
uint64_t block_info::nLastBlockTx = 0;
uint64_t block_info::nLastBlockSize = 0;
uint32_t block_info::nLastCoinStakeSearchInterval = 0;
int block_info::nBestHeight = -1;
uint256 block_info::nBestChainTrust = 0;
uint256 block_info::nBestInvalidTrust = 0;
uint256 block_info::hashBestChain = 0;
CBlockIndex *block_info::pindexBest = nullptr;
unsigned int block_info::nTransactionsUpdated = 0;
int64_t block_info::nTransactionFee = block_params::MIN_TX_FEE;
int64_t block_info::nMinimumInputValue = block_params::MIN_TXOUT_AMOUNT;
int block_info::nScriptCheckThreads = 0;
unsigned char block_info::gpchMessageStart[4] = { 0xe4, 0xe8, 0xe9, 0xe5 };

// block_hash_modifier checkpoints and modifierChecksum
const MapCheckpoints block_hash_modifier_checkpoints::mapCheckpoints = {
    {SWITCH_LYRE2RE_BLOCK-1, block_hash_modifier_genesis::mainnet_genesic_hash},
};

const MapCheckpoints block_hash_modifier_checkpoints::mapCheckpointsTestnet = {
    {SWITCH_LYRE2RE_BLOCK_TESTNET-1, block_hash_modifier_genesis::testnet_genesis_hash},
    {1501700, uint256("0xe70859bc50c10caf55d3436e70614b50553d2805bf802846605af839f311ff1e")},
};

const LastCheckpointTime block_hash_modifier_checkpoints::CheckpointLastTime = 0;
const LastCheckpointTime block_hash_modifier_checkpoints::CheckpointLastTimeTestnet = 0;

bool block_hash_modifier_checkpoints::CheckOrphanBlock(int nHeight, const uint256 &hash, const std::string ToString/*=""*/) { // nHeight is current
    if(args_bool::fDebug)
        debugcs::instance() << "block_hash_modifier checkpoint nHeight: " << nHeight << " hash: " << hash.ToString().c_str() << debugcs::endl();
    const MapCheckpoints &mapcp = args_bool::fTestNet ?
            block_hash_modifier_checkpoints::mapCheckpointsTestnet:
            block_hash_modifier_checkpoints::mapCheckpoints;

    MapCheckpoints::const_iterator mi = mapcp.find(nHeight);
    if(mi==mapcp.end())
        return true;
    if((*mi).second==hash)
        return true;

    // under development
    logging::LogPrintf("If pass block_hash_modifier_checkpoints::CheckOrphanBlock, there is an orphan block on the Blockchain.\n");
    return true;
}

// block_hash_modofier message
unsigned char block_hash_modifier_info::gpchMessageStart[4] = { 0xfe, 0xf8, 0xf5, 0xf1 };

// block_hash_modifier genesis
BLOCK_HASH_MODIFIER_MUTABLE block_hash_modifier_genesis::create_block_hash_modifier_genesis() {
    BLOCK_HASH_MODIFIER_MUTABLE bhm;
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

// block hash flags
int32_t block_hash_helper::create_proof_nonce_zero(bool pos, bool masternode, bool pobench, bool pospace, bool popredict) {
    return ( ((pos?1:0) << 4) |
             ((masternode?1:0) << 5) |
             ((pobench?1:0) << 6) |
             ((pospace?1:0) << 7) |
             ((popredict?1:0) << 8) );
}

bool block_hash_helper::is_proof(int type, int32_t nonce_zero_value) {
    if(type==SCRYPT_POS_TYPE)
        return (bool)(nonce_zero_value & (1 << 4));
    if(type==SCRYPT_MASTERNODE_TYPE)
        return (bool)(nonce_zero_value & (1 << 5));
    if(type==SCRYPT_POBENCH_TYPE)
        return (bool)(nonce_zero_value & (1 << 6));
    if(type==SCRYPT_POSPACE_TYPE)
        return (bool)(nonce_zero_value & (1 << 7));
    if(type==SCRYPT_POPREDICT_TYPE)
        return (bool)(nonce_zero_value & (1 << 8));

    return false;
}

uint256 BLOCK_HASH_MODIFIER::GetBlockModifierHash() const {
    uint256 hash;
    lyra2re2_hash((const char *)this, BEGIN(hash));
    if(args_bool::fDebug)
        logging::LogPrintf("BLOCK_HASH_MODIFIER::GetBlockModifierHash hash:%s info:%s\n", hash.ToString().c_str(), this->ToString().c_str());
    return hash;
}

//
// PoW [uint256] HASH Algorithm
// "const char *data" size is 80 bytes.
//
uint256 block_hash_func::GetPoW_Scrypt(const char *data) {
    return bitscrypt::scrypt_blockhash(data);
}

uint256 block_hash_func::GetPoW_Lyra2REV2(const char *data) {
    uint256 hash;
    lyra2re2_hash(data, BEGIN(hash));
    return hash;
}

uint256 block_hash_func::GetPoW_Lyra2RE(const char *data) {
    uint256 hash;
    lyra2re_hash(data, BEGIN(hash));
    return hash;
}

uint256 block_hash_func::GetPoW_SHA256D(const char *data) {
    uint256 hash;
    latest_crypto::CSHA256().Write((const unsigned char *)data, 80).Finalize((unsigned char *)BEGIN(hash));
    uint256 hashD;
    latest_crypto::CSHA256().Write((const unsigned char *)BEGIN(hash), sizeof(uint256)).Finalize((unsigned char *)BEGIN(hashD));
    return hashD;
}

uint256 block_hash_func::GetPoW_SHA512D(const char *data) {
    uint512 hash;
    latest_crypto::CSHA512().Write((const unsigned char *)data, 80).Finalize((unsigned char *)BEGIN(hash));
    uint512 hashD;
    latest_crypto::CSHA512().Write((const unsigned char *)BEGIN(hash), sizeof(uint512)).Finalize((unsigned char *)BEGIN(hashD));
    CBigNum bn(bignum_vector(hashD.begin(), hashD.end()));
    return bn.getuint256();
}

uint256 block_hash_func::GetPoW_Blake2S(const char *data) {
    uint256 hash;
    latest_crypto::CBLAKE2S().Write((const unsigned char *)data, 80).Finalize((unsigned char *)BEGIN(hash));
    return hash;
}
