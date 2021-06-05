// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Copyright (c) 2018-2021 The Sora neko developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_INFO_H
#define BITCOIN_BLOCK_INFO_H

#include <map>
#include <set>
#include <unordered_map>
#include <uint256.h>
#include <version.h>
#include <block/block_chain.h>
#include <block/block_keyhasher.h>
#include <serialize.h>

template <typename T> class CBlockIndex_impl;
template <typename T> class COutPoint_impl;
class CWallet;
class CScript;

using BlockMap = std::unordered_map<uint256, CBlockIndex_impl<uint256> *, CCoinsKeyHasher>;
using BlockMap65536 = std::unordered_map<uint65536, CBlockIndex_impl<uint65536> *, CCoinsKeyHasher>;

// BLOCK_HASH_MODIFIER genesis block hash
const std::string block_hash_modifier_genesis = "Certain exchange in Hong Kong stole a Dogecoin that one of the SorachanCoin(Sora neko) developers own. We are currently under negotiation a return coins.";

// hash type: Block hash algo.
enum BLOCK_HASH_TYPE {
    SCRYPT_POW_TYPE,           // ASIC
    LYRA2REV2_POW_TYPE,        // GPU
    YESPOWER_POW_TYPE,         // CPU
    LYRA2REV2_POS_TYPE,        // Stake
    LYRA2REV2_MASTERNODE_TYPE, // Masternode
    LYRA2REV2_POBENCH_TYPE,    // SSD: Sora neko
    LYRA2REV2_POSPACE_TYPE     // HDD: Chia
};
template <typename T>
struct BLOCK_HASH_MODIFIER {
#pragma pack(push, 1)
    int type;
    T prevHash; // 0: unconfirmed(valid), hash value: confirmed(valid)
    uint64_t workModifier;
    uint32_t workChecksum;
    unsigned char pad[80-sizeof(int)-sizeof(T)-sizeof(uint64_t)-sizeof(uint32_t)]; // note: when T == uint256, 80 bytes
#pragma pack(pop)
    BLOCK_HASH_MODIFIER() {
        static_assert(sizeof(int)+sizeof(T)+sizeof(uint64_t)+sizeof(uint32_t)+sizeof(pad)==80, "BLOCK_HASH_MODOFIER invalid size.");
        type = LYRA2REV2_POW_TYPE;
        prevHash = 0;
        workModifier = 1;
        workChecksum = 0;
        std::memset(pad, 0x00, sizeof(pad));
    }

    T GetBlockModifierHash(uint32_t _in) const;

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(type);
        READWRITE(prevHash);
        READWRITE(workModifier);
        READWRITE(workChecksum);
    }
};

// insert: Scrypt(Last), Lyra(Switch), Lyra, Lyra ...
using BH_TYPE = std::pair<int, BLOCK_HASH_MODIFIER<uint256> >;
using BlockHeight = std::unordered_map<uint256, BH_TYPE, CCoinsKeyHasher>;
using BH_TYPE65536 = std::pair<int, BLOCK_HASH_MODIFIER<uint65536> >;
using BlockHeight65536 = std::unordered_map<uint65536, BH_TYPE65536, CCoinsKeyHasher>;

// T == uint256
namespace block_info
{
    extern CScript COINBASE_FLAGS;

    extern CChain_impl<uint256> chainActive;
    extern BlockMap mapBlockIndex;
    extern BlockHeight mapBlockLyraHeight;
    extern std::set<std::pair<COutPoint_impl<uint256>, unsigned int> > setStakeSeen;
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

#endif
