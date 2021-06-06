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
#include <script/script.h>

template <typename T> class CBlockIndex_impl;
template <typename T> class COutPoint_impl;
class CWallet;

using BlockMap = std::unordered_map<uint256, CBlockIndex_impl<uint256> *, CCoinsKeyHasher>;
using BlockMap65536 = std::unordered_map<uint65536, CBlockIndex_impl<uint65536> *, CCoinsKeyHasher>;

/*
 * BLOCK_HASH_MODIFIER (SORA)
 * It is a mechanism that enables different hashes algorithm on the same Blockchain.
 *
 * - About instance:
 * - nHeight
 * SWITCH_LYRE2RE_BLOCK - 2 (LastBlock, No BLOCK_HASH_MODIFIER)
 * SWITCH_LYRE2RE_BLOCK - 1 (Genesis, BLOCK_HASH_MODIFIER, ONLY Scrypt)
 * SWITCH_LYRE2RE_BLOCK     (begin, BLOCK_HASH_MODIFIER)
 *
 * - About diff:
 * - workModifier low diff (reward)
 *     ASIC(1) ASIC(1) GPU(1) GPU(1) = 4 (12 min) 0
 *     ASIC(1) ASIC(1) GPU(1) GPU(1) CPU(0.05) CPU(0.05) GPU(1) = 5.1 (21 min) -1.9
 *     ASIC(1) ASIC(1) GPU(1) GPU(1) CPU(0.05) CPU(0.05) GPU(1) ASIC(2.9) = 8 (24 min) 0
 * - workModifier high diff (reward)
 *     ASIC(1) ASIC(1) GPU(1) GPU(1) = 4 (12 min) 0
 *     ASIC(1) ASIC(1) GPU(1) GPU(1) CPU(0.005) CPU(0.005) GPU(1) = 5.01 (21 min) -1.99
 *     ASIC(1) ASIC(1) GPU(1) GPU(1) CPU(0.05) CPU(0.05) GPU(1) ASIC(2.99) = 8 (24 min) 0
 */

template <typename T>
struct BLOCK_HASH_MODIFIER_MUTABLE {
#pragma pack(push, 1)
    int32_t nVersion;
    int32_t type;
    int32_t nFlags;
    int32_t nHeight;
    T prevHash;
    uint64_t workModifier;
    uint32_t workChecksum;
    unsigned char padding[80-sizeof(int32_t)*4-sizeof(T)-sizeof(uint64_t)-sizeof(uint32_t)]; // note: when T == uint256, 80 bytes
#pragma pack(pop)
    BLOCK_HASH_MODIFIER_MUTABLE() {
        static_assert(sizeof(int32_t)*4+sizeof(T)+sizeof(uint64_t)+sizeof(uint32_t)+sizeof(padding)==80, "BLOCK_HASH_MODOFIER invalid size.");
    }
};

// BLOCK_HASH_MODIFIER genesis block
namespace block_hash_modifier_genesis {
    const std::string szStr           = "Certain Exchange in Hong Kong stole a Dogecoin that is owned one of the SorachanCoin(Sora neko) developers. "
                                        "We are currently under negotiation. Please back a Dogecoin.";
    constexpr int32_t nVersion        = 1;
    constexpr int32_t type            = 1;
    constexpr int32_t nFlags          = 1;
    constexpr int32_t nHeight         = -1;
    constexpr uint64_t workModifier   = 0;
    constexpr uint32_t workChecksum   = 0;

    extern BLOCK_HASH_MODIFIER_MUTABLE<uint256> create_block_hash_modifier_genesis();
}

// BLOCK_HASH_MODIFIER info
namespace block_hash_modifier_info {
    extern unsigned char gpchMessageStart[4]; // = { 0xfe, 0xf8, 0xf5, 0xf1 }
}

// hash type: Block hash algo.
enum BLOCK_HASH_TYPE {
    SCRYPT_POW_TYPE = 1,       // ASIC
    LYRA2REV2_POW_TYPE,        // GPU
    YESPOWER_POW_TYPE,         // CPU
    LYRA2REV2_POS_TYPE,        // Stake
    LYRA2REV2_MASTERNODE_TYPE, // Masternode
    LYRA2REV2_POBENCH_TYPE,    // SSD: Sora neko
    LYRA2REV2_POSPACE_TYPE     // HDD: Chia
};

// block hash type flags
enum BLOCK_HASH_FLAG {
    BH_INVALID = (1 << 0),
    BH_NORMAL = (1 << 1),
    BH_MOD_DIFF = (1 << 2),
};

template <typename T>
class BLOCK_HASH_MODIFIER : protected BLOCK_HASH_MODIFIER_MUTABLE<T> {
    //BLOCK_HASH_MODIFIER(const BLOCK_HASH_MODIFIER &)=delete;
    //BLOCK_HASH_MODIFIER &operator=(const BLOCK_HASH_MODIFIER &)=delete;
    //BLOCK_HASH_MODIFIER(BLOCK_HASH_MODIFIER &&)=delete;
    //BLOCK_HASH_MODIFIER &operator=(BLOCK_HASH_MODIFIER &&)=delete;
    static constexpr int32_t BLOCK_HASH_MODIFIER_VERSION = 1;
public:
    int32_t get_nVersion() const {return this->nVersion;}
    int32_t get_type() const {return this->type;}
    int32_t get_nFlags() const {return this->nFlags;}
    int32_t get_nHeight() const {return this->nHeight;}
    const T &get_prevHash() const {return this->prevHash;}
    uint64_t get_workModifier() const {return this->workModifier;}
    uint32_t get_workChecksum() const {return this->workChecksum;}

    void set_nVersion(int32_t _v) {this->nVersion = _v;}
    void set_type(int32_t _v) {this->type = _v;}
    void set_nFlags(int32_t _v) {this->nFlags = _v;}
    void set_nHeight(int32_t _v) {this->nHeight = _v;}
    void set_prevHash(const T &_v) {this->prevHash = _v;}
    void set_workModifier(uint64_t _v) {this->workModifier = _v;}
    void set_workChecksum(uint32_t _v) {this->workChecksum = _v;}

    BLOCK_HASH_MODIFIER() {
        SetNull();
    }

    BLOCK_HASH_MODIFIER(const BLOCK_HASH_MODIFIER_MUTABLE<T> &obj) {
        this->nVersion = obj.nVersion;
        this->type = obj.type;
        this->nFlags = obj.nFlags;
        this->nHeight = obj.nHeight;
        this->prevHash = obj.prevHash;
        this->workModifier = obj.workModifier;
        this->workChecksum = obj.workChecksum;
        std::memcpy(this->padding, obj.padding, sizeof(this->padding));
    }

    explicit BLOCK_HASH_MODIFIER(int32_t height) {
        SetNull();
        this->nHeight = height;
    }

    void SetNull() {
        this->nVersion = BLOCK_HASH_MODIFIER<T>::BLOCK_HASH_MODIFIER_VERSION;
        this->type = LYRA2REV2_POW_TYPE;
        this->nFlags = BH_NORMAL;
        this->nHeight = -1;
        this->prevHash = 0;
        this->workModifier = 1;
        this->workChecksum = 0;
        std::memset(this->padding, 0x00, sizeof(this->padding));
    }

    bool IsValid() const {
        return !(this->nFlags & BH_INVALID);
    }

    T GetBlockModifierHash(int32_t height) const;

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(this->type);
        READWRITE(this->nFlags);
        READWRITE(this->nHeight);
        READWRITE(this->prevHash);
        READWRITE(this->workModifier);
        READWRITE(this->workChecksum);
    }
};

using BH_TYPE = BLOCK_HASH_MODIFIER<uint256>;
using BlockHeight = std::unordered_map<uint256, BH_TYPE, CCoinsKeyHasher>;
using BH_TYPE65536 = BLOCK_HASH_MODIFIER<uint65536>;
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
