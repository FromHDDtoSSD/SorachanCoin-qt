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
    static constexpr int32_t BLOCK_HASH_MODIFIER_VERSION = 1;
#pragma pack(push, 1)
    int32_t nVersion;
    T prevHash;
    int32_t type;
    int32_t nFlags;
    int32_t nHeight;
    uint32_t workModifierL;
    uint32_t workModifierH;
    uint32_t workChecksum;
    uint32_t nTime;
    int32_t unused1;
    int32_t unused2;
    int32_t unused3;
    int32_t unused4;
#pragma pack(pop)
    BLOCK_HASH_MODIFIER_MUTABLE() {
        static_assert(sizeof(*this)==80, "BLOCK_HASH_MODIFIER_MUTABLE invalid size.");
    }
};

// BLOCK_HASH_MODIFIER genesis block
namespace block_hash_modifier_genesis {
    const std::string szStr           = "Certain Exchange in Hong Kong stole a Dogecoin that is owned by one of the SorachanCoin(Sora neko) developers. "
                                        "We are currently under negotiation. Please back a Dogecoin. "
                                        "[junkhdd.com and iuec.co.jp] Data Recovery in JAPAN project.";
    constexpr int32_t nVersion        = 1;
    constexpr int32_t type            = 1;
    constexpr int32_t nFlags          = 1;
    //constexpr int32_t nHeight       = -1; // args_bool::fTestNet ? SWITCH_LYRE2RE_BLOCK_TESTNET-1: SWITCH_LYRE2RE_BLOCK-1;
    constexpr uint32_t workModifierLH = 0;
    constexpr uint32_t workChecksum   = 0;

    constexpr uint32_t mainnet_timestamp = 0;
    constexpr uint32_t testnet_timestamp = 1623044072; // 07-Jun 2021 14:34:32

    // uint256
    const uint256 mainnet_genesic_hash = uint256("0");
    const uint256 testnet_genesis_hash = uint256("0x7cc52e194af3c88de879a5d27e157d71f4e359da84937f2382edeba27230ed1b");
    extern BLOCK_HASH_MODIFIER_MUTABLE<uint256> create_block_hash_modifier_genesis();
}

// BLOCK_HASH_MODIFIER info
namespace block_hash_modifier_info {
    extern unsigned char gpchMessageStart[4]; // = { 0xfe, 0xf8, 0xf5, 0xf1 }
}

// BLOCK HASH functions
namespace block_hash_func {
    extern uint256 GetPoW_Scrypt(const char *data);
    extern uint256 GetPoW_Lyra2REV2(const char *data);
    extern uint256 GetPoW_Lyra2RE(const char *data);
    extern uint256 GetPoW_SHA256D(const char *data);
    extern uint256 GetPoW_SHA512D(const char *data);
    extern uint256 GetPoW_Blake2S(const char *data);
}

// hash type: Block hash algo.
enum BLOCK_HASH_TYPE {
    SCRYPT_POW_TYPE = 1,       // ASIC
    LYRA2REV2_POW_TYPE,        // GPU
    YESPOWER_POW_TYPE,         // CPU
    LYRA2REV2_POS_TYPE,        // Stake
    LYRA2REV2_MASTERNODE_TYPE, // Masternode
    LYRA2REV2_POBENCH_TYPE,    // SSD: Sora neko
    LYRA2REV2_POSPACE_TYPE,    // HDD: Chia
    LYRA2REV2_POPREDICT_TYPE,  // drive failure prediction: SoraChan
    SHA256D_POW_TYPE,          // ASIC
    SHA512D_POW_TYPE,          // ASIC
    BLAKE2S_POW_TYPE,          // ASIC
    LYRA2RE_POW_TYPE,          // GPU
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
public:
    int32_t get_nVersion() const {return this->nVersion;}
    const T &get_prevHash() const {return this->prevHash;}
    int32_t get_type() const {return this->type;}
    int32_t get_nFlags() const {return this->nFlags;}
    int32_t get_nHeight() const {return this->nHeight;}
    uint32_t get_workModifierL() const {return this->workModifierL;}
    uint32_t get_workModifierH() const {return this->workModifierH;}
    uint32_t get_workChecksum() const {return this->workChecksum;}
    uint32_t get_nTime() const {return this->nTime;}

    void set_nVersion(int32_t _v) {this->nVersion = _v;}
    void set_prevHash(const T &_v) {this->prevHash = _v;}
    void set_type(int32_t _v) {this->type = _v;}
    void set_nFlags(int32_t _v) {this->nFlags = _v;}
    void set_nHeight(int32_t _v) {this->nHeight = _v;}
    void set_workModifierL(uint32_t _v) {this->workModifierL = _v;}
    void set_workModifierH(uint32_t _v) {this->workModifierH = _v;}
    void set_workChecksum(uint32_t _v) {this->workChecksum = _v;}
    void set_nTime(uint32_t _v) {this->nTime = _v;}

    BLOCK_HASH_MODIFIER() {
        SetNull();
    }

    BLOCK_HASH_MODIFIER(const BLOCK_HASH_MODIFIER_MUTABLE<T> &obj) {
        this->nVersion = obj.nVersion;
        this->prevHash = obj.prevHash;
        this->type = obj.type;
        this->nFlags = obj.nFlags;
        this->nHeight = obj.nHeight;
        this->workModifierL = obj.workModifierL;
        this->workModifierH = obj.workModifierH;
        this->workChecksum = obj.workChecksum;
        this->nTime = obj.nTime;
        this->unused1 = obj.unused1;
        this->unused2 = obj.unused2;
        this->unused3 = obj.unused3;
        this->unused4 = obj.unused4;
    }

    explicit BLOCK_HASH_MODIFIER(int32_t height, uint32_t tim) {
        SetNull();
        this->nHeight = height;
        this->nTime = tim;
    }

    void SetNull() {
        this->nVersion = BLOCK_HASH_MODIFIER_MUTABLE<T>::BLOCK_HASH_MODIFIER_VERSION;
        this->prevHash = 0;
        this->type = LYRA2REV2_POW_TYPE;
        this->nFlags = BH_NORMAL;
        this->nHeight = -1;
        this->workModifierL = 1;
        this->workModifierH = 0;
        this->workChecksum = 0;
        this->nTime = 0;
        this->unused1 = 0;
        this->unused2 = 0;
        this->unused3 = 0;
        this->unused4 = 0;
    }

    bool IsValid() const {
        return !(this->nFlags & BH_INVALID);
    }

    std::string ToString() const {
        return tfm::format("BLOCK_HASH_MODIFIER nVersion=%d, prevHash=%s, type=%d, nFlags=%d, nHeight=%d, workModifierL=%d, workModifierH=%d, workChecksum=%d, nTime=%d",
                           this->nVersion,
                           this->prevHash.ToString().c_str(),
                           this->type,
                           this->nFlags,
                           this->nHeight,
                           this->workModifierL,
                           this->workModifierH,
                           this->workChecksum,
                           this->nTime);
    }

    T GetBlockModifierHash() const;
    //T GetBlockModifierHash(int32_t height) const;

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(this->prevHash);
        READWRITE(this->type);
        READWRITE(this->nFlags);
        READWRITE(this->nHeight);
        READWRITE(this->workModifierL);
        READWRITE(this->workModifierH);
        READWRITE(this->workChecksum);
        READWRITE(this->nTime);
        READWRITE(this->unused1);
        READWRITE(this->unused2);
        READWRITE(this->unused3);
        READWRITE(this->unused4);
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
