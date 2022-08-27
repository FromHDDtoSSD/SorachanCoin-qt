// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2014-2015 Vertcoin Developers
// Copyright (c) 2018 The Merge developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Copyright (c) 2018-2021 The Sora neko developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_H
#define BITCOIN_BLOCK_H

#include <script/interpreter.h>
#include <block/transaction.h>
#include <block/block_locator.h>
#include <merkle/merkle_tree.h>
#include <const/amount.h>
#include <prevector/prevector.h>

#ifndef SWITCH_LYRE2RE_BLOCK
# define SWITCH_LYRE2RE_BLOCK (84950000) // hardfork: to Lyra2REv2
# define SWITCH_LYRE2RE_BLOCK_TESTNET (1495000)
#endif

/** Capture information about block/transaction validation */
class CValidationState
{
private:
    enum mode_state {
        MODE_VALID,   //! everything ok
        MODE_INVALID, //! network rule violation (DoS value may be set)
        MODE_ERROR,   //! run-time error
    } mode;
    int nDoS;
    std::string strRejectReason;
    unsigned char chRejectCode;
    bool corruptionPossible;

public:
    CValidationState() : mode(MODE_VALID), nDoS(0), chRejectCode(0), corruptionPossible(false) {}
    bool DoS(int level, bool ret = false, unsigned char chRejectCodeIn = 0, std::string strRejectReasonIn = "", bool corruptionIn = false)
    {
        chRejectCode = chRejectCodeIn;
        strRejectReason = strRejectReasonIn;
        corruptionPossible = corruptionIn;
        if (mode == MODE_ERROR)
            return ret;
        nDoS += level;
        mode = MODE_INVALID;
        return ret;
    }
    bool Invalid(bool ret = false,
        unsigned char _chRejectCode = 0,
        std::string _strRejectReason = "")
    {
        return DoS(0, ret, _chRejectCode, _strRejectReason);
    }
    bool Error(std::string strRejectReasonIn = "")
    {
        if (mode == MODE_VALID)
            strRejectReason = strRejectReasonIn;
        mode = MODE_ERROR;
        return false;
    }
    bool Abort(const std::string &msg);
    bool IsValid() const
    {
        return mode == MODE_VALID;
    }
    bool IsInvalid() const
    {
        return mode == MODE_INVALID;
    }
    bool IsError() const
    {
        return mode == MODE_ERROR;
    }
    bool IsInvalid(int& nDoSOut) const
    {
        if (IsInvalid()) {
            nDoSOut = nDoS;
            return true;
        }
        return false;
    }
    bool CorruptionPossible() const
    {
        return corruptionPossible;
    }
    unsigned char GetRejectCode() const { return chRejectCode; }
    std::string GetRejectReason() const { return strRejectReason; }
};

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator of the block.
 *
 * Blocks are appended to blk0001.dat files on disk.
 * Their location on disk is indexed by CBlockIndex objects in memory.
 */
class CBlockHeader {
protected:
    static constexpr int CURRENT_VERSION = 6;
    static constexpr int CURRENT_VERSION_Lyra2REV2 = 7;
#pragma pack(push, 1)
    // header
    mutable int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
#pragma pack(pop)
private:
    mutable int32_t LastHeight; // get nHeight from CBlockHeader (LastBlock+1==nHeight)
public:
    CBlockHeader() : LastHeight(-1) {SetNull();}
    void SetNull() {
        nVersion = CBlockHeader::CURRENT_VERSION;
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }
    int32_t get_nVersion() const {return nVersion;}
    const uint256 &get_hashPrevBlock() const {return hashPrevBlock;}
    const uint256 &get_hashMerkleRoot() const {return hashMerkleRoot;}
    uint32_t get_nTime() const {return nTime;}
    uint32_t get_nBits() const {return nBits;}
    uint32_t get_nNonce() const {return nNonce;}
    void set_nVersion(int32_t _in) {nVersion=_in;}
    void set_hashPrevBlock(const uint256 &_in) {hashPrevBlock=_in;}
    void set_hashMerkleRoot(const uint256 &_in) {hashMerkleRoot=_in;}
    void set_nTime(uint32_t _in) {nTime=_in;}
    uint32_t &set_nTime() {return nTime;}
    void set_nBits(uint32_t _in) {nBits=_in;}
    void set_nNonce(uint32_t _in) {nNonce=_in;}
    uint32_t &set_nNonce() {return nNonce;}

    void set_LastHeight(int32_t _in) const;
    int32_t get_LastHeight() const {return LastHeight;}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(this->hashPrevBlock);
        READWRITE(this->hashMerkleRoot);
        READWRITE(this->nTime);
        READWRITE(this->nBits);
        READWRITE(this->nNonce);
    }
};

class CBlockHeader_impl : public CBlockHeader {
private:
    uint256 GetHash(int type) const;
public:
    bool IsNull() const {
        return (CBlockHeader::nBits == 0);
    }
    int set_Last_LyraHeight_hash(int32_t _in, int32_t nonce_zero_proof) const; // return: BLOCK_HASH_TYPE
    //uint256 GetPoHash() const;
    uint256 GetPoHash(int32_t height, int type) const;
    int64_t GetBlockTime() const {
        return (int64_t)CBlockHeader::nTime;
    }
    void UpdateTime(const CBlockIndex *pindexPrev);
    std::string ToString() const {
        return tfm::format("CBlockHeader_impl: nVersion=%d hashPrevBlock=%s hashMerkleRoot=%s nTime=%d nBits=%d nNonce=%d",
                           CBlockHeader::nVersion,
                           CBlockHeader::hashPrevBlock.ToString().c_str(),
                           CBlockHeader::hashMerkleRoot.ToString().c_str(),
                           CBlockHeader::nTime,
                           CBlockHeader::nBits,
                           CBlockHeader::nNonce);
    }
};

//
// blk000 ... dat files.
// CBlockHeader + MerkleTree + Transactions, block data.
// About R/W: ReadFromDisk or WriteToDisk. (pos: CBlockIndex)
//
class CBlock final : public CBlockHeader_impl, public CMerkleTree<CTransaction>
{
#ifdef BLOCK_PREVECTOR_ENABLE
    using vMerkle_t = prevector<PREVECTOR_BLOCK_N, uint256>;
#else
    using vMerkle_t = std::vector<uint256>;
#endif
    // CBlock(const CBlock &)=delete;
    // CBlock(CBlock &&)=delete;
    // CBlock &operator=(const CBlock &)=delete;
    // CBlock &operator=(CBlock &&)=delete;
private:
    using Merkle_t = CMerkleTree<CTransaction>;
    // ppcoin: block signature - signed by one of the coin base txout[N]'s owner
    Script_util::valtype vchBlockSig;
    // Denial-of-service detection:
    mutable int nDoS;
    bool SetBestChainInner(CTxDB &txdb, CBlockIndex *pindexNew);
public:
    const std::vector<CTransaction> &get_vtx() const {return Merkle_t::vtx;}
    const CTransaction &get_vtx(int index) const {return Merkle_t::vtx[index];}
    const Script_util::valtype &get_vchBlockSig() const {return vchBlockSig;}
    std::vector<CTransaction> &set_vtx() {return Merkle_t::vtx;}
    CTransaction &set_vtx(int index) {return Merkle_t::vtx[index];}
    Script_util::valtype &set_vchBlockSig() {return vchBlockSig;}
    bool DoS(int nDoSIn, bool fIn) const {
        nDoS += nDoSIn;
        return fIn;
    }
    int get_nDoS() const {return nDoS;}
    CBlock() {SetNull();}
    void SetNull() {
        CBlockHeader::SetNull();
        vchBlockSig.clear();
        nDoS = 0;
    }
    uint256 GetPoHash() const;

    // entropy bit for stake modifier if chosen by modifier
    unsigned int GetStakeEntropyBit(unsigned int nHeight) const {
        // Take last bit of block hash as entropy bit
        unsigned int nEntropyBit = ((GetPoHash().Get64()) & 1llu);
        if (args_bool::fDebug && map_arg::GetBoolArg("-printstakemodifier"))
            logging::LogPrintf("GetStakeEntropyBit: hashBlock=%s nEntropyBit=%u\n", GetPoHash().ToString().c_str(), nEntropyBit);
        return nEntropyBit;
    }
    // ppcoin: two types of block: proof-of-work or proof-of-stake
    // sora neko: four types of block: proof-of-work, proof-of-stake, proof-of-space or proof-of-masternode
    bool IsProofOfStake() const {
        return (Merkle_t::vtx.size() > 1 && Merkle_t::vtx[1].IsCoinStake());
    }
    bool IsProofOfBench() const {
        return (Merkle_t::vtx.size() > 1 && Merkle_t::vtx[1].IsCoinBench());
    }
    bool IsProofOfMasternode() const {
        return (Merkle_t::vtx.size() > 1 && Merkle_t::vtx[1].IsCoinMasternode());
    }
    bool IsProofOfWork() const {
        return !IsProofOfStake() && !IsProofOfBench() && !IsProofOfMasternode();
    }
    std::pair<COutPoint, unsigned int> GetProofOfStake() const {
        return IsProofOfStake() ? std::make_pair(Merkle_t::vtx[1].get_vin(0).get_prevout(), Merkle_t::vtx[1].get_nTime()) : std::make_pair(COutPoint(), (unsigned int)0);
    }
    std::pair<COutPoint, unsigned int> GetProofOfBench() const {
        return IsProofOfBench() ? std::make_pair(Merkle_t::vtx[2].get_vin(0).get_prevout(), Merkle_t::vtx[2].get_nTime()) : std::make_pair(COutPoint(), (unsigned int)0);
    }
    std::pair<COutPoint, unsigned int> GetProofOfMasternode() const {
        return IsProofOfMasternode() ? std::make_pair(Merkle_t::vtx[3].get_vin(0).get_prevout(), Merkle_t::vtx[3].get_nTime()) : std::make_pair(COutPoint(), (unsigned int)0);
    }
    // ppcoin: get max transaction timestamp
    int64_t GetMaxTransactionTime() const {
        int64_t maxTransactionTime = 0;
        for(const CTransaction &tx: Merkle_t::vtx)
            maxTransactionTime = std::max(maxTransactionTime, (int64_t)tx.get_nTime());
        return maxTransactionTime;
    }
    bool WriteToDisk(unsigned int &nFileRet, unsigned int &nBlockPosRet);
    bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions=true);
    void print() const;
    bool DisconnectBlock(CTxDB &txdb, CBlockIndex *pindex);
    bool ConnectBlock(CTxDB &txdb, CBlockIndex *pindex, bool fJustCheck=false);
    bool ReadFromDisk(const CBlockIndex *pindex, bool fReadTransactions=true);
    bool SetBestChain(CTxDB &txdb, CBlockIndex *pindexNew);
    bool AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos);
    bool CheckBlock(bool fCheckPOW=true, bool fCheckMerkleRoot=true, bool fCheckSig=true) const;
    bool AcceptBlock();
    bool GetCoinAge(uint64_t &nCoinAge) const; // ppcoin: calculate total coin age spent in block
    bool CheckBlockSignature() const;

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        int nType = 0;
        READWRITE(this->nVersion); // CBlockHeader this Version READWRITE
        //int nVersion = this->nVersion;
        READWRITE(this->hashPrevBlock);
        READWRITE(this->hashMerkleRoot);
        READWRITE(this->nTime);
        READWRITE(this->nBits);
        READWRITE(this->nNonce);
        // ConnectBlock depends on vtx following header to generate CDiskTxPos
        if (!(nType & (SER_GETHASH|SER_BLOCKHEADERONLY))) {
            READWRITE(this->vtx);
            READWRITE(this->vchBlockSig);
        } else if (ser_action.ForRead()) {
            const_cast<CBlock *>(this)->vtx.clear();
            const_cast<CBlock *>(this)->vchBlockSig.clear();
        }

        //ReadWriteLastHeight(s, ser_action);
    }
};

struct CBlockTemplate {
    CBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOps;
};

/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block.  pprev and pnext link a path through the
 * main/longest chain.  A blockindex may have multiple pprev pointing back
 * to it, but pnext will only point forward to the longest branch, or will
 * be null if the block is not part of the longest chain.
 */
class CBlockIndex : public CBlockHeader
{
    // CBlockIndex(const CBlockIndex &)=delete;
    // CBlockIndex(CBlockIndex &&)=delete;
    // CBlockIndex &operator=(const CBlockIndex &)=delete;
    // CBlockIndex &operator=(CBlockIndex &&)=delete;
protected:
    const uint256 *phashBlock; // mapBlockIndex hash pointer
    CBlockIndex *pprev;
    CBlockIndex *pnext;
    uint32_t nFile;
    uint32_t nBlockPos;
    uint256 nChainTrust; // ppcoin: trust score of block chain
    int32_t nHeight;
    int64_t nMint;
    int64_t nMoneySupply;
    uint64_t nStakeModifier; // hash modifier for proof-of-stake
    uint64_t nBenchModifier; // hash modifier for proof-of-bench
    uint64_t nMasternodeModifier; // hash modifier for masternode
    uint32_t nStakeModifierChecksum; // checksum of index; in-memory only
    uint32_t nBenchModifierChecksum; // checksum of index; in-memory only
    uint32_t nMasternodeModifierChecksum; // checksum of index; in-memory only
    // proof-of-stake specific fields
    COutPoint prevoutStake;
    uint32_t nStakeTime;
    uint256 hashProofOfStake;
    // proof-of-bench specific fields
    COutPoint prevoutBench;
    uint32_t nBenchTime;
    uint256 hashProofOfBench;
    // proof-of-masternode specific fields
    COutPoint prevoutMasternode;
    uint32_t nMasternodeTime;
    uint256 hashProofOfMasternode;
    // ppcoin: block index flags
    uint32_t nFlags;
    // pointer to the index of some further predecessor of this block
    CBlockIndex *pskip;
    // (memory only) Total amount of work (expected number of hashes) in the chain up to and including this block
    uint256 nChainWork;
    // (memory only) Sequential id assigned to distinguish order in which blocks are received.
    uint32_t nSequenceId;
    //! (memory only) Number of transactions in the chain up to and including this block.
    //! This value will be non-zero only if and only if transactions for this block and all its parents are available.
    uint64_t nChainTx;
public:
    const uint256 *get_phashBlock() const {return phashBlock;}
    const CBlockIndex *get_pprev() const {return pprev;}
    const CBlockIndex *get_pnext() const {return pnext;}
    uint32_t get_nFile() const {return nFile;}
    uint32_t get_nBlockPos() const {return nBlockPos;}
    uint256 get_nChainTrust() const {return nChainTrust;}
    int32_t get_nHeight() const {return nHeight;} ///// []
    int32_t get_nMint() const {return nMint;}
    int64_t get_nMoneySupply() const {return nMoneySupply;}
    uint64_t get_nStakeModifier() const {return nStakeModifier;}
    uint32_t get_nStakeModifierChecksum() const {return nStakeModifierChecksum;}
    uint64_t get_nMasternodeModifier() const {return nMasternodeModifier;}
    uint32_t get_nMasterModifierChecksum() const {return nMasternodeModifierChecksum;}
    COutPoint get_prevoutStake() const {return prevoutStake;}
    uint32_t get_nStakeTime() const {return nStakeTime;}
    uint256 get_hashProofOfStake() const {return hashProofOfStake;}
    COutPoint get_prevoutMasternode() const {return prevoutMasternode;}
    uint32_t get_nMasternodeTime() const {return nMasternodeTime;}
    uint256 get_hashProofOfMasternode() const {return hashProofOfMasternode;}
    uint32_t get_nFlags() const {return nFlags;}
    const uint256 &get_nChainWork() const {return nChainWork;}
    uint32_t get_nSequenceId() const {return nSequenceId;}
    void set_phashBlock(const uint256 *_in) {phashBlock=_in;}
    void set_pprev(CBlockIndex *_in) {pprev=_in;}
    void set_pnext(CBlockIndex *_in) {pnext=_in;}
    CBlockIndex *set_pprev() {return pprev;}
    CBlockIndex *set_pnext() {return pnext;}
    void set_nFile(uint32_t _in) {nFile=_in;}
    void set_nBlockPos(uint32_t _in) {nBlockPos=_in;}
    void set_nChainTrust(const uint256 &_in) {nChainTrust=_in;}
    void set_nHeight(int32_t _in) {nHeight=_in;}
    void set_nMint(int32_t _in) {nMint=_in;}
    void set_nMoneySupply(int64_t _in) {nMoneySupply=_in;}
    void set_nStakeModifier(uint64_t _in) {nStakeModifier=_in;}
    void set_nStakeModifierChecksum(uint32_t _in) {nStakeModifierChecksum=_in;}
    void set_nMasternodeModifier(uint64_t _in) {nMasternodeModifier=_in;}
    void set_nMasternodeModifierChecksum(uint32_t _in) {nMasternodeModifierChecksum=_in;}
    void set_prevoutStake(const COutPoint &_in) {prevoutStake=_in;}
    void set_nStakeTime(uint32_t _in) {nStakeTime=_in;}
    void set_hashProofOfStake(const uint256 &_in) {hashProofOfStake=_in;}
    void set_prevoutMasternode(const COutPoint &_in) {prevoutMasternode=_in;}
    void set_nMasternodeTime(uint32_t _in) {nMasternodeTime=_in;}
    void set_hashProofOfMasternode(const uint256 &_in) {hashProofOfMasternode=_in;}
    void set_nFlags(uint32_t _in) {nFlags=_in;}
    void set_nChainWork(const uint256 &_in) {nChainWork=_in;}
    void set_nSequenceId(uint32_t _in) {nSequenceId=_in;}
    enum
    {
        BLOCK_PROOF_OF_STAKE = (1 << 0),        // v1 is proof-of-stake block
        BLOCK_STAKE_ENTROPY  = (1 << 1),        // v1 entropy bit for stake modifier
        BLOCK_STAKE_MODIFIER = (1 << 2),        // v1 regenerated stake modifier
        BLOCK_PROOF_OF_BENCH = (1 << 8),        // v4 is prrof-of-bench block
        BLOCK_PROOF_OF_MASTERNODE = (1 << 16),  // v3 is masternode block
        BLOCK_MASTERNODE_ENTROPY  = (1 << 17),  // v3 entropy bit for masternode modifier
        BLOCK_MASTERNODE_RATIO    = (1 << 18),  // v3 prrof-of-masternode block stake modifier ratio
        BLOCK_MASTERNODE_MODIFIER = (1 << 19)   // v3 regenerated stake modifier
    };
    CBlockIndex() {
        //CBlockHeader::SetNull();
        phashBlock = nullptr;
        pprev = nullptr;
        pnext = nullptr;
        pskip = nullptr;
        nFile = 0;
        nBlockPos = 0;
        nHeight = 0;
        nChainTrust = 0;
        nMint = 0;
        nMoneySupply = 0;
        nFlags = 0;
        nChainWork = 0;
        nSequenceId = 0;
        nChainTx = 0;
        nStakeModifier = 0;
        nStakeModifierChecksum = 0;
        nBenchModifier = 0;
        nBenchModifierChecksum = 0;
        nMasternodeModifier = 0;
        nMasternodeModifierChecksum = 0;
        hashProofOfStake = 0;
        prevoutStake.SetNull();
        nStakeTime = 0;
        hashProofOfBench = 0;
        prevoutBench.SetNull();
        nBenchTime = 0;
        hashProofOfMasternode = 0;
        prevoutMasternode.SetNull();
        nMasternodeTime = 0;
    }
    CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock &block) {
        //CBlockHeader::SetNull();
        phashBlock = nullptr;
        pprev = nullptr;
        pnext = nullptr;
        pskip = nullptr;
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nHeight = 0;
        nChainTrust = 0;
        nMint = 0;
        nMoneySupply = 0;
        nFlags = 0;
        nChainWork = 0;
        nSequenceId = 0;
        nChainTx = 0;
        nStakeModifier = 0;
        nStakeModifierChecksum = 0;
        hashProofOfStake = 0;
        nBenchModifier = 0;
        nBenchModifierChecksum = 0;
        hashProofOfBench = 0;
        nMasternodeModifier = 0;
        nMasternodeModifierChecksum = 0;
        hashProofOfMasternode = 0;
        if (block.IsProofOfStake()) {
            SetProofOfStake();
            prevoutStake = block.get_vtx(1).get_vin(0).get_prevout();
            nStakeTime = block.get_vtx(1).get_nTime();
        } else if (block.IsProofOfBench()) {
            SetProofOfBench();
            prevoutBench = block.get_vtx(2).get_vin(0).get_prevout();
            nBenchTime = block.get_vtx(2).get_nTime();
        } else if (block.IsProofOfMasternode()) {
            SetProofOfMasternode();
            prevoutMasternode = block.get_vtx(3).get_vin(0).get_prevout();
            nMasternodeTime = block.get_vtx(3).get_nTime();
        } else { // proof-of-work (use coinbase)
            prevoutStake.SetNull();
            prevoutBench.SetNull();
            prevoutMasternode.SetNull();
            nStakeTime = 0;
            nBenchTime = 0;
            nMasternodeTime = 0;
        }
        CBlockHeader::nVersion       = block.get_nVersion();
        CBlockHeader::hashMerkleRoot = block.get_hashMerkleRoot();
        CBlockHeader::nTime          = block.get_nTime();
        CBlockHeader::nBits          = block.get_nBits();
        CBlockHeader::nNonce         = block.get_nNonce();
    }
    virtual ~CBlockIndex() {}
    CBlock GetBlockHeader() const {
        CBlock block;
        block.set_nVersion(CBlockHeader::nVersion);
        if (pprev) block.set_hashPrevBlock(pprev->GetBlockHash());
        block.set_hashMerkleRoot(CBlockHeader::hashMerkleRoot);
        block.set_nTime(CBlockHeader::nTime);
        block.set_nBits(CBlockHeader::nBits);
        block.set_nNonce(CBlockHeader::nNonce);
        return block;
    }
    uint256 GetBlockHash() const {
        return *phashBlock;
    }
    int64_t GetBlockTime() const {
        return (int64_t)CBlockHeader::nTime;
    }
    uint256 GetBlockTrust() const;
    bool IsInMainChain() const {
        return (pnext || this == block_info::pindexBest);
    }
    bool CheckIndex() const {
        return true;
    }
    const unsigned int nMedianTimeSpan = 11;
    int64_t GetMedianTimePast() const {
        int64_t pmedian[nMedianTimeSpan];
        int64_t *pbegin = &pmedian[nMedianTimeSpan];
        int64_t *pend = &pmedian[nMedianTimeSpan];
        const CBlockIndex *pindex = this;
        for (int i=0; i<(const int)nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->GetBlockTime();
        std::sort(pbegin, pend);
        return pbegin[(pend-pbegin)/2];
    }
    int64_t GetMedianTime() const {
        const CBlockIndex *pindex = this;
        for (int i=0; i<(const int)nMedianTimeSpan / 2; ++i) {
            if (!pindex->pnext) return GetBlockTime();
            pindex = pindex->pnext;
        }
        return pindex->GetMedianTimePast();
    }
    // Returns true if there are nRequired or more blocks of minVersion or above
    // in the last nToCheck blocks, starting at pstart and going backwards.
    static bool IsSuperMajority(int minVersion, const CBlockIndex *pstart, unsigned int nRequired, unsigned int nToCheck) {
        unsigned int nFound = 0;
        for (unsigned int i=0; i<nToCheck && nFound<nRequired && pstart!=nullptr; ++i) {
            if (pstart->nVersion >= minVersion)
                ++nFound;
            pstart = pstart->pprev;
        }
        return (nFound>=nRequired);
    }
    bool IsProofOfWork() const {
        return !IsProofOfStake() && !IsProofOfBench() && !IsProofOfMasternode();
    }
    bool IsProofOfStake() const {
        return (nFlags & BLOCK_PROOF_OF_STAKE);
    }
    bool IsProofOfBench() const {
        return (nFlags & BLOCK_PROOF_OF_BENCH);
    }
    bool IsProofOfMasternode() const {
        return (nFlags & BLOCK_PROOF_OF_MASTERNODE);
    }
    void SetProofOfStake() {
        nFlags |= BLOCK_PROOF_OF_STAKE;
    }
    void SetProofOfBench() {
        nFlags |= BLOCK_PROOF_OF_BENCH;
    }
    void SetProofOfMasternode() {
        nFlags |= BLOCK_PROOF_OF_MASTERNODE;
    }
    unsigned int GetStakeEntropyBit() const {
        return ((nFlags & BLOCK_STAKE_ENTROPY) >> 1);
    }
    bool SetStakeEntropyBit(unsigned int nEntropyBit) {
        if (nEntropyBit > 1) return false;
        nFlags |= (nEntropyBit? BLOCK_STAKE_ENTROPY : 0);
        return true;
    }
    unsigned int GetMasternodeEntropyBit() const {
        return ((nFlags & BLOCK_MASTERNODE_ENTROPY) >> 1);
    }
    bool SetMasternodeEntropyBit(unsigned int nEntropyBit) {
        if (nEntropyBit > 1) return false;
        nFlags |= (nEntropyBit? BLOCK_MASTERNODE_ENTROPY : 0);
        return true;
    }
    bool GeneratedStakeModifier() const {
        return (nFlags & BLOCK_STAKE_MODIFIER) != 0;
    }
    void SetStakeModifier(uint64_t nModifier, bool fGeneratedStakeModifier) {
        nStakeModifier = nModifier;
        if (fGeneratedStakeModifier) nFlags |= BLOCK_STAKE_MODIFIER;
    }
    bool GeneratedMasternodeModifier() const {
        return (nFlags & BLOCK_MASTERNODE_MODIFIER) != 0;
    }
    void SetMasternodeModifier(uint64_t nModifier, bool fGeneratedMasternodeModifier) {
        nMasternodeModifier = nModifier;
        if (fGeneratedMasternodeModifier) nFlags |= BLOCK_MASTERNODE_MODIFIER;
    }

    CBlockIndex *GetAncestor(int height);
    const CBlockIndex *GetAncestor(int height) const;
    void BuildSkip();
    std::string ToString() const;
    void print() const {
        logging::LogPrintf("%s\n", ToString().c_str());
    }
};

struct CBlockIndexWorkComparator {
    bool operator()(CBlockIndex *pa, CBlockIndex *pb) const
    {
        // First sort by most total work, ...
        if (pa->get_nChainWork() > pb->get_nChainWork()) return false;
        if (pa->get_nChainWork() < pb->get_nChainWork()) return true;

        // ... then by earliest time received, ...
        if (pa->get_nSequenceId() < pb->get_nSequenceId()) return false;
        if (pa->get_nSequenceId() > pb->get_nSequenceId()) return true;

        // Use pointer address as tie breaker (should only happen with blocks
        // loaded from disk, as those all have id 0).
        if (pa < pb) return false;
        if (pa > pb) return true;

        // Identical blocks.
        return false;
    }
};

//
// Used to marshal pointers into hashes for db storage. (unused CDiskBlockHeader)
// from DB to CDiskBlockIndex, from CDiskBlockIndex to CBlockIndex.
//
class CDiskBlockHeader final : public CBlockHeader_impl
{
    CDiskBlockHeader(const CDiskBlockHeader &)=delete;
    CDiskBlockHeader(CDiskBlockHeader &&)=delete;
    CDiskBlockHeader &operator=(const CDiskBlockHeader &)=delete;
    CDiskBlockHeader &operator=(CDiskBlockHeader &&)=delete;
private:
    mutable uint256 blockHash;
    uint256 hashPrev;
    uint256 hashNext;
public:
    CDiskBlockHeader() {
        blockHash = 0;
        hashPrev = 0;
        hashNext = 0;
    }

    const uint256 &get_hashPrev() const {return hashPrev;}
    const uint256 &get_hashNext() const {return hashNext;}
    void set_hashPrev(const uint256 &_in) {hashPrev=_in;}
    void set_hashNext(const uint256 &_in) {hashNext=_in;}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        int nVersion = 0;
        READWRITE(nVersion); // new core takes over old core in the nVersion (unused).
        READWRITE(this->hashNext);

        // block header
        READWRITE(this->nVersion);  // CBlockHeader this nVersion
        READWRITE(this->hashPrev);
        READWRITE(this->hashMerkleRoot);
        READWRITE(this->nTime);
        READWRITE(this->nBits);
        READWRITE(this->nNonce);
        READWRITE(this->blockHash);
    }
};

class CDiskBlockIndex final : public CBlockIndex
{
    CDiskBlockIndex(const CDiskBlockIndex &)=delete;
    CDiskBlockIndex &operator=(const CDiskBlockIndex &)=delete;
    CDiskBlockIndex &operator=(CDiskBlockIndex &&)=delete;
private:
    mutable uint256 blockHash;
    uint256 hashPrev;
    uint256 hashNext;
public:
    const uint256 &get_hashPrev() const {return hashPrev;}
    const uint256 &get_hashNext() const {return hashNext;}
    void set_hashPrev(const uint256 &_in) {hashPrev=_in;}
    void set_hashNext(const uint256 &_in) {hashNext=_in;}
    CDiskBlockIndex() {
        hashPrev = 0;
        hashNext = 0;
        blockHash = 0;
    }
    explicit CDiskBlockIndex(CBlockIndex *pindex) : CBlockIndex(*pindex) {
        hashPrev = (CBlockIndex::pprev ? CBlockIndex::pprev->GetBlockHash() : 0);
        hashNext = (CBlockIndex::pnext ? CBlockIndex::pnext->GetBlockHash() : 0);
    }
    uint256 GetBlockHash() const;
    std::string ToString() const;
    void print() const {
        logging::LogPrintf("%s\n", ToString().c_str());
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        int nVersion = 0;
        READWRITE(nVersion); // new core takes over old core in the nVersion (unused).

        READWRITE(this->hashNext);
        READWRITE(this->nFile);
        READWRITE(this->nBlockPos);
        READWRITE(this->nHeight);
        READWRITE(this->nMint);
        READWRITE(this->nMoneySupply);
        READWRITE(this->nFlags);
        READWRITE(this->nStakeModifier);
        if (CBlockIndex::IsProofOfStake()) {
            READWRITE(this->prevoutStake);
            READWRITE(this->nStakeTime);
            READWRITE(this->hashProofOfStake);
        } else if (ser_action.ForRead()) {
            const_cast<CDiskBlockIndex *>(this)->prevoutStake.SetNull();
            const_cast<CDiskBlockIndex *>(this)->nStakeTime = 0;
            const_cast<CDiskBlockIndex *>(this)->hashProofOfStake = 0;
        }

        // block header
        READWRITE(this->nVersion);  // CBlockHeader this nVersion
        READWRITE(this->hashPrev);
        READWRITE(this->hashMerkleRoot);
        READWRITE(this->nTime);
        READWRITE(this->nBits);
        READWRITE(this->nNonce);
        READWRITE(this->blockHash);
    }
};

class block_notify : private no_instance
{
    friend class CBlock;
private:
    static void SetBestChain(const CBlockLocator &loc);
    static void UpdatedTransaction(const uint256 &hashTx);
public:
    static bool IsInitialBlockDownload();
    static void PrintWallets(const CBlock &block);
};

class CBlock_print : private no_instance
{
#ifdef BLOCK_PREVECTOR_ENABLE
    using vStack_t = prevector<PREVECTOR_BLOCK_N, std::pair<int, CBlockIndex *> >;
    using vBlockIndex_t = prevector<PREVECTOR_BLOCK_N, CBlockIndex *>;
#else
    using vStack_t = std::vector<std::pair<int, CBlockIndex *> >;
    using vBlockIndex_t = std::vector<CBlockIndex *>;
#endif
public:
    static void PrintBlockTree();
};

#endif // BITCOIN_BLOCK_H
