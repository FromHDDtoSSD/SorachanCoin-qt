// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2014-2015 Vertcoin Developers
// Copyright (c) 2018 The Merge developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_H
#define BITCOIN_BLOCK_H

#include <script/interpreter.h>
#include <block/transaction.h>
#include <block/block_locator.h>
#include <merkle/merkle_tree.h>
#include <const/amount.h>

#ifndef SWITCH_LYRE2RE_BLOCK
# define SWITCH_LYRE2RE_BLOCK (550000) // hardfork: to Lyra2REv2
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
template <typename T>
class CBlockHeader {
protected:
    static constexpr int CURRENT_VERSION = 6;
    //static constexpr int CURRENT_VERSION = 7;
#pragma pack(push, 1)
    // header
    int32_t nVersion;
    T hashPrevBlock;
    T hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
#pragma pack(pop)
public:
    int32_t LastHeight;
public:
    CBlockHeader() {SetNull();}
    void SetNull() {
        nVersion = CBlockHeader<T>::CURRENT_VERSION;
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        LastHeight = 0;
    }
    int32_t get_nVersion() const {return nVersion;}
    const T &get_hashPrevBlock() const {return hashPrevBlock;}
    const T &get_hashMerkleRoot() const {return hashMerkleRoot;}
    uint32_t get_nTime() const {return nTime;}
    uint32_t get_nBits() const {return nBits;}
    uint32_t get_nNonce() const {return nNonce;}
    void set_nVersion(int32_t _in) {nVersion=_in;}
    void set_hashPrevBlock(const T &_in) {hashPrevBlock=_in;}
    void set_hashMerkleRoot(const T &_in) {hashMerkleRoot=_in;}
    void set_nTime(uint32_t _in) {nTime=_in;}
    uint32_t &set_nTime() {return nTime;}
    void set_nBits(uint32_t _in) {nBits=_in;}
    void set_nNonce(uint32_t _in) {nNonce=_in;}
    uint32_t &set_nNonce() {return nNonce;}

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
template <typename T>
class CBlockHeader_impl : public CBlockHeader<T> {
public:
    bool IsNull() const {
        return (CBlockHeader<T>::nBits == 0);
    }
    uint256 GetPoHash() const;
    uint256 GetPoHash(int height) const;
    int64_t GetBlockTime() const {
        return (int64_t)CBlockHeader<T>::nTime;
    }
    void UpdateTime(const CBlockIndex_impl<T> *pindexPrev) {
        CBlockHeader<T>::nTime = std::max(GetBlockTime(), bitsystem::GetAdjustedTime());
        CBlockHeader<T>::LastHeight = pindexPrev->get_nHeight();
    }
};
template <typename T>
class CDiskBlockHeader_impl : public CBlockHeader_impl<T> {
    CDiskBlockHeader_impl(const CDiskBlockHeader_impl &)=delete;
    CDiskBlockHeader_impl(CDiskBlockHeader_impl &&)=delete;
    CDiskBlockHeader_impl &operator=(const CDiskBlockHeader_impl &)=delete;
    CDiskBlockHeader_impl &operator=(CDiskBlockHeader_impl &&)=delete;
private:
    mutable T blockHash;
    T hashPrev;
    T hashNext;
public:
    CDiskBlockHeader_impl() {
        blockHash = 0;
        hashPrev = 0;
        hashNext = 0;
    }

    const T &get_hashPrev() const {return hashPrev;}
    const T &get_hashNext() const {return hashNext;}
    void set_hashPrev(const T &_in) {hashPrev=_in;}
    void set_hashNext(const T &_in) {hashNext=_in;}

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
using CDiskBlockHeader = CDiskBlockHeader_impl<uint256>;

template <typename T>
class CBlock_impl : public CBlockHeader_impl<T>, public CMerkleTree<T, CTransaction_impl<T> >
{
#ifdef BLOCK_PREVECTOR_ENABLE
    using vMerkle_t = prevector<PREVECTOR_BLOCK_N, T>;
#else
    using vMerkle_t = std::vector<T>;
#endif
    // CBlock_impl(const CBlock_impl &)=delete;
    // CBlock_impl(CBlock_impl &&)=delete;
    // CBlock_impl &operator=(const CBlock_impl &)=delete;
    // CBlock_impl &operator=(CBlock_impl &&)=delete;
private:
    using Merkle_t = CMerkleTree<T, CTransaction_impl<T> >;
    // ppcoin: block signature - signed by one of the coin base txout[N]'s owner
    Script_util::valtype vchBlockSig;
    // Denial-of-service detection:
    mutable int nDoS;
    bool SetBestChainInner(CTxDB_impl<T> &txdb, CBlockIndex_impl<T> *pindexNew);
public:
    const std::vector<CTransaction_impl<T> > &get_vtx() const {return Merkle_t::vtx;}
    const CTransaction_impl<T> &get_vtx(int index) const {return Merkle_t::vtx[index];}
    const Script_util::valtype &get_vchBlockSig() const {return vchBlockSig;}
    std::vector<CTransaction_impl<T> > &set_vtx() {return Merkle_t::vtx;}
    CTransaction_impl<T> &set_vtx(int index) {return Merkle_t::vtx[index];}
    Script_util::valtype &set_vchBlockSig() {return vchBlockSig;}
    bool DoS(int nDoSIn, bool fIn) const {
        nDoS += nDoSIn;
        return fIn;
    }
    int get_nDoS() const {return nDoS;}
    CBlock_impl() {SetNull();}
    void SetNull() {
        CBlockHeader<T>::SetNull();
        vchBlockSig.clear();
        nDoS = 0;
    }
    // entropy bit for stake modifier if chosen by modifier
    unsigned int GetStakeEntropyBit(unsigned int nHeight) const {
        // Take last bit of block hash as entropy bit
        unsigned int nEntropyBit = ((CBlockHeader_impl<T>::GetPoHash().Get64()) & 1llu);
        if (args_bool::fDebug && map_arg::GetBoolArg("-printstakemodifier"))
            logging::LogPrintf("GetStakeEntropyBit: hashBlock=%s nEntropyBit=%u\n", CBlockHeader_impl<T>::GetPoHash().ToString().c_str(), nEntropyBit);
        return nEntropyBit;
    }
    // ppcoin: two types of block: proof-of-work or proof-of-stake
    // sora neko: four types of block: proof-of-work, proof-of-stake, proof-of-space or proof-of-masternode
    bool IsProofOfStake() const {
        return (Merkle_t::vtx.size() > 1 && Merkle_t::vtx[1].IsCoinStake());
    }
    bool IsProofOfSpace() const {
        return (Merkle_t::vtx.size() > 1 && Merkle_t::vtx[1].IsCoinSpace());
    }
    bool IsProofOfMasternode() const {
        return (Merkle_t::vtx.size() > 1 && Merkle_t::vtx[1].IsCoinMasternode());
    }
    bool IsProofOfWork() const {
        return !IsProofOfStake() && !IsProofOfSpace() && !IsProofOfMasternode();
    }
    std::pair<COutPoint_impl<T>, unsigned int> GetProofOfStake() const {
        return IsProofOfStake() ? std::make_pair(Merkle_t::vtx[1].get_vin(0).get_prevout(), Merkle_t::vtx[1].get_nTime()) : std::make_pair(COutPoint_impl<T>(), (unsigned int)0);
    }
    std::pair<COutPoint_impl<T>, unsigned int> GetProofOfSpace() const {
        return IsProofOfSpace() ? std::make_pair(Merkle_t::vtx[2].get_vin(0).get_prevout(), Merkle_t::vtx[2].get_nTime()) : std::make_pair(COutPoint_impl<T>(), (unsigned int)0);
    }
    std::pair<COutPoint_impl<T>, unsigned int> GetProofOfMasternode() const {
        return IsProofOfMasternode() ? std::make_pair(Merkle_t::vtx[3].get_vin(0).get_prevout(), Merkle_t::vtx[3].get_nTime()) : std::make_pair(COutPoint_impl<T>(), (unsigned int)0);
    }
    // ppcoin: get max transaction timestamp
    int64_t GetMaxTransactionTime() const {
        int64_t maxTransactionTime = 0;
        for(const CTransaction_impl<T> &tx: Merkle_t::vtx)
            maxTransactionTime = std::max(maxTransactionTime, (int64_t)tx.get_nTime());
        return maxTransactionTime;
    }
    bool WriteToDisk(unsigned int &nFileRet, unsigned int &nBlockPosRet);
    bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions=true);
    void print() const;
    bool DisconnectBlock(CTxDB_impl<T> &txdb, CBlockIndex_impl<T> *pindex);
    bool ConnectBlock(CTxDB_impl<T> &txdb, CBlockIndex_impl<T> *pindex, bool fJustCheck=false);
    bool ReadFromDisk(const CBlockIndex_impl<T> *pindex, bool fReadTransactions=true);
    bool SetBestChain(CTxDB_impl<T> &txdb, CBlockIndex_impl<T> *pindexNew);
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
            const_cast<CBlock_impl<T> *>(this)->vtx.clear();
            const_cast<CBlock_impl<T> *>(this)->vchBlockSig.clear();
        }
    }
};
using CBlock = CBlock_impl<uint256>;

template <typename T>
struct CBlockTemplate_impl {
    CBlock_impl<T> block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOps;
};
using CBlockTemplate = CBlockTemplate_impl<uint256>;

/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block.  pprev and pnext link a path through the
 * main/longest chain.  A blockindex may have multiple pprev pointing back
 * to it, but pnext will only point forward to the longest branch, or will
 * be null if the block is not part of the longest chain.
 */
template <typename T>
class CBlockIndex_impl : public CBlockHeader<T>
{
    // CBlockIndex_impl(const CBlockIndex_impl &)=delete;
    // CBlockIndex_impl(CBlockIndex_impl &&)=delete;
    // CBlockIndex_impl &operator=(const CBlockIndex_impl &)=delete;
    // CBlockIndex_impl &operator=(CBlockIndex_impl &&)=delete;
protected:
    const T *phashBlock; // CBlock_impl<T>::AddToBlockIndex
    CBlockIndex_impl<T> *pprev;
    CBlockIndex_impl<T> *pnext;
    uint32_t nFile;
    uint32_t nBlockPos;
    T nChainTrust; // ppcoin: trust score of block chain
    int32_t nHeight;
    int64_t nMint;
    int64_t nMoneySupply;
    uint64_t nStakeModifier; // hash modifier for proof-of-stake
    uint64_t nSpaceModifier; // hash modifier for proof-of-space
    uint64_t nMasternodeModifier; // hash modifier for masternode
    uint32_t nStakeModifierChecksum; // checksum of index; in-memory only
    uint32_t nSpaceModifierChecksum; // checksum of index; in-memory only
    uint32_t nMasternodeModifierChecksum; // checksum of index; in-memory only
    // proof-of-stake specific fields
    COutPoint_impl<T> prevoutStake;
    uint32_t nStakeTime;
    T hashProofOfStake;
    // proof-of-space specific fields
    COutPoint_impl<T> prevoutSpace;
    uint32_t nSpaceTime;
    T hashProofOfSpace;
    // proof-of-masternode specific fields
    COutPoint_impl<T> prevoutMasternode;
    uint32_t nMasternodeTime;
    T hashProofOfMasternode;
    // ppcoin: block index flags
    uint32_t nFlags;
    // pointer to the index of some further predecessor of this block
    CBlockIndex_impl<T> *pskip;
public:
    const T *get_phashBlock() const {return phashBlock;}
    const CBlockIndex_impl<T> *get_pprev() const {return pprev;}
    const CBlockIndex_impl<T> *get_pnext() const {return pnext;}
    uint32_t get_nFile() const {return nFile;}
    uint32_t get_nBlockPos() const {return nBlockPos;}
    T get_nChainTrust() const {return nChainTrust;}
    int32_t get_nHeight() const {return nHeight;} ///// []
    int32_t get_nMint() const {return nMint;}
    int64_t get_nMoneySupply() const {return nMoneySupply;}
    uint64_t get_nStakeModifier() const {return nStakeModifier;}
    uint32_t get_nStakeModifierChecksum() const {return nStakeModifierChecksum;}
    uint64_t get_nMasternodeModifier() const {return nMasternodeModifier;}
    uint32_t get_nMasterModifierChecksum() const {return nMasternodeModifierChecksum;}
    COutPoint_impl<T> get_prevoutStake() const {return prevoutStake;}
    uint32_t get_nStakeTime() const {return nStakeTime;}
    T get_hashProofOfStake() const {return hashProofOfStake;}
    COutPoint_impl<T> get_prevoutMasternode() const {return prevoutMasternode;}
    uint32_t get_nMasternodeTime() const {return nMasternodeTime;}
    T get_hashProofOfMasternode() const {return hashProofOfMasternode;}
    uint32_t get_nFlags() const {return nFlags;}
    void set_phashBlock(const T *_in) {phashBlock=_in;}
    void set_pprev(CBlockIndex_impl<T> *_in) {pprev=_in;}
    void set_pnext(CBlockIndex_impl<T> *_in) {pnext=_in;}
    CBlockIndex_impl<T> *set_pprev() {return pprev;}
    CBlockIndex_impl<T> *set_pnext() {return pnext;}
    void set_nFile(uint32_t _in) {nFile=_in;}
    void set_nBlockPos(uint32_t _in) {nBlockPos=_in;}
    void set_nChainTrust(const T &_in) {nChainTrust=_in;}
    void set_nHeight(int32_t _in) {nHeight=_in;}
    void set_nMint(int32_t _in) {nMint=_in;}
    void set_nMoneySupply(int64_t _in) {nMoneySupply=_in;}
    void set_nStakeModifier(uint64_t _in) {nStakeModifier=_in;}
    void set_nStakeModifierChecksum(uint32_t _in) {nStakeModifierChecksum=_in;}
    void set_nMasternodeModifier(uint64_t _in) {nMasternodeModifier=_in;}
    void set_nMasternodeModifierChecksum(uint32_t _in) {nMasternodeModifierChecksum=_in;}
    void set_prevoutStake(const COutPoint_impl<T> &_in) {prevoutStake=_in;}
    void set_nStakeTime(uint32_t _in) {nStakeTime=_in;}
    void set_hashProofOfStake(const T &_in) {hashProofOfStake=_in;}
    void set_prevoutMasternode(const COutPoint_impl<T> &_in) {prevoutMasternode=_in;}
    void set_nMasternodeTime(uint32_t _in) {nMasternodeTime=_in;}
    void set_hashProofOfMasternode(const T &_in) {hashProofOfMasternode=_in;}
    void set_nFlags(uint32_t _in) {nFlags=_in;}
    enum
    {
        BLOCK_PROOF_OF_STAKE = (1 << 0),        // v1 is proof-of-stake block
        BLOCK_STAKE_ENTROPY  = (1 << 1),        // v1 entropy bit for stake modifier
        BLOCK_STAKE_MODIFIER = (1 << 2),        // v1 regenerated stake modifier
        BLOCK_PROOF_OF_SPACE = (1 << 8),        // v4 is prrof-of-space block
        BLOCK_PROOF_OF_MASTERNODE = (1 << 16),  // v3 is masternode block
        BLOCK_MASTERNODE_ENTROPY  = (1 << 17),  // v3 entropy bit for masternode modifier
        BLOCK_MASTERNODE_RATIO    = (1 << 18),  // v3 prrof-of-masternode block stake modifier ratio
        BLOCK_MASTERNODE_MODIFIER = (1 << 19)   // v3 regenerated stake modifier
    };
    CBlockIndex_impl() {
        //CBlockHeader<T>::SetNull();
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
        nStakeModifier = 0;
        nStakeModifierChecksum = 0;
        nSpaceModifier = 0;
        nSpaceModifierChecksum = 0;
        nMasternodeModifier = 0;
        nMasternodeModifierChecksum = 0;
        hashProofOfStake = 0;
        prevoutStake.SetNull();
        nStakeTime = 0;
        hashProofOfSpace = 0;
        prevoutSpace.SetNull();
        nSpaceTime = 0;
        hashProofOfMasternode = 0;
        prevoutMasternode.SetNull();
        nMasternodeTime = 0;
    }
    CBlockIndex_impl(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock_impl<T> &block) {
        //CBlockHeader<T>::SetNull();
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
        nStakeModifier = 0;
        nStakeModifierChecksum = 0;
        hashProofOfStake = 0;
        nSpaceModifier = 0;
        nSpaceModifierChecksum = 0;
        hashProofOfSpace = 0;
        nMasternodeModifier = 0;
        nMasternodeModifierChecksum = 0;
        hashProofOfMasternode = 0;
        if (block.IsProofOfStake()) {
            SetProofOfStake();
            prevoutStake = block.get_vtx(1).get_vin(0).get_prevout();
            nStakeTime = block.get_vtx(1).get_nTime();
        } else if (block.IsProofOfSpace()) {
            SetProofOfSpace();
            prevoutSpace = block.get_vtx(2).get_vin(0).get_prevout();
            nSpaceTime = block.get_vtx(2).get_nTime();
        } else if (block.IsProofOfMasternode()) {
            SetProofOfMasternode();
            prevoutMasternode = block.get_vtx(3).get_vin(0).get_prevout();
            nMasternodeTime = block.get_vtx(3).get_nTime();
        } else { // proof-of-work (use coinbase)
            prevoutStake.SetNull();
            prevoutSpace.SetNull();
            prevoutMasternode.SetNull();
            nStakeTime = 0;
            nSpaceTime = 0;
            nMasternodeTime = 0;
        }
        CBlockHeader<T>::nVersion       = block.get_nVersion();
        CBlockHeader<T>::hashMerkleRoot = block.get_hashMerkleRoot();
        CBlockHeader<T>::nTime          = block.get_nTime();
        CBlockHeader<T>::nBits          = block.get_nBits();
        CBlockHeader<T>::nNonce         = block.get_nNonce();
    }
    virtual ~CBlockIndex_impl() {}
    CBlock_impl<T> GetBlockHeader() const {
        CBlock_impl<T> block;
        block.set_nVersion(CBlockHeader<T>::nVersion);
        if (pprev) block.set_hashPrevBlock(pprev->GetBlockHash());
        block.set_hashMerkleRoot(CBlockHeader<T>::hashMerkleRoot);
        block.set_nTime(CBlockHeader<T>::nTime);
        block.set_nBits(CBlockHeader<T>::nBits);
        block.set_nNonce(CBlockHeader<T>::nNonce);
        return block;
    }
    T GetBlockHash() const {
        return *phashBlock;
    }
    int64_t GetBlockTime() const {
        return (int64_t)CBlockHeader<T>::nTime;
    }
    T GetBlockTrust() const;
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
        const CBlockIndex_impl<T> *pindex = this;
        for (int i=0; i<(const int)nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->GetBlockTime();
        std::sort(pbegin, pend);
        return pbegin[(pend-pbegin)/2];
    }
    int64_t GetMedianTime() const {
        const CBlockIndex_impl<T> *pindex = this;
        for (int i=0; i<(const int)nMedianTimeSpan / 2; ++i) {
            if (!pindex->pnext) return GetBlockTime();
            pindex = pindex->pnext;
        }
        return pindex->GetMedianTimePast();
    }
    // Returns true if there are nRequired or more blocks of minVersion or above
    // in the last nToCheck blocks, starting at pstart and going backwards.
    static bool IsSuperMajority(int minVersion, const CBlockIndex_impl<T> *pstart, unsigned int nRequired, unsigned int nToCheck) {
        unsigned int nFound = 0;
        for (unsigned int i=0; i<nToCheck && nFound<nRequired && pstart!=nullptr; ++i) {
            if (pstart->nVersion >= minVersion) ++nFound;
            pstart = pstart->pprev;
        }
        return (nFound>=nRequired);
    }
    bool IsProofOfWork() const {
        return !IsProofOfStake() && !IsProofOfSpace() && !IsProofOfMasternode();
    }
    bool IsProofOfStake() const {
        return (nFlags & BLOCK_PROOF_OF_STAKE);
    }
    bool IsProofOfSpace() const {
        return (nFlags & BLOCK_PROOF_OF_SPACE);
    }
    bool IsProofOfMasternode() const {
        return (nFlags & BLOCK_PROOF_OF_MASTERNODE);
    }
    void SetProofOfStake() {
        nFlags |= BLOCK_PROOF_OF_STAKE;
    }
    void SetProofOfSpace() {
        nFlags |= BLOCK_PROOF_OF_SPACE;
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

    CBlockIndex_impl<T> *GetAncestor(int height);
    const CBlockIndex_impl<T> *GetAncestor(int height) const;
    void BuildSkip();
    std::string ToString() const;
    void print() const {
        logging::LogPrintf("%s\n", ToString().c_str());
    }
};
using CBlockIndex = CBlockIndex_impl<uint256>;

/** An in-memory indexed chain of blocks. */
template <typename T>
class CChain_impl
{
    CChain_impl(const CChain_impl &)=delete;
    CChain_impl &operator=(const CChain_impl &)=delete;
    CChain_impl(CChain_impl &&)=delete;
    CChain_impl &operator=(CChain_impl &&)=delete;
public:
    CChain_impl() {}

    /** Returns the index entry for the genesis block of this chain, or NULL if none. */
    CBlockIndex_impl<T> *Genesis() const {
        return vChain.size() > 0 ? vChain[0] : nullptr;
    }

    /** Returns the index entry for the tip of this chain, or NULL if none. */
    CBlockIndex_impl<T> *Tip(bool fProofOfStake=false, bool fProofOfSpace=false, bool fProofOfMasternode=false) const {
        if (vChain.size() < 1)
            return nullptr;

        CBlockIndex_impl<T> *pindex = vChain[vChain.size() - 1];
        if (fProofOfStake) {
            while (pindex && pindex->get_pprev() && !pindex->IsProofOfStake())
                pindex = pindex->set_pprev();
        }
        if (fProofOfSpace) {
            while (pindex && pindex->get_pprev() && !pindex->IsProofOfSpace())
                pindex = pindex->set_pprev();
        }
        if (fProofOfMasternode) {
            while (pindex && pindex->get_pprev() && !pindex->IsProofOfMasternode())
                pindex = pindex->set_pprev();
        }
        return pindex;
    }

    /** Returns the index entry at a particular height in this chain, or NULL if no such height exists. */
    CBlockIndex_impl<T> *operator[](int nHeight) const {
        if (nHeight < 0 || nHeight >= (int)vChain.size())
            return nullptr;
        return vChain[nHeight];
    }

    /** Compare two chains efficiently. */
    friend bool operator==(const CChain_impl &a, const CChain_impl &b) {
        return a.vChain.size() == b.vChain.size() &&
               a.vChain[a.vChain.size() - 1] == b.vChain[b.vChain.size() - 1];
    }

    /** Efficiently check whether a block is present in this chain. */
    bool Contains(const CBlockIndex_impl<T> *pindex) const {
        return (*this)[pindex->get_nHeight()] == pindex;
    }

    /** Find the successor of a block in this chain, or NULL if the given index is not found or is the tip. */
    CBlockIndex_impl<T> *Next(const CBlockIndex_impl<T> *pindex) const {
        if (Contains(pindex))
            return (*this)[pindex->get_nHeight() + 1];
        else
            return nullptr;
    }

    /** Return the maximal height in the chain. Is equal to chain.Tip() ? chain.Tip()->nHeight : -1. */
    int Height() const {
        return vChain.size() - 1;
    }

    /** Set/initialize a chain with a given tip. */
    void SetTip(CBlockIndex_impl<T> *pindex);

    /** Return a CBlockLocator that refers to a block in this chain (by default the tip). */
    CBlockLocator_impl<T> GetLocator(const CBlockIndex_impl<T> *pindex = nullptr) const;

    /** Find the last common block between this chain and a block index entry. */
    const CBlockIndex_impl<T> *FindFork(const CBlockIndex_impl<T> *pindex) const;

private:
    std::vector<CBlockIndex_impl<T> *> vChain;
};
using CChain = CChain_impl<uint256>;

//
// Used to marshal pointers into hashes for db storage.
//
template <typename T>
class CDiskBlockIndex_impl final : public CBlockIndex_impl<T>
{
private:
    CDiskBlockIndex_impl(const CDiskBlockIndex_impl &)=delete;
    CDiskBlockIndex_impl &operator=(const CDiskBlockIndex_impl &)=delete;
    CDiskBlockIndex_impl &operator=(const CDiskBlockIndex_impl &&)=delete;
    mutable T blockHash;
    T hashPrev;
    T hashNext;
public:
    const T &get_hashPrev() const {return hashPrev;}
    const T &get_hashNext() const {return hashNext;}
    void set_hashPrev(const T &_in) {hashPrev=_in;}
    void set_hashNext(const T &_in) {hashNext=_in;}
    CDiskBlockIndex_impl() {
        hashPrev = 0;
        hashNext = 0;
        blockHash = 0;
    }
    explicit CDiskBlockIndex_impl(CBlockIndex_impl<T> *pindex) : CBlockIndex_impl<T>(*pindex) {
        hashPrev = (CBlockIndex_impl<T>::pprev ? CBlockIndex_impl<T>::pprev->GetBlockHash() : 0);
        hashNext = (CBlockIndex_impl<T>::pnext ? CBlockIndex_impl<T>::pnext->GetBlockHash() : 0);
    }
    T GetBlockHash() const {
        if (args_bool::fUseFastIndex && (CBlockIndex_impl<T>::nTime < bitsystem::GetAdjustedTime() - util::nOneDay) && this->blockHash != 0)
            return blockHash;
        CBlock_impl<T> block;
        block.set_nVersion(CBlockIndex_impl<T>::nVersion);
        block.set_hashPrevBlock(hashPrev);
        block.set_hashMerkleRoot(CBlockIndex_impl<T>::hashMerkleRoot);
        block.set_nTime(CBlockIndex_impl<T>::nTime);
        block.set_nBits(CBlockIndex_impl<T>::nBits);
        block.set_nNonce(CBlockIndex_impl<T>::nNonce);
        blockHash = block.GetPoHash();
        return blockHash;
    }
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
        if (CBlockIndex_impl<T>::IsProofOfStake()) {
            READWRITE(this->prevoutStake);
            READWRITE(this->nStakeTime);
            READWRITE(this->hashProofOfStake);
        } else if (ser_action.ForRead()) {
            const_cast<CDiskBlockIndex_impl *>(this)->prevoutStake.SetNull();
            const_cast<CDiskBlockIndex_impl *>(this)->nStakeTime = 0;
            const_cast<CDiskBlockIndex_impl *>(this)->hashProofOfStake = 0;
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
using CDiskBlockIndex = CDiskBlockIndex_impl<uint256>;

template <typename T>
class block_notify : private no_instance
{
    friend class CBlock_impl<T>;
private:
    static void SetBestChain(const CBlockLocator &loc);
    static void UpdatedTransaction(const T &hashTx);
public:
    static bool IsInitialBlockDownload();
    static void PrintWallets(const CBlock_impl<T> &block);
};

template <typename T>
class CBlock_print_impl : private no_instance
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
using CBlock_print = CBlock_print_impl<uint256>;

#endif // BITCOIN_BLOCK_H
