// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_H
#define BITCOIN_BLOCK_H

#include <block/transaction.h>
#include <block/block_locator.h>
#include <merkle/merkle_tree.h>
#include <prevector/prevector.h>

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
#pragma pack(push, 1)
    // header
    static const int CURRENT_VERSION = 6;
    int32_t nVersion;
    T hashPrevBlock;
    T hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
#pragma pack(pop)
public:
    CBlockHeader() {SetNull();}
    void SetNull() {
        nVersion = CBlockHeader<T>::CURRENT_VERSION;
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nTime = 0;
        nBits = 0;
        nNonce = 0;
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
};
template <typename T>
class CBlockHeader_impl : public CBlockHeader<T> {
public:
    bool IsNull() const {
        return (CBlockHeader<T>::nBits == 0);
    }
    uint256 GetHash() const;
    int64_t GetBlockTime() const {
        return (int64_t)CBlockHeader<T>::nTime;
    }
    void UpdateTime(const CBlockIndex *pindexPrev) {
        CBlockHeader<T>::nTime = std::max(GetBlockTime(), bitsystem::GetAdjustedTime());
    }
};
template <typename T>
class CBlock_impl : public CBlockHeader_impl<T>, public CMerkleTree<T, CTransaction>
{
#ifdef BLOCK_PREVECTOR_ENABLE
    using vMerkle_t = prevector<PREVECTOR_BLOCK_N, T>;
#else
    using vMerkle_t = std::vector<T>;
#endif
//private:
    // CBlock_impl(const CBlock_impl &)=delete;
    // CBlock_impl &operator=(const CBlock_impl &)=delete;
    // CBlock_impl &operator=(const CBlock_impl &&)=delete;
private:
    using Merkle_t = CMerkleTree<T, CTransaction>;
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
    CBlock_impl() {SetNull();}
    void SetNull() {
        CBlockHeader<T>::SetNull();
        vchBlockSig.clear();
        nDoS = 0;
    }
    // entropy bit for stake modifier if chosen by modifier
    unsigned int GetStakeEntropyBit(unsigned int nHeight) const {
        // Take last bit of block hash as entropy bit
        unsigned int nEntropyBit = ((CBlockHeader_impl<T>::GetHash().Get64()) & 1llu);
        if (args_bool::fDebug && map_arg::GetBoolArg("-printstakemodifier"))
            printf("GetStakeEntropyBit: hashBlock=%s nEntropyBit=%u\n", CBlockHeader_impl<T>::GetHash().ToString().c_str(), nEntropyBit);
        return nEntropyBit;
    }
    // ppcoin: two types of block: proof-of-work or proof-of-stake
    bool IsProofOfStake() const {
        return (Merkle_t::vtx.size() > 1 && Merkle_t::vtx[1].IsCoinStake());
    }
    bool IsProofOfWork() const {
        return !IsProofOfStake();
    }
    std::pair<COutPoint, unsigned int> GetProofOfStake() const {
        return IsProofOfStake() ? std::make_pair(Merkle_t::vtx[1].vin[0].prevout, Merkle_t::vtx[1].nTime) : std::make_pair(COutPoint(), (unsigned int)0);
    }
    // ppcoin: get max transaction timestamp
    int64_t GetMaxTransactionTime() const {
        int64_t maxTransactionTime = 0;
        for(const CTransaction &tx: Merkle_t::vtx)
            maxTransactionTime = std::max(maxTransactionTime, (int64_t)tx.nTime);
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
    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion); // CBlockHeader this Version READWRITE
        nVersion = this->nVersion;
        READWRITE(this->hashPrevBlock);
        READWRITE(this->hashMerkleRoot);
        READWRITE(this->nTime);
        READWRITE(this->nBits);
        READWRITE(this->nNonce);
        // ConnectBlock depends on vtx following header to generate CDiskTxPos
        if (!(nType & (SER_GETHASH|SER_BLOCKHEADERONLY))) {
            READWRITE(this->vtx);
            READWRITE(this->vchBlockSig);
        } else if (ser_ctr.isRead()) {
            const_cast<CBlock_impl<T> *>(this)->vtx.clear();
            const_cast<CBlock_impl<T> *>(this)->vchBlockSig.clear();
        }
    )
};
using CBlock = CBlock_impl<uint256>;

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
#ifdef BLOCK_PREVECTOR_ENABLE
    //using vMerkle_t = prevector<PREVECTOR_BLOCK_N, T>;
#else
    //using vMerkle_t = std::vector<T>;
#endif
// private:
    // CBlockIndex_impl(const CBlockIndex_impl &)=delete;
    // CBlockIndex_impl &operator=(const CBlockIndex_impl &)=delete;
    // CBlockIndex_impl &operator=(const CBlockIndex_impl &&)=delete;
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
    uint32_t nStakeModifierChecksum; // checksum of index; in-memeory only
    // proof-of-stake specific fields
    COutPoint prevoutStake;
    uint32_t nStakeTime;
    T hashProofOfStake;
    // ppcoin: block index flags
    uint32_t nFlags;
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
    COutPoint get_prevoutStake() const {return prevoutStake;}
    uint32_t get_nStakeTime() const {return nStakeTime;}
    T get_hashProofOfStake() const {return hashProofOfStake;}
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
    void set_prevoutStake(const COutPoint &_in) {prevoutStake=_in;}
    void set_nStakeTime(uint32_t _in) {nStakeTime=_in;}
    void set_hashProofOfStake(const T &_in) {hashProofOfStake=_in;}
    void set_nFlags(uint32_t _in) {nFlags=_in;}
    enum
    {
        BLOCK_PROOF_OF_STAKE = (1 << 0),        // is proof-of-stake block
        BLOCK_STAKE_ENTROPY  = (1 << 1),        // entropy bit for stake modifier
        BLOCK_STAKE_MODIFIER = (1 << 2),        // regenerated stake modifier
    };
    CBlockIndex_impl() {
        //CBlockHeader<T>::SetNull();
        phashBlock = nullptr;
        pprev = nullptr;
        pnext = nullptr;
        nFile = 0;
        nBlockPos = 0;
        nHeight = 0;
        nChainTrust = 0;
        nMint = 0;
        nMoneySupply = 0;
        nFlags = 0;
        nStakeModifier = 0;
        nStakeModifierChecksum = 0;
        hashProofOfStake = 0;
        prevoutStake.SetNull();
        nStakeTime = 0;
    }
    CBlockIndex_impl(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock &block) {
        //CBlockHeader<T>::SetNull();
        phashBlock = nullptr;
        pprev = nullptr;
        pnext = nullptr;
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
        if (block.IsProofOfStake()) {
            SetProofOfStake();
            prevoutStake = block.get_vtx(1).vin[0].prevout;
            nStakeTime = block.get_vtx(1).nTime;
        } else {
            prevoutStake.SetNull();
            nStakeTime = 0;
        }
        CBlockHeader<T>::nVersion       = block.get_nVersion();
        CBlockHeader<T>::hashMerkleRoot = block.get_hashMerkleRoot();
        CBlockHeader<T>::nTime          = block.get_nTime();
        CBlockHeader<T>::nBits          = block.get_nBits();
        CBlockHeader<T>::nNonce         = block.get_nNonce();
    }
    virtual ~CBlockIndex_impl() {}
    CBlock GetBlockHeader() const {
        CBlock block;
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
    static bool IsSuperMajority(int minVersion, const CBlockIndex *pstart, unsigned int nRequired, unsigned int nToCheck) {
        unsigned int nFound = 0;
        for (unsigned int i=0; i<nToCheck && nFound<nRequired && pstart!=nullptr; ++i) {
            if (pstart->nVersion >= minVersion) ++nFound;
            pstart = pstart->pprev;
        }
        return (nFound>=nRequired);
    }
    bool IsProofOfWork() const {
        return !IsProofOfStake();
    }
    bool IsProofOfStake() const {
        return (nFlags & BLOCK_PROOF_OF_STAKE);
    }
    void SetProofOfStake() {
        nFlags |= BLOCK_PROOF_OF_STAKE;
    }
    unsigned int GetStakeEntropyBit() const {
        return ((nFlags & BLOCK_STAKE_ENTROPY) >> 1);
    }
    bool SetStakeEntropyBit(unsigned int nEntropyBit) {
        if (nEntropyBit > 1) return false;
        nFlags |= (nEntropyBit? BLOCK_STAKE_ENTROPY : 0);
        return true;
    }
    bool GeneratedStakeModifier() const {
        return (nFlags & BLOCK_STAKE_MODIFIER) != 0;
    }
    void SetStakeModifier(uint64_t nModifier, bool fGeneratedStakeModifier) {
        nStakeModifier = nModifier;
        if (fGeneratedStakeModifier) nFlags |= BLOCK_STAKE_MODIFIER;
    }
    std::string ToString() const;
    void print() const {
        printf("%s\n", ToString().c_str());
    }
};
using CBlockIndex = CBlockIndex_impl<uint256>;

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
        CBlock block;
        block.set_nVersion(CBlockIndex_impl<T>::nVersion);
        block.set_hashPrevBlock(hashPrev);
        block.set_hashMerkleRoot(CBlockIndex_impl<T>::hashMerkleRoot);
        block.set_nTime(CBlockIndex_impl<T>::nTime);
        block.set_nBits(CBlockIndex_impl<T>::nBits);
        block.set_nNonce(CBlockIndex_impl<T>::nNonce);
        blockHash = block.GetHash();
        return blockHash;
    }
    std::string ToString() const;
    void print() const {
        printf("%s\n", ToString().c_str());
    }
    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH)) {
            READWRITE(nVersion);    // IMPLEMENT_SERIALIZE has argument(nVersion).
        }
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
        } else if (ser_ctr.isRead()) {
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
    )
};
using CDiskBlockIndex = CDiskBlockIndex_impl<uint256>;

class block_notify : private no_instance
{
    friend class CBlock_impl<uint256>;
private:
    static void SetBestChain(const CBlockLocator &loc);
    static void UpdatedTransaction(const uint256 &hashTx);
public:
    static bool IsInitialBlockDownload();
    static void PrintWallets(const CBlock &block);
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
