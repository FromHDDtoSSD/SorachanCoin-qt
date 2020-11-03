// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MERKLE_TX_H
#define BITCOIN_MERKLE_TX_H

#include <block/block.h>
#include <prevector/prevector.h>
#include <block/transaction.h>

// transaction with a merkle branch linking it to the block chain.
class CMerkleTx : public CTransaction
{
#ifdef BLOCK_PREVECTOR_ENABLE
    using vMerkle_t = prevector<PREVECTOR_BLOCK_N, uint256>;
#else
    using vMerkle_t = std::vector<uint256>;
#endif
//private:
    // CMerkleTx(const CMerkleTx &)=delete;
    // CMerkleTx &operator=(const CMerkleTx &)=delete;
    // CMerkleTx &operator=(const CMerkleTx &&)=delete;
public:
    uint256 hashBlock;
    vMerkle_t vMerkleBranch;
    int32_t nIndex;
    // memory only
    mutable bool fMerkleVerified;
    CMerkleTx() {
        Init();
    }
    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn) {
        Init();
    }
    void Init() {
        hashBlock = 0;
        nIndex = -1;
        fMerkleVerified = false;
    }
    IMPLEMENT_SERIALIZE
    (
        nSerSize += imp_ser::manage::SerReadWrite(s, *(CTransaction *)this, ser_action);
        nVersion = this->nVersion;
        READWRITE(this->hashBlock);
        READWRITE(this->vMerkleBranch);
        READWRITE(this->nIndex);
    )
    int SetMerkleBranch(const CBlock *pblock=nullptr);
    int GetDepthInMainChain(CBlockIndex *&pindexRet) const;
    int GetDepthInMainChain() const {
        CBlockIndex *pindexRet;
        return GetDepthInMainChain(pindexRet);
    }
    bool IsInMainChain() const {
        return GetDepthInMainChain() > 0;
    }
    int GetBlocksToMaturity() const;
    bool AcceptToMemoryPool(CTxDB &txdb, bool fCheckInputs=true);
    bool AcceptToMemoryPool();
};

#endif // BITCOIN_MERKLE_TX_H
