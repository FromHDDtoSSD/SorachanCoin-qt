// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <merkle/merkle_tx.h>
#include <util.h>
#include <txdb.h>
#include <net.h>

int CMerkleTx::SetMerkleBranch(const CBlock *pblock/*=nullptr*/)
{
    if (args_bool::fClient) {
        if (hashBlock == 0) return 0;
    } else {
        CBlock blockTmp;
        if (pblock == nullptr) {
            // Load the block this tx is in
            CTxIndex txindex;
            if (! CTxDB("r").ReadTxIndex(GetHash(), txindex))
                return 0;
            if (! blockTmp.ReadFromDisk(txindex.get_pos().get_nFile(), txindex.get_pos().get_nBlockPos()))
                return 0;
            pblock = &blockTmp;
        }

        // Update the tx's hashBlock
        hashBlock = pblock->GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < (int)pblock->get_vtx().size(); ++nIndex) {
            if (pblock->get_vtx(nIndex) == *(CTransaction *)this) break;
        }
        if (nIndex == (int)pblock->get_vtx().size()) {
            vMerkleBranch.clear();
            nIndex = -1;
            logging::LogPrintf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
    }

    // Is the tx in a block that's in the main chain
    std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hashBlock);
    if (mi == block_info::mapBlockIndex.end())
        return 0;

    const CBlockIndex *pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return block_info::pindexBest->get_nHeight() - pindex->get_nHeight() + 1;
}

int CMerkleTx::GetDepthInMainChain(CBlockIndex *&pindexRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;

    // Find the block it claims to be in
    std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hashBlock);
    if (mi == block_info::mapBlockIndex.end())
        return 0;

    CBlockIndex *pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Make sure the merkle branch connects to this block
    if (! fMerkleVerified) {
        if (CMerkleTree<uint256, CTransaction>::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->get_hashMerkleRoot())
            return 0;
        fMerkleVerified = true;
    }

    pindexRet = pindex;
    return block_info::pindexBest->get_nHeight() - pindex->get_nHeight() + 1;
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!(IsCoinBase() || IsCoinStake()))
        return 0;

    return std::max(0, (block_transaction::nCoinbaseMaturity + 0) - GetDepthInMainChain());
}

bool CMerkleTx::AcceptToMemoryPool(CTxDB &txdb, bool fCheckInputs/*=true*/)
{
    if (args_bool::fClient) {
        if (!IsInMainChain() && !ClientConnectInputs())
            return false;
        return CTransaction::AcceptToMemoryPool(txdb, false);
    } else
        return CTransaction::AcceptToMemoryPool(txdb, fCheckInputs);
}

bool CMerkleTx::AcceptToMemoryPool()
{
    CTxDB txdb("r");
    return AcceptToMemoryPool(txdb);
}
