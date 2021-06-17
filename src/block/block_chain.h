// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Copyright (c) 2018-2021 The Sora neko developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLOCK_CHAIN_H
#define BLOCK_CHAIN_H

class CBlockIndex;
template <typename T>
class CBlockLocator_impl;
class CBlock;

class CValidationState;

#include <vector>
#include <uint256.h>

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
    CBlockIndex *Genesis() const;

    /** Returns the index entry for the tip of this chain, or NULL if none. */
    CBlockIndex *Tip(bool fProofOfStake=false, bool fProofOfBench=false, bool fProofOfMasternode=false) const;

    /** Returns the index entry at a particular height in this chain, or NULL if no such height exists. */
    CBlockIndex *operator[](int nHeight) const;

    /** Compare two chains efficiently. */
    friend bool operator==(const CChain_impl &a, const CChain_impl &b) {
        return a.vChain.size() == b.vChain.size() &&
               a.vChain[a.vChain.size() - 1] == b.vChain[b.vChain.size() - 1];
    }

    /** Efficiently check whether a block is present in this chain. */
    bool Contains(const CBlockIndex *pindex) const;

    /** Find the successor of a block in this chain, or NULL if the given index is not found or is the tip. */
    CBlockIndex *Next(const CBlockIndex *pindex) const;

    /** Return the maximal height in the chain. Is equal to chain.Tip() ? chain.Tip()->nHeight : -1. */
    int Height() const {
        return vChain.size() - 1;
    }

    /** Set/initialize a chain with a given tip. */
    void SetTip(CBlockIndex *pindex);

    /** Return a CBlockLocator that refers to a block in this chain (by default the tip). */
    CBlockLocator_impl<T> GetLocator(const CBlockIndex *pindex = nullptr) const;

    /** Find the last common block between this chain and a block index entry. */
    const CBlockIndex *FindFork(const CBlockIndex *pindex) const;

private:
    std::vector<CBlockIndex *> vChain;
};
using CChain = CChain_impl<uint256>;

namespace block_active {
    // under development
    //template <typename T>
    //extern void UpdateTip(CBlockIndex *pindexNew);
    //extern bool DisconnectTip(CValidationState &state);
    //template <typename T>
    //extern bool ConnectTip(CValidationState &state, CBlockIndex *pindexNew, CBlock_impl<T> *pblock, bool fAlreadyChecked);
    //extern bool DisconnectBlocksAndReprocess(int blocks);
}

#endif
