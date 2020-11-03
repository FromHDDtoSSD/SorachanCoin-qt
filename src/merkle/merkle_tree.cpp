// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <merkle/merkle_tree.h>
#include <uint256.h>
#include <block/transaction.h>

template <typename T, typename SRC>
T CMerkleTree<T, SRC>::BuildMerkleTree() const {
    vMerkleTree.clear();
    for(const SRC &tx: vtx) vMerkleTree.push_back(tx.GetHash());
    int j=0;
    for (int nSize=(int)vtx.size(); nSize>1; nSize=(nSize+1)/2) {
        for (int i=0; i<nSize; i+=2) {
            int i2 = std::min(i+1, nSize-1);
            vMerkleTree.push_back(hash_basis::Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
                                                   BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
        }
        j+=nSize;
    }
    return (vMerkleTree.empty()? 0: vMerkleTree.back());
}

template <typename T, typename SRC>
#ifdef BLOCK_PREVECTOR_ENABLE
prevector<PREVECTOR_BLOCK_N, T> CMerkleTree<T, SRC>::GetMerkleBranch(int nIndex) const {
#else
std::vector<T> CMerkleTree<T, SRC>::GetMerkleBranch(int nIndex) const {
#endif
    if (vMerkleTree.empty()) BuildMerkleTree();
    vMerkle_t vMerkleBranch;
    int j = 0;
    for (int nSize=(int)vtx.size(); nSize>1; nSize=(nSize+1)/2) {
        int i = std::min(nIndex ^ 1, nSize - 1);
        vMerkleBranch.push_back(vMerkleTree[j+i]);
        nIndex >>= 1;
        j+=nSize;
    }
    return vMerkleBranch;
}

template <typename T, typename SRC>
T CMerkleTree<T, SRC>::CheckMerkleBranch(T hash, const vMerkle_t &vMerkleBranch, int nIndex) {
    if (nIndex == -1) return 0;
    for(const T &otherside: vMerkleBranch) {
        if (nIndex & 1)
            hash = hash_basis::Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
        else
            hash = hash_basis::Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
        nIndex >>= 1;
    }
    return hash;
}

template class CMerkleTree<uint256, CTransaction_impl<uint256> >;
