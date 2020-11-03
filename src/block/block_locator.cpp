// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <block/block_locator.h>
#include <block/block.h>

template <typename T>
void CBlockLocator_impl<T>::Set(const CBlockIndex *pindex) {
    vHave.clear();
    int nStep = 1;
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());

        // Exponentially larger steps back
        for (int i = 0; pindex && i < nStep; ++i)
            pindex = pindex->get_pprev();
        if (vHave.size() > 10)
            nStep *= 2;
    }
    vHave.push_back((!args_bool::fTestNet ? block_param::hashGenesisBlock : block_param::hashGenesisBlockTestNet));
}

template <typename T>
int CBlockLocator_impl<T>::GetDistanceBack() {
    // Retrace how far back it was in the sender's branch
    int nDistance = 0;
    int nStep = 1;
    for(const uint256 &hash: this->vHave) {
        std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hash);
        if (mi != block_info::mapBlockIndex.end()) {
            CBlockIndex *pindex = (*mi).second;
            if (pindex->IsInMainChain()) return nDistance;
        }

        nDistance += nStep;
        if (nDistance > 10)
            nStep *= 2;
    }
    return nDistance;
}

template <typename T>
CBlockIndex *CBlockLocator_impl<T>::GetBlockIndex() {
    // Find the first block the caller has in the main chain
    for(const uint256 &hash: this->vHave) {
        std::map<uint256, CBlockIndex*>::iterator mi = block_info::mapBlockIndex.find(hash);
        if (mi != block_info::mapBlockIndex.end()) {
            CBlockIndex *pindex = (*mi).second;
            if (pindex->IsInMainChain()) return pindex;
        }
    }
    return block_info::pindexGenesisBlock;
}

template <typename T>
uint256 CBlockLocator_impl<T>::GetBlockHash() {
    // Find the first block the caller has in the main chain
    for(const uint256 &hash: this->vHave) {
        std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hash);
        if (mi != block_info::mapBlockIndex.end()) {
            CBlockIndex *pindex = (*mi).second;
            if (pindex->IsInMainChain()) return hash;
        }
    }
    return (!args_bool::fTestNet ? block_param::hashGenesisBlock : block_param::hashGenesisBlockTestNet);
}

template <typename T>
int CBlockLocator_impl<T>::GetHeight() {
    CBlockIndex *pindex = GetBlockIndex();
    if (! pindex) return 0;
    return pindex->get_nHeight();
}

template class CBlockLocator_impl<uint256>;
