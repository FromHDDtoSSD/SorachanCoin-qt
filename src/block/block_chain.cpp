// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Copyright (c) 2018-2021 The Sora neko developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <block/block_chain.h>
#include <block/block.h>
#include <checkpoints.h>

/**
 * CChain_impl implementation
 */
template <typename T>
CBlockIndex_impl<T> *CChain_impl<T>::Genesis() const {
    return vChain.size() > 0 ? vChain[0] : nullptr;
}

template <typename T>
CBlockIndex_impl<T> *CChain_impl<T>::Tip(bool fProofOfStake/*=false*/, bool fProofOfBench/*=false*/, bool fProofOfMasternode/*=false*/) const {
    if (vChain.size() < 1)
        return nullptr;

    CBlockIndex_impl<T> *pindex = vChain[vChain.size() - 1];
    if (fProofOfStake) {
        while (pindex && pindex->get_pprev() && !pindex->IsProofOfStake())
            pindex = pindex->set_pprev();
    }
    if (fProofOfBench) {
        while (pindex && pindex->get_pprev() && !pindex->IsProofOfBench())
            pindex = pindex->set_pprev();
    }
    if (fProofOfMasternode) {
        while (pindex && pindex->get_pprev() && !pindex->IsProofOfMasternode())
            pindex = pindex->set_pprev();
    }
    return pindex;
}

template <typename T>
CBlockIndex_impl<T> *CChain_impl<T>::operator[](int nHeight) const {
    if (nHeight < 0 || nHeight >= (int)vChain.size())
        return nullptr;
    return vChain[nHeight];
}

template <typename T>
bool CChain_impl<T>::Contains(const CBlockIndex_impl<T> *pindex) const {
    return (*this)[pindex->get_nHeight()] == pindex;
}

template <typename T>
CBlockIndex_impl<T> *CChain_impl<T>::Next(const CBlockIndex_impl<T> *pindex) const {
    if (Contains(pindex))
        return (*this)[pindex->get_nHeight() + 1];
    else
        return nullptr;
}

template <typename T>
void CChain_impl<T>::SetTip(CBlockIndex_impl<T> *pindex)
{
    if (pindex == nullptr) {
        vChain.clear();
        return;
    }
    vChain.resize(pindex->get_nHeight() + 1);
    while (pindex && vChain[pindex->get_nHeight()] != pindex) {
        vChain[pindex->get_nHeight()] = pindex;
        pindex = pindex->set_pprev();
    }
}

template <typename T>
CBlockLocator_impl<T> CChain_impl<T>::GetLocator(const CBlockIndex_impl<T> *pindex) const
{
    int nStep = 1;
    std::vector<T> vHave;
    vHave.reserve(32);

    if (! pindex)
        pindex = Tip();
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());
        // Stop when we have added the genesis block.
        if (pindex->get_nHeight() == 0)
            break;
        // Exponentially larger steps back, plus the genesis block.
        int nHeight = std::max(pindex->get_nHeight() - nStep, 0);
        if (Contains(pindex)) {
            // Use O(1) CChain index if possible.
            pindex = (*this)[nHeight];
        } else {
            // Otherwise, use O(log n) skiplist.
            pindex = pindex->GetAncestor(nHeight);
        }
        if (vHave.size() > 10)
            nStep *= 2;
    }

    return CBlockLocator_impl<T>(vHave);
}

template <typename T>
const CBlockIndex_impl<T> *CChain_impl<T>::FindFork(const CBlockIndex_impl<T> *pindex) const
{
    if (pindex->get_nHeight() > Height())
        pindex = pindex->GetAncestor(Height());
    while (pindex && !Contains(pindex))
        pindex = pindex->get_pprev();
    return pindex;
}

/** Update chainActive and related internal data structures. */
/*
template <typename T> // tip update: SetBestChain
void block_active::UpdateTip(CBlockIndex_impl<T> *pindexNew)
{
    block_info::chainActive.SetTip(pindexNew);

    // New best block
    block_info::nTimeBestReceived = bitsystem::GetTime();
    CTxMemPool::mempool.AddTransactionsUpdated(1);

    logging::LogPrintf("UpdateTip: new best=%s  height=%d  log2_work=%.8g  tx=%d  date=%s progress=%f  cache=%u\n",
        block_info::chainActive.Tip()->GetBlockHash().ToString(),
        block_info::chainActive.Height(),
        ::log(block_info::chainActive.Tip()->nChainWork.getdouble()) / ::log(2.0),
        (unsigned long)block_info::chainActive.Tip()->nChainTx,
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", block_info::chainActive.Tip()->GetBlockTime()),
        Checkpoints::GuessVerificationProgress(block_info::chainActive.Tip()), (unsigned int)pcoinsTip->GetCacheSize());

    cvBlockChange.notify_all();

    // Check the version of the last 100 blocks to see if we need to upgrade:
    static bool fWarned = false;
    if (!IsInitialBlockDownload() && !fWarned) {
        int nUpgraded = 0;
        const CBlockIndex_impl<T> *pindex = block_info::chainActive.Tip();
        for (int i = 0; i < 100 && pindex != nullptr; i++) {
            if (pindex->nVersion > CBlock_impl<T>::CURRENT_VERSION)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            LogPrintf("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, (int)CBlock::CURRENT_VERSION);
        if (nUpgraded > 100 / 2) {
            // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            strMiscWarning = _("Warning: This version is obsolete, upgrade required!");
            CAlert::Notify(strMiscWarning, true);
            fWarned = true;
        }
    }
}
*/

template class CChain_impl<uint256>;
