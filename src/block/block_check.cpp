// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <block/block_check.h>
#include <net.h>
#include <txdb.h>
#include <util/thread.h>

CCheckQueue<CScriptCheck> block_check::thread::scriptcheckqueue(128);
unsigned int block_check::nStakeMinAge = block_check::mainnet::nStakeMinAge;
unsigned int block_check::nStakeTargetSpacing = block_check::mainnet::nStakeTargetSpacing;
unsigned int block_check::nPowTargetSpacing = block_check::mainnet::nPowTargetSpacing;
unsigned int block_check::nModifierInterval = block_check::mainnet::nModifierInterval;

template <typename T>
void block_check::manage<T>::InvalidChainFound(CBlockIndex_impl<T> *pindexNew)
{
    if (pindexNew->get_nChainTrust() > block_info::nBestInvalidTrust) {
        block_info::nBestInvalidTrust = pindexNew->get_nChainTrust();
        CTxDB().WriteBestInvalidTrust(CBigNum(block_info::nBestInvalidTrust));
        CClientUIInterface::uiInterface.NotifyBlocksChanged();
    }

    uint256 nBestInvalidBlockTrust = pindexNew->get_nChainTrust() - pindexNew->get_pprev()->get_nChainTrust();
    uint256 nBestBlockTrust = block_info::pindexBest->get_nHeight() != 0 ? (block_info::pindexBest->get_nChainTrust() - block_info::pindexBest->get_pprev()->get_nChainTrust()) : block_info::pindexBest->get_nChainTrust();

    logging::LogPrintf("block_check::manage::InvalidChainFound: invalid block=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
            pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->get_nHeight(),
            CBigNum(pindexNew->get_nChainTrust()).ToString().c_str(), nBestInvalidBlockTrust.Get64(),
            util::DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()).c_str());
    logging::LogPrintf("block_check::manage::InvalidChainFound:  current best=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
            block_info::hashBestChain.ToString().substr(0,20).c_str(), block_info::nBestHeight,
            CBigNum(block_info::pindexBest->get_nChainTrust()).ToString().c_str(),
            nBestBlockTrust.Get64(),
            util::DateTimeStrFormat("%x %H:%M:%S", block_info::pindexBest->GetBlockTime()).c_str());
}

template <typename T>
bool block_check::manage<T>::VerifySignature(const CTransaction &txFrom, const CTransaction &txTo, unsigned int nIn, unsigned int flags, int nHashType)
{
    return CScriptCheck(txFrom, txTo, nIn, flags, nHashType)();    // Call by functor
}

template <typename T>
bool block_check::manage<T>::Reorganize(CTxDB_impl<T> &txdb, CBlockIndex_impl<T> *pindexNew)
{
    logging::LogPrintf("REORGANIZE\n");

    // Find the fork
    CBlockIndex *pfork = block_info::pindexBest;
    CBlockIndex *plonger = pindexNew;
    while (pfork != plonger) {
        while (plonger->get_nHeight() > pfork->get_nHeight()) {
            if ((plonger = plonger->set_pprev()) == nullptr)
                return logging::error("block_check::manage::Reorganize() : plonger->pprev is null");
        }
        if (pfork == plonger)
            break;
        if ((pfork = pfork->set_pprev()) == nullptr)
            return logging::error("block_check::manage::Reorganize() : pfork->pprev is null");
    }

    // List of what to disconnect
    std::vector<CBlockIndex *> vDisconnect;
    for (CBlockIndex *pindex = block_info::pindexBest; pindex != pfork; pindex = pindex->set_pprev())
        vDisconnect.push_back(pindex);

    // List of what to connect
    std::vector<CBlockIndex *> vConnect;
    for (CBlockIndex *pindex = pindexNew; pindex != pfork; pindex = pindex->set_pprev())
        vConnect.push_back(pindex);

    reverse(vConnect.begin(), vConnect.end());
    logging::LogPrintf("REORGANIZE: Disconnect %" PRIszu " blocks; %s..%s\n", vDisconnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), block_info::pindexBest->GetBlockHash().ToString().substr(0,20).c_str());
    logging::LogPrintf("REORGANIZE: Connect %" PRIszu " blocks; %s..%s\n", vConnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->GetBlockHash().ToString().substr(0,20).c_str());

    // Disconnect shorter branch
    std::vector<CTransaction> vResurrect;
    for(CBlockIndex *pindex: vDisconnect) {
        CBlock_impl<T> block;
        if (! block.ReadFromDisk(pindex))
            return logging::error("block_check::manage::Reorganize() : ReadFromDisk for disconnect failed");
        if (! block.DisconnectBlock(txdb, pindex))
            return logging::error("block_check::manage::Reorganize() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());

        // Queue memory transactions to resurrect
        for(const CTransaction &tx: block.get_vtx()) {
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
                vResurrect.push_back(tx);
        }
    }

    // Connect longer branch
    std::vector<CTransaction> vDelete;
    for (unsigned int i = 0; i < vConnect.size(); ++i) {
        CBlockIndex *pindex = vConnect[i];
        CBlock_impl<T> block;
        if (! block.ReadFromDisk(pindex))
            return logging::error("block_check::manage::Reorganize() : ReadFromDisk for connect failed");
        if (! block.ConnectBlock(txdb, pindex)) // Invalid block
            return logging::error("block_check::manage::Reorganize() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());

        // Queue memory transactions to delete
        for(const CTransaction &tx: block.get_vtx())
            vDelete.push_back(tx);
    }
    if (! txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
        return logging::error("block_check::manage::Reorganize() : WriteHashBestChain failed");

    // Make sure it's successfully written to disk before changing memory structure
    if (! txdb.TxnCommit())
        return logging::error("block_check::manage::Reorganize() : TxnCommit failed");

    // Disconnect shorter branch
    for(CBlockIndex *pindex: vDisconnect) {
        if (pindex->get_pprev())
            pindex->set_pprev()->set_pnext(nullptr);
    }

    // Connect longer branch
    for(CBlockIndex *pindex: vConnect) {
        if (pindex->get_pprev())
            pindex->set_pprev()->set_pnext(pindex);
    }

    // Resurrect memory transactions that were in the disconnected branch
    for(CTransaction &tx: vResurrect)
        tx.AcceptToMemoryPool(txdb, false);

    // Delete redundant memory transactions that are in the connected branch
    for(CTransaction &tx: vDelete)
        CTxMemPool::mempool.remove(tx);

    logging::LogPrintf("REORGANIZE: done\n");
    return true;
}

void block_check::thread::ThreadScriptCheck(void *)
{
    net_node::vnThreadsRunning[THREAD_SCRIPTCHECK]++;
    bitthread::RenameThread(strCoinName "-scriptch");
    scriptcheckqueue.Thread();
    net_node::vnThreadsRunning[THREAD_SCRIPTCHECK]--;
}

void block_check::thread::ThreadScriptCheckQuit()
{
    scriptcheckqueue.Quit();
}

template class block_check::manage<uint256>;
