// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <block/block.h>
#include <wallet.h>
#include <checkpoints.h>
#include <kernel.h>
#include <init.h>
#include <txdb.h>
#include <scrypt.h>
#include <block/block_process.h>
#include <miner/diff.h>
#include <block/block_info.h>
#include <prime/autocheckpoint.h>
#include <util/system.h>
#include <block/blockdata_db.h>
#include <rpc/bitcoinrpc.h> // cs_accept
#include <Lyra2RE/Lyra2RE.h>

bool CValidationState::Abort(const std::string &msg) {
    boot::AbortNode(msg);
    return Error(msg);
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
static int InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
static int GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

template<typename T>
CBlockIndex_impl<T> *CBlockIndex_impl<T>::GetAncestor(int height) {
    if (height > nHeight || height < 0)
        return nullptr;

    CBlockIndex_impl<T> *pindexWalk = this;
    int heightWalk = nHeight;
    while (heightWalk > height) {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (heightSkip == height ||
            (heightSkip > height && !(heightSkipPrev < heightSkip - 2 && heightSkipPrev >= height))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

template <typename T>
const CBlockIndex_impl<T> *CBlockIndex_impl<T>::GetAncestor(int height) const {
    return const_cast<CBlockIndex_impl<T> *>(this)->GetAncestor(height);
}

template <typename T>
void CBlockIndex_impl<T>::BuildSkip() {
    // under development
    //if (pprev) {
    //    int height = GetSkipHeight(nHeight);
    //    debugcs::instance() << "CBlockIndex BuildSkip nHeight: " << nHeight << " Ancestor height: " << height;
    //    pskip = pprev->GetAncestor(height);
    //    debugcs::instance() << " pskip NULL: " << (pskip? 1: 0) << debugcs::endl();
    //}
}



/*
** collect Block Print
*/
template <typename T>
std::string CBlockIndex_impl<T>::ToString() const {
    return tfm::format("CBlockIndex(nprev=%p, pnext=%p, nFile=%u, nBlockPos=%-6d nHeight=%d, nMint=%s, nMoneySupply=%s, \
                      nFlags=(%s)(%d)(%s), \
                      nStakeModifier=%016" PRIx64 ", nStakeModifierChecksum=%08x, hashProofOfStake=%s, prevoutStake=(%s), nStakeTime=%d merkle=%s, hashBlock=%s)",
        (const void *)pprev,
        (const void *)pnext,
        nFile,
        nBlockPos,
        nHeight,
        strenc::FormatMoney(nMint).c_str(),
        strenc::FormatMoney(nMoneySupply).c_str(),
        GeneratedStakeModifier() ? "MOD": "-",   GetStakeEntropyBit(),   IsProofOfStake() ? "PoS": "PoW",
        nStakeModifier,
        nStakeModifierChecksum,
        hashProofOfStake.ToString().c_str(),
        prevoutStake.ToString().c_str(),
        nStakeTime,
        CBlockHeader<T>::hashMerkleRoot.ToString().c_str(),
        GetBlockHash().ToString().c_str()
        );
}

template<typename T>
std::string CDiskBlockIndex_impl<T>::ToString() const {
    std::string str = "CDiskBlockIndex(";
    str += tfm::format("  nHeight=%d nBlockPos=%d  )", CBlockIndex_impl<T>::nHeight, CBlockIndex_impl<T>::nBlockPos);
    //str += CBlockIndex::ToString();
    //str += tfm::format("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)", GetBlockHash().ToString().c_str(), this->hashPrev.ToString().c_str(), this->hashNext.ToString().c_str());
    return str;
}

template <typename T>
void CBlock_print_impl<T>::PrintBlockTree() {
    // pre-compute tree structure
    std::map<CBlockIndex *, vBlockIndex_t> mapNext;
    for (BlockMap::iterator mi = block_info::mapBlockIndex.begin(); mi != block_info::mapBlockIndex.end(); ++mi) {
        CBlockIndex *pindex = (*mi).second;
        mapNext[pindex->set_pprev()].push_back(pindex);
        // test
        // while (rand()%3==0) mapNext[pindex->pprev].push_back(pindex);
    }

    vStack_t vStack;
    vStack.push_back(std::make_pair(0, block_info::pindexGenesisBlock));
    int nPrevCol = 0;
    while (! vStack.empty()) {
        int nCol = vStack.back().first;
        CBlockIndex *pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol) {
            for (int i=0; i < nCol-1; ++i) logging::LogPrintf("| ");
            logging::LogPrintf("|\\\n");
        } else if (nCol < nPrevCol) {
            for (int i=0; i < nCol; ++i) logging::LogPrintf("| ");
            logging::LogPrintf("|\n");
        }
        nPrevCol = nCol;

        // print columns
        for (int i=0; i < nCol; ++i) logging::LogPrintf("| ");

        // print item
        CBlock_impl<T> block;
        block.ReadFromDisk(pindex);
        logging::LogPrintf("%d (%u,%u) %s  %08x  %s  mint %7s  tx %" PRIszu "\n",
            pindex->get_nHeight(),
            pindex->get_nFile(),
            pindex->get_nBlockPos(),
            block.GetPoHash().ToString().c_str(),
            block.get_nBits(),
            util::DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()).c_str(),
            strenc::FormatMoney(pindex->get_nMint()).c_str(),
            block.get_vtx().size());

        block_notify<T>::PrintWallets(block);

        // put the main time-chain first
        vBlockIndex_t &vNext = mapNext[pindex];
        for (unsigned int i=0; i < vNext.size(); ++i) {
            if (vNext[i]->get_pnext()) {
                std::swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (unsigned int i=0; i < vNext.size(); ++i) vStack.push_back(std::make_pair(nCol+i, vNext[i]));
    }
}

// notify wallets about a new best chain
template <typename T>
void block_notify<T>::SetBestChain(const CBlockLocator &loc)
{
    for(CWallet *pwallet: block_info::setpwalletRegistered)
        pwallet->SetBestChain(loc);
}

// notify wallets about an updated transaction
template <typename T>
void block_notify<T>::UpdatedTransaction(const T &hashTx)
{
    for(CWallet *pwallet: block_info::setpwalletRegistered)
        pwallet->UpdatedTransaction(hashTx);
}

// dump all wallets
template <typename T>
void block_notify<T>::PrintWallets(const CBlock_impl<T> &block)
{
    for(CWallet *pwallet: block_info::setpwalletRegistered)
        pwallet->PrintWallet(block);
}

template <typename T>
bool block_notify<T>::IsInitialBlockDownload()
{
    if (block_info::pindexBest == nullptr || block_info::nBestHeight < Checkpoints::manage::GetTotalBlocksEstimate())
        return true;

    static int64_t nLastUpdate = 0;
    static CBlockIndex_impl<T> *pindexLastBest = nullptr;
    int64_t nCurrentTime = bitsystem::GetTime();
    if (block_info::pindexBest != pindexLastBest) {
        pindexLastBest = block_info::pindexBest;
        nLastUpdate = nCurrentTime;
    }
    return (nCurrentTime - nLastUpdate < 10 && block_info::pindexBest->GetBlockTime() < nCurrentTime - util::nOneDay);
}

template <typename T>
void CBlockHeader<T>::set_LastHeight(int32_t _in) {
    const int32_t sw_height=args_bool::fTestNet ? SWITCH_LYRE2RE_BLOCK_TESTNET: SWITCH_LYRE2RE_BLOCK;
    if(_in + 1 >= sw_height) {
        CBlockHeader<T>::LastHeight = _in;
        CBlockHeader<T>::nVersion = CURRENT_VERSION_Lyra2REV2;
    } else {
        CBlockHeader<T>::LastHeight = _in;
        CBlockHeader<T>::nVersion = CURRENT_VERSION;
    }
}

template <typename T>
T CBlockHeader_impl<T>::GetPoHash() const {
    const int32_t sw_height=args_bool::fTestNet ? SWITCH_LYRE2RE_BLOCK_TESTNET: SWITCH_LYRE2RE_BLOCK;
    if(CBlockHeader<T>::get_LastHeight() + 1 >= sw_height) {
        T hash;
        lyra2re2_hash((const char *)this, BEGIN(hash));
        return hash;
    } else
        return bitscrypt::scrypt_blockhash((const char *)this);
}

template <typename T>
T CBlockHeader_impl<T>::GetPoHash(int32_t height) const {
    assert(height!=-1);
    T hash;
    const int32_t sw_height=args_bool::fTestNet ? SWITCH_LYRE2RE_BLOCK_TESTNET: SWITCH_LYRE2RE_BLOCK;
    if(height >= sw_height)
        lyra2re2_hash((const char *)this, BEGIN(hash));
    else
        hash = GetPoHash();
    return hash;
}

template <typename T>
bool CBlock_impl<T>::DisconnectBlock(CTxDB_impl<T> &txdb, CBlockIndex_impl<T> *pindex)
{
    // Disconnect in reverse order
    for (int i = Merkle_t::vtx.size() - 1; i >= 0; --i) {
        if (! Merkle_t::vtx[i].DisconnectInputs(txdb)) return false;
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->get_pprev()) {
        CDiskBlockIndex_impl<T> blockindexPrev(pindex->set_pprev());
        blockindexPrev.set_hashNext(0);
        if (! txdb.WriteBlockIndex(blockindexPrev))
            return logging::error("DisconnectBlock() : WriteBlockIndex failed");
    }

    // ppcoin: clean up wallet after disconnecting coinstake
    for(CTransaction_impl<T> &tx: this->vtx)
        wallet_process::manage::SyncWithWallets(tx, this, false, false);

    return true;
}

template <typename T>
bool CBlock_impl<T>::ConnectBlock(CTxDB_impl<T> &txdb, CBlockIndex_impl<T> *pindex, bool fJustCheck/*=false*/)
{
    CBlockHeader<T>::set_LastHeight(pindex->get_nHeight() - 1);

    // Check it again in case a previous version let a bad block in, but skip BlockSig checking
    if (! CheckBlock(!fJustCheck, !fJustCheck, false))
        return false;

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied all blocks whose timestamp was after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes in their initial block download.
    bool fEnforceBIP30 = true; // Always active in coin
    bool fScriptChecks = pindex->get_nHeight() >= Checkpoints::manage::GetTotalBlocksEstimate();

    // issue here: it doesn't know the version
    unsigned int nTxPos;
    if (fJustCheck) {
        // FetchInputs treats CDiskTxPos(1,1,1) as a special "refer to memorypool" indicator
        // Since we're just checking the block and not actually connecting it, it might not (and probably shouldn't) be on the disk to get the transaction from
        nTxPos = 1;
    } else
        nTxPos = pindex->get_nBlockPos() + ::GetSerializeSize(CBlock()) - (2 * compact_size::manage::GetSizeOfCompactSize(0)) + compact_size::manage::GetSizeOfCompactSize(Merkle_t::vtx.size());

    std::map<T, CTxIndex> mapQueuedChanges;
    CCheckQueueControl<CScriptCheck> control(fScriptChecks && block_info::nScriptCheckThreads ? &block_check::thread::scriptcheckqueue : NULL);

    int64_t nFees = 0;
    int64_t nValueIn = 0;
    int64_t nValueOut = 0;
    unsigned int nSigOps = 0;
    for(CTransaction_impl<T> &tx: this->vtx) {
        T hashTx = tx.GetHash();
        if (fEnforceBIP30) {
            CTxIndex txindexOld;
            if (txdb.ReadTxIndex(hashTx, txindexOld)) {
                for(const CDiskTxPos &pos: txindexOld.get_vSpent()) {
                    if (pos.IsNull()) return false;
                }
            }
        }

        nSigOps += tx.GetLegacySigOpCount();
        if (nSigOps > block_params::MAX_BLOCK_SIGOPS)
            return DoS(100, logging::error("ConnectBlock() : too many sigops"));

        CDiskTxPos posThisTx(pindex->get_nFile(), pindex->get_nBlockPos(), nTxPos);
        if (! fJustCheck)
            nTxPos += ::GetSerializeSize(tx);

        MapPrevTx mapInputs;
        if (tx.IsCoinBase())
            nValueOut += tx.GetValueOut();
        else {
            bool fInvalid;
            if (! tx.FetchInputs(txdb, mapQueuedChanges, true, false, mapInputs, fInvalid))
                return false;

            // Add in sigops done by pay-to-script-hash inputs;
            // this is to prevent a "rogue miner" from creating
            // an incredibly-expensive-to-validate block.
            nSigOps += tx.GetP2SHSigOpCount(mapInputs);
            if (nSigOps > block_params::MAX_BLOCK_SIGOPS)
                return DoS(100, logging::error("ConnectBlock() : too many sigops"));

            int64_t nTxValueIn = tx.GetValueIn(mapInputs);
            int64_t nTxValueOut = tx.GetValueOut();
            nValueIn += nTxValueIn;
            nValueOut += nTxValueOut;
            if (! tx.IsCoinStake())
                nFees += nTxValueIn - nTxValueOut;

            unsigned int nFlags = Script_param::SCRIPT_VERIFY_NOCACHE | Script_param::SCRIPT_VERIFY_P2SH;
            if (tx.get_nTime() >= timestamps::CHECKLOCKTIMEVERIFY_SWITCH_TIME) {
                nFlags |= Script_param::SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
                // OP_CHECKSEQUENCEVERIFY is senseless without BIP68, so we're going disable it for now.
                // nFlags |= Script_param::SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
            }

            std::vector<CScriptCheck> vChecks;
            if (! tx.ConnectInputs(txdb, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false, fScriptChecks, nFlags, block_info::nScriptCheckThreads ? &vChecks : nullptr))
                return false;

            control.Add(std::move(vChecks));
        }
        mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.get_vout().size());
    }
    if (! control.Wait())
        return DoS(100, false);
    if (IsProofOfWork()) {
        int64_t nBlockReward = diff::reward::GetProofOfWorkReward(CBlockHeader<T>::nBits, nFees);
        // Check coinbase reward
        if (Merkle_t::vtx[0].GetValueOut() > nBlockReward)
            return logging::error("CheckBlock() : coinbase reward exceeded (actual=%" PRId64 " vs calculated=%" PRId64 ")", Merkle_t::vtx[0].GetValueOut(), nBlockReward);
    }

    // track money supply and mint amount info
    pindex->set_nMint(nValueOut - nValueIn + nFees);
    pindex->set_nMoneySupply((pindex->get_pprev()? pindex->get_pprev()->get_nMoneySupply() : 0) + nValueOut - nValueIn);
    if (! txdb.WriteBlockIndex(CDiskBlockIndex_impl<T>(pindex)))
        return logging::error("Connect() : WriteBlockIndex for pindex failed");

    // fees are not collected by proof-of-stake miners
    // fees are destroyed to compensate the entire network
    if (args_bool::fDebug && IsProofOfStake() && map_arg::GetBoolArg("-printcreation"))
        logging::LogPrintf("ConnectBlock() : destroy=%s nFees=%" PRId64 "\n", strenc::FormatMoney(nFees).c_str(), nFees);
    if (fJustCheck)
        return true;

    // Write queued txindex changes
    for (typename std::map<T, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi) {
        if (! txdb.UpdateTxIndex((*mi).first, (*mi).second)) return logging::error("ConnectBlock() : UpdateTxIndex failed");
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->get_pprev()) {
        CDiskBlockIndex_impl<T> blockindexPrev(pindex->set_pprev());
        blockindexPrev.set_hashNext(pindex->GetBlockHash());
        if (! txdb.WriteBlockIndex(blockindexPrev))
            return logging::error("ConnectBlock() : WriteBlockIndex failed");
    }

    // Watch for transactions paying to me
    for(CTransaction_impl<T> &tx: this->vtx)
        wallet_process::manage::SyncWithWallets(tx, this, true);

    return true;
}

template <typename T>
bool CBlock_impl<T>::ReadFromDisk(const CBlockIndex_impl<T> *pindex, bool fReadTransactions/*=true*/)
{
    CBlockHeader<T>::set_LastHeight(pindex->get_nHeight() - 1);
    if (! fReadTransactions) {
        *this = pindex->GetBlockHeader();
        return true;
    }
    if (! ReadFromDisk(pindex->get_nFile(), pindex->get_nBlockPos(), fReadTransactions))
        return false;
    if (CBlockHeader_impl<T>::GetPoHash() != pindex->GetBlockHash())
        return logging::error("CBlock::ReadFromDisk() : GetHash() doesn't match index");

    return true;
}

template <typename T>
bool CBlock_impl<T>::SetBestChain(CTxDB_impl<T> &txdb, CBlockIndex_impl<T> *pindexNew)
{
    T hash = CBlockHeader_impl<T>::GetPoHash();
    if (! txdb.TxnBegin())
        return logging::error("SetBestChain() : TxnBegin failed");

    if (block_info::pindexGenesisBlock == NULL && hash == (!args_bool::fTestNet ? block_params::hashGenesisBlock : block_params::hashGenesisBlockTestNet)) {
        txdb.WriteHashBestChain(hash);
        if (! txdb.TxnCommit())
            return logging::error("SetBestChain() : TxnCommit failed");
        block_info::pindexGenesisBlock = pindexNew;
    } else if (CBlockHeader<T>::hashPrevBlock == block_info::hashBestChain) {
        if (! SetBestChainInner(txdb, pindexNew))
            return logging::error("SetBestChain() : SetBestChainInner failed");
    } else {
        // the first block in the new chain that will cause it to become the new best chain
        CBlockIndex_impl<T> *pindexIntermediate = pindexNew;

        // list of blocks that need to be connected afterwards
        std::vector<CBlockIndex_impl<T> *> vpindexSecondary;

        // block_check::manage::Reorganize is costly in terms of db load, as it works in a single db transaction.
        // Try to limit how much needs to be done inside
        while (pindexIntermediate->get_pprev() && pindexIntermediate->get_pprev()->get_nChainTrust() > block_info::pindexBest->get_nChainTrust()) {
            vpindexSecondary.push_back(pindexIntermediate);
            pindexIntermediate = pindexIntermediate->set_pprev();
        }
        if (! vpindexSecondary.empty())
            logging::LogPrintf("Postponing %" PRIszu " reconnects\n", vpindexSecondary.size());

        // Switch to new best branch
        if (! block_check::manage<T>::Reorganize(txdb, pindexIntermediate)) {
            txdb.TxnAbort();
            block_check::manage<T>::InvalidChainFound(pindexNew);
            return logging::error("SetBestChain() : block_check::manage::Reorganize failed");
        }

        // Connect further blocks
        for (typename std::vector<CBlockIndex_impl<T> *>::reverse_iterator rit = vpindexSecondary.rbegin(); rit != vpindexSecondary.rend(); ++rit) {
            CBlock_impl<T> block;
            if (! block.ReadFromDisk(*rit)) {
                logging::LogPrintf("SetBestChain() : ReadFromDisk failed\n");
                break;
            }
            if (! txdb.TxnBegin()) {
                logging::LogPrintf("SetBestChain() : TxnBegin 2 failed\n");
                break;
            }

            // errors now are not fatal, we still did a reorganisation to a new chain in a valid way
            if (! block.SetBestChainInner(txdb, *rit))
                break;
        }
    }

    // Update best block in wallet (so we can detect restored wallets)
    bool fIsInitialDownload = block_notify<T>::IsInitialBlockDownload();
    if (! fIsInitialDownload) {
        const CBlockLocator_impl<T> locator(pindexNew);
        block_notify<T>::SetBestChain(locator);
    }

    // New best block
    block_info::hashBestChain = hash;
    block_info::pindexBest = pindexNew;
    block_transaction::manage::setnull_pblockindexFBBHLast(); // pblockindexFBBHLast = nullptr;
    block_info::nBestHeight = block_info::pindexBest->get_nHeight();
    block_info::nBestChainTrust = pindexNew->get_nChainTrust();
    block_info::nTimeBestReceived = bitsystem::GetTime();
    block_info::nTransactionsUpdated++;

    T nBestBlockTrust = block_info::pindexBest->get_nHeight() != 0 ? (block_info::pindexBest->get_nChainTrust() - block_info::pindexBest->get_pprev()->get_nChainTrust()) : block_info::pindexBest->get_nChainTrust();
    logging::LogPrintf("SetBestChain: new best=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
        block_info::hashBestChain.ToString().substr(0,20).c_str(), block_info::nBestHeight,
        CBigNum(block_info::nBestChainTrust).ToString().c_str(),
        nBestBlockTrust.Get64(),
        util::DateTimeStrFormat("%x %H:%M:%S", block_info::pindexBest->GetBlockTime()).c_str());

    // Check the version of the last 100 blocks to see if we need to upgrade:
    if (! fIsInitialDownload) {
        int nUpgraded = 0;
        const CBlockIndex_impl<T> *pindex = block_info::pindexBest;
        for (int i=0; i<100 && pindex!=nullptr; ++i) {
            if (pindex->get_nVersion() > this->get_nVersion())
                ++nUpgraded;
            pindex = pindex->get_pprev();
        }
        if (nUpgraded > 0)
            logging::LogPrintf("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, this->get_nVersion());
        if (nUpgraded > 100 / 2) {
            // excep::strMiscWarning is read by block_alert::manage::GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            excep::set_strMiscWarning( _("Warning: This version is obsolete, upgrade required!") );
        }
    }

    std::string strCmd = map_arg::GetArg("-blocknotify", "");
    if (!fIsInitialDownload && !strCmd.empty()) {
        boost::replace_all(strCmd, "%s", block_info::hashBestChain.GetHex());
        boost::thread t(lutil::runCommand, strCmd); // thread runs free
    }

    return true;
}

template <typename T>
bool CBlock_impl<T>::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos)
{
    // Check for duplicate
    T hash = CBlockHeader_impl<T>::GetPoHash();
    if (block_info::mapBlockIndex.count(hash))
        return logging::error("AddToBlockIndex() : %s already exists", hash.ToString().substr(0,20).c_str());

    // Construct new block index object
    CBlockIndex_impl<T> *pindexNew = new(std::nothrow) CBlockIndex_impl<T>(nFile, nBlockPos, *this);
    if (! pindexNew)
        return logging::error("AddToBlockIndex() : new CBlockIndex failed");

    pindexNew->set_phashBlock(&hash);
    auto miPrev = block_info::mapBlockIndex.find(CBlockHeader<T>::hashPrevBlock);
    if (miPrev != block_info::mapBlockIndex.end()) {
        pindexNew->set_pprev((*miPrev).second);
        pindexNew->set_nHeight(pindexNew->get_pprev()->get_nHeight() + 1);
        pindexNew->BuildSkip();
    }

    // ppcoin: compute chain trust score
    pindexNew->set_nChainTrust((pindexNew->get_pprev() ? pindexNew->get_pprev()->get_nChainTrust() : 0) + pindexNew->GetBlockTrust());

    // ppcoin: compute stake entropy bit for stake modifier
    if (! pindexNew->SetStakeEntropyBit(GetStakeEntropyBit(pindexNew->get_nHeight())))
        return logging::error("AddToBlockIndex() : SetStakeEntropyBit() failed");

    // ppcoin: record proof-of-stake hash value
    if (pindexNew->IsProofOfStake()) {
        if (! block_process::mapProofOfStake.count(hash))
            return logging::error("AddToBlockIndex() : hashProofOfStake not found in map");
        pindexNew->set_hashProofOfStake(block_process::mapProofOfStake[hash]);
    }

    // ppcoin: compute stake modifier
    uint64_t nStakeModifier = 0;
    bool fGeneratedStakeModifier = false;
    if (! bitkernel<T>::ComputeNextStakeModifier(pindexNew, nStakeModifier, fGeneratedStakeModifier))
        return logging::error("AddToBlockIndex() : bitkernel::ComputeNextStakeModifier() failed");

    pindexNew->SetStakeModifier(nStakeModifier, fGeneratedStakeModifier);
    pindexNew->set_nStakeModifierChecksum(bitkernel<T>::GetStakeModifierChecksum(pindexNew));
    if (! bitkernel<T>::CheckStakeModifierCheckpoints(pindexNew->get_nHeight(), pindexNew->get_nStakeModifierChecksum()))
        return logging::error("AddToBlockIndex() : Rejected by stake modifier checkpoint height=%d, modifier=0x%016" PRIx64, pindexNew->get_nHeight(), nStakeModifier);

    // Add to block_info::mapBlockIndex
    auto mi = block_info::mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    if (pindexNew->IsProofOfStake())
        block_info::setStakeSeen.insert(std::make_pair(pindexNew->get_prevoutStake(), pindexNew->get_nStakeTime()));
    pindexNew->set_phashBlock(&((*mi).first));

    // Write to disk block index
    CTxDB_impl<T> txdb;
    if (! txdb.TxnBegin()) return false;
    txdb.WriteBlockIndex(CDiskBlockIndex_impl<T>(pindexNew));
    if (! txdb.TxnCommit()) return false;

    LOCK(block_process::cs_main);

    // New best
    if (pindexNew->get_nChainTrust() > block_info::nBestChainTrust) {
        if (! SetBestChain(txdb, pindexNew)) return false;
    }
    if (pindexNew == block_info::pindexBest) {
        // Notify UI to display prev block's coinbase if it was ours
        static T hashPrevBestCoinBase;
        block_notify<T>::UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = Merkle_t::vtx[0].GetHash();
    }

    static int8_t counter = 0;
    if( (++counter & 0x0F) == 0 || !block_notify<T>::IsInitialBlockDownload()) // repaint every 16 blocks if not in initial block download
        CClientUIInterface::uiInterface.NotifyBlocksChanged();

    return true;
}

template <typename T>
bool CBlock_impl<T>::CheckBlock(bool fCheckPOW/*=true*/, bool fCheckMerkleRoot/*=true*/, bool fCheckSig/*=true*/) const
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.
    std::set<T> uniqueTx; // tx hashes
    unsigned int nSigOps = 0; // total sigops

    // Size limits
    if (Merkle_t::vtx.empty() || Merkle_t::vtx.size() > block_params::MAX_BLOCK_SIZE || ::GetSerializeSize(*this) > block_params::MAX_BLOCK_SIZE)
        return DoS(100, logging::error("CheckBlock() : size limits failed"));

    bool fProofOfStake = IsProofOfStake();

    // First transaction must be coinbase, the rest must not be
    if (! Merkle_t::vtx[0].IsCoinBase())
        return DoS(100, logging::error("CheckBlock() : first tx is not coinbase"));
    if (! Merkle_t::vtx[0].CheckTransaction())
        return DoS(Merkle_t::vtx[0].nDoS, logging::error("CheckBlock() : CheckTransaction failed on coinbase"));

    uniqueTx.insert(Merkle_t::vtx[0].GetHash());
    nSigOps += Merkle_t::vtx[0].GetLegacySigOpCount();
    if (fProofOfStake) {
        // Proof-of-STake related checkings. Note that we know here that 1st transactions is coinstake. We don't need
        // check the type of 1st transaction because it's performed earlier by IsProofOfStake()
        // note: nNonce must be zero for proof-of-stake blocks
        if (CBlockHeader<T>::nNonce != 0)
            return DoS(100, logging::error("CheckBlock() : non-zero nonce in proof-of-stake block"));

        // Coinbase output should be empty if proof-of-stake block
        if (Merkle_t::vtx[0].get_vout().size() != 1 || !Merkle_t::vtx[0].get_vout(0).IsEmpty())
            return DoS(100, logging::error("CheckBlock() : coinbase output not empty for proof-of-stake block"));

        // Check coinstake timestamp
        if (CBlockHeader_impl<T>::GetBlockTime() != (int64_t)Merkle_t::vtx[1].get_nTime())
            return DoS(50, logging::error("CheckBlock() : coinstake timestamp violation nTimeBlock=%" PRId64 " nTimeTx=%u", CBlockHeader_impl<T>::GetBlockTime(), Merkle_t::vtx[1].get_nTime()));

        // ppcoin: check proof-of-stake block signature
        if (fCheckSig && !CheckBlockSignature())
            return DoS(100, logging::error("CheckBlock() : bad proof-of-stake block signature"));

        if (! Merkle_t::vtx[1].CheckTransaction())
            return DoS(Merkle_t::vtx[1].nDoS, logging::error("CheckBlock() : CheckTransaction failed on coinstake"));

        uniqueTx.insert(Merkle_t::vtx[1].GetHash());
        nSigOps += Merkle_t::vtx[1].GetLegacySigOpCount();
    } else {
        // Check proof of work matches claimed amount
        if (fCheckPOW && !diff::check::CheckProofOfWork(CBlockHeader_impl<T>::GetPoHash(), CBlockHeader<T>::nBits))
            return DoS(50, logging::error("CheckBlock() : proof of work failed"));
        /*
        {
            CBlockIndex_impl<T> *pindexPrev = nullptr;
            int nHeight = 0;
            if (CBlockHeader_impl<T>::GetPoHash() != get_hashGenesisBlock(args_bool::fTestNet)) {
                auto mi = block_info::mapBlockIndex.find(CBlockHeader<T>::get_hashPrevBlock());
                pindexPrev = (*mi).second;
                if (mi != block_info::mapBlockIndex.end()) {
                    if (pindexPrev != nullptr) {
                        nHeight = pindexPrev->get_nHeight()+1;
                        // Check proof of work matches claimed amount
                        if (fCheckPOW && !diff::check::CheckProofOfWork(CBlockHeader_impl<T>::GetPoHash(nHeight), CBlockHeader_impl<T>::get_nBits()))
                            return DoS(50, logging::error("CheckBlock() : proof of work failed"));
                    }
                }
            }
        }
        */

        // Check timestamp
        if (CBlockHeader_impl<T>::GetBlockTime() > block_check::manage<uint256>::FutureDrift(bitsystem::GetAdjustedTime()))
            return logging::error("CheckBlock() : block timestamp too far in the future");

        // Check coinbase timestamp
        if (CBlockHeader_impl<T>::GetBlockTime() < block_check::manage<uint256>::PastDrift((int64_t)Merkle_t::vtx[0].get_nTime()))
            return DoS(50, logging::error("CheckBlock() : coinbase timestamp is too late"));
    }

    // Iterate all transactions starting from second for proof-of-stake block or first for proof-of-work block
    for (unsigned int i = fProofOfStake ? 2 : 1; i < Merkle_t::vtx.size(); ++i) {
        const CTransaction &tx = Merkle_t::vtx[i];

        // Reject coinbase transactions at non-zero index
        if (tx.IsCoinBase())
            return DoS(100, logging::error("CheckBlock() : coinbase at wrong index"));

        // Reject coinstake transactions at index != 1
        if (tx.IsCoinStake())
            return DoS(100, logging::error("CheckBlock() : coinstake at wrong index"));

        // Check transaction timestamp
        if (CBlockHeader_impl<T>::GetBlockTime() < (int64_t)tx.get_nTime())
            return DoS(50, logging::error("CheckBlock() : block timestamp earlier than transaction timestamp"));

        // Check transaction consistency
        if (! tx.CheckTransaction())
            return DoS(tx.nDoS, logging::error("CheckBlock() : CheckTransaction failed"));

        // Add transaction hash into list of unique transaction IDs
        uniqueTx.insert(tx.GetHash());

        // Calculate sigops count
        nSigOps += tx.GetLegacySigOpCount();
    }

    // Check for duplicate txids. This is caught by ConnectInputs(),
    // but catching it earlier avoids a potential DoS attack:
    if (uniqueTx.size() != Merkle_t::vtx.size())
        return DoS(100, logging::error("CheckBlock() : duplicate transaction"));

    // Reject block if validation would consume too much resources.
    if (nSigOps > block_params::MAX_BLOCK_SIGOPS)
        return DoS(100, logging::error("CheckBlock() : out-of-bounds SigOpCount"));

    // Check merkle root
    if (fCheckMerkleRoot && CBlockHeader<T>::hashMerkleRoot != Merkle_t::BuildMerkleTree())
        return DoS(100, logging::error("CheckBlock() : hashMerkleRoot mismatch"));

    return true;
}

//#define ACCEPT_DEBUG_CS(k, v) debugcs::instance() << (k) << (v) << debugcs::endl()
#define ACCEPT_DEBUG_CS(k, v)
template <typename T>
bool CBlock_impl<T>::AcceptBlock()
{
    // Check for duplicate
    T hash = CBlockHeader_impl<T>::GetPoHash();
    if (block_info::mapBlockIndex.count(hash))
        return logging::error("CBlock::AcceptBlock() : block already in block_info::mapBlockIndex");

    // Get prev block index
    auto mi = block_info::mapBlockIndex.find(CBlockHeader<T>::hashPrevBlock);
    if (mi == block_info::mapBlockIndex.end())
        return DoS(10, logging::error("CBlock::AcceptBlock() : prev block not found"));

    CBlockIndex *pindexPrev = (*mi).second;
    int nHeight = pindexPrev->get_nHeight() + 1;
    CBlockHeader<T>::set_LastHeight(pindexPrev->get_nHeight());
    ACCEPT_DEBUG_CS("CBlock_impl::AcceptBlock nHeight: ", nHeight);

    // Check proof-of-work or proof-of-stake
    if (CBlockHeader<T>::nBits != diff::spacing::GetNextTargetRequired(pindexPrev, IsProofOfStake()))
        return DoS(100, logging::error("CBlock::AcceptBlock() : incorrect %s", IsProofOfWork() ? "proof-of-work" : "proof-of-stake"));
    ACCEPT_DEBUG_CS("CBlock_impl::AcceptBlock nBits: ", CBlockHeader<T>::nBits);

    int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();
    int nMaxOffset = (args_bool::fTestNet || pindexPrev->get_nTime() < timestamps::BLOCKS_ADMIT_HOURS_SWITCH_TIME) ?
        block_transaction::DONOT_ACCEPT_BLOCKS_ADMIT_HOURS_TESTNET * util::nOneHour:
        block_transaction::DONOT_ACCEPT_BLOCKS_ADMIT_HOURS * util::nOneHour;

    // Check timestamp against prev
    if (CBlockHeader_impl<T>::GetBlockTime() <= nMedianTimePast || block_check::manage<uint256>::FutureDrift(CBlockHeader_impl<T>::GetBlockTime()) < pindexPrev->GetBlockTime())
        return logging::error("CBlock::AcceptBlock() : block's timestamp is too early");

    // Don't accept blocks with future timestamps
    if (pindexPrev->get_nHeight() > 1 && nMedianTimePast + nMaxOffset < CBlockHeader_impl<T>::GetBlockTime()) {
        return logging::error((std::string("CBlock::AcceptBlock() : block's timestamp is too far in the future ___ nMedianTimePast：")
                     + std::to_string(nMedianTimePast) + " nMaxOffset：" + std::to_string(nMaxOffset) + " GetBlockTime()："
                     + std::to_string(CBlockHeader_impl<T>::GetBlockTime()) + " nHeight：" + std::to_string(pindexPrev->get_nHeight())).c_str());
    }

    // Check that all transactions are finalized
    for(const CTransaction &tx: Merkle_t::vtx) {
        if (! tx.IsFinal(nHeight, CBlockHeader_impl<T>::GetBlockTime()))
            return DoS(10, logging::error("CBlock::AcceptBlock() : contains a non-final transaction"));
    }

    // Check that the block chain matches the known block chain up to a checkpoint
    if (! Checkpoints::manage::CheckHardened(nHeight, hash))
        return DoS(100, logging::error("CBlock::AcceptBlock() : rejected by hardened checkpoint lock-in at %d", nHeight));

    bool cpSatisfies = Checkpoints::manage::CheckSync(hash, pindexPrev);

    // Check that the block satisfies synchronized checkpoint
    if (Checkpoints::CheckpointsMode == Checkpoints::STRICT && !cpSatisfies)
        return logging::error("CBlock::AcceptBlock() : rejected by synchronized checkpoint");
    if (Checkpoints::CheckpointsMode == Checkpoints::ADVISORY && !cpSatisfies)
        excep::set_strMiscWarning( _("WARNING: syncronized checkpoint violation detected, but skipped!") );

    // Enforce rule that the coinbase starts with serialized block height
    if(CBlockHeader_impl<T>::get_nVersion()<=6) {
        CScript expect = CScript() << nHeight;
        if (Merkle_t::vtx[0].get_vin(0).get_scriptSig().size() < expect.size() || !std::equal(expect.begin(), expect.end(), Merkle_t::vtx[0].get_vin(0).get_scriptSig().begin()))
            return DoS(100, logging::error("CBlock::AcceptBlock() : block height mismatch in coinbase"));
    } else if (CBlockHeader_impl<T>::get_nVersion()>=7) {
        // if 750 of the last 1,000 blocks are version 2 or greater (51/100 if testnet):
        if ((!args_bool::fTestNet && CBlockIndex_impl<T>::IsSuperMajority(7, pindexPrev, 750, 1000)) ||
             (args_bool::fTestNet && CBlockIndex_impl<T>::IsSuperMajority(7, pindexPrev, 51, 100))) {
            CScript expect = CScript() << nHeight;
            if (Merkle_t::vtx[0].get_vin(0).get_scriptSig().size() < expect.size() || !std::equal(expect.begin(), expect.end(), Merkle_t::vtx[0].get_vin(0).get_scriptSig().begin()))
                return DoS(100, logging::error("CBlock::AcceptBlock() : block height mismatch in coinbase"));
        }
    }

    // Write block to history file
    if (! file_open::CheckDiskSpace(::GetSerializeSize(*this)))
        return logging::error("CBlock::AcceptBlock() : out of disk space");

    unsigned int nFile = std::numeric_limits<unsigned int>::max();
    unsigned int nBlockPos = 0;
    if (! WriteToDisk(nFile, nBlockPos))
        return logging::error("CBlock::AcceptBlock() : WriteToDisk failed");
    if (! AddToBlockIndex(nFile, nBlockPos))
        return logging::error("CBlock::AcceptBlock() : AddToBlockIndex failed");

    // Relay inventory, but don't relay old inventory during initial block download
    int nBlockEstimate = Checkpoints::manage::GetTotalBlocksEstimate();
    if (block_info::hashBestChain == hash) {
        LOCK(net_node::cs_vNodes);
        for(CNode *pnode: net_node::vNodes) {
            if (block_info::nBestHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
                pnode->PushInventory(CInv(_CINV_MSG_TYPE::MSG_BLOCK, hash));
        }
    }

    // ppcoin: check pending sync-checkpoint
    Checkpoints::manage::AcceptPendingSyncCheckpoint();

    // SorachanCoin: check Autocheckpoint
    return CAutocheckPoint::get_instance().Check();
}

// ppcoin: total coin age spent in block, in the unit of coin-days.
template <typename T>
bool CBlock_impl<T>::GetCoinAge(uint64_t &nCoinAge) const
{
    nCoinAge = 0;

    CTxDB txdb("r");
    for(const CTransaction &tx: this->vtx) {
        uint64_t nTxCoinAge;
        if (tx.GetCoinAge(txdb, nTxCoinAge))
            nCoinAge += nTxCoinAge;
        else return false;
    }

    if (nCoinAge == 0)    // block coin age minimum 1 coin-day
        nCoinAge = 1;
    if (args_bool::fDebug && map_arg::GetBoolArg("-printcoinage"))
        logging::LogPrintf("block %s age total nCoinDays=%" PRId64 "\n", strCoinName, nCoinAge);

    return true;
}

// ppcoin: check block signature
template <typename T>
bool CBlock_impl<T>::CheckBlockSignature() const
{
    if (vchBlockSig.empty()) return false;

    TxnOutputType::txnouttype whichType;
    Script_util::statype vSolutions;
    if (! Script_util::Solver(Merkle_t::vtx[1].get_vout(1).get_scriptPubKey(), whichType, vSolutions))
        return false;
    if (whichType == TxnOutputType::TX_PUBKEY) {
        Script_util::valtype &vchPubKey = vSolutions[0];
        CPubKey key(vchPubKey);
        if (! key.IsValid()) return false;
        return key.Verify(CBlockHeader_impl<T>::GetPoHash(), vchBlockSig);
    }

    return false;
}

// Called from inside SetBestChain: attaches a block to the new best chain being built
template <typename T>
bool CBlock_impl<T>::SetBestChainInner(CTxDB_impl<T> &txdb, CBlockIndex_impl<T> *pindexNew)
{
    T hash = CBlockHeader_impl<T>::GetPoHash();

    // Adding to current best branch
    if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash)) {
        txdb.TxnAbort();
        block_check::manage<uint256>::InvalidChainFound(pindexNew);
        return false;
    }
    if (! txdb.TxnCommit())
        return logging::error("SetBestChain() : TxnCommit failed");

    // Add to current best branch
    pindexNew->set_pprev()->set_pnext(pindexNew);

    // Delete redundant memory transactions
    for(CTransaction &tx: this->vtx)
        CTxMemPool::mempool.remove(tx);

    return true;
}

template<typename T>
bool CBlock_impl<T>::WriteToDisk(unsigned int &nFileRet, unsigned int &nBlockPosRet) {
    //debugcs::instance() << "CBlock_impl() WriteToDisk nFileRet: " << nFileRet << " nBlockPosRet: " << nBlockPosRet << debugcs::endl();

    // Open history file to append
    CAutoFile fileout = CAutoFile(file_open::AppendBlockFile(nFileRet), SER_DISK, version::CLIENT_VERSION);
    if (! fileout) return logging::error("CBlock::WriteToDisk() : file_open::AppendBlockFile failed");
    // Write index header
    unsigned int nSize = fileout.GetSerializeSize(*this);
    fileout << FLATDATA(block_info::gpchMessageStart) << nSize;
    // Write block
    long fileOutPos = ::ftell(fileout);
    if (fileOutPos < 0) return logging::error("CBlock::WriteToDisk() : ftell failed");
    nBlockPosRet = fileOutPos;
    fileout << *this;
    // Flush stdio buffers and commit to disk before returning
    fflush(fileout);
    if (!block_notify<T>::IsInitialBlockDownload() || (block_info::nBestHeight+1)%500==0)
        iofs::FileCommit(fileout);
    return true;
}

template <typename T>
bool CBlock_impl<T>::ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions/*=true*/) {
    //debugcs::instance() << "CBlock_impl() ReadFromDisk nFile: " << nFile << " nBlockPos: " << nBlockPos << " fReadTransactions: " << fReadTransactions << debugcs::endl();

    SetNull();
    // Open history file to read
    CAutoFile filein = CAutoFile(file_open::OpenBlockFile(nFile, nBlockPos, "rb"), SER_DISK, version::CLIENT_VERSION);
    if (! filein) return logging::error("CBlock::ReadFromDisk() : file_open::OpenBlockFile failed");
    if (! fReadTransactions) filein.AddType(SER_BLOCKHEADERONLY);
    // Read block
    try {
        filein >> *this;
    } catch (const std::exception &) {
        return logging::error("%s() : deserialize or I/O error", BOOST_CURRENT_FUNCTION);
    }
    // Check the header
    /*
    if (fReadTransactions && IsProofOfWork() && !diff::check::CheckProofOfWork(CBlockHeader_impl<T>::GetPoHash(), CBlockHeader<T>::nBits))
        return logging::error("CBlock::ReadFromDisk() : errors in block header");
    return true;
    */
    if (fReadTransactions && IsProofOfWork() && !diff::check::CheckProofOfWork(CBlockHeader_impl<T>::GetPoHash(CBlockHeader<T>::get_LastHeight()+1), CBlockHeader<T>::nBits))
        return logging::error("CBlock::ReadFromDisk() : errors in block header");
    return true;
}

template <typename T>
void CBlock_impl<T>::print() const {
    logging::LogPrintf("CBlock(hash1=%s, hash2=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%" PRIszu ", vchBlockSig=%s)\n",
        CBlockHeader_impl<T>::GetPoHash().ToString().c_str(),
        CBlockHeader_impl<T>::GetPoHash(CBlockHeader<T>::get_LastHeight()+1).ToString().c_str(),
        CBlockHeader<T>::nVersion,
        CBlockHeader<T>::hashPrevBlock.ToString().c_str(),
        CBlockHeader<T>::hashMerkleRoot.ToString().c_str(),
        CBlockHeader<T>::nTime,
        CBlockHeader<T>::nBits,
        CBlockHeader<T>::nNonce,
        Merkle_t::vtx.size(),
        util::HexStr(vchBlockSig.begin(), vchBlockSig.end()).c_str());
    for (unsigned int i=0; i<this->vtx.size(); ++i) {
        logging::LogPrintf("  ");
        Merkle_t::vtx[i].print();
    }
    logging::LogPrintf("  vMerkleTree: ");
    for (unsigned int i=0; i<Merkle_t::vMerkleTree.size(); ++i)
        logging::LogPrintf("%s ", Merkle_t::vMerkleTree[i].ToString().substr(0,10).c_str());
    logging::LogPrintf("\n");
}

template <typename T>
T CBlockIndex_impl<T>::GetBlockTrust() const
{
    CBigNum bnTarget;
    bnTarget.SetCompact(CBlockHeader<T>::nBits);
    if (bnTarget <= 0) return 0;

    // Return 1 for the first 12 blocks
    if (pprev == nullptr || pprev->nHeight < 12)
        return 1;

    const CBlockIndex *currentIndex = pprev;
    if(IsProofOfStake()) {
        CBigNum bnNewTrust = (CBigNum(1) << 256) / (bnTarget + 1);

        // Return 1/3 of score if parent block is not the PoW block
        if (! pprev->IsProofOfWork())
            return (bnNewTrust / 3).getuint256();

        int nPoWCount = 0;

        // Check last 12 blocks type
        while (pprev->nHeight - currentIndex->nHeight < 12) {
            if (currentIndex->IsProofOfWork())
                ++nPoWCount;
            currentIndex = currentIndex->pprev;
        }

        // Return 1/3 of score if less than 3 PoW blocks found
        if (nPoWCount < 3) {
            logging::LogPrintf("GetBlockTrust(Return 1/3 of score) nPoWCount %d\n", nPoWCount);
            return (bnNewTrust / 3).getuint256();
        }

        return bnNewTrust.getuint256();
    } else {
        // Calculate work amount for block
        CBigNum bnPoWTrust = CBigNum(diff::nPoWBase) / (bnTarget+1);

        // Set nPowTrust to 1 if PoW difficulty is too low
        if (bnPoWTrust < 1) bnPoWTrust = 1;

        CBigNum bnLastBlockTrust = CBigNum(pprev->nChainTrust - pprev->pprev->nChainTrust);

        // Return nPoWTrust + 2/3 of previous block score if two parent blocks are not PoS blocks
        if (!(pprev->IsProofOfStake() && pprev->pprev->IsProofOfStake()))
            return (bnPoWTrust + 2 * bnLastBlockTrust / 3).getuint256();

        int nPoSCount = 0;

        // Check last 12 blocks type
        while (pprev->nHeight - currentIndex->nHeight < 12) {
            if (currentIndex->IsProofOfStake())
                ++nPoSCount;
            currentIndex = currentIndex->pprev;
        }

        // Return nPoWTrust + 2/3 of previous block score if less than 7 PoS blocks found
        if (nPoSCount < 7) {
            logging::LogPrintf("GetBlockTrust(nPoWTrust + 2/3 of previous block) nPosCount %d\n", nPoSCount);
            return (bnPoWTrust + 2 * bnLastBlockTrust / 3).getuint256();
        }

        bnTarget.SetCompact(pprev->nBits);
        if (bnTarget <= 0) return 0;

        CBigNum bnNewTrust = (CBigNum(1) << 256) / (bnTarget + 1);

        // Return nPoWTrust + full trust score for previous block nBits
        return (bnPoWTrust + bnNewTrust).getuint256();
    }
}

template class CBlock_print_impl<uint256>;
template class CBlockHeader<uint256>;
template class CBlockHeader_impl<uint256>;
template class CBlock_impl<uint256>;
template class CBlockIndex_impl<uint256>;
template class CDiskBlockIndex_impl<uint256>;
