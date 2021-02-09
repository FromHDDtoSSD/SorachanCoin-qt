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

/*
** collect Block Print
*/
template <typename T>
std::string CBlockIndex_impl<T>::ToString() const {
    return strprintf("CBlockIndex(nprev=%p, pnext=%p, nFile=%u, nBlockPos=%-6d nHeight=%d, nMint=%s, nMoneySupply=%s, \
                      nFlags=(%s)(%d)(%s), \
                      nStakeModifier=%016" PRIx64 ", nStakeModifierChecksum=%08x, hashProofOfStake=%s, prevoutStake=(%s), nStakeTime=%d merkle=%s, hashBlock=%s)",
        (const void *)pprev,
        (const void *)pnext,
        nFile,
        nBlockPos,
        nHeight,
        bitstr::FormatMoney(nMint).c_str(),
        bitstr::FormatMoney(nMoneySupply).c_str(),
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
    str += CBlockIndex::ToString();
    str += strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)", GetBlockHash().ToString().c_str(), this->hashPrev.ToString().c_str(), this->hashNext.ToString().c_str());
    return str;
}

template <typename T>
void CBlock_print_impl<T>::PrintBlockTree() {
    // pre-compute tree structure
    std::map<CBlockIndex *, vBlockIndex_t> mapNext;
    for (std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.begin(); mi != block_info::mapBlockIndex.end(); ++mi) {
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
            for (int i=0; i < nCol-1; ++i) printf("| ");
            printf("|\\\n");
        } else if (nCol < nPrevCol) {
            for (int i=0; i < nCol; ++i) printf("| ");
            printf("|\n");
        }
        nPrevCol = nCol;

        // print columns
        for (int i=0; i < nCol; ++i) printf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex);
        printf("%d (%u,%u) %s  %08x  %s  mint %7s  tx %" PRIszu "\n",
            pindex->get_nHeight(),
            pindex->get_nFile(),
            pindex->get_nBlockPos(),
            block.GetHash().ToString().c_str(),
            block.get_nBits(),
            util::DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()).c_str(),
            bitstr::FormatMoney(pindex->get_nMint()).c_str(),
            block.get_vtx().size());

        block_notify::PrintWallets(block);

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
void block_notify::SetBestChain(const CBlockLocator &loc)
{
    for(CWallet *pwallet: block_info::setpwalletRegistered)
        pwallet->SetBestChain(loc);
}

// notify wallets about an updated transaction
void block_notify::UpdatedTransaction(const uint256 &hashTx)
{
    for(CWallet *pwallet: block_info::setpwalletRegistered)
        pwallet->UpdatedTransaction(hashTx);
}

// dump all wallets
void block_notify::PrintWallets(const CBlock &block)
{
    for(CWallet *pwallet: block_info::setpwalletRegistered)
        pwallet->PrintWallet(block);
}

bool block_notify::IsInitialBlockDownload()
{
    if (block_info::pindexBest == nullptr || block_info::nBestHeight < Checkpoints::manage::GetTotalBlocksEstimate())
        return true;

    static int64_t nLastUpdate = 0;
    static CBlockIndex *pindexLastBest = nullptr;
    int64_t nCurrentTime = bitsystem::GetTime();
    if (block_info::pindexBest != pindexLastBest) {
        pindexLastBest = block_info::pindexBest;
        nLastUpdate = nCurrentTime;
    }
    return (nCurrentTime - nLastUpdate < 10 && block_info::pindexBest->GetBlockTime() < nCurrentTime - util::nOneDay);
}

template <typename T>
uint256 CBlockHeader_impl<T>::GetHash() const { // todo: from uint256 to T (please replace bitscrypt to T)
#if defined(USE_QUANTUM)
    // debug
    //uint65536 tt = bitscrypt::scrypt_blockhash_65536((const uint8_t *)this);
    //assert(0 < tt);
    //debugcs::instance() << "QHASH65536:" << debugcs::endl();
    //debugcs::instance() << tt.GetHex() << debugcs::endl() << "------------------------" << debugcs::endl();
#endif
    assert(sizeof(*this)==80); // uint256 blockheader size.
    return bitscrypt::scrypt_blockhash((const uint8_t *)this);
}

template <typename T>
bool CBlock_impl<T>::DisconnectBlock(CTxDB &txdb, CBlockIndex *pindex)
{
    // Disconnect in reverse order
    for (int i = Merkle_t::vtx.size() - 1; i >= 0; --i) {
        if (! Merkle_t::vtx[i].DisconnectInputs(txdb)) return false;
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->get_pprev()) {
        CDiskBlockIndex blockindexPrev(pindex->set_pprev());
        blockindexPrev.set_hashNext(0);
        if (! txdb.WriteBlockIndex(blockindexPrev))
            return print::error("DisconnectBlock() : WriteBlockIndex failed");
    }

    // ppcoin: clean up wallet after disconnecting coinstake
    for(CTransaction &tx: this->vtx)
        wallet_process::manage::SyncWithWallets(tx, this, false, false);

    return true;
}

template <typename T>
bool CBlock_impl<T>::ConnectBlock(CTxDB &txdb, CBlockIndex *pindex, bool fJustCheck/*=false*/)
{
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
    for(CTransaction &tx: this->vtx) {
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
        if (nSigOps > block_param::MAX_BLOCK_SIGOPS)
            return DoS(100, print::error("ConnectBlock() : too many sigops"));

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
            if (nSigOps > block_param::MAX_BLOCK_SIGOPS)
                return DoS(100, print::error("ConnectBlock() : too many sigops"));

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

            control.Add(vChecks);
        }
        mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.get_vout().size());
    }
    if (! control.Wait())
        return DoS(100, false);
    if (IsProofOfWork()) {
        int64_t nBlockReward = diff::reward::GetProofOfWorkReward(CBlockHeader<T>::nBits, nFees);
        // Check coinbase reward
        if (Merkle_t::vtx[0].GetValueOut() > nBlockReward)
            return print::error("CheckBlock() : coinbase reward exceeded (actual=%" PRId64 " vs calculated=%" PRId64 ")", Merkle_t::vtx[0].GetValueOut(), nBlockReward);
    }

    // track money supply and mint amount info
    pindex->set_nMint(nValueOut - nValueIn + nFees);
    pindex->set_nMoneySupply((pindex->get_pprev()? pindex->get_pprev()->get_nMoneySupply() : 0) + nValueOut - nValueIn);
    if (! txdb.WriteBlockIndex(CDiskBlockIndex(pindex)))
        return print::error("Connect() : WriteBlockIndex for pindex failed");

    // fees are not collected by proof-of-stake miners
    // fees are destroyed to compensate the entire network
    if (args_bool::fDebug && IsProofOfStake() && map_arg::GetBoolArg("-printcreation"))
        printf("ConnectBlock() : destroy=%s nFees=%" PRId64 "\n", bitstr::FormatMoney(nFees).c_str(), nFees);
    if (fJustCheck)
        return true;

    // Write queued txindex changes
    for (typename std::map<T, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi) {
        if (! txdb.UpdateTxIndex((*mi).first, (*mi).second)) return print::error("ConnectBlock() : UpdateTxIndex failed");
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->get_pprev()) {
        CDiskBlockIndex blockindexPrev(pindex->set_pprev());
        blockindexPrev.set_hashNext(pindex->GetBlockHash());
        if (! txdb.WriteBlockIndex(blockindexPrev))
            return print::error("ConnectBlock() : WriteBlockIndex failed");
    }

    // Watch for transactions paying to me
    for(CTransaction &tx: this->vtx)
        wallet_process::manage::SyncWithWallets(tx, this, true);

    return true;
}

template <typename T>
bool CBlock_impl<T>::ReadFromDisk(const CBlockIndex *pindex, bool fReadTransactions/*=true*/)
{
    if (! fReadTransactions) {
        *this = pindex->GetBlockHeader();
        return true;
    }
    if (! ReadFromDisk(pindex->get_nFile(), pindex->get_nBlockPos(), fReadTransactions))
        return false;
    if (CBlockHeader_impl<T>::GetHash() != pindex->GetBlockHash())
        return print::error("CBlock::ReadFromDisk() : GetHash() doesn't match index");

    return true;
}

template <typename T>
bool CBlock_impl<T>::SetBestChain(CTxDB &txdb, CBlockIndex *pindexNew)
{
    T hash = CBlockHeader_impl<T>::GetHash();
    if (! txdb.TxnBegin())
        return print::error("SetBestChain() : TxnBegin failed");

    if (block_info::pindexGenesisBlock == NULL && hash == (!args_bool::fTestNet ? block_param::hashGenesisBlock : block_param::hashGenesisBlockTestNet)) {
        txdb.WriteHashBestChain(hash);
        if (! txdb.TxnCommit())
            return print::error("SetBestChain() : TxnCommit failed");
        block_info::pindexGenesisBlock = pindexNew;
    } else if (CBlockHeader<T>::hashPrevBlock == block_info::hashBestChain) {
        if (! SetBestChainInner(txdb, pindexNew))
            return print::error("SetBestChain() : SetBestChainInner failed");
    } else {
        // the first block in the new chain that will cause it to become the new best chain
        CBlockIndex *pindexIntermediate = pindexNew;

        // list of blocks that need to be connected afterwards
        std::vector<CBlockIndex *> vpindexSecondary;

        // block_check::manage::Reorganize is costly in terms of db load, as it works in a single db transaction.
        // Try to limit how much needs to be done inside
        while (pindexIntermediate->get_pprev() && pindexIntermediate->get_pprev()->get_nChainTrust() > block_info::pindexBest->get_nChainTrust()) {
            vpindexSecondary.push_back(pindexIntermediate);
            pindexIntermediate = pindexIntermediate->set_pprev();
        }
        if (! vpindexSecondary.empty())
            printf("Postponing %" PRIszu " reconnects\n", vpindexSecondary.size());

        // Switch to new best branch
        if (! block_check::manage::Reorganize(txdb, pindexIntermediate)) {
            txdb.TxnAbort();
            block_check::manage::InvalidChainFound(pindexNew);
            return print::error("SetBestChain() : block_check::manage::Reorganize failed");
        }

        // Connect further blocks
        for (std::vector<CBlockIndex *>::reverse_iterator rit = vpindexSecondary.rbegin(); rit != vpindexSecondary.rend(); ++rit) {
            CBlock block;
            if (! block.ReadFromDisk(*rit)) {
                printf("SetBestChain() : ReadFromDisk failed\n");
                break;
            }
            if (! txdb.TxnBegin()) {
                printf("SetBestChain() : TxnBegin 2 failed\n");
                break;
            }

            // errors now are not fatal, we still did a reorganisation to a new chain in a valid way
            if (! block.SetBestChainInner(txdb, *rit))
                break;
        }
    }

    // Update best block in wallet (so we can detect restored wallets)
    bool fIsInitialDownload = block_notify::IsInitialBlockDownload();
    if (! fIsInitialDownload) {
        const CBlockLocator locator(pindexNew);
        block_notify::SetBestChain(locator);
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
    printf("SetBestChain: new best=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
        block_info::hashBestChain.ToString().substr(0,20).c_str(), block_info::nBestHeight,
        CBigNum(block_info::nBestChainTrust).ToString().c_str(),
        nBestBlockTrust.Get64(),
        util::DateTimeStrFormat("%x %H:%M:%S", block_info::pindexBest->GetBlockTime()).c_str());

    // Check the version of the last 100 blocks to see if we need to upgrade:
    if (! fIsInitialDownload) {
        int nUpgraded = 0;
        const CBlockIndex *pindex = block_info::pindexBest;
        for (int i=0; i<100 && pindex!=nullptr; ++i) {
            if (pindex->get_nVersion() > this->get_nVersion())
                ++nUpgraded;
            pindex = pindex->get_pprev();
        }
        if (nUpgraded > 0)
            printf("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, this->get_nVersion());
        if (nUpgraded > 100 / 2) {
            // excep::strMiscWarning is read by block_alert::manage::GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            excep::set_strMiscWarning( _("Warning: This version is obsolete, upgrade required!") );
        }
    }

    std::string strCmd = map_arg::GetArg("-blocknotify", "");
    if (!fIsInitialDownload && !strCmd.empty()) {
        boost::replace_all(strCmd, "%s", block_info::hashBestChain.GetHex());
        boost::thread t(cmd::runCommand, strCmd); // thread runs free
    }

    return true;
}

template <typename T>
bool CBlock_impl<T>::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos)
{
    // Check for duplicate
    T hash = CBlockHeader_impl<T>::GetHash();
    if (block_info::mapBlockIndex.count(hash))
        return print::error("AddToBlockIndex() : %s already exists", hash.ToString().substr(0,20).c_str());

    // Construct new block index object
    CBlockIndex *pindexNew = new(std::nothrow) CBlockIndex(nFile, nBlockPos, *this);
    if (! pindexNew)
        return print::error("AddToBlockIndex() : new CBlockIndex failed");

    pindexNew->set_phashBlock(&hash);
    typename std::map<T, CBlockIndex *>::iterator miPrev = block_info::mapBlockIndex.find(CBlockHeader<T>::hashPrevBlock);
    if (miPrev != block_info::mapBlockIndex.end()) {
        pindexNew->set_pprev((*miPrev).second);
        pindexNew->set_nHeight(pindexNew->get_pprev()->get_nHeight() + 1);
    }

    // ppcoin: compute chain trust score
    pindexNew->set_nChainTrust((pindexNew->get_pprev() ? pindexNew->get_pprev()->get_nChainTrust() : 0) + pindexNew->GetBlockTrust());

    // ppcoin: compute stake entropy bit for stake modifier
    if (! pindexNew->SetStakeEntropyBit(GetStakeEntropyBit(pindexNew->get_nHeight())))
        return print::error("AddToBlockIndex() : SetStakeEntropyBit() failed");

    // ppcoin: record proof-of-stake hash value
    if (pindexNew->IsProofOfStake()) {
        if (! block_process::mapProofOfStake.count(hash))
            return print::error("AddToBlockIndex() : hashProofOfStake not found in map");
        pindexNew->set_hashProofOfStake(block_process::mapProofOfStake[hash]);
    }

    // ppcoin: compute stake modifier
    uint64_t nStakeModifier = 0;
    bool fGeneratedStakeModifier = false;
    if (! bitkernel::ComputeNextStakeModifier(pindexNew, nStakeModifier, fGeneratedStakeModifier))
        return print::error("AddToBlockIndex() : bitkernel::ComputeNextStakeModifier() failed");

    pindexNew->SetStakeModifier(nStakeModifier, fGeneratedStakeModifier);
    pindexNew->set_nStakeModifierChecksum(bitkernel::GetStakeModifierChecksum(pindexNew));
    if (! bitkernel::CheckStakeModifierCheckpoints(pindexNew->get_nHeight(), pindexNew->get_nStakeModifierChecksum()))
        return print::error("AddToBlockIndex() : Rejected by stake modifier checkpoint height=%d, modifier=0x%016" PRIx64, pindexNew->get_nHeight(), nStakeModifier);

    // Add to block_info::mapBlockIndex
    typename std::map<T, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    if (pindexNew->IsProofOfStake())
        block_info::setStakeSeen.insert(std::make_pair(pindexNew->get_prevoutStake(), pindexNew->get_nStakeTime()));
    pindexNew->set_phashBlock(&((*mi).first));

    // Write to disk block index
    CTxDB txdb;
    if (! txdb.TxnBegin()) return false;
    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
    if (! txdb.TxnCommit()) return false;

    LOCK(block_process::cs_main);

    // New best
    if (pindexNew->get_nChainTrust() > block_info::nBestChainTrust) {
        if (! SetBestChain(txdb, pindexNew)) return false;
    }
    if (pindexNew == block_info::pindexBest) {
        // Notify UI to display prev block's coinbase if it was ours
        static T hashPrevBestCoinBase;
        block_notify::UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = Merkle_t::vtx[0].GetHash();
    }

    static int8_t counter = 0;
    if( (++counter & 0x0F) == 0 || !block_notify::IsInitialBlockDownload()) // repaint every 16 blocks if not in initial block download
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
    if (Merkle_t::vtx.empty() || Merkle_t::vtx.size() > block_param::MAX_BLOCK_SIZE || ::GetSerializeSize(*this) > block_param::MAX_BLOCK_SIZE)
        return DoS(100, print::error("CheckBlock() : size limits failed"));

    bool fProofOfStake = IsProofOfStake();

    // First transaction must be coinbase, the rest must not be
    if (! Merkle_t::vtx[0].IsCoinBase())
        return DoS(100, print::error("CheckBlock() : first tx is not coinbase"));
    if (! Merkle_t::vtx[0].CheckTransaction())
        return DoS(Merkle_t::vtx[0].nDoS, print::error("CheckBlock() : CheckTransaction failed on coinbase"));

    uniqueTx.insert(Merkle_t::vtx[0].GetHash());
    nSigOps += Merkle_t::vtx[0].GetLegacySigOpCount();
    if (fProofOfStake) {
        // Proof-of-STake related checkings. Note that we know here that 1st transactions is coinstake. We don't need
        // check the type of 1st transaction because it's performed earlier by IsProofOfStake()
        // note: nNonce must be zero for proof-of-stake blocks
        if (CBlockHeader<T>::nNonce != 0)
            return DoS(100, print::error("CheckBlock() : non-zero nonce in proof-of-stake block"));

        // Coinbase output should be empty if proof-of-stake block
        if (Merkle_t::vtx[0].get_vout().size() != 1 || !Merkle_t::vtx[0].get_vout(0).IsEmpty())
            return DoS(100, print::error("CheckBlock() : coinbase output not empty for proof-of-stake block"));

        // Check coinstake timestamp
        if (CBlockHeader_impl<T>::GetBlockTime() != (int64_t)Merkle_t::vtx[1].get_nTime())
            return DoS(50, print::error("CheckBlock() : coinstake timestamp violation nTimeBlock=%" PRId64 " nTimeTx=%u", CBlockHeader_impl<T>::GetBlockTime(), Merkle_t::vtx[1].get_nTime()));

        // ppcoin: check proof-of-stake block signature
        if (fCheckSig && !CheckBlockSignature())
            return DoS(100, print::error("CheckBlock() : bad proof-of-stake block signature"));

        if (! Merkle_t::vtx[1].CheckTransaction())
            return DoS(Merkle_t::vtx[1].nDoS, print::error("CheckBlock() : CheckTransaction failed on coinstake"));

        uniqueTx.insert(Merkle_t::vtx[1].GetHash());
        nSigOps += Merkle_t::vtx[1].GetLegacySigOpCount();
    } else {
        // Check proof of work matches claimed amount
        if (fCheckPOW && !diff::check::CheckProofOfWork(CBlockHeader_impl<T>::GetHash(), CBlockHeader<T>::nBits))
            return DoS(50, print::error("CheckBlock() : proof of work failed"));

        // Check timestamp
        if (CBlockHeader_impl<T>::GetBlockTime() > block_check::manage::FutureDrift(bitsystem::GetAdjustedTime()))
            return print::error("CheckBlock() : block timestamp too far in the future");

        // Check coinbase timestamp
        if (CBlockHeader_impl<T>::GetBlockTime() < block_check::manage::PastDrift((int64_t)Merkle_t::vtx[0].get_nTime()))
            return DoS(50, print::error("CheckBlock() : coinbase timestamp is too late"));
    }

    // Iterate all transactions starting from second for proof-of-stake block or first for proof-of-work block
    for (unsigned int i = fProofOfStake ? 2 : 1; i < Merkle_t::vtx.size(); ++i) {
        const CTransaction &tx = Merkle_t::vtx[i];

        // Reject coinbase transactions at non-zero index
        if (tx.IsCoinBase())
            return DoS(100, print::error("CheckBlock() : coinbase at wrong index"));

        // Reject coinstake transactions at index != 1
        if (tx.IsCoinStake())
            return DoS(100, print::error("CheckBlock() : coinstake at wrong index"));

        // Check transaction timestamp
        if (CBlockHeader_impl<T>::GetBlockTime() < (int64_t)tx.get_nTime())
            return DoS(50, print::error("CheckBlock() : block timestamp earlier than transaction timestamp"));

        // Check transaction consistency
        if (! tx.CheckTransaction())
            return DoS(tx.nDoS, print::error("CheckBlock() : CheckTransaction failed"));

        // Add transaction hash into list of unique transaction IDs
        uniqueTx.insert(tx.GetHash());

        // Calculate sigops count
        nSigOps += tx.GetLegacySigOpCount();
    }

    // Check for duplicate txids. This is caught by ConnectInputs(),
    // but catching it earlier avoids a potential DoS attack:
    if (uniqueTx.size() != Merkle_t::vtx.size())
        return DoS(100, print::error("CheckBlock() : duplicate transaction"));

    // Reject block if validation would consume too much resources.
    if (nSigOps > block_param::MAX_BLOCK_SIGOPS)
        return DoS(100, print::error("CheckBlock() : out-of-bounds SigOpCount"));

    // Check merkle root
    if (fCheckMerkleRoot && CBlockHeader<T>::hashMerkleRoot != Merkle_t::BuildMerkleTree())
        return DoS(100, print::error("CheckBlock() : hashMerkleRoot mismatch"));

    return true;
}

template <typename T>
bool CBlock_impl<T>::AcceptBlock()
{
    // Check for duplicate
    T hash = CBlockHeader_impl<T>::GetHash();
    if (block_info::mapBlockIndex.count(hash))
        return print::error("CBlock::AcceptBlock() : block already in block_info::mapBlockIndex");

    // Get prev block index
    typename std::map<T, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(CBlockHeader<T>::hashPrevBlock);
    if (mi == block_info::mapBlockIndex.end())
        return DoS(10, print::error("CBlock::AcceptBlock() : prev block not found"));

    CBlockIndex *pindexPrev = (*mi).second;
    int nHeight = pindexPrev->get_nHeight() + 1;

    // Check proof-of-work or proof-of-stake
    if (CBlockHeader<T>::nBits != diff::spacing::GetNextTargetRequired(pindexPrev, IsProofOfStake()))
        return DoS(100, print::error("CBlock::AcceptBlock() : incorrect %s", IsProofOfWork() ? "proof-of-work" : "proof-of-stake"));

    int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();
    int nMaxOffset = (args_bool::fTestNet || pindexPrev->get_nTime() < timestamps::BLOCKS_ADMIT_HOURS_SWITCH_TIME) ?
        block_transaction::DONOT_ACCEPT_BLOCKS_ADMIT_HOURS_TESTNET * util::nOneHour:
        block_transaction::DONOT_ACCEPT_BLOCKS_ADMIT_HOURS * util::nOneHour;

    // Check timestamp against prev
    if (CBlockHeader_impl<T>::GetBlockTime() <= nMedianTimePast || block_check::manage::FutureDrift(CBlockHeader_impl<T>::GetBlockTime()) < pindexPrev->GetBlockTime())
        return print::error("CBlock::AcceptBlock() : block's timestamp is too early");

    // Don't accept blocks with future timestamps
    if (pindexPrev->get_nHeight() > 1 && nMedianTimePast + nMaxOffset < CBlockHeader_impl<T>::GetBlockTime()) {
        print::error((std::string("CBlock::AcceptBlock() : block's timestamp is too far in the future ___ nMedianTimePast：")
                     + std::to_string(nMedianTimePast) + " nMaxOffset：" + std::to_string(nMaxOffset) + " GetBlockTime()："
                     + std::to_string(CBlockHeader_impl<T>::GetBlockTime()) + " nHeight：" + std::to_string(pindexPrev->get_nHeight())).c_str());
    }

    // Check that all transactions are finalized
    for(const CTransaction &tx: Merkle_t::vtx) {
        if (! tx.IsFinal(nHeight, CBlockHeader_impl<T>::GetBlockTime()))
            return DoS(10, print::error("CBlock::AcceptBlock() : contains a non-final transaction"));
    }

    // Check that the block chain matches the known block chain up to a checkpoint
    if (! Checkpoints::manage::CheckHardened(nHeight, hash))
        return DoS(100, print::error("CBlock::AcceptBlock() : rejected by hardened checkpoint lock-in at %d", nHeight));

    bool cpSatisfies = Checkpoints::manage::CheckSync(hash, pindexPrev);

    // Check that the block satisfies synchronized checkpoint
    if (Checkpoints::CheckpointsMode == Checkpoints::STRICT && !cpSatisfies)
        return print::error("CBlock::AcceptBlock() : rejected by synchronized checkpoint");
    if (Checkpoints::CheckpointsMode == Checkpoints::ADVISORY && !cpSatisfies)
        excep::set_strMiscWarning( _("WARNING: syncronized checkpoint violation detected, but skipped!") );

    // Enforce rule that the coinbase starts with serialized block height
    CScript expect = CScript() << nHeight;
    if (Merkle_t::vtx[0].get_vin(0).get_scriptSig().size() < expect.size() || !std::equal(expect.begin(), expect.end(), Merkle_t::vtx[0].get_vin(0).get_scriptSig().begin()))
        return DoS(100, print::error("CBlock::AcceptBlock() : block height mismatch in coinbase"));

    // Write block to history file
    if (! file_open::CheckDiskSpace(::GetSerializeSize(*this)))
        return print::error("CBlock::AcceptBlock() : out of disk space");

    unsigned int nFile = std::numeric_limits<unsigned int>::max();
    unsigned int nBlockPos = 0;
    if (! WriteToDisk(nFile, nBlockPos))
        return print::error("CBlock::AcceptBlock() : WriteToDisk failed");
    if (! AddToBlockIndex(nFile, nBlockPos))
        return print::error("CBlock::AcceptBlock() : AddToBlockIndex failed");

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
        printf("block %s age total nCoinDays=%" PRId64 "\n", strCoinName, nCoinAge);

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
        return key.Verify(CBlockHeader_impl<T>::GetHash(), vchBlockSig);
    }

    return false;
}

// Called from inside SetBestChain: attaches a block to the new best chain being built
template <typename T>
bool CBlock_impl<T>::SetBestChainInner(CTxDB &txdb, CBlockIndex *pindexNew)
{
    T hash = CBlockHeader_impl<T>::GetHash();

    // Adding to current best branch
    if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash)) {
        txdb.TxnAbort();
        block_check::manage::InvalidChainFound(pindexNew);
        return false;
    }
    if (! txdb.TxnCommit())
        return print::error("SetBestChain() : TxnCommit failed");

    // Add to current best branch
    pindexNew->set_pprev()->set_pnext(pindexNew);

    // Delete redundant memory transactions
    for(CTransaction &tx: this->vtx)
        CTxMemPool::mempool.remove(tx);

    return true;
}

template<typename T>
bool CBlock_impl<T>::WriteToDisk(unsigned int &nFileRet, unsigned int &nBlockPosRet) {
    // Open history file to append
    CAutoFile fileout = CAutoFile(file_open::AppendBlockFile(nFileRet), SER_DISK, version::CLIENT_VERSION);
    if (! fileout) return print::error("CBlock::WriteToDisk() : file_open::AppendBlockFile failed");
    // Write index header
    unsigned int nSize = fileout.GetSerializeSize(*this);
    fileout << FLATDATA(block_info::gpchMessageStart) << nSize;
    // Write block
    long fileOutPos = ::ftell(fileout);
    if (fileOutPos < 0) return print::error("CBlock::WriteToDisk() : ftell failed");
    nBlockPosRet = fileOutPos;
    fileout << *this;
    // Flush stdio buffers and commit to disk before returning
    fflush(fileout);
    if (!block_notify::IsInitialBlockDownload() || (block_info::nBestHeight+1)%500==0)
        iofs::FileCommit(fileout);
    return true;
}

template <typename T>
bool CBlock_impl<T>::ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions/*=true*/) {
    SetNull();
    // Open history file to read
    CAutoFile filein = CAutoFile(file_open::OpenBlockFile(nFile, nBlockPos, "rb"), SER_DISK, version::CLIENT_VERSION);
    if (! filein) return print::error("CBlock::ReadFromDisk() : file_open::OpenBlockFile failed");
    if (! fReadTransactions) filein.AddType(SER_BLOCKHEADERONLY);
    // Read block
    try {
        filein >> *this;
    } catch (const std::exception &) {
        return print::error("%s() : deserialize or I/O error", BOOST_CURRENT_FUNCTION);
    }
    // Check the header
    if (fReadTransactions && IsProofOfWork() && !diff::check::CheckProofOfWork(CBlockHeader_impl<T>::GetHash(), CBlockHeader<T>::nBits))
        return print::error("CBlock::ReadFromDisk() : errors in block header");
    return true;
}

template <typename T>
void CBlock_impl<T>::print() const {
    printf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%" PRIszu ", vchBlockSig=%s)\n",
        CBlockHeader_impl<T>::GetHash().ToString().c_str(),
        CBlockHeader<T>::nVersion,
        CBlockHeader<T>::hashPrevBlock.ToString().c_str(),
        CBlockHeader<T>::hashMerkleRoot.ToString().c_str(),
        CBlockHeader<T>::nTime, CBlockHeader<T>::nBits, CBlockHeader<T>::nNonce,
        Merkle_t::vtx.size(),
        util::HexStr(vchBlockSig.begin(), vchBlockSig.end()).c_str());
    for (unsigned int i=0; i<this->vtx.size(); ++i) {
        printf("  ");
        Merkle_t::vtx[i].print();
    }
    printf("  vMerkleTree: ");
    for (unsigned int i=0; i<Merkle_t::vMerkleTree.size(); ++i)
        printf("%s ", Merkle_t::vMerkleTree[i].ToString().substr(0,10).c_str());
    printf("\n");
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
            printf("GetBlockTrust(Return 1/3 of score) nPoWCount %d\n", nPoWCount);
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
            printf("GetBlockTrust(nPoWTrust + 2/3 of previous block) nPosCount %d\n", nPoSCount);
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
template class CBlockHeader_impl<uint256>;
template class CBlock_impl<uint256>;
template class CBlockIndex_impl<uint256>;
