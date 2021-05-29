// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <main.h>
#include <wallet.h>
#include <txdb.h>
#include <kernel.h>
#include <checkpoints.h>
#include <block/block_process.h>
#include <miner/diff.h>
#include <const/block_params.h>
#include <block/block_info.h>
#include <block/block_check.h>
#include <util/time.h>

CCriticalSection wallet_process::manage::cs_setpwalletRegistered;

//
// These functions dispatch to one or all registered wallets
//
void wallet_process::manage::RegisterWallet(CWallet *pwalletIn)
{
    {
        LOCK(wallet_process::manage::cs_setpwalletRegistered);
        block_info::setpwalletRegistered.insert(pwalletIn);
    }
}

void wallet_process::manage::UnregisterWallet(CWallet *pwalletIn)
{
    {
        LOCK(wallet_process::manage::cs_setpwalletRegistered);
        block_info::setpwalletRegistered.erase(pwalletIn);
    }
}

// make sure all wallets know about the given transaction, in the given block
void wallet_process::manage::SyncWithWallets(const CTransaction &tx, const CBlock *pblock /*= NULL*/, bool fUpdate/*= false*/, bool fConnect/*= true*/)
{
    if (! fConnect) {
        // wallets need to refund inputs when disconnecting coinstake
        if (tx.IsCoinStake()) {
            for(CWallet *pwallet: block_info::setpwalletRegistered)
            {
                if (pwallet->IsFromMe(tx)) {
                    pwallet->DisableTransaction(tx);
                }
            }
        }
        return;
    }

    for(CWallet *pwallet: block_info::setpwalletRegistered)
    {
        pwallet->AddToWalletIfInvolvingMe(tx, pblock, fUpdate);
    }
}

bool CWalletTx::AcceptWalletTransaction(CTxDB &txdb, bool fCheckInputs)
{
    {
        LOCK(CTxMemPool::mempool.get_cs());

        //
        // Add previous supporting transactions first
        //
        for(CMerkleTx &tx: this->vtxPrev)
        {
            if (!(tx.IsCoinBase() || tx.IsCoinStake())) {
                uint256 hash = tx.GetHash();
                if (!CTxMemPool::mempool.exists(hash) && !txdb.ContainsTx(hash)) {
                    tx.AcceptToMemoryPool(txdb, fCheckInputs);
                }
            }
        }
        return AcceptToMemoryPool(txdb, fCheckInputs);
    }
    return false;
}

bool CWalletTx::AcceptWalletTransaction()
{
    CTxDB txdb("r");
    return AcceptWalletTransaction(txdb);
}

int CTxIndex::GetDepthInMainChain() const noexcept
{
    // Read block header
    CBlock block;
    if (! block.ReadFromDisk(pos.get_nFile(), pos.get_nBlockPos(), false)) {
        return 0;
    }

    // Find the block in the index
    auto mi = block_info::mapBlockIndex.find(block.GetPoHash());
    if (mi == block_info::mapBlockIndex.end()) {
        return 0;
    }

    CBlockIndex *pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain()) {
        return 0;
    }

    return 1 + block_info::nBestHeight - pindex->get_nHeight();
}

//
// Called from inside SetBestChain: attaches a block to the new best chain being built
//
template <typename T>
bool CBlock_impl<T>::SetBestChainInner(CTxDB_impl<T> &txdb, CBlockIndex_impl<T> *pindexNew)
{
    uint256 hash = CBlockHeader_impl<T>::GetHash();
    //debugcs::instance() << "SetBestChainInner hash: " << hash.ToString() << debugcs::endl();

    // Adding to current best branch
    if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash)) {
        txdb.TxnAbort();
        block_check::manage<T>::InvalidChainFound(pindexNew);
        return false;
    }
    if (! txdb.TxnCommit()) {
        return logging::error("SetBestChain() : TxnCommit failed");
    }

    // Add to current best branch
    pindexNew->set_pprev()->set_pnext(pindexNew);

    // Delete redundant memory transactions
    for(CTransaction &tx: this->vtx)
    {
        CTxMemPool::mempool.remove(tx);
    }

    return true;
}

void block_load::UnloadBlockIndex()
{
    block_info::mapBlockIndex.clear();
    block_info::setStakeSeen.clear();
    block_info::pindexGenesisBlock = NULL;
    block_info::nBestHeight = 0;
    block_info::nBestChainTrust = 0;
    block_info::nBestInvalidTrust = 0;
    block_info::hashBestChain = 0;
    block_info::pindexBest = NULL;

}

bool block_load::LoadBlockIndex(bool fAllowNew/*=true*/)    // Call by init.cpp
{
    if (args_bool::fTestNet) {
        block_info::gpchMessageStart[0] = 0xcd;
        block_info::gpchMessageStart[1] = 0xf2;
        block_info::gpchMessageStart[2] = 0xc0;
        block_info::gpchMessageStart[3] = 0xef;

        diff::bnProofOfWorkLimit = diff::testnet::bnProofOfWorkLimit;
        block_check::nStakeMinAge = block_check::testnet::nStakeMinAge;
        block_check::nModifierInterval = block_check::testnet::nModifierInterval;
        block_transaction::nCoinbaseMaturity = block_transaction::testnet::nCoinbaseMaturity;
        block_check::nStakeTargetSpacing = block_check::testnet::nStakeTargetSpacing;
        block_check::nPowTargetSpacing = block_check::testnet::nPowTargetSpacing;
    }

    //
    // Load block index
    //
    CTxDB txdb("cr+");
    if (! txdb.LoadBlockIndex(block_info::mapBlockIndex,
                              block_info::setStakeSeen,
                              block_info::pindexGenesisBlock,
                              block_info::hashBestChain,
                              block_info::nBestHeight,
                              block_info::pindexBest,
                              block_info::nBestInvalidTrust,
                              block_info::nBestChainTrust)) {
        return false;
    }

    //
    // Init with genesis block
    //
    if (block_info::mapBlockIndex.empty()) {
        if (! fAllowNew) {
            return false;
        }

        //
        // Genesis block
        //
        const char *pszTimestamp = block_params::pszTimestamp;

        CTransaction txNew;
        txNew.set_nTime( !args_bool::fTestNet ? block_params::nGenesisTimeMainnet: block_params::nGenesisTimeTestnet );
        txNew.set_vin().resize(1);
        txNew.set_vout().resize(1);
        txNew.set_vin(0).set_scriptSig(CScript() << 0 << CBigNum(42) << bignum_vector((const unsigned char *)pszTimestamp, (const unsigned char *)pszTimestamp + ::strlen(pszTimestamp)));
        txNew.set_vout(0).SetEmpty();

        CBlock block;
        block.set_vtx().push_back(txNew);
        block.set_hashPrevBlock(0);
        block.set_hashMerkleRoot(block.BuildMerkleTree());
        block.set_nVersion(1);
        block.set_nTime(!args_bool::fTestNet ? block_params::nGenesisTimeMainnet: block_params::nGenesisTimeTestnet);
        block.set_nBits(diff::bnProofOfWorkLimit.GetCompact());
        block.set_nNonce(!args_bool::fTestNet ? block_params::nGenesisNonceMainnet : block_params::nGenesisNonceTestnet);

        if (true && (block.GetPoHash() != block_params::hashGenesisBlock)) {
            //
            // This will figure out a valid hash and Nonce if you're creating a different genesis block
            //
            uint256 hashTarget = CBigNum().SetCompact(block.get_nBits()).getuint256();
            while (block.GetPoHash() > hashTarget)
            {
                ++block.set_nNonce();
                if (block.get_nNonce() == 0) {
                    logging::LogPrintf("NONCE WRAPPED, incrementing time");
                    ++block.set_nTime();
                }
            }
        }

        //
        // Genesis check
        //
        block.print();        
        logging::LogPrintf("block.GetHash() == %s\n", block.GetPoHash().ToString().c_str());
        logging::LogPrintf("block.hashMerkleRoot == %s\n", block.get_hashMerkleRoot().ToString().c_str());
        logging::LogPrintf("block.nTime = %u \n", block.get_nTime());
        logging::LogPrintf("block.nNonce = %u \n", block.get_nNonce());

        assert(block.get_hashMerkleRoot() == block_params::hashMerkleRoot);
        assert(block.GetPoHash() == (!args_bool::fTestNet ? block_params::hashGenesisBlock : block_params::hashGenesisBlockTestNet));
        assert(block.CheckBlock());

        //
        // Start new block file
        //
        unsigned int nFile;
        unsigned int nBlockPos;
        if (! block.WriteToDisk(nFile, nBlockPos)) {
            return logging::error("LoadBlockIndex() : writing genesis block to disk failed");
        }
        if (! block.AddToBlockIndex(nFile, nBlockPos)) {
            return logging::error("LoadBlockIndex() : genesis block not accepted");
        }

        // initialize synchronized checkpoint
        if (! Checkpoints::manage::WriteSyncCheckpoint((!args_bool::fTestNet ? block_params::hashGenesisBlock : block_params::hashGenesisBlockTestNet))) {
            return logging::error("LoadBlockIndex() : failed to init sync checkpoint");
        }

        // upgrade time set to zero if txdb initialized
        {
            if (! txdb.WriteModifierUpgradeTime(0)) {
                return logging::error("LoadBlockIndex() : failed to init upgrade info");
            }
            logging::LogPrintf(" Upgrade Info: ModifierUpgradeTime txdb initialization\n");
        }

    }

    {
        CTxDB txdb("r+");

        //
        // if checkpoint master key changed must reset sync-checkpoint
        //
        std::string strPubKey = "";
        if (!txdb.ReadCheckpointPubKey(strPubKey) || strPubKey != CSyncCheckpoint::Get_strMasterPubKey()) {
            //
            // write checkpoint master key to db
            //
            txdb.TxnBegin();
            if (! txdb.WriteCheckpointPubKey(CSyncCheckpoint::Get_strMasterPubKey())) {
                return logging::error("LoadBlockIndex() : failed to write new checkpoint master key to db");
            }
            if (! txdb.TxnCommit()) {
                return logging::error("LoadBlockIndex() : failed to commit new checkpoint master key to db");
            }
            if ((!args_bool::fTestNet) && !Checkpoints::manage::ResetSyncCheckpoint()) {
                return logging::error("LoadBlockIndex() : failed to reset sync-checkpoint");
            }
        }

        //
        // upgrade time set to zero if blocktreedb initialized
        //
        if (txdb.ReadModifierUpgradeTime(bitkernel<uint256>::nModifierUpgradeTime)) {
            if (bitkernel<uint256>::nModifierUpgradeTime) {
                logging::LogPrintf(" Upgrade Info: blocktreedb upgrade detected at timestamp %d\n", bitkernel<uint256>::nModifierUpgradeTime);
            } else {
                logging::LogPrintf(" Upgrade Info: no blocktreedb upgrade detected.\n");
            }
        } else {
            bitkernel<uint256>::nModifierUpgradeTime = bitsystem::GetTime();
            logging::LogPrintf(" Upgrade Info: upgrading blocktreedb at timestamp %u\n", bitkernel<uint256>::nModifierUpgradeTime);
            if (! txdb.WriteModifierUpgradeTime(bitkernel<uint256>::nModifierUpgradeTime)) {
                return logging::error("LoadBlockIndex() : failed to write upgrade info");
            }
        }
    }

    return true;
}

bool block_load::LoadExternalBlockFile(FILE *fileIn)
{
    int64_t nStart = util::GetTimeMillis();

    int nLoaded = 0;
    {
        LOCK(block_process::cs_main);
        try {
            CAutoFile blkdat(fileIn, SER_DISK, version::CLIENT_VERSION);
            unsigned int nPos = 0;
            while (nPos != std::numeric_limits<uint32_t>::max() && blkdat.good() && !args_bool::fRequestShutdown)
            {
                unsigned char pchData[65536];
                do
                {
                    ::fseek(blkdat, nPos, SEEK_SET);
                    size_t nRead = ::fread(pchData, 1, sizeof(pchData), blkdat);
                    if (nRead <= 8) {
                        nPos = std::numeric_limits<uint32_t>::max();
                        break;
                    }

                    void *nFind = ::memchr(pchData, block_info::gpchMessageStart[0], nRead + 1 - sizeof(block_info::gpchMessageStart));
                    if (nFind) {
                        if (::memcmp(nFind, block_info::gpchMessageStart, sizeof(block_info::gpchMessageStart)) == 0 ) {
                            nPos += ((unsigned char *)nFind - pchData) + sizeof(block_info::gpchMessageStart);
                            break;
                        }
                        nPos += ((unsigned char *)nFind - pchData) + 1;
                    } else {
                        nPos += sizeof(pchData) - sizeof(block_info::gpchMessageStart) + 1;
                    }
                } while(! args_bool::fRequestShutdown);

                if (nPos == std::numeric_limits<uint32_t>::max()) {
                    break;
                }

                ::fseek(blkdat, nPos, SEEK_SET);
                unsigned int nSize;
                blkdat >> nSize;
                if (nSize > 0 && nSize <= block_params::MAX_BLOCK_SIZE) {
                    CBlock block;
                    blkdat >> block;
                    if (block_process::manage::ProcessBlock(NULL, &block)) {
                        nLoaded++;
                        nPos += 4 + nSize;
                    }
                }
            }
        } catch (const std::exception &) {
            logging::LogPrintf("%s() : Deserialize or I/O error caught during load\n", BOOST_CURRENT_FUNCTION);
        }
    }

    logging::LogPrintf("Loaded %i blocks from external file in %" PRId64 "ms\n", nLoaded, util::GetTimeMillis() - nStart);
    return nLoaded > 0;
}

//
// main cleanup
// Singleton Class
//
class CMainCleanup
{
private:
    static CMainCleanup instance_of_cmaincleanup;

    CMainCleanup() {}
    ~CMainCleanup() {
        //
        // Thread stop
        //

        //
        // block headers
        //
        auto it1 = block_info::mapBlockIndex.begin();
        for (; it1 != block_info::mapBlockIndex.end(); it1++)
        {
            delete (*it1).second;
        }
        block_info::mapBlockIndex.clear();

        //
        // orphan blocks
        //
        std::map<uint256, CBlock *>::iterator it2 = block_process::mapOrphanBlocks.begin();
        for (; it2 != block_process::mapOrphanBlocks.end(); it2++)
        {
            delete (*it2).second;
        }
        block_process::mapOrphanBlocks.clear();

        // orphan transactions
        // development ...
    }
};
CMainCleanup CMainCleanup::instance_of_cmaincleanup;
