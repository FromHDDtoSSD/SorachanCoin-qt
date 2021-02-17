// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef USE_LEVELDB

#include "db.h"
#include "kernel.h"
#include "checkpoints.h"
#include "txdb-bdb.h"
#include "util.h"
#include "main.h"
#include <boost/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#ifndef WIN32
# include "sys/stat.h"
#endif

//
// CTxDB
//
bool CTxDB::ReadTxIndex(uint256 hash, CTxIndex &txindex)
{
    assert(!args_bool::fClient);
    txindex.SetNull();
    return Read(std::make_pair(std::string("tx"), hash), txindex);
}

bool CTxDB::UpdateTxIndex(uint256 hash, const CTxIndex &txindex)
{
    assert(!args_bool::fClient);
    return Write(std::make_pair(std::string("tx"), hash), txindex);
}

bool CTxDB::AddTxIndex(const CTransaction &tx, const CDiskTxPos &pos, int nHeight)
{
    assert(!args_bool::fClient);

    // Add to tx index
    uint256 hash = tx.GetHash();
    CTxIndex txindex(pos, tx.get_vout().size());
    return Write(std::make_pair(std::string("tx"), hash), txindex);
}

bool CTxDB::EraseTxIndex(const CTransaction &tx)
{
    assert(!args_bool::fClient);
    uint256 hash = tx.GetHash();

    return Erase(std::make_pair(std::string("tx"), hash));
}

bool CTxDB::ContainsTx(uint256 hash)
{
    assert(!args_bool::fClient);
    return Exists(std::make_pair(std::string("tx"), hash));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction &tx, CTxIndex &txindex)
{
    assert(!args_bool::fClient);
    tx.SetNull();
    if (! ReadTxIndex(hash, txindex)) {
        return false;
    }
    return (tx.ReadFromDisk(txindex.get_pos()));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction &tx)
{
    CTxIndex txindex;
    return ReadDiskTx(hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction &tx, CTxIndex &txindex)
{
    return ReadDiskTx(outpoint.get_hash(), tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction &tx)
{
    CTxIndex txindex;
    return ReadDiskTx(outpoint.get_hash(), tx, txindex);
}

bool CTxDB::WriteBlockIndex(const CDiskBlockIndex &blockindex)
{
    return Write(std::make_pair(std::string("blockindex"), blockindex.GetBlockHash()), blockindex);
}

bool CTxDB::ReadHashBestChain(uint256 &hashBestChain)
{
    return Read(std::string("hashBestChain"), hashBestChain);
}

bool CTxDB::WriteHashBestChain(uint256 hashBestChain)
{
    return Write(std::string("hashBestChain"), hashBestChain);
}

bool CTxDB::ReadBestInvalidTrust(CBigNum &bnBestInvalidTrust)
{
    return Read(std::string("bnBestInvalidTrust"), bnBestInvalidTrust);
}

bool CTxDB::WriteBestInvalidTrust(CBigNum bnBestInvalidTrust)
{
    return Write(std::string("bnBestInvalidTrust"), bnBestInvalidTrust);
}

bool CTxDB::ReadSyncCheckpoint(uint256 &hashCheckpoint)
{
    return Read(std::string("hashSyncCheckpoint"), hashCheckpoint);
}

bool CTxDB::WriteSyncCheckpoint(uint256 hashCheckpoint)
{
    return Write(std::string("hashSyncCheckpoint"), hashCheckpoint);
}

bool CTxDB::ReadCheckpointPubKey(std::string &strPubKey)
{
    return Read(std::string("strCheckpointPubKey"), strPubKey);
}

bool CTxDB::WriteCheckpointPubKey(const std::string &strPubKey)
{
    return Write(std::string("strCheckpointPubKey"), strPubKey);
}

bool CTxDB::ReadModifierUpgradeTime(unsigned int &nUpgradeTime)
{
    return Read(std::string("nUpgradeTime"), nUpgradeTime);
}

bool CTxDB::WriteModifierUpgradeTime(const unsigned int &nUpgradeTime)
{
    return Write(std::string("nUpgradeTime"), nUpgradeTime);
}

CBlockIndex *CTxDB::InsertBlockIndex(uint256 hash)
{
    if (hash == 0) {
        return nullptr;
    }

    //
    // Return existing
    //
    std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hash);
    if (mi != block_info::mapBlockIndex.end()) {
        return (*mi).second;
    }

    //
    // Create new
    //
    CBlockIndex *pindexNew = new(std::nothrow) CBlockIndex();
    if (! pindexNew) {
        throw std::runtime_error("LoadBlockIndex() : new CBlockIndex failed");
    }

    mi = block_info::mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->set_phashBlock( &((*mi).first) );

    return pindexNew;
}

bool CTxDB::LoadBlockIndex()
{
    if (! LoadBlockIndexGuts()) {
        return false;
    }

    if (args_bool::fRequestShutdown) {
        return true;
    }

    //
    // Calculate nChainTrust
    //
    std::vector<std::pair<int, CBlockIndex *> > vSortedByHeight;
    vSortedByHeight.reserve(block_info::mapBlockIndex.size());
    for(const std::pair<uint256, CBlockIndex *> &item: block_info::mapBlockIndex)
    {
        CBlockIndex *pindex = item.second;
        vSortedByHeight.push_back(std::make_pair(pindex->get_nHeight(), pindex));
    }

    std::sort(vSortedByHeight.begin(), vSortedByHeight.end());
    for(const std::pair<int, CBlockIndex *> &item: vSortedByHeight)
    {
        CBlockIndex *pindex = item.second;
        pindex->set_nChainTrust( (pindex->get_pprev() ? pindex->get_pprev()->get_nChainTrust() : 0) + pindex->GetBlockTrust() );
        //
        // ppcoin: calculate stake modifier checksum
        //
        pindex->set_nStakeModifierChecksum( bitkernel::GetStakeModifierChecksum(pindex) );
        if (! bitkernel::CheckStakeModifierCheckpoints(pindex->get_nHeight(), pindex->get_nStakeModifierChecksum())) {
            return print::error("CTxDB::LoadBlockIndex() : Failed stake modifier checkpoint height=%d, modifier=0x%016" PRIx64, pindex->get_nHeight(), pindex->get_nStakeModifier());
        }
    }

    //
    // Load block_info::hashBestChain pointer to end of best chain
    //
    if (! ReadHashBestChain(block_info::hashBestChain)) {
        if (block_info::pindexGenesisBlock == nullptr) {
            return true;
        }

        return print::error("CTxDB::LoadBlockIndex() : block_info::hashBestChain not loaded");
    }

    if (! block_info::mapBlockIndex.count(block_info::hashBestChain)) {
        return print::error("CTxDB::LoadBlockIndex() : block_info::hashBestChain not found in the block index");
    }

    block_info::pindexBest = block_info::mapBlockIndex[block_info::hashBestChain];
    block_info::nBestHeight = block_info::pindexBest->get_nHeight();
    block_info::nBestChainTrust = block_info::pindexBest->get_nChainTrust();

    logging::LogPrintf("LoadBlockIndex(): hashBestChain=%s  height=%d  trust=%s  date=%s\n", block_info::hashBestChain.ToString().substr(0, 20).c_str(), block_info::nBestHeight, CBigNum(block_info::nBestChainTrust).ToString().c_str(), util::DateTimeStrFormat("%x %H:%M:%S", block_info::pindexBest->GetBlockTime()).c_str());

    //
    // ppcoin: load hashSyncCheckpoint
    //
    if (! ReadSyncCheckpoint(Checkpoints::manage::getHashSyncCheckpoint())) {
        return print::error("CTxDB::LoadBlockIndex() : hashSyncCheckpoint not loaded");
    }

    logging::LogPrintf("LoadBlockIndex(): synchronized checkpoint %s\n", Checkpoints::manage::getHashSyncCheckpoint().ToString().c_str());

    //
    // Load bnBestInvalidTrust, OK if it doesn't exist
    //
    CBigNum bnBestInvalidTrust;
    ReadBestInvalidTrust(bnBestInvalidTrust);
    block_info::nBestInvalidTrust = bnBestInvalidTrust.getuint256();

    //
    // Verify blocks in the best chain
    //
    int nCheckLevel = map_arg::GetArgInt("-checklevel", 1);
    int nCheckDepth = map_arg::GetArgInt("-checkblocks", 2500);
    if (nCheckDepth == 0) {
        nCheckDepth = 1000000000; // suffices until the year 19000
    }
    if (nCheckDepth > block_info::nBestHeight) {
        nCheckDepth = block_info::nBestHeight;
    }

    logging::LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);

    CBlockIndex *pindexFork = nullptr;
    std::map<std::pair<unsigned int, unsigned int>, CBlockIndex *> mapBlockPos;
    for (CBlockIndex *pindex = block_info::pindexBest; pindex && pindex->get_pprev(); pindex = pindex->set_pprev())
    {
        if (args_bool::fRequestShutdown || pindex->get_nHeight() < block_info::nBestHeight - nCheckDepth) {
            break;
        }

        CBlock block;
        if (! block.ReadFromDisk(pindex)) {
            return print::error("LoadBlockIndex() : block.ReadFromDisk failed");
        }

        //
        // check level 1: verify block validity
        // check level 7: verify block signature too
        //
        if (nCheckLevel > 0 && !block.CheckBlock(true, true, (nCheckLevel > 6))) {
            logging::LogPrintf("LoadBlockIndex() : *** found bad block at %d, hash=%s\n", pindex->get_nHeight(), pindex->GetBlockHash().ToString().c_str());
            pindexFork = pindex->set_pprev();
        }

        //
        // check level 2: verify transaction index validity
        //
        if (nCheckLevel > 1) {
            std::pair<unsigned int, unsigned int> pos = std::make_pair(pindex->get_nFile(), pindex->get_nBlockPos());
            mapBlockPos[pos] = pindex;
            for(const CTransaction &tx: block.get_vtx())
            {
                uint256 hashTx = tx.GetHash();
                CTxIndex txindex;
                if (ReadTxIndex(hashTx, txindex)) {
                    //
                    // check level 3: checker transaction hashes
                    //
                    if (nCheckLevel > 2 || pindex->get_nFile() != txindex.get_pos().get_nFile() || pindex->get_nBlockPos() != txindex.get_pos().get_nBlockPos()) {
                        // either an error or a duplicate transaction
                        CTransaction txFound;
                        if (! txFound.ReadFromDisk(txindex.get_pos())) {
                            logging::LogPrintf("LoadBlockIndex() : *** cannot read mislocated transaction %s\n", hashTx.ToString().c_str());
                            pindexFork = pindex->set_pprev();
                        } else {
                            if (txFound.GetHash() != hashTx) {    // not a duplicate tx
                                logging::LogPrintf("LoadBlockIndex(): *** invalid tx position for %s\n", hashTx.ToString().c_str());
                                pindexFork = pindex->set_pprev();
                            }
                        }
                    }

                    //
                    // check level 4: check whether spent txouts were spent within the main chain
                    //
                    unsigned int nOutput = 0;
                    if (nCheckLevel > 3) {
                        for(const CDiskTxPos &txpos: txindex.get_vSpent())
                        {
                            if (! txpos.IsNull()) {
                                std::pair<unsigned int, unsigned int> posFind = std::make_pair(txpos.get_nFile(), txpos.get_nBlockPos());
                                if (! mapBlockPos.count(posFind)) {
                                    logging::LogPrintf("LoadBlockIndex(): *** found bad spend at %d, hashBlock=%s, hashTx=%s\n", pindex->get_nHeight(), pindex->GetBlockHash().ToString().c_str(), hashTx.ToString().c_str());
                                    pindexFork = pindex->set_pprev();
                                }

                                //
                                // check level 6: check whether spent txouts were spent by a valid transaction that consume them
                                //
                                if (nCheckLevel > 5) {
                                    CTransaction txSpend;
                                    if (! txSpend.ReadFromDisk(txpos)) {
                                        logging::LogPrintf("LoadBlockIndex(): *** cannot read spending transaction of %s:%i from disk\n", hashTx.ToString().c_str(), nOutput);
                                        pindexFork = pindex->set_pprev();
                                    } else if (! txSpend.CheckTransaction()) {
                                        logging::LogPrintf("LoadBlockIndex(): *** spending transaction of %s:%i is invalid\n", hashTx.ToString().c_str(), nOutput);
                                        pindexFork = pindex->set_pprev();
                                    } else {
                                        bool fFound = false;
                                        for(const CTxIn &txin: txSpend.get_vin())
                                        {
                                            if (txin.get_prevout().get_hash() == hashTx && txin.get_prevout().get_n() == nOutput) {
                                                fFound = true;
                                            }
                                        }
                                        if (! fFound) {
                                            logging::LogPrintf("LoadBlockIndex(): *** spending transaction of %s:%i does not spend it\n", hashTx.ToString().c_str(), nOutput);
                                            pindexFork = pindex->set_pprev();
                                        }
                                    }
                                }
                            }
                            ++nOutput;
                        }
                    }
                }

                //
                // check level 5: check whether all prevouts are marked spent
                //
                if (nCheckLevel > 4) {
                    for(const CTxIn &txin: tx.get_vin())
                    {
                        CTxIndex txindex;
                        if (ReadTxIndex(txin.get_prevout().get_hash(), txindex)) {
                            if (txindex.get_vSpent().size() - 1 < txin.get_prevout().get_n() || txindex.get_vSpent(txin.get_prevout().get_n()).IsNull()) {
                                logging::LogPrintf("LoadBlockIndex(): *** found unspent prevout %s:%i in %s\n", txin.get_prevout().get_hash().ToString().c_str(), txin.get_prevout().get_n(), hashTx.ToString().c_str());
                                pindexFork = pindex->set_pprev();
                            }
                        }
                    }
                }
            }
        }
    }

    if (pindexFork && !args_bool::fRequestShutdown) {
        //
        // Reorg back to the fork
        //
        logging::LogPrintf("LoadBlockIndex() : *** moving best chain pointer back to block %d\n", pindexFork->get_nHeight());
        CBlock block;
        if (! block.ReadFromDisk(pindexFork)) {
            return print::error("LoadBlockIndex() : block.ReadFromDisk failed");
        }

        CTxDB txdb;
        block.SetBestChain(txdb, pindexFork);
    }

    return true;
}

bool CTxDB::LoadBlockIndexGuts()
{
    // Get database cursor
    Dbc *pcursor = GetCursor();
    if (! pcursor) {
        return false;
    }

    // Load mapBlockIndex
    unsigned int fFlags = DB_SET_RANGE;
    for ( ; ; )
    {
        // Read next record
        CDataStream ssKey(SER_DISK, version::CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE) {
            ssKey << std::make_pair(std::string("blockindex"), uint256(0));
        }

        CDataStream ssValue(SER_DISK, version::CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;

        if (ret == DB_NOTFOUND) {
            break;
        } else if (ret != 0) {
            return false;
        }

        // Unserialize(read)
        try {
            std::string strType;
            ssKey >> strType;
            // logging::LogPrintf("CTxDB::LoadBlockIndexGuts() strType %s\n", strType.c_str());

            if (strType == "blockindex" && !args_bool::fRequestShutdown) {
                CDiskBlockIndex diskindex;
                ssValue >> diskindex;

                uint256 blockHash = diskindex.GetBlockHash();

                // Construct block index object
                CBlockIndex *pindexNew = InsertBlockIndex(blockHash);
                pindexNew->set_pprev( InsertBlockIndex(diskindex.get_hashPrev()) );
                pindexNew->set_pnext( InsertBlockIndex(diskindex.get_hashNext()) );
                pindexNew->set_nFile( diskindex.get_nFile() );
                pindexNew->set_nBlockPos( diskindex.get_nBlockPos() );
                pindexNew->set_nHeight( diskindex.get_nHeight() );
                pindexNew->set_nMint( diskindex.get_nMint() );
                pindexNew->set_nMoneySupply( diskindex.get_nMoneySupply() );
                pindexNew->set_nFlags( diskindex.get_nFlags() );
                pindexNew->set_nStakeModifier( diskindex.get_nStakeModifier() );
                pindexNew->set_prevoutStake( diskindex.get_prevoutStake() );
                pindexNew->set_nStakeTime( diskindex.get_nStakeTime() );
                pindexNew->set_hashProofOfStake( diskindex.get_hashProofOfStake() );
                pindexNew->set_nVersion( diskindex.get_nVersion() );
                pindexNew->set_hashMerkleRoot( diskindex.get_hashMerkleRoot() );
                pindexNew->set_nTime( diskindex.get_nTime() );
                pindexNew->set_nBits( diskindex.get_nBits() );
                pindexNew->set_nNonce( diskindex.get_nNonce() );

                // Watch for genesis block
                if (block_info::pindexGenesisBlock == nullptr && blockHash == (!args_bool::fTestNet ? block_params::hashGenesisBlock : block_params::hashGenesisBlockTestNet)) {
                    block_info::pindexGenesisBlock = pindexNew;
                }

                if (! pindexNew->CheckIndex()) {
                    return print::error("LoadBlockIndex() : CheckIndex failed at %d", pindexNew->get_nHeight());
                }

                // ppcoin: build block_info::setStakeSeen
                if (pindexNew->IsProofOfStake()) {
                    block_info::setStakeSeen.insert(std::make_pair(pindexNew->get_prevoutStake(), pindexNew->get_nStakeTime()));
                }
            } else {
                break; // if shutdown requested or finished loading block index
            }
        } catch (const std::exception &) {
            return print::error("%s() : deserialize error", BOOST_CURRENT_FUNCTION);
        }
    }
    pcursor->close();

    return true;
}

#endif
