// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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
#include "sys/stat.h"
#endif

/*
void MakeMockTXDB() {
    //
    // In practice this won't do anything because the test framework always initializes
    // an in-memory BDB via CDBEnv::bitdb.MakeMock() first, as we use BDB for addresses and wallets.
    //
    if (! CDBEnv::bitdb.IsMock()) {
        CDBEnv::bitdb.MakeMock();
    }
}
*/

//
// CTxDB
//
bool CTxDB::ReadTxIndex(uint256 hash, CTxIndex &txindex)
{
    assert(! args_bool::fClient);
    txindex.SetNull();
    return Read(std::make_pair(std::string("tx"), hash), txindex);
}

bool CTxDB::UpdateTxIndex(uint256 hash, const CTxIndex &txindex)
{
    assert(! args_bool::fClient);
    return Write(std::make_pair(std::string("tx"), hash), txindex);
}

bool CTxDB::AddTxIndex(const CTransaction &tx, const CDiskTxPos &pos, int nHeight)
{
    assert(! args_bool::fClient);

    // Add to tx index
    uint256 hash = tx.GetHash();
    CTxIndex txindex(pos, tx.vout.size());
    return Write(std::make_pair(std::string("tx"), hash), txindex);
}

bool CTxDB::EraseTxIndex(const CTransaction &tx)
{
    assert(! args_bool::fClient);
    uint256 hash = tx.GetHash();

    return Erase(std::make_pair(std::string("tx"), hash));
}

bool CTxDB::ContainsTx(uint256 hash)
{
    assert(! args_bool::fClient);
    return Exists(std::make_pair(std::string("tx"), hash));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction &tx, CTxIndex &txindex)
{
    assert(! args_bool::fClient);
    tx.SetNull();
    if (! ReadTxIndex(hash, txindex)) {
        return false;
    }
    return (tx.ReadFromDisk(txindex.pos));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction &tx)
{
    CTxIndex txindex;
    return ReadDiskTx(hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction &tx, CTxIndex &txindex)
{
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction &tx)
{
    CTxIndex txindex;
    return ReadDiskTx(outpoint.hash, tx, txindex);
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
        return NULL;
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
    pindexNew->phashBlock = &((*mi).first);

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
    BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex *)&item, block_info::mapBlockIndex)
    {
        CBlockIndex *pindex = item.second;
        vSortedByHeight.push_back(std::make_pair(pindex->nHeight, pindex));
    }

    std::sort(vSortedByHeight.begin(), vSortedByHeight.end());
    BOOST_FOREACH(const PAIRTYPE(int, CBlockIndex *)&item, vSortedByHeight)
    {
        CBlockIndex *pindex = item.second;
        pindex->nChainTrust = (pindex->pprev ? pindex->pprev->nChainTrust : 0) + pindex->GetBlockTrust();
        //
        // ppcoin: calculate stake modifier checksum
        //
        pindex->nStakeModifierChecksum = bitkernel::GetStakeModifierChecksum(pindex);
        if (! bitkernel::CheckStakeModifierCheckpoints(pindex->nHeight, pindex->nStakeModifierChecksum)) {
            return print::error("CTxDB::LoadBlockIndex() : Failed stake modifier checkpoint height=%d, modifier=0x%016" PRIx64, pindex->nHeight, pindex->nStakeModifier);
        }
    }

    //
    // Load block_info::hashBestChain pointer to end of best chain
    //
    if (! ReadHashBestChain(block_info::hashBestChain)) {
        if (block_info::pindexGenesisBlock == NULL) {
            return true;
        }

        return print::error("CTxDB::LoadBlockIndex() : block_info::hashBestChain not loaded");
    }

    if (! block_info::mapBlockIndex.count(block_info::hashBestChain)) {
        return print::error("CTxDB::LoadBlockIndex() : block_info::hashBestChain not found in the block index");
    }

    block_info::pindexBest = block_info::mapBlockIndex[block_info::hashBestChain];
    block_info::nBestHeight = block_info::pindexBest->nHeight;
    block_info::nBestChainTrust = block_info::pindexBest->nChainTrust;

    printf("LoadBlockIndex(): hashBestChain=%s  height=%d  trust=%s  date=%s\n", block_info::hashBestChain.ToString().substr(0,20).c_str(), block_info::nBestHeight, CBigNum(block_info::nBestChainTrust).ToString().c_str(), util::DateTimeStrFormat("%x %H:%M:%S", block_info::pindexBest->GetBlockTime()).c_str());

    //
    // ppcoin: load hashSyncCheckpoint
    //
    if (! ReadSyncCheckpoint(Checkpoints::manage::getHashSyncCheckpoint())) {
        return print::error("CTxDB::LoadBlockIndex() : hashSyncCheckpoint not loaded");
    }

    printf("LoadBlockIndex(): synchronized checkpoint %s\n", Checkpoints::manage::getHashSyncCheckpoint().ToString().c_str());

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
    int nCheckDepth = map_arg::GetArgInt( "-checkblocks", 2500);
    if (nCheckDepth == 0) {
        nCheckDepth = 1000000000; // suffices until the year 19000
    }
    if (nCheckDepth > block_info::nBestHeight) {
        nCheckDepth = block_info::nBestHeight;
    }

    printf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);

    CBlockIndex *pindexFork = NULL;
    std::map<std::pair<unsigned int, unsigned int>, CBlockIndex *> mapBlockPos;
    for (CBlockIndex *pindex = block_info::pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
    {
        if (args_bool::fRequestShutdown || pindex->nHeight < block_info::nBestHeight-nCheckDepth) {
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
            printf("LoadBlockIndex() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            pindexFork = pindex->pprev;
        }

        //
        // check level 2: verify transaction index validity
        //
        if (nCheckLevel > 1) {
            std::pair<unsigned int, unsigned int> pos = std::make_pair(pindex->nFile, pindex->nBlockPos);
            mapBlockPos[pos] = pindex;
            BOOST_FOREACH(const CTransaction &tx, block.vtx)
            {
                uint256 hashTx = tx.GetHash();
                CTxIndex txindex;
                if (ReadTxIndex(hashTx, txindex)) {
                    //
                    // check level 3: checker transaction hashes
                    //
                    if (nCheckLevel > 2 || pindex->nFile != txindex.pos.nFile || pindex->nBlockPos != txindex.pos.nBlockPos) {
                        // either an error or a duplicate transaction
                        CTransaction txFound;
                        if (! txFound.ReadFromDisk(txindex.pos)) {
                            printf("LoadBlockIndex() : *** cannot read mislocated transaction %s\n", hashTx.ToString().c_str());
                            pindexFork = pindex->pprev;
                        } else {
                            if (txFound.GetHash() != hashTx) {    // not a duplicate tx
                                printf("LoadBlockIndex(): *** invalid tx position for %s\n", hashTx.ToString().c_str());
                                pindexFork = pindex->pprev;
                            }
                        }
                    }

                    //
                    // check level 4: check whether spent txouts were spent within the main chain
                    //
                    unsigned int nOutput = 0;
                    if (nCheckLevel > 3) {
                        BOOST_FOREACH(const CDiskTxPos &txpos, txindex.vSpent)
                        {
                            if (! txpos.IsNull()) {
                                std::pair<unsigned int, unsigned int> posFind = std::make_pair(txpos.nFile, txpos.nBlockPos);
                                if (! mapBlockPos.count(posFind)) {
                                    printf("LoadBlockIndex(): *** found bad spend at %d, hashBlock=%s, hashTx=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str(), hashTx.ToString().c_str());
                                    pindexFork = pindex->pprev;
                                }

                                //
                                // check level 6: check whether spent txouts were spent by a valid transaction that consume them
                                //
                                if (nCheckLevel > 5) {
                                    CTransaction txSpend;
                                    if (! txSpend.ReadFromDisk(txpos)) {
                                        printf("LoadBlockIndex(): *** cannot read spending transaction of %s:%i from disk\n", hashTx.ToString().c_str(), nOutput);
                                        pindexFork = pindex->pprev;
                                    } else if (! txSpend.CheckTransaction()) {
                                        printf("LoadBlockIndex(): *** spending transaction of %s:%i is invalid\n", hashTx.ToString().c_str(), nOutput);
                                        pindexFork = pindex->pprev;
                                    } else {
                                        bool fFound = false;
                                        BOOST_FOREACH(const CTxIn &txin, txSpend.vin)
                                        {
                                            if (txin.prevout.hash == hashTx && txin.prevout.n == nOutput) {
                                                fFound = true;
                                            }
                                        }
                                        if (! fFound) {
                                            printf("LoadBlockIndex(): *** spending transaction of %s:%i does not spend it\n", hashTx.ToString().c_str(), nOutput);
                                            pindexFork = pindex->pprev;
                                        }
                                    }
                                }
                            }
                            nOutput++;
                        }
                    }
                }

                //
                // check level 5: check whether all prevouts are marked spent
                //
                if (nCheckLevel > 4) {
                     BOOST_FOREACH(const CTxIn &txin, tx.vin)
                     {
                          CTxIndex txindex;
                          if (ReadTxIndex(txin.prevout.hash, txindex)) {
                              if (txindex.vSpent.size()-1 < txin.prevout.n || txindex.vSpent[txin.prevout.n].IsNull()) {
                                  printf("LoadBlockIndex(): *** found unspent prevout %s:%i in %s\n", txin.prevout.hash.ToString().c_str(), txin.prevout.n, hashTx.ToString().c_str());
                                  pindexFork = pindex->pprev;
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
        printf("LoadBlockIndex() : *** moving best chain pointer back to block %d\n", pindexFork->nHeight);
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
            // printf("CTxDB::LoadBlockIndexGuts() strType %s\n", strType.c_str());

            if (strType == "blockindex" && !args_bool::fRequestShutdown) {
                CDiskBlockIndex diskindex;
                ssValue >> diskindex;

                uint256 blockHash = diskindex.GetBlockHash();

                // Construct block index object
                CBlockIndex* pindexNew = InsertBlockIndex(blockHash);
                pindexNew->pprev          = InsertBlockIndex(diskindex.hashPrev);
                pindexNew->pnext          = InsertBlockIndex(diskindex.hashNext);
                pindexNew->nFile          = diskindex.nFile;
                pindexNew->nBlockPos      = diskindex.nBlockPos;
                pindexNew->nHeight        = diskindex.nHeight;
                pindexNew->nMint          = diskindex.nMint;
                pindexNew->nMoneySupply   = diskindex.nMoneySupply;
                pindexNew->nFlags         = diskindex.nFlags;
                pindexNew->nStakeModifier = diskindex.nStakeModifier;
                pindexNew->prevoutStake   = diskindex.prevoutStake;
                pindexNew->nStakeTime     = diskindex.nStakeTime;
                pindexNew->hashProofOfStake = diskindex.hashProofOfStake;
                pindexNew->nVersion       = diskindex.nVersion;
                pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
                pindexNew->nTime          = diskindex.nTime;
                pindexNew->nBits          = diskindex.nBits;
                pindexNew->nNonce         = diskindex.nNonce;

                // Watch for genesis block
                if (block_info::pindexGenesisBlock == NULL && blockHash == (!args_bool::fTestNet ? block_param::hashGenesisBlock : block_param::hashGenesisBlockTestNet)) {
                    block_info::pindexGenesisBlock = pindexNew;
                }

                if (! pindexNew->CheckIndex()) {
                    return print::error("LoadBlockIndex() : CheckIndex failed at %d", pindexNew->nHeight);
                }

                // ppcoin: build block_info::setStakeSeen
                if (pindexNew->IsProofOfStake()) {
                    block_info::setStakeSeen.insert(std::make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));
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
