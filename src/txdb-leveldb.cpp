// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include <map>
#include <boost/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <leveldb/env.h>
#include <leveldb/cache.h>
#include <leveldb/filter_policy.h>
#include <memenv/memenv.h>
#include <kernel.h>
#include <checkpoints.h>
#include <txdb.h>
#include <util.h>
#include <main.h>
#include <util/logging.h>
#include <file_operate/iofs.h>
#include <sync/sync.h>
#include <debugcs/debugcs.h>

#ifdef BLK_SQL_MODE
CTxDBHybrid::CTxDBHybrid(const char *pszMode) : sqldb(CSqliteDBEnv::getname_blkindexsql(), pszMode) {}
#else
CTxDBHybrid::CTxDBHybrid(const char *pszMode) : CLevelDB(CLevelDBEnv::getname_mainchain(), pszMode) {}
#endif
CTxDBHybrid::~CTxDBHybrid() {}


static void oldblockindex_remove(bool fRemoveOld) {
    fs::path directory = iofs::GetDataDir() / "txleveldb";
    if (fRemoveOld) {
        fs::remove_all(directory); // remove directory
        unsigned int nFile = 1;
        for (;;) {
            fs::path strBlockFile = iofs::GetDataDir() / tfm::format("blk%04u.dat", nFile);

            // Break if no such file
            if (! fs::exists(strBlockFile)) {
                break;
            }

            fs::remove(strBlockFile);
            ++nFile;
        }
    }
}

// Note(pszMode): fReadOnly == false
template <typename HASH>
void CTxDB_impl<HASH>::init_blockindex(const char *pszMode, bool fRemoveOld /*= false*/) {
    bool fCreate = ::strchr(pszMode, 'c');
    if (Exists(std::string("version"))) {
        int nVersion;
        ReadVersion(nVersion);
        logging::LogPrintf("Transaction index version is %d\n", nVersion);

        if (nVersion < version::DATABASE_VERSION) {
            logging::LogPrintf("Required index version is %d, removing old database\n", version::DATABASE_VERSION);

            // Leveldb instance destruction
            // Note: activeBatch is nullptr.
            // Remove directory and create new database.
            if(! CLevelDBEnv::get_instance().restart(iofs::GetDataDir(), fRemoveOld, oldblockindex_remove)) {
                throw std::runtime_error("CTxDB_impl::init_blockindex(): error opening database environment");
            }

            WriteVersion(version::DATABASE_VERSION); // Save transaction index version
        }
    } else if (fCreate) {
        WriteVersion(version::DATABASE_VERSION);
    }

    logging::LogPrintf("Opened LevelDB successfully\n");
}

// CLevelDB subclasses are created and destroyed VERY OFTEN. That's why we shouldn't treat this as a free operations.
template <typename HASH>
CTxDB_impl<HASH>::CTxDB_impl(const char *pszMode/* ="r+" */) : CTxDBHybrid(pszMode) {
    assert(pszMode);
}

template <typename HASH>
CTxDB_impl<HASH>::~CTxDB_impl() {}

template <typename HASH>
bool CTxDB_impl<HASH>::ReadTxIndex(HASH hash, CTxIndex &txindex)
{
    assert(!args_bool::fClient);

    txindex.SetNull();
    return Read(std::make_pair(std::string("tx"), hash), txindex);
}

template <typename HASH>
bool CTxDB_impl<HASH>::UpdateTxIndex(HASH hash, const CTxIndex &txindex)
{
    assert(!args_bool::fClient);
    return Write(std::make_pair(std::string("tx"), hash), txindex);
}

template <typename HASH>
bool CTxDB_impl<HASH>::AddTxIndex(const CTransaction_impl<HASH> &tx, const CDiskTxPos &pos, int nHeight)
{
    assert(!args_bool::fClient);

    // Add to tx index
    HASH hash = tx.GetHash();
    CTxIndex txindex(pos, tx.get_vout().size());
    return Write(std::make_pair(std::string("tx"), hash), txindex);
}

template <typename HASH>
bool CTxDB_impl<HASH>::EraseTxIndex(const CTransaction_impl<HASH> &tx)
{
    assert(!args_bool::fClient);
    HASH hash = tx.GetHash();

    return Erase(std::make_pair(std::string("tx"), hash));
}

template <typename HASH>
bool CTxDB_impl<HASH>::ContainsTx(HASH hash)
{
    assert(!args_bool::fClient);
    return Exists(std::make_pair(std::string("tx"), hash));
}

template <typename HASH>
bool CTxDB_impl<HASH>::ReadDiskTx(HASH hash, CTransaction_impl<HASH> &tx, CTxIndex &txindex)
{
    assert(!args_bool::fClient);
    tx.SetNull();
    if (!ReadTxIndex(hash, txindex)) {
        return false;
    }

    return (tx.ReadFromDisk(txindex.get_pos()));
}

template <typename HASH>
bool CTxDB_impl<HASH>::ReadDiskTx(HASH hash, CTransaction_impl<HASH> &tx)
{
    CTxIndex txindex;
    return ReadDiskTx(hash, tx, txindex);
}

template <typename HASH>
bool CTxDB_impl<HASH>::ReadDiskTx(COutPoint_impl<HASH> outpoint, CTransaction_impl<HASH> &tx, CTxIndex &txindex)
{
    return ReadDiskTx(outpoint.get_hash(), tx, txindex);
}

template <typename HASH>
bool CTxDB_impl<HASH>::ReadDiskTx(COutPoint_impl<HASH> outpoint, CTransaction_impl<HASH> &tx)
{
    CTxIndex txindex;
    return ReadDiskTx(outpoint.get_hash(), tx, txindex);
}

template <typename HASH>
bool CTxDB_impl<HASH>::WriteBlockIndex(const CDiskBlockIndex &blockindex)
{
    return Write(std::make_pair(std::string("blockindex"), blockindex.GetBlockHash()), blockindex);
}

template <typename HASH>
bool CTxDB_impl<HASH>::ReadHashBestChain(HASH &hashBestChain)
{
    return Read(std::string("hashBestChain"), hashBestChain);
}

template <typename HASH>
bool CTxDB_impl<HASH>::WriteHashBestChain(HASH hashBestChain)
{
    //debugcs::instance() << "CTxDB_impl called WriteHashBestChain hash: " << hashBestChain.ToString() << debugcs::endl();
    return Write(std::string("hashBestChain"), hashBestChain);
}

template <typename HASH>
bool CTxDB_impl<HASH>::ReadBestInvalidTrust(CBigNum &bnBestInvalidTrust)
{
    return Read(std::string("bnBestInvalidTrust"), bnBestInvalidTrust);
}

template <typename HASH>
bool CTxDB_impl<HASH>::WriteBestInvalidTrust(CBigNum bnBestInvalidTrust)
{
    return Write(std::string("bnBestInvalidTrust"), bnBestInvalidTrust);
}

template <typename HASH>
bool CTxDB_impl<HASH>::ReadSyncCheckpoint(HASH &hashCheckpoint)
{
    return Read(std::string("hashSyncCheckpoint"), hashCheckpoint);
}

template <typename HASH>
bool CTxDB_impl<HASH>::WriteSyncCheckpoint(HASH hashCheckpoint)
{
    return Write(std::string("hashSyncCheckpoint"), hashCheckpoint);
}

template <typename HASH>
bool CTxDB_impl<HASH>::ReadCheckpointPubKey(std::string &strPubKey)
{
    return Read(std::string("strCheckpointPubKey"), strPubKey);
}

template <typename HASH>
bool CTxDB_impl<HASH>::WriteCheckpointPubKey(const std::string &strPubKey)
{
    return Write(std::string("strCheckpointPubKey"), strPubKey);
}

template <typename HASH>
bool CTxDB_impl<HASH>::ReadModifierUpgradeTime(unsigned int &nUpgradeTime)
{
    return Read(std::string("nUpgradeTime"), nUpgradeTime);
}

template <typename HASH>
bool CTxDB_impl<HASH>::WriteModifierUpgradeTime(const unsigned int &nUpgradeTime)
{
    return Write(std::string("nUpgradeTime"), nUpgradeTime);
}

template <typename HASH>
static CBlockIndex_impl<HASH> *InsertBlockIndex(const HASH &hash, std::map<HASH, CBlockIndex_impl<HASH> *> &mapBlockIndex) {
    if (hash == 0)
        return nullptr;

    // Return existing
    typename std::map<HASH, CBlockIndex_impl<HASH> *>::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex_impl<HASH> *pindexNew = new(std::nothrow) CBlockIndex_impl<HASH>;
    if (! pindexNew)
        throw std::runtime_error("LoadBlockIndex() : CBlockIndex failed to allocate memory");

    mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->set_phashBlock(&((*mi).first));

    return pindexNew;
}

template <typename HASH>
bool CTxDB_impl<HASH>::LoadBlockIndex(
        std::map<HASH, CBlockIndex_impl<HASH> *> &mapBlockIndex,
        std::set<std::pair<COutPoint_impl<HASH>, unsigned int>> &setStakeSeen,
        CBlockIndex_impl<HASH> *&pindexGenesisBlock,
        HASH &hashBestChain,
        int &nBestHeight,
        CBlockIndex_impl<HASH> *&pindexBest,
        HASH &nBestInvalidTrust,
        HASH &nBestChainTrust)
{
    if (mapBlockIndex.size() > 0) {
        // Already loaded once in this session. It can happen during migration from BDB.
        return true;
    }

    // The block index is an in-memory structure that maps hashes to on-disk
    // locations where the contents of the block can be found. Here, we scan it
    // out of the DB and into mapBlockIndex.

#ifdef BLK_SQL_MODE

    // Seek to start key.
    IDB::DbIterator ite = this->GetIteCursor(std::string("%blockindex%"));

    // Now read each entry.
    int ret;
    std::vector<char> vchKey;
    CDBStream ssKey(&vchKey);
    std::vector<char> vchValue;
    CDBStream ssValue(&vchValue, 10000);
    while((ret=CSqliteDB::ReadAtCursor(ite, ssKey, ssValue))!=DB_NOTFOUND)
    {
        if(ret>0)
            return logging::error("LoadBlockIndex() : sql read failure");

        // Unpack keys and values.
        std::string strType;
        ::Unserialize(ssKey, strType);

        // Did we reach the end of the data to read?
        if (args_bool::fRequestShutdown || strType != "blockindex") {
            break;
        }

        CDiskBlockIndex_impl<HASH> diskindex;
        ::Unserialize(ssValue, diskindex);

        HASH blockHash = diskindex.GetBlockHash();
        //debugcs::instance() << "CTxDB_impl ReadAtCursor HASH: " << blockHash.ToString().c_str() << debugcs::endl();

        // Construct block index object
        CBlockIndex_impl<HASH> *pindexNew = InsertBlockIndex(blockHash, mapBlockIndex);
        pindexNew->set_pprev(InsertBlockIndex(diskindex.get_hashPrev(), mapBlockIndex));
        pindexNew->set_pnext(InsertBlockIndex(diskindex.get_hashNext(), mapBlockIndex));
        pindexNew->set_nFile(diskindex.get_nFile());
        pindexNew->set_nBlockPos(diskindex.get_nBlockPos());
        pindexNew->set_nHeight(diskindex.get_nHeight());
        pindexNew->set_nMint(diskindex.get_nMint());
        pindexNew->set_nMoneySupply(diskindex.get_nMoneySupply());
        pindexNew->set_nFlags(diskindex.get_nFlags());
        pindexNew->set_nStakeModifier(diskindex.get_nStakeModifier());
        pindexNew->set_prevoutStake(diskindex.get_prevoutStake());
        pindexNew->set_nStakeTime(diskindex.get_nStakeTime());
        pindexNew->set_hashProofOfStake(diskindex.get_hashProofOfStake());
        pindexNew->set_nVersion(diskindex.get_nVersion());
        pindexNew->set_hashMerkleRoot(diskindex.get_hashMerkleRoot());
        pindexNew->set_nTime(diskindex.get_nTime());
        pindexNew->set_nBits(diskindex.get_nBits());
        pindexNew->set_nNonce(diskindex.get_nNonce());
        pindexNew->set_hashPrevBlock(diskindex.get_hashPrev()); // fixed: prevHash

        // Watch for genesis block
        if (pindexGenesisBlock == nullptr && blockHash == (!args_bool::fTestNet ? block_params::hashGenesisBlock : block_params::hashGenesisBlockTestNet)) {
            pindexGenesisBlock = pindexNew;
        }

        if (! pindexNew->CheckIndex()) {
            return logging::error("LoadBlockIndex() : CheckIndex failed at %d", pindexNew->get_nHeight());
        }

        // ppcoin: build setStakeSeen
        if (pindexNew->IsProofOfStake()) {
            setStakeSeen.insert(std::make_pair(pindexNew->get_prevoutStake(), pindexNew->get_nStakeTime()));
        }
    }

#else

    // Seek to start key.
    if(! this->seek(std::string("blockindex"), HASH(0))) {
        return logging::error("LoadBlockIndex() Error: memory allocate failure.");
    }

    // Now read each entry.
    for(const_iterator iterator=this->begin(); iterator!=this->end(); ++iterator)
    {
        // Unpack keys and values.
        CDBStream ssKey(const_cast<char *>(iterator->key().data()), iterator->key().size());
        CDBStream ssValue(const_cast<char *>(iterator->value().data()), iterator->value().size());
        std::string strType;
        ::Unserialize(ssKey, strType);

        // Did we reach the end of the data to read?
        if (args_bool::fRequestShutdown || strType != "blockindex") {
            break;
        }

        CDiskBlockIndex_impl<HASH> diskindex;
        ::Unserialize(ssValue, diskindex);

        HASH blockHash = diskindex.GetBlockHash();

        // Construct block index object
        CBlockIndex_impl<HASH> *pindexNew = InsertBlockIndex(blockHash, mapBlockIndex);
        pindexNew->set_pprev(InsertBlockIndex(diskindex.get_hashPrev(), mapBlockIndex));
        pindexNew->set_pnext(InsertBlockIndex(diskindex.get_hashNext(), mapBlockIndex));
        pindexNew->set_nFile(diskindex.get_nFile());
        pindexNew->set_nBlockPos(diskindex.get_nBlockPos());
        pindexNew->set_nHeight(diskindex.get_nHeight());
        pindexNew->set_nMint(diskindex.get_nMint());
        pindexNew->set_nMoneySupply(diskindex.get_nMoneySupply());
        pindexNew->set_nFlags(diskindex.get_nFlags());
        pindexNew->set_nStakeModifier(diskindex.get_nStakeModifier());
        pindexNew->set_prevoutStake(diskindex.get_prevoutStake());
        pindexNew->set_nStakeTime(diskindex.get_nStakeTime());
        pindexNew->set_hashProofOfStake(diskindex.get_hashProofOfStake());
        pindexNew->set_nVersion(diskindex.get_nVersion());
        pindexNew->set_hashMerkleRoot(diskindex.get_hashMerkleRoot());
        pindexNew->set_nTime(diskindex.get_nTime());
        pindexNew->set_nBits(diskindex.get_nBits());
        pindexNew->set_nNonce(diskindex.get_nNonce());
        pindexNew->set_hashPrevBlock(diskindex.get_hashPrev()); // fixed: prevHash

        // Watch for genesis block
        if (pindexGenesisBlock == nullptr && blockHash == (!args_bool::fTestNet ? block_params::hashGenesisBlock : block_params::hashGenesisBlockTestNet)) {
            pindexGenesisBlock = pindexNew;
        }

        if (! pindexNew->CheckIndex()) {
            return logging::error("LoadBlockIndex() : CheckIndex failed at %d", pindexNew->get_nHeight());
        }

        // ppcoin: build setStakeSeen
        if (pindexNew->IsProofOfStake()) {
            setStakeSeen.insert(std::make_pair(pindexNew->get_prevoutStake(), pindexNew->get_nStakeTime()));
        }
    }

#endif

    if (args_bool::fRequestShutdown) {
        return true;
    }

    // Calculate nChainTrust
    std::vector<std::pair<int, CBlockIndex *> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    for(const std::pair<HASH, CBlockIndex *>&item: mapBlockIndex) {
        CBlockIndex *pindex = item.second;
        vSortedByHeight.push_back(std::make_pair(pindex->get_nHeight(), pindex));
    }

    std::sort(vSortedByHeight.begin(), vSortedByHeight.end());
    for(const std::pair<int, CBlockIndex *>&item: vSortedByHeight) {
        CBlockIndex *pindex = item.second;
        pindex->set_nChainTrust((pindex->get_pprev() ? pindex->get_pprev()->get_nChainTrust() : 0) + pindex->GetBlockTrust());

        // calculate stake modifier checksum
        pindex->set_nStakeModifierChecksum(bitkernel<HASH>::GetStakeModifierChecksum(pindex));
        if (!bitkernel<HASH>::CheckStakeModifierCheckpoints(pindex->get_nHeight(), pindex->get_nStakeModifierChecksum())) {
            return logging::error("CTxDB::LoadBlockIndex() : Failed stake modifier checkpoint height=%d, modifier=0x%016" PRIx64, pindex->get_nHeight(), pindex->get_nStakeModifier());
        }
    }

    //
    // Load hashBestChain pointer to end of best chain
    //
    if (! ReadHashBestChain(hashBestChain)) {
        if (pindexGenesisBlock == nullptr) {
            return true;
        }

        return logging::error("CTxDB::LoadBlockIndex() : hashBestChain not loaded");
    }

    if (! mapBlockIndex.count(hashBestChain)) {
        return logging::error("CTxDB::LoadBlockIndex() : hashBestChain not found in the block index");
    }
    pindexBest = mapBlockIndex[hashBestChain];
    nBestHeight = pindexBest->get_nHeight();
    nBestChainTrust = pindexBest->get_nChainTrust();

    logging::LogPrintf("LoadBlockIndex(): hashBestChain=%s  height=%d  trust=%s  date=%s\n", hashBestChain.ToString().substr(0, 20).c_str(), nBestHeight, CBigNum(nBestChainTrust).ToString().c_str(), util::DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

    // load hashSyncCheckpoint
    if (! ReadSyncCheckpoint(Checkpoints::manage::getHashSyncCheckpoint())) {
        return logging::error("CTxDB::LoadBlockIndex() : hashSyncCheckpoint not loaded");
    }
    logging::LogPrintf("LoadBlockIndex(): synchronized checkpoint %s\n", Checkpoints::manage::getHashSyncCheckpoint().ToString().c_str());

    // Load bnBestInvalidTrust, OK if it doesn't exist
    CBigNum bnBestInvalidTrust;
    ReadBestInvalidTrust(bnBestInvalidTrust);
    nBestInvalidTrust = bnBestInvalidTrust.getuint256();

    // Verify blocks in the best chain
    int nCheckLevel = map_arg::GetArgInt("-checklevel", 1);
    int nCheckDepth = map_arg::GetArgInt("-checkblocks", 2500);
    if (nCheckDepth == 0) {
        nCheckDepth = 1000000000; // suffices until the year 19000
    }
    if (nCheckDepth > nBestHeight) {
        nCheckDepth = nBestHeight;
    }

    logging::LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CBlockIndex *pindexFork = nullptr;
    std::map<std::pair<unsigned int, unsigned int>, CBlockIndex *> mapBlockPos;
    for (CBlockIndex *pindex = pindexBest; pindex && pindex->get_pprev(); pindex = pindex->set_pprev())
    {
        if (args_bool::fRequestShutdown || pindex->get_nHeight() < nBestHeight - nCheckDepth) {
            break;
        }

        CBlock block;
        if (! block.ReadFromDisk(pindex)) {
            return logging::error("LoadBlockIndex() : block.ReadFromDisk failed");
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
                HASH hashTx = tx.GetHash();
                CTxIndex txindex;
                if (ReadTxIndex(hashTx, txindex)) {
                    //
                    // check level 3: checker transaction hashes
                    //
                    if (nCheckLevel>2 || pindex->get_nFile() != txindex.get_pos().get_nFile() || pindex->get_nBlockPos() != txindex.get_pos().get_nBlockPos()) {
                        //
                        // either an error or a duplicate transaction
                        //
                        CTransaction txFound;
                        if (! txFound.ReadFromDisk(txindex.get_pos())) {
                            logging::LogPrintf("LoadBlockIndex() : *** cannot read mislocated transaction %s\n", hashTx.ToString().c_str());
                            pindexFork = pindex->set_pprev();
                        } else {
                            if (txFound.GetHash() != hashTx) { // not a duplicate tx
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
                                    } else if (!txSpend.CheckTransaction()) {
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
            return logging::error("LoadBlockIndex() : block.ReadFromDisk failed");
        }

        CTxDB txdb;
        block.SetBestChain(txdb, pindexFork);
    }

    return true;
}

// multi-threading DB
/*
unsigned int CMTxDB::dbcall(cla_thread<CMTxDB>::thread_data *data) {


    return 0;
}
*/



template class CTxDB_impl<uint256>;
//template class CTxDB_impl<uint65536>;
