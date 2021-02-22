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

CCriticalSection CMTxDB::csTxdb_write;
template <typename HASH> leveldb::DB *CTxDB_impl<HASH>::txdb = nullptr;

template <typename HASH>
leveldb::Options CTxDB_impl<HASH>::GetOptions()
{
    leveldb::Options options;
    int nCacheSizeMB = map_arg::GetArgInt("-dbcache", 25);

    options.block_cache = leveldb::NewLRUCache(nCacheSizeMB * 1048576);
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);

    return options;
}

template <typename HASH>
void CTxDB_impl<HASH>::init_blockindex(leveldb::Options &options, bool fRemoveOld /* = false */)
{
    // First time init.
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

    fs::create_directory(directory);
    logging::LogPrintf("Opening LevelDB in %s\n", directory.string().c_str());

    leveldb::Status status = leveldb::DB::Open(options, directory.string(), &CTxDB::txdb);
    if (! status.ok()) {
        throw std::runtime_error(tfm::format("CTxDB::init_blockindex(): error opening database environment %s", status.ToString().c_str()));
    }
}

// CDB subclasses are created and destroyed VERY OFTEN. That's why we shouldn't treat this as a free operations.
template <typename HASH>
CTxDB_impl<HASH>::CTxDB_impl(const char *pszMode/* ="r+" */)
{
    assert(pszMode);

    this->activeBatch = nullptr;
    fReadOnly = (!::strchr(pszMode, '+') && !::strchr(pszMode, 'w'));
    if (CTxDB_impl<HASH>::txdb) {
        pdb = CTxDB_impl<HASH>::txdb;
        return;
    }

    bool fCreate = ::strchr(pszMode, 'c');

    this->options = GetOptions();
    this->options.create_if_missing = fCreate;
    this->options.filter_policy = leveldb::NewBloomFilterPolicy(10);

    init_blockindex(options); // Init directory

    pdb = CTxDB_impl<HASH>::txdb;

    if (Exists(std::string("version"))) {
        ReadVersion(nVersion);
        logging::LogPrintf("Transaction index version is %d\n", nVersion);

        if (nVersion < version::DATABASE_VERSION) {
            logging::LogPrintf("Required index version is %d, removing old database\n", version::DATABASE_VERSION);

            // Leveldb instance destruction
            delete CTxDB_impl<HASH>::txdb;
            CTxDB_impl<HASH>::txdb = pdb = nullptr;
            delete this->activeBatch;
            this->activeBatch = nullptr;

            init_blockindex(options, true); // Remove directory and create new database
            pdb = CTxDB_impl<HASH>::txdb;

            bool fTmp = fReadOnly;
            fReadOnly = false;
            WriteVersion(version::DATABASE_VERSION); // Save transaction index version
            fReadOnly = fTmp;
        }
    } else if (fCreate) {
        bool fTmp = fReadOnly;

        fReadOnly = false;
        WriteVersion(version::DATABASE_VERSION);
        fReadOnly = fTmp;
    }

    logging::LogPrintf("Opened LevelDB successfully\n");
}

template <typename HASH>
CTxDB_impl<HASH>::~CTxDB_impl() {
    // Note that this is not the same as Close() because it deletes only
    // data scoped to this TxDB object.
    delete this->activeBatch;
}

template <typename HASH>
void CTxDB_impl<HASH>::Close()
{
    delete CTxDB_impl<HASH>::txdb;
    CTxDB_impl<HASH>::txdb = pdb = nullptr;

    delete this->options.filter_policy;
    this->options.filter_policy = nullptr;

    delete this->options.block_cache;
    this->options.block_cache = nullptr;

    delete this->activeBatch;
    this->activeBatch = nullptr;
}

template <typename HASH>
bool CTxDB_impl<HASH>::TxnBegin()
{
    assert(!this->activeBatch);
    this->activeBatch = new(std::nothrow) leveldb::WriteBatch();
    if (! this->activeBatch) {
        throw std::runtime_error("LevelDB : WriteBatch failed to allocate memory");
        return false;
    }
    return true;
}

template <typename HASH>
bool CTxDB_impl<HASH>::TxnCommit()
{
    assert(this->activeBatch);

    leveldb::Status status = pdb->Write(leveldb::WriteOptions(), activeBatch);
    delete this->activeBatch;
    this->activeBatch = nullptr;

    if (! status.ok()) {
        logging::LogPrintf("LevelDB batch commit failure: %s\n", status.ToString().c_str());
        return false;
    }
    return true;
}

template <typename HASH>
bool CTxDB_impl<HASH>::TxnAbort() {
    delete this->activeBatch;
    this->activeBatch = nullptr;
    return true;
}

template <typename HASH>
bool CTxDB_impl<HASH>::ReadVersion(int &nVersion) {
    nVersion = 0;
    return Read(std::string("version"), nVersion);
}

template <typename HASH>
bool CTxDB_impl<HASH>::WriteVersion(int nVersion) {
    return Write(std::string("version"), nVersion);
}

template<typename HASH>
template<typename K, typename T>
bool CTxDB_impl<HASH>::Read(const K &key, T &value) {
    CDataStream ssKey(0, 0);
    ssKey.reserve(1000);
    ssKey << key;
    std::string strValue;

    bool readFromDb = true;
    if (this->activeBatch) {
        // First we must search for it in the currently pending set of
        // changes to the db. If not found in the batch, go on to read disk.
        bool deleted = false;
        readFromDb = ScanBatch(ssKey, &strValue, &deleted) == false;
        if (deleted) {
            return false;
        }
    }
    if (readFromDb) {
        leveldb::Status status = this->pdb->Get(leveldb::ReadOptions(), ssKey.str(), &strValue);
        if (!status.ok()) {
            if (status.IsNotFound()) {
                return false;
            }

            // Some unexpected error.
            logging::LogPrintf("LevelDB read failure: %s\n", status.ToString().c_str());
            return false;
        }
    }

    // Unserialize value
    try {
        CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(), 0, 0);
        ssValue >> value;
    } catch (const std::exception &) {
        return false;
    }

    return true;
}

template<typename HASH>
template<typename K, typename T>
bool CTxDB_impl<HASH>::Write(const K &key, const T &value) {
    if (this->fReadOnly)
        assert(!"Write called on database in read-only mode");

    CDataStream ssKey(0, 0);
    ssKey.reserve(1000);
    ssKey << key;

    CDataStream ssValue(0, 0);
    ssValue.reserve(10000);
    ssValue << value;

    if (this->activeBatch) {
        this->activeBatch->Put(ssKey.str(), ssValue.str());
        return true;
    }

    leveldb::Status status = this->pdb->Put(leveldb::WriteOptions(), ssKey.str(), ssValue.str());
    if (! status.ok()) {
        logging::LogPrintf("LevelDB write failure: %s\n", status.ToString().c_str());
        return false;
    }

    return true;
}

template<typename HASH>
template<typename K>
bool CTxDB_impl<HASH>::Erase(const K &key) {
    if (! this->pdb)
        return false;
    if (this->fReadOnly)
        assert(!"Erase called on database in read-only mode");

    CDataStream ssKey(0, 0);
    ssKey.reserve(1000);
    ssKey << key;
    if (this->activeBatch) {
        this->activeBatch->Delete(ssKey.str());
        return true;
    }

    leveldb::Status status = this->pdb->Delete(leveldb::WriteOptions(), ssKey.str());
    return (status.ok() || status.IsNotFound());
}

template<typename HASH>
template<typename K>
bool CTxDB_impl<HASH>::Exists(const K &key) {
    CDataStream ssKey(0, 0);
    ssKey.reserve(1000);
    ssKey << key;
    std::string unused;

    if (this->activeBatch) {
        bool deleted;
        if (ScanBatch(ssKey, &unused, &deleted) && !deleted) {
            return true;
        }
    }

    leveldb::Status status = this->pdb->Get(leveldb::ReadOptions(), ssKey.str(), &unused);
    return status.IsNotFound() == false;
}

namespace {
class CBatchScanner final : public leveldb::WriteBatch::Handler
{
private:
    CBatchScanner(const CBatchScanner &)=delete;
    CBatchScanner(CBatchScanner &&)=delete;
    CBatchScanner &operator=(const CBatchScanner &)=delete;
    CBatchScanner &operator=(CBatchScanner &&)=delete;

public:
    std::string needle;
    bool *deleted;
    std::string *foundValue;
    bool foundEntry;

    CBatchScanner() : foundEntry(false) {}

    void Put(const leveldb::Slice &key, const leveldb::Slice &value) {
        if (key.ToString() == needle) {
            foundEntry = true;
            *deleted = false;
            *foundValue = value.ToString();
        }
    }

    void Delete(const leveldb::Slice &key) {
        if (key.ToString() == needle) {
            foundEntry = true;
            *deleted = true;
        }
    }
};
} // namespace

// When performing a read, if we have an active batch we need to check it first
// before reading from the database, as the rest of the code assumes that once
// a database transaction begins reads are consistent with it. It would be good
// to change that assumption in future and avoid the performance hit, though in
// practice it does not appear to be large.
template <typename HASH>
bool CTxDB_impl<HASH>::ScanBatch(const CDataStream &key, std::string *value, bool *deleted) const
{
    assert(this->activeBatch);

    *deleted = false;

    CBatchScanner scanner;
    scanner.needle = key.str();
    scanner.deleted = deleted;
    scanner.foundValue = value;
    leveldb::Status status = this->activeBatch->Iterate(&scanner);
    if (! status.ok()) {
        throw std::runtime_error(status.ToString());
    }
    return scanner.foundEntry;
}

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
static CBlockIndex_impl<HASH> *InsertBlockIndex(const HASH &hash) {
    if (hash == 0)
        return nullptr;

    // Return existing
    typename std::map<HASH, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hash);
    if (mi != block_info::mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex *pindexNew = new(std::nothrow) CBlockIndex;
    if (! pindexNew)
        throw std::runtime_error("LoadBlockIndex() : CBlockIndex failed to allocate memory");

    mi = block_info::mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->set_phashBlock(&((*mi).first));

    return pindexNew;
}

template <typename HASH>
bool CTxDB_impl<HASH>::LoadBlockIndex()
{
    if (block_info::mapBlockIndex.size() > 0) {
        // Already loaded once in this session. It can happen during migration from BDB.
        return true;
    }

    // The block index is an in-memory structure that maps hashes to on-disk
    // locations where the contents of the block can be found. Here, we scan it
    // out of the DB and into block_info::mapBlockIndex.
    leveldb::Iterator *iterator = pdb->NewIterator(leveldb::ReadOptions());

    // Seek to start key.
    CDataStream ssStartKey(0, 0);
    ssStartKey << std::make_pair(std::string("blockindex"), HASH(0));
    iterator->Seek(ssStartKey.str());

    // Now read each entry.
    while (iterator->Valid())
    {
        // Unpack keys and values.
        CDataStream ssKey(0, 0);
        ssKey.write(iterator->key().data(), iterator->key().size());
        CDataStream ssValue(0, 0);
        ssValue.write(iterator->value().data(), iterator->value().size());
        std::string strType;
        ssKey >> strType;

        // Did we reach the end of the data to read?
        if (args_bool::fRequestShutdown || strType != "blockindex") {
            break;
        }

        CDiskBlockIndex_impl<HASH> diskindex;
        ssValue >> diskindex;

        HASH blockHash = diskindex.GetBlockHash();

        // Construct block index object
        CBlockIndex_impl<HASH> *pindexNew = InsertBlockIndex(blockHash);
        pindexNew->set_pprev(InsertBlockIndex(diskindex.get_hashPrev()));
        pindexNew->set_pnext(InsertBlockIndex(diskindex.get_hashNext()));
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
        if (block_info::pindexGenesisBlock == nullptr && blockHash == (!args_bool::fTestNet ? block_params::hashGenesisBlock : block_params::hashGenesisBlockTestNet)) {
            block_info::pindexGenesisBlock = pindexNew;
        }

        if (! pindexNew->CheckIndex()) {
            delete iterator;
            return logging::error("LoadBlockIndex() : CheckIndex failed at %d", pindexNew->get_nHeight());
        }

        // ppcoin: build block_info::setStakeSeen
        if (pindexNew->IsProofOfStake()) {
            block_info::setStakeSeen.insert(std::make_pair(pindexNew->get_prevoutStake(), pindexNew->get_nStakeTime()));
        }

        iterator->Next();
    }
    delete iterator;

    if (args_bool::fRequestShutdown) {
        return true;
    }

    // Calculate nChainTrust
    std::vector<std::pair<int, CBlockIndex *> > vSortedByHeight;
    vSortedByHeight.reserve(block_info::mapBlockIndex.size());
    for(const std::pair<HASH, CBlockIndex *>&item: block_info::mapBlockIndex) {
        CBlockIndex *pindex = item.second;
        vSortedByHeight.push_back(std::make_pair(pindex->get_nHeight(), pindex));
    }

    std::sort(vSortedByHeight.begin(), vSortedByHeight.end());
    for(const std::pair<int, CBlockIndex *>&item: vSortedByHeight) {
        CBlockIndex *pindex = item.second;
        pindex->set_nChainTrust((pindex->get_pprev() ? pindex->get_pprev()->get_nChainTrust() : 0) + pindex->GetBlockTrust());

        // calculate stake modifier checksum
        pindex->set_nStakeModifierChecksum(bitkernel::GetStakeModifierChecksum(pindex));
        if (!bitkernel::CheckStakeModifierCheckpoints(pindex->get_nHeight(), pindex->get_nStakeModifierChecksum())) {
            return logging::error("CTxDB::LoadBlockIndex() : Failed stake modifier checkpoint height=%d, modifier=0x%016" PRIx64, pindex->get_nHeight(), pindex->get_nStakeModifier());
        }
    }

    //
    // Load hashBestChain pointer to end of best chain
    //
    if (! ReadHashBestChain(block_info::hashBestChain)) {
        if (block_info::pindexGenesisBlock == nullptr) {
            return true;
        }

        return logging::error("CTxDB::LoadBlockIndex() : block_info::hashBestChain not loaded");
    }

    if (! block_info::mapBlockIndex.count(block_info::hashBestChain)) {
        return logging::error("CTxDB::LoadBlockIndex() : block_info::hashBestChain not found in the block index");
    }
    block_info::pindexBest = block_info::mapBlockIndex[block_info::hashBestChain];
    block_info::nBestHeight = block_info::pindexBest->get_nHeight();
    block_info::nBestChainTrust = block_info::pindexBest->get_nChainTrust();

    logging::LogPrintf("LoadBlockIndex(): hashBestChain=%s  height=%d  trust=%s  date=%s\n", block_info::hashBestChain.ToString().substr(0, 20).c_str(), block_info::nBestHeight, CBigNum(block_info::nBestChainTrust).ToString().c_str(), util::DateTimeStrFormat("%x %H:%M:%S", block_info::pindexBest->GetBlockTime()).c_str());

    // load hashSyncCheckpoint
    if (! ReadSyncCheckpoint(Checkpoints::manage::getHashSyncCheckpoint())) {
        return logging::error("CTxDB::LoadBlockIndex() : hashSyncCheckpoint not loaded");
    }
    logging::LogPrintf("LoadBlockIndex(): synchronized checkpoint %s\n", Checkpoints::manage::getHashSyncCheckpoint().ToString().c_str());

    // Load bnBestInvalidTrust, OK if it doesn't exist
    CBigNum bnBestInvalidTrust;
    ReadBestInvalidTrust(bnBestInvalidTrust);
    block_info::nBestInvalidTrust = bnBestInvalidTrust.getuint256();

    // Verify blocks in the best chain
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
unsigned int CMTxDB::dbcall(cla_thread<CMTxDB>::thread_data *data) {


    return 0;
}



template class CTxDB_impl<uint256>;
//template class CTxDB_impl<uint65536>;
