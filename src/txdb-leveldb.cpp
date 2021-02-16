// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifdef USE_LEVELDB

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

leveldb::DB *CTxDB::txdb = nullptr;

leveldb::Options CTxDB::GetOptions()
{
    leveldb::Options options;
    int nCacheSizeMB = map_arg::GetArgInt("-dbcache", 25);

    options.block_cache = leveldb::NewLRUCache(nCacheSizeMB * 1048576);
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);

    return options;
}

void CTxDB::init_blockindex(leveldb::Options &options, bool fRemoveOld /* = false */)
{
    //
    // First time init.
    //
    fs::path directory = iofs::GetDataDir() / "txleveldb";

    if (fRemoveOld) {
        fs::remove_all(directory); // remove directory
        unsigned int nFile = 1;
        for (;;) {
            fs::path strBlockFile = iofs::GetDataDir() / strprintf("blk%04u.dat", nFile);

            // Break if no such file
            if (! fs::exists(strBlockFile)) {
                break;
            }

            fs::remove(strBlockFile);
            ++nFile;
        }
    }

    fs::create_directory(directory);
    printf("Opening LevelDB in %s\n", directory.string().c_str());

    leveldb::Status status = leveldb::DB::Open(options, directory.string(), &CTxDB::txdb);
    if (! status.ok()) {
        throw std::runtime_error(strprintf("CTxDB::init_blockindex(): error opening database environment %s", status.ToString().c_str()));
    }
}

//
// CDB subclasses are created and destroyed VERY OFTEN. That's why we shouldn't treat this as a free operations.
//
CTxDB::CTxDB(const char *pszMode/* ="r+" */)
{
    assert(pszMode);

    this->activeBatch = nullptr;
    fReadOnly = (!::strchr(pszMode, '+') && !::strchr(pszMode, 'w'));
    if (CTxDB::txdb) {
        pdb = CTxDB::txdb;
        return;
    }

    bool fCreate = ::strchr(pszMode, 'c');

    this->options = GetOptions();
    this->options.create_if_missing = fCreate;
    this->options.filter_policy = leveldb::NewBloomFilterPolicy(10);

    init_blockindex(options); // Init directory

    pdb = CTxDB::txdb;

    if (Exists(std::string("version"))) {
        ReadVersion(nVersion);
        printf("Transaction index version is %d\n", nVersion);

        if (nVersion < version::DATABASE_VERSION) {
            printf("Required index version is %d, removing old database\n", version::DATABASE_VERSION);

            //
            // Leveldb instance destruction
            //
            delete CTxDB::txdb;
            CTxDB::txdb = pdb = nullptr;
            delete this->activeBatch;
            this->activeBatch = nullptr;

            init_blockindex(options, true); // Remove directory and create new database
            pdb = CTxDB::txdb;

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

    printf("Opened LevelDB successfully\n");
}

void CTxDB::Close()
{
    delete CTxDB::txdb;
    CTxDB::txdb = pdb = nullptr;

    delete this->options.filter_policy;
    this->options.filter_policy = nullptr;

    delete this->options.block_cache;
    this->options.block_cache = nullptr;

    delete this->activeBatch;
    this->activeBatch = nullptr;
}

bool CTxDB::TxnBegin()
{
    assert(!this->activeBatch);
    this->activeBatch = new(std::nothrow) leveldb::WriteBatch();
    if (! this->activeBatch) {
        throw std::runtime_error("LevelDB : WriteBatch failed to allocate memory");
        return false;
    }
    return true;
}

bool CTxDB::TxnCommit()
{
    assert(this->activeBatch);

    leveldb::Status status = pdb->Write(leveldb::WriteOptions(), activeBatch);
    delete this->activeBatch;
    this->activeBatch = nullptr;

    if (! status.ok()) {
        printf("LevelDB batch commit failure: %s\n", status.ToString().c_str());
        return false;
    }
    return true;
}

class CBatchScanner : public leveldb::WriteBatch::Handler
{
private:
    CBatchScanner(const CBatchScanner &); // {}
    CBatchScanner(const CBatchScanner &&); // {}
    CBatchScanner &operator=(const CBatchScanner &); // {}
    CBatchScanner &operator=(const CBatchScanner &&); // {}

public:
    std::string needle;
    bool *deleted;
    std::string *foundValue;
    bool foundEntry;

    CBatchScanner() : foundEntry(false) {}

    virtual void Put(const leveldb::Slice &key, const leveldb::Slice &value) {
        if (key.ToString() == needle) {
            foundEntry = true;
            *deleted = false;
            *foundValue = value.ToString();
        }
    }

    virtual void Delete(const leveldb::Slice &key) {
        if (key.ToString() == needle) {
            foundEntry = true;
            *deleted = true;
        }
    }
};

//
// When performing a read, if we have an active batch we need to check it first
// before reading from the database, as the rest of the code assumes that once
// a database transaction begins reads are consistent with it. It would be good
// to change that assumption in future and avoid the performance hit, though in
// practice it does not appear to be large.
//
bool CTxDB::ScanBatch(const CDataStream &key, std::string *value, bool *deleted) const
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
    if (!ReadTxIndex(hash, txindex)) {
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
        throw std::runtime_error("LoadBlockIndex() : CBlockIndex failed to allocate memory");
    }

    mi = block_info::mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->set_phashBlock(&((*mi).first));

    return pindexNew;
}

bool CTxDB::LoadBlockIndex()
{
    if (block_info::mapBlockIndex.size() > 0) {
        //
        // Already loaded once in this session. It can happen during migration
        // from BDB.
        //
        return true;
    }

    // The block index is an in-memory structure that maps hashes to on-disk
    // locations where the contents of the block can be found. Here, we scan it
    // out of the DB and into block_info::mapBlockIndex.
    leveldb::Iterator *iterator = pdb->NewIterator(leveldb::ReadOptions());

    // Seek to start key.
    CDataStream ssStartKey(0, 0);
    ssStartKey << std::make_pair(std::string("blockindex"), uint256(0));
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

        CDiskBlockIndex diskindex;
        ssValue >> diskindex;

        uint256 blockHash = diskindex.GetBlockHash();

        // Construct block index object
        CBlockIndex *pindexNew = InsertBlockIndex(blockHash);
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
            return print::error("LoadBlockIndex() : CheckIndex failed at %d", pindexNew->get_nHeight());
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
    for(const std::pair<uint256, CBlockIndex *>&item: block_info::mapBlockIndex) {
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
            return print::error("CTxDB::LoadBlockIndex() : Failed stake modifier checkpoint height=%d, modifier=0x%016" PRIx64, pindex->get_nHeight(), pindex->get_nStakeModifier());
        }
    }

    //
    // Load hashBestChain pointer to end of best chain
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

    printf("LoadBlockIndex(): hashBestChain=%s  height=%d  trust=%s  date=%s\n", block_info::hashBestChain.ToString().substr(0, 20).c_str(), block_info::nBestHeight, CBigNum(block_info::nBestChainTrust).ToString().c_str(), util::DateTimeStrFormat("%x %H:%M:%S", block_info::pindexBest->GetBlockTime()).c_str());

    // load hashSyncCheckpoint
    if (! ReadSyncCheckpoint(Checkpoints::manage::getHashSyncCheckpoint())) {
        return print::error("CTxDB::LoadBlockIndex() : hashSyncCheckpoint not loaded");
    }
    printf("LoadBlockIndex(): synchronized checkpoint %s\n", Checkpoints::manage::getHashSyncCheckpoint().ToString().c_str());

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

    printf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
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
            printf("LoadBlockIndex() : *** found bad block at %d, hash=%s\n", pindex->get_nHeight(), pindex->GetBlockHash().ToString().c_str());
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
                    if (nCheckLevel>2 || pindex->get_nFile() != txindex.get_pos().get_nFile() || pindex->get_nBlockPos() != txindex.get_pos().get_nBlockPos()) {
                        //
                        // either an error or a duplicate transaction
                        //
                        CTransaction txFound;
                        if (! txFound.ReadFromDisk(txindex.get_pos())) {
                            printf("LoadBlockIndex() : *** cannot read mislocated transaction %s\n", hashTx.ToString().c_str());
                            pindexFork = pindex->set_pprev();
                        } else {
                            if (txFound.GetHash() != hashTx) { // not a duplicate tx
                                printf("LoadBlockIndex(): *** invalid tx position for %s\n", hashTx.ToString().c_str());
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
                                    printf("LoadBlockIndex(): *** found bad spend at %d, hashBlock=%s, hashTx=%s\n", pindex->get_nHeight(), pindex->GetBlockHash().ToString().c_str(), hashTx.ToString().c_str());
                                    pindexFork = pindex->set_pprev();
                                }

                                //
                                // check level 6: check whether spent txouts were spent by a valid transaction that consume them
                                //
                                if (nCheckLevel > 5) {
                                    CTransaction txSpend;
                                    if (! txSpend.ReadFromDisk(txpos)) {
                                        printf("LoadBlockIndex(): *** cannot read spending transaction of %s:%i from disk\n", hashTx.ToString().c_str(), nOutput);
                                        pindexFork = pindex->set_pprev();
                                    } else if (!txSpend.CheckTransaction()) {
                                        printf("LoadBlockIndex(): *** spending transaction of %s:%i is invalid\n", hashTx.ToString().c_str(), nOutput);
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
                                            printf("LoadBlockIndex(): *** spending transaction of %s:%i does not spend it\n", hashTx.ToString().c_str(), nOutput);
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
                                printf("LoadBlockIndex(): *** found unspent prevout %s:%i in %s\n", txin.get_prevout().get_hash().ToString().c_str(), txin.get_prevout().get_n(), hashTx.ToString().c_str());
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
        printf("LoadBlockIndex() : *** moving best chain pointer back to block %d\n", pindexFork->get_nHeight());
        CBlock block;
        if (! block.ReadFromDisk(pindexFork)) {
            return print::error("LoadBlockIndex() : block.ReadFromDisk failed");
        }

        CTxDB txdb;
        block.SetBestChain(txdb, pindexFork);
    }

    return true;
}

#endif

