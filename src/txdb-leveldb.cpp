// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include <map>
#include <boost/version.hpp>
#ifdef USE_LEVELDB
# include <leveldb/env.h>
# include <leveldb/cache.h>
# include <leveldb/filter_policy.h>
# include <memenv/memenv.h>
#endif
#include <kernel.h>
#include <checkpoints.h>
#include <txdb.h>
#include <util.h>
#include <main.h>
#include <util/logging.h>
#include <file_operate/iofs.h>
#include <sync/lsync.h>
#include <debugcs/debugcs.h>

#ifdef BLK_SQL_MODE
CTxDBHybrid::CTxDBHybrid(const char *pszMode) : sqldb(CSqliteDBEnv::getname_mainchain(), pszMode) {}
#else
CTxDBHybrid::CTxDBHybrid(const char *pszMode) : CLevelDB(CLevelDBEnv::getname_mainchain(), pszMode) {}
#endif
CTxDBHybrid::~CTxDBHybrid() {}

static void oldblockindex_remove(bool fRemoveOld) {
    return;

    unsigned int nFile = 1;
    for (;;) {
        fs::path strBlockFile = iofs::GetDataDir() / tfm::format("blk%04u.dat", nFile);

        // Break if no such file
        if (! fsbridge::file_exists(strBlockFile))
            break;

        fsbridge::file_remove(strBlockFile);
        ++nFile;
    }
}

static void leveldb_oldblockindex_remove(bool fRemoveOld) {
    fs::path directory = iofs::GetDataDir() / "txleveldb";
    if(! fsbridge::dir_exists(directory))
        return;
    if (fRemoveOld) {
        fsbridge::dir_safe_remove_all(directory); // remove directory
        oldblockindex_remove(fRemoveOld);
    }
}

// extern
void leveldb_oldblockchain_remove_once() {
    // sqlite size get
    fs::path sqlpath = iofs::GetDataDir() / CSqliteDBEnv::getname_mainchain();
    size_t size = 100*1024;
    if(! fsbridge::file_size(sqlpath, &size)) {
        leveldb_oldblockindex_remove(true);
        return;
    }

    // removed if blkmainchain.sql size < 20KB
    debugcs::instance() << "sqlblockchain size: " << size << debugcs::endl();
    if(size < 20 * 1024) {
        leveldb_oldblockindex_remove(true);
    }
}

// extern
void sqlitedb_oldblockchain_remove_once() {
    fs::path blksqlfilename = iofs::GetDataDir() / CSqliteDBEnv::getname_mainchain();
    size_t size;
    if(! fsbridge::file_size(blksqlfilename, &size))
        return;
    if(20 * 1024<size) {
        fs::path directory = iofs::GetDataDir() / "txleveldb";
        fs::remove_all(directory); // remove directory
        oldblockindex_remove(true);
        fsbridge::file_remove(blksqlfilename);
    }
}

// extern (from LevelDB to SQLite)
void leveldb_to_sqlite_blockchain() {
    std::vector<fs::path> blocksPath;
    for(int nFile=1;;++nFile) {
        fs::path strBlockFile = iofs::GetDataDir() / tfm::format("blk%04u.dat", nFile);
        debugcs::instance() << "strBlockFile path: " << strBlockFile.string().c_str() << debugcs::endl();
        if(! fsbridge::file_exists(strBlockFile))
            break;
        blocksPath.push_back(strBlockFile);
    }

    // sqlite exists check
    fs::path sqlpath = iofs::GetDataDir() / CSqliteDBEnv::getname_mainchain();
    if(! fsbridge::file_exists(sqlpath)) {
        fs::path bootstrapPath = iofs::GetDataDir() / "bootstrap.dat";
        if(! fsbridge::file_copy_ap(bootstrapPath, blocksPath)) {
            debugcs::instance() << "sqlblockchain file_copy_cp failure" << debugcs::endl();
        }
        leveldb_oldblockindex_remove(true);
        return;
    }

    // sqlite size get
    size_t size = 100*1024;
    if(! fsbridge::file_size(sqlpath, &size))
        return;

    // removed if blkmainchain.sql size < 20KB
    debugcs::instance() << "sqlblockchain size: " << size << debugcs::endl();
    if(size < 20 * 1024) {
        fs::path bootstrapPath = iofs::GetDataDir() / "bootstrap.dat";
        if(! fsbridge::file_copy_ap(bootstrapPath, blocksPath)) {
            debugcs::instance() << "sqlblockchain file_copy_cp failure" << debugcs::endl();
        }
        leveldb_oldblockindex_remove(true);
    }
}

static void sqlite_oldblockindex_remove(bool fRemoveOld) {
    fs::path sqlfile = iofs::GetDataDir() / CSqliteDBEnv::getname_mainchain();
    if (fRemoveOld) {
        fsbridge::file_remove(sqlfile);
        unsigned int nFile = 1;
        for (;;) {
            fs::path strBlockFile = iofs::GetDataDir() / tfm::format("blk%04u.dat", nFile);

            // Break if no such file
            if (! fsbridge::file_exists(strBlockFile))
                break;

            fsbridge::file_remove(strBlockFile);
            ++nFile;
        }
    }
}

// Note(pszMode): fReadOnly == false
void CTxDB::init_blockindex(const char *pszMode, bool fRemoveOld /*= false*/) {
    bool fCreate = ::strchr(pszMode, 'c');
    if (Exists(std::string("version"))) {
        int nVersion;
        ReadVersion(nVersion);
        logging::LogPrintf("Transaction index version is %d\n", nVersion);

        if (nVersion < version::DATABASE_VERSION) {
            logging::LogPrintf("Required index version is %d, removing old database\n", version::DATABASE_VERSION);

#ifdef USE_LEVELDB
            // Leveldb instance destruction
            // Note: activeBatch is nullptr.
            // Remove directory and create new database.
            if(! CLevelDBEnv::get_instance().restart(iofs::GetDataDir(), fRemoveOld, leveldb_oldblockindex_remove)) {
                throw std::runtime_error("CTxDB::init_blockindex(): error opening database environment");
            }
#else
            if(! CSqliteDBEnv::get_instance().restart(iofs::GetDataDir(), fRemoveOld, sqlite_oldblockindex_remove)) {
                throw std::runtime_error("CTxDB::init_blockindex(): error opening database environment");
            }
#endif

            WriteVersion(version::DATABASE_VERSION); // Save transaction index version
        }
    } else if (fCreate) {
        WriteVersion(version::DATABASE_VERSION);
    }

    logging::LogPrintf("Opened LevelDB successfully\n");
}

// CLevelDB subclasses are created and destroyed VERY OFTEN. That's why we shouldn't treat this as a free operations.
CTxDB::CTxDB(const char *pszMode/* ="r+" */) : CTxDBHybrid(pszMode) {
    assert(pszMode);
}

CTxDB::~CTxDB() {}

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
    //debugcs::instance() << "CTxDB called WriteHashBestChain hash: " << hashBestChain.ToString() << debugcs::endl();
    bool ret1 = Write(std::string("hashBestChain"), hashBestChain);
    bool ret2 = Write(std::string("hashGenesisChain"),
                     (!args_bool::fTestNet ? block_params::hashGenesisBlock : block_params::hashGenesisBlockTestNet));
    return ret1 && ret2;
    //return Write(std::string("hashBestChain"), hashBestChain);
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

bool CTxDB::WriteBlockHashType(uint256 hash, const BLOCK_HASH_MODIFIER &modifier) {
    return Write(std::make_pair(std::string("blockhashtype"), hash), modifier); // overwrite: true
}

// like block_info::mapBlockIndex
// must be singleton model
class CmapBlockIndex final {
    CmapBlockIndex(const CmapBlockIndex &)=delete;
    CmapBlockIndex(CmapBlockIndex &&)=delete;
    CmapBlockIndex &operator=(const CmapBlockIndex &)=delete;
    CmapBlockIndex &operator=(CmapBlockIndex &&)=delete;
 public:
    class iterator {
        iterator(const iterator &)=delete;
        iterator &operator=(const iterator &)=delete;
        iterator &operator=(iterator &&)=delete;
     public:
        iterator() : pidb(nullptr), pmap(nullptr) { // end iterator
            fNotfound=true;
        }
        explicit iterator(IDB::DbIterator *pidbIn, typename std::map<uint256, CBlockIndex *> *pmapIn, typename std::map<uint256, CBlockIndex *>::iterator imapIn) {
            this->pidb = pidbIn;
            this->pmap = pmapIn;
            this->imap = imapIn;
            this->fNotfound = false;
        }
        iterator(iterator &&obj) {
            this->pidb = obj.pidb;
            this->pmap = obj.pmap;
            this->imap = std::move(obj.imap);
            this->vbuffer = std::move(obj.vbuffer);
            this->fNotfound = obj.fNotfound;
            obj.pidb = nullptr;
            obj.pmap = nullptr;
            obj.fNotfound = true;
        }
        void inc() {
            if(imap!=pmap->end())
                ++imap;
            if(imap==pmap->end()) {
                std::vector<char> vchKey;
                CDBStream ssKey(&vchKey);
                std::vector<char> vchValue;
                CDBStream ssValue(&vchValue, 10000);
                int ret = CSqliteDB::ReadAtCursor(*pidb, ssKey, ssValue);
                if(ret==DB_NOTFOUND) {
                    fNotfound=true;
                    return;
                }
                try {
                    uint256 hash;
                    CBlockIndex *pobj = new CBlockIndex;
                    ssKey.ignore();
                    ::Unserialize(ssKey, hash);
                    ::Unserialize(ssValue, *pobj);
                    pmap->emplace(hash, pobj);
                    vbuffer.emplace_back(std::make_pair(hash, pobj));
                    //::fprintf_s(stdout, "hash: %s\n", hash.ToString().c_str());
                    ibuffer = vbuffer.end() - 1;
                } catch (const std::exception &) {
                    throw std::runtime_error("CmapBlockIndex inc() out of memory");
                }
            }
        }
        void operator++() {
            inc();
        }
        void operator++(int) {
            inc();
        }
        bool operator==(const iterator &obj) const {
            if(fNotfound==obj.fNotfound)
                return true;
            return imap==obj.imap && vbuffer==obj.vbuffer;
        }
        bool operator!=(const iterator &obj) const {
            return !operator==(obj);
        }
        const std::pair<uint256, CBlockIndex *> operator*() const {
            if(vbuffer.size()==0)
                return *imap;
            else
                return *ibuffer;
        }
     private:
        mutable bool fNotfound;
        IDB::DbIterator *pidb;
        std::map<uint256, CBlockIndex *> *pmap;
        typename std::map<uint256, CBlockIndex *>::iterator imap;

        // temp buffer
        std::vector<std::pair<uint256, CBlockIndex *>> vbuffer;
        typename std::vector<std::pair<uint256, CBlockIndex *>>::iterator ibuffer;
    };

    static CmapBlockIndex &get_instance() {
        static CmapBlockIndex obj;
        return obj;
    }

    int count(const uint256 &hash) const {
        if(_mapBlockIndex.count(hash))
            return 1;
        try {
            CBlockIndex *pobj = new CBlockIndex;
            if(getsqlBlockIndex(hash, *pobj)==false) {
                delete pobj;
                return 0;
            }
            _mapBlockIndex.insert(std::make_pair(hash, pobj));
            return 1;
        } catch (const std::exception &) {
            throw std::runtime_error("CmapBlockIndex count() out of memory");
        }
    }

    iterator find(const uint256 &hash) {
        if(count(hash)==0)
            return std::move(iterator());
        return std::move(iterator(&_ite, &_mapBlockIndex, _mapBlockIndex.find(hash)));
    }

    iterator begin() {
        if(_mapBlockIndex.size()==0) {
            try {
                CBlockIndex *pobj = new CBlockIndex;
                uint256 hash;
                if(getnextBlockIndex(_ite, hash, *pobj)==false) {
                    delete pobj;
                    return end();
                }
                _mapBlockIndex.insert(std::make_pair(hash, pobj));
            } catch (const std::exception &) {
                throw std::runtime_error("CmapBlockIndex begin: out of memory");
            }
        }
        return std::move(iterator(&_ite, &_mapBlockIndex, _mapBlockIndex.begin()));
    }

    iterator end() const {
        return std::move(iterator());
    }

    CBlockIndex *operator[](const uint256 &hash) const {
        if(_mapBlockIndex.count(hash))
            return _mapBlockIndex[hash];
        try {
            CBlockIndex *pobj = new CBlockIndex;
            if(! getsqlBlockIndex(hash, *pobj))
                throw std::runtime_error("CmapBlockIndex [] getsqlBlockIndex failure");
            _mapBlockIndex.insert(std::make_pair(hash, pobj));
            return _mapBlockIndex[hash];
        } catch (const std::exception &e) {
            throw std::runtime_error(e.what());
        }
    }

 private:
    CmapBlockIndex() {
        _ite = CSqliteDB(CSqliteDBEnv::getname_mainchain(), "r").GetIteCursor(std::string("%blockindex%"));
    }
    ~CmapBlockIndex() {}

    static bool getnextBlockIndex(const IDB::DbIterator &ite, uint256 &hash, CBlockIndex &blockIndex) {
        std::vector<char> vchKey;
        CDBStream ssKey(&vchKey);
        std::vector<char> vchValue;
        CDBStream ssValue(&vchValue, 10000);
        if(CSqliteDB::ReadAtCursor(ite, ssKey, ssValue)!=0)
            return false;
        ssKey.ignore();
        ::Unserialize(ssKey, hash);
        ::Unserialize(ssValue, blockIndex);
        return true;
    }
    static bool getsqlBlockIndex(const uint256 &hash, CBlockIndex &blockIndex) {
        try {
            std::vector<char> vchKey;
            CDBStream ssKey(&vchKey);
            ::Serialize(ssKey, std::make_pair(std::string("blockindex"), hash));
            IDB::DbIterator ite = CSqliteDB(CSqliteDBEnv::getname_mainchain(), "r").GetIteCursor(std::string(ssKey.data(), ssKey.data()+ssKey.size()));
            std::vector<char> vchValue;
            CDBStream ssValue(&vchValue, 10000);
            if(CSqliteDB::ReadAtCursor(ite, ssKey, ssValue)!=0)
                return false;
            ::Unserialize(ssValue, blockIndex);
            return true;
        } catch (const std::exception &) {
            return false;
        }
    }

 private:
    IDB::DbIterator _ite;
    mutable std::map<uint256, CBlockIndex *> _mapBlockIndex;
};

static CBlockIndex *InsertBlockIndex(const uint256 &hash, std::unordered_map<uint256, CBlockIndex *, CCoinsKeyHasher> &mapBlockIndex) {
    if (hash == 0)
        return nullptr;

    // Return existing
    auto mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex *pindexNew = new(std::nothrow) CBlockIndex;
    if (! pindexNew)
        throw std::runtime_error("LoadBlockIndex() : CBlockIndex failed to allocate memory");

    mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->set_phashBlock(&((*mi).first));

    return pindexNew;
}

bool CTxDB::LoadBlockIndex(std::unordered_map<uint256, CBlockIndex *, CCoinsKeyHasher> &mapBlockIndex,
        std::set<std::pair<COutPoint, unsigned int> > &setStakeSeen,
        CBlockIndex *&pindexGenesisBlock,
        uint256 &hashBestChain,
        int &nBestHeight,
        CBlockIndex *&pindexBest,
        uint256 &nBestInvalidTrust,
        uint256 &nBestChainTrust)
{
    if (mapBlockIndex.size() > 0) {
        // Already loaded once in this session. It can happen during migration from BDB.
        return true;
    }

    // The block index is an in-memory structure that maps hashes to on-disk
    // locations where the contents of the block can be found. Here, we scan it
    // out of the DB and into mapBlockIndex.

#ifdef BLK_SQL_MODE

    // Seek to start blockhashtype.
    IDB::DbIterator iterator1 = this->GetIteCursor(std::string("%blockhashtype%"));

    // Now read each blockhashtype.
    int ret=DB_NOTFOUND;
    std::vector<char> vchBuffer;
    CDBStream ssData(&vchBuffer, 10000);

    while((ret=CSqliteDB::ReadAtCursor(iterator1, CDBStreamInvalid(), ssData))!=DB_NOTFOUND)
    {
        if(ret>0)
            return logging::error("LoadBlockIndex() : sql read failure");

        // Unpack values.
        if (args_bool::fRequestShutdown)
            break;

        //CDBStream ssKey(const_cast<char *>(iterator->key().data()), iterator->key().size());
        //CDBStream ssValue(const_cast<char *>(iterator->value().data()), iterator->value().size());
        //ssKey.ignore();
        ssData.ignore();

        uint256 hash;
        ::Unserialize(ssData, hash);
        BLOCK_HASH_MODIFIER data;
        ::Unserialize(ssData, data);

        block_info::mapBlockLyraHeight.insert(std::make_pair(hash, data));
        //debugcs::instance() << "LoadBlockIndex height: " << data.nHeight << " hash: " << hash.ToString().c_str() << debugcs::endl();
    }

    // Seek to start key.
    IDB::DbIterator iterator2 = this->GetIteCursor(std::string("%blockindex%"));

    // Now read each entry.
    ret=DB_NOTFOUND;
    while((ret=CSqliteDB::ReadAtCursor(iterator2, CDBStreamInvalid(), ssData))!=DB_NOTFOUND)
    {
        if(ret>0)
            return logging::error("LoadBlockIndex() : sql read failure");

        // Unpack values.
        if (args_bool::fRequestShutdown)
            break;

        CDiskBlockIndex diskindex;
        ::Unserialize(ssData, diskindex);

        uint256 blockHash = diskindex.GetBlockHash();
        //debugcs::instance() << "CTxDB ReadAtCursor hash: " << blockHash.ToString().c_str() << debugcs::endl();
        //if(diskindex.get_nHeight() > 1400000)
        //    debugcs::instance() << "CTxDB ReadAtCursor height: " << diskindex.get_nHeight() << debugcs::endl();

        // Construct block index object
        CBlockIndex *pindexNew = InsertBlockIndex(blockHash, mapBlockIndex);
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
        if (pindexGenesisBlock == nullptr && blockHash == (!args_bool::fTestNet ? block_params::hashGenesisBlock : block_params::hashGenesisBlockTestNet))
            pindexGenesisBlock = pindexNew;

        if (! pindexNew->CheckIndex())
            return logging::error("LoadBlockIndex() : CheckIndex failed at %d", pindexNew->get_nHeight());

        // ppcoin: build setStakeSeen
        if (pindexNew->IsProofOfStake())
            setStakeSeen.insert(std::make_pair(pindexNew->get_prevoutStake(), pindexNew->get_nStakeTime()));
    }

    //debugcs::instance() << "LoadBlockIndex done" << debugcs::endl();

    // debug
    // checking mapBlockIndex
    /*
    {
        CmapBlockIndex &mbi = CmapBlockIndex::get_instance();
        for(typename CmapBlockIndex::iterator ite = mbi.begin(); ite != mbi.end(); ++ite) {
            debugcs::instance() << "block hash : " << (*ite).first.ToString().c_str() << debugcs::endl();
        }
    }
    */

#else

    // Seek to start blockhashtype.
    if(! this->seek(std::string("blockhashtype"), uint256(0)))
        return logging::error("LoadBlockIndex() Error: memory allocate failure.");

    // Now read each blockhashtype.
    for(const_iterator iterator=this->begin(); iterator!=this->end(); ++iterator)
    {
        // Unpack keys and values.
        CDBStream ssKey(const_cast<char *>(iterator->key().data()), iterator->key().size());
        CDBStream ssValue(const_cast<char *>(iterator->value().data()), iterator->value().size());
        std::string strType;
        ::Unserialize(ssKey, strType);

        // Did we reach the end of the data to read?
        if (args_bool::fRequestShutdown || strType != "blockhashtype")
            break;

        uint256 hash;
        ::Unserialize(ssKey, hash);
        BLOCK_HASH_MODIFIER data;
        ::Unserialize(ssValue, data);

        block_info::mapBlockLyraHeight.insert(std::make_pair(hash, data));
        //debugcs::instance() << "LoadBlockIndex height: " << data.get_nHeight() << " hash: " << hash.ToString().c_str() << debugcs::endl();
    }

    // Seek to start key.
    if(! this->seek(std::string("blockindex"), uint256(0)))
        return logging::error("LoadBlockIndex() Error: memory allocate failure.");

    // Now read each entry.
    for(const_iterator iterator=this->begin(); iterator!=this->end(); ++iterator)
    {
        // Unpack keys and values.
        CDBStream ssKey(const_cast<char *>(iterator->key().data()), iterator->key().size());
        CDBStream ssValue(const_cast<char *>(iterator->value().data()), iterator->value().size());
        std::string strType;
        ::Unserialize(ssKey, strType);

        // Did we reach the end of the data to read?
        if (args_bool::fRequestShutdown || strType != "blockindex")
            break;

        CDiskBlockIndex diskindex;
        ::Unserialize(ssValue, diskindex);

        uint256 blockHash = diskindex.GetBlockHash();

        // Construct block index object
        CBlockIndex *pindexNew = InsertBlockIndex(blockHash, mapBlockIndex);
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
        if (pindexGenesisBlock == nullptr && blockHash == (!args_bool::fTestNet ? block_params::hashGenesisBlock : block_params::hashGenesisBlockTestNet))
            pindexGenesisBlock = pindexNew;

        if (! pindexNew->CheckIndex())
            return logging::error("LoadBlockIndex() : CheckIndex failed at %d", pindexNew->get_nHeight());

        // ppcoin: build setStakeSeen
        if (pindexNew->IsProofOfStake())
            setStakeSeen.insert(std::make_pair(pindexNew->get_prevoutStake(), pindexNew->get_nStakeTime()));
    }

#endif

    if (args_bool::fRequestShutdown)
        return true;

    std::vector<std::pair<int32_t, CBlockIndex *> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    for(const auto &item: mapBlockIndex) {
        CBlockIndex *pindex = item.second;
        vSortedByHeight.push_back(std::make_pair(pindex->get_nHeight(), pindex));
    }
    std::sort(vSortedByHeight.begin(), vSortedByHeight.end());

    // BLOCK_HASH_MODIFIER orphan checker
    // Note: when -debug, Checkpoints take from the Blockchain where no assert.
    if(0 < block_info::mapBlockLyraHeight.size()) {
        std::vector<std::pair<int32_t, BLOCK_HASH_MODIFIER *> > vSortedModiByHeight;
        vSortedModiByHeight.reserve(block_info::mapBlockLyraHeight.size());
        for (auto &item: block_info::mapBlockLyraHeight) {
            BLOCK_HASH_MODIFIER *pmodi = &item.second;
            vSortedModiByHeight.push_back(std::make_pair(pmodi->get_nHeight(), pmodi));
        }
        std::sort(vSortedModiByHeight.begin(), vSortedModiByHeight.end());
        std::map<int32_t, int32_t> orphan_block; // nHeight, dummy(always 0)
        for (int i=0; i<vSortedModiByHeight.size()-1; ++i) {
            BLOCK_HASH_MODIFIER *p1 = vSortedModiByHeight[i].second;
            BLOCK_HASH_MODIFIER *p2 = vSortedModiByHeight[i+1].second;
            if(p1->get_nHeight()==p2->get_nHeight()) { // orphan Block_hash_modifier found
                if(args_bool::fDebug)
                    debugcs::instance() << "vSortedModiByHeight orphan found nHeight: " << p1->get_nHeight() << debugcs::endl();
                orphan_block.insert(std::make_pair(p1->get_nHeight(), 0));
            }
        }
        if(args_bool::fDebug) {
            assert(orphan_block.size()==0);
        }
    }

    // Calculate nChainTrust
    for(const auto &item: vSortedByHeight) {
        CBlockIndex *pindex = item.second;

        // build pskip
        if(pindex->get_pprev())
            pindex->BuildSkip();

        // build LastHeight
        if(pindex->get_pprev())
            pindex->set_LastHeight(pindex->get_nHeight()-1);
    }
    for(const auto &item: vSortedByHeight) {
        CBlockIndex *pindex = item.second;
        pindex->set_nChainTrust((pindex->get_pprev() ? pindex->get_pprev()->get_nChainTrust() : 0) + pindex->GetBlockTrust());

        // calculate stake modifier checksum
        pindex->set_nStakeModifierChecksum(bitkernel::GetStakeModifierChecksum(pindex));
        if (! bitkernel::CheckStakeModifierCheckpoints(pindex->get_nHeight(), pindex->get_nStakeModifierChecksum()))
            return logging::error("CTxDB::LoadBlockIndex() : Failed stake modifier checkpoint height=%d, modifier=0x%016" PRIx64,
                                  pindex->get_nHeight(),
                                  pindex->get_nStakeModifier());
    }

    // Load hashBestChain pointer to end of best chain
    if (! ReadHashBestChain(hashBestChain)) {
        if (pindexGenesisBlock == nullptr)
            return true;
        return logging::error("CTxDB::LoadBlockIndex() : hashBestChain not loaded");
    }
    //::fprintf(stdout, "hashBestChain: %s\n", hashBestChain.ToString().c_str());

    if (! mapBlockIndex.count(hashBestChain))
        return logging::error("CTxDB::LoadBlockIndex() : hashBestChain not found in the block index");

    pindexBest = mapBlockIndex[hashBestChain];
    nBestHeight = pindexBest->get_nHeight();
    nBestChainTrust = pindexBest->get_nChainTrust();
    logging::LogPrintf("LoadBlockIndex(): hashBestChain=%s  height=%d  trust=%s  date=%s\n",
                       hashBestChain.ToString().substr(0, 20).c_str(),
                       nBestHeight,
                       CBigNum(nBestChainTrust).ToString().c_str(),
                       util::DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

    // load hashSyncCheckpoint
    if (! ReadSyncCheckpoint(Checkpoints::manage::getHashSyncCheckpoint()))
        return logging::error("CTxDB::LoadBlockIndex() : hashSyncCheckpoint not loaded");

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
