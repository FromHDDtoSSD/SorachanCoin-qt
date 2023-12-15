// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <db.h>
#include <net.h>
#include <util.h>
#include <main.h>
#include <ui_interface.h>
#include <init.h>
#include <file_operate/fs.h>
#include <boost/filesystem/fstream.hpp>
#include <util/time.h>

#ifndef WIN32
# include "sys/stat.h"
#endif

#ifdef USE_BERKELEYDB
CCriticalSection CDBEnv::cs_db;
#endif
#ifdef USE_LEVELDB
CCriticalSection CLevelDBEnv::cs_leveldb;
#endif
CCriticalSection CSqliteDBEnv::cs_sqlite;

static CCriticalSection cs_w_update;
static unsigned int nWalletDBUpdated = 0;
void dbparam::IncWalletUpdate() {
    LOCK(cs_w_update);
    ++nWalletDBUpdated;
}

unsigned int dbparam::GetWalletUpdate() {
    LOCK(cs_w_update);
    return nWalletDBUpdated;
}

// SorachanCoin: CDB only use wallet.dat
bool dbparam::IsChainFile(std::string strFile) {
    //debugcs::instance() << "dbparam::InChainFile: " << strFile.c_str() << debugcs::endl();
    //util::Sleep(5000);
    assert(strFile != "blkindex.dat");
    return (strFile == "blkindex.dat");
}

//////////////////////////////////////////////////////////////////////////////////////////////
// CDBEnv class
//////////////////////////////////////////////////////////////////////////////////////////////

#ifdef USE_BERKELEYDB
void CDBEnv::EnvShutdown() {
    LOCK(cs_db);
    if (! fDbEnvInit)
        return;

    fDbEnvInit = false;
    int ret = dbenv.close(0);
    if (ret != 0)
        logging::LogPrintf("EnvShutdown exception: %s (%d)\n", DbEnv::strerror(ret), ret);
    if (! fMockDb) {
        int ret = DbEnv(0).remove(pathEnv.string().c_str(), 0);
        if(ret > 0)
            throw std::runtime_error("EnvShutdown database remove failure");
    }
}

CDBEnv::CDBEnv() : fDetachDB(false), fDbEnvInit(false), dbenv(DB_CXX_NO_EXCEPTIONS) {}
CDBEnv::~CDBEnv() {
    EnvShutdown();
}

void CDBEnv::Close() {
    EnvShutdown();
}
bool CDBEnv::TxnCheckPoint(uint32_t kbyte, uint32_t min) {
    LOCK(cs_db);
    return dbenv.txn_checkpoint(kbyte, min, 0)==0;
}
bool CDBEnv::Remove(const std::string &strFile) {
    LOCK(cs_db);
    Db db(&dbenv, 0);
    return db.remove(strFile.c_str(), nullptr, 0)==0;
}
bool CDBEnv::Rename(const std::string &strFileRes, const std::string &strFile) {
    LOCK(cs_db);
    Db db(&dbenv, 0);
    return db.rename(strFileRes.c_str(), nullptr, strFile.c_str(), 0)==0;
}
bool CDBEnv::DbRename(const std::string &filename, const std::string &newFilename) {
    LOCK(cs_db);
    return dbenv.dbrename(nullptr, filename.c_str(), nullptr, newFilename.c_str(), DB_AUTO_COMMIT)==0;
}

bool CDBEnv::Open(fs::path pathEnv_) {
    LOCK(cs_db);
    if (fDbEnvInit)
        return true;
    if (args_bool::fShutdown)
        return false;

    // create directory and db.log
    pathEnv = pathEnv_;
    const fs::path pathDataDir = pathEnv;
    const fs::path pathLogDir = pathDataDir / "database";
    if(! fsbridge::dir_create(pathLogDir))
        return false;

    const fs::path pathErrorFile = pathDataDir / "db.log";
    logging::LogPrintf("dbenv.open LogDir=%s ErrorFile=%s\n", pathLogDir.string().c_str(), pathErrorFile.string().c_str());

    unsigned int nEnvFlags = 0;
    if (map_arg::GetBoolArg("-privdb", true))
        nEnvFlags |= DB_PRIVATE;

    int nDbCache = map_arg::GetArgInt("-dbcache", dbcache_size);
    dbenv.set_lg_dir(pathLogDir.string().c_str());
    dbenv.set_cachesize(nDbCache / 1024, (nDbCache % 1024) * 1048576, 1);
    dbenv.set_lg_bsize(1048576);
    dbenv.set_lg_max(10485760);

    // Bugfix: Bump lk_max_locks default to 537000, to safely handle reorgs with up to 5 blocks reversed
    // dbenv.set_lk_max_locks(10000);
    dbenv.set_lk_max_locks(537000);

    dbenv.set_lk_max_objects(10000);
    dbenv.set_errfile(fopen(pathErrorFile.string().c_str(), "a")); /// debug
    dbenv.set_flags(DB_AUTO_COMMIT, 1);
    dbenv.set_flags(DB_TXN_WRITE_NOSYNC, 1);

#ifdef DB_LOG_AUTO_REMOVE
    dbenv.log_set_config(DB_LOG_AUTO_REMOVE, 1);
#endif

    int ret = dbenv.open(pathEnv.string().c_str(),
        DB_CREATE |
        DB_INIT_LOCK |
        DB_INIT_LOG |
        DB_INIT_MPOOL |
        DB_INIT_TXN |
        DB_THREAD |
        DB_RECOVER |
        nEnvFlags,
        S_IRUSR | S_IWUSR);
    if (ret != 0) {
        return logging::error("CDB() : error %s (%d) opening database environment", DbEnv::strerror(ret), ret);
    }

    fDbEnvInit = true;
    //fMockDb = false;

    return true;
}

/*
void CDBEnv::MakeMock()
{
    if (fDbEnvInit)
        throw std::runtime_error("CDBEnv::MakeMock(): already initialized");
    if (args_bool::fShutdown)
        throw std::runtime_error("CDBEnv::MakeMock(): during shutdown");

    logging::LogPrintf("CDBEnv::MakeMock()\n");

    dbenv.set_cachesize(1, 0, 1);
    dbenv.set_lg_bsize(10485760 * 4);
    dbenv.set_lg_max(10485760);
    dbenv.set_lk_max_locks(10000);
    dbenv.set_lk_max_objects(10000);
    dbenv.set_flags(DB_AUTO_COMMIT, 1);
#ifdef DB_LOG_IN_MEMORY
    dbenv.log_set_config(DB_LOG_IN_MEMORY, args_bool::fUseMemoryLog ? 1 : 0);
#endif
    int ret = dbenv.open(nullptr,
        DB_CREATE |
        DB_INIT_LOCK |
        DB_INIT_LOG |
        DB_INIT_MPOOL |
        DB_INIT_TXN |
        DB_THREAD |
        DB_PRIVATE,
        S_IRUSR | S_IWUSR);
    if (ret > 0)
        throw std::runtime_error(tfm::format("CDBEnv::MakeMock(): error %d opening database environment", ret));

    fDbEnvInit = true;
    fMockDb = true;
}
*/

CDBEnv::VerifyResult CDBEnv::Verify(std::string strFile, bool (*recoverFunc)(std::string strFile, bool fOnlyKeys))
{
    LOCK(cs_db);
    assert(mapFileUseCount.count(strFile) == 0);

    Db db(&dbenv, 0);
    int result = db.verify(strFile.c_str(), nullptr, nullptr, 0);
    if (result == 0)
        return VERIFY_OK;
    else if (recoverFunc == nullptr)
        return RECOVER_FAIL;

    // Try to recover:
    bool fRecovered = (*recoverFunc)(strFile, false);
    return (fRecovered ? RECOVER_OK : RECOVER_FAIL);
}

bool CDBEnv::Salvage(std::string strFile, bool fAggressive, std::vector<CDBEnv::KeyValPair> &vResult)
{
    LOCK(cs_db);
    assert(mapFileUseCount.count(strFile) == 0);

    u_int32_t flags = DB_SALVAGE;
    if (fAggressive) { flags |= DB_AGGRESSIVE; }

    std::stringstream strDump;

    Db db(&dbenv, 0);
    int result = db.verify(strFile.c_str(), nullptr, &strDump, flags);
    if (result != 0) {
        logging::LogPrintf("ERROR: db salvage failed\n");
        return false;
    }

    //
    // Format of bdb dump is ascii lines:
    // header lines...
    // HEADER=END
    // hexadecimal key
    // hexadecimal value
    // ... repeated
    // DATA=END
    //

    std::string strLine;
    while (!strDump.eof() && strLine != "HEADER=END") {
        std::getline(strDump, strLine); // Skip past header
    }

    std::string keyHex, valueHex;
    while (!strDump.eof() && keyHex != "DATA=END") {
        std::getline(strDump, keyHex);
        if (keyHex != "DATA=END") {
            std::getline(strDump, valueHex);
            vResult.push_back(std::make_pair(strenc::ParseHex(keyHex), strenc::ParseHex(valueHex)));
        }
    }

    return (result == 0);
}


void CDBEnv::CheckpointLSN(std::string strFile)
{
    dbenv.txn_checkpoint(0, 0, 0);
    if (fMockDb) {
        return;
    }
    dbenv.lsn_reset(strFile.c_str(), 0);
}

std::unique_ptr<Db> CDBEnv::TempCreate(DbTxn *txnid, const std::string &strFile, unsigned int nFlags) {
    std::unique_ptr<Db> pdb(new(std::nothrow) Db(&dbenv, 0));
    if(pdb) {
        int ret = pdb->open(txnid,                // Txn pointer
                            strFile.c_str(),      // Filename
                            "main",               // Logical db name
                            DB_BTREE,             // Database type
                            nFlags,               // Flags
                            0);
        if(ret > 0) {
            pdb.reset(); // release and nullptr
            assert(pdb.get()==nullptr);
        }
    }
    return std::move(pdb);
}

Db *CDBEnv::Create(const std::string &strFile, unsigned int nFlags)
{
    LOCK(cs_db);
    if (! Open(iofs::GetDataDir())) {
        if(args_bool::fShutdown)
            return nullptr;
        else
            throw std::runtime_error("CDBEnv::bitdb : failed to open file");
    }

    IncUseCount(strFile);
    Db *&pdb = getDb(strFile);
    if (pdb == nullptr) {
        pdb = new(std::nothrow) Db(&dbenv, 0);
        if (pdb == nullptr)
            throw std::runtime_error("CDB() : failed to allocate memory");

        /*
        bool fMockDb = IsMock();
        if (fMockDb) {
            DbMpoolFile *mpf = pdb->get_mpf();
            int ret = mpf->set_flags(DB_MPOOL_NOFILE, 1);
            if (ret != 0)
                throw std::runtime_error(tfm::format("CDB() : failed to configure for no temp file backing for database %s", strFile.c_str()));
        }
        */

        for (int cc = 0; cc < retry_counter; ++cc) {
            int ret = pdb->open(nullptr,             // Txn pointer
                fMockDb ? nullptr : strFile.c_str(), // Filename
                "main",                              // Logical db name
                DB_BTREE,                            // Database type
                nFlags,                              // Flags
                0);

            if (ret != 0) {
                if(cc < retry_counter - 1) {
                    util::Sleep(1000);
                    continue;
                }
                delete pdb;
                pdb = nullptr;
                DecUseCount(strFile);
                //strFile.clear();
                throw std::runtime_error(tfm::format("CDB() : can't open database file %s, error %d", strFile.c_str(), ret));
            } else {
                break;
            }
        }

        //setDb(strFile, pdb);
    }
    return pdb;
}

void CDBEnv::CloseDb(const std::string &strFile)
{
    {
        LOCK(cs_db);
        if (mapDb[strFile] != nullptr) {
            //
            // Close the database handle
            //
            Db *pdb = mapDb[strFile];
            pdb->close(0);
            delete pdb;
            mapDb[strFile] = nullptr;
        }
    }
}

bool CDBEnv::RemoveDb(const std::string &strFile)
{
    CloseDb(strFile);

    LOCK(cs_db);
    int rc = dbenv.dbremove(nullptr, strFile.c_str(), nullptr, DB_AUTO_COMMIT);
    return (rc == 0);
}

DbTxn *CDBEnv::TxnBegin(int flags /*= DB_TXN_WRITE_NOSYNC*/) {
    DbTxn *ptxn = nullptr;
    int ret = dbenv.txn_begin(nullptr, &ptxn, flags);
    if (!ptxn || ret != 0)
        return nullptr;

    return ptxn;
}

void CDBEnv::Flush(bool fShutdown)
{
    LOCK(cs_db);
    const int64_t nStart = util::GetTimeMillis();

    // Flush log data to the actual data file on all files that are not in use
    logging::LogPrintf("Flush(%s)%s\n", args_bool::fShutdown ? "true" : "false", fDbEnvInit ? "" : " db not started");
    if (! fDbEnvInit) {
        return;
    }

    {
        LOCK(cs_db);
        std::map<std::string, int>::iterator mi = mapFileUseCount.begin();
        while (mi != mapFileUseCount.end())
        {
            std::string strFile = (*mi).first;
            int nRefCount = (*mi).second;
            logging::LogPrintf("%s refcount=%d\n", strFile.c_str(), nRefCount);
            if (nRefCount == 0) {
                // Move log data to the dat file
                CloseDb(strFile);
                logging::LogPrintf("%s checkpoint\n", strFile.c_str());
                dbenv.txn_checkpoint(0, 0, 0);
                if (!dbparam::IsChainFile(strFile) || fDetachDB) {
                    logging::LogPrintf("%s detach\n", strFile.c_str());
                    if (!fMockDb) {
                        dbenv.lsn_reset(strFile.c_str(), 0);
                    }
                }
                logging::LogPrintf("%s closed\n", strFile.c_str());
                mapFileUseCount.erase(mi++);
            } else {
                ++mi;
            }
        }

        logging::LogPrintf("DBFlush(%s)%s ended %15" PRId64 "ms\n", args_bool::fShutdown ? "true" : "false", fDbEnvInit ? "" : " db not started", util::GetTimeMillis() - nStart);
        if (args_bool::fShutdown) {
            char **listp;
            if (mapFileUseCount.empty()) {
                dbenv.log_archive(&listp, DB_ARCH_REMOVE);
                Close();
            }
        }
    }
}
#endif // USE_BERKELEYDB

//////////////////////////////////////////////////////////////////////////////////////////////
// CLevelDBEnv class
//////////////////////////////////////////////////////////////////////////////////////////////

#ifdef USE_LEVELDB
CLevelDBEnv::CLevelDBEnv(std::vector<std::string> instIn) : fLevelDbEnvInit(false), instance(instIn) {
    LOCK(cs_leveldb);
    this->options = CLevelDBEnv::GetOptions();
}

CLevelDBEnv::~CLevelDBEnv() {
    EnvShutdown();
}

void CLevelDBEnv::EnvShutdown() {
    LOCK(cs_leveldb);
    if(! fLevelDbEnvInit)
        return;

    for(auto &ite: lobj) {
        delete ite.second->ptxdb;
        delete ite.second;
    }
    lobj.clear();

    delete options.block_cache;
    options.block_cache = nullptr;

    delete options.filter_policy;
    options.filter_policy = nullptr;

    debugcs::instance() << "CLevelDBEnv::EnvShutdown() global instance all delete" << debugcs::endl();
}

leveldb::Options CLevelDBEnv::GetOptions() {
    LOCK(cs_leveldb);
    leveldb::Options options;
    const int nCacheSizeMB = map_arg::GetArgInt("-dbcache", IDBEnv::dbcache_size);

    options.block_cache = leveldb::NewLRUCache(nCacheSizeMB * 1048576);
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);
    if(!options.block_cache || !options.filter_policy)
        throw std::runtime_error("leveldb GetOptions(): failure");

    options.create_if_missing = true;
    return options;
}

bool CLevelDBEnv::Open(fs::path pathEnv_) {
    LOCK(cs_leveldb);
    if (fLevelDbEnvInit)
        return true;
    if (args_bool::fShutdown)
        return false;

    pathEnv = pathEnv_;
    for(size_t i=0; i<instance.size(); ++i) {
        // First time init.
        fs::path directory = pathEnv_ / instance[i];

        if(! fsbridge::dir_create(directory))
            throw std::runtime_error("CLevelDBEnv::Open(): dir create failure");

        leveldb_object *ptarget = new (std::nothrow) leveldb_object;
        if(! ptarget)
            throw std::runtime_error("CLevelDBEnv::Open(): out of memory");

        logging::LogPrintf("Opening LevelDB in %s\n", directory.string().c_str());
        leveldb::Status status = leveldb::DB::Open(this->options, directory.string(), &ptarget->ptxdb);
        if (! status.ok())
            throw std::runtime_error(tfm::format("CLevelDBEnv::Open(): error opening database environment %s", status.ToString().c_str()));

        lobj.insert(std::make_pair(instance[i], ptarget));
    }

    fLevelDbEnvInit = true;
    return true;
}

void CLevelDBEnv::Close() {
    Flush(args_bool::fShutdown);
    EnvShutdown();
}

bool CLevelDBEnv::Flush(const std::string &strDb) {
    LOCK3(cs_leveldb, lobj[strDb]->cs_ldb, lobj[strDb]->cs_iterator);
    CloseDb(strDb);
    fs::path directory = pathEnv / strDb;
    leveldb::Status status = leveldb::DB::Open(this->options, directory.string(), &lobj[strDb]->ptxdb);
    if(! status.ok())
        throw std::runtime_error(tfm::format("CLevelDBEnv::Flush(): error opening database environment %s", status.ToString().c_str()));
    return true;
}

void CLevelDBEnv::Flush(bool fShutdown) {
    (void)fShutdown;
    LOCK(cs_leveldb);
    for(auto &ite: lobj) {
        if(! Flush(ite.first))
            return;
    }
}

void CLevelDBEnv::CloseDb(const std::string &strDb) {
    LOCK(cs_leveldb);
    delete lobj[strDb]->ptxdb;
    lobj[strDb]->ptxdb = nullptr;
}

bool CLevelDBEnv::RemoveDb(const std::string &strDb) {
    LOCK(cs_leveldb);
    CloseDb(strDb);
    lobj.erase(strDb);
    return true;
}
#endif // USE_LEVELDB

//////////////////////////////////////////////////////////////////////////////////////////////
// CSqliteDBEnv class
//////////////////////////////////////////////////////////////////////////////////////////////

CSqliteDBEnv::CSqliteDBEnv(std::vector<std::string> instIn) : instance(instIn) {}

CSqliteDBEnv::~CSqliteDBEnv() {
    EnvShutdown();
}

void CSqliteDBEnv::EnvShutdown() {
    LOCK(cs_sqlite);
    for(const auto &ite: sqlobj) {
        if(ite.second->psql) {
            ::sqlite3_close(ite.second->psql);
        }
        delete ite.second;
    }
    sqlobj.clear();
}

bool CSqliteDBEnv::Open(fs::path pathEnv_) {
    LOCK(cs_sqlite);
    pathEnv = pathEnv_;
    for(const auto &ite: instance) {
        fs::path path_ = pathEnv_ / ite;
        sqlite_object *sobj = new(std::nothrow) sqlite_object;
        if(! sobj) {
            EnvShutdown();
            throw std::runtime_error("CSqliteDBEnv::Open memory allocate failure");
        }
#ifdef VSTREAM_INMEMORY_MODE
        if(::sqlite3_open(":memory:", &sobj->psql)!=SQLITE_OK) {
            EnvShutdown();
            throw std::runtime_error("CSqliteDBEnv::Open Sqlite Object open failure");
        }
#else
        if(::sqlite3_open(path_.string().c_str(), &sobj->psql)!=SQLITE_OK) {
            EnvShutdown();
            throw std::runtime_error("CSqliteDBEnv::Open Sqlite Object open failure");
        }
#endif

        sqlobj.insert(std::make_pair(ite, sobj));
        if(is_table_exists(ite, std::string("key_value"))==false) {
            const std::string sql_cmd("create table key_value (key blob primary key, value blob not null);"); // sql const object: no necessary placeholder
            if(! sql(ite, sql_cmd)) {
                EnvShutdown();
                throw std::runtime_error("CSqliteDBEnv::Open Sqlite key_value table create failure");
            }
        }
    }
    return true;
}

bool CSqliteDBEnv::is_table_exists(const std::string &strFile, const std::string &table_name) {
    table_check tc(table_name);
    const std::string sql_cmd("select name from sqlite_master where type='table';"); // sql const object: no necessary placeholder
    char *error;
    bool ret = (::sqlite3_exec(sqlobj[strFile]->psql, sql_cmd.c_str(), m_tablenamecheck_callback, &tc, &error)==SQLITE_OK);
    return ret && tc.exists;
}

void CSqliteDBEnv::Close() {
    LOCK(cs_sqlite);
    Flush(args_bool::fShutdown);
    EnvShutdown();
}

bool CSqliteDBEnv::Flush(const std::string &strFile) {
    //LOCK3(cs_sqlite, sqlobj[strFile]->cs_sql, sqlobj[strFile]->cs_iterator);
    //if(args_bool::fShutdown)
    //    return true;

    LOCK2(cs_sqlite, sqlobj[strFile]->cs_sql);
    ::sqlite3_db_cacheflush(sqlobj[strFile]->psql); // this is bool, therefore exactly due to flush, database stopped then resume (except using iterator).

    /*
    if(sqlobj[strFile]->fUsingIterator)
        return true;

    if(::sqlite3_close(sqlobj[strFile]->psql)!=SQLITE_OK)
        return false;

    fs::path strPath = pathEnv / strFile;
    if(::sqlite3_open(strPath.string().c_str(), &sqlobj[strFile]->psql)!=SQLITE_OK) {
        EnvShutdown();
        throw std::runtime_error("CSqliteDBEnv::Flush Sqlite Object open failure");
    }
    */
    return true;
}

void CSqliteDBEnv::Flush(bool fShutdown) {
    (void)fShutdown;
    LOCK(cs_sqlite);
    for(const auto &ite: sqlobj) {
        if(! Flush(ite.first))
            return;
    }
}

void CSqliteDBEnv::CloseDb(const std::string &strFile) {
    LOCK(cs_sqlite);
    Flush(strFile);
    ::sqlite3_close(sqlobj[strFile]->psql);
    sqlobj[strFile]->psql = nullptr;
}

bool CSqliteDBEnv::RemoveDb(const std::string &strFile) {
    LOCK(cs_sqlite);
    CloseDb(strFile);
    sqlobj.erase(strFile);
    return true;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// CDB class
//////////////////////////////////////////////////////////////////////////////////////////////

#ifdef USE_BERKELEYDB
CDB::CDB(const char *pszFile, const char *pszMode/*="r+"*/) : pdb(nullptr), activeTxn(nullptr) {
    LOCK(CDBEnv::cs_db);
    if (pszFile == nullptr)
        return;

    fReadOnly = (!::strchr(pszMode, '+') && !::strchr(pszMode, 'w'));
    bool fCreate = ::strchr(pszMode, 'c') != nullptr;
    unsigned int nFlags = DB_THREAD;
    if (fCreate)
        nFlags |= DB_CREATE;

    {
        LOCK(CDBEnv::cs_db);
        strFile = pszFile;
        pdb = CDBEnv::get_instance().Create(strFile, nFlags);
        if (fCreate && !Exists(std::string("version"))) {
            bool fTmp = fReadOnly;
            fReadOnly = false;
            WriteVersion(version::CLIENT_VERSION);
            fReadOnly = fTmp;
        }
    }
}

CDB::~CDB() {
    Close();
}

void CDB::Close() {
    LOCK(CDBEnv::cs_db);
    if (! pdb)
        return;
    if (activeTxn)
        activeTxn->abort();

    activeTxn = nullptr;
    pdb = nullptr;

    // Flush database activity from memory pool to disk log
    unsigned int nMinutes = 0;
    if (fReadOnly)
        nMinutes = 1;
    //if (dbparam::IsChainFile(strFile))
    //    nMinutes = 2;
    //if (dbparam::IsChainFile(strFile) && block_notify<HASH>::IsInitialBlockDownload())
    //    nMinutes = 5;

    CDBEnv::get_instance().TxnCheckPoint(nMinutes ? map_arg::GetArgUInt("-dblogsize", 100) * 1024 : 0, nMinutes);
    CDBEnv::get_instance().DecUseCount(strFile);
}
#endif // USE_BERKELEYDB

// fFlags(BDB): DB_SET_RANGE, DB_NEXT, DB_NEXT, ...
int CSqliteDB::ReadAtCursor(const DbIterator &pcursor, CDBStream &ssKey, CDBStream &ssValue, unsigned int fFlags /*= DB_NEXT*/) {
    auto sqldb = [&]() {
        //if (fFlags == DB_SET || fFlags == DB_SET_RANGE || fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE) {
            // no statement
        //}
        //if (fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE) {
            // no statement
        //}

        sqlite3_stmt *stmt = (sqlite3_stmt *)pcursor;
        int ret;
        if((ret=::sqlite3_step(stmt)) == SQLITE_ROW) {
            const char *pkey = reinterpret_cast<const char *>(::sqlite3_column_blob(stmt, 0));
            const int keysize = ::sqlite3_column_bytes(stmt, 0) / sizeof(char);
            const char *pvalue = reinterpret_cast<const char *>(::sqlite3_column_blob(stmt, 1));
            const int valuesize = ::sqlite3_column_bytes(stmt, 1) / sizeof(char);

            try {
                if(ssKey.data()!=(char *)0) {
                    ssKey.clear();
                    ssKey.write(pkey, keysize);
                }
                if(ssValue.data()!=(char *)0) {
                    ssValue.clear();
                    ssValue.write(pvalue, valuesize);
                }
            } catch (const std::exception &) {
                throw std::runtime_error("CSqliteDB::ReadAtCursor memory allocate failure");
            }
        }
        if(ret==SQLITE_DONE)
            return DB_NOTFOUND;

        return 0;
    };
    LOCK(pcursor.get_cs());
    (void)fFlags;
    return sqldb();
}

int CSqliteDB::IgnoreAtCursor(const DbIterator &pcursor) {
    auto sqldb = [&]() {
        sqlite3_stmt *stmt = (sqlite3_stmt *)pcursor;
        int ret;
        if((ret=::sqlite3_step(stmt)) == SQLITE_ROW) {
            // no statement
        } else
            return 99999;
        if(ret==SQLITE_DONE)
            return DB_NOTFOUND;

        return 0;
    };
    LOCK(pcursor.get_cs());
    return sqldb();
}

int IDB::ReadAtCursor(const DbIterator &pcursor, CDataStream &ssKey, CDataStream &ssValue, unsigned int fFlags /*= DB_NEXT*/) {
#ifdef USE_LEVELDB
    auto ldb = [&]() {
        //if (fFlags == DB_SET || fFlags == DB_SET_RANGE || fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE) {
            // no statement
        //}
        //if (fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE) {
            // no statement
        //}

        leveldb::Iterator *ite = (leveldb::Iterator *)pcursor;
        if(ite->Valid()==false)
            return DB_NOTFOUND;

        ssKey.SetType(SER_DISK);
        ssKey.clear();
        ssKey.write((char *)ite->key().data(), ite->key().size());
        ssValue.SetType(SER_DISK);
        ssValue.clear();
        ssValue.write((char *)ite->value().data(), ite->value().size());

        cleanse::OPENSSL_cleanse(const_cast<char *>(ite->key().data()), ite->key().size());
        cleanse::OPENSSL_cleanse(const_cast<char *>(ite->value().data()), ite->value().size());
        ite->Next();
        return ite->Valid() ? 0: DB_NOTFOUND;
    };
#endif
#ifdef USE_BERKELEYDB
    auto bdb = [&]() {
        Dbt datKey;
        if (fFlags == DB_SET || fFlags == DB_SET_RANGE || fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE) {
            datKey.set_data(&ssKey[0]);
            datKey.set_size((uint32_t)ssKey.size());
        }

        Dbt datValue;
        if (fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE) {
            datValue.set_data(&ssValue[0]);
            datValue.set_size((uint32_t)ssValue.size());
        }

        datKey.set_flags(DB_DBT_MALLOC);
        datValue.set_flags(DB_DBT_MALLOC);
        int ret = ((Dbc *)pcursor)->get(&datKey, &datValue, fFlags);
        if (ret != 0)
            return ret;
        else if (datKey.get_data() == nullptr || datValue.get_data() == nullptr)
            return 99999;

        // Convert to streams
        ssKey.SetType(SER_DISK);
        ssKey.clear();
        ssKey.write((char *)datKey.get_data(), datKey.get_size());
        ssValue.SetType(SER_DISK);
        ssValue.clear();
        ssValue.write((char *)datValue.get_data(), datValue.get_size());

        // Clear and free memory
        cleanse::OPENSSL_cleanse(datKey.get_data(), datKey.get_size());
        cleanse::OPENSSL_cleanse(datValue.get_data(), datValue.get_size());
        ::free(datKey.get_data());
        ::free(datValue.get_data());
        return 0;
    };
#endif
    auto sqldb = [&]() {
        //if (fFlags == DB_SET || fFlags == DB_SET_RANGE || fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE) {
            // no statement
        //}
        //if (fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE) {
            // no statement
        //}

        sqlite3_stmt *stmt = (sqlite3_stmt *)pcursor;
        int ret;
        if((ret=::sqlite3_step(stmt)) == SQLITE_ROW) {
            const char *pkey = reinterpret_cast<const char *>(::sqlite3_column_blob(stmt, 0));
            const int keysize = ::sqlite3_column_bytes(stmt, 0) / sizeof(char);
            const char *pvalue = reinterpret_cast<const char *>(::sqlite3_column_blob(stmt, 1));
            const int valuesize = ::sqlite3_column_bytes(stmt, 1) / sizeof(char);

            try {
                ssKey.SetType(SER_DISK);
                ssKey.clear();
                ssKey.write(pkey, keysize);
                ssValue.SetType(SER_DISK);
                ssValue.clear();
                ssValue.write(pvalue, valuesize);
            } catch (const std::exception &) {
                cleanse::OPENSSL_cleanse(const_cast<char *>(pkey), keysize);
                cleanse::OPENSSL_cleanse(const_cast<char *>(pvalue), valuesize);
                throw std::runtime_error("IDB::ReadAtCursor memory allocate failure");
            }

            cleanse::OPENSSL_cleanse(const_cast<char *>(pkey), keysize);
            cleanse::OPENSSL_cleanse(const_cast<char *>(pvalue), valuesize);
        }
        if(ret==SQLITE_DONE)
            return DB_NOTFOUND;

        return 0;
    };
    LOCK(pcursor.get_cs());
#if defined(USE_BERKELEYDB) && defined(USE_LEVELDB)
    if(pcursor.is_bdb())
        return bdb();
    else if(pcursor.is_leveldb())
        return ldb();
    else if(pcursor.is_sqlite())
        return sqldb();
    else
        return 99999;
#elif defined(USE_BERKELEYDB)
    if(pcursor.is_bdb())
        return bdb();
    else if(pcursor.is_sqlite())
        return sqldb();
    else
        return 99999;
#elif defined(USE_LEVELDB)
    if(pcursor.is_leveldb())
        return ldb();
    else if(pcursor.is_sqlite())
        return sqldb();
    else
        return 99999;
#else
    if(pcursor.is_sqlite())
        return sqldb();
    else
        return 99999;
#endif
}

bool CSqliteDB::PortToSqlite(DbIterator ite, migrate type) {
    if(type==MIGRATE_WALLET) { // wallet (BDB to SQLite)
        // if exists "minversion", already port completed. therefore, skip PortToSqlite.
        LOCK(cs_db);
        const std::string tykey("minversion");
        int tyValue;
        bool version_ret = Read(tykey, tyValue);
        debugcs::instance() << "portToSqlite minversion version_ret(bool): " << version_ret << debugcs::endl();
        if(version_ret)
            return true;
    }
    else if (type==MIGRATE_BLOCKCHAIN) { // Blockchain (LevelDB to SQLite)
        // if exists "hashGenesisChain", already port completed. therefore, skip PortToSqlite.
        LOCK(cs_db);
        const std::string tykey("hashBestChain");
        uint256 tyValue;
        bool hash_ret = Read(tykey, tyValue);
        debugcs::instance() << "portToSqlite hashBestChain hash_ret(bool): " << hash_ret << debugcs::endl();
        if(hash_ret)
            return true;
        // cleanse
        char *err;
        if(::sqlite3_exec(pdb, "delete from key_value;", nullptr, nullptr, &err)!=SQLITE_OK)
            return false;
    }
    else
        return false;

    sqlite3_stmt *stmt=nullptr;
    bool result = false;
    for(;;) {
        CDataStream ssKey;
        ssKey.reserve(1000);
        CDataStream ssValue;
        ssValue.reserve(10000);
        int ret = IDB::ReadAtCursor(ite, ssKey, ssValue);
        //debugcs::instance() << "PortToSqlite ret: " << ret << debugcs::endl();
        if(ret==DB_NOTFOUND) {
            result = true;
            break;
        }
        if(ret!=0)
            break;
        if(::sqlite3_prepare_v2(pdb, "insert into key_value (key, value) values ($1, $2);", -1, &stmt, nullptr)!=SQLITE_OK) break;
        if(::sqlite3_bind_blob(stmt, 1, &ssKey[0], ssKey.size(), SQLITE_STATIC)!=SQLITE_OK) break;
        if(::sqlite3_bind_blob(stmt, 2, &ssValue[0], ssValue.size(), SQLITE_STATIC)!=SQLITE_OK) break;
        if(::sqlite3_step(stmt)!=SQLITE_DONE) break;
        if(::sqlite3_finalize(stmt)!=SQLITE_OK) break;
        stmt=nullptr;
    }
    if(!result && stmt)
        ::sqlite3_finalize(stmt);
    return result;
}

#ifdef USE_BERKELEYDB
bool CDB::TxnBegin() {
    LOCK(CDBEnv::cs_db);
    if (!pdb || activeTxn)
        return false;

    DbTxn *ptxn = CDBEnv::get_instance().TxnBegin();
    if (! ptxn)
        return false;

    activeTxn = ptxn;
    return true;
}

bool CDB::TxnCommit() {
    LOCK(CDBEnv::cs_db);
    if (!pdb || !activeTxn)
        return false;

    int ret = activeTxn->commit(0);
    activeTxn = nullptr;
    return (ret == 0);
}

bool CDB::TxnAbort() {
    LOCK(CDBEnv::cs_db);
    if (!pdb || !activeTxn)
        return false;

    int ret = activeTxn->abort();
    activeTxn = nullptr;
    return (ret == 0);
}

bool CDB::ReadVersion(int &nVersion) {
    LOCK(CDBEnv::cs_db);
    nVersion = 0;
    return Read(std::string("version"), nVersion);
}

bool CDB::WriteVersion(int nVersion) {
    LOCK(CDBEnv::cs_db);
    return Write(std::string("version"), nVersion);
}

IDB::DbIterator CDB::GetIteCursor() {
    LOCK(CDBEnv::cs_db);
    if (! pdb)
        return std::move(DbIterator());

    Dbc *pcursor = nullptr;
    int ret = pdb->cursor(nullptr, &pcursor, 0);
    if (ret != 0)
        pcursor = nullptr;

    return std::move(DbIterator(std::move(pcursor), &CDBEnv::cs_db));
}

#ifndef WALLET_SQL_MODE
bool CDB::Rewrite(const std::string &strFile, const char *pszSkip/* = nullptr */)
{
    while (! args_bool::fShutdown)
    {
        {
            LOCK(CDBEnv::cs_db);
            if (!CDBEnv::get_instance().ExistsFileCount(strFile) || CDBEnv::get_instance().GetFileCount(strFile)==0) {
                // Flush log data to the dat file
                CDBEnv::get_instance().CloseDb(strFile);
                CDBEnv::get_instance().CheckpointLSN(strFile);
                CDBEnv::get_instance().EraseFileCount(strFile);

                bool fSuccess = true;
                logging::LogPrintf("Rewriting %s...\n", strFile.c_str());
                std::string strFileRes = strFile + ".rewrite";

                { // surround usage of db with extra {}
                    CDB db(strFile.c_str(), "r");
                    std::unique_ptr<Db> pdbCopy = CDBEnv::get_instance().TempCreate(nullptr, strFileRes, DB_CREATE);
                    if(pdbCopy.get() == nullptr) {
                        logging::LogPrintf("Cannot create database file %s\n", strFileRes.c_str());
                        fSuccess = false;
                    }

                    //Dbc *pcursor = db.GetCursor();
                    IDB::DbIterator ite = db.GetIteCursor();
                    //if (pcursor) {
                    if (ite.is_ok()) {
                        while (fSuccess)
                        {
                            CDataStream ssKey(SER_DISK, version::CLIENT_VERSION);
                            CDataStream ssValue(SER_DISK, version::CLIENT_VERSION);
                            //int ret = db.ReadAtCursor(pcursor, ssKey, ssValue, DB_NEXT);
                            int ret = db.ReadAtCursor(ite, ssKey, ssValue, DB_NEXT);
                            if (ret == DB_NOTFOUND) {
                                //pcursor->close();
                                break;
                            } else if (ret != 0) {
                                //pcursor->close();
                                fSuccess = false;
                                break;
                            }

                            if (pszSkip != nullptr) {
                                size_t pszSkipLen = strlen(pszSkip);
                                if (::strncmp(&ssKey[0], pszSkip, std::min(ssKey.size(), pszSkipLen)) == 0) {
                                    continue;
                                }
                            }

                            if (::strncmp(&ssKey[0], "\x07version", 8) == 0) {
                                // Update version:
                                ssValue.clear();
                                ssValue << version::CLIENT_VERSION;
                            }

                            Dbt datKey(&ssKey[0], ssKey.size());
                            Dbt datValue(&ssValue[0], ssValue.size());
                            int ret2 = pdbCopy->put(nullptr, &datKey, &datValue, DB_NOOVERWRITE);
                            if (ret2 > 0) {
                                fSuccess = false;
                            }
                        }
                    }
                    if (fSuccess) {
                        db.Close();
                        CDBEnv::get_instance().CloseDb(strFile);
                        ite.setnull();
                        if (pdbCopy->close(0)) {
                            fSuccess = false;
                        }
                    }
                }
                if (fSuccess) {
                    fSuccess = CDBEnv::get_instance().Remove(strFile);
                    fSuccess = CDBEnv::get_instance().Rename(strFileRes, strFile);
                }
                if (! fSuccess) {
                    logging::LogPrintf("Rewriting of %s FAILED!\n", strFileRes.c_str());
                }
                return fSuccess;
            }
        }
        util::Sleep(100);
    }
    return false;
}
#endif
#endif // USE_BERKELEYDB

//////////////////////////////////////////////////////////////////////////////////////////////
// CLevelDB class
//////////////////////////////////////////////////////////////////////////////////////////////

#ifdef USE_LEVELDB
namespace {
class CBatchScanner final : public leveldb::WriteBatch::Handler
{
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

bool CLevelDB::ScanBatch(const CDBStream &key, std::string *value, bool *deleted) const {
    LOCK(cs_db);
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

CLevelDB::CLevelDB(const std::string &strDb, const char *pszMode /*="r+"*/, bool fSecureIn /*= false*/) :
    pdb(CLevelDBEnv::get_instance().get_ptxdb(strDb)), cs_db(CLevelDBEnv::get_instance().get_rcs(strDb)), cs_iterator(CLevelDBEnv::get_instance().get_rcs_ite(strDb)), fReadOnly(true), p(nullptr) {
    assert(pszMode);
    fSecure = fSecureIn;

    this->activeBatch = nullptr;
    fReadOnly = (!::strchr(pszMode, '+') && !::strchr(pszMode, 'w'));
}

CLevelDB::~CLevelDB() {
    Close();
}

IDB::DbIterator CLevelDB::GetIteCursor() {
    LOCK(cs_db);
    leveldb::Iterator *p = pdb->NewIterator(leveldb::ReadOptions());
    if(! p)
        throw std::runtime_error("CLevelDB::GetIteCursor memory allocate failure");
    p->SeekToFirst();
    return std::move(DbIterator(std::move(p), &cs_db));
}

void CLevelDB::Close() {
    LOCK(cs_db);
    delete this->activeBatch;
    this->activeBatch = nullptr;

    // p is no necessary delete. because delete by const_iterator.
    //debugcs::instance() << "CLevelDB::Close()" << debugcs::endl();
}

bool CLevelDB::TxnBegin() {
    LOCK(cs_db);
    assert(fSecure==false);
    assert(! this->activeBatch);
    ENTER_CRITICAL_SECTION(cs_iterator);
    this->activeBatch = new(std::nothrow) leveldb::WriteBatch();
    if (! this->activeBatch) {
        throw std::runtime_error("LevelDB : WriteBatch failed to allocate memory");
        return false;
    }
    return true;
}

bool CLevelDB::TxnCommit() {
    LOCK(cs_db);
    assert(fSecure==false);
    assert(this->activeBatch);

    leveldb::Status status = pdb->Write(leveldb::WriteOptions(), activeBatch);
    delete this->activeBatch;
    this->activeBatch = nullptr;

    if (! status.ok()) {
        logging::LogPrintf("LevelDB batch commit failure: %s\n", status.ToString().c_str());
        LEAVE_CRITICAL_SECTION(cs_iterator);
        return false;
    }
    LEAVE_CRITICAL_SECTION(cs_iterator);
    return true;
}

bool CLevelDB::TxnAbort() {
    LOCK(cs_db);
    assert(fSecure==false);
    delete this->activeBatch;
    this->activeBatch = nullptr;
    LEAVE_CRITICAL_SECTION(cs_iterator);
    return true;
}

bool CLevelDB::ReadVersion(int &nVersion) {
    LOCK(cs_db);
    nVersion = 0;
    return Read(std::string("version"), nVersion);
}

bool CLevelDB::WriteVersion(int nVersion) {
    LOCK(cs_db);
    return Write(std::string("version"), nVersion);
}
#endif // USE_LEVELDB

//////////////////////////////////////////////////////////////////////////////////////////////
// CSqliteDB class
// like key value store database.
//////////////////////////////////////////////////////////////////////////////////////////////

CSqliteDB::CSqliteDB(const std::string &strFile, const char *pszMode /*= "r+"*/, bool fSecureIn /*= false*/) :
    pdb(CSqliteDBEnv::get_instance().get_psqldb(strFile)), cs_db(CSqliteDBEnv::get_instance().get_rcs(strFile)),
    cs_iterator(CSqliteDBEnv::get_instance().get_rcs_ite(strFile)), txn(nullptr), fUsingIterator(CSqliteDBEnv::get_instance().get_using_ite(strFile)) {
    fSecure = fSecureIn;

    fReadOnly = (!::strchr(pszMode, '+') && !::strchr(pszMode, 'w'));
}
CSqliteDB::~CSqliteDB() {
    Close();
}

IDB::DbIterator CSqliteDB::GetIteCursor() {
    LOCK(cs_db);
    ENTER_CRITICAL_SECTION(cs_iterator);
    fUsingIterator = true;
    sqlite3_stmt *stmt;
    if(::sqlite3_prepare_v2(pdb, "select * from key_value;", -1, &stmt, nullptr)!=SQLITE_OK) {
        fUsingIterator = false;
        LEAVE_CRITICAL_SECTION(cs_iterator);
        throw std::runtime_error("CSqliteDB::GetIteCursor prepair failure");
    }
    return std::move(IDB::DbIterator(std::move(stmt), &cs_db, &cs_iterator, &fUsingIterator));
}

IDB::DbIterator CSqliteDB::GetIteCursor(std::string mkey, bool asc/*=true*/) {
    LOCK(cs_db);
    ENTER_CRITICAL_SECTION(cs_iterator);
    fUsingIterator = true;
    sqlite3_stmt *stmt;
    if(asc) {
        if(::sqlite3_prepare_v2(pdb, "select * from key_value where key like $1 order by key asc;", -1, &stmt, nullptr)!=SQLITE_OK) {
            fUsingIterator = false;
            LEAVE_CRITICAL_SECTION(cs_iterator);
            throw std::runtime_error("CSqliteDB::GetIteCursor prepair failure");
        }
    } else {
        if(::sqlite3_prepare_v2(pdb, "select * from key_value where key like $1;", -1, &stmt, nullptr)!=SQLITE_OK) {
            fUsingIterator = false;
            LEAVE_CRITICAL_SECTION(cs_iterator);
            throw std::runtime_error("CSqliteDB::GetIteCursor prepair failure");
        }
    }
    if(::sqlite3_bind_blob(stmt, 1, (const char *)mkey.c_str(), mkey.size(), SQLITE_TRANSIENT)!=SQLITE_OK) {
        ::sqlite3_finalize(stmt);
        fUsingIterator = false;
        LEAVE_CRITICAL_SECTION(cs_iterator);
        throw std::runtime_error("CSqliteDB::GetIteCursor prepair failure");
    }
    return std::move(IDB::DbIterator(std::move(stmt), &cs_db, &cs_iterator, &fUsingIterator));
}

void CSqliteDB::Close() {
    if(txn) {
        delete txn;
        txn = nullptr;
    }
}

//
// Sqlite: About Txn, Only Secure and Write
// using: mainly wallet crypto
//
bool CSqliteDB::TxnBegin() {
    LOCK(cs_db);
    assert(txn==nullptr);
    //assert(fSecure);
    txn = new(std::nothrow) CTxnSecureBuffer;
    return txn != nullptr;
}

bool CSqliteDB::TxnCommit() {
    /*
    auto dummy_writer = [&](const CTxnSecureBuffer::secure_keyvalue &data) {
        //
        // Note: After writing dummy random data (same size), update value.
        //
        bool result = false;
        sqlite3_stmt *stmt;
        do {
            if(::sqlite3_prepare_v2(pdb, "select value from key_value where key=$1;", -1, &stmt, nullptr)!=SQLITE_OK) break;
            if(::sqlite3_bind_blob(stmt, 1, &data.first[0], data.first.size(), SQLITE_STATIC)!=SQLITE_OK) break;
            if(::sqlite3_step(stmt)!=SQLITE_ROW) break;
            const char *rdata = reinterpret_cast<const char *>(::sqlite3_column_blob(stmt, 0));
            const int rsize = ::sqlite3_column_bytes(stmt, 0);
            cleanse::OPENSSL_cleanse(const_cast<char *>(rdata), rsize);
            if(::sqlite3_step(stmt)!=SQLITE_DONE) break;
            if(::sqlite3_finalize(stmt)!=SQLITE_OK) break;
            std::vector<unsigned char> rbuf;
            try {
                rbuf.resize(rsize);
            } catch (const std::exception &) {
                break;
            }
            //debugcs::instance() << "dummy_writer size: " << rsize << debugcs::endl();
            if(rsize>32)
                cleanse::OPENSSL_cleanse(&rbuf[0], rsize);
            else
                latest_crypto::random::GetStrongRandBytes(&rbuf[0], rsize); // assert(num <= 32);
            if(::sqlite3_prepare_v2(pdb, "update key_value set value=$1 where key=$2;", -1, &stmt, nullptr)!=SQLITE_OK) break;
            if(::sqlite3_bind_blob(stmt, 1, &rbuf[0], rsize, SQLITE_STATIC)!=SQLITE_OK) break;
            if(::sqlite3_bind_blob(stmt, 2, &data.first[0], data.first.size(), SQLITE_STATIC)!=SQLITE_OK) break;
            if(::sqlite3_step(stmt)!=SQLITE_DONE) break;
            if(::sqlite3_finalize(stmt)!=SQLITE_OK) break;

            result = true;
        } while(0);
        if(! result)
            ::sqlite3_finalize(stmt);
        //debugcs::instance() << "dummy_writer result: " << result << debugcs::endl();
        return result;
    };
    */

    LOCK(cs_db);
    assert(txn);
    //assert(fSecure);
    bool fGood = true;
    for(int i=0; i<txn->size(); ++i) {
        bool result = false;
        const auto &target = txn->get(i);
        if(target.first==CTxnSecureBuffer::TXN_READ) {
            assert(!"TXN_READ unsupported");
            throw std::runtime_error("TXN_READ unsupported");
        }
        else if(target.first==CTxnSecureBuffer::TXN_WRITE_UPDATE) {
            const auto &data = target.second; // data.first: key, data.second: value
            sqlite3_stmt *stmt;
            do {
                //if(! dummy_writer(data)) break;
                if(::sqlite3_prepare_v2(pdb, "update key_value set value=$1 where key=$2;", -1, &stmt, nullptr)!=SQLITE_OK) break;
                if(::sqlite3_bind_blob(stmt, 1, &data.second[0], data.second.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                if(::sqlite3_bind_blob(stmt, 2, &data.first[0], data.first.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                if(::sqlite3_step(stmt)!=SQLITE_DONE) break;
                if(::sqlite3_finalize(stmt)!=SQLITE_OK) break;

                result = true;
            } while(0);
            if(! result)
                ::sqlite3_finalize(stmt);
        }
        else if(target.first==CTxnSecureBuffer::TXN_ERASE) {
            const auto &data = target.second; // data.first: key, data.second: value
            sqlite3_stmt *stmt;
            do {
                if(::sqlite3_prepare_v2(pdb, "delete from key_value where key=$1;", -1, &stmt, nullptr)!=SQLITE_OK) break;
                if(::sqlite3_bind_blob(stmt, 1, &data.first[0], data.first.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                if(::sqlite3_step(stmt)!=SQLITE_DONE) break;
                if(::sqlite3_finalize(stmt)!=SQLITE_OK) break;

                result = true;
            } while(0);
            if(! result)
                ::sqlite3_finalize(stmt);
        }
        else if(target.first==CTxnSecureBuffer::TXN_WRITE_INSERT) {
            const auto &data = target.second; // data.first: key, data.second: value
            sqlite3_stmt *stmt;
            do {
                if(::sqlite3_prepare_v2(pdb, "insert into key_value (key, value) values ($1, $2);", -1, &stmt, nullptr)!=SQLITE_OK) break;
                if(::sqlite3_bind_blob(stmt, 1, &data.first[0], data.first.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                if(::sqlite3_bind_blob(stmt, 2, &data.second[0], data.second.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                if(::sqlite3_step(stmt)!=SQLITE_DONE) break;
                if(::sqlite3_finalize(stmt)!=SQLITE_OK) break;

                result = true;
            } while(0);
            if(! result)
                ::sqlite3_finalize(stmt);
        }
        else
            throw std::runtime_error("TXN unsupported");

        if(result==false) {
            fGood = false;
            break;
        }
    }
    delete txn;
    txn = nullptr;
    return fGood;
}

bool CSqliteDB::TxnAbort() {
    LOCK(cs_db);
    assert(txn);
    //assert(fSecure);
    delete txn;
    txn = nullptr;
    return true;
}

bool CSqliteDB::ReadVersion(int &nVersion) {
    LOCK(cs_db);
    nVersion = 0;
    return Read(std::string("version"), nVersion);
}

bool CSqliteDB::WriteVersion(int nVersion) {
    LOCK(cs_db);
    return Write(std::string("version"), nVersion);
}

/*
 * Rewrite
 * migrate from old sql to new sql.
 * therefore, remaining deleted data(value) are complete eleminated.
 */
bool CSqliteDBEnv::Rewrite(const std::string &target, const char *pszSkip/*=nullptr*/) { // pszSkip: Serialize data. (e.g. "\x07version")
    assert(sqlobj.count(target)>0);
    LOCK2(CSqliteDBEnv::cs_sqlite, sqlobj[target]->cs_sql);
    fs::path pathsql = iofs::GetDataDir() / fs::path(target);
    pathsql += ".rewrite";
    fs::path pathsrc = iofs::GetDataDir() / target;

    sqlite3 *prw3;
    if(::sqlite3_open(pathsql.string().c_str(), &prw3)!=SQLITE_OK) {
        fs::remove(pathsql);
        return false;
    }

    const std::string sql_cmd("create table key_value (key blob primary key, value blob not null);"); // sql const object: no necessary placeholder
    char *error;
    if(::sqlite3_exec(prw3, sql_cmd.c_str(), nullptr, nullptr, &error)!=SQLITE_OK) {
        ::sqlite3_close(prw3);
        fs::remove(pathsql);
        return false;
    }

    sqlite3_stmt *stmt_src;
    if(::sqlite3_prepare_v2(sqlobj[target]->psql, "select * from key_value;", -1, &stmt_src, nullptr)!=SQLITE_OK) {
        ::sqlite3_close(prw3);
        fs::remove(pathsql);
        return false;
    }
    int ret;
    bool result = true;
    while((ret=::sqlite3_step(stmt_src))==SQLITE_ROW) {
        const char *key_data = nullptr;
        int key_size = 0;
        const char *value_data = nullptr;
        int value_size = 0;
        do {
            key_data = reinterpret_cast<const char *>(::sqlite3_column_blob(stmt_src, 0));
            key_size = ::sqlite3_column_bytes(stmt_src, 0);
            if(pszSkip) {
                if(std::strncmp(pszSkip, key_data, std::min((int)std::strlen(pszSkip), key_size))==0)
                    break;
            }
            value_data = reinterpret_cast<const char *>(::sqlite3_column_blob(stmt_src, 1));
            value_size = ::sqlite3_column_bytes(stmt_src, 1);
            sqlite3_stmt *stmt_dest;
            if(::sqlite3_prepare_v2(prw3, "insert into key_value (key, value) values ($1, $2);", -1, &stmt_dest, nullptr)!=SQLITE_OK) {result=false; break;}
            if(::sqlite3_bind_blob(stmt_dest, 1, key_data, key_size, SQLITE_STATIC)!=SQLITE_OK) {result=false; ::sqlite3_finalize(stmt_dest); break;}
            if(::sqlite3_bind_blob(stmt_dest, 2, value_data, value_size, SQLITE_STATIC)!=SQLITE_OK) {result=false; ::sqlite3_finalize(stmt_dest); break;}
            if(::sqlite3_step(stmt_dest)!=SQLITE_DONE) {result=false; ::sqlite3_finalize(stmt_dest); break;}
            if(::sqlite3_finalize(stmt_dest)!=SQLITE_OK) {result=false; break;}
        } while(0);
        cleanse::OPENSSL_cleanse(const_cast<char *>(key_data), key_size);
        cleanse::OPENSSL_cleanse(const_cast<char *>(value_data), value_size);
        if(! result) break;
    }
    if(!result || ret!=SQLITE_DONE) {
        ::sqlite3_finalize(stmt_src);
        ::sqlite3_close(prw3);
        fs::remove(pathsql);
        return false;
    }

    if(::sqlite3_finalize(stmt_src)!=SQLITE_OK) {
        ::sqlite3_close(prw3);
        fs::remove(pathsql);
        return false;
    }
    if(::sqlite3_close(prw3)!=SQLITE_OK) {
        fs::remove(pathsql);
        return false;
    }

    // rewrite and restart
    // note that even if error, restart splobj[target]->psql.
    if(::sqlite3_close(sqlobj[target]->psql)!=SQLITE_OK) {
        fs::remove(pathsql);
        return false;
    }
    fs::remove(pathsrc);

    if(! fsbridge::file_rename(pathsql, pathsrc))
        return false;

    return ::sqlite3_open(pathsrc.string().c_str(), &sqlobj[target]->psql)==SQLITE_OK;
}
