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
#include <boost/filesystem/fstream.hpp>
#include <util/time.h>

#ifndef WIN32
# include "sys/stat.h"
#endif

unsigned int dbparam::nWalletDBUpdated = 0;

void CDBEnv::EnvShutdown() {
    LOCK(cs_db);
    if (! fDbEnvInit)
        return;

    fDbEnvInit = false;
    int ret = dbenv.close(0);
    if (ret != 0)
        logging::LogPrintf("EnvShutdown exception: %s (%d)\n", DbEnv::strerror(ret), ret);
    if (! fMockDb)
        DbEnv(0).remove(strPath.c_str(), 0);
}

CDBEnv::CDBEnv() : fDetachDB(false), fDbEnvInit(false), fMockDb(false), dbenv(DB_CXX_NO_EXCEPTIONS) {}
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
    if (fDbEnvInit)
        return true;
    if (args_bool::fShutdown)
        return false;

    // create directory and db.log
    pathEnv = pathEnv_;
    fs::path pathDataDir = pathEnv;

    strPath = pathDataDir.string();
    fs::path pathLogDir = pathDataDir / "database";
    fs::create_directory(pathLogDir);

    fs::path pathErrorFile = pathDataDir / "db.log";
    logging::LogPrintf("dbenv.open LogDir=%s ErrorFile=%s\n", pathLogDir.string().c_str(), pathErrorFile.string().c_str());

    unsigned int nEnvFlags = 0;
    if (map_arg::GetBoolArg("-privdb", true)) {
        nEnvFlags |= DB_PRIVATE;
    }

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

    int ret = dbenv.open(strPath.c_str(),
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
    fMockDb = false;

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

CDBEnv::VerifyResult CDBEnv::Verify(std::string strFile, bool(* recoverFunc)(CDBEnv &dbenv, std::string strFile))
{
    LOCK(cs_db);
    assert(mapFileUseCount.count(strFile) == 0);

    Db db(&dbenv, 0);
    int result = db.verify(strFile.c_str(), nullptr, nullptr, 0);
    if (result == 0) {
        return VERIFY_OK;
    } else if (recoverFunc == nullptr) {
        return RECOVER_FAIL;
    }

    // Try to recover:
    bool fRecovered = (*recoverFunc)(*this, strFile);
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
    while (!strDump.eof() && strLine != "HEADER=END")
    {
        std::getline(strDump, strLine); // Skip past header
    }

    std::string keyHex, valueHex;
    while (!strDump.eof() && keyHex != "DATA=END")
    {
        std::getline(strDump, keyHex);
        if (keyHex != "DATA=END") {
            std::getline(strDump, valueHex);
#ifdef CSCRIPT_PREVECTOR_ENABLE
            vResult.push_back(std::make_pair(strenc::ParseHex(keyHex).get_std_vector(), strenc::ParseHex(valueHex).get_std_vector()));
#else
            vResult.push_back(std::make_pair(strenc::ParseHex(keyHex), strenc::ParseHex(valueHex)));
#endif
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
    Db *pdb = getDb(strFile);
    if (pdb == nullptr) {
        pdb = createDb();
        if (pdb == nullptr)
            throw std::runtime_error("CDB() : failed to allocate memory");

        bool fMockDb = IsMock();
        if (fMockDb) {
            DbMpoolFile *mpf = pdb->get_mpf();
            int ret = mpf->set_flags(DB_MPOOL_NOFILE, 1);
            if (ret != 0)
                throw std::runtime_error(tfm::format("CDB() : failed to configure for no temp file backing for database %s", strFile.c_str()));
        }

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

        setDb(strFile, pdb);
    }
    return pdb;
}

CDB::CDB(const char *pszFile, const char *pszMode/*="r+"*/) : pdb(nullptr), activeTxn(nullptr)
{
    if (pszFile == nullptr)
        return;

    fReadOnly = (!::strchr(pszMode, '+') && !::strchr(pszMode, 'w'));
    bool fCreate = ::strchr(pszMode, 'c') != nullptr;
    unsigned int nFlags = DB_THREAD;
    if (fCreate)
        nFlags |= DB_CREATE;

    {
        LOCK(CDBEnv::get_instance().cs_db);
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

bool dbparam::IsChainFile(std::string strFile)
{
    return (strFile == "blkindex.dat");
}

void CDB::Close()
{
    if (! pdb) {
        return;
    }
    if (activeTxn) {
        activeTxn->abort();
    }
    activeTxn = nullptr;
    pdb = nullptr;

    //
    // Flush database activity from memory pool to disk log
    //
    unsigned int nMinutes = 0;
    if (fReadOnly) {
        nMinutes = 1;
    }
    if (dbparam::IsChainFile(strFile)) {
        nMinutes = 2;
    }
    if (dbparam::IsChainFile(strFile) && block_notify<uint256>::IsInitialBlockDownload()) {
        nMinutes = 5;
    }

    CDBEnv::get_instance().TxnCheckPoint(nMinutes ? map_arg::GetArgUInt("-dblogsize", 100) * 1024 : 0, nMinutes);
    CDBEnv::get_instance().DecUseCount(strFile);
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

bool CDB::Rewrite(const std::string &strFile, const char *pszSkip/* = nullptr */)
{
    while (!args_bool::fShutdown)
    {
        {
            LOCK(CDBEnv::get_instance().cs_db);
            //if (!CDBEnv::get_instance().mapFileUseCount.count(strFile) || CDBEnv::get_instance().mapFileUseCount[strFile] == 0) {
            if (!CDBEnv::get_instance().ExistsFileCount(strFile) || CDBEnv::get_instance().GetFileCount(strFile)==0) {
                // Flush log data to the dat file
                CDBEnv::get_instance().CloseDb(strFile);
                CDBEnv::get_instance().CheckpointLSN(strFile);
                //CDBEnv::get_instance().mapFileUseCount.erase(strFile);
                CDBEnv::get_instance().EraseFileCount(strFile);

                bool fSuccess = true;
                logging::LogPrintf("Rewriting %s...\n", strFile.c_str());
                std::string strFileRes = strFile + ".rewrite";

                { // surround usage of db with extra {}
                    CDB db(strFile.c_str(), "r");
                    //Db *pdbCopy = new(std::nothrow) Db(&CDBEnv::get_instance().dbenv, 0);
                    Db *pdbCopy = CDBEnv::get_instance().createDb();
                    if (pdbCopy == nullptr) {
                        logging::LogPrintf("Memory allocate failure for CDB::Rewrite.");
                        return false;
                    }

                    int ret = pdbCopy->open(nullptr,  // Txn pointer
                        strFileRes.c_str(),           // Filename
                        "main",                       // Logical db name
                        DB_BTREE,                     // Database type
                        DB_CREATE,                    // Flags
                        0);
                    if (ret > 0) {
                        logging::LogPrintf("Cannot create database file %s\n", strFileRes.c_str());
                        fSuccess = false;
                    }

                    Dbc *pcursor = db.GetCursor();
                    if (pcursor) {
                        while (fSuccess)
                        {
                            CDataStream ssKey(SER_DISK, version::CLIENT_VERSION);
                            CDataStream ssValue(SER_DISK, version::CLIENT_VERSION);
                            int ret = db.ReadAtCursor(pcursor, ssKey, ssValue, DB_NEXT);
                            if (ret == DB_NOTFOUND) {
                                pcursor->close();
                                break;
                            } else if (ret != 0) {
                                pcursor->close();
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
                        if (pdbCopy->close(0)) {
                            fSuccess = false;
                        }
                        delete pdbCopy;
                    }
                }
                if (fSuccess) {
                    fSuccess = CDBEnv::get_instance().Remove(strFile);
                    fSuccess = CDBEnv::get_instance().Rename(strFileRes, strFile);
                    /*
                    Db dbA(&CDBEnv::get_instance().dbenv, 0);
                    if (dbA.remove(strFile.c_str(), nullptr, 0)) {
                        fSuccess = false;
                    }

                    Db dbB(&CDBEnv::get_instance().dbenv, 0);
                    if (dbB.rename(strFileRes.c_str(), nullptr, strFile.c_str(), 0)) {
                        fSuccess = false;
                    }
                    */
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


void CDBEnv::Flush(bool fShutdown)
{
    int64_t nStart = util::GetTimeMillis();

    //
    // Flush log data to the actual data file on all files that are not in use
    //
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
                //
                // Move log data to the dat file
                //
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
