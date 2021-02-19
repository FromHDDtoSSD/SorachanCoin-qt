// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "db.h"
#include "net.h"
#include "util.h"
#include "main.h"
#include "ui_interface.h"
#include "init.h"
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <util/time.h>

#ifndef WIN32
# include "sys/stat.h"
#endif

CDBEnv CDBEnv::bitdb;
unsigned int dbparam::nWalletDBUpdated = 0;

//
// CDB
//
void CDBEnv::EnvShutdown()
{
    if (! fDbEnvInit) {
        return;
    }

    fDbEnvInit = false;
    int ret = dbenv.close(0);
    if (ret != 0) {
        logging::LogPrintf("EnvShutdown exception: %s (%d)\n", DbEnv::strerror(ret), ret);
    }
    if (! fMockDb) {
        DbEnv(0).remove(strPath.c_str(), 0);
    }
}

CDBEnv::CDBEnv() : CDBCommon(), fDetachDB(false), fDbEnvInit(false), fMockDb(false), dbenv(DB_CXX_NO_EXCEPTIONS) {}

CDBEnv::~CDBEnv()
{
    EnvShutdown();
}

void CDBEnv::Close()
{
    EnvShutdown();
}

bool CDBEnv::Open(boost::filesystem::path pathEnv_)
{
    if (fDbEnvInit) {
        return true;
    }
    if (args_bool::fShutdown) {
        return false;
    }

    //
    // create directory and db.log
    //
    pathEnv = pathEnv_;
    boost::filesystem::path pathDataDir = pathEnv;

    strPath = pathDataDir.string();
    boost::filesystem::path pathLogDir = pathDataDir / "database";
    boost::filesystem::create_directory(pathLogDir);

    boost::filesystem::path pathErrorFile = pathDataDir / "db.log";
    logging::LogPrintf("dbenv.open LogDir=%s ErrorFile=%s\n", pathLogDir.string().c_str(), pathErrorFile.string().c_str());

    unsigned int nEnvFlags = 0;
    if (map_arg::GetBoolArg("-privdb", true)) {
        nEnvFlags |= DB_PRIVATE;
    }

    int nDbCache = map_arg::GetArgInt("-dbcache", 25);
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

#ifndef USE_LEVELDB
    //
    // Check that the number of locks is sufficient (to prevent chain fork possibility, read http://bitcoin.org/may15 for more info)
    //
    u_int32_t nMaxLocks;
    if (! dbenv.get_lk_max_locks(&nMaxLocks)) {
        int nBlocks, nDeepReorg;
        std::string strMessage;

        nBlocks = nMaxLocks / 48768;
        nDeepReorg = (nBlocks - 1) / 2;

        logging::LogPrintf("Final lk_max_locks is %u, sufficient for (worst case) %d block%s in a single transaction (up to a %d-deep reorganization)\n", nMaxLocks, nBlocks, (nBlocks == 1) ? "" : "s", nDeepReorg);
        if (nDeepReorg < 3) {
            if (nBlocks < 1) {
                strMessage = tfm::format(_("Warning: DB_CONFIG has set_lk_max_locks %u, which may be too low for a single block. If this limit is reached, %s may stop working."), nMaxLocks, strCoinName);
            } else {
                strMessage = tfm::format(_("Warning: DB_CONFIG has set_lk_max_locks %u, which may be too low for a common blockchain reorganization. If this limit is reached, %s may stop working."), nMaxLocks, strCoinName);
            }

            excep::set_strMiscWarning(strMessage);
            logging::LogPrintf("*** %s\n", strMessage.c_str());
        }
    }
#endif

    return true;
}

void CDBEnv::MakeMock()
{
    if (fDbEnvInit) {
        throw std::runtime_error("CDBEnv::MakeMock(): already initialized");
    }
    if (args_bool::fShutdown) {
        throw std::runtime_error("CDBEnv::MakeMock(): during shutdown");
    }

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
    if (ret > 0) {
        throw std::runtime_error(tfm::format("CDBEnv::MakeMock(): error %d opening database environment", ret));
    }

    fDbEnvInit = true;
    fMockDb = true;
}

CDBEnv::VerifyResult CDBEnv::Verify(std::string strFile, bool(*recoverFunc)(CDBEnv &dbenv, std::string strFile))
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
            vResult.push_back(std::make_pair(hex::ParseHex(keyHex).get_std_vector(), hex::ParseHex(valueHex).get_std_vector()));
#else
            vResult.push_back(std::make_pair(hex::ParseHex(keyHex), hex::ParseHex(valueHex)));
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

CDB::CDB(const char *pszFile, const char *pszMode/*="r+"*/) : CDBCommon(), pdb(nullptr), activeTxn(nullptr)
{
    const int retry_counter = 10;
    if (pszFile == nullptr) {
        return;
    }

    fReadOnly = (!::strchr(pszMode, '+') && !::strchr(pszMode, 'w'));
    bool fCreate = ::strchr(pszMode, 'c') != nullptr;
    unsigned int nFlags = DB_THREAD;
    if (fCreate) {
        nFlags |= DB_CREATE;
    }

    {
        LOCK(CDBEnv::bitdb.cs_db);
        if (! CDBEnv::bitdb.Open(iofs::GetDataDir())) {
            if(args_bool::fShutdown) {
                return;
            } else {
                throw std::runtime_error("CDBEnv::bitdb : failed to open file");
            }
        }

        strFile = pszFile;
        ++CDBEnv::bitdb.mapFileUseCount[strFile];
        pdb = CDBEnv::bitdb.mapDb[strFile];
        if (pdb == nullptr) {
            pdb = new(std::nothrow) Db(&CDBEnv::bitdb.dbenv, 0);
            if (pdb == nullptr) {
                throw std::runtime_error("CDB() : failed to allocate memory");
            }

            bool fMockDb = CDBEnv::bitdb.IsMock();
            if (fMockDb) {
                DbMpoolFile *mpf = pdb->get_mpf();
                int ret = mpf->set_flags(DB_MPOOL_NOFILE, 1);
                if (ret != 0) {
                    throw std::runtime_error(tfm::format("CDB() : failed to configure for no temp file backing for database %s", pszFile));
                }
            }

            /*
            int ret = pdb->open(nullptr,     // Txn pointer
                fMockDb ? nullptr : pszFile, // Filename
                "main",                      // Logical db name
                DB_BTREE,                    // Database type
                nFlags,                      // Flags
                0);

            if (ret != 0) {
                delete pdb;
                pdb = nullptr;
                --CDBEnv::bitdb.mapFileUseCount[strFile];
                strFile.clear();
                throw std::runtime_error(tfm::format("CDB() : can't open database file %s, error %d", pszFile, ret));
            }
            */

            for (int cc = 0; cc < retry_counter; ++cc) {
                int ret = pdb->open(nullptr,     // Txn pointer
                    fMockDb ? nullptr : pszFile, // Filename
                    "main",                      // Logical db name
                    DB_BTREE,                    // Database type
                    nFlags,                      // Flags
                    0);

                //debugcs::instance() << "CDB::CDB open db: " << ret << debugcs::endl();
                if (ret != 0) {
                    if(cc < retry_counter - 1) {util::Sleep(3000); continue;}
                    delete pdb;
                    pdb = nullptr;
                    --CDBEnv::bitdb.mapFileUseCount[strFile];
                    strFile.clear();
                    throw std::runtime_error(tfm::format("CDB() : can't open database file %s, error %d", pszFile, ret));
                } else {
                    break;
                }
            }

            if (fCreate && !Exists(std::string("version"))) {
                bool fTmp = fReadOnly;
                fReadOnly = false;
                WriteVersion(version::CLIENT_VERSION);
                fReadOnly = fTmp;
            }

            CDBEnv::bitdb.mapDb[strFile] = pdb;
        }
    }
}

bool CDBCommon::IsChainFile(std::string strFile) const    // Berkeley DB
{
    if (strFile == "blkindex.dat") {
        return true;
    }
    return false;
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
    if (CDBCommon::IsChainFile(strFile)) {
        nMinutes = 2;
    }
    if (CDBCommon::IsChainFile(strFile) && block_notify::IsInitialBlockDownload()) {
        nMinutes = 5;
    }

    CDBEnv::bitdb.dbenv.txn_checkpoint(nMinutes ? map_arg::GetArgUInt("-dblogsize", 100) * 1024 : 0, nMinutes, 0);

    {
        LOCK(CDBEnv::bitdb.cs_db);
        --CDBEnv::bitdb.mapFileUseCount[strFile];
    }
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
            LOCK(CDBEnv::bitdb.cs_db);
            if (!CDBEnv::bitdb.mapFileUseCount.count(strFile) || CDBEnv::bitdb.mapFileUseCount[strFile] == 0) {
                // Flush log data to the dat file
                CDBEnv::bitdb.CloseDb(strFile);
                CDBEnv::bitdb.CheckpointLSN(strFile);
                CDBEnv::bitdb.mapFileUseCount.erase(strFile);

                bool fSuccess = true;
                logging::LogPrintf("Rewriting %s...\n", strFile.c_str());
                std::string strFileRes = strFile + ".rewrite";

                { // surround usage of db with extra {}
                    CDB db(strFile.c_str(), "r");
                    Db *pdbCopy = new(std::nothrow) Db(&CDBEnv::bitdb.dbenv, 0);
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
                        CDBEnv::bitdb.CloseDb(strFile);
                        if (pdbCopy->close(0)) {
                            fSuccess = false;
                        }
                        delete pdbCopy;
                    }
                }
                if (fSuccess) {
                    Db dbA(&CDBEnv::bitdb.dbenv, 0);
                    if (dbA.remove(strFile.c_str(), nullptr, 0)) {
                        fSuccess = false;
                    }

                    Db dbB(&CDBEnv::bitdb.dbenv, 0);
                    if (dbB.rename(strFileRes.c_str(), nullptr, strFile.c_str(), 0)) {
                        fSuccess = false;
                    }
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
                if (!CDBCommon::IsChainFile(strFile) || fDetachDB) {
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
