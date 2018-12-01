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

#ifndef WIN32
#include "sys/stat.h"
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
        printf("EnvShutdown exception: %s (%d)\n", DbEnv::strerror(ret), ret);
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
    printf("dbenv.open LogDir=%s ErrorFile=%s\n", pathLogDir.string().c_str(), pathErrorFile.string().c_str());

    unsigned int nEnvFlags = 0;
    if (map_arg::GetBoolArg("-privdb", true)) {
        nEnvFlags |= DB_PRIVATE;
    }

    int nDbCache = map_arg::GetArgInt("-dbcache", 25);
    dbenv.set_lg_dir(pathLogDir.string().c_str());
    dbenv.set_cachesize(nDbCache / 1024, (nDbCache % 1024)*1048576, 1);
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
                            DB_CREATE     |
                            DB_INIT_LOCK  |
                            DB_INIT_LOG   |
                            DB_INIT_MPOOL |
                            DB_INIT_TXN   |
                            DB_THREAD     |
                            DB_RECOVER    |
                            nEnvFlags,
                            S_IRUSR | S_IWUSR);
    if (ret != 0) {
        return print::error("CDB() : error %s (%d) opening database environment", DbEnv::strerror(ret), ret);
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

        printf("Final lk_max_locks is %u, sufficient for (worst case) %d block%s in a single transaction (up to a %d-deep reorganization)\n", nMaxLocks, nBlocks, (nBlocks == 1) ? "" : "s", nDeepReorg);
        if (nDeepReorg < 3) {
            if (nBlocks < 1) {
                strMessage = strprintf(_("Warning: DB_CONFIG has set_lk_max_locks %u, which may be too low for a single block. If this limit is reached, %s may stop working."), nMaxLocks, coin_param::strCoinName.c_str());
            } else {
                strMessage = strprintf(_("Warning: DB_CONFIG has set_lk_max_locks %u, which may be too low for a common blockchain reorganization. If this limit is reached, %s may stop working."), nMaxLocks, coin_param::strCoinName.c_str());
            }

            excep::set_strMiscWarning(strMessage);
            printf("*** %s\n", strMessage.c_str());
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

    printf("CDBEnv::MakeMock()\n");

    dbenv.set_cachesize(1, 0, 1);
    dbenv.set_lg_bsize(10485760*4);
    dbenv.set_lg_max(10485760);
    dbenv.set_lk_max_locks(10000);
    dbenv.set_lk_max_objects(10000);
    dbenv.set_flags(DB_AUTO_COMMIT, 1);
#ifdef DB_LOG_IN_MEMORY
    dbenv.log_set_config(DB_LOG_IN_MEMORY, args_bool::fUseMemoryLog ? 1 : 0);
#endif
    int ret = dbenv.open(NULL,
                            DB_CREATE     |
                            DB_INIT_LOCK  |
                            DB_INIT_LOG   |
                            DB_INIT_MPOOL |
                            DB_INIT_TXN   |
                            DB_THREAD     |
                            DB_PRIVATE,
                            S_IRUSR | S_IWUSR);
    if (ret > 0) {
        throw std::runtime_error(strprintf("CDBEnv::MakeMock(): error %d opening database environment", ret));
    }

    fDbEnvInit = true;
    fMockDb = true;
}

CDBEnv::VerifyResult CDBEnv::Verify(std::string strFile, bool (*recoverFunc)(CDBEnv &dbenv, std::string strFile))
{
    LOCK(cs_db);
    assert(mapFileUseCount.count(strFile) == 0);

    Db db(&dbenv, 0);
    int result = db.verify(strFile.c_str(), NULL, NULL, 0);
    if (result == 0) {
        return VERIFY_OK;
    } else if (recoverFunc == NULL) {
        return RECOVER_FAIL;
    }

    // Try to recover:
    bool fRecovered = (*recoverFunc)(*this, strFile);
    return (fRecovered ? RECOVER_OK : RECOVER_FAIL);
}

bool CDBEnv::Salvage(std::string strFile, bool fAggressive, std::vector<CDBEnv::KeyValPair > &vResult)
{
    LOCK(cs_db);
    assert(mapFileUseCount.count(strFile) == 0);

    u_int32_t flags = DB_SALVAGE;
    if (fAggressive) { flags |= DB_AGGRESSIVE; }

    std::stringstream strDump;

    Db db(&dbenv, 0);
    int result = db.verify(strFile.c_str(), NULL, &strDump, flags);
    if (result != 0) {
        printf("ERROR: db salvage failed\n");
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
            vResult.push_back(std::make_pair(hex::ParseHex(keyHex), hex::ParseHex(valueHex)));
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

CDB::CDB(const char *pszFile, const char *pszMode/*="r+"*/) : CDBCommon(), pdb(NULL), activeTxn(NULL)
{
    if (pszFile == NULL) {
        return;
    }

    fReadOnly = (!::strchr(pszMode, '+') && !::strchr(pszMode, 'w'));
    bool fCreate = ::strchr(pszMode, 'c') != NULL;
    unsigned int nFlags = DB_THREAD;
    if (fCreate) {
        nFlags |= DB_CREATE;
    }

    {
        LOCK(CDBEnv::bitdb.cs_db);
        if (! CDBEnv::bitdb.Open(iofs::GetDataDir())) {
            throw std::runtime_error("env open failed");
        }

        strFile = pszFile;
        ++CDBEnv::bitdb.mapFileUseCount[strFile];
        pdb = CDBEnv::bitdb.mapDb[strFile];
        if (pdb == NULL) {
            pdb = new(std::nothrow) Db(&CDBEnv::bitdb.dbenv, 0);
            if(pdb == NULL) {
                throw std::runtime_error("CDB() : failed to allocate memory for database");
            }

            bool fMockDb = CDBEnv::bitdb.IsMock();
            if (fMockDb) {
                DbMpoolFile *mpf = pdb->get_mpf();
                int ret = mpf->set_flags(DB_MPOOL_NOFILE, 1);
                if (ret != 0) {
                    throw std::runtime_error(strprintf("CDB() : failed to configure for no temp file backing for database %s", pszFile));
                }
            }

            int ret = pdb->open(NULL,                        // Txn pointer
                                fMockDb ? NULL : pszFile,    // Filename
                                "main",                      // Logical db name
                                DB_BTREE,                    // Database type
                                nFlags,                      // Flags
                                0);

            if (ret != 0) {
                delete pdb;
                pdb = NULL;
                --CDBEnv::bitdb.mapFileUseCount[strFile];
                strFile.clear();
                throw std::runtime_error(strprintf("CDB() : can't open database file %s, error %d", pszFile, ret));
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
    activeTxn = NULL;
    pdb = NULL;

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
    if (CDBCommon::IsChainFile(strFile) && block_process::manage::IsInitialBlockDownload()) {
        nMinutes = 5;
    }

    CDBEnv::bitdb.dbenv.txn_checkpoint(nMinutes ? map_arg::GetArgUInt("-dblogsize", 100)*1024 : 0, nMinutes, 0);

    {
        LOCK(CDBEnv::bitdb.cs_db);
        --CDBEnv::bitdb.mapFileUseCount[strFile];
    }
}

void CDBEnv::CloseDb(const std::string &strFile)
{
    {
        LOCK(cs_db);
        if (mapDb[strFile] != NULL) {
            //
            // Close the database handle
            //
            Db *pdb = mapDb[strFile];
            pdb->close(0);
            delete pdb;
            mapDb[strFile] = NULL;
        }
    }
}

bool CDBEnv::RemoveDb(const std::string &strFile)
{
    CloseDb(strFile);

    LOCK(cs_db);
    int rc = dbenv.dbremove(NULL, strFile.c_str(), NULL, DB_AUTO_COMMIT);
    return (rc == 0);
}

bool CDB::Rewrite(const std::string &strFile, const char *pszSkip/* = NULL */)
{
    while (! args_bool::fShutdown)
    {
        {
            LOCK(CDBEnv::bitdb.cs_db);
            if (!CDBEnv::bitdb.mapFileUseCount.count(strFile) || CDBEnv::bitdb.mapFileUseCount[strFile] == 0) {
                // Flush log data to the dat file
                CDBEnv::bitdb.CloseDb(strFile);
                CDBEnv::bitdb.CheckpointLSN(strFile);
                CDBEnv::bitdb.mapFileUseCount.erase(strFile);

                bool fSuccess = true;
                printf("Rewriting %s...\n", strFile.c_str());
                std::string strFileRes = strFile + ".rewrite";

                { // surround usage of db with extra {}
                    CDB db(strFile.c_str(), "r");
                    Db *pdbCopy = new(std::nothrow) Db(&CDBEnv::bitdb.dbenv, 0);
                    if(pdbCopy == NULL) {
                        printf("Cannot allocate memory for database.");
                        return false;
                    }

                    int ret = pdbCopy->open(NULL,                    // Txn pointer
                                            strFileRes.c_str(),      // Filename
                                            "main",                  // Logical db name
                                            DB_BTREE,                // Database type
                                            DB_CREATE,               // Flags
                                            0);
                    if (ret > 0) {
                        printf("Cannot create database file %s\n", strFileRes.c_str());
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

                            if (pszSkip != NULL) {
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
                            int ret2 = pdbCopy->put(NULL, &datKey, &datValue, DB_NOOVERWRITE);
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
                    if (dbA.remove(strFile.c_str(), NULL, 0)) {
                        fSuccess = false;
                    }

                    Db dbB(&CDBEnv::bitdb.dbenv, 0);
                    if (dbB.rename(strFileRes.c_str(), NULL, strFile.c_str(), 0)) {
                        fSuccess = false;
                    }
                }
                if (! fSuccess) {
                    printf("Rewriting of %s FAILED!\n", strFileRes.c_str());
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
    printf("Flush(%s)%s\n", args_bool::fShutdown ? "true" : "false", fDbEnvInit ? "" : " db not started");
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
            printf("%s refcount=%d\n", strFile.c_str(), nRefCount);
            if (nRefCount == 0) {
                //
                // Move log data to the dat file
                //
                CloseDb(strFile);
                printf("%s checkpoint\n", strFile.c_str());
                dbenv.txn_checkpoint(0, 0, 0);
                if (!CDBCommon::IsChainFile(strFile) || fDetachDB) {
                    printf("%s detach\n", strFile.c_str());
                    if (! fMockDb) {
                        dbenv.lsn_reset(strFile.c_str(), 0);
                    }
                }
                printf("%s closed\n", strFile.c_str());
                mapFileUseCount.erase(mi++);
            } else {
                mi++;
            }
        }

        printf("DBFlush(%s)%s ended %15" PRId64 "ms\n", args_bool::fShutdown ? "true" : "false", fDbEnvInit ? "" : " db not started", util::GetTimeMillis() - nStart);
        if (args_bool::fShutdown) {
            char **listp;
            if (mapFileUseCount.empty()) {
                dbenv.log_archive(&listp, DB_ARCH_REMOVE);
                Close();
            }
        }
    }
}

//
// CAddrDB
//
CAddrDB::CAddrDB()
{
    pathAddr = iofs::GetDataDir() / "peers.dat";
}

bool CAddrDB::Write(const CAddrMan &addr)
{
    // Generate random temporary filename
    unsigned short randv = 0;
    RAND_bytes((unsigned char *)&randv, sizeof(randv));
    std::string tmpfn = strprintf("peers.dat.%04x", randv);

    // serialize addresses, checksum data up to that point, then append csum
    CDataStream ssPeers(SER_DISK, version::CLIENT_VERSION);
    ssPeers << FLATDATA(block_info::gpchMessageStart);
    ssPeers << addr;
    uint256 hash = hash_basis::Hash(ssPeers.begin(), ssPeers.end());
    ssPeers << hash;

    // open temp output file, and associate with CAutoFile
    boost::filesystem::path pathTmp = iofs::GetDataDir() / tmpfn;
    FILE *file = fopen(pathTmp.string().c_str(), "wb");
    CAutoFile fileout = CAutoFile(file, SER_DISK, version::CLIENT_VERSION);
    if (! fileout) {
        return print::error("CAddrman::Write() : open failed");
    }

    // Write and commit header, data
    try {
        fileout << ssPeers;
    } catch (const std::exception &) {
        return print::error("CAddrman::Write() : I/O error");
    }

    iofs::FileCommit(fileout);
    fileout.fclose();

    // replace existing peers.dat, if any, with new peers.dat.XXXX
    if (! iofs::RenameOver(pathTmp, pathAddr)) {
        return print::error("CAddrman::Write() : Rename-into-place failed");
    }
    return true;
}

bool CAddrDB::Read(CAddrMan &addr)
{
    // open input file, and associate with CAutoFile
    FILE *file = ::fopen(pathAddr.string().c_str(), "rb");
    CAutoFile filein = CAutoFile(file, SER_DISK, version::CLIENT_VERSION);
    if (! filein) {
        return print::error("CAddrman::Read() : open failed");
    }

    // use file size to size memory buffer
    int fileSize = iofs::GetFilesize(filein);
    int dataSize = fileSize - sizeof(uint256);

    //Don't try to resize to a negative number if file is small
    if ( dataSize < 0 ) { dataSize = 0; }
    std::vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    } catch (const std::exception &) {
        return print::error("CAddrman::Read() 2 : I/O error or stream data corrupted");
    }
    filein.fclose();

    CDataStream ssPeers(vchData, SER_DISK, version::CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = hash_basis::Hash(ssPeers.begin(), ssPeers.end());
    if (hashIn != hashTmp) {
        return print::error("CAddrman::Read() : checksum mismatch; data corrupted");
    }

    unsigned char pchMsgTmp[4];
    try {
        // de-serialize file header (block_info::gpchMessageStart magic number) and
        ssPeers >> FLATDATA(pchMsgTmp);

        // verify the network matches ours
        if (::memcmp(pchMsgTmp, block_info::gpchMessageStart, sizeof(pchMsgTmp))) {
            return print::error("CAddrman::Read() : invalid network magic number");
        }

        // de-serialize address data into one CAddrMan object
        ssPeers >> addr;
    } catch (const std::exception &) {
        return print::error("CAddrman::Read() : I/O error or stream data corrupted");
    }
    return true;
}
