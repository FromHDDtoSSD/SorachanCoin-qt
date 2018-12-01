// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef BITCOIN_DB_H
#define BITCOIN_DB_H

#include "main.h"

#include <map>
#include <string>
#include <vector>

#include <db_cxx.h>

class CAddress;
class CAddrMan;
class CBlockLocator;
class CDiskBlockIndex;
class CDiskTxPos;
class CMasterKey;
class COutPoint;
class CTxIndex;
class CWallet;
class CWalletTx;

namespace wallet_dispatch
{
    void ThreadFlushWalletDB(void *parg);
    bool BackupWallet(const CWallet &wallet, const std::string &strDest);
    bool DumpWallet(CWallet *pwallet, const std::string &strDest);
    bool ImportWallet(CWallet *pwallet, const std::string &strLocation);
}

namespace dbparam
{
    extern unsigned int nWalletDBUpdated;// = 0;
}

class CDBCommon
{
private:
    CDBCommon(const CDBCommon &); // {}
    CDBCommon &operator=(const CDBCommon &); // {}
protected:
    bool IsChainFile(std::string strFile) const;
public:
    CDBCommon() {}
};

//
// Database map
// Singleton Class
//
class CDBEnv : public CDBCommon
{
private:
    CDBEnv();
    ~CDBEnv();

    CDBEnv(const CDBEnv &); // {}
    CDBEnv &operator=(const CDBEnv &); // {}

    bool fDetachDB;
    bool fDbEnvInit;
    bool fMockDb;
    boost::filesystem::path pathEnv;
    std::string strPath;

    void EnvShutdown();

public:
    static CDBEnv bitdb;    // Singleton object instance, db.cpp

    mutable CCriticalSection cs_db;
    DbEnv dbenv;
    std::map<std::string, int> mapFileUseCount;
    std::map<std::string, Db *> mapDb;

    void MakeMock();
    bool IsMock() {
        return fMockDb;
    }

    /*
     * Verify that database file strFile is OK. If it is not,
     * call the callback to try to recover.
     * This must be called BEFORE strFile is opened.
     * Returns true if strFile is OK.
     */
    enum VerifyResult
    { 
        VERIFY_OK, 
        RECOVER_OK, 
        RECOVER_FAIL 
    };
    VerifyResult Verify(std::string strFile, bool (*recoverFunc)(CDBEnv &dbenv, std::string strFile));

    /*
     * Salvage data from a file that Verify says is bad.
     * fAggressive sets the DB_AGGRESSIVE flag (see berkeley DB->verify() method documentation).
     * Appends binary key/value pairs to vResult, returns true if successful.
     * NOTE: reads the entire database into memory, so cannot be used
     * for huge databases.
     */
    typedef std::pair<std::vector<unsigned char>, std::vector<unsigned char> > KeyValPair;
    bool Salvage(std::string strFile, bool fAggressive, std::vector<KeyValPair> &vResult);

    bool Open(boost::filesystem::path pathEnv_);
    void Close();
    void Flush(bool fShutdown);
    void CheckpointLSN(std::string strFile);

    void SetDetach(bool fDetachDB_) {
        fDetachDB = fDetachDB_;
    }
    bool GetDetach() { 
        return fDetachDB;
    }

    void CloseDb(const std::string &strFile);
    bool RemoveDb(const std::string &strFile);

    DbTxn *TxnBegin(int flags=DB_TXN_WRITE_NOSYNC) {
        DbTxn *ptxn = NULL;
        int ret = dbenv.txn_begin(NULL, &ptxn, flags);
        if (!ptxn || ret != 0) {
            return NULL;
        }
        return ptxn;
    }
};

/**
 ** RAII class that provides access to a Berkeley database
 ** CTxDB(Berkeley), CWalletDB
 ** Type Db Dbt : Berkeley DB
 */
class CDB : public CDBCommon
{
private:
    CDB(); // {}
    CDB(const CDB &); // {}
    CDB &operator=(const CDB &); // {}

protected:
    Db *pdb;
    std::string strFile;
    DbTxn *activeTxn;
    bool fReadOnly;

    explicit CDB(const char *pszFile, const char *pszMode="r+");    // open DB
    ~CDB() { 
        Close();
    }

public:
    void Close();

protected:
    template<typename K, typename T>
    bool Read(const K &key, T &value) {
        if (! pdb) {
            return false;
        }

        // Key
        CDataStream ssKey(SER_DISK, version::CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], (uint32_t)ssKey.size());

        // Read
        Dbt datValue;
        datValue.set_flags(DB_DBT_MALLOC);
        int ret = pdb->get(activeTxn, &datKey, &datValue, 0);
        ::memset(datKey.get_data(), 0, datKey.get_size());
        if (datValue.get_data() == NULL) {
            return false;
        }

        // Unserialize value
        try {
            CDataStream ssValue((char *)datValue.get_data(), (char *)datValue.get_data() + datValue.get_size(), SER_DISK, version::CLIENT_VERSION);
            ssValue >> value;
        } catch (const std::exception &) {
            return false;
        }

        // Clear and free memory
        ::memset(datValue.get_data(), 0, datValue.get_size());
        ::free(datValue.get_data());
        return (ret == 0);
    }

    template<typename K, typename T>
    bool Write(const K &key, const T &value, bool fOverwrite=true) {
        if (! pdb) {
            return false;
        }
        if (fReadOnly) {
            assert(!"Write called on database in read-only mode");
        }

        // Key
        CDataStream ssKey(SER_DISK, version::CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], (uint32_t)ssKey.size());

        // Value
        CDataStream ssValue(SER_DISK, version::CLIENT_VERSION);
        ssValue.reserve(10000);
        ssValue << value;
        Dbt datValue(&ssValue[0], (uint32_t)ssValue.size());

        // Write
        int ret = pdb->put(activeTxn, &datKey, &datValue, (fOverwrite ? 0 : DB_NOOVERWRITE));

        // Clear memory in case it was a private key
        ::memset(datKey.get_data(), 0, datKey.get_size());
        ::memset(datValue.get_data(), 0, datValue.get_size());
        return (ret == 0);
    }

    template<typename K>
    bool Erase(const K &key) {
        if (! pdb) {
            return false;
        }
        if (fReadOnly) {
            assert(!"Erase called on database in read-only mode");
        }

        // Key
        CDataStream ssKey(SER_DISK, version::CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], (uint32_t)ssKey.size());

        // Erase
        int ret = pdb->del(activeTxn, &datKey, 0);

        // Clear memory
        ::memset(datKey.get_data(), 0, datKey.get_size());
        return (ret == 0 || ret == DB_NOTFOUND);
    }

    template<typename K>
    bool Exists(const K &key) {
        if (! pdb) {
            return false;
        }

        // Key
        CDataStream ssKey(SER_DISK, version::CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], (uint32_t)ssKey.size());

        // Exists
        int ret = pdb->exists(activeTxn, &datKey, 0);

        // Clear memory
        ::memset(datKey.get_data(), 0, datKey.get_size());
        return (ret == 0);
    }

    Dbc *GetCursor() {
        if (! pdb) {
            return NULL;
        }

        Dbc *pcursor = NULL;
        int ret = pdb->cursor(NULL, &pcursor, 0);
        if (ret != 0) {
            return NULL;
        }
        return pcursor;
    }

    // fFlags: DB_SET_RANGE, DB_NEXT, DB_NEXT, ... 
    static int ReadAtCursor(Dbc *pcursor, CDataStream &ssKey, CDataStream &ssValue, unsigned int fFlags = DB_NEXT) {
        // Read at cursor, return: 0 success, 1` ERROE_CODE
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
        int ret = pcursor->get(&datKey, &datValue, fFlags);
        if (ret != 0) {
            return ret;
        } else if (datKey.get_data() == NULL || datValue.get_data() == NULL) {
            return 99999;
        }

        // Convert to streams
        ssKey.SetType(SER_DISK);
        ssKey.clear();
        ssKey.write((char *)datKey.get_data(), datKey.get_size());
        ssValue.SetType(SER_DISK);
        ssValue.clear();
        ssValue.write((char *)datValue.get_data(), datValue.get_size());

        // Clear and free memory
        ::memset(datKey.get_data(), 0, datKey.get_size());
        ::memset(datValue.get_data(), 0, datValue.get_size());
        ::free(datKey.get_data());
        ::free(datValue.get_data());
        return 0;
    }

public:
    bool TxnBegin() {
        if (!pdb || activeTxn) {
            return false;
        }

        DbTxn *ptxn = CDBEnv::bitdb.TxnBegin();
        if (! ptxn) {
            return false;
        }

        activeTxn = ptxn;
        return true;
    }

    bool TxnCommit() {
        if (!pdb || !activeTxn) {
            return false;
        }

        int ret = activeTxn->commit(0);
        activeTxn = NULL;
        return (ret == 0);
    }

    bool TxnAbort() {
        if (!pdb || !activeTxn) {
            return false;
        }

        int ret = activeTxn->abort();
        activeTxn = NULL;
        return (ret == 0);
    }

    bool ReadVersion(int &nVersion) {
        nVersion = 0;
        return Read(std::string("version"), nVersion);
    }

    bool WriteVersion(int nVersion) {
        return Write(std::string("version"), nVersion);
    }

    ///////

    static bool Rewrite(const std::string &strFile, const char *pszSkip = NULL);
};

/**
 ** Access to the (IP) address database (peers.dat) 
 */
class CAddrDB
{
private:
    CAddrDB(const CAddrDB &); // {}
    CAddrDB &operator=(const CAddrDB &); // {}

    boost::filesystem::path pathAddr;

public:
    CAddrDB();
    bool Write(const CAddrMan &addr);
    bool Read(CAddrMan &addr);
};

#endif
//@
