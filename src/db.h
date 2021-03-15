// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DB_H
#define BITCOIN_DB_H

#include <main.h>
#include <db_addr.h>
#include <map>
#include <string>
#include <vector>
#include <db_cxx.h>
#include <leveldb/db.h>
#include <leveldb/env.h>
#include <leveldb/cache.h>
#include <leveldb/filter_policy.h>
#include <leveldb/write_batch.h>
#include <memenv/memenv.h>
#include <sqlite/sqlite3.h>

class CAddress;
class CAddrMan;
template <typename T> class CBlockLocator_impl;
using CBlockLocator = CBlockLocator_impl<uint256>;
template<typename T> class CDiskBlockIndex_impl;
using CDiskBlockIndex = CDiskBlockIndex_impl<uint256>;
class CDiskTxPos;
class CMasterKey;
template <typename T> class COutPoint_impl;
using COutPoint = COutPoint_impl<uint256>;
class CTxIndex;
class CWallet;
class CWalletTx;

// SorachanCoin: wallet SQLite
#define WALLET_SQL_MODE

// under development: WALLET_SQL_MODE
namespace wallet_dispatch
{
    void ThreadFlushWalletDB(void *parg);
    bool BackupWallet(const CWallet &wallet, const std::string &strDest);
    bool DumpWallet(CWallet *pwallet, const std::string &strDest);
    bool ImportWallet(CWallet *pwallet, const std::string &strLocation);
}

namespace dbparam
{
    void IncWalletUpdate();
    unsigned int GetWalletUpdate();
    bool IsChainFile(std::string strFile);
}

/**
 * DB Manager Interface
 */
class IDBEnv
{
    IDBEnv(const IDBEnv &)=delete;
    IDBEnv(IDBEnv &&)=delete;
    IDBEnv &operator=(const IDBEnv &)=delete;
    IDBEnv &operator=(IDBEnv &&)=delete;
protected:
    static constexpr int dbcache_size = 25;
    static constexpr int retry_counter = 10; // Create retry counter
    static constexpr bool fMockDb = false; // no using MockDB

    fs::path pathEnv;
    mutable CCriticalSection cs_env;
    std::map<std::string, int> mapFileUseCount;
    std::map<std::string, Db *> mapDb; // database handle

    virtual void EnvShutdown()=0;
public:
    IDBEnv() {}
    virtual ~IDBEnv() {}

    void IncUseCount(const std::string &strFile, bool fempty = true) {
        LOCK(cs_env);
        if(fempty==false && mapFileUseCount.count(strFile)==0)
            throw std::runtime_error("IDBEnv inc: No register strFile");
        if(mapFileUseCount.count(strFile)==0)
            mapFileUseCount.insert(std::make_pair(strFile, 0));
        ++mapFileUseCount[strFile];
    }
    void DecUseCount(const std::string &strFile) {
        LOCK(cs_env);
        if(mapFileUseCount.count(strFile)==0)
            throw std::runtime_error("IDBEnv dec: No register strFile");
        if(mapFileUseCount[strFile]==0)
            throw std::runtime_error("IDBEnv: strFile is already removed");
        --mapFileUseCount[strFile];
    }
    bool ExistsFileCount(const std::string &strFile) const {
        LOCK(cs_env);
        return mapFileUseCount.count(strFile)>0;
    }
    int GetFileCount(const std::string &strFile) const {
        LOCK(cs_env);
        if(mapFileUseCount.count(strFile)==0)
            throw std::runtime_error("IDBEnv getfilecount: No register strFile");
        std::map<std::string, int>::const_iterator mi = mapFileUseCount.find(strFile);
        return (*mi).second;
    }
    void EraseFileCount(const std::string &strFile) {
        LOCK(cs_env);
        if(ExistsFileCount(strFile))
            mapFileUseCount.erase(strFile);
    }
    int GetRefCount() const { // when 0, No using DB.
        LOCK(cs_env);
        int RefCount = 0;
        for(const auto &mi: mapFileUseCount)
            RefCount += mi.second;
        return RefCount;
    }
    bool FindFile(const std::string &strFile) const {
        LOCK(cs_env);
        std::map<std::string, int>::const_iterator mi = mapFileUseCount.find(strFile);
        return (mi != mapFileUseCount.end());
    }

    virtual bool Open(fs::path pathEnv_)=0;
    virtual void Close()=0;
    virtual bool Flush(const std::string &)=0;
    virtual void Flush(bool fShutdown)=0;
    virtual void CloseDb(const std::string &)=0;
    virtual bool RemoveDb(const std::string &)=0;
};

/**
 * DB Interface
 */
class IDB
{
public:
    class leveldb_secure_string final : public std::string {
    public:
        leveldb_secure_string() {
            ((std::string *const)this)->reserve(10000);
            *((std::string *const)this) = "MIKE";
            *((std::string *const)this) = "";
        }
        template <typename Iterator>
        explicit leveldb_secure_string(Iterator begin, Iterator end) : std::string(begin, end) {}
        ~leveldb_secure_string() {
            cleanse::OPENSSL_cleanse(&(((std::string *const)this)->operator[](0)), ((std::string *const)this)->size());
        }
    };

    class DbIterator final {
        DbIterator(const DbIterator &)=delete;
        DbIterator &operator=(const DbIterator &)=delete;
    public:
        DbIterator &operator=(DbIterator &&obj) noexcept {
            this->cs = obj.cs;
            obj.cs = nullptr;
            this->bp = obj.bp;
            obj.bp = nullptr;
            this->lp = obj.lp;
            obj.lp = nullptr;
            this->qp = obj.qp;
            obj.qp = nullptr;
            return *this;
        }

        DbIterator(DbIterator &&obj) noexcept {
            operator=(std::move(obj));
        }
        DbIterator() noexcept : bp(nullptr), lp(nullptr), cs(nullptr) {}
        explicit DbIterator(Dbc *&&p, CCriticalSection *csIn) noexcept : bp(p), lp(nullptr), qp(nullptr), cs(csIn) {
            assert(cs);
            p = nullptr;
        }
        explicit DbIterator(leveldb::Iterator *&&p, CCriticalSection *csIn) noexcept : bp(nullptr), lp(p), qp(nullptr), cs(csIn) {
            assert(cs);
            p = nullptr;
        }
        explicit DbIterator(sqlite3_stmt *&&p, CCriticalSection *csIn) noexcept : bp(nullptr), lp(nullptr), qp(p), cs(csIn) {
            assert(cs);
            p = nullptr;
        }
        ~DbIterator() {
            if(bp)
                bp->close();
            if(lp)
                delete lp;
            if(qp)
                ::sqlite3_finalize(qp);
        }

        bool is_bdb() const noexcept {
            return bp != nullptr;
        }
        bool is_leveldb() const noexcept {
            return lp != nullptr;
        }
        bool is_sqlite() const noexcept {
            return qp != nullptr;
        }
        bool is_error() const noexcept {
            return (lp == nullptr && bp == nullptr && qp == nullptr);
        }
        bool is_ok() const noexcept {
            return !is_error();
        }
        CCriticalSection &get_cs() const noexcept {
            return *cs;
        }

        operator Dbc *() const noexcept {
            return bp;
        }
        operator leveldb::Iterator *() const noexcept {
            return lp;
        }
        operator sqlite3_stmt *() const noexcept {
            return qp;
        }

        // call CloseDB before setnull().
        void setnull() noexcept {
            bp=nullptr;
            lp=nullptr;
            qp=nullptr;
            cs=nullptr;
        }

    private:
        Dbc *bp;
        leveldb::Iterator *lp;
        sqlite3_stmt *qp;
        CCriticalSection *cs;
    };

    //
    // Delayed writing: for LevelDB, Sqlite
    //
    class CTxnSecureBuffer {
        CTxnSecureBuffer(const CTxnSecureBuffer &)=delete;
        CTxnSecureBuffer(CTxnSecureBuffer &&)=delete;
        CTxnSecureBuffer &operator=(const CTxnSecureBuffer &)=delete;
        CTxnSecureBuffer &operator=(CTxnSecureBuffer &&)=delete;
    public:
        enum txn_method {
            TXN_READ,
            TXN_WRITE_INSERT,
            TXN_WRITE_UPDATE
        };

        using secure_binary = std::vector<char, secure_allocator<char>>;
        using secure_keyvalue = std::pair<secure_binary, secure_binary>;

        CTxnSecureBuffer() {}
        ~CTxnSecureBuffer() {}
        void clear() {
            buf.clear();
        }
        size_t size() const noexcept {
            return buf.size();
        }

        void insert(txn_method method, const CDataStream &ssKey, const CDataStream &ssValue) {
            buf.emplace_back(std::move(
                                  std::make_pair(method,
                                                 std::move(std::make_pair(std::vector<char, secure_allocator<char>>(&ssKey[0], &ssKey[0]+ssKey.size()),
                                                                          std::vector<char, secure_allocator<char>>(&ssValue[0], &ssValue[0]+ssValue.size()))))));
        }
        const std::pair<txn_method, secure_keyvalue> &get(int index) const noexcept {
            return buf[index];
        }

    private:
        std::vector<std::pair<txn_method, secure_keyvalue>> buf;
    };

    virtual DbIterator GetIteCursor()=0;

#ifndef DB_NEXT
# define DB_NEXT 16
#endif
    // fFlags: DB_SET_RANGE, DB_NEXT, DB_NEXT, ...
    static int ReadAtCursor(const DbIterator &pcursor, CDataStream &ssKey, CDataStream &ssValue, unsigned int fFlags = DB_NEXT);

    virtual void Close()=0;
    virtual bool TxnBegin()=0;
    virtual bool TxnCommit()=0;
    virtual bool TxnAbort()=0;

    virtual bool ReadVersion(int &nVersion)=0;
    virtual bool WriteVersion(int nVersion)=0;

    /*
    template<typename K, typename T>
    virtual bool Read(const K &key, T &value)=0;

    template<typename K, typename T>
    virtual bool Write(const K &key, const T &value, bool fOverwrite)=0;

    template<typename K>
    virtual bool Erase(const K &key)=0;

    template<typename K>
    virtual bool Exists(const K &key)=0;
    */
};

/**
 * Berkeley DB Manager
 */
class CDBEnv final : public IDBEnv
{
private:
    CDBEnv(const CDBEnv &)=delete;
    CDBEnv(CDBEnv &&)=delete;
    CDBEnv &operator=(const CDBEnv &)=delete;
    CDBEnv &operator=(CDBEnv &&)=delete;

    CDBEnv();
    ~CDBEnv();

    bool fDetachDB;
    bool fDbEnvInit;
    DbEnv dbenv;

    void EnvShutdown();

    Db *&getDb(const std::string &strFile) {
        LOCK(cs_db);
        if(mapDb.count(strFile)==0)
            mapDb.insert(std::make_pair(strFile, nullptr));
        return mapDb[strFile];
    }

public:
    static CCriticalSection cs_db;

    static CDBEnv &get_instance() {
        LOCK(cs_db);
        static CDBEnv bitdb;
        return bitdb;
    }

    bool Flush(const std::string &strFile) {
        LOCK(cs_db);
        if(GetRefCount()>0)
            return false;
        std::map<std::string, int>::iterator mi = mapFileUseCount.find(strFile);
        if(mi != mapFileUseCount.end()) {
            CloseDb(strFile);
            CheckpointLSN(strFile);
            mapFileUseCount.erase(mi);
            return true;
        } else
            return false;
    }

    //void MakeMock();
    //bool IsMock() const { return fMockDb; }

    /*
    * Verify that database file strFile is OK. If it is not,
    * call the callback to try to recover.
    * This must be called BEFORE strFile is opened.
    * Returns true if strFile is OK.
    */
    enum VerifyResult {
        VERIFY_OK,
        RECOVER_OK,
        RECOVER_FAIL
    };
    VerifyResult Verify(std::string strFile, bool (*recoverFunc)(std::string strFile, bool fOnlyKeys));

    /*
    * Salvage data from a file that Verify says is bad.
    * fAggressive sets the DB_AGGRESSIVE flag (see berkeley DB->verify() method documentation).
    * Appends binary key/value pairs to vResult, returns true if successful.
    * NOTE: reads the entire database into memory, so cannot be used
    * for huge databases.
    */
#ifdef CSCRIPT_PREVECTOR_ENABLE
    using KeyValPair = std::pair<prevector<PREVECTOR_N, unsigned char>, prevector<PREVECTOR_N, unsigned char>>;
#else
    using KeyValPair = std::pair<std::vector<unsigned char>, std::vector<unsigned char>>;
#endif
    bool Salvage(std::string strFile, bool fAggressive, std::vector<KeyValPair> &vResult);
    std::unique_ptr<Db> TempCreate(DbTxn *txnid, const std::string &strFile, unsigned int nFlags);

    Db *Create(const std::string &strFile, unsigned int nFlags);
    bool Open(fs::path pathEnv_);
    bool TxnCheckPoint(uint32_t kbyte, uint32_t min);
    void Close();
    bool Remove(const std::string &strFile);
    bool Rename(const std::string &strFileRes, const std::string &strFile);
    bool DbRename(const std::string &filename, const std::string &newFilename);
    void Flush(bool fShutdown);
    void CheckpointLSN(std::string strFile);

    void SetDetach(bool fDetachDB_) noexcept {fDetachDB = fDetachDB_;}
    bool GetDetach() const {return fDetachDB;}

    void CloseDb(const std::string &strFile);
    bool RemoveDb(const std::string &strFile);
    DbTxn *TxnBegin(int flags = DB_TXN_WRITE_NOSYNC);
};

/**
 * Level DB Manager
 */
class CLevelDBEnv final : public IDBEnv
{
private:
    CLevelDBEnv()=delete;
    CLevelDBEnv(const CLevelDBEnv &)=delete;
    CLevelDBEnv(CLevelDBEnv &&)=delete;
    CLevelDBEnv &operator=(const CLevelDBEnv &)=delete;
    CLevelDBEnv &operator=(CLevelDBEnv &&)=delete;

    CLevelDBEnv(std::vector<std::string> instIn);
    ~CLevelDBEnv();

    bool fLevelDbEnvInit;
    leveldb::Options options;

    void EnvShutdown();
    static leveldb::Options GetOptions();

    // global pointer array for LevelDB object instance
    const std::vector<std::string> instance;
    struct leveldb_object {
        CCriticalSection cs_ldb;
        leveldb::DB *ptxdb;
    };
    mutable std::map<std::string, leveldb_object *> lobj;

    // global only use CLevelDBEnv
    static CCriticalSection cs_leveldb;

public:
    static CLevelDBEnv &get_instance() {
        LOCK(cs_leveldb);
        //static CLevelDBEnv obj({getname_mainchain(), getname_finexdrivechain(), getname_wallet()});
        static CLevelDBEnv obj({getname_mainchain(), getname_finexdrivechain()});
        return obj;
    }

    static std::string getname_mainchain() {
        return "txleveldb";
    }
    static std::string getname_finexdrivechain() {
        return "txfinexdrivechain";
    }
    static std::string getname_wallet() {
        return "txwallet";
    }

    leveldb::DB *&get_ptxdb(const std::string &name) const {
        LOCK(cs_leveldb);
        //debugcs::instance() << "CLevelDBEnv get_ptxdb name:" << name.c_str() << debugcs::endl();
        assert(lobj.count(name)>0);
        return lobj[name]->ptxdb;
    }

    CCriticalSection &get_rcs(const std::string &name) const {
        LOCK(cs_leveldb);
        assert(lobj.count(name)>0);
        return lobj[name]->cs_ldb;
    }

    bool restart(fs::path pathEnv_, bool fRemoveOld, void (*func)(bool fRemoveOld)) {
        LOCK(cs_leveldb);
        EnvShutdown();
        func(fRemoveOld);
        return Open(pathEnv_);
    }

    bool Open(fs::path pathEnv_);

    void Close();
    bool Flush(const std::string &strDb);
    void Flush(bool fShutdown);
    void CloseDb(const std::string &strDb);
    bool RemoveDb(const std::string &strDb);
};

/**
 * Sqlite DB Manager
 */
class CSqliteDBEnv final : public IDBEnv
{
    CSqliteDBEnv()=delete;
    CSqliteDBEnv(const CSqliteDBEnv &)=delete;
    CSqliteDBEnv &operator=(const CSqliteDBEnv &)=delete;
    CSqliteDBEnv(CSqliteDBEnv &&)=delete;
    CSqliteDBEnv &operator=(CSqliteDBEnv &&)=delete;
private:
    CSqliteDBEnv(std::vector<std::string> instIn);
    ~CSqliteDBEnv();
    static CCriticalSection cs_sqlite;

    fs::path pathEnv;

    // global pointer array for Sqlite object instance
    const std::vector<std::string> instance;
    struct sqlite_object {
        CCriticalSection cs_sql;
        sqlite3 *psql;
        sqlite_object() {
            psql = nullptr;
        }
    };
    mutable std::map<std::string, sqlite_object *> sqlobj;

    void EnvShutdown();

    struct table_check {
        std::string name;
        bool exists;
        table_check(const std::string &nameIn) {
            name = nameIn;
            exists = false;
        }
    };

    static int m_default_callback(void *unused, int argc, char **argv, char **azColName) {
        (void)unused;
        (void)argc;
        (void)argv;
        (void)azColName;
        return SQLITE_OK;
    }

    static int m_tablenamecheck_callback(void *table_context, int argc, char **argv, char **azColName) {
        table_check *tc = reinterpret_cast<table_check *>(table_context);
        if(tc->exists)
            return SQLITE_OK;
        for(int i=0; i<argc; ++i) {
            if(std::strcmp(azColName[i], "name")==0) {
                if(tc->name == argv[i]) {
                    tc->exists=true;
                    return SQLITE_OK;
                }
            }
        }
        return SQLITE_OK;
    }

    bool sql(const std::string &strFile, const std::string &cmd) {
        LOCK(sqlobj[strFile]->cs_sql);
        char *error;
        if(::sqlite3_exec(sqlobj[strFile]->psql, cmd.c_str(), m_default_callback, nullptr, &error)!=SQLITE_OK)
            return false;
        return true;
    }

    bool is_table_exists(const std::string &strFile, const std::string &table_name);

public:
    static CSqliteDBEnv &get_instance() {
        LOCK(cs_sqlite);
        //static CSqliteDBEnv obj({getname_mainchain(), getname_finexdrivechain(), getname_wallet()});
        static CSqliteDBEnv obj({getname_wallet()});
        return obj;
    }

    /*
    static std::string getname_mainchain() {
        return "blkmainchain.dat";
    }
    static std::string getname_finexdrivechain() {
        return "blkfinexdrivechain.dat";
    }
    */
    static std::string getname_wallet() {
        return "walletsql.dat";
    }

    sqlite3 *&get_psqldb(const std::string &name) const {
        LOCK(cs_sqlite);
        assert(sqlobj.count(name)>0);
        return sqlobj[name]->psql;
    }

    CCriticalSection &get_rcs(const std::string &name) const {
        LOCK(cs_sqlite);
        assert(sqlobj.count(name)>0);
        return sqlobj[name]->cs_sql;
    }

    bool Open(fs::path pathEnv_);

    void Close();
    bool Flush(const std::string &strFile);
    void Flush(bool fShutdown);
    void CloseDb(const std::string &strFile);
    bool RemoveDb(const std::string &strFile);
};

/**
 * DB Stream
 */
class CDBStream
{
    CDBStream()=delete;
    CDBStream(const CDBStream &)=delete;
    CDBStream(CDBStream &&)=delete;
    CDBStream &operator=(const CDBStream &)=delete;
    CDBStream &operator=(CDBStream &&)=delete;
public:
    explicit CDBStream(char *beginIn, uint32_t sizeIn) noexcept : pos(0), pbegin(beginIn), pend(beginIn+sizeIn), pvch(nullptr) { // Unserialize
        assert(pbegin!=pend);
    }
    explicit CDBStream(std::vector<char> *vch, int vch_reserve=1000) noexcept : pos(0), pend(nullptr), pvch(vch) { // Serialize
        vch->reserve(vch_reserve);
        vch->resize(128);
        pbegin = vch->data();
    }

    CDBStream &read(char *dest, uint32_t size) {
        assert(size>0);
        dest ? std::memcpy(dest, pbegin+pos, size): 0;
        pos += size;
        return *this;
    }

    CDBStream &write(const char *src, uint32_t size) {
        assert(size>0);
        pvch->resize(pos+size);
        pbegin = pvch->data();
        src ? std::memcpy(pbegin+pos, src, size): 0;
        pos += size;
        pend = pbegin+pos;
        return *this;
    }

    std::string str() const {
        return (std::string(pbegin, pend));
    }

private:
    uint32_t pos;
    char *pbegin;
    char *pend;
    std::vector<char> *const pvch;
};

/**
 * Berkeley DB
 * RAII class that provides access to a Berkeley database
 * using (Wallet): old CWalletDB (up to v3)
 */
class CDB : public IDB
{
private:
    CDB()=delete;
    CDB(const CDB &)=delete;
    CDB(CDB &&)=delete;
    CDB &operator=(const CDB &)=delete;
    CDB &operator=(CDB &&)=delete;

    Db *pdb;
    std::string strFile;
    DbTxn *activeTxn;
    bool fReadOnly;

public:
    explicit CDB(const char *pszFile, const char *pszMode /*= "r+"*/); // open DB
    virtual ~CDB();

    template<typename K, typename T>
    bool Read(const K &key, T &value) {
        LOCK(CDBEnv::cs_db);
        if (! pdb)
            return false;

        // Key
        CDataStream ssKey(0, 0);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], (uint32_t)ssKey.size());
        //assert(datKey.get_data()==&ssKey[0]); // USERMEM

        // Test [OK]
        /*
        Dbt datTest;
        datTest.set_flags(DB_DBT_USERMEM);
        datTest.set_size(ssKey.size());
        datTest.set_data(&ssKey[0]);
        assert(::memcmp(datKey.get_data(), datTest.get_data(), datKey.get_size())==0);
        */

        // Read
        Dbt datValue;
        datValue.set_flags(DB_DBT_MALLOC);
        int ret = pdb->get(activeTxn, &datKey, &datValue, 0);
        cleanse::OPENSSL_cleanse(datKey.get_data(), datKey.get_size());
        if (datValue.get_data() == nullptr)
            return false;

        // Unserialize value
        try {
            CDBStream stream((char *)datValue.get_data(), datValue.get_size());
            ::Unserialize(stream, value);
        } catch (const std::exception &) {
            cleanse::OPENSSL_cleanse(datValue.get_data(), datValue.get_size());
            ::free(datValue.get_data());
            return false;
        }

        // Clear and free memory
        cleanse::OPENSSL_cleanse(datValue.get_data(), datValue.get_size());
        ::free(datValue.get_data());
        return (ret == 0);
    }

    template<typename K, typename T>
    bool Write(const K &key, const T &value, bool fOverwrite = true) {
        LOCK(CDBEnv::cs_db);
        if (! pdb)
            return false;
        if (fReadOnly) {
            assert(!"Write called on database in read-only mode");
        }

        // Key
        CDataStream ssKey(0, 0);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], (uint32_t)ssKey.size());

        // Value
        CDataStream ssValue(0, 0);
        ssValue.reserve(10000);
        ssValue << value;
        Dbt datValue(&ssValue[0], (uint32_t)ssValue.size());

        // Write
        int ret = pdb->put(activeTxn, &datKey, &datValue, (fOverwrite ? 0 : DB_NOOVERWRITE));

        // Clear memory in case it was a private key
        cleanse::OPENSSL_cleanse(datKey.get_data(), datKey.get_size());
        cleanse::OPENSSL_cleanse(datValue.get_data(), datValue.get_size());
        return (ret == 0);
    }

    template<typename K>
    bool Erase(const K &key) {
        LOCK(CDBEnv::cs_db);
        if (! pdb)
            return false;
        if (fReadOnly) {
            assert(!"Erase called on database in read-only mode");
        }

        // Key
        CDataStream ssKey(0, 0);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], (uint32_t)ssKey.size());

        // Erase
        int ret = pdb->del(activeTxn, &datKey, 0);

        // Clear memory
        cleanse::OPENSSL_cleanse(datKey.get_data(), datKey.get_size());
        return (ret == 0 || ret == DB_NOTFOUND);
    }

    template<typename K>
    bool Exists(const K &key) {
        LOCK(CDBEnv::cs_db);
        if (! pdb)
            return false;

        // Key
        CDataStream ssKey(0, 0);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], (uint32_t)ssKey.size());

        // Exists
        int ret = pdb->exists(activeTxn, &datKey, 0);

        // Clear memory
        cleanse::OPENSSL_cleanse(datKey.get_data(), datKey.get_size());
        return (ret == 0);
    }

    //Dbc *GetCursor();
    DbIterator GetIteCursor();

    void Close();
    bool TxnBegin();
    bool TxnCommit();
    bool TxnAbort();
    bool ReadVersion(int &nVersion);
    bool WriteVersion(int nVersion);

    static bool Rewrite(const std::string &strFile, const char *pszSkip = nullptr);
};

/**
 * Level DB
 * RAII class that provides access to a LevelDB database
 * using (Blockchain): CTxDB_impl<uint256>, CTxDB_impl<uint65536>
 */
class CLevelDB : public IDB
{
private:
    CLevelDB(const CLevelDB &)=delete;
    CLevelDB(CLevelDB &&)=delete;
    CLevelDB &operator=(const CLevelDB &)=delete;
    CLevelDB &operator=(CLevelDB &&)=delete;

    bool ScanBatch(const CDBStream &key, std::string *value, bool *deleted) const;

    // A batch stores up writes and deletes for atomic application. When this
    // field is non-NULL, writes/deletes go there instead of directly to disk.
    leveldb::WriteBatch *activeBatch;

    bool fReadOnly;
    bool fSecure;

    // Points to the global instance
    leveldb::DB *&pdb;
    CCriticalSection &cs_db;

    mutable leveldb::Iterator *p;

public:
    //
    // About CLevelDB: const_iterator (if fSecure == false)
    // Note that, must be using below. memory management is auto.
    // iterator->: leveldb::Iterator pointer object. key() and value(), data() and size().
    //
    // if(! this->seek(KEY, VALUE)) { error }
    // for(const_iterator iterator=this->begin(); iterator!=this->end(); ++iterator) { statement }
    //
    class const_iterator final {
        const_iterator(const const_iterator &)=delete;
        const_iterator &operator=(const const_iterator &)=delete;
    public:
        const_iterator &operator=(const_iterator &&obj) noexcept {
            this->p = obj.p;
            obj.p = nullptr;
            this->cs = obj.cs;
            obj.cs = nullptr;
            return *this;
        }
        const_iterator(const_iterator &&obj) noexcept {
            operator=(std::move(obj));
        }

        const_iterator() noexcept {
            p = nullptr;
            cs = nullptr;
        }
        explicit const_iterator(leveldb::Iterator *&&pIn, CCriticalSection *csIn) noexcept : p(pIn), cs(csIn) {
            assert(pIn && csIn);
            pIn = nullptr;
        }
        ~const_iterator() {
            delete p;
            if(cs) {
                LEAVE_CRITICAL_SECTION(*cs);
            }
        }

        void operator++() noexcept {
            assert(p && cs);
            p->Next();
            if(p->Valid()==false) {
                delete p;
                p = nullptr;
                LEAVE_CRITICAL_SECTION(*cs);
                cs = nullptr;
            }
        }
        void operator++(int) noexcept {
            operator++();
        }
        bool operator==(const const_iterator &obj) const noexcept {
            return p == obj.p;
        }
        bool operator!=(const const_iterator &obj) const noexcept {
            return p != obj.p;
        }
        leveldb::Iterator &operator*() const noexcept {
            assert(p);
            return *p;
        }
        leveldb::Iterator *operator->() const noexcept {
            assert(p);
            return p;
        }
    private:
        leveldb::Iterator *p;
        CCriticalSection *cs;
    };

    template <typename KEY, typename VALUE>
    NODISCARD bool seek(const KEY &key, const VALUE &val) const noexcept {
        LOCK(cs_db);
        delete p;
        p = pdb->NewIterator(leveldb::ReadOptions());
        if(! p)
            return false;
        CDataStream ssStartKey(0, 0);
        ssStartKey << std::make_pair(key, val);
        p->Seek(ssStartKey.str());
        return true;
    }

    const_iterator begin() const noexcept {
        assert(p);
        assert(fSecure==false);
        ENTER_CRITICAL_SECTION(cs_db);
        if(p->Valid()==false) {
            delete p;
            p = nullptr;
            LEAVE_CRITICAL_SECTION(cs_db);
            return end();
        }
        return std::move(const_iterator(std::move(p), &cs_db));
    }
    constexpr const_iterator end() const noexcept {
        return std::move(const_iterator());
    }

public:
    explicit CLevelDB(const std::string &strDb, const char *pszMode /*= "r+"*/, bool fSecureIn = false); // open LevelDB
    virtual ~CLevelDB();

    //
    // About CLevelDB: Get Cursor (if fSecure == true)
    //
#ifndef DB_SET
# define DB_SET 27
#endif
#ifndef DB_SET_RANGE
# define DB_SET_RANGE 28
#endif
#ifndef DB_GET_BOTH
# define DB_GET_BOTH 8
#endif
#ifndef DB_GET_BOTH_RANGE
# define DB_GET_BOTH_RANGE 10
#endif
#ifndef DB_NOTFOUND
# define DB_NOTFOUND (-30988)
#endif
    DbIterator GetIteCursor();

    void Close();
    bool TxnBegin();
    bool TxnCommit();
    bool TxnAbort();

    bool ReadVersion(int &nVersion);
    bool WriteVersion(int nVersion);

    template<typename K, typename T>
    bool Read(const K &key, T &value) {
        return fSecure ? ReadSecure(key, value): ReadNormal(key, value);
    }

    template<typename K, typename T>
    bool Write(const K &key, const T &value, bool fOverwrite = true) {
        return fSecure ? WriteSecure(key, value, fOverwrite): WriteNormal(key, value, fOverwrite);
    }

    template<typename K>
    bool Erase(const K &key) {
        return fSecure ? EraseSecure(key): EraseNormal(key);
    }

    template<typename K>
    bool Exists(const K &key) {
        return fSecure ? ExistsSecure(key): ExistsNormal(key);
    }

private:
    template<typename K, typename T>
    bool ReadSecure(const K &key, T &value) {
        LOCK(cs_db);
        assert(this->activeBatch==nullptr);
        leveldb_secure_string secureValue;
        try {
            CDataStream ssKey(0, 0);
            ssKey.reserve(1000);
            ssKey << key;
            leveldb::Slice slKey(&ssKey[0], ssKey.size());
            leveldb::Status status = this->pdb->Get(leveldb::ReadOptions(), slKey, (std::string *)&secureValue);
            if (! status.ok()) {
                if (status.IsNotFound())
                    return false;
                // Some unexpected error.
                logging::LogPrintf("LevelDB read secure failure: %s\n", status.ToString().c_str());
                return false;
            }
            //if(secureValue.size()==0) {
            //    debugcs::instance() << "CLevelDB ReadSecure stream size==0" << debugcs::endl();
            //    return false;
            //}

            // Unserialize value
            CDataStream ssValue(&secureValue[0], &secureValue[0]+secureValue.size());
            ssValue >> value;
        } catch (const std::exception &) {
            return false;
        }

        return true;
    }

    template<typename K, typename T>
    bool ReadNormal(const K &key, T &value) {
        LOCK(cs_db);
        std::vector<char> vch;
        CDBStream ssKey(&vch);
        ::Serialize(ssKey, key);

        std::string strValue;
        bool readFromDb = true;
        if (this->activeBatch) {
            // First we must search for it in the currently pending set of
            // changes to the db. If not found in the batch, go on to read disk.
            bool deleted = false;
            readFromDb = ScanBatch(ssKey, &strValue, &deleted) == false;
            if (deleted)
                return false;
        }
        if (readFromDb) {
            leveldb::Status status = this->pdb->Get(leveldb::ReadOptions(), ssKey.str(), &strValue);
            if (! status.ok()) {
                if (status.IsNotFound())
                    return false;
                // Some unexpected error.
                logging::LogPrintf("LevelDB read failure: %s\n", status.ToString().c_str());
                return false;
            }
        }

        // Unserialize value
        try {
            CDBStream stream((char *)&strValue[0], strValue.size());
            ::Unserialize(stream, value);
        } catch (const std::exception &) {
            return false;
        }

        return true;
    }

    template<typename K, typename T>
    bool WriteSecure(const K &key, const T &value, bool fOverwrite) {
        LOCK(cs_db);
        assert(this->activeBatch==nullptr);
        if (this->fReadOnly) {
            assert(!"Write called on database in read-only mode");
        }
        if(! fOverwrite) {
            if(ExistsSecure(key))
                return false;
        }

        try {
            CDataStream ssKey(0, 0);
            ssKey.reserve(1000);
            ssKey << key;

            CDataStream ssValue(0, 0);
            ssValue.reserve(10000);
            ssValue << value;

            leveldb::Slice slKey(&ssKey[0], ssKey.size());
            leveldb::Slice slValue(&ssValue[0], ssValue.size());
            leveldb::Status status = this->pdb->Put(leveldb::WriteOptions(), slKey, slValue);
            if (! status.ok()) {
                logging::LogPrintf("LevelDB write failure: %s\n", status.ToString().c_str());
                return false;
            }
        } catch (const std::exception &) {
            return false;
        }

        return true;
    }

    template<typename K, typename T>
    bool WriteNormal(const K &key, const T &value, bool fOverwrite) {
        LOCK(cs_db);
        if (this->fReadOnly) {
            assert(!"Write called on database in read-only mode");
        }
        if(! fOverwrite) {
            if(ExistsNormal(key))
                return false;
        }

        std::vector<char> vch;
        CDBStream ssKey(&vch);
        ::Serialize(ssKey, key);

        std::vector<char> vch2;
        CDBStream ssValue(&vch2, 10000);
        ::Serialize(ssValue, value);

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

    template<typename K>
    bool EraseSecure(const K &key) {
        LOCK(cs_db);
        assert(this->activeBatch==nullptr);
        if (! this->pdb)
            return false;
        if (this->fReadOnly) {
            assert(!"Erase called on database in read-only mode");
        }

        try {
            CDataStream ssKey(0, 0);
            ssKey.reserve(1000);
            ssKey << key;
            leveldb::Slice slKey(&ssKey[0], ssKey.size());
            leveldb::Status status = this->pdb->Delete(leveldb::WriteOptions(), slKey);
            return (status.ok() || status.IsNotFound());
        } catch (const std::exception &) {
            return false;
        }
    }

    template<typename K>
    bool EraseNormal(const K &key) {
        LOCK(cs_db);
        if (! this->pdb)
            return false;
        if (this->fReadOnly) {
            assert(!"Erase called on database in read-only mode");
        }

        std::vector<char> vch;
        CDBStream ssKey(&vch);
        ::Serialize(ssKey, key);

        if (this->activeBatch) {
            this->activeBatch->Delete(ssKey.str());
            return true;
        }

        leveldb::Status status = this->pdb->Delete(leveldb::WriteOptions(), ssKey.str());
        return (status.ok() || status.IsNotFound());
    }

    template<typename K>
    bool ExistsSecure(const K &key) {
        LOCK(cs_db);
        assert(this->activeBatch==nullptr);
        leveldb_secure_string unused;
        try {
            CDataStream ssKey(0, 0);
            ssKey.reserve(1000);
            ssKey << key;
            leveldb::Slice slKey(&ssKey[0], ssKey.size());
            leveldb::Status status = this->pdb->Get(leveldb::ReadOptions(), slKey, (std::string *)&unused);
            return status.IsNotFound() == false;
        } catch (const std::exception &) {
            return false;
        }
    }

    template<typename K>
    bool ExistsNormal(const K &key) {
        LOCK(cs_db);
        std::vector<char> vch;
        CDBStream ssKey(&vch);
        ::Serialize(ssKey, key);

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
};

/**
 * Sqlite DB
 * RAII class that provides access to a SqliteDB database
 * using: testing ...
 */
class CSqliteDB : public IDB
{
    CSqliteDB()=delete;
    CSqliteDB(const CSqliteDB &)=delete;
    CSqliteDB(CSqliteDB &&)=delete;
    CSqliteDB &operator=(const CSqliteDB &)=delete;
    CSqliteDB &operator=(CSqliteDB &&)=delete;
private:
    bool fReadOnly;
    bool fSecure;

    sqlite3 *&pdb;
    CCriticalSection &cs_db;

    CTxnSecureBuffer *txn;

public:
    explicit CSqliteDB(const std::string &strFile, const char *pszMode /*= "r+"*/, bool fSecureIn = false); // open SqliteDB
    virtual ~CSqliteDB();

    DbIterator GetIteCursor();

    void Close();
    bool TxnBegin();
    bool TxnCommit();
    bool TxnAbort();

    bool ReadVersion(int &nVersion);
    bool WriteVersion(int nVersion);

    bool PortToSqlite(DbIterator ite);

    // below Read/Write are from "key_value" table.
    template<typename K, typename T>
    bool Read(const K &key, T &value) {
        return fSecure ? ReadSecure(key, value): ReadNormal(key, value);
    }

    template<typename K, typename T>
    bool Write(const K &key, const T &value, bool fOverwrite = true) {
        return fSecure ? WriteSecure(key, value, fOverwrite): WriteNormal(key, value, fOverwrite);
    }

    template<typename K>
    bool Erase(const K &key) {
        return fSecure ? EraseSecure(key): EraseNormal(key);
    }

    template<typename K>
    bool Exists(const K &key) {
        return fSecure ? ExistsSecure(key): ExistsNormal(key);
    }

private:
    // below Read/Write are from "key_value" table.
    template<typename K, typename T>
    bool ReadSecure(const K &key, T &value) {
        LOCK(cs_db);
        assert(pdb);
        bool ret = false;
        try {
            CDataStream ssKey;
            ssKey.reserve(1000);
            ssKey << key;

            CDataStream ssValue;
            ssValue.reserve(10000);

            sqlite3_stmt *stmt;
            do {
                if(::sqlite3_prepare_v2(pdb, "select value from key_value where key=$1", -1, &stmt, nullptr)!=SQLITE_OK) break;
                if(::sqlite3_bind_blob(stmt, 1, &ssKey[0], ssKey.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                if(::sqlite3_step(stmt) == SQLITE_ROW) {
                    const char *pdata = reinterpret_cast<const char *>(::sqlite3_column_blob(stmt, 0));
                    const int size = ::sqlite3_column_bytes(stmt, 0) / sizeof(char);
                    ssValue.write(pdata, size);
                    cleanse::OPENSSL_cleanse(const_cast<char *>(pdata), size);
                } else break;
                if(::sqlite3_step(stmt)!=SQLITE_DONE) break;  // key value pair must be unique.
                ret = true;
            } while(0);
            if(::sqlite3_finalize(stmt)!=SQLITE_OK)
                return false;
            if(ret)
                ssValue >> value;
        } catch (const std::exception &) {
            return false;
        }
        return ret;
    }

    template<typename K, typename T>
    bool ReadNormal(const K &key, T &value) {
        LOCK(cs_db);
        assert(pdb);
        bool ret = false;
        try {
            std::vector<char> vchKey;
            CDBStream ssKey(&vchKey);
            ::Serialize(ssKey, key);

            std::vector<char> vchValue;
            CDBStream ssValue(&vchValue, 10000);

            sqlite3_stmt *stmt;
            do {
                if(::sqlite3_prepare_v2(pdb, "select value from key_value where key=$1", -1, &stmt, nullptr)!=SQLITE_OK) break;
                if(::sqlite3_bind_blob(stmt, 1, &vchKey[0], vchKey.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                if(::sqlite3_step(stmt) == SQLITE_ROW) {
                    const char *pdata = reinterpret_cast<const char *>(::sqlite3_column_blob(stmt, 0));
                    const int size = ::sqlite3_column_bytes(stmt, 0) / sizeof(char);
                    ssValue.write(pdata, size);
                } else break;
                if(::sqlite3_step(stmt)!=SQLITE_DONE) break;  // key value pair must be unique.
                ret = true;
            } while(0);
            if(::sqlite3_finalize(stmt)!=SQLITE_OK)
                return false;
            if(ret)
                ::Unserialize(ssValue, value);
        } catch (const std::exception &) {
            return false;
        }
        return ret;
    }

    template<typename K, typename T>
    bool WriteSecure(const K &key, const T &value, bool fOverwrite) {
        LOCK(cs_db);
        assert(pdb);
        if (this->fReadOnly) {
            assert(!"Write called on database in read-only mode");
        }
        bool update = ExistsSecure(key);
        if(fOverwrite==false && update)
            return false;
        if(txn) {
            try {
                CDataStream ssKey;
                ssKey.reserve(1000);
                ssKey << key;
                CDataStream ssValue;
                ssValue.reserve(10000);
                ssValue << value;
                txn->insert(update ? CTxnSecureBuffer::TXN_WRITE_UPDATE: CTxnSecureBuffer::TXN_WRITE_INSERT, ssKey, ssValue);
            } catch (const std::exception &) {
                return false;
            }
            return true;
        }
        bool ret = false;
        sqlite3_stmt *stmt=nullptr;
        try {
            CDataStream ssKey;
            ssKey.reserve(1000);
            ssKey << key;

            CDataStream ssValue;
            ssValue.reserve(10000);
            ssValue << value;

            do {
                if(update) {
                    if(::sqlite3_prepare_v2(pdb, "update key_value set value=$1 where key=$2;", -1, &stmt, nullptr)!=SQLITE_OK) break;
                    if(::sqlite3_bind_blob(stmt, 1, &ssValue[0], ssValue.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                    if(::sqlite3_bind_blob(stmt, 2, &ssKey[0], ssKey.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                } else {
                    if(::sqlite3_prepare_v2(pdb, "insert into key_value (key, value) values ($1, $2);", -1, &stmt, nullptr)!=SQLITE_OK) break;
                    if(::sqlite3_bind_blob(stmt, 1, &ssKey[0], ssKey.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                    if(::sqlite3_bind_blob(stmt, 2, &ssValue[0], ssValue.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                }
                if(::sqlite3_step(stmt)!=SQLITE_DONE) break;
                ret = true;
            } while(0);
            if(stmt) {
                if(::sqlite3_finalize(stmt)!=SQLITE_OK)
                    return false;
            }
        } catch (const std::exception &) {
            if(stmt)
                ::sqlite3_finalize(stmt);
            return false;
        }
        return ret;
    }

    template<typename K, typename T>
    bool WriteNormal(const K &key, const T &value, bool fOverwrite) {
        LOCK(cs_db);
        assert(pdb);
        if (this->fReadOnly) {
            assert(!"Write called on database in read-only mode");
        }
        bool update = ExistsNormal(key);
        if(fOverwrite==false && update)
            return false;
        if(txn) {
            try {
                CDataStream ssKey;
                ssKey.reserve(1000);
                ssKey << key;
                CDataStream ssValue;
                ssValue.reserve(10000);
                ssValue << value;
                txn->insert(update ? CTxnSecureBuffer::TXN_WRITE_UPDATE: CTxnSecureBuffer::TXN_WRITE_INSERT, ssKey, ssValue);
            } catch (const std::exception &) {
                return false;
            }
            return true;
        }
        bool ret = false;
        sqlite3_stmt *stmt=nullptr;
        try {
            std::vector<char> vchKey;
            CDBStream ssKey(&vchKey);
            ::Serialize(ssKey, key);

            std::vector<char> vchValue;
            CDBStream ssValue(&vchValue);
            ::Serialize(ssValue, value);

            do {
                if(update) {
                    if(::sqlite3_prepare_v2(pdb, "update key_value set value=$1 where key=$2;", -1, &stmt, nullptr)!=SQLITE_OK) break;
                    if(::sqlite3_bind_blob(stmt, 1, &vchValue[0], vchValue.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                    if(::sqlite3_bind_blob(stmt, 2, &vchKey[0], vchKey.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                } else {
                    if(::sqlite3_prepare_v2(pdb, "insert into key_value (key, value) values ($1, $2);", -1, &stmt, nullptr)!=SQLITE_OK) break;
                    if(::sqlite3_bind_blob(stmt, 1, &vchKey[0], vchKey.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                    if(::sqlite3_bind_blob(stmt, 2, &vchValue[0], vchValue.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                }
                if(::sqlite3_step(stmt)!=SQLITE_DONE) break;
                ret = true;
            } while(0);
            if(stmt) {
                if(::sqlite3_finalize(stmt)!=SQLITE_OK)
                    return false;
            }
        } catch (const std::exception &) {
            if(stmt)
                ::sqlite3_finalize(stmt);
            return false;
        }
        return ret;
    }

    template<typename K>
    bool EraseSecure(const K &key) {
        LOCK(cs_db);
        assert(pdb);
        if (this->fReadOnly) {
            assert(!"Erase called on database in read-only mode");
        }
        bool ret = false;
        try {
            CDataStream ssKey;
            ssKey.reserve(1000);
            ssKey << key;

            sqlite3_stmt *stmt;
            do {
                if(::sqlite3_prepare_v2(pdb, "delete from key_value where key=$1", -1, &stmt, nullptr)!=SQLITE_OK) break;
                if(::sqlite3_bind_blob(stmt, 1, &ssKey[0], ssKey.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                if(::sqlite3_step(stmt)==SQLITE_DONE)
                    ret = true;
            } while(0);
            if(::sqlite3_finalize(stmt)!=SQLITE_OK)
                return false;
        } catch (const std::exception &) {
            return false;
        }
        return ret;
    }

    template<typename K>
    bool EraseNormal(const K &key) {
        LOCK(cs_db);
        assert(pdb);
        if (this->fReadOnly) {
            assert(!"Erase called on database in read-only mode");
        }
        bool ret = false;
        try {
            std::vector<char> vchKey;
            CDBStream ssKey(&vchKey);
            ::Serialize(ssKey, key);

            sqlite3_stmt *stmt;
            do {
                if(::sqlite3_prepare_v2(pdb, "delete from key_value where key=$1", -1, &stmt, nullptr)!=SQLITE_OK) break;
                if(::sqlite3_bind_blob(stmt, 1, &vchKey[0], vchKey.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                if(::sqlite3_step(stmt)==SQLITE_DONE)
                    ret = true;
            } while(0);
            if(::sqlite3_finalize(stmt)!=SQLITE_OK)
                return false;
        } catch (const std::exception &) {
            return false;
        }
        return ret;
    }

    template<typename K>
    bool ExistsSecure(const K &key) {
        LOCK(cs_db);
        assert(pdb);
        bool ret = false;
        try {
            CDataStream ssKey;
            ssKey.reserve(1000);
            ssKey << key;

            sqlite3_stmt *stmt;
            do {
                if(::sqlite3_prepare_v2(pdb, "select value from key_value where key=$1", -1, &stmt, nullptr)!=SQLITE_OK) break;
                if(::sqlite3_bind_blob(stmt, 1, &ssKey[0], ssKey.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                if(::sqlite3_step(stmt) == SQLITE_ROW) {
                    // buffer cleanse
                    const char *pdata = reinterpret_cast<const char *>(::sqlite3_column_blob(stmt, 0));
                    const int size = ::sqlite3_column_bytes(stmt, 0) / sizeof(char);
                    cleanse::OPENSSL_cleanse(const_cast<char *>(pdata), size);
                    ret = true;
                }
                if(::sqlite3_step(stmt)!=SQLITE_DONE) // key value pair must be unique.
                    ret = false;
            } while(0);
            if(::sqlite3_finalize(stmt)!=SQLITE_OK)
                return false;
        } catch (const std::exception &) {
            return false;
        }
        return ret;
    }

    template<typename K>
    bool ExistsNormal(const K &key) {
        LOCK(cs_db);
        assert(pdb);
        bool ret = false;
        try {
            std::vector<char> vch;
            CDBStream ssKey(&vch);
            ::Serialize(ssKey, key);

            sqlite3_stmt *stmt;
            do {
                if(::sqlite3_prepare_v2(pdb, "select value from key_value where key=$1", -1, &stmt, nullptr)!=SQLITE_OK) break;
                if(::sqlite3_bind_blob(stmt, 1, &vch[0], vch.size(), SQLITE_STATIC)!=SQLITE_OK) break;
                if(::sqlite3_step(stmt) == SQLITE_ROW)
                    ret = true;
                if(::sqlite3_step(stmt)!=SQLITE_DONE) // key value pair must be unique.
                    ret = false;
            } while(0);
            if(::sqlite3_finalize(stmt)!=SQLITE_OK)
                return false;
        } catch (const std::exception &) {
            return false;
        }
        return ret;
    }
};

#endif
