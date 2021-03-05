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
protected:
    static constexpr int dbcache_size = 25;
    static constexpr int retry_counter = 10; // Create retry counter
    static constexpr bool fMockDb = false; // no using MockDB

    virtual void EnvShutdown()=0;
public:
    virtual bool Open(fs::path pathEnv_)=0;
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
    fs::path pathEnv;
    DbEnv dbenv;
    std::map<std::string, int> mapFileUseCount;
    std::map<std::string, Db *> mapDb; // database handle

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

    void IncUseCount(const std::string &strFile, bool fempty = true) {
        LOCK(cs_db);
        if(fempty==false && mapFileUseCount.count(strFile)==0)
            throw std::runtime_error("CDBEnv inc: No register strFile");
        if(mapFileUseCount.count(strFile)==0)
            mapFileUseCount.insert(std::make_pair(strFile, 0));
        ++mapFileUseCount[strFile];
    }
    void DecUseCount(const std::string &strFile) {
        LOCK(cs_db);
        if(mapFileUseCount.count(strFile)==0)
            throw std::runtime_error("CDBEnv dec: No register strFile");
        if(mapFileUseCount[strFile]==0)
            throw std::runtime_error("CDBEnv: strFile is already removed");
        --mapFileUseCount[strFile];
    }
    bool ExistsFileCount(const std::string &strFile) const {
        LOCK(cs_db);
        return mapFileUseCount.count(strFile)>0;
    }
    int GetFileCount(const std::string &strFile) const {
        LOCK(cs_db);
        if(mapFileUseCount.count(strFile)==0)
            throw std::runtime_error("CDBEnv getfilecount: No register strFile");
        std::map<std::string, int>::const_iterator mi = mapFileUseCount.find(strFile);
        return (*mi).second;
    }
    void EraseFileCount(const std::string &strFile) {
        LOCK(cs_db);
        if(ExistsFileCount(strFile))
            mapFileUseCount.erase(strFile);
    }
    int GetRefCount() const { // when 0, No using DB.
        LOCK(cs_db);
        int RefCount = 0;
        for(const auto &mi: mapFileUseCount)
            RefCount += mi.second;
        return RefCount;
    }
    bool FindFile(const std::string &strFile) const {
        LOCK(cs_db);
        std::map<std::string, int>::const_iterator mi = mapFileUseCount.find(strFile);
        return (mi != mapFileUseCount.end());
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
    CLevelDBEnv(const CLevelDBEnv &)=delete;
    CLevelDBEnv(CLevelDBEnv &&)=delete;
    CLevelDBEnv &operator=(const CLevelDBEnv &)=delete;
    CLevelDBEnv &operator=(CLevelDBEnv &&)=delete;

    CLevelDBEnv();
    ~CLevelDBEnv();

    bool fLevelDbEnvInit;
    leveldb::Options options;

    void EnvShutdown();
    static leveldb::Options GetOptions();

    // global pointer for LevelDB object instance
    leveldb::DB *ptxdb;

    // only using CLevelDBEnv
    static CCriticalSection cs_leveldb;

public:
    static CLevelDBEnv &get_instance() {
        LOCK(cs_leveldb);
        static CLevelDBEnv obj;
        return obj;
    }

    leveldb::DB *get_ptxdb() const {
        LOCK(cs_leveldb);
        return ptxdb;
    }

    bool restart(fs::path pathEnv_, bool fRemoveOld, void (*func)(bool fRemoveOld)) {
        LOCK(cs_leveldb);
        EnvShutdown();
        func(fRemoveOld);
        return Open(pathEnv_);
    }

    bool Open(fs::path pathEnv_);
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
 * using (Wallet): CWalletDB, CWallethdDB, CWalletqDB
 */
class CDB
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

protected:
    explicit CDB(const char *pszFile, const char *pszMode = "r+"); // open DB
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

    Dbc *GetCursor();

    // fFlags: DB_SET_RANGE, DB_NEXT, DB_NEXT, ...
    static int ReadAtCursor(Dbc *pcursor, CDataStream &ssKey, CDataStream &ssValue, unsigned int fFlags = DB_NEXT);

public:
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
class CLevelDB
{
private:
    CLevelDB(const CLevelDB &)=delete;
    CLevelDB(CLevelDB &&)=delete;
    CLevelDB &operator=(const CLevelDB &)=delete;
    CLevelDB &operator=(CLevelDB &&)=delete;

    bool ScanBatch(const CDataStream &key, std::string *value, bool *deleted) const;
    bool ScanBatch(const CDBStream &key, std::string *value, bool *deleted) const;

    // A batch stores up writes and deletes for atomic application. When this
    // field is non-NULL, writes/deletes go there instead of directly to disk.
    leveldb::WriteBatch *activeBatch;

    bool fReadOnly;

    // Points to the global instance
    leveldb::DB *pdb;

public:
    //
    // About CLevelDB: const_iterator
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
            return *this;
        }
        const_iterator(const_iterator &&obj) noexcept {
            operator=(std::move(obj));
        }

        const_iterator() noexcept {
            p = nullptr;
        }
        explicit const_iterator(leveldb::Iterator *pIn) noexcept {
            assert(pIn);
            p = pIn;
        }
        ~const_iterator() {
            delete p;
        }

        void operator++() noexcept {
            assert(p);
            p->Next();
            if(p->Valid()==false) {
                delete p;
                p = nullptr;
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
    };

    mutable leveldb::Iterator *p;
    template <typename KEY, typename VALUE>
    NODISCARD bool seek(const KEY &key, const VALUE &val) const noexcept {
        if(p) delete p;
        p = pdb->NewIterator(leveldb::ReadOptions());
        if(! p)
            return false;
        CDataStream ssStartKey(0, 0);
        ssStartKey << std::make_pair(key, val);
        p->Seek(ssStartKey.str());
        return true;
    }

    const_iterator begin() const noexcept {
        return std::move(const_iterator(p));
    }
    constexpr const_iterator end() const noexcept {
        return std::move(const_iterator());
    }

public:
    CLevelDB(const char *pszMode ="r+");
    ~CLevelDB();

    bool TxnBegin();
    bool TxnCommit();
    bool TxnAbort();

    template<typename K, typename T>
    bool Read(const K &key, T &value) {
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
            CDBStream stream((char *)&strValue[0], strValue.size());
            ::Unserialize(stream, value);
        } catch (const std::exception &) {
            return false;
        }

        return true;
    }

    template<typename K, typename T>
    bool Write(const K &key, const T &value) {
        if (this->fReadOnly)
            assert(!"Write called on database in read-only mode");

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
    bool Erase(const K &key) {
        if (! this->pdb)
            return false;
        if (this->fReadOnly)
            assert(!"Erase called on database in read-only mode");

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
    bool Exists(const K &key) {

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

#endif
