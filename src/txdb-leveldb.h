// Copyright (c) 2009-2012 The Bitcoin Developers.
// Copyright (c) 2018-2021 The SorachanCoin developers
// Authored by Google, Inc.
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Learn more: http://code.google.com/p/leveldb/

#ifndef BITCOIN_LEVELDB_H
#define BITCOIN_LEVELDB_H

// SorachanCoin
// Multi-Threading supported

#include <main.h>
#include <map>
#include <string>
#include <vector>
#include <leveldb/db.h>
#include <leveldb/write_batch.h>
#include <util/thread.h>

class CTxDB // Note: no necessary virtual.
{
public:
    CTxDB(const char *pszMode = "r+");
    ~CTxDB();
    void Close(); // Destroys the underlying shared global state accessed by this TxDB.

    bool TxnBegin();
    bool TxnCommit();
    bool TxnAbort();

    bool ReadVersion(int &nVersion);
    bool WriteVersion(int nVersion);

    bool ReadTxIndex(uint256 hash, CTxIndex &txindex);
    bool UpdateTxIndex(uint256 hash, const CTxIndex &txindex);
    bool AddTxIndex(const CTransaction &tx, const CDiskTxPos &pos, int nHeight);
    bool EraseTxIndex(const CTransaction& tx);
    bool ContainsTx(uint256 hash);

    bool ReadDiskTx(uint256 hash, CTransaction &tx, CTxIndex &txindex);
    bool ReadDiskTx(uint256 hash, CTransaction &tx);
    bool ReadDiskTx(COutPoint outpoint, CTransaction &tx, CTxIndex &txindex);
    bool ReadDiskTx(COutPoint outpoint, CTransaction &tx);

    bool WriteBlockIndex(const CDiskBlockIndex &blockindex);

    bool ReadHashBestChain(uint256 &hashBestChain);
    bool WriteHashBestChain(uint256 hashBestChain);

    bool ReadBestInvalidTrust(CBigNum &bnBestInvalidTrust);
    bool WriteBestInvalidTrust(CBigNum bnBestInvalidTrust);

    bool ReadSyncCheckpoint(uint256 &hashCheckpoint);
    bool WriteSyncCheckpoint(uint256 hashCheckpoint);

    bool ReadCheckpointPubKey(std::string &strPubKey);
    bool WriteCheckpointPubKey(const std::string &strPubKey);

    bool ReadModifierUpgradeTime(unsigned int &nUpgradeTime);
    bool WriteModifierUpgradeTime(const unsigned int &nUpgradeTime);

    bool LoadBlockIndex();

private:
    CTxDB(const CTxDB &)=delete;
    CTxDB(CTxDB &&)=delete;
    CTxDB &operator=(const CTxDB &)=delete;
    CTxDB &operator=(CTxDB &&)=delete;

    // global pointer for LevelDB object instance
    static leveldb::DB *txdb;

    // Points to the global instance
    leveldb::DB *pdb;

    // A batch stores up writes and deletes for atomic application. When this
    // field is non-NULL, writes/deletes go there instead of directly to disk.
    leveldb::WriteBatch *activeBatch;
    leveldb::Options options;
    bool fReadOnly;
    int nVersion;

    leveldb::Options GetOptions();
    void init_blockindex(leveldb::Options &options, bool fRemoveOld = false);

    // Returns true and sets (value,false) if activeBatch contains the given key
    // or leaves value alone and sets deleted = true if activeBatch contains a
    // delete for it.
    bool ScanBatch(const CDataStream &key, std::string *value, bool *deleted) const;

    template<typename K, typename T>
    bool Read(const K &key, T &value);

    template<typename K, typename T>
    bool Write(const K &key, const T &value);

    template<typename K>
    bool Erase(const K &key);

    template<typename K>
    bool Exists(const K &key);
};

// multi-threading DB
class CMTxDB final : public CTxDB
{
public:
    CMTxDB(const char *pszMode = "r+") : thread(&CMTxDB::dbcall), CTxDB(pszMode) {}
    ~CMTxDB() {}

    bool start() {return thread.start(nullptr, this);}
    void stop() {thread.stop();}
    bool signal() const {return thread.signal();}

    template<typename K, typename T>
    bool Write(const K &key, const T &value) {
        LOCK(csTxdb_write);
        return CTxDB::Write(key, value);
    }

    template<typename K>
    bool Erase(const K &key) {
        LOCK(csTxdb_write);
        return CTxDB::Erase(key);
    }

private:
    static CCriticalSection csTxdb_write; // Write and Erase
    unsigned int dbcall(cla_thread<CMTxDB>::thread_data *data);
    cla_thread<CMTxDB> thread;
};

#endif // BITCOIN_DB_H
