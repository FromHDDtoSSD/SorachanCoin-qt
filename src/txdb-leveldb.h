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

template <typename HASH>
class CTxDB_impl // Note: no necessary virtual.
{
public:
    CTxDB_impl(const char *pszMode = "r+");
    ~CTxDB_impl();
    void Close(); // Destroys the underlying shared global state accessed by this TxDB.

    bool TxnBegin();
    bool TxnCommit();
    bool TxnAbort();

    bool ReadVersion(int &nVersion);
    bool WriteVersion(int nVersion);

    bool ReadTxIndex(HASH hash, CTxIndex &txindex);
    bool UpdateTxIndex(HASH hash, const CTxIndex &txindex);
    bool AddTxIndex(const CTransaction_impl<HASH> &tx, const CDiskTxPos &pos, int nHeight);
    bool EraseTxIndex(const CTransaction_impl<HASH> &tx);
    bool ContainsTx(HASH hash);

    bool ReadDiskTx(HASH hash, CTransaction_impl<HASH> &tx, CTxIndex &txindex);
    bool ReadDiskTx(HASH hash, CTransaction_impl<HASH> &tx);
    bool ReadDiskTx(COutPoint_impl<HASH> outpoint, CTransaction_impl<HASH> &tx, CTxIndex &txindex);
    bool ReadDiskTx(COutPoint_impl<HASH> outpoint, CTransaction_impl<HASH> &tx);

    bool WriteBlockIndex(const CDiskBlockIndex &blockindex);

    bool ReadHashBestChain(HASH &hashBestChain);
    bool WriteHashBestChain(HASH hashBestChain);

    bool ReadBestInvalidTrust(CBigNum &bnBestInvalidTrust);
    bool WriteBestInvalidTrust(CBigNum bnBestInvalidTrust);

    bool ReadSyncCheckpoint(HASH &hashCheckpoint);
    bool WriteSyncCheckpoint(HASH hashCheckpoint);

    bool ReadCheckpointPubKey(std::string &strPubKey);
    bool WriteCheckpointPubKey(const std::string &strPubKey);

    bool ReadModifierUpgradeTime(unsigned int &nUpgradeTime);
    bool WriteModifierUpgradeTime(const unsigned int &nUpgradeTime);

    bool LoadBlockIndex(std::map<HASH, CBlockIndex_impl<HASH> *> &mapBlockIndex,
                        std::set<std::pair<COutPoint_impl<HASH>, unsigned int> > &setStakeSeen,
                        CBlockIndex_impl<HASH> *&pindexGenesisBlock,
                        HASH &hashBestChain,
                        int &nBestHeight,
                        CBlockIndex_impl<HASH> *&pindexBest,
                        HASH &nBestInvalidTrust,
                        HASH &nBestChainTrust);

private:
    CTxDB_impl(const CTxDB_impl &)=delete;
    CTxDB_impl(CTxDB_impl &&)=delete;
    CTxDB_impl &operator=(const CTxDB_impl &)=delete;
    CTxDB_impl &operator=(CTxDB_impl &&)=delete;

    // global pointer for LevelDB object instance
    static leveldb::DB *ptxdb;

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
using CTxDB = CTxDB_impl<uint256>; // mainchain
//using CTxDB_finexDriveChain = CTxDB_impl<uint65536>; // sidechain-1

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
