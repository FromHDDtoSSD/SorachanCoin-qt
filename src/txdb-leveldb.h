// Copyright (c) 2009-2012 The Bitcoin Developers.
// Copyright (c) 2018-2021 The SorachanCoin developers
// Authored by Google, Inc.
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Learn more: http://code.google.com/p/leveldb/

#ifndef BITCOIN_LEVELDB_H
#define BITCOIN_LEVELDB_H

// SorachanCoin
// Hybrid DB Blockchain
// Multi-Threading supported

#include <main.h>
#include <map>
#include <string>
#include <vector>
#ifdef USE_LEVELDB
# include <leveldb/db.h>
# include <leveldb/write_batch.h>
#endif
#include <util/thread.h>
#include <db.h>

#ifdef BLK_SQL_MODE
class CTxDBHybrid {
#else
class CTxDBHybrid : public CLevelDB {
#endif
    CTxDBHybrid(const CTxDBHybrid &)=delete;
    CTxDBHybrid(CTxDBHybrid &&)=delete;
    CTxDBHybrid &operator=(const CTxDBHybrid &)=delete;
    CTxDBHybrid &operator=(CTxDBHybrid &&)=delete;
public:
    explicit CTxDBHybrid(const char *pszMode="r+");
    virtual ~CTxDBHybrid();

#ifdef BLK_SQL_MODE
    IDB::DbIterator GetIteCursor(std::string mkey) {
        return std::move(sqldb.GetIteCursor(mkey, false));
    }

    template <typename K, typename T>
    bool Read(const K &key, T &value) {
        return sqldb.Read(key, value);
    }

    template <typename K, typename T>
    bool Write(const K &key, const T &value) {
        return sqldb.Write(key, value);
    }

    template <typename K>
    bool Erase(const K &key) {
        return sqldb.Erase(key);
    }

    template <typename K>
    bool Exists(const K &key) {
        return sqldb.Exists(key);
    }

    bool ReadVersion(int &nVersion) {
        return sqldb.ReadVersion(nVersion);
    }
    bool WriteVersion(int nVersion) {
        return sqldb.WriteVersion(nVersion);
    }

    bool TxnBegin() {
        return sqldb.TxnBegin();
    }
    bool TxnCommit() {
        return sqldb.TxnCommit();
    }
    bool TxnAbort() {
        return sqldb.TxnAbort();
    }
#endif

#ifdef BLK_SQL_MODE
private:
    CSqliteDB sqldb;
#endif
};

class CTxDB final : protected CTxDBHybrid // should use protected: hide Write() method.
{
    CTxDB(const CTxDB &)=delete;
    CTxDB(CTxDB &&)=delete;
    CTxDB &operator=(const CTxDB &)=delete;
    CTxDB &operator=(CTxDB &&)=delete;
public:
    CTxDB(const char *pszMode = "r+");
    ~CTxDB();

    bool TxnBegin() {return CTxDBHybrid::TxnBegin();}
    bool TxnCommit() {return CTxDBHybrid::TxnCommit();}
    bool TxnAbort() {return CTxDBHybrid::TxnAbort();}

    void init_blockindex(const char *pszMode, bool fRemoveOld = false);

    bool ReadTxIndex(uint256 hash, CTxIndex &txindex);
    bool UpdateTxIndex(uint256 hash, const CTxIndex &txindex);
    bool AddTxIndex(const CTransaction &tx, const CDiskTxPos &pos, int nHeight);
    bool EraseTxIndex(const CTransaction &tx);
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

    bool WriteBlockHashType(uint256 hash, const BLOCK_HASH_MODIFIER &modifier);

    bool LoadBlockIndex(std::unordered_map<uint256, CBlockIndex *, CCoinsKeyHasher> &mapBlockIndex,
                        std::set<std::pair<COutPoint, unsigned int> > &setStakeSeen,
                        CBlockIndex *&pindexGenesisBlock,
                        uint256 &hashBestChain,
                        int &nBestHeight,
                        CBlockIndex *&pindexBest,
                        uint256 &nBestInvalidTrust,
                        uint256 &nBestChainTrust);
};

#endif // BITCOIN_DB_H
