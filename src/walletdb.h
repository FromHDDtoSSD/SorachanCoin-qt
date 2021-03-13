// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLETDB_H
#define BITCOIN_WALLETDB_H

#include <db.h>
#include <keystore.h>

class CKeyPool;
class CAccount;
class CAccountingEntry;

// Error statuses for the wallet database
enum DBErrors
{
    DB_LOAD_OK,
    DB_CORRUPT,
    DB_NONCRITICAL_ERROR,      // Wallet is succeeded in loading from DB, but failed to decipher it.
    DB_TOO_NEW,
    DB_LOAD_FAIL,
    DB_NEED_REWRITE            // Wallet rewriting is completed, it needs restart.
};

class CKeyMetadata
{
private:
    CKeyMetadata(const CKeyMetadata &)=delete;
    // CKeyMetadata(CKeyMetadata &&)=delete;
    // CKeyMetadata &operator=(const CKeyMetadata &)=delete;
    // CKeyMetadata &operator=(CKeyMetadata &&)=delete;

public:
    static const int CURRENT_VERSION = 1;

    int nVersion;
    int64_t nCreateTime; // 0 means unknown

    CKeyMetadata() {
        SetNull();
    }

    CKeyMetadata(int64_t nCreateTime_) {
        nVersion = CKeyMetadata::CURRENT_VERSION;
        nCreateTime = nCreateTime_;
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(this->nCreateTime);
    }

    void SetNull() {
        nVersion = CKeyMetadata::CURRENT_VERSION;
        nCreateTime = 0;
    }
};

//
// SorachanCoin: wallet DB Hybrid system
//
// Note that LevelDB "bool fSecureIn" always is used turning on "true". handle "privateKey".
//
class CDBHybrid
{
    CDBHybrid(const CDBHybrid &)=delete;
    CDBHybrid &operator=(const CDBHybrid &)=delete;
    CDBHybrid(CDBHybrid &&)=delete;
    CDBHybrid &operator=(CDBHybrid &&)=delete;
public:
    CDBHybrid(const std::string &strFilename, const std::string &strLevelDB, const std::string &strSqlFile, const char *pszMode="r+");
    virtual ~CDBHybrid();

    IDB::DbIterator GetIteCursor();

    template<typename K, typename T>
    bool Write(const K &key, const T &value, bool fOverwrite = true) {
        bool ret1 = bdb.Write(key, value, fOverwrite);
        bool ret2 = ldb.Write(key, value, fOverwrite);
        assert(ret1 && ret2);
        {
            T valid;
            assert(ldb.Read(key, valid));
            CDataStream ssValue1;
            ssValue1 << value;
            CDataStream ssValue2;
            ssValue2 << valid;
            assert(ssValue1.size()==ssValue2.size());
            assert(memcmp(&ssValue1[0], &ssValue2[0], ssValue1.size())==0);
        }
        return ret2;
    }

    /*
    template<typename K, typename T>
    bool Read(const K &key, T &value) {
        bool ret = CDB::Read(key, value);
        T lval;
        if(! ldb.Read(key, lval)) {
            assert(ldb.Write(key, value)); // sync from CDB to CLevelDB.
        }
        return ret;
    }
    */

    template<typename K, typename T>
    bool Read(const K &key, T &value) {
        if(! ldb.Read(key, value))
            return false;
        CDataStream ssValue1;
        ssValue1 << value;

        T value2;
        if(! bdb.Read(key, value2))
            return false;

        CDataStream ssValue2;
        ssValue2 << value2;

        debugcs::instance() << "CDBHybrid::Read debug mode size:" << ssValue1.size() << debugcs::endl(); // only can display size.
        assert(ssValue1.size()==ssValue2.size());
        assert(std::memcmp(&ssValue1[0], &ssValue2[0], ssValue1.size())==0);
        return true;
    }

    template<typename K>
    bool Erase(const K &key) {
        bool ret1 = bdb.Erase(key);
        bool ret2 = ldb.Erase(key);
        assert(ret1==ret2);
        return ret1;
    }

    template<typename K>
    bool Exists(const K &key) {
        bool ret1 = bdb.Exists(key);
        bool ret2 = ldb.Exists(key);
        assert(ret1==ret2);
        return ret1;
    }

    bool TxnBegin();
    bool TxnCommit();
    bool TxnAbort();

    bool ReadVersion(int &nVersion);
    bool WriteVersion(int nVersion);

    /*
    template<typename K, typename T>
    bool Write(const K &key, const T &value, bool fOverwrite = true) {
        bool ret = ldb.Write(key, value, fOverwrite);
        if(ret)
            CLevelDBEnv::get_instance().Flush(ldb_name);
        return ret;
    }

    template<typename K, typename T>
    bool Read(const K &key, T &value) {
        return ldb.Read(key, value);
    }

    template<typename K>
    bool Erase(const K &key) {
        bool ret = ldb.Erase(key);
        if(ret)
            CLevelDBEnv::get_instance().Flush(ldb_name);
        return ret;
    }

    template<typename K>
    bool Exists(const K &key) {
        return ldb.Exists(key);
    }
    */

private:
    std::string ldb_name;
    std::string sqldb_name;
    CDB bdb;
    CLevelDB ldb;
    CSqliteDB sqldb;
};

// Access to the wallet database (CWalletDB: wallet.dat / txwallet)
class CWalletScanState;
class CWalletDB final : public CDBHybrid
{
    CWalletDB(const CWalletDB &)=delete;
    CWalletDB &operator=(const CWalletDB &)=delete;
    CWalletDB(CWalletDB &&)=delete;
    CWalletDB &operator=(CWalletDB &&)=delete;
public:
    explicit CWalletDB(const std::string &strFilename, const std::string &strLevelDB, const std::string &strSqlFile, const char *pszMode="r+");

    bool WriteName(const std::string &strAddress, const std::string &strName);
    bool EraseName(const std::string &strAddress);

    bool WriteTx(uint256 hash, const CWalletTx &wtx) {
        dbparam::IncWalletUpdate();
        return Write(std::make_pair(std::string("tx"), hash), wtx);
    }

    bool EraseTx(uint256 hash) {
        dbparam::IncWalletUpdate();
        return Erase(std::make_pair(std::string("tx"), hash));
    }

    bool WriteKey(const CPubKey &key, const CPrivKey &vchPrivKey, const CKeyMetadata &keyMeta) {
        dbparam::IncWalletUpdate();
        if(! Write(std::make_pair(std::string("keymeta"), key), keyMeta))
            return false;
        if(! Write(std::make_pair(std::string("key"), key), vchPrivKey, false))
            return false;
        return true;
    }

    bool WriteMalleableKey(const CMalleableKeyView &keyView, const CSecret &vchSecretH, const CKeyMetadata &keyMeta) {
        dbparam::IncWalletUpdate();
        if(! Write(std::make_pair(std::string("malmeta"), keyView.ToString()), keyMeta))
            return false;
        if(! Write(std::make_pair(std::string("malpair"), keyView.ToString()), vchSecretH, false))
            return false;
        return true;
    }

    bool WriteCryptedMalleableKey(const CMalleableKeyView &keyView, const std::vector<unsigned char> &vchCryptedSecretH, const CKeyMetadata &keyMeta) {
        dbparam::IncWalletUpdate();
        if(! Write(std::make_pair(std::string("malmeta"), keyView.ToString()), keyMeta))
            return false;
        if(! Write(std::make_pair(std::string("malcpair"), keyView.ToString()), vchCryptedSecretH, false))
            return false;

        Erase(std::make_pair(std::string("malpair"), keyView.ToString()));
        return true;
    }

    bool WriteCryptedKey(const CPubKey &key, const std::vector<unsigned char> &vchCryptedSecret, const CKeyMetadata &keyMeta) {
        dbparam::IncWalletUpdate();
        bool fEraseUnencryptedKey = true;

        if (! Write(std::make_pair(std::string("keymeta"), key), keyMeta))
            return false;
        if (! Write(std::make_pair(std::string("ckey"), key), vchCryptedSecret, false))
            return false;
        if (fEraseUnencryptedKey) {
            Erase(std::make_pair(std::string("key"), key));
            Erase(std::make_pair(std::string("wkey"), key));
        }
        return true;
    }

    bool WriteMasterKey(unsigned int nID, const CMasterKey &kMasterKey) {
        dbparam::IncWalletUpdate();
        return Write(std::make_pair(std::string("mkey"), nID), kMasterKey, true);
    }

    bool EraseMasterKey(unsigned int nID) {
        dbparam::IncWalletUpdate();
        return Erase(std::make_pair(std::string("mkey"), nID));
    }

    bool EraseCryptedKey(const CPubKey &key) {
        return Erase(std::make_pair(std::string("ckey"), key));
    }

    bool EraseCryptedMalleableKey(const CMalleableKeyView &keyView) {
        return Erase(std::make_pair(std::string("malcpair"), keyView.ToString()));
    }

    bool WriteCScript(const uint160 &hash, const CScript &redeemScript) {
        dbparam::IncWalletUpdate();
        return Write(std::make_pair(std::string("cscript"), hash), redeemScript, false);
    }

    bool WriteWatchOnly(const CScript &dest) {
        dbparam::IncWalletUpdate();
        return Write(std::make_pair(std::string("watchs"), dest), '1');
    }

    bool EraseWatchOnly(const CScript &dest) {
        dbparam::IncWalletUpdate();
        return Erase(std::make_pair(std::string("watchs"), dest));
    }

    bool WriteBestBlock(const CBlockLocator &locator) {
        dbparam::IncWalletUpdate();
        return Write(std::string("bestblock"), locator);
    }

    bool ReadBestBlock(CBlockLocator &locator) {
        return Read(std::string("bestblock"), locator);
    }

    bool WriteOrderPosNext(int64_t nOrderPosNext) {
        dbparam::IncWalletUpdate();
        return Write(std::string("orderposnext"), nOrderPosNext);
    }

    bool WriteDefaultKey(const CPubKey &key) {
        dbparam::IncWalletUpdate();
        return Write(std::string("defaultkey"), key);
    }

    bool ReadPool(int64_t nPool, CKeyPool &keypool) {
        return Read(std::make_pair(std::string("pool"), nPool), keypool);
    }

    bool WritePool(int64_t nPool, const CKeyPool &keypool) {
        dbparam::IncWalletUpdate();
        return Write(std::make_pair(std::string("pool"), nPool), keypool);
    }

    bool ErasePool(int64_t nPool) {
        dbparam::IncWalletUpdate();
        return Erase(std::make_pair(std::string("pool"), nPool));
    }

    bool WriteMinVersion(int nVersion) {
        return Write(std::string("minversion"), nVersion);
    }

    bool ReadAccount(const std::string &strAccount, CAccount &account);
    bool WriteAccount(const std::string &strAccount, const CAccount &account);

    bool WriteAccountingEntry(const CAccountingEntry &acentry);
    int64_t GetAccountCreditDebit(const std::string &strAccount);
    void ListAccountCreditDebit(const std::string &strAccount, std::list<CAccountingEntry> &acentries);

    DBErrors ReorderTransactions(CWallet *);
    DBErrors LoadWallet(CWallet *pwallet);
    DBErrors FindWalletTx(CWallet *pwallet, std::vector<uint256> &vTxHash);
    DBErrors ZapWalletTx(CWallet *pwallet);

    static bool Recover(std::string filename, bool fOnlyKeys=false);

private:
    static uint64_t nAccountingEntryNumber;

    static bool ReadKeyValue(CWallet *pwallet, CDataStream &ssKey, CDataStream &ssValue, CWalletScanState &wss, std::string &strType, std::string &strErr);
    static bool IsKeyType(std::string strType);
    bool WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry &acentry);
};

#endif // BITCOIN_WALLETDB_H
