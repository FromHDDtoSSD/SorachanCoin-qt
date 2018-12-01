// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef BITCOIN_WALLETDB_H
#define BITCOIN_WALLETDB_H

#include "db.h"
//#include "base58.h"
#include "keystore.h"

class CKeyPool;
class CAccount;
class CAccountingEntry;

//
// Error statuses for the wallet database
//
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
    CKeyMetadata(const CKeyMetadata &); //{}
    // CKeyMetadata &operator=(const CKeyMetadata &); // {}

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

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(this->nCreateTime);
    )

    void SetNull() {
        nVersion = CKeyMetadata::CURRENT_VERSION;
        nCreateTime = 0;
    }
};

//
// Access to the wallet database (wallet.dat)
//
class CWalletScanState;
class CWalletDB : public CDB
{
public:
    CWalletDB(std::string strFilename, const char *pszMode="r+") : CDB(strFilename.c_str(), pszMode) {}

private:
    CWalletDB(const CWalletDB &); // {}
    CWalletDB &operator=(const CWalletDB &); // {}

    static uint64_t nAccountingEntryNumber;

public:
    bool WriteName(const std::string &strAddress, const std::string &strName);
    bool EraseName(const std::string &strAddress);

    bool WriteTx(uint256 hash, const CWalletTx &wtx) {
        dbparam::nWalletDBUpdated++;
        return Write(std::make_pair(std::string("tx"), hash), wtx);
    }

    bool EraseTx(uint256 hash) {
        dbparam::nWalletDBUpdated++;
        return Erase(std::make_pair(std::string("tx"), hash));
    }

    bool WriteKey(const CPubKey &key, const CPrivKey &vchPrivKey, const CKeyMetadata &keyMeta) {
        dbparam::nWalletDBUpdated++;
        if(! Write(std::make_pair(std::string("keymeta"), key), keyMeta)) {
            return false;
        }
        if(! Write(std::make_pair(std::string("key"), key), vchPrivKey, false)) {
            return false;
        }
        return true;
    }

    bool WriteMalleableKey(const CMalleableKeyView &keyView, const CSecret &vchSecretH, const CKeyMetadata &keyMeta) {
        dbparam::nWalletDBUpdated++;
        if(! Write(std::make_pair(std::string("malmeta"), keyView.ToString()), keyMeta)) {
            return false;
        }
        if(! Write(std::make_pair(std::string("malpair"), keyView.ToString()), vchSecretH, false)) {
            return false;
        }
        return true;
    }

    bool WriteCryptedMalleableKey(const CMalleableKeyView &keyView, const std::vector<unsigned char> &vchCryptedSecretH, const CKeyMetadata &keyMeta) {
        dbparam::nWalletDBUpdated++;
        if(! Write(std::make_pair(std::string("malmeta"), keyView.ToString()), keyMeta)) {
            return false;
        }
        if(! Write(std::make_pair(std::string("malcpair"), keyView.ToString()), vchCryptedSecretH, false)) {
            return false;
        }

        Erase(std::make_pair(std::string("malpair"), keyView.ToString()));
        return true;
    }


    bool WriteCryptedKey(const CPubKey &key, const std::vector<unsigned char> &vchCryptedSecret, const CKeyMetadata &keyMeta) {
        dbparam::nWalletDBUpdated++;
        bool fEraseUnencryptedKey = true;

        if (! Write(std::make_pair(std::string("keymeta"), key), keyMeta)) {
            return false;
        }
        if (! Write(std::make_pair(std::string("ckey"), key), vchCryptedSecret, false)) {
            return false;
        }
        if (fEraseUnencryptedKey) {
            Erase(std::make_pair(std::string("key"), key));
            Erase(std::make_pair(std::string("wkey"), key));
        }
        return true;
    }

    bool WriteMasterKey(unsigned int nID, const CMasterKey &kMasterKey) {
        dbparam::nWalletDBUpdated++;
        return Write(std::make_pair(std::string("mkey"), nID), kMasterKey, true);
    }

    bool EraseMasterKey(unsigned int nID) {
        dbparam::nWalletDBUpdated++;
        return Erase(std::make_pair(std::string("mkey"), nID));
    }

    bool EraseCryptedKey(const CPubKey &key) {
        return Erase(std::make_pair(std::string("ckey"), key));
    }

    bool EraseCryptedMalleableKey(const CMalleableKeyView &keyView) {
        return Erase(std::make_pair(std::string("malcpair"), keyView.ToString()));
    }

    bool WriteCScript(const uint160 &hash, const CScript &redeemScript) {
        dbparam::nWalletDBUpdated++;
        return Write(std::make_pair(std::string("cscript"), hash), redeemScript, false);
    }

    bool WriteWatchOnly(const CScript &dest) {
        dbparam::nWalletDBUpdated++;
        return Write(std::make_pair(std::string("watchs"), dest), '1');
    }

    bool EraseWatchOnly(const CScript &dest) {
        dbparam::nWalletDBUpdated++;
        return Erase(std::make_pair(std::string("watchs"), dest));
    }

    bool WriteBestBlock(const CBlockLocator &locator) {
        dbparam::nWalletDBUpdated++;
        return Write(std::string("bestblock"), locator);
    }

    bool ReadBestBlock(CBlockLocator &locator) {
        return Read(std::string("bestblock"), locator);
    }

    bool WriteOrderPosNext(int64_t nOrderPosNext) {
        dbparam::nWalletDBUpdated++;
        return Write(std::string("orderposnext"), nOrderPosNext);
    }

    bool WriteDefaultKey(const CPubKey &key) {
        dbparam::nWalletDBUpdated++;
        return Write(std::string("defaultkey"), key);
    }

    bool ReadPool(int64_t nPool, CKeyPool &keypool) {
        return Read(std::make_pair(std::string("pool"), nPool), keypool);
    }

    bool WritePool(int64_t nPool, const CKeyPool &keypool) {
        dbparam::nWalletDBUpdated++;
        return Write(std::make_pair(std::string("pool"), nPool), keypool);
    }

    bool ErasePool(int64_t nPool) {
        dbparam::nWalletDBUpdated++;
        return Erase(std::make_pair(std::string("pool"), nPool));
    }

    bool WriteMinVersion(int nVersion) {
        return Write(std::string("minversion"), nVersion);
    }

    bool ReadAccount(const std::string &strAccount, CAccount &account);
    bool WriteAccount(const std::string &strAccount, const CAccount &account);

private:
    static bool ReadKeyValue(CWallet *pwallet, CDataStream &ssKey, CDataStream &ssValue, CWalletScanState &wss, std::string &strType, std::string &strErr);
    static bool IsKeyType(std::string strType);

    bool WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry &acentry);

public:
    bool WriteAccountingEntry(const CAccountingEntry &acentry);
    int64_t GetAccountCreditDebit(const std::string &strAccount);
    void ListAccountCreditDebit(const std::string &strAccount, std::list<CAccountingEntry> &acentries);

    DBErrors ReorderTransactions(CWallet *);
    DBErrors LoadWallet(CWallet *pwallet);
    DBErrors FindWalletTx(CWallet *pwallet, std::vector<uint256> &vTxHash);
    DBErrors ZapWalletTx(CWallet *pwallet);

    static bool Recover(CDBEnv &dbenv, std::string filename, bool fOnlyKeys);
    static bool Recover(CDBEnv &dbenv, std::string filename);
};

#endif // BITCOIN_WALLETDB_H
//@
