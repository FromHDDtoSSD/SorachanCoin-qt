// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2024 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <walletdb.h>
#include <wallet.h>
#include <address/base58.h>
#include <iostream>
#include <fstream>
#include <boost/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/variant/get.hpp>
#include <boost/algorithm/string.hpp>
#include <util/time.h>
#include <util/thread.h>

uint64_t CWalletDB::nAccountingEntryNumber = 0;

////////////////////////////////////////////////
// SorachanCoin
// CWalletDB use CSqliteDB. (CDB is up to v3)
//
// CDBHybrid
////////////////////////////////////////////////

#ifdef WALLET_SQL_MODE
CDBHybrid::CDBHybrid(const std::string &strFilename, const std::string &strSqlFile, const char *pszMode/*="r+"*/) :
    sqldb(strSqlFile, pszMode, true) {
    (void)strFilename;
    sqldb_name = strSqlFile;
    //debugcs::instance() << "CDBHybrid::CDBHybrid strSqliteDB:" << strLevelDB.c_str() << debugcs::endl();
}
#else
CDBHybrid::CDBHybrid(const std::string &strFilename, const std::string &strSqlFile, const char *pszMode/*="r+"*/) :
    bdb(strFilename.c_str(), pszMode) {
    sqldb_name = strSqlFile;
    //debugcs::instance() << "CDBHybrid::CDBHybrid strSqliteDB:" << strLevelDB.c_str() << debugcs::endl();
}
#endif

CDBHybrid::~CDBHybrid() {}

#ifndef WALLET_SQL_MODE
IDB::DbIterator CDBHybrid::GetIteCursor() {
    return bdb.GetIteCursor();
}

bool CDBHybrid::TxnBegin() {
    return bdb.TxnBegin();
}

bool CDBHybrid::TxnCommit() {
    return bdb.TxnCommit();
}

bool CDBHybrid::TxnAbort() {
    return bdb.TxnAbort();
}

bool CDBHybrid::ReadVersion(int &nVersion) {
    return bdb.ReadVersion(nVersion);
}

bool CDBHybrid::WriteVersion(int nVersion) {
    return bdb.WriteVersion(nVersion);
}
#else
IDB::DbIterator CDBHybrid::GetIteCursor() {
    return sqldb.GetIteCursor();
}
IDB::DbIterator CDBHybrid::GetIteCursor(std::string mkey) {
    return sqldb.GetIteCursor(mkey);
}

bool CDBHybrid::TxnBegin() {
    return sqldb.TxnBegin();
}

bool CDBHybrid::TxnCommit() {
    return sqldb.TxnCommit();
}

bool CDBHybrid::TxnAbort() {
    return sqldb.TxnAbort();
}

bool CDBHybrid::ReadVersion(int &nVersion) {
    return sqldb.ReadVersion(nVersion);
}

bool CDBHybrid::WriteVersion(int nVersion) {
    return sqldb.WriteVersion(nVersion);
}
#endif

////////////////////////////////////////////////////////////
// CWalletDB
////////////////////////////////////////////////////////////

CWalletDB::CWalletDB(const std::string &strFilename, const std::string &strLevelDB, const std::string &strSqlFile, const char *pszMode/*="r+"*/) :
    CDBHybrid(strFilename.c_str(), strSqlFile, pszMode) {
    (void)strLevelDB;
}

bool CWalletDB::WriteName(const std::string &strAddress, const std::string &strName) {
    dbparam::IncWalletUpdate();
    return Write(std::make_pair(std::string("name"), strAddress), strName);
}

bool CWalletDB::EraseName(const std::string &strAddress) {
    // This should only be used for sending addresses, never for receiving addresses,
    // receiving addresses must always have an address book entry if they're not change return.
    dbparam::IncWalletUpdate();
    return Erase(std::make_pair(std::string("name"), strAddress));
}

bool CWalletDB::ReadAccount(const std::string &strAccount, CAccount &account) {
    account.SetNull();
    return Read(std::make_pair(std::string("acc"), strAccount), account);
}

bool CWalletDB::WriteAccount(const std::string &strAccount, const CAccount &account) {
    return Write(std::make_pair(std::string("acc"), strAccount), account);
}

bool CWalletDB::WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry &acentry)
{
    return Write(std::make_tuple(std::string("acentry"), acentry.strAccount, nAccEntryNum), acentry);
}

bool CWalletDB::WriteAccountingEntry(const CAccountingEntry &acentry)
{
    return WriteAccountingEntry(++nAccountingEntryNumber, acentry);
}

int64_t CWalletDB::GetAccountCreditDebit(const std::string &strAccount)
{
    std::list<CAccountingEntry> entries;
    ListAccountCreditDebit(strAccount, entries);

    int64_t nCreditDebit = 0;
    for(const CAccountingEntry &entry: entries) {
        nCreditDebit += entry.nCreditDebit;
    }

    return nCreditDebit;
}

void CWalletDB::ListAccountCreditDebit(const std::string &strAccount, std::list<CAccountingEntry> &entries)
{
    bool fAllAccounts = (strAccount == "*");

#ifdef WALLET_SQL_MODE
    CDataStream lKey;
    if(fAllAccounts)
        lKey << std::string("acentry");
    else
        lKey << std::make_pair(std::string("acentry"), strAccount);
    IDB::DbIterator ite = GetIteCursor(std::string("%") + std::string(lKey.begin(), lKey.end()) + std::string("%"));
    if (ite.is_error())
        throw std::runtime_error("CWalletDB::ListAccountCreditDebit() : cannot create DB cursor");
#else
    IDB::DbIterator ite = GetIteCursor();
    if (ite.is_error())
        throw std::runtime_error("CWalletDB::ListAccountCreditDebit() : cannot create DB cursor");
#endif

    unsigned int fFlags = DB_SET_RANGE;
    for (;;) {
        // Read next record
        CDataStream ssKey(SER_DISK, version::CLIENT_VERSION);
#ifndef WALLET_SQL_MODE
        if (fFlags == DB_SET_RANGE)
            ssKey << std::make_tuple(std::string("acentry"), (fAllAccounts? std::string("") : strAccount), uint64_t(0));
#endif

        CDataStream ssValue(SER_DISK, version::CLIENT_VERSION);
        //int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        int ret = IDB::ReadAtCursor(ite, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND) {
            break;
        } else if (ret != 0) {
            throw std::runtime_error("CWalletDB::ListAccountCreditDebit() : error scanning DB");
        }

        std::string strType;
        ssKey >> strType;
#ifndef WALLET_SQL_MODE
        if (strType != "acentry")
            break;
#endif

        CAccountingEntry acentry;
        ssKey >> acentry.strAccount;
        if (!fAllAccounts && acentry.strAccount != strAccount)
            break;

        ssValue >> acentry;
        ssKey >> acentry.nEntryNo;
        entries.push_back(acentry);
    }
}

DBErrors CWalletDB::ReorderTransactions(CWallet *pwallet)
{
    LOCK(pwallet->cs_wallet);

    /////////////////////////////////////////////////////////////
    // Old wallets didn't have any defined order for transactions
    // Probably a bad idea to change the output of this
    /////////////////////////////////////////////////////////////

    //
    // First: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap
    //

    typedef std::pair<CWalletTx *, CAccountingEntry *> TxPair;
    typedef std::multimap<int64_t, TxPair > TxItems;
    TxItems txByTime;

    for (std::map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it)
    {
        CWalletTx *wtx = &((*it).second);
        txByTime.insert(make_pair(wtx->nTimeReceived, TxPair(wtx, (CAccountingEntry*)0)));
    }

    std::list<CAccountingEntry> acentries;
    ListAccountCreditDebit("", acentries);
    for(CAccountingEntry &entry: acentries)
    {
        txByTime.insert(std::make_pair(entry.nTime, TxPair((CWalletTx *)0, &entry)));
    }

    int64_t &nOrderPosNext = pwallet->nOrderPosNext;
    nOrderPosNext = 0;
    std::vector<int64_t> nOrderPosOffsets;
    for (TxItems::iterator it = txByTime.begin(); it != txByTime.end(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        CAccountingEntry *const pacentry = (*it).second.second;
        int64_t& nOrderPos = (pwtx != 0) ? pwtx->nOrderPos : pacentry->nOrderPos;
        if (nOrderPos == -1) {
            nOrderPos = nOrderPosNext++;
            nOrderPosOffsets.push_back(nOrderPos);
            if (pacentry) {
                //
                // Have to write accounting regardless, since we don't keep it in memory
                //
                if (! WriteAccountingEntry(pacentry->nEntryNo, *pacentry)) {
                    return DB_LOAD_FAIL;
                }
            }
        } else {
            int64_t nOrderPosOff = 0;
            for(const int64_t &nOffsetStart: nOrderPosOffsets)
            {
                if (nOrderPos >= nOffsetStart) {
                    ++nOrderPosOff;
                }
            }

            nOrderPos += nOrderPosOff;
            nOrderPosNext = std::max(nOrderPosNext, nOrderPos + 1);
            if (! nOrderPosOff) {
                continue;
            }

            //
            // Since we're changing the order, write it back
            //
            if (pwtx) {
                if (! WriteTx(pwtx->GetHash(), *pwtx)) {
                    return DB_LOAD_FAIL;
                }
            } else {
                if (! WriteAccountingEntry(pacentry->nEntryNo, *pacentry)) {
                    return DB_LOAD_FAIL;
                }
            }
        }
    }

    return DB_LOAD_OK;
}

class CWalletScanState
{
private:
    CWalletScanState(const CWalletScanState &); // {}
    CWalletScanState &operator=(const CWalletScanState &); // {}

public:
    unsigned int nKeys;
    unsigned int nCKeys;
    unsigned int nKeyMeta;
    bool fIsEncrypted;
    bool fAnyUnordered;
    int nFileVersion;
    std::vector<uint256> vWalletUpgrade;

    CWalletScanState() {
        nKeys = nCKeys = nKeyMeta = 0;
        fIsEncrypted = false;
        fAnyUnordered = false;
        nFileVersion = 0;
    }
};

bool CWalletDB::ReadKeyValue(CWallet *pwallet, CDataStream &ssKey, CDataStream &ssValue, CWalletScanState &wss, std::string &strType, std::string &strErr)
{
    try {
        //
        // Unserialize
        // Taking advantage of the fact that pair serialization
        // is just the two items serialized one after the other
        //
        ssKey >> strType;

        if (strType == "name") {
            std::string strAddress;
            ssKey >> strAddress;
            ssValue >> pwallet->mapAddressBook[CBitcoinAddress(strAddress)];
        } else if (strType == "tx") {
            uint256 hash;
            ssKey >> hash;
            CWalletTx &wtx = pwallet->mapWallet[hash];
            ssValue >> wtx;
            if (wtx.CheckTransaction() && (wtx.GetHash() == hash)) {
                wtx.BindWallet(pwallet);
            } else {
                pwallet->mapWallet.erase(hash);
                return false;
            }

            //
            // Undo serialize changes in 31600
            //
            if (31404 <= wtx.fTimeReceivedIsTxTime && wtx.fTimeReceivedIsTxTime <= 31703)
            {
                if (! ssValue.empty()) {
                    char fTmp;
                    char fUnused;
                    ssValue >> fTmp >> fUnused >> wtx.strFromAccount;
                    strErr = tfm::format("LoadWallet() upgrading tx ver=%d %d '%s' %s", wtx.fTimeReceivedIsTxTime, fTmp, wtx.strFromAccount.c_str(), hash.ToString().c_str());
                    wtx.fTimeReceivedIsTxTime = fTmp;
                } else {
                    strErr = tfm::format("LoadWallet() repairing tx ver=%d %s", wtx.fTimeReceivedIsTxTime, hash.ToString().c_str());
                    wtx.fTimeReceivedIsTxTime = 0;
                }
                wss.vWalletUpgrade.push_back(hash);
            }
            if (wtx.nOrderPos == -1) {
                wss.fAnyUnordered = true;
            }

            //// debug print
            //printf("LoadWallet  %s\n", wtx.GetHash().ToString().c_str());
            //printf(" %12"PRId64"  %s  %s  %s\n",
            //        wtx.vout[0].nValue,
            //        util::DateTimeStrFormat("%x %H:%M:%S", wtx.GetBlockTime()).c_str(),
            //        wtx.hashBlock.ToString().substr(0,20).c_str(),
            //        wtx.mapValue["message"].c_str());
        } else if (strType == "acentry") {
            std::string strAccount;
            ssKey >> strAccount;
            uint64_t nNumber;
            ssKey >> nNumber;
            if (nNumber > nAccountingEntryNumber) {
                nAccountingEntryNumber = nNumber;
            }
            if (! wss.fAnyUnordered) {
                CAccountingEntry acentry;
                ssValue >> acentry;
                if (acentry.nOrderPos == -1) {
                    wss.fAnyUnordered = true;
                }
            }
        } else if (strType == "watchs") {
            CScript script;
            ssKey >> script;
            char fYes;
            ssValue >> fYes;
            if (fYes == '1') {
                pwallet->LoadWatchOnly(script);
            }

            //
            // Watch-only addresses have no birthday information for now,
            // so set the wallet birthday to the beginning of time.
            //
            pwallet->nTimeFirstKey = 1;
        } else if (strType == "malpair") {
            std::string strKeyView;

            CSecret vchSecret;
            ssKey >> strKeyView;
            ssValue >> vchSecret;

            CMalleableKeyView keyView(strKeyView);
            if (! pwallet->LoadKey(keyView, vchSecret)) {
                strErr = "Error reading wallet database: LoadKey failed";
                return false;
            }
        } else if (strType == "malcpair") {
            std::string strKeyView;

            std::vector<unsigned char> vchCryptedSecret;
            ssKey >> strKeyView;
            ssValue >> vchCryptedSecret;

            CMalleableKeyView keyView(strKeyView);
            if (! pwallet->LoadCryptedKey(keyView, vchCryptedSecret)) {
                strErr = "Error reading wallet database: LoadCryptedKey failed";
                return false;
            }
        } else if (strType == "hdkeyseed") {
            CPubKey pubkey;
            ssKey >> pubkey;

            hd_wallet::get().pkeyseed = new (std::nothrow) CExtKey;
            if(! hd_wallet::get().pkeyseed) {
                strErr = "Error reading wallet database: memory allocate failure";
                return false;
            }

            unsigned int fcrypto;
            ssValue >> hd_wallet::get().vchextkey;
            ssValue >> hd_wallet::get()._child_offset;
            ssValue >> hd_wallet::get().cryptosalt;
            ssValue >> fcrypto;
            if(fcrypto == 0)
                hd_wallet::get().fcryptoseed = false;
            else
                hd_wallet::get().fcryptoseed = true;

            __printf("SeedKey _childnumof: %d, fcryptoseed: %d\n", hd_wallet::get()._child_offset, fcrypto);
            if(! hd_wallet::get().fcryptoseed) {
                if(hd_wallet::get().vchextkey.size() != CExtPubKey::BIP32_EXTKEY_SIZE) {
                    strErr = "Error reading wallet database: extkey decode size failure";
                    return false;
                }
                if(! hd_wallet::get().pkeyseed->Decode(hd_wallet::get().vchextkey.data())) {
                    strErr = "Error reading wallet database: setseed failure";
                    return false;
                }
                if(hd_wallet::get().pkeyseed->privkey_.GetPubKey() != pubkey) {
                    strErr = "Error reading wallet database: pubkey corrupt";
                    return false;
                }
            } else {
                if(! hd_wallet::get().InValidKeyseed())
                    return false;
            }

        } else if (strType == "hdpubkeys") {

            ssValue >> hd_wallet::get().reserved_pubkey;

        } else if (strType == "hdusedkey") {

            ssValue >> hd_wallet::get()._usedkey_offset;

        } else if (strType == "key" || strType == "wkey") {
            CKey key;
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (strType == "key") {
                wss.nKeys++;
                CPrivKey pkey;
                ssValue >> pkey;
                if (! key.SetPrivKey(pkey)) {
                    strErr = "Error reading wallet database: CPrivKey corrupt";
                    return false;
                }
                if (key.GetPubKey() != vchPubKey) {
                    strErr = "Error reading wallet database: CPrivKey pubkey inconsistency";
                    return false;
                }

                key.SetCompressedPubKey(vchPubKey.IsCompressed());
                if (! key.IsValid()) {
                    strErr = "Error reading wallet database: invalid CPrivKey";
                    return false;
                }
            } else {
                CWalletKey wkey;
                ssValue >> wkey;
                if (! key.SetPrivKey(wkey.vchPrivKey)) {
                    strErr = "Error reading wallet database: CPrivKey corrupt";
                    return false;
                }
                if (key.GetPubKey() != vchPubKey) {
                    strErr = "Error reading wallet database: CWalletKey pubkey inconsistency";
                    return false;
                }

                key.SetCompressedPubKey(vchPubKey.IsCompressed());
                if (! key.IsValid()) {
                    strErr = "Error reading wallet database: invalid CWalletKey";
                    return false;
                }
            }
            if (! pwallet->LoadKey(key)) {
                strErr = "Error reading wallet database: LoadKey failed";
                return false;
            }
        } else if (strType == "mkey") {
            unsigned int nID;
            ssKey >> nID;
            CMasterKey kMasterKey;
            ssValue >> kMasterKey;

            if(pwallet->mapMasterKeys.count(nID) != 0) {
                strErr = tfm::format("Error reading wallet database: duplicate CMasterKey id %u", nID);
                return false;
            }

            pwallet->mapMasterKeys[nID] = kMasterKey;
            if (pwallet->nMasterKeyMaxID < nID) {
                pwallet->nMasterKeyMaxID = nID;
            }
        } else if (strType == "ckey") {
            wss.nCKeys++;
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            std::vector<unsigned char> vchPrivKey;
            ssValue >> vchPrivKey;
            if (! pwallet->LoadCryptedKey(vchPubKey, vchPrivKey)) {
                strErr = "Error reading wallet database: LoadCryptedKey failed";
                return false;
            }
            wss.fIsEncrypted = true;
        } else if (strType == "malmeta") {
            std::string strKeyView;
            ssKey >> strKeyView;

            CMalleableKeyView keyView;
            keyView.SetString(strKeyView);

            CKeyMetadata keyMeta;
            ssValue >> keyMeta;
            wss.nKeyMeta++;

            pwallet->LoadKeyMetadata(keyView, keyMeta);
        } else if (strType == "keymeta") {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            CKeyMetadata keyMeta;
            ssValue >> keyMeta;
            wss.nKeyMeta++;

            pwallet->LoadKeyMetadata(vchPubKey, keyMeta);

            //
            // find earliest key creation time, as wallet birthday
            //
            if (!pwallet->nTimeFirstKey || (keyMeta.nCreateTime < pwallet->nTimeFirstKey)) {
                pwallet->nTimeFirstKey = keyMeta.nCreateTime;
            }
        } else if (strType == "defaultkey") {
            ssValue >> pwallet->vchDefaultKey;
        } else if (strType == "pool") {
            int64_t nIndex;
            ssKey >> nIndex;
            CKeyPool keypool;
            ssValue >> keypool;
            pwallet->setKeyPool.insert(nIndex);

            //
            // If no metadata exists yet, create a default with the pool key's
            // creation time. Note that this may be overwritten by actually
            // stored metadata for that key later, which is fine.
            //
            CBitcoinAddress addr = CBitcoinAddress(keypool.vchPubKey.GetID());
            if (pwallet->mapKeyMetadata.count(addr) == 0) {
                pwallet->mapKeyMetadata[addr] = CKeyMetadata(keypool.nTime);
            }
        } else if (strType == "version") {
            ssValue >> wss.nFileVersion;
            if (wss.nFileVersion == 10300) {
                wss.nFileVersion = 300;
            }
        } else if (strType == "cscript") {
            uint160 hash;
            ssKey >> hash;
            CScript script;
            ssValue >> script;
            if (! pwallet->LoadCScript(script)) {
                strErr = "Error reading wallet database: LoadCScript failed";
                return false;
            }
        } else if (strType == "cscriptethsora") {
            uint160 hash;
            ssKey >> hash;
            CScript script;
            ssValue >> script;
            CKeyID keyid;
            ssValue >> keyid;
            CEthID ethid;
            ssValue >> ethid;
            if (! pwallet->LoadCScript(script, keyid, ethid)) {
                strErr = "Error reading wallet database: LoadCScript failed";
                return false;
            }
        } else if (strType == "orderposnext") {
            ssValue >> pwallet->nOrderPosNext;
        }
    } catch (...) {
        return false;
    }
    return true;
}

bool CWalletDB::IsKeyType(std::string strType)
{
    return (strType == "key" || strType == "wkey" || strType == "mkey" || strType == "ckey" || strType == "malpair" || strType == "malcpair" || strType == "hdkey");
}

DBErrors CWalletDB::LoadWallet(CWallet *pwallet)
{
    pwallet->vchDefaultKey = CPubKey();

    CWalletScanState wss;
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    try {
        LOCK(pwallet->cs_wallet);
        int nMinVersion = 0;
        if (Read((std::string)"minversion", nMinVersion)) {
            if (nMinVersion > version::CLIENT_VERSION) {
                return DB_TOO_NEW;
            }
            pwallet->LoadMinVersion(nMinVersion);
        }

        //
        // check hd wallet
        //
        {
            IDB::DbIterator ite = GetIteCursor();
            if(ite.is_error()) {
                logging::LogPrintf("Error getting wallet database cursor\n");
                //debugcs::instance() << "LoadWallet Iterator Error" << debugcs::endl();
                return DB_CORRUPT;
            }
            for(;;) {
                CDataStream ssKey, ssValue;
                int ret = IDB::ReadAtCursor(ite, ssKey, ssValue);
                if(ret == DB_NOTFOUND)
                    break;
                else if(ret != 0) {
                    logging::LogPrintf("Error getting wallet database cursor\n");
                    //debugcs::instance() << "LoadWallet Iterator Error" << debugcs::endl();
                    return DB_CORRUPT;
                }
                std::string key;
                ssKey >> key;
                if(key == "hdkeyseed") {
                    hd_wallet::get().enable = true;
                    break;
                }
            }
        }

        //
        // Get cursor
        //
        IDB::DbIterator ite = GetIteCursor();
        if (ite.is_error()) {
            logging::LogPrintf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        for (;;)
        {
            //
            // Read next record (for DB)
            //
            CDataStream ssKey(SER_DISK, version::CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, version::CLIENT_VERSION);
            int ret = IDB::ReadAtCursor(ite, ssKey, ssValue);
            if (ret == DB_NOTFOUND) {
                break;
            } else if (ret != 0) {
                logging::LogPrintf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            //
            // Try to be tolerant of single corrupt records:
            //
            std::string strType, strErr;
            if (! ReadKeyValue(pwallet, ssKey, ssValue, wss, strType, strErr)) {
                //
                // losing keys is considered a catastrophic error, anything else
                // we assume the user can live with
                //
                if (IsKeyType(strType)) {
                    result = DB_CORRUPT;
                } else {
                    // Leave other errors alone, if we try to fix them we might make things worse.
                    fNoncriticalErrors = true; // ... but do warn the user there is something wrong.
                    
                    if (strType == "tx") {
                        // Rescan if there is a bad transaction record:
                        map_arg::SoftSetBoolArg("-rescan", true);
                    }
                }
            }
            if (! strErr.empty()) {
                logging::LogPrintf("%s\n", strErr.c_str());
            }
        }
    } catch (...) {
        result = DB_CORRUPT;
    }

    //
    // DB Load Success, but ReadKeyValue failed. so ERROR.
    //
    if (fNoncriticalErrors && result == DB_LOAD_OK) {
        result = DB_NONCRITICAL_ERROR;
    }

    //
    // Any wallet corruption at all: skip any rewriting or
    // upgrading, we don't want to make it worse.
    //
    if (result != DB_LOAD_OK) {
        return result;
    }

    logging::LogPrintf("nFileVersion = %d\n", wss.nFileVersion);
    logging::LogPrintf("Keys: %u plaintext, %u encrypted, %u w/ metadata, %u total\n", wss.nKeys, wss.nCKeys, wss.nKeyMeta, wss.nKeys + wss.nCKeys);

    // nTimeFirstKey is only reliable if all keys have metadata
    if ((wss.nKeys + wss.nCKeys) != wss.nKeyMeta) {
        pwallet->nTimeFirstKey = 1; // 0 would be considered 'no value'
    }

    for(uint256 hash: wss.vWalletUpgrade)
    {
        WriteTx(hash, pwallet->mapWallet[hash]);
    }

    //
    // Rewrite encrypted wallets of versions 0.4.0 and 0.5.0rc(SorachanCoin)
    //
    //if (wss.fIsEncrypted && (wss.nFileVersion == 40000 || wss.nFileVersion == 50000)) {
    //    return DB_NEED_REWRITE;
    //}
    if (wss.nFileVersion < version::CLIENT_VERSION) { // Update
        WriteVersion(version::CLIENT_VERSION);
    }
    if (wss.fAnyUnordered) {
        result = ReorderTransactions(pwallet);
    }

    return result;
}

DBErrors CWalletDB::FindWalletTx(CWallet *pwallet, std::vector<uint256> &vTxHash)
{
    pwallet->vchDefaultKey = CPubKey();

    CWalletScanState wss;
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    try {
        LOCK(pwallet->cs_wallet);
        int nMinVersion = 0;
        if (Read((std::string)"minversion", nMinVersion)) {
            if (nMinVersion > version::CLIENT_VERSION) {
                return DB_TOO_NEW;
            }
            pwallet->LoadMinVersion(nMinVersion);
        }

        //
        // Get cursor
        //
        IDB::DbIterator ite = GetIteCursor();
        if (ite.is_error()) {
            logging::LogPrintf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }
        //Dbc *pcursor = GetCursor();
        //if (! pcursor) {
        //    logging::LogPrintf("Error getting wallet database cursor\n");
        //    return DB_CORRUPT;
        //}

        for (;;)
        {
            //
            // Read next record
            //
            CDataStream ssKey(SER_DISK, version::CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, version::CLIENT_VERSION);
            //int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            int ret = IDB::ReadAtCursor(ite, ssKey, ssValue);
            if (ret == DB_NOTFOUND) {
                break;
            } else if (ret != 0) {
                logging::LogPrintf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            std::string strType;
            ssKey >> strType;
            if (strType == "tx") {
                uint256 hash;
                ssKey >> hash;

                vTxHash.push_back(hash);
            }
        }
        //pcursor->close();
    } catch (const boost::thread_interrupted&) {
        throw;
    } catch (...) {
        result = DB_CORRUPT;
    }

    if (fNoncriticalErrors && result == DB_LOAD_OK) {
        result = DB_NONCRITICAL_ERROR;
    }

    return result;
}

DBErrors CWalletDB::ZapWalletTx(CWallet *pwallet)
{
    //
    // build list of wallet TXs
    //
    std::vector<uint256> vTxHash;
    DBErrors err = FindWalletTx(pwallet, vTxHash);
    if (err != DB_LOAD_OK) {
        return err;
    }

    // erase each wallet TX
    for(uint256& hash: vTxHash)
    {
        if (! EraseTx(hash)) {
            return DB_CORRUPT;
        }
    }

    return DB_LOAD_OK;
}

void wallet_dispatch::ThreadFlushWalletDB(void *parg)
{
    //
    // Make this thread recognisable as the wallet flushing thread
    //
    bitthread::RenameThread(strCoinName "-wallet");

    {
#ifdef USE_BERKELEYDB
        LOCK(CDBEnv::get_instance().cs_db);
#else
        LOCK(CSqliteDBEnv::get_instance().cs_sqlite);
#endif
        static bool fOneThread = false;
        if (fOneThread) {
            return;
        }
        fOneThread = true;
    }

    if (! map_arg::GetBoolArg("-flushwallet", true)) {
        return;
    }

#ifdef WALLET_SQL_MODE
    (void)parg;
    while (! args_bool::fShutdown) {
        util::Sleep(3000);
        CSqliteDBEnv::get_instance().Flush(CSqliteDBEnv::getname_wallet());
    }
#else
    const std::string &strFile = ((const std::string *)parg)[0];
    unsigned int nLastSeen = dbparam::GetWalletUpdate();
    unsigned int nLastFlushed = dbparam::GetWalletUpdate();
    int64_t nLastWalletUpdate = bitsystem::GetTime();
    while (! args_bool::fShutdown)
    {
        util::Sleep(500);

        if (nLastSeen != dbparam::GetWalletUpdate()) {
            nLastSeen = dbparam::GetWalletUpdate();
            nLastWalletUpdate = bitsystem::GetTime();
        }

        if (nLastFlushed != dbparam::GetWalletUpdate() && bitsystem::GetTime() - nLastWalletUpdate >= 2) {
            TRY_LOCK(CDBEnv::get_instance().cs_db, lockDb);
            if (lockDb) {
                // Don't do this if any databases are in use
                const int nRefCount = CDBEnv::get_instance().GetRefCount();
                if (nRefCount == 0 && CDBEnv::get_instance().FindFile(strFile) && !args_bool::fShutdown) {
                    logging::LogPrintf("Flushing %s\n", strFile.c_str());
                    nLastFlushed = dbparam::GetWalletUpdate();
                    int64_t nStart = util::GetTimeMillis();
                    // Flush wallet.dat so it's self contained
                    if(CDBEnv::get_instance().Flush(strFile))
                        logging::LogPrintf("Flushed %s %" PRId64 "ms\n", strFile.c_str(), util::GetTimeMillis() - nStart);
                }
            }
        }
    }
#endif
}

bool wallet_dispatch::BackupWallet(const CWallet &wallet, const std::string &strDest)
{
    if (! wallet.fFileBacked)
        return false;

#ifdef WALLET_SQL_MODE
    return CSqliteDBEnv::get_instance().backup(iofs::GetDataDir(), wallet.strWalletSqlFile, strDest); // strDest accepts file or directory.
#else
    while (! args_bool::fShutdown)
    {
        {
            LOCK(CDBEnv::get_instance().cs_db);
            //if (!CDBEnv::get_instance().mapFileUseCount.count(wallet.strWalletFile) || CDBEnv::get_instance().mapFileUseCount[wallet.strWalletFile] == 0) {
            if (!CDBEnv::get_instance().ExistsFileCount(wallet.strWalletFile) || CDBEnv::get_instance().GetFileCount(wallet.strWalletFile)==0) {
                //
                // Flush log data to the dat file
                //
                //CDBEnv::get_instance().CloseDb(wallet.strWalletFile);
                //CDBEnv::get_instance().CheckpointLSN(wallet.strWalletFile);
                //CDBEnv::get_instance().mapFileUseCount.erase(wallet.strWalletFile);
                CDBEnv::get_instance().Flush(wallet.strWalletFile);

                //
                // Copy wallet.dat
                //
                fs::path pathSrc = iofs::GetDataDir() / wallet.strWalletFile;
                fs::path pathDest(strDest);
                if (fs::is_directory(pathDest)) {
                    pathDest /= wallet.strWalletFile;
                }

                try {
                    fs::copy_file(pathSrc, pathDest, fs::copy_option::overwrite_if_exists);
                    logging::LogPrintf("copied wallet data to %s\n", pathDest.string().c_str());
                    return true;
                } catch(const fs::filesystem_error &e) {
                    logging::LogPrintf("error copying wallet data to %s - %s\n", pathDest.string().c_str(), e.what());
                    return false;
                }
            }
        }
        util::Sleep(100);
    }
    return false;
#endif
}

bool wallet_dispatch::DumpWallet(CWallet *pwallet, const std::string &strDest)
{
    if (! pwallet->fFileBacked) {
        return false;
    }

    std::map<CBitcoinAddress, int64_t> mapAddresses;
    std::set<CKeyID> setKeyPool;

    pwallet->GetAddresses(mapAddresses);
    pwallet->GetAllReserveKeys(setKeyPool);

    //
    // sort time/key pairs
    //
    std::vector<std::pair<int64_t, CBitcoinAddress> > vAddresses;
    for (std::map<CBitcoinAddress, int64_t>::const_iterator it = mapAddresses.begin(); it != mapAddresses.end(); it++)
    {
        vAddresses.push_back(std::make_pair(it->second, it->first));
    }
    mapAddresses.clear();
    std::sort(vAddresses.begin(), vAddresses.end());

    //
    // open outputfile as a stream
    //
    std::ofstream file;
    file.open(strDest.c_str());
    if (! file.is_open()) {
       return false;
    }

    //
    // produce output
    //
    file << tfm::format("# Wallet dump created by %s %s (%s)\n", strCoinName, version::CLIENT_BUILD.c_str(), version::CLIENT_DATE.c_str());
    file << tfm::format("# * Created on %s\n", dump::EncodeDumpTime(bitsystem::GetTime()).c_str());
    file << tfm::format("# * Best block at time of backup was %i (%s),\n", block_info::nBestHeight, block_info::hashBestChain.ToString().c_str());
    file << tfm::format("#   mined on %s\n", dump::EncodeDumpTime(block_info::pindexBest->get_nTime()).c_str());
    file << "\n";

    for (std::vector<std::pair<int64_t, CBitcoinAddress> >::const_iterator it = vAddresses.begin(); it != vAddresses.end(); it++)
    {
        const CBitcoinAddress &addr = it->second;
        std::string strTime = dump::EncodeDumpTime(it->first);
        std::string strAddr = addr.ToString();

        if (addr.IsPair()) {
            // Pubkey pair address
            CMalleableKeyView keyView;
            CMalleablePubKey mPubKey(addr.GetData());
            if (! pwallet->GetMalleableView(mPubKey, keyView)) {
                continue;
            }

            CMalleableKey mKey;
            pwallet->GetMalleableKey(keyView, mKey);
            file << mKey.ToString();
            if (pwallet->mapAddressBook.count(addr)) {
                file << tfm::format(" %s label=%s # view=%s addr=%s\n", strTime.c_str(), dump::EncodeDumpString(pwallet->mapAddressBook[addr]).c_str(), keyView.ToString().c_str(), strAddr.c_str());
            } else {
                file << tfm::format(" %s # view=%s addr=%s\n", strTime.c_str(), keyView.ToString().c_str(), strAddr.c_str());
            }
        } else {
            // Pubkey hash address
            CKeyID keyid;
            addr.GetKeyID(keyid);
            bool IsCompressed;
            CKey key;
            if (! pwallet->GetKey(keyid, key)) {
                continue;
            }

            CSecret secret = key.GetSecret(IsCompressed);
            file << CBitcoinSecret(secret, IsCompressed).ToString();
            if (pwallet->mapAddressBook.count(addr)) {
                file << tfm::format(" %s label=%s # addr=%s\n", strTime.c_str(), dump::EncodeDumpString(pwallet->mapAddressBook[addr]).c_str(), strAddr.c_str());
            } else if (setKeyPool.count(keyid)) {
                file << tfm::format(" %s reserve=1 # addr=%s\n", strTime.c_str(), strAddr.c_str());
            } else {
                file << tfm::format(" %s change=1 # addr=%s\n", strTime.c_str(), strAddr.c_str());
            }
        }
    }

    file << "\n";
    file << "# End of dump\n";
    file.close();

    return true;
}

bool wallet_dispatch::ImportWallet(CWallet *pwallet, const std::string &strLocation)
{
    if (! pwallet->fFileBacked) {
        return false;
    }

    // open inputfile as stream
    std::ifstream file;
    file.open(strLocation.c_str());
    if (! file.is_open()) {
        return false;
    }

    bool fGood = true;
    int64_t nTimeBegin = block_info::pindexBest->get_nTime();

    //
    // read through input file checking and importing keys into wallet.
    //
    while (file.good())
    {
        std::string line;
        std::getline(file, line);
        if (line.empty() || line[0] == '#') {
            continue; // Skip comments and empty lines
        }

        std::vector<std::string> vstr;
        std::istringstream iss(line);
        std::copy(std::istream_iterator<std::string>(iss), std::istream_iterator<std::string>(), std::back_inserter(vstr));
        if (vstr.size() < 2) {
            continue;
        }

        int64_t nTime = dump::DecodeDumpTime(vstr[1]);
        std::string strLabel;
        bool fLabel = true;
        for (unsigned int nStr = 2; nStr < vstr.size(); ++nStr)
        {
            if (boost::algorithm::starts_with(vstr[nStr], "#")) {
                break;
            }
            if (vstr[nStr] == "change=1") {
                fLabel = false;
            }
            if (vstr[nStr] == "reserve=1") {
                fLabel = false;
            }
            if (boost::algorithm::starts_with(vstr[nStr], "label=")) {
                strLabel = dump::DecodeDumpString(vstr[nStr].substr(6));
                fLabel = true;
            }
        }

        CBitcoinAddress addr;
        CBitcoinSecret vchSecret;
        if (vchSecret.SetString(vstr[0])) {
            //
            // Simple private key
            //
            bool fCompressed;
            CKey key;
            CSecret secret = vchSecret.GetSecret(fCompressed);
            key.SetSecret(secret, fCompressed);
            CKeyID keyid = key.GetPubKey().GetID();
            addr = CBitcoinAddress(keyid);

            if (pwallet->HaveKey(keyid)) {
                logging::LogPrintf("Skipping import of %s (key already present)\n", addr.ToString().c_str());
                continue;
            }

            logging::LogPrintf("Importing %s...\n", addr.ToString().c_str());
            if (! pwallet->AddKey(key)) {
                fGood = false;
                continue;
            }
        } else {
            //
            // A pair of private keys
            //
            CMalleableKey mKey;
            if (! mKey.SetString(vstr[0])) {
                continue;
            }

            CMalleablePubKey mPubKey = mKey.GetMalleablePubKey();
            addr = CBitcoinAddress(mPubKey);
            if (pwallet->CheckOwnership(mPubKey)) {
                logging::LogPrintf("Skipping import of %s (key already present)\n", addr.ToString().c_str());
                continue;
            }

            logging::LogPrintf("Importing %s...\n", addr.ToString().c_str());
            if (! pwallet->AddKey(mKey)) {
                fGood = false;
                continue;
            }
        }

        pwallet->mapKeyMetadata[addr].nCreateTime = nTime;
        if (fLabel) {
            pwallet->SetAddressBookName(addr, strLabel);
        }

        nTimeBegin = std::min(nTimeBegin, nTime);
    }
    file.close();

    // rescan block chain looking for coins from new keys
    CBlockIndex *pindex = block_info::pindexBest;
    while (pindex && pindex->get_pprev() && pindex->get_nTime() > nTimeBegin - 7200)
    {
        pindex = pindex->set_pprev();
    }

    logging::LogPrintf("Rescanning last %i blocks\n", block_info::pindexBest->get_nHeight() - pindex->get_nHeight() + 1);
    pwallet->ScanForWalletTransactions(pindex);
    pwallet->ReacceptWalletTransactions();
    pwallet->MarkDirty();

    return fGood;
}

//
// Try to (very carefully!) recover wallet.dat if there is a problem.
//
#ifdef USE_BERKELEYDB
bool CWalletDB::Recover(std::string filename, bool fOnlyKeys/*=false*/)
{
    //
    // Recovery procedure:
    // move wallet.dat to wallet.timestamp.bak
    // Call Salvage with fAggressive=true to get as much data as possible.
    // Rewrite salvaged data to wallet.dat
    // Set -rescan so any missing transactions will be found.
    //

    CDBEnv &dbenv = CDBEnv::get_instance();

    //
    // create backup file (.bak)
    //
    int64_t now = bitsystem::GetTime();
    std::string newFilename = tfm::format("wallet.%" PRId64 ".bak", now);

    if (dbenv.DbRename(filename, newFilename)) {
        logging::LogPrintf("Renamed %s to %s\n", filename.c_str(), newFilename.c_str());
    } else {
        logging::LogPrintf("Failed to rename %s to %s\n", filename.c_str(), newFilename.c_str());
        return false;
    }

    std::vector<CDBEnv::KeyValPair> salvagedData;
    bool allOK = dbenv.Salvage(newFilename, true, salvagedData);
    if (salvagedData.empty()) {
        logging::LogPrintf("Salvage(aggressive) found no records in %s.\n", newFilename.c_str());
        return false;
    }
    logging::LogPrintf("Salvage(aggressive) found %" PRIszu " records\n", salvagedData.size());

    bool fSuccess = allOK;
    std::unique_ptr<Db> pdbCopy = dbenv.TempCreate(nullptr, filename, DB_CREATE);
    if(pdbCopy.get()==nullptr) {
        logging::LogPrintf("Cannot create database file %s\n", filename.c_str());
        return false;
    }

    CWallet dummyWallet;
    CWalletScanState wss;

    //
    // Data Salvage
    //
    DbTxn *ptxn = dbenv.TxnBegin();
    for(CDBEnv::KeyValPair &row: salvagedData) {
        if (fOnlyKeys) {
            CDataStream ssKey(row.first, SER_DISK, version::CLIENT_VERSION);
            CDataStream ssValue(row.second, SER_DISK, version::CLIENT_VERSION);

            std::string strType, strErr;
            bool fReadOK = ReadKeyValue(&dummyWallet, ssKey, ssValue, wss, strType, strErr);
            if (! IsKeyType(strType)) {
                continue;
            }
            if (! fReadOK) {
                logging::LogPrintf("WARNING: CWalletDB::Recover skipping %s: %s\n", strType.c_str(), strErr.c_str());
                continue;
            }
        }

        Dbt datKey(&row.first[0], row.first.size());
        Dbt datValue(&row.second[0], row.second.size());
        int ret2 = pdbCopy->put(ptxn, &datKey, &datValue, DB_NOOVERWRITE);
        if (ret2 > 0) {
            fSuccess = false;
        }
    }

    ptxn->commit(0);
    pdbCopy->close(0);

    return fSuccess;
}
#endif
