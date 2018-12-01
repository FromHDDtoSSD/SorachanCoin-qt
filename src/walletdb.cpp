// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletdb.h"
#include "wallet.h"
#include "base58.h"

#include <iostream>
#include <fstream>

#include <boost/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/variant/get.hpp>
#include <boost/algorithm/string.hpp>

uint64_t CWalletDB::nAccountingEntryNumber = 0;

//
// CWalletDB (wallet.dat)
//
bool CWalletDB::WriteName(const std::string &strAddress, const std::string &strName)
{
    dbparam::nWalletDBUpdated++;
    return Write(std::make_pair(std::string("name"), strAddress), strName);
}

bool CWalletDB::EraseName(const std::string &strAddress)
{
    //
    // This should only be used for sending addresses, never for receiving addresses,
    // receiving addresses must always have an address book entry if they're not change return.
    //
    dbparam::nWalletDBUpdated++;
    return Erase(std::make_pair(std::string("name"), strAddress));
}

bool CWalletDB::ReadAccount(const std::string &strAccount, CAccount &account)
{
    account.SetNull();
    return Read(std::make_pair(std::string("acc"), strAccount), account);
}

bool CWalletDB::WriteAccount(const std::string &strAccount, const CAccount &account)
{
    return Write(std::make_pair(std::string("acc"), strAccount), account);
}

bool CWalletDB::WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry &acentry)
{
    return Write(boost::make_tuple(std::string("acentry"), acentry.strAccount, nAccEntryNum), acentry);
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
    BOOST_FOREACH (const CAccountingEntry &entry, entries)
    {
        nCreditDebit += entry.nCreditDebit;
    }

    return nCreditDebit;
}

void CWalletDB::ListAccountCreditDebit(const std::string &strAccount, std::list<CAccountingEntry> &entries)
{
    bool fAllAccounts = (strAccount == "*");

    Dbc* pcursor = GetCursor();
    if (! pcursor) {
        throw std::runtime_error("CWalletDB::ListAccountCreditDebit() : cannot create DB cursor");
    }

    unsigned int fFlags = DB_SET_RANGE;
    for ( ; ; )
    {
        //
        // Read next record
        //
        CDataStream ssKey(SER_DISK, version::CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE) {
            ssKey << boost::make_tuple(std::string("acentry"), (fAllAccounts? std::string("") : strAccount), uint64_t(0));
        }

        CDataStream ssValue(SER_DISK, version::CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND) {
            break;
        } else if (ret != 0) {
            pcursor->close();
            throw std::runtime_error("CWalletDB::ListAccountCreditDebit() : error scanning DB");
        }

        //
        // Unserialize
        //
        std::string strType;
        ssKey >> strType;
        if (strType != "acentry") {
            break;
        }

        CAccountingEntry acentry;
        ssKey >> acentry.strAccount;
        if (!fAllAccounts && acentry.strAccount != strAccount) {
            break;
        }

        ssValue >> acentry;
        ssKey >> acentry.nEntryNo;
        entries.push_back(acentry);
    }

    pcursor->close();
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
    BOOST_FOREACH(CAccountingEntry &entry, acentries)
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
            BOOST_FOREACH(const int64_t &nOffsetStart, nOrderPosOffsets)
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
                    strErr = strprintf("LoadWallet() upgrading tx ver=%d %d '%s' %s", wtx.fTimeReceivedIsTxTime, fTmp, wtx.strFromAccount.c_str(), hash.ToString().c_str());
                    wtx.fTimeReceivedIsTxTime = fTmp;
                } else {
                    strErr = strprintf("LoadWallet() repairing tx ver=%d %s", wtx.fTimeReceivedIsTxTime, hash.ToString().c_str());
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
                strErr = strprintf("Error reading wallet database: duplicate CMasterKey id %u", nID);
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
    return (strType== "key" || strType == "wkey" || strType == "mkey" || strType == "ckey" || strType == "malpair" || strType == "malcpair");
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
        // Get cursor
        //
        Dbc *pcursor = GetCursor();
        if (! pcursor) {
            printf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        for ( ; ; )
        {
            //
            // Read next record (for DB)
            //
            CDataStream ssKey(SER_DISK, version::CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, version::CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND) {
                break;
            } else if (ret != 0) {
                printf("Error reading next record from wallet database\n");
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
                printf("%s\n", strErr.c_str());
            }
        }
        pcursor->close();
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

    printf("nFileVersion = %d\n", wss.nFileVersion);
    printf("Keys: %u plaintext, %u encrypted, %u w/ metadata, %u total\n", wss.nKeys, wss.nCKeys, wss.nKeyMeta, wss.nKeys + wss.nCKeys);

    // nTimeFirstKey is only reliable if all keys have metadata
    if ((wss.nKeys + wss.nCKeys) != wss.nKeyMeta) {
        pwallet->nTimeFirstKey = 1; // 0 would be considered 'no value'
    }

    BOOST_FOREACH(uint256 hash, wss.vWalletUpgrade)
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
        Dbc *pcursor = GetCursor();
        if (! pcursor) {
            printf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        for ( ; ; )
        {
            //
            // Read next record
            //
            CDataStream ssKey(SER_DISK, version::CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, version::CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND) {
                break;
            } else if (ret != 0) {
                printf("Error reading next record from wallet database\n");
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
        pcursor->close();
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
    BOOST_FOREACH (uint256& hash, vTxHash)
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
    bitthread::manage::RenameThread((coin_param::strCoinName + "-wallet").c_str());

    const std::string &strFile = ((const std::string *)parg)[0];

    static bool fOneThread = false;
    if (fOneThread) {
        return;
    }
    fOneThread = true;

    if (! map_arg::GetBoolArg("-flushwallet", true)) {
        return;
    }

    unsigned int nLastSeen = dbparam::nWalletDBUpdated;
    unsigned int nLastFlushed = dbparam::nWalletDBUpdated;
    int64_t nLastWalletUpdate = bitsystem::GetTime();
    while (! args_bool::fShutdown)
    {
        util::Sleep(500);

        if (nLastSeen != dbparam::nWalletDBUpdated) {
            nLastSeen = dbparam::nWalletDBUpdated;
            nLastWalletUpdate = bitsystem::GetTime();
        }

        if (nLastFlushed != dbparam::nWalletDBUpdated && bitsystem::GetTime() - nLastWalletUpdate >= 2) {
            TRY_LOCK(CDBEnv::bitdb.cs_db,lockDb);
            if (lockDb) {
                //
                // Don't do this if any databases are in use
                //
                int nRefCount = 0;
                std::map<std::string, int>::iterator mi = CDBEnv::bitdb.mapFileUseCount.begin();
                while (mi != CDBEnv::bitdb.mapFileUseCount.end())
                {
                    nRefCount += (*mi).second;
                    mi++;
                }

                if (nRefCount == 0 && !args_bool::fShutdown) {
                    std::map<std::string, int>::iterator mi = CDBEnv::bitdb.mapFileUseCount.find(strFile);
                    if (mi != CDBEnv::bitdb.mapFileUseCount.end()) {
                        printf("Flushing wallet.dat\n");
                        nLastFlushed = dbparam::nWalletDBUpdated;
                        int64_t nStart = util::GetTimeMillis();

                        //
                        // Flush wallet.dat so it's self contained
                        //
                        CDBEnv::bitdb.CloseDb(strFile);
                        CDBEnv::bitdb.CheckpointLSN(strFile);

                        CDBEnv::bitdb.mapFileUseCount.erase(mi++);
                        printf("Flushed wallet.dat %" PRId64 "ms\n", util::GetTimeMillis() - nStart);
                    }
                }
            }
        }
    }
}

bool wallet_dispatch::BackupWallet(const CWallet &wallet, const std::string &strDest)
{
    if (! wallet.fFileBacked) {
        return false;
    }

    while (! args_bool::fShutdown)
    {
        {
            LOCK(CDBEnv::bitdb.cs_db);
            if (!CDBEnv::bitdb.mapFileUseCount.count(wallet.strWalletFile) || CDBEnv::bitdb.mapFileUseCount[wallet.strWalletFile] == 0) {
                //
                // Flush log data to the dat file
                //
                CDBEnv::bitdb.CloseDb(wallet.strWalletFile);
                CDBEnv::bitdb.CheckpointLSN(wallet.strWalletFile);
                CDBEnv::bitdb.mapFileUseCount.erase(wallet.strWalletFile);

                //
                // Copy wallet.dat
                //
                boost::filesystem::path pathSrc = iofs::GetDataDir() / wallet.strWalletFile;
                boost::filesystem::path pathDest(strDest);
                if (boost::filesystem::is_directory(pathDest)) {
                    pathDest /= wallet.strWalletFile;
                }

                try {
#if BOOST_VERSION >= 104000
                    boost::filesystem::copy_file(pathSrc, pathDest, boost::filesystem::copy_option::overwrite_if_exists);
#else
                    boost::filesystem::copy_file(pathSrc, pathDest);
#endif
                    printf("copied wallet.dat to %s\n", pathDest.string().c_str());
                    return true;
                } catch(const boost::filesystem::filesystem_error &e) {
                    printf("error copying wallet.dat to %s - %s\n", pathDest.string().c_str(), e.what());
                    return false;
                }
            }
        }
        util::Sleep(100);
    }
    return false;
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
    file << strprintf("# Wallet dump created by %s %s (%s)\n", coin_param::strCoinName.c_str(), version::CLIENT_BUILD.c_str(), version::CLIENT_DATE.c_str());
    file << strprintf("# * Created on %s\n", dump::EncodeDumpTime(bitsystem::GetTime()).c_str());
    file << strprintf("# * Best block at time of backup was %i (%s),\n", block_info::nBestHeight, block_info::hashBestChain.ToString().c_str());
    file << strprintf("#   mined on %s\n", dump::EncodeDumpTime(block_info::pindexBest->nTime).c_str());
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
                file << strprintf(" %s label=%s # view=%s addr=%s\n", strTime.c_str(), dump::EncodeDumpString(pwallet->mapAddressBook[addr]).c_str(), keyView.ToString().c_str(), strAddr.c_str());
            } else {
                file << strprintf(" %s # view=%s addr=%s\n", strTime.c_str(), keyView.ToString().c_str(), strAddr.c_str());
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
                file << strprintf(" %s label=%s # addr=%s\n", strTime.c_str(), dump::EncodeDumpString(pwallet->mapAddressBook[addr]).c_str(), strAddr.c_str());
            } else if (setKeyPool.count(keyid)) {
                file << strprintf(" %s reserve=1 # addr=%s\n", strTime.c_str(), strAddr.c_str());
            } else {
                file << strprintf(" %s change=1 # addr=%s\n", strTime.c_str(), strAddr.c_str());
            }
        }
    }

    file << "\n";
    file << "# End of dump\n";
    file.close();

    return true;
}

bool wallet_dispatch::ImportWallet(CWallet *pwallet, const std::string& strLocation)
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
    int64_t nTimeBegin = block_info::pindexBest->nTime;

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
                printf("Skipping import of %s (key already present)\n", addr.ToString().c_str());
                continue;
            }

            printf("Importing %s...\n", addr.ToString().c_str());
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
                printf("Skipping import of %s (key already present)\n", addr.ToString().c_str());
                continue;
            }

            printf("Importing %s...\n", addr.ToString().c_str());
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
    while (pindex && pindex->pprev && pindex->nTime > nTimeBegin - 7200)
    {
        pindex = pindex->pprev;
    }

    printf("Rescanning last %i blocks\n", block_info::pindexBest->nHeight - pindex->nHeight + 1);
    pwallet->ScanForWalletTransactions(pindex);
    pwallet->ReacceptWalletTransactions();
    pwallet->MarkDirty();

    return fGood;
}

//
// Try to (very carefully!) recover wallet.dat if there is a problem.
//
bool CWalletDB::Recover(CDBEnv &dbenv, std::string filename, bool fOnlyKeys)
{
    //
    // Recovery procedure:
    // move wallet.dat to wallet.timestamp.bak
    // Call Salvage with fAggressive=true to get as much data as possible.
    // Rewrite salvaged data to wallet.dat
    // Set -rescan so any missing transactions will be found.
    //

    //
    // create backup file (.bak)
    //
    int64_t now = bitsystem::GetTime();
    std::string newFilename = strprintf("wallet.%" PRId64 ".bak", now);

    int result = dbenv.dbenv.dbrename(NULL, filename.c_str(), NULL, newFilename.c_str(), DB_AUTO_COMMIT);
    if (result == 0) {
        printf("Renamed %s to %s\n", filename.c_str(), newFilename.c_str());
    } else {
        printf("Failed to rename %s to %s\n", filename.c_str(), newFilename.c_str());
        return false;
    }

    std::vector<CDBEnv::KeyValPair> salvagedData;
    bool allOK = dbenv.Salvage(newFilename, true, salvagedData);
    if (salvagedData.empty()) {
        printf("Salvage(aggressive) found no records in %s.\n", newFilename.c_str());
        return false;
    }
    printf("Salvage(aggressive) found %" PRIszu " records\n", salvagedData.size());

    bool fSuccess = allOK;
    Db* pdbCopy = new Db(&dbenv.dbenv, 0);
    int ret = pdbCopy->open(NULL,                    // Txn pointer
                            filename.c_str(),        // Filename
                            "main",                  // Logical db name
                            DB_BTREE,                // Database type
                            DB_CREATE,               // Flags
                            0);
    if (ret > 0) {
        printf("Cannot create database file %s\n", filename.c_str());
        return false;
    }

    CWallet dummyWallet;
    CWalletScanState wss;

    //
    // Data Salvage
    //
    DbTxn *ptxn = dbenv.TxnBegin();
    BOOST_FOREACH(CDBEnv::KeyValPair &row, salvagedData)
    {
        if (fOnlyKeys) {
            CDataStream ssKey(row.first, SER_DISK, version::CLIENT_VERSION);
            CDataStream ssValue(row.second, SER_DISK, version::CLIENT_VERSION);

            std::string strType, strErr;
            bool fReadOK = ReadKeyValue(&dummyWallet, ssKey, ssValue, wss, strType, strErr);
            if (! IsKeyType(strType)) {
                continue;
            }
            if (! fReadOK) {
                printf("WARNING: CWalletDB::Recover skipping %s: %s\n", strType.c_str(), strErr.c_str());
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
    delete pdbCopy;

    return fSuccess;
}

bool CWalletDB::Recover(CDBEnv &dbenv, std::string filename)
{
    return CWalletDB::Recover(dbenv, filename, false);
}
