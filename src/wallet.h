// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef BITCOIN_WALLET_H
#define BITCOIN_WALLET_H

#include <string>
#include <vector>

#include <stdlib.h>

#include "main.h"
#include "key.h"
#include "keystore.h"
#include "script.h"
#include "ui_interface.h"
#include "util.h"
#include "walletdb.h"
#include "base58.h"

class CAccountingEntry;
class CWalletTx;
class CReserveKey;
class COutput;
class CCoinControl;

// Set of selected transactions
typedef std::set<std::pair<const CWalletTx*,unsigned int> > CoinsSet;

//
// (client) version numbers for particular wallet features
//
enum WalletFeature
{
    FEATURE_BASE = 10500,                // the earliest version new wallets supports (only useful for getinfo's clientversion output)

    FEATURE_WALLETCRYPT = 40000,         // wallet encryption
    FEATURE_COMPRPUBKEY = 60000,         // compressed public keys
    FEATURE_MALLKEY = 60017,
    FEATURE_LATEST = 60017
};

//
// A key pool entry
//
class CKeyPool
{
private:
    CKeyPool(const CKeyPool &); // {}
    CKeyPool &operator=(const CKeyPool &); // {}

public:
    int64_t nTime;
    CPubKey vchPubKey;

    CKeyPool() {
        nTime = bitsystem::GetTime();
    }

    CKeyPool(const CPubKey &vchPubKeyIn) {
        nTime = bitsystem::GetTime();
        vchPubKey = vchPubKeyIn;
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH)) {
            READWRITE(nVersion);
        }
        READWRITE(this->nTime);
        READWRITE(this->vchPubKey);
    )
};

//
// A CWallet is an extension of a keystore, which also maintains a set of transactions and balances,
// and provides the ability to create new transactions.
//
class CWallet : public CCryptoKeyStore
{
private:
    CWallet(const CWallet &); // {}
    CWallet &operator=(const CWallet &); // {}

    bool SelectCoins(int64_t nTargetValue, unsigned int nSpendTime, std::set<std::pair<const CWalletTx *, unsigned int> > &setCoinsRet, int64_t &nValueRet, const CCoinControl *coinControl = NULL) const;

    CWalletDB *pwalletdbEncryption, *pwalletdbDecryption;

    //
    // Wallet State
    //
    // the current wallet version.
    // clients below this version are not able to load the wallet
    //
    int nWalletVersion;

    // the maximum wallet format version: memory-only variable that specifies to what version this wallet may be upgraded
    int nWalletMaxVersion;

    int64_t nNextResend;
    int64_t nLastResend;

    // stake mining statistics
    uint64_t nKernelsTried;
    uint64_t nCoinDaysTried;

public:

    //
    // ppcoin: optional setting to unlock wallet for block minting only;
    //         serves to disable the trivial sendmoney when OS account compromised
    //
    static bool fWalletUnlockMintOnly;

    mutable CCriticalSection cs_wallet;

    bool fFileBacked;
    std::string strWalletFile;

    std::set<int64_t> setKeyPool;
    
    /*
    std::map<CKeyID, CKeyMetadata> mapKeyMetadata;
    std::map<CMalleableKeyView, CKeyMetadata> mapMalleableKeyMetadata;
    */

    std::map<CBitcoinAddress, CKeyMetadata> mapKeyMetadata;

    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;

    CWallet() {
        SetNull();
    }

    CWallet(std::string strWalletFileIn) {
        SetNull();
        strWalletFile = strWalletFileIn;
        fFileBacked = true;
    }

    void SetNull() {
        nWalletVersion = FEATURE_BASE;
        nWalletMaxVersion = FEATURE_BASE;
        fFileBacked = false;
        nMasterKeyMaxID = 0;
        pwalletdbEncryption = NULL;
        pwalletdbDecryption = NULL;
        nNextResend = 0;
        nLastResend = 0;
        nOrderPosNext = 0;
        nKernelsTried = 0;
        nCoinDaysTried = 0;
        nTimeFirstKey = 0;
    }

    //
    // Balance
    //
    std::map<uint256, CWalletTx> mapWallet;

    std::vector<uint256> vMintingWalletUpdated;
    int64_t nOrderPosNext;
    std::map<uint256, int> mapRequestCount;
    std::map<CBitcoinAddress, std::string> mapAddressBook;

    CPubKey vchDefaultKey;
    int64_t nTimeFirstKey;
    const CWalletTx *GetWalletTx(const uint256 &hash) const;

    // check whether we are allowed to upgrade (or already support) to the named feature
    bool CanSupportFeature(enum WalletFeature wf) { return nWalletMaxVersion >= wf; }

    void AvailableCoinsMinConf(std::vector<COutput> &vCoins, int nConf, int64_t nMinValue, int64_t nMaxValue) const;
    void AvailableCoins(std::vector<COutput> &vCoins, bool fOnlyConfirmed=true, const CCoinControl *coinControl=NULL) const;
    bool SelectCoinsMinConf(int64_t nTargetValue, unsigned int nSpendTime, int nConfMine, int nConfTheirs, std::vector<COutput> vCoins, std::set<std::pair<const CWalletTx *,unsigned int> > &setCoinsRet, int64_t &nValueRet) const;

    // Simple select (without randomization)
    bool SelectCoinsSimple(int64_t nTargetValue, int64_t nMinValue, int64_t nMaxValue, unsigned int nSpendTime, int nMinConf, std::set<std::pair<const CWalletTx *,unsigned int> > &setCoinsRet, int64_t &nValueRet) const;

    //
    // keystore implementation
    // Generate a new key
    //
    CPubKey GenerateNewKey();
    CMalleableKeyView GenerateNewMalleableKey();

    // Adds a key to the store, and saves it to disk.
    bool AddKey(const CKey &key);
    bool AddKey(const CMalleableKey &mKey);

    // Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey &key) {
        return CCryptoKeyStore::AddKey(key);
    }

    // Load metadata (used by LoadWallet)
    bool LoadKeyMetadata(const CPubKey &pubkey, const CKeyMetadata &metadata);
    bool LoadKeyMetadata(const CMalleableKeyView &keyView, const CKeyMetadata &metadata);

    // Load malleable key without saving it to disk (used by LoadWallet)
    bool LoadKey(const CMalleableKeyView &keyView, const CSecret &vchSecretH) {
        return CCryptoKeyStore::AddMalleableKey(keyView, vchSecretH);
    }
    bool LoadCryptedKey(const CMalleableKeyView &keyView, const std::vector<unsigned char> &vchCryptedSecretH) {
        return CCryptoKeyStore::AddCryptedMalleableKey(keyView, vchCryptedSecretH);
    }
    bool LoadMinVersion(int nVersion) {
        nWalletVersion = nVersion; nWalletMaxVersion = std::max(nWalletMaxVersion, nVersion);
        return true;
    }

    // Adds an encrypted key to the store, and saves it to disk.
    bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    bool AddCryptedMalleableKey(const CMalleableKeyView &keyView, const std::vector<unsigned char> &vchCryptedSecretH);

    // Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret) {
        SetMinVersion(FEATURE_WALLETCRYPT);
        return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
    }
    bool AddCScript(const CScript &redeemScript);
    bool LoadCScript(const CScript &redeemScript);

    // Adds a watch-only address to the store, and saves it to disk.
    bool AddWatchOnly(const CScript &dest);
    bool RemoveWatchOnly(const CScript &dest);

    // Adds a watch-only address to the store, without saving it to disk (used by LoadWallet)
    bool LoadWatchOnly(const CScript &dest);

    bool Unlock(const SecureString &strWalletPassphrase);
    bool ChangeWalletPassphrase(const SecureString &strOldWalletPassphrase, const SecureString &strNewWalletPassphrase);
    bool EncryptWallet(const SecureString &strWalletPassphrase);
    bool DecryptWallet(const SecureString &strWalletPassphrase);

    void GetAddresses(std::map<CBitcoinAddress, int64_t> &mapAddresses) const;
    bool GetPEM(const CKeyID &keyID, const std::string &fileName, const SecureString &strPassPhrase) const;

    //
    // Increment the next transaction order id
    // @return next transaction order id
    //
    int64_t IncOrderPosNext(CWalletDB *pwalletdb = NULL);

    typedef std::pair<CWalletTx *, CAccountingEntry *> TxPair;
    typedef std::multimap<int64_t, TxPair > TxItems;

    //
    // Get the wallet's activity log
    // @return multimap of ordered transactions and accounting entries
    // @warning Returned pointers are *only* valid within the scope of passed acentries
    //
    TxItems OrderedTxItems(std::list<CAccountingEntry> &acentries, std::string strAccount = "");

    void MarkDirty();
    bool AddToWallet(const CWalletTx &wtxIn);
    bool AddToWalletIfInvolvingMe(const CTransaction &tx, const CBlock *pblock, bool fUpdate = false);
    bool EraseFromWallet(uint256 hash);
    void ClearOrphans();

    void WalletUpdateSpent(const CTransaction &prevout, bool fBlock = false);
    int ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate = false);
    int ScanForWalletTransaction(const uint256& hashTx);
    void ReacceptWalletTransactions();
    void ResendWalletTransactions(int64_t nBestBlockTime);
    std::vector<uint256> ResendWalletTransactionsBefore(int64_t nTime);

    int64_t GetBalance() const;
    int64_t GetWatchOnlyBalance() const;
    int64_t GetUnconfirmedBalance() const;
    int64_t GetUnconfirmedWatchOnlyBalance() const;
    int64_t GetImmatureBalance() const;
    int64_t GetImmatureWatchOnlyBalance() const;
    int64_t GetStake() const;
    int64_t GetNewMint() const;
    int64_t GetWatchOnlyStake() const;
    int64_t GetWatchOnlyNewMint() const;

    bool CreateTransaction(const std::vector<std::pair<CScript, int64_t> > &vecSend, CWalletTx &wtxNew, CReserveKey &reservekey, int64_t &nFeeRet, const CCoinControl *coinControl=NULL);
    bool CreateTransaction(CScript scriptPubKey, int64_t nValue, CWalletTx &wtxNew, CReserveKey &reservekey, int64_t &nFeeRet, const CCoinControl *coinControl=NULL);
    bool CommitTransaction(CWalletTx &wtxNew, CReserveKey &reservekey);
    void GetStakeWeightFromValue(const int64_t &nTime, const int64_t &nValue, uint64_t &nWeight);

    //
    // Stake, Merge
    //
    bool CreateCoinStake(uint256 &hashTx, uint32_t nOut, uint32_t nTime, uint32_t nBits, CTransaction &txNew, CKey &key);
    bool MergeCoins(const int64_t &nAmount, const int64_t &nMinValue, const int64_t &nMaxValue, std::list<uint256> &listMerged);

    std::string SendMoney(CScript scriptPubKey, int64_t nValue, CWalletTx &wtxNew, bool fAskFee=false);

    bool NewKeyPool(unsigned int nSize = 0);
    bool TopUpKeyPool(unsigned int nSize = 0);
    int64_t AddReserveKey(const CKeyPool &keypool);
    void ReserveKeyFromKeyPool(int64_t &nIndex, CKeyPool &keypool);
    void KeepKey(int64_t nIndex);
    void ReturnKey(int64_t nIndex);
    bool GetKeyFromPool(CPubKey &key, bool fAllowReuse=true);
    int64_t GetOldestKeyPoolTime();
    void GetAllReserveKeys(std::set<CKeyID> &setAddress) const;

    std::set< std::set<CBitcoinAddress> > GetAddressGroupings();
    std::map<CBitcoinAddress, int64_t> GetAddressBalances();

    isminetype IsMine(const CTxIn &txin) const;
    int64_t GetDebit(const CTxIn &txin, const isminefilter &filter) const;
    isminetype IsMine(const CTxOut &txout) const;
    int64_t GetCredit(const CTxOut &txout, const isminefilter &filter) const;
    bool IsChange(const CTxOut &txout) const;
    int64_t GetChange(const CTxOut &txout) const;
    bool IsMine(const CTransaction &tx) const;
    bool IsFromMe(const CTransaction &tx) const;
    int64_t GetDebit(const CTransaction &tx, const isminefilter &filter) const;
    int64_t GetCredit(const CTransaction &tx, const isminefilter &filter) const;
    int64_t GetChange(const CTransaction &tx) const;
    void SetBestChain(const CBlockLocator &loc);

    DBErrors LoadWallet(bool &fFirstRunRet);
    DBErrors ZapWalletTx();

    bool SetAddressBookName(const CTxDestination &address, const std::string &strName);
    bool SetAddressBookName(const CBitcoinAddress &address, const std::string &strName);
    bool DelAddressBookName(const CBitcoinAddress &address);
    void UpdatedTransaction(const uint256 &hashTx);
    void PrintWallet(const CBlock &block);

    void Inventory(const uint256 &hash) {
        {
            LOCK(cs_wallet);
            std::map<uint256, int>::iterator mi = mapRequestCount.find(hash);
            if (mi != mapRequestCount.end()) {
                (*mi).second++;
            }
        }
    }

    unsigned int GetKeyPoolSize() {
        return (unsigned int)(setKeyPool.size());
    }

    bool GetTransaction(const uint256 &hashTx, CWalletTx &wtx);
    bool SetDefaultKey(const CPubKey &vchPubKey);

    //
    // signify that a particular wallet feature is now used. this may change nWalletVersion and nWalletMaxVersion if those are lower
    //
    bool SetMinVersion(enum WalletFeature, CWalletDB *pwalletdbIn = NULL, bool fExplicit = false);

    // change which version we're allowed to upgrade to (note that this does not immediately imply upgrading to that format)
    bool SetMaxVersion(int nVersion);

    // get the current wallet format (the oldest client version guaranteed to understand this wallet)
    // Wallet Status
    int GetVersion() { 
        return nWalletVersion;
    }

    void FixSpentCoins(int &nMismatchSpent, int64_t &nBalanceInQuestion, bool fCheckOnly = false);
    void DisableTransaction(const CTransaction &tx);

    //
    // Address book entry changed.
    // @note called with lock cs_wallet held.
    //
    boost::signals2::signal<void (CWallet *wallet, const CBitcoinAddress &address, const std::string &label, bool isMine, ChangeType status)> NotifyAddressBookChanged;

    //
    // Wallet transaction added, removed or updated.
    // @note called with lock cs_wallet held.
    //
    boost::signals2::signal<void (CWallet *wallet, const uint256 &hashTx, ChangeType status)> NotifyTransactionChanged;

    //
    // Watch-only address added
    //
    boost::signals2::signal<void (bool fHaveWatchOnly)> NotifyWatchonlyChanged;
};

//
// A key allocated from the key pool. 
//
class CReserveKey
{
private:
    CReserveKey(); // {}
    CReserveKey(const CReserveKey &); // {}
    CReserveKey &operator=(const CReserveKey &); // {}

protected:
    CWallet *pwallet;
    int64_t nIndex;
    CPubKey vchPubKey;

public:
    CReserveKey(CWallet *pwalletIn) {
        nIndex = -1;
        pwallet = pwalletIn;
    }

    ~CReserveKey() {
        if (! args_bool::fShutdown) {
            ReturnKey();
        }
    }

    void ReturnKey();
    CPubKey GetReservedKey();
    void KeepKey();
};

namespace mapValuePos
{
    typedef std::map<std::string, std::string> mapValue_t;

    inline void ReadOrderPos(int64_t &nOrderPos, mapValue_t &mapValue) {
        if (! mapValue.count("n")) {
            nOrderPos = -1; // TODO: calculate elsewhere
            return;
        }
        nOrderPos = atoi64(mapValue["n"].c_str());
    }

    inline void WriteOrderPos(const int64_t &nOrderPos, mapValue_t &mapValue) {
        if (nOrderPos == -1) {
            return;
        }
        mapValue["n"] = i64tostr(nOrderPos);
    }
}

//
// A transaction with a bunch of additional info that only the owner cares about.
//
// It includes any unrecorded transactions needed to link it back to the block chain.
//
class CWalletTx : public CMerkleTx
{
//private:
    // CWalletTx(const CWalletTx &); // {}
    // CWalletTx &operator=(const CWalletTx &); // {}

private:
    const CWallet *pwallet;

public:
    std::vector<CMerkleTx> vtxPrev;
    mapValuePos::mapValue_t mapValue;
    std::vector<std::pair<std::string, std::string> > vOrderForm;
    unsigned int fTimeReceivedIsTxTime;
    unsigned int nTimeReceived;  // time received by this node
    unsigned int nTimeSmart;
    char fFromMe;
    std::string strFromAccount;
    std::vector<char> vfSpent; // which outputs are already spent
    int64_t nOrderPos;  // position in ordered transaction list

    // memory only
    mutable bool fDebitCached;
    mutable bool fWatchDebitCached;
    mutable bool fCreditCached;
    mutable bool fWatchCreditCached;
    mutable bool fAvailableCreditCached;
    mutable bool fImmatureCreditCached;
    mutable bool fImmatureWatchCreditCached;
    mutable bool fAvailableWatchCreditCached;
    mutable bool fChangeCached;
    mutable int64_t nDebitCached;
    mutable int64_t nWatchDebitCached;
    mutable int64_t nCreditCached;
    mutable int64_t nWatchCreditCached;
    mutable int64_t nAvailableCreditCached;
    mutable int64_t nImmatureCreditCached;
    mutable int64_t nImmatureWatchCreditCached;
    mutable int64_t nAvailableWatchCreditCached;
    mutable int64_t nChangeCached;

    CWalletTx() {
        Init(NULL);
    }

    CWalletTx(const CWallet *pwalletIn) {
        Init(pwalletIn);
    }

    CWalletTx(const CWallet *pwalletIn, const CMerkleTx &txIn) : CMerkleTx(txIn) {
        Init(pwalletIn);
    }

    CWalletTx(const CWallet *pwalletIn, const CTransaction &txIn) : CMerkleTx(txIn) {
        Init(pwalletIn);
    }

    void Init(const CWallet *pwalletIn) {
        pwallet = pwalletIn;
        vtxPrev.clear();
        mapValue.clear();
        vOrderForm.clear();
        fTimeReceivedIsTxTime = false;
        nTimeReceived = 0;
        nTimeSmart = 0;
        fFromMe = false;
        strFromAccount.clear();
        vfSpent.clear();
        fDebitCached = false;
        fWatchDebitCached = false;
        fCreditCached = false;
        fWatchCreditCached = false;
        fAvailableCreditCached = false;
        fAvailableWatchCreditCached = false;
        fImmatureCreditCached = false;
        fImmatureWatchCreditCached = false;
        fChangeCached = false;
        nDebitCached = 0;
        nWatchDebitCached = 0;
        nCreditCached = 0;
        nWatchCreditCached = 0;
        nAvailableCreditCached = 0;
        nAvailableWatchCreditCached = 0;
        nImmatureCreditCached = 0;
        nImmatureWatchCreditCached = 0;
        nChangeCached = 0;
        nOrderPos = -1;
    }

    IMPLEMENT_SERIALIZE
    (
        CWalletTx *pthis = const_cast<CWalletTx *>(this);
        if (fRead) {
            pthis->Init(NULL);
        }

        char fSpent = false;
        if (! fRead) {
            pthis->mapValue["fromaccount"] = pthis->strFromAccount;

            std::string str;
            BOOST_FOREACH(char f, this->vfSpent)
            {
                str += (f ? '1' : '0');
                if (f) {
                    fSpent = true;
                }
            }
            pthis->mapValue["spent"] = str;

            mapValuePos::WriteOrderPos(pthis->nOrderPos, pthis->mapValue);

            if (this->nTimeSmart) {
                pthis->mapValue["timesmart"] = strprintf("%u", this->nTimeSmart);
            }
        }

        nSerSize += imp_ser::manage::SerReadWrite(s, *(CMerkleTx*)this, nType, nVersion,ser_action);
        READWRITE(this->vtxPrev);
        READWRITE(this->mapValue);
        READWRITE(this->vOrderForm);
        READWRITE(this->fTimeReceivedIsTxTime);
        READWRITE(this->nTimeReceived);
        READWRITE(this->fFromMe);
        READWRITE(fSpent);

        if (fRead) {
            pthis->strFromAccount = pthis->mapValue["fromaccount"];

            if (mapValue.count("spent")) {
                BOOST_FOREACH(char c, pthis->mapValue["spent"])
                {
                    pthis->vfSpent.push_back(c != '0');
                }
            } else {
                pthis->vfSpent.assign(vout.size(), fSpent);
            }

            mapValuePos::ReadOrderPos(pthis->nOrderPos, pthis->mapValue);

            pthis->nTimeSmart = mapValue.count("timesmart") ? (unsigned int)atoi64(pthis->mapValue["timesmart"]) : 0;
        }

        pthis->mapValue.erase("fromaccount");
        pthis->mapValue.erase("version");
        pthis->mapValue.erase("spent");
        pthis->mapValue.erase("n");
        pthis->mapValue.erase("timesmart");
    )

    //
    // marks certain txout's as spent
    // returns true if any update took place
    //
    bool UpdateSpent(const std::vector<char> &vfNewSpent);

    // make sure balances are recalculated
    void MarkDirty();
    void BindWallet(CWallet *pwalletIn);
    void MarkSpent(unsigned int nOut);
    void MarkUnspent(unsigned int nOut);
    bool IsSpent(unsigned int nOut) const;

    int64_t GetDebit(const isminefilter &filter) const;
    int64_t GetCredit(const isminefilter &filter) const;
    int64_t GetImmatureCredit(bool fUseCache=true) const;
    int64_t GetImmatureWatchOnlyCredit(bool fUseCache=true) const;
    int64_t GetAvailableCredit(bool fUseCache=true) const;        // hold coin
    int64_t GetAvailableWatchCredit(bool fUseCache=true) const;
    int64_t GetChange() const;

    void GetAmounts(int64_t &nGeneratedImmature, int64_t &nGeneratedMature, std::list<std::pair<CBitcoinAddress, int64_t> > &listReceived,
                    std::list<std::pair<CBitcoinAddress, int64_t> > &listSent, int64_t &nFee, std::string &strSentAccount, const isminefilter &filter) const;

    void GetAccountAmounts(const std::string &strAccount, int64_t &nGenerated, int64_t &nReceived, int64_t &nSent, int64_t &nFee, const isminefilter &filter) const;

    bool IsFromMe(const isminefilter &filter) const {
        return (GetDebit(filter) > 0);
    }

    bool InMempool() const;
    bool IsTrusted() const;        // ture: valid coin

    bool WriteToDisk();

    int64_t GetTxTime() const;
    int GetRequestCount() const;

    void AddSupportingTransactions(CTxDB &txdb);

    bool AcceptWalletTransaction(CTxDB &txdb, bool fCheckInputs=true);
    bool AcceptWalletTransaction();

    bool RelayWalletTransaction(CTxDB &txdb);
    bool RelayWalletTransaction();
};

class COutput
{
private:
    COutput(); // {}
    // COutput(const COutput &); // {}
    // COutput &operator=(const COutput &); // {}

public:
    const CWalletTx *tx;
    int i;
    int nDepth;
    bool fSpendable;

    COutput(const CWalletTx *txIn, int iIn, int nDepthIn, bool fSpendableIn) {
        tx = txIn;
        i = iIn;
        nDepth = nDepthIn;
        fSpendable = fSpendableIn;
    }

    std::string ToString() const {
        return strprintf("COutput(%s, %d, %d, %d) [%s]", tx->GetHash().ToString().substr(0,10).c_str(), i, fSpendable, nDepth, bitstr::FormatMoney(tx->vout[i].nValue).c_str());
    }
};

//
// Private key that includes an expiration date in case it never gets used.
//
class CWalletKey
{
private:
    // CWalletKey(); Call by CWalletKey(int64_t nExpires = 0)
    CWalletKey(const CWalletKey &); // {}
    CWalletKey &operator=(const CWalletKey &); // {}

public:
    CPrivKey vchPrivKey;
    int64_t nTimeCreated;
    int64_t nTimeExpires;
    std::string strComment;

    ////
    //// todo: add something to note what created it (user, getnewaddress, change)
    //// maybe should have a map<string, string> property map
    ////

    CWalletKey(int64_t nExpires = 0) {
        nTimeCreated = (nExpires ? bitsystem::GetTime() : 0);
        nTimeExpires = nExpires;
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH)) {
            READWRITE(nVersion);
        }
        READWRITE(this->vchPrivKey);
        READWRITE(this->nTimeCreated);
        READWRITE(this->nTimeExpires);
        READWRITE(this->strComment);
    )
};

//
// Account information.
// Stored in wallet with key "acc"+string account name.
//
class CAccount
{
private:
    CAccount(const CAccount &); // {}
    CAccount &operator=(const CAccount &); // {}

public:
    CPubKey vchPubKey;

    CAccount() {
        SetNull();
    }

    void SetNull() {
        vchPubKey = CPubKey();
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH)) {
            READWRITE(nVersion);
        }
        READWRITE(this->vchPubKey);
    )
};

//
// Internal transfers.
// Database key is acentry<account><counter>.
//
class CAccountingEntry
{
private:
    // CAccountingEntry(const CAccountingEntry &); // {}
    CAccountingEntry &operator=(const CAccountingEntry &); // {}

    std::vector<char> _ssExtra;

public:
    std::string strAccount;
    int64_t nCreditDebit;
    int64_t nTime;
    std::string strOtherAccount;
    std::string strComment;
    mapValuePos::mapValue_t mapValue;
    int64_t nOrderPos;    // position in ordered transaction list
    uint64_t nEntryNo;

    CAccountingEntry() {
        SetNull();
    }

    void SetNull() {
        nCreditDebit = 0;
        nTime = 0;
        strAccount.clear();
        strOtherAccount.clear();
        strComment.clear();
        nOrderPos = -1;
    }

    IMPLEMENT_SERIALIZE
    (
        CAccountingEntry &me = *const_cast<CAccountingEntry *>(this);
        if (!(nType & SER_GETHASH)) {
            READWRITE(nVersion);
        }

        //
        // Note: strAccount is serialized as part of the key, not here.
        //
        READWRITE(this->nCreditDebit);
        READWRITE(this->nTime);
        READWRITE(this->strOtherAccount);

        if (! fRead) {
            mapValuePos::WriteOrderPos(this->nOrderPos, me.mapValue);

            if (!(this->mapValue.empty() && this->_ssExtra.empty())) {
                CDataStream ss(nType, nVersion);
                ss.insert(ss.begin(), '\0');
                ss << mapValue;
                ss.insert(ss.end(), _ssExtra.begin(), _ssExtra.end());
                me.strComment.append(ss.str());
            }
        }

        READWRITE(this->strComment);

        size_t nSepPos = this->strComment.find("\0", 0, 1);
        if (fRead) {
            me.mapValue.clear();
            if (std::string::npos != nSepPos) {
                CDataStream ss(std::vector<char>(this->strComment.begin() + nSepPos + 1, this->strComment.end()), nType, nVersion);
                ss >> me.mapValue;
                me._ssExtra = std::vector<char>(ss.begin(), ss.end());
            }
            mapValuePos::ReadOrderPos(me.nOrderPos, me.mapValue);
        }
        if (std::string::npos != nSepPos) {
            me.strComment.erase(nSepPos);
        }

        me.mapValue.erase("n");
    )
};

namespace wallet_file
{
    inline bool GetWalletFile(CWallet *pwallet, std::string &strWalletFileOut) {
        if (! pwallet->fFileBacked) {
            return false;
        }

        strWalletFileOut = pwallet->strWalletFile;
        return true;
    }
}

#endif
//@
