// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/walletmodel.h>
#include <qt/guiconstants.h>
#include <qt/optionsmodel.h>
#include <qt/addresstablemodel.h>
#include <qt/mintingtablemodel.h>
#include <qt/transactiontablemodel.h>
#include <ui_interface.h>
#include <wallet.h>
#include <walletdb.h> // for BackupWallet
//#include <address/base58.h>
#include <block/block_process.h>
#include <QSet>
#include <QTimer>
#include <allocator/qtsecure.h>

#ifndef CLI_MODE_ENABLE
WalletModel::WalletModel(CWallet *wallet, OptionsModel *optionsModel, QObject *parent) :
    QObject(parent), wallet(wallet), optionsModel(optionsModel), addressTableModel(nullptr),
    transactionTableModel(nullptr),
    cachedBalance(0), cachedStake(0), cachedUnconfirmedBalance(0), cachedImmatureBalance(0), cachedQaiBalance(0),
    cachedNumTransactions(0),
    cachedEncryptionStatus(Unencrypted),
    cachedNumBlocks(0)
{
    try {

        fHaveWatchOnly = wallet->HaveWatchOnly();

        addressTableModel = new AddressTableModel(wallet, this);
        mintingTableModel = new MintingTableModel(wallet, this);
        transactionTableModel = new TransactionTableModel(wallet, this);

        // This timer will be fired repeatedly to update the balance
        pollTimer = new QTimer(this);
        connect(pollTimer, SIGNAL(timeout()), this, SLOT(pollBalanceChanged()));
        pollTimer->start(MODEL_UPDATE_DELAY);

        subscribeToCoreSignals();

    } catch (const std::bad_alloc &) {
        throw qt_error("WalletModel Failed to allocate memory.", nullptr);
    }
}
#else
WalletModel::WalletModel(CWallet *wallet, OptionsModel *optionsModel, QObject *parent) :
    QObject(parent), wallet(wallet), optionsModel(optionsModel), addressTableModel(nullptr),
    transactionTableModel(nullptr),
    cachedBalance(0), cachedStake(0), cachedUnconfirmedBalance(0), cachedImmatureBalance(0),
    cachedNumTransactions(0),
    cachedEncryptionStatus(Unencrypted),
    cachedNumBlocks(0)
{}
#endif

WalletModel::~WalletModel()
{
    unsubscribeFromCoreSignals();
}

bool WalletModel::haveWatchOnly() const
{
    return fHaveWatchOnly;
}

qint64 WalletModel::getBalance() const
{
    return wallet->GetBalance();
}

qint64 WalletModel::getBalanceWatchOnly() const
{
    return wallet->GetWatchOnlyBalance();
}

qint64 WalletModel::getUnconfirmedBalance() const
{
    return wallet->GetUnconfirmedBalance();
}

qint64 WalletModel::getStake() const
{
    return wallet->GetStake();
}

qint64 WalletModel::getImmatureBalance() const
{
    return wallet->GetImmatureBalance();
}

qint64 WalletModel::getQaiBalance() const
{
    return wallet->GetQaiBalance();
}

int WalletModel::getNumTransactions() const
{
    int numTransactions = 0;
    {
        LOCK(wallet->cs_wallet);
        numTransactions = (int)(wallet->mapWallet.size());
    }
    return numTransactions;
}

void WalletModel::updateStatus()
{
    EncryptionStatus newEncryptionStatus = getEncryptionStatus();

    if(cachedEncryptionStatus != newEncryptionStatus) {
        emit encryptionStatusChanged(newEncryptionStatus);
    }
}

void WalletModel::pollBalanceChanged()
{
    if(block_info::nBestHeight != cachedNumBlocks) {
        // Balance and number of transactions might have changed
        cachedNumBlocks = block_info::nBestHeight;
        checkBalanceChanged();
    }
}

void WalletModel::checkBalanceChanged()
{
    qint64 newBalanceTotal=getBalance(), newBalanceWatchOnly=getBalanceWatchOnly();
    qint64 newStake = getStake();
    qint64 newUnconfirmedBalance = getUnconfirmedBalance();
    qint64 newImmatureBalance = getImmatureBalance();
    qint64 newQaiBalance = getQaiBalance();

    if(cachedBalance != newBalanceTotal || cachedStake != newStake || cachedUnconfirmedBalance != newUnconfirmedBalance || cachedImmatureBalance != newImmatureBalance || cachedQaiBalance != newQaiBalance) {
        cachedBalance = newBalanceTotal;
        cachedStake = newStake;
        cachedUnconfirmedBalance = newUnconfirmedBalance;
        cachedImmatureBalance = newImmatureBalance;
        cachedQaiBalance = newQaiBalance;
        emit balanceChanged(newBalanceTotal, newBalanceWatchOnly, newStake, newUnconfirmedBalance, newImmatureBalance, newQaiBalance);
    }
}

void WalletModel::updateTransaction(const QString &hash, int status)
{
    if(transactionTableModel) {
        transactionTableModel->updateTransaction(hash, status);
    }

    // Balance and number of transactions might have changed
    checkBalanceChanged();

    int newNumTransactions = getNumTransactions();
    if(cachedNumTransactions != newNumTransactions) {
        cachedNumTransactions = newNumTransactions;
        emit numTransactionsChanged(newNumTransactions);
    }
}

void WalletModel::updateAddressBook(const QString &address, const QString &label, bool isMine, int status)
{
    if(addressTableModel) {
        addressTableModel->updateEntry(address, label, isMine, status);
    }
}

void WalletModel::updateWatchOnlyFlag(bool fHaveWatchonly)
{
    fHaveWatchOnly = fHaveWatchonly;
    emit notifyWatchonlyChanged(fHaveWatchonly);
}

bool WalletModel::validateAddress(const QString &address)
{
    CBitcoinAddress addressParsed(address.toStdString());
    return addressParsed.IsValid();
}

WalletModel::SendCoinsReturn WalletModel::sendCoins(const QList<SendCoinsRecipient> &recipients, const CCoinControl *coinControl)
{
    qint64 total = 0;
    QSet<QString> setAddress;
    QString hex;

    if(recipients.empty()) {
        return OK;
    }

    const bool fToAllQaiTransaction = (recipients.size() == 1 && recipients[0].label.contains(qaiTransaction));
    int64_t nBalance = 0;
    if(!fToAllQaiTransaction) {
        //debugcs::instance() << "Qt Wallet SendCoins" << debugcs::endl();

        // Pre-check input data for validity
        foreach(const SendCoinsRecipient &rcp, recipients)
        {
            if(! validateAddress(rcp.address)) {
                return InvalidAddress;
            }
            setAddress.insert(rcp.address);

            if(rcp.amount <= 0) {
                return InvalidAmount;
            }
            total += rcp.amount;
        }

        if(recipients.size() > setAddress.size()) {
            return DuplicateAddress;
        }

        std::vector<COutput> vCoins;
        wallet->AvailableCoins(vCoins, true, coinControl);

        for(const COutput &out: vCoins)
        {
            if(out.fSpendable) {
                nBalance += out.tx->get_vout(out.i).get_nValue();
            }
        }

        if(total > nBalance) {
            return AmountExceedsBalance;
        }

        if((total + block_info::nTransactionFee) > nBalance) {
            return SendCoinsReturn(AmountWithFeeExceedsBalance, block_info::nTransactionFee);
        }
    }

    {
        LOCK2(block_process::cs_main, wallet->cs_wallet);

        // Sendmany
        std::vector<std::pair<CScript, int64_t> > vecSend;
        foreach(const SendCoinsRecipient &rcp, recipients)
        {
            debugcs::instance() << "wallet address: " << rcp.address.toStdString() << debugcs::endl();
            CScript scriptPubKey;
            scriptPubKey.SetAddress(CBitcoinAddress(rcp.address.toStdString()));
            vecSend.push_back(std::make_pair(scriptPubKey, rcp.amount));
        }

        CWalletTx wtx;
        CReserveKey keyChange(wallet);
        int64_t nFeeRequired = 0;
        bool fCreated = false;
        if(fToAllQaiTransaction)
            fCreated = wallet->CreateTransactionAllBalancesToQAI(vecSend, wtx, keyChange, nFeeRequired);
        else
            fCreated = wallet->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, coinControl);

        if(! fCreated) {
            if((total + nFeeRequired) > nBalance) { // FIXME: could cause collisions in the future
                return SendCoinsReturn(AmountWithFeeExceedsBalance, nFeeRequired);
            }
            return TransactionCreationFailed;
        }
        if(! CClientUIInterface::get().ThreadSafeAskFee(nFeeRequired, tr("Sending...").toStdString())) {
            return Aborted;
        }
        if(! wallet->CommitTransaction(wtx, keyChange)) {
            return TransactionCommitFailed;
        }
        hex = QString::fromStdString(wtx.GetHash().GetHex());
    }

    // Add addresses / update labels that we've sent to to the address book
    foreach(const SendCoinsRecipient &rcp, recipients)
    {
        std::string strAddress = rcp.address.toStdString();
        CBitcoinAddress addr(strAddress);
        std::string strLabel = rcp.label.toStdString();
        {
            LOCK(wallet->cs_wallet);

            std::map<CBitcoinAddress, std::string>::iterator mi = wallet->mapAddressBook.find(addr);

            // Check if we have a new address or an updated label
            if (mi == wallet->mapAddressBook.end() || mi->second != strLabel) {
                wallet->SetAddressBookName(addr, strLabel);
            }
        }
    }

    return SendCoinsReturn(OK, 0, hex);
}

bool WalletModel::getMintflag() const {
    return CWallet::fWalletUnlockMintOnly;
}

OptionsModel *WalletModel::getOptionsModel()
{
    return optionsModel;
}

AddressTableModel *WalletModel::getAddressTableModel()
{
    return addressTableModel;
}

MintingTableModel *WalletModel::getMintingTableModel()
{
    return mintingTableModel;
}

TransactionTableModel *WalletModel::getTransactionTableModel()
{
    return transactionTableModel;
}

WalletModel::EncryptionStatus WalletModel::getEncryptionStatus() const
{
    if(! wallet->IsCrypted()) {
        return Unencrypted;
    } else if(wallet->IsLocked()) {
        return Locked;
    } else {
        return Unlocked;
    }
}

bool WalletModel::setWalletEncrypted(bool encrypted, const SecureString &passphrase)
{
    if(encrypted) {
        // Encrypt
        return wallet->EncryptWallet(passphrase);
    } else {
        // Decrypt
        return wallet->DecryptWallet(passphrase);
    }
}

bool WalletModel::setWalletLocked(bool locked, const SecureString &passPhrase)
{
    if(locked) {
        // Lock
        return wallet->Lock();
    } else {
        // Unlock
        return wallet->Unlock(passPhrase);
    }
}

bool WalletModel::changePassphrase(const SecureString &oldPass, const SecureString &newPass)
{
    bool retval;
    {
        LOCK(wallet->cs_wallet);
        wallet->Lock(); // Make sure wallet is locked before attempting pass change
        retval = wallet->ChangeWalletPassphrase(oldPass, newPass);
    }
    return retval;
}

void WalletModel::getStakeWeightFromValue(const int64_t &nTime, const int64_t &nValue, uint64_t &nWeight)
{
    wallet->GetStakeWeightFromValue(nTime, nValue, nWeight);
}

bool WalletModel::dumpWallet(const QString &filename)
{
    return wallet_dispatch::DumpWallet(wallet, filename.toLocal8Bit().data());
}

bool WalletModel::importWallet(const QString &filename)
{
    return wallet_dispatch::ImportWallet(wallet, filename.toLocal8Bit().data());
}

bool WalletModel::backupWallet(const QString &filename)
{
    return wallet_dispatch::BackupWallet(*wallet, filename.toLocal8Bit().data());
}

// Handlers for core signals
static void NotifyKeyStoreStatusChanged(WalletModel *walletmodel, CCryptoKeyStore *wallet)
{
    logging::LogPrintf("NotifyKeyStoreStatusChanged\n");
    QMetaObject::invokeMethod(walletmodel, "updateStatus", Qt::QueuedConnection);
}

static void NotifyAddressBookChanged(WalletModel *walletmodel, CWallet *wallet, const CBitcoinAddress &address, const std::string &label, bool isMine, ChangeType status)
{
    logging::LogPrintf("NotifyAddressBookChanged %s %s isMine=%i status=%i\n", address.ToString().c_str(), label.c_str(), isMine, status);
    QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(address.ToString())),
                              Q_ARG(QString, QString::fromStdString(label)),
                              Q_ARG(bool, isMine),
                              Q_ARG(int, status));
}

static void NotifyTransactionChanged(WalletModel *walletmodel, CWallet *wallet, const uint256 &hash, ChangeType status)
{
    logging::LogPrintf("NotifyTransactionChanged %s status=%i\n", hash.GetHex().c_str(), status);
    QMetaObject::invokeMethod(walletmodel, "updateTransaction", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(hash.GetHex())),
                              Q_ARG(int, status));
}

static void NotifyWatchonlyChanged(WalletModel *walletmodel, bool fHaveWatchonly)
{
    QMetaObject::invokeMethod(walletmodel, "updateWatchOnlyFlag", Qt::QueuedConnection,
    Q_ARG(bool, fHaveWatchonly));
}

void WalletModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    wallet->NotifyStatusChanged.connect(boost::bind(&NotifyKeyStoreStatusChanged, this, _1));
    wallet->NotifyAddressBookChanged.connect(boost::bind(NotifyAddressBookChanged, this, _1, _2, _3, _4, _5));
    wallet->NotifyTransactionChanged.connect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
    wallet->NotifyWatchonlyChanged.connect(boost::bind(NotifyWatchonlyChanged, this, _1));
}

void WalletModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    wallet->NotifyStatusChanged.disconnect(boost::bind(&NotifyKeyStoreStatusChanged, this, _1));
    wallet->NotifyAddressBookChanged.disconnect(boost::bind(NotifyAddressBookChanged, this, _1, _2, _3, _4, _5));
    wallet->NotifyTransactionChanged.disconnect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
    wallet->NotifyWatchonlyChanged.disconnect(boost::bind(NotifyWatchonlyChanged, this, _1));
}

// WalletModel::UnlockContext implementation
WalletModel::UnlockContext WalletModel::requestUnlock()
{
    bool was_locked = getEncryptionStatus() == Locked;
    bool mintflag = CWallet::fWalletUnlockMintOnly;

    if ((!was_locked) && CWallet::fWalletUnlockMintOnly) {
        setWalletLocked(true);
        was_locked = getEncryptionStatus() == Locked;
    }
    if(was_locked) {
        // Request UI to unlock wallet
        emit requireUnlock();
    }

    // If wallet is still locked, unlock was failed or cancelled, mark context as invalid
    bool valid = getEncryptionStatus() != Locked;

    return UnlockContext(this, valid, was_locked, mintflag);
}

bool WalletModel::requestUnlock_manualLock()
{
    bool was_locked = getEncryptionStatus() == Locked;
    bool mintflag = CWallet::fWalletUnlockMintOnly;

    if ((!was_locked) && CWallet::fWalletUnlockMintOnly) {
        setWalletLocked(true);
        was_locked = getEncryptionStatus() == Locked;
    }
    if(was_locked) {
        // Request UI to unlock wallet
        emit requireUnlock();
    }

    // If wallet is still locked, unlock was failed or cancelled, mark context as invalid
    bool valid = getEncryptionStatus() != Locked;

    return valid;
}

WalletModel::UnlockContext::UnlockContext(WalletModel *wallet, bool valid, bool relock, bool mintflag):
        wallet(wallet),
        valid(valid),
        relock(relock),
        mintflag(mintflag)
{
}

WalletModel::UnlockContext::~UnlockContext()
{
    if(valid && relock) {
        if (mintflag) {
            // Restore unlock minting flag
            CWallet::fWalletUnlockMintOnly = mintflag;
            return;
        }
        wallet->setWalletLocked(true);
    }
}

void WalletModel::UnlockContext::CopyFrom(const UnlockContext& rhs)
{
    // Transfer context; old object no longer relocks wallet
    *this = rhs;
    rhs.relock = false;
}

bool WalletModel::getPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    return wallet->GetPubKey(address, vchPubKeyOut);
}

// returns a list of COutputs from COutPoints
void WalletModel::getOutputs(const std::vector<COutPoint> &vOutpoints, std::vector<COutput> &vOutputs)
{
    for(const COutPoint &outpoint: vOutpoints)
    {
        if (! wallet->mapWallet.count(outpoint.get_hash())) {
            continue;
        }
        COutput out(&wallet->mapWallet[outpoint.get_hash()], outpoint.get_n(), wallet->mapWallet[outpoint.get_hash()].GetDepthInMainChain(), true);
        vOutputs.push_back(out);
    }
}

// AvailableCoins + LockedCoins grouped by wallet address (put change in one group with wallet address) 
void WalletModel::listCoins(std::map<QString, std::vector<COutput> >& mapCoins) const
{
    std::vector<COutput> vCoins;
    wallet->AvailableCoins(vCoins);
    std::vector<COutPoint> vLockedCoins;

    // add locked coins
    for(const COutPoint &outpoint: vLockedCoins)
    {
        if (! wallet->mapWallet.count(outpoint.get_hash())) {
            continue;
        }
        COutput out(&wallet->mapWallet[outpoint.get_hash()], outpoint.get_n(), wallet->mapWallet[outpoint.get_hash()].GetDepthInMainChain(), true);
        if (outpoint.get_n() < out.tx->get_vout().size() && wallet->IsMine(out.tx->get_vout(outpoint.get_n())) == MINE_SPENDABLE) {
            vCoins.push_back(out);
        }
    }

    for(const COutput &out: vCoins)
    {
        COutput cout = out;

        while (wallet->IsChange(cout.tx->get_vout(cout.i)) && cout.tx->get_vin().size() > 0 && wallet->IsMine(cout.tx->get_vin(0)))
        {
            if (! wallet->mapWallet.count(cout.tx->get_vin(0).get_prevout().get_hash())) {
                break;
            }
            cout = COutput(&wallet->mapWallet[cout.tx->get_vin(0).get_prevout().get_hash()], cout.tx->get_vin(0).get_prevout().get_n(), 0, true);
        }

        CBitcoinAddress addressRet;
        if(!out.fSpendable || !Script_util::ExtractAddress(*wallet, cout.tx->get_vout(cout.i).get_scriptPubKey(), addressRet)) {
            continue;
        }

        mapCoins[addressRet.ToString().c_str()].push_back(out);
    }
}

bool WalletModel::isLockedCoin(uint256 hash, unsigned int n) const
{
    (void)hash;
    (void)n;
    return false;
}

void WalletModel::lockCoin(COutPoint &output)
{
    (void)output;
    return;
}

void WalletModel::unlockCoin(COutPoint &output)
{
    (void)output;
    return;
}

void WalletModel::listLockedCoins(std::vector<COutPoint> &vOutpts)
{
    (void)vOutpts;
    return;
}

void WalletModel::clearOrphans()
{
    wallet->ClearOrphans();
}

CWallet *WalletModel::getWallet()
{
    return wallet;
}
