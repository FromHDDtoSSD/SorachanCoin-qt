// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WALLETMODEL_H
#define WALLETMODEL_H

#include <QObject>
#include <vector>
#include <map>
#include <allocator/allocators.h> /* for SecureString */
#include <uint256.h>

class OptionsModel;
class AddressTableModel;
class TransactionTableModel;
class MintingTableModel;
class CWallet;
class CKeyID;
class CPubKey;
class COutput;
class COutPoint;
class uint256;
class CCoinControl;

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

class SendCoinsRecipient
{
private:
    //SendCoinsRecipient(const SendCoinsRecipient &)=delete;
    //SendCoinsRecipient &operator=(const SendCoinsRecipient &)=delete;
    //SendCoinsRecipient(SendCoinsRecipient &&)=delete;
    //SendCoinsRecipient &operator=(SendCoinsRecipient &&)=delete;
public:
    QString address;
    QString label;
    qint64 amount;
};

/** Interface to Bitcoin wallet from Qt view code. */
const QString qaiTransaction("QAI_scriptPubKey_Transaction");
class WalletModel : public QObject
{
    Q_OBJECT
private:
    WalletModel(const WalletModel &)=delete;
    WalletModel &operator=(const WalletModel &)=delete;
    WalletModel(WalletModel &&)=delete;
    WalletModel &operator=(WalletModel &&)=delete;
public:
    explicit WalletModel(CWallet *wallet, OptionsModel *optionsModel, QObject *parent = nullptr);
    ~WalletModel();

    enum StatusCode // Returned by sendCoins
    {
        OK,
        InvalidAmount,
        InvalidAddress,
        AmountExceedsBalance,
        AmountWithFeeExceedsBalance,
        DuplicateAddress,
        TransactionCreationFailed, // Error returned when wallet is still locked
        TransactionCommitFailed,
        Aborted
    };

    enum EncryptionStatus
    {
        Unencrypted,  // !wallet->IsCrypted()
        Locked,       // wallet->IsCrypted() && wallet->IsLocked()
        Unlocked      // wallet->IsCrypted() && !wallet->IsLocked()
    };

    OptionsModel *getOptionsModel();
    AddressTableModel *getAddressTableModel();
    MintingTableModel *getMintingTableModel();
    TransactionTableModel *getTransactionTableModel();

    bool getMintflag() const;

    bool haveWatchOnly() const;
    qint64 getBalance() const;
    qint64 getBalanceWatchOnly() const;
    qint64 getStake() const;
    qint64 getUnconfirmedBalance() const;
    qint64 getImmatureBalance() const;
    qint64 getQaiBalance() const;
    int getNumTransactions() const;
    EncryptionStatus getEncryptionStatus() const;

    // Check address for validity
    bool validateAddress(const QString &address);

    // Return status record for SendCoins, contains error id + information
    struct SendCoinsReturn
    {
        SendCoinsReturn(StatusCode status=Aborted,
                         qint64 fee=0,
                         QString hex=QString()):
            status(status), fee(fee), hex(hex) {}
        StatusCode status;
        qint64 fee; // is used in case status is "AmountWithFeeExceedsBalance"
        QString hex; // is filled with the transaction hash if status is "OK"
    };

    // Send coins to a list of recipients
    SendCoinsReturn sendCoins(const QList<SendCoinsRecipient> &recipients, const CCoinControl *coinControl=NULL);

    // Wallet encryption
    bool setWalletEncrypted(bool encrypted, const SecureString &passphrase);
    // Passphrase only needed when unlocking
    bool setWalletLocked(bool locked, const SecureString &passPhrase=SecureString());
    bool changePassphrase(const SecureString &oldPass, const SecureString &newPass);
    // Wallet backup
    bool backupWallet(const QString &filename);

    bool dumpWallet(const QString &filename);
    bool importWallet(const QString &filename);

    void getStakeWeightFromValue(const int64_t& nTime, const int64_t& nValue, uint64_t& nWeight);

    // RAI object for unlocking wallet, returned by requestUnlock()
    class UnlockContext
    {
    public:
        UnlockContext(WalletModel *wallet, bool valid, bool relock, bool mintflag);
        ~UnlockContext();

        bool isValid() const { return valid; }

        // Copy operator and constructor transfer the context
        UnlockContext(const UnlockContext &obj) { CopyFrom(obj); }
        UnlockContext& operator=(const UnlockContext &rhs) { CopyFrom(rhs); return *this; }
    private:
        WalletModel *wallet;
        bool valid;
        mutable bool relock; // mutable, as it can be set to false by copying
        bool mintflag;

        void CopyFrom(const UnlockContext &rhs);
    };

    UnlockContext requestUnlock();
    bool requestUnlock_manualLock();

    bool getPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const;
    void getOutputs(const std::vector<COutPoint> &vOutpoints, std::vector<COutput> &vOutputs);
    void listCoins(std::map<QString, std::vector<COutput> > &mapCoins) const;

    bool isLockedCoin(uint256 hash, unsigned int n) const;
    void lockCoin(COutPoint &output);
    void unlockCoin(COutPoint &output);
    void listLockedCoins(std::vector<COutPoint> &vOutpts);
    void clearOrphans();
    CWallet *getWallet();

private:
    CWallet *wallet;
    bool fHaveWatchOnly;

    // Wallet has an options model for wallet-specific options
    // (transaction fee, for example)
    OptionsModel *optionsModel;

    AddressTableModel *addressTableModel;
    MintingTableModel *mintingTableModel;
    TransactionTableModel *transactionTableModel;

    // Cache some values to be able to detect changes
    qint64 cachedBalance;
    qint64 cachedStake;
    qint64 cachedUnconfirmedBalance;
    qint64 cachedImmatureBalance;
    qint64 cachedNumTransactions;
    qint64 cachedQaiBalance;
    EncryptionStatus cachedEncryptionStatus;
    int cachedNumBlocks;

    QTimer *pollTimer;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();
    void checkBalanceChanged();

public slots:
    /* Wallet status might have changed */
    void updateStatus();
    /* New transaction, or transaction changed status */
    void updateTransaction(const QString &hash, int status);
    /* New, updated or removed address book entry */
    void updateAddressBook(const QString &address, const QString &label, bool isMine, int status);
    /* Watchonly added */
    void updateWatchOnlyFlag(bool fHaveWatchonly);
    /* Current, immature or unconfirmed balance might have changed - emit 'balanceChanged' if so */
    void pollBalanceChanged();

signals:
    // Signal that balance in wallet changed
    void balanceChanged(qint64 total, qint64 watchOnly, qint64 stake, qint64 unconfirmedBalance, qint64 immatureBalance, qint64 qaiBalance);

    // Number of transactions in wallet changed
    void numTransactionsChanged(int count);

    // Encryption status of wallet changed
    void encryptionStatusChanged(int status);

    // Signal emitted when wallet needs to be unlocked
    // It is valid behaviour for listeners to keep the wallet locked after this signal;
    // this means that the unlocking failed or was cancelled.
    void requireUnlock();

    // Asynchronous error notification
    void error(const QString &title, const QString &message, bool modal);

    // Watch-only address added
    void notifyWatchonlyChanged(bool fHaveWatchonly);
};


#endif // WALLETMODEL_H
