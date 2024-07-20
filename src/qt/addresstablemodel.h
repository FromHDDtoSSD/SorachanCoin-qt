// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ADDRESSTABLEMODEL_H
#define ADDRESSTABLEMODEL_H

#include <QAbstractTableModel>
#include <QStringList>

class AddressTablePriv;
class CWallet;
class WalletModel;

// Qt model of the address book in the core. This allows views to access and modify the address book.
class AddressTableModel : public QAbstractTableModel
{
    friend class AddressTablePriv;
    Q_OBJECT
private:
    AddressTableModel()=delete;
    AddressTableModel(const AddressTableModel &)=delete;
    AddressTableModel &operator=(const AddressTableModel &)=delete;
    AddressTableModel(AddressTableModel &&)=delete;
    AddressTableModel &operator=(AddressTableModel &&)=delete;

public:
    explicit AddressTableModel(CWallet *wallet, WalletModel *parent = nullptr);
    ~AddressTableModel();

    enum ColumnIndex
    {
        Label = 0,   /**< User specified label */
        Address = 1  /**< Bitcoin address */
    };

    enum RoleIndex
    {
        TypeRole = Qt::UserRole /**< Type of address (#Send or #Receive) */
    };

    /** Return status of edit/insert operation */
    enum EditStatus
    {
        OK,                     /**< Everything ok */
        NO_CHANGES,             /**< No changes were made during edit operation */
        INVALID_ADDRESS,        /**< Unparseable address */
        DUPLICATE_ADDRESS,      /**< Address already in address book */
        WALLET_UNLOCK_FAILURE,  /**< Wallet could not be unlocked to create new receiving address */
        KEY_GENERATION_FAILURE  /**< Generating a new public key for a receiving address failed */
    };

    static const QString Send;      /**< Specifies send address */
    static const QString Receive;   /**< Specifies receive address */

    /** name Methods overridden from QAbstractTableModel */
    int rowCount(const QModelIndex &parent) const;
    int columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    bool setData(const QModelIndex &index, const QVariant &value, int role);
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    QModelIndex index(int row, int column, const QModelIndex &parent) const;
    bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex());
    Qt::ItemFlags flags(const QModelIndex &index) const;

    /* Add an address to the model. Returns the added address on success, and an empty string otherwise. */
    QString addRow(const QString &type, const QString &label, const QString &address);

    /* Add an address to the SORA-QAI */
    void addQai_eth(const QString &label);
    void addQai_v1(const QString &label);
    void addQai_v2(const QString &label);
    bool addQai_v3(bool &mintflag);
    void addQai_v3_wallet_tolock(bool mintflag);

    /* Look up label for address in address book, if not found return empty string. */
    QString labelForAddress(const QString &address) const;

    /* Look up row index of an address in the model. Return -1 if not found. */
    int lookupAddress(const QString &address) const;

    EditStatus getEditStatus() const { return editStatus; }

private:
    WalletModel *walletModel;
    CWallet *wallet;
    AddressTablePriv *priv;
    QStringList columns;
    EditStatus editStatus;

    /** Notify listeners that data changed. */
    void emitDataChanged(int index);

signals:
    void defaultAddressChanged(const QString &address);

public slots:
    /* Update address list from core. */
    void updateEntry(const QString &address, const QString &label, bool isMine, int status);

};

#endif // ADDRESSTABLEMODEL_H
