// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MULTISIGADDRESSENTRY_H
#define MULTISIGADDRESSENTRY_H

#include <QFrame>

class WalletModel;

namespace Ui
{
    class MultisigAddressEntry;
}

class MultisigAddressEntry : public QFrame
{
    Q_OBJECT;

  private:
    MultisigAddressEntry(const MultisigAddressEntry &)=delete;
    MultisigAddressEntry &operator=(const MultisigAddressEntry &)=delete;
    MultisigAddressEntry(MultisigAddressEntry &&)=delete;
    MultisigAddressEntry &operator=(MultisigAddressEntry &&)=delete;
  public:
    explicit MultisigAddressEntry(QWidget *parent = nullptr);
    ~MultisigAddressEntry();
    void setModel(WalletModel *model);
    bool validate();
    QString getPubkey();

    public slots:
    void setRemoveEnabled(bool enabled);
    void clear();

  signals:
    void removeEntry(MultisigAddressEntry *entry);

  private:
    Ui::MultisigAddressEntry *ui;
    WalletModel *model;

  private slots:
    void on_pubkey_textChanged(const QString &pubkey);
    void on_pasteButton_clicked();
    void on_deleteButton_clicked();
    void on_address_textChanged(const QString &address);
    void on_addressBookButton_clicked();
};

#endif // MULTISIGADDRESSENTRY_H
