// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <QApplication>
#include <QClipboard>
#include <string>
#include <vector>
#include <qt/addressbookpage.h>
#include <qt/addresstablemodel.h>
#include <address/key_io.h>
#include <qt/guiutil.h>
#include <key.h>
#include <qt/multisigaddressentry.h>
#include <ui_multisigaddressentry.h>
#include <qt/walletmodel.h>
#include <allocator/qtsecure.h>

MultisigAddressEntry::MultisigAddressEntry(QWidget *parent) : QFrame(parent), ui(new(std::nothrow) Ui::MultisigAddressEntry), model(0)
{
    if(! ui)
        throw qt_error("MultisigAddressEntry out of memory.", this);
    ui->setupUi(this);
    GUIUtil::setupAddressWidget(ui->address, this);
}

MultisigAddressEntry::~MultisigAddressEntry()
{
    delete ui;
}

void MultisigAddressEntry::setModel(WalletModel *model)
{
    this->model = model;
    clear();
}

void MultisigAddressEntry::clear()
{
    ui->pubkey->clear();
    ui->address->clear();
    ui->label->clear();
    ui->pubkey->setFocus();
}

bool MultisigAddressEntry::validate()
{
    return !ui->pubkey->text().isEmpty();
}

QString MultisigAddressEntry::getPubkey()
{
    return ui->pubkey->text();
}

void MultisigAddressEntry::setRemoveEnabled(bool enabled)
{
    ui->deleteButton->setEnabled(enabled);
}

void MultisigAddressEntry::on_pasteButton_clicked()
{
    ui->address->setText(QApplication::clipboard()->text());
}

void MultisigAddressEntry::on_deleteButton_clicked()
{
    emit removeEntry(this);
}

void MultisigAddressEntry::on_addressBookButton_clicked()
{
    if(! model) {
        return;
    }

    AddressBookPage dlg(AddressBookPage::ForSending, AddressBookPage::ReceivingTab, this);
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec()) {
        ui->address->setText(dlg.getReturnValue());
    }
}

void MultisigAddressEntry::on_pubkey_textChanged(const QString &pubkey)
{
    // Compute address from public key
    key_vector vchPubKey(hex::ParseHex(pubkey.toStdString().c_str()));
    CPubKey pkey(vchPubKey);
    CKeyID keyID = pkey.GetID();
    CBitcoinAddress address(keyID);
    ui->address->setText(address.ToString().c_str());

    if(! model) {
        return;
    }

    // Get label of address
    QString associatedLabel = model->getAddressTableModel()->labelForAddress(address.ToString().c_str());
    if(! associatedLabel.isEmpty()) {
        ui->label->setText(associatedLabel);
    } else {
        ui->label->setText(QString());
    }
}

void MultisigAddressEntry::on_address_textChanged(const QString &address)
{
    if(! model) {
        return;
    }

    // Get public key of address
    CBitcoinAddress addr(address.toStdString().c_str());
    CKeyID keyID;
    if(addr.GetKeyID(keyID)) {
        CPubKey vchPubKey;
        model->getPubKey(keyID, vchPubKey);
        std::string pubkey = util::HexStr(vchPubKey.begin(), vchPubKey.end());
        if(! pubkey.empty()) {
            ui->pubkey->setText(pubkey.c_str());
        }
    }

    // Get label of address
    QString associatedLabel = model->getAddressTableModel()->labelForAddress(address);
    if(! associatedLabel.isEmpty()) {
        ui->label->setText(associatedLabel);
    }
}
