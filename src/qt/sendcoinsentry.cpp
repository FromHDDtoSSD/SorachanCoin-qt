// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/sendcoinsentry.h>
#include <ui_sendcoinsentry.h>
#include <qt/guiutil.h>
#include <qt/bitcoinunits.h>
#include <qt/addressbookpage.h>
#include <qt/walletmodel.h>
#include <qt/optionsmodel.h>
#include <qt/addresstablemodel.h>
#include <QApplication>
#include <QClipboard>
#include <allocator/qtsecure.h>

SendCoinsEntry::SendCoinsEntry(QWidget *parent) :
    QFrame(parent),
    ui(new(std::nothrow) Ui::SendCoinsEntry),
    model(nullptr)
{
    if(! ui) {
        throw qt_error("SendCoinsEntry Failed to allocate memory.", this);
    }

    ui->setupUi(this);

#ifdef Q_OS_MAC
    ui->payToLayout->setSpacing(4);
#endif
#if QT_VERSION >= 0x040700
    /* Do not move this to the XML file, Qt before 4.7 will choke on it */
    ui->addAsLabel->setPlaceholderText(tr("Enter a label for this address to add it to your address book"));
    ui->payTo->setPlaceholderText(tr("Enter a SorachanCoin address (e.g. SUEgQX5BMKamE3eZYJD7wGfV1T3EuytBak)"));
#endif
    setFocusPolicy(Qt::TabFocus);
    setFocusProxy(ui->payTo);

    GUIUtil::setupAddressWidget(ui->payTo, this);
}

SendCoinsEntry::~SendCoinsEntry()
{
    delete ui;
}

void SendCoinsEntry::on_pasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->payTo->setText(QApplication::clipboard()->text());
}

void SendCoinsEntry::on_addressBookButton_clicked()
{
    if(! model) {
        return;
    }

    AddressBookPage dlg(AddressBookPage::ForSending, AddressBookPage::SendingTab, this);
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec()) {
        ui->payTo->setText(dlg.getReturnValue());
        ui->payAmount->setFocus();
    }
}

void SendCoinsEntry::on_payTo_textChanged(const QString &address)
{
    if(! model) {
        return;
    }
    // Fill in label from address book
    ui->addAsLabel->setText(model->getAddressTableModel()->labelForAddress(address));
}

void SendCoinsEntry::setModel(WalletModel *model)
{
    this->model = model;

    if(model && model->getOptionsModel()) {
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
    }

    connect(ui->payAmount, SIGNAL(textChanged()), this, SIGNAL(payAmountChanged()));

    clear();
}

void SendCoinsEntry::setRemoveEnabled(bool enabled)
{
    ui->deleteButton->setEnabled(enabled);
}

void SendCoinsEntry::clear()
{
    ui->payTo->clear();
    ui->addAsLabel->clear();
    ui->payAmount->clear();
    ui->payTo->setFocus();
    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void SendCoinsEntry::on_deleteButton_clicked()
{
    emit removeEntry(this);
}

bool SendCoinsEntry::validate()
{
    // Check input validity
    bool retval = true;

    if(! ui->payAmount->validate()) {
        retval = false;
    } else {
        if(ui->payAmount->value() <= 0) {
            // Cannot send 0 coins or less
            ui->payAmount->setValid(false);
            retval = false;
        }
    }

    if(!ui->payTo->hasAcceptableInput() ||
       (model && !model->validateAddress(ui->payTo->text())))
    {
        ui->payTo->setValid(false);
        retval = false;
    }

    return retval;
}

SendCoinsRecipient SendCoinsEntry::getValue()
{
    SendCoinsRecipient rv;

    rv.address = ui->payTo->text();
    rv.label = ui->addAsLabel->text();
    rv.amount = ui->payAmount->value();

    return rv;
}

QWidget *SendCoinsEntry::setupTabChain(QWidget *prev)
{
    QWidget::setTabOrder(prev, ui->payTo);
    QWidget::setTabOrder(ui->payTo, ui->addressBookButton);
    QWidget::setTabOrder(ui->addressBookButton, ui->pasteButton);
    QWidget::setTabOrder(ui->pasteButton, ui->deleteButton);
    QWidget::setTabOrder(ui->deleteButton, ui->addAsLabel);
    return ui->payAmount->setupTabChain(ui->addAsLabel);
}

void SendCoinsEntry::setValue(const SendCoinsRecipient &value)
{
    ui->payTo->setText(value.address);
    ui->addAsLabel->setText(value.label);
    ui->payAmount->setValue(value.amount);
}

bool SendCoinsEntry::isClear()
{
    return ui->payTo->text().isEmpty();
}

void SendCoinsEntry::setFocus()
{
    ui->payTo->setFocus();
}

void SendCoinsEntry::updateDisplayUnit()
{
    if(model && model->getOptionsModel()) {
        // Update payAmount with the current unit
        ui->payAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    }
}
