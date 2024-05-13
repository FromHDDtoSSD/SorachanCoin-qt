// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/editaddressdialog.h>
#include <ui_editaddressdialog.h>
#include <qt/addresstablemodel.h>
#include <qt/dialogwindowflags.h>
#include <qt/guiutil.h>
#include <QDataWidgetMapper>
#include <QMessageBox>
#include <allocator/qtsecure.h>
#include <rpc/bitcoinrpc.h>

EditAddressDialog::EditAddressDialog(Mode mode, QWidget *parent) :
    QDialog(parent, DIALOGWINDOWHINTS),
    ui(new(std::nothrow) Ui::EditAddressDialog), mapper(0), mode(mode), model(0)
{
    if(! ui) {
        throw qt_error("EditAddressDialog Failed to allocate memory.", this);
    }
    try {

        ui->setupUi(this);
        GUIUtil::setupAddressWidget(ui->addressEdit, this);
        switch(mode)
        {
        case NewReceivingAddress:
            setWindowTitle(tr("New receiving address"));
            ui->label->setEnabled(true);
            ui->label->setVisible(true);
            ui->labelEdit->setEnabled(true);
            ui->labelEdit->setVisible(true);
            ui->label_2->setEnabled(false);
            ui->label_2->setVisible(false);
            ui->addressEdit->setEnabled(false);
            ui->addressEdit->setVisible(false);
            ui->qaicheckbutton->setEnabled(true);
            ui->qaicheckbutton->setVisible(true);
            ui->ethcheckbutton->setEnabled(true);
            ui->ethcheckbutton->setVisible(true);
            break;
        case NewSendingAddress:
            setWindowTitle(tr("New sending address"));
            ui->label->setEnabled(true);
            ui->label->setVisible(true);
            ui->labelEdit->setEnabled(true);
            ui->labelEdit->setVisible(true);
            ui->label_2->setEnabled(true);
            ui->label_2->setVisible(true);
            ui->addressEdit->setEnabled(true);
            ui->addressEdit->setVisible(true);
            ui->qaicheckbutton->setEnabled(false);
            ui->qaicheckbutton->setVisible(false);
            ui->ethcheckbutton->setEnabled(false);
            ui->ethcheckbutton->setVisible(false);
            break;
        case EditReceivingAddress:
            setWindowTitle(tr("Edit receiving address"));
            ui->label->setEnabled(true);
            ui->label->setVisible(true);
            ui->labelEdit->setEnabled(true);
            ui->labelEdit->setVisible(true);
            ui->label_2->setEnabled(false);
            ui->label_2->setVisible(false);
            ui->addressEdit->setEnabled(false);
            ui->addressEdit->setVisible(false);
            ui->qaicheckbutton->setEnabled(false);
            ui->qaicheckbutton->setVisible(false);
            ui->ethcheckbutton->setEnabled(false);
            ui->ethcheckbutton->setVisible(false);
            break;
        case EditSendingAddress:
            setWindowTitle(tr("Edit sending address"));
            ui->label->setEnabled(true);
            ui->label->setVisible(true);
            ui->labelEdit->setEnabled(true);
            ui->labelEdit->setVisible(true);
            ui->label_2->setEnabled(true);
            ui->label_2->setVisible(true);
            ui->addressEdit->setEnabled(true);
            ui->addressEdit->setVisible(true);
            ui->qaicheckbutton->setEnabled(false);
            ui->qaicheckbutton->setVisible(false);
            ui->ethcheckbutton->setEnabled(false);
            ui->ethcheckbutton->setVisible(false);
            break;
        }

        mapper = new QDataWidgetMapper(this);
        mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);

    } catch (const std::bad_alloc &) {
        throw qt_error("EditAddressDialog Failed to allocate memory.", this);
    }
}

EditAddressDialog::~EditAddressDialog()
{
    delete ui;
}

void EditAddressDialog::setModel(AddressTableModel *model)
{
    this->model = model;
    if(! model) {
        return;
    }

    mapper->setModel(model);
    mapper->addMapping(ui->labelEdit, AddressTableModel::Label);
    mapper->addMapping(ui->addressEdit, AddressTableModel::Address);
}

void EditAddressDialog::loadRow(int row)
{
    mapper->setCurrentIndex(row);
}

bool EditAddressDialog::saveCurrentRow()
{
    if(! model) {
        return false;
    }

    if(ui->ethcheckbutton->isChecked() && ui->qaicheckbutton->isChecked()) {
        QMessageBox::warning(this, windowTitle(),
            tr("It cannot choose both. Please make only one selection."),
            QMessageBox::Ok, QMessageBox::Ok);
        return false;
    }

    switch(mode)
    {
    case NewReceivingAddress:
    case NewSendingAddress:
        try {
            if(ui->ethcheckbutton->isChecked()) {
                json_spirit::Array obj;
                obj.push_back(ui->labelEdit->text().toStdString());
                CRPCTable::getnewethaddress(obj, false);
                return true;
            } else if(ui->qaicheckbutton->isChecked()) {
                json_spirit::Array obj;
                obj.push_back(ui->labelEdit->text().toStdString());
                CRPCTable::getnewqaiaddress(obj, false);
                return true;
            }
        } catch (const json_spirit::Object &s) {
            QMessageBox::warning(this, windowTitle(),
                tr(s.at(1).value_.get_str().c_str()),
                QMessageBox::Ok, QMessageBox::Ok);
            return false;
        } catch (const std::exception &) {
            return false;
        }

        address = model->addRow(
                mode == NewSendingAddress ? AddressTableModel::Send : AddressTableModel::Receive,
                ui->labelEdit->text(),
                ui->addressEdit->text());
        break;
    case EditReceivingAddress:
    case EditSendingAddress:
        if(mapper->submit()) {
            address = ui->addressEdit->text();
        }
        break;
    }
    return !address.isEmpty();
}

void EditAddressDialog::accept()
{
    if(! model) {
        return;
    }

    if(! saveCurrentRow()) {
        switch(model->getEditStatus())
        {
        case AddressTableModel::OK:
            // Failed with unknown reason. Just reject.
            break;
        case AddressTableModel::NO_CHANGES:
            // No changes were made during edit operation. Just reject.
            break;
        case AddressTableModel::INVALID_ADDRESS:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered address \"%1\" is not a valid SorachanCoin address.").arg(ui->addressEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case AddressTableModel::DUPLICATE_ADDRESS:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered address \"%1\" is already in the address book.").arg(ui->addressEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case AddressTableModel::WALLET_UNLOCK_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("Could not unlock wallet."),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case AddressTableModel::KEY_GENERATION_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("New key generation failed."),
                QMessageBox::Ok, QMessageBox::Ok);
            break;

        }
        return;
    }
    QDialog::accept();
}

QString EditAddressDialog::getAddress() const
{
    return address;
}

void EditAddressDialog::setAddress(const QString &address)
{
    this->address = address;
    ui->addressEdit->setText(address);
}
