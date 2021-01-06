// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EDITADDRESSDIALOG_H
#define EDITADDRESSDIALOG_H

#include <QDialog>

QT_BEGIN_NAMESPACE
class QDataWidgetMapper;
QT_END_NAMESPACE

namespace Ui {
    class EditAddressDialog;
}
class AddressTableModel;

/** Dialog for editing an address and associated information.
 */
class EditAddressDialog : public QDialog
{
    Q_OBJECT
private:
    EditAddressDialog(const EditAddressDialog &)=delete;
    EditAddressDialog &operator=(const EditAddressDialog &)=delete;
    EditAddressDialog(EditAddressDialog &&)=delete;
    EditAddressDialog &operator=(EditAddressDialog &&)=delete;
public:
    enum Mode {
        NewReceivingAddress,
        NewSendingAddress,
        EditReceivingAddress,
        EditSendingAddress
    };

    explicit EditAddressDialog(Mode mode, QWidget *parent = nullptr);
    ~EditAddressDialog();

    void setModel(AddressTableModel *model);
    void loadRow(int row);

    QString getAddress() const;
    void setAddress(const QString &address);

public slots:
    void accept();

private:
    bool saveCurrentRow();

    Ui::EditAddressDialog *ui;
    QDataWidgetMapper *mapper;
    Mode mode;
    AddressTableModel *model;

    QString address;
};

#endif // EDITADDRESSDIALOG_H
