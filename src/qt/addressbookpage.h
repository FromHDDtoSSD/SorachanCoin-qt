// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ADDRESSBOOKPAGE_H
#define ADDRESSBOOKPAGE_H

#include <QDialog>

namespace Ui {
    class AddressBookPage;
}

class AddressTableModel;
class OptionsModel;

QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
QT_END_NAMESPACE

//
// Widget that shows a list of sending or receiving addresses.
//
class AddressBookPage : public QDialog
{
    Q_OBJECT

private:
    AddressBookPage()=delete;
    AddressBookPage(const AddressBookPage &)=delete;
    AddressBookPage &operator=(const AddressBookPage &)=delete;
    AddressBookPage(AddressBookPage &&)=delete;
    AddressBookPage &operator=(const AddressBookPage &&)=delete;

public:
    enum Tabs
    {
        SendingTab = 0,
        ReceivingTab = 1
    };

    enum Mode
    {
        ForSending, /**< Open address book to pick address for sending */
        ForEditing  /**< Open address book for editing */
    };

    explicit AddressBookPage(Mode mode, Tabs tab, QWidget *parent = nullptr);
    ~AddressBookPage();

    void setModel(AddressTableModel *model);
    void setOptionsModel(OptionsModel *optionsModelIn);
    const QString &getReturnValue() const { return returnValue; }

public slots:
    void done(int retval);
    void exportClicked();

private:
    Ui::AddressBookPage *ui;
    AddressTableModel *model;
    OptionsModel *optionsModel;
    Mode mode;
    Tabs tab;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *deleteAction;
    QString newAddressToSelect;

private slots:
    void on_deleteButton_clicked();
    void on_newAddressButton_clicked();

    /** Copy address of currently selected address entry to clipboard */
    void on_copyToClipboard_clicked();
    void on_signMessage_clicked();
    void on_verifyMessage_clicked();
    void selectionChanged();
    void on_showQRCode_clicked();

    /** Spawn contextual menu (right mouse menu) for address book entry */
    void contextualMenu(const QPoint &point);

    /** Copy label of currently selected address entry to clipboard */
    void onCopyLabelAction();

    /** Edit currently selected address entry */
    void onEditAction();

    /** New entry/entries were added to address table */
    void selectNewAddress(const QModelIndex &parent, int begin, int end);

signals:
    void signMessage(QString addr);
    void verifyMessage(QString addr);
};

#endif // ADDRESSBOOKDIALOG_H
