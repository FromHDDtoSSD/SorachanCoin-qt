// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TRANSACTIONDESCDIALOG_H
#define TRANSACTIONDESCDIALOG_H

#include <QWidget>

namespace Ui {
    class TransactionDescDialog;
}
QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Dialog showing transaction details. */
class TransactionDescDialog : public QWidget
{
    Q_OBJECT
private:
    TransactionDescDialog(const TransactionDescDialog &)=delete;
    TransactionDescDialog &operator=(const TransactionDescDialog &)=delete;
    TransactionDescDialog(TransactionDescDialog &&)=delete;
    TransactionDescDialog &operator=(TransactionDescDialog &&)=delete;
protected:
    void keyPressEvent(QKeyEvent *);
    void closeEvent(QCloseEvent *e);

public:
    explicit TransactionDescDialog(const QModelIndex &idx, QWidget *parent = nullptr);
    ~TransactionDescDialog();

private:
    Ui::TransactionDescDialog *ui;

signals:
    void stopExec();
};

#endif // TRANSACTIONDESCDIALOG_H
