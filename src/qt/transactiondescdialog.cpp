// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/transactiondescdialog.h>
#include <ui_transactiondescdialog.h>
#include <qt/transactiontablemodel.h>
#include <qt/dialogwindowflags.h>
#include <QModelIndex>
#include <QKeyEvent>
#include <allocator/qtsecure.h>

TransactionDescDialog::TransactionDescDialog(const QModelIndex &idx, QWidget *parent) :
    QWidget(parent, DIALOGWINDOWHINTS),
    ui(new(std::nothrow) Ui::TransactionDescDialog)
{
    if(! ui){
        throw qt_error("TransactionDescDialog Failed to allocate memory.", this);
    }

    ui->setupUi(this);
    QString desc = idx.data(TransactionTableModel::LongDescriptionRole).toString();
    ui->detailText->setHtml(desc);
}

TransactionDescDialog::~TransactionDescDialog()
{
    delete ui;
}

void TransactionDescDialog::keyPressEvent(QKeyEvent *event)
{
#ifdef ANDROID
    if(event->key() == Qt::Key_Back) {
        close();
    }
#else
    if(event->key() == Qt::Key_Escape) {
        close();
    }
#endif
}

void TransactionDescDialog::closeEvent(QCloseEvent *e)
{
    emit(stopExec());
    QWidget::closeEvent(e);
}
