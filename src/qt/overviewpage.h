// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OVERVIEWPAGE_H
#define OVERVIEWPAGE_H

#include <QWidget>

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

namespace Ui {
    class OverviewPage;
}
class WalletModel;
class TxViewDelegate;
class TransactionFilterProxy;

/** Overview ("home") page widget */
class OverviewPage : public QWidget
{
    Q_OBJECT
private:
    OverviewPage(const OverviewPage &)=delete;
    OverviewPage &operator=(const OverviewPage &)=delete;
    OverviewPage(OverviewPage &&)=delete;
    OverviewPage &operator=(OverviewPage &&)=delete;
public:
    explicit OverviewPage(QWidget *parent = nullptr);
    ~OverviewPage();

    void setModel(WalletModel *model);
    void showOutOfSyncWarning(bool fShow);

public slots:
    void setBalance(qint64 total, qint64 watchOnly, qint64 stake, qint64 unconfirmedBalance, qint64 immatureBalance);
    void setNumTransactions(int count);

signals:
    void transactionClicked(const QModelIndex &index);

private:
    Ui::OverviewPage *ui;
    WalletModel *model;
    qint64 currentBalanceTotal;
    qint64 currentBalanceWatchOnly;
    qint64 currentStake;
    qint64 currentUnconfirmedBalance;
    qint64 currentImmatureBalance;

    TxViewDelegate *txdelegate;
    TransactionFilterProxy *filter;

private slots:
    void updateDisplayUnit();
    void handleTransactionClicked(const QModelIndex &index);
    void updateWatchOnlyLabels(bool showWatchOnly);
    void on_BenchmarkCommandLinkButton_clicked();
    void on_DriveVerifyCommandLinkButton_clicked();
    //void on_pushButton_clicked();
    //void on_pushButton_2_clicked();
};

#endif // OVERVIEWPAGE_H
