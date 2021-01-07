// Copyright (c) 2012-2013 The PPCoin developers
// Copyright (c) 2013-2015 The Novacoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MINTINGVIEW_H
#define MINTINGVIEW_H

#include <QWidget>
#include <QComboBox>
#include <qt/mintingfilterproxy.h>

class WalletModel;

QT_BEGIN_NAMESPACE
class QTableView;
class QMenu;
QT_END_NAMESPACE

class MintingView : public QWidget
{
    Q_OBJECT
private:
    MintingView(const MintingView &)=delete;
    MintingView &operator=(const MintingView &)=delete;
    MintingView(MintingView &&)=delete;
    MintingView &operator=(MintingView &&)=delete;
public:
    explicit MintingView(QWidget *parent = nullptr);
    void setModel(WalletModel *model);

    enum MintingEnum
    {
        Minting10min,
        Minting1day,
        Minting7days,
        Minting30days,
        Minting60days,
        Minting90days
    };

private:
    WalletModel *model;
    QTableView *mintingView;

    QComboBox *mintingCombo;

    MintingFilterProxy *mintingProxyModel;

    QMenu *contextMenu;

signals:

public slots:
    void exportClicked();
    void chooseMintingInterval(int idx);
    void copyTxID();
    void copyAddress();
    void showHideAddress();
    void showHideTxID();
    void contextualMenu(const QPoint &point);
};

#endif // MINTINGVIEW_H
