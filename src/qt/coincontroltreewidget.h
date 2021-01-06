// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef COINCONTROLTREEWIDGET_H
#define COINCONTROLTREEWIDGET_H

#include <QKeyEvent>
#include <QTreeWidget>

class CoinControlTreeWidget : public QTreeWidget
{
Q_OBJECT
private:
    CoinControlTreeWidget(const CoinControlTreeWidget &)=delete;
    CoinControlTreeWidget &operator=(const CoinControlTreeWidget &)=delete;
    CoinControlTreeWidget(CoinControlTreeWidget &&)=delete;
    CoinControlTreeWidget &operator=(CoinControlTreeWidget &&)=delete;
public:
    explicit CoinControlTreeWidget(QWidget *parent = nullptr);
    
protected:
  virtual void  keyPressEvent(QKeyEvent *event);
};

#endif // COINCONTROLTREEWIDGET_H
