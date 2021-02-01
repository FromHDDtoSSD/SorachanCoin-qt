// Copyright (c) 2011-2013 The Bitcoin developers
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PEERS_WIDGET_H
#define PEERS_WIDGET_H

#include <qt/rpcconsole.h>

class PeersWidget : public QObject
{
    Q_OBJECT
public slots:
    void update();
signals:
    void newnode(bool ban, const QString &name, bool html);
};

#endif // PEERS_WIDGET_H
