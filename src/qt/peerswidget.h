// Copyright (c) 2011-2013 The Bitcoin developers
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PEERS_WIDGET_H
#define PEERS_WIDGET_H

#include <QWidget>
#include <QQueue>

class ClientModel;

QT_BEGIN_NAMESPACE
class QPaintEvent;
class QTimer;
QT_END_NAMESPACE

class PeersWidget : public QWidget
{
    Q_OBJECT
private:
    PeersWidget(const PeersWidget &)=delete;
    PeersWidget &operator=(const PeersWidget &)=delete;
    PeersWidget(PeersWidget &&)=delete;
    PeersWidget &operator=(PeersWidget &&)=delete;
public:
    explicit PeersWidget(QWidget *parent = nullptr);
    void setClientModel(ClientModel *model);

public slots:
    void update();
    void ban();

private:
    QTimer *timer;
    ClientModel *clientModel;
};

#endif // PEERS_WIDGET_H
