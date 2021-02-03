// Copyright (c) 2011-2013 The Bitcoin developers
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYNCWAIT_H
#define SYNCWAIT_H

#include <QWidget>

namespace Ui {
    class SyncWidget;
}

class SyncWidget : public QWidget
{
    Q_OBJECT
public:
    explicit SyncWidget(QWidget *parent = nullptr);

private:
    Ui::SyncWidget *ui;
};

#endif
