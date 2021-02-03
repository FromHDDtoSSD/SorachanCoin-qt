// Copyright (c) 2011-2013 The Bitcoin developers
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/syncwait.h>
#include <allocator/qtsecure.h>

#include "ui_syncview.h"

SyncWidget::SyncWidget(QWidget *parent) : ui(new(std::nothrow) Ui::SyncWidget) {
    if(! ui)
        throw qt_error("SyncWidget out of memory.", this);


}
