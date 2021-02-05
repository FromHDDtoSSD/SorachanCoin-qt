// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/autocheckpoints.h>
#include <allocator/qtsecure.h>

#include "ui_autocheckpoints.h"

AutocheckpointsWidget::AutocheckpointsWidget(QWidget *parent) :
    QWidget(parent),
    ui(new (std::nothrow) Ui::AutocheckpointsWidget) {
    if(! ui)
        throw qt_error("AutocheckpointsWidget out of memory.", this);
    ui->setupUi(this);


}

// slot (callback: bitcoingui mainwindow: autocheckpoints tab clicked)
void AutocheckpointsWidget::exportClicked() {

}
