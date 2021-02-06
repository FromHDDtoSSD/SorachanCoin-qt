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

AutocheckpointsWidget::~AutocheckpointsWidget() {
    delete ui;
}

void AutocheckpointsWidget::setCheckpointsModel(CheckpointsModel *checkpointsModel) {
    this->checkpointModel = checkpointModel;
    connect(this->checkpointModel, SIGNAL(CheckpointsHardcode(const MapCheckpoints)), this, SLOT(update1(const MapCheckpoints)));
    connect(this->checkpointModel, SIGNAL(CheckpointsAuto(const MapCheckpoints)), this, SLOT(update2(const MapCheckpoints)));
}

// slot (callback: AutocheckpointsModel: CheckpointsHardcode)
void AutocheckpointsWidget::update1(const MapCheckpoints &hardcode) {

}

// slot (callback: AutocheckpointsModel: CheckpointsAuto)
void AutocheckpointsWidget::update2(const MapCheckpoints &hardcode) {

}

// slot (callback: bitcoingui mainwindow: autocheckpoints tab clicked)
void AutocheckpointsWidget::exportClicked() {}
