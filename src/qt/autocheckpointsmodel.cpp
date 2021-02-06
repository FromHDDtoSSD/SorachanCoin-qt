// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <QTimer>
#include <qt/autocheckpointsmodel.h>
#include <qt/optionsmodel.h>
#include <allocator/qtsecure.h>

constexpr int INTERVAL_AUTOCHECKPOINTS_RELOAD = 10 * 1000;

CheckpointsModel::CheckpointsModel(OptionsModel *in) :
    options(in),
    hardcode(Checkpoints::manage::getMapCheckpoints()) {
    timer = new (std::nothrow) QTimer(this);
    if(! timer)
        throw qt_error("CheckpointsModel out of memory.", nullptr);
    connect(timer, SIGNAL(timeout()), this, SLOT(update()));
    timer->start(INTERVAL_AUTOCHECKPOINTS_RELOAD);
}

CheckpointsModel::~CheckpointsModel() {
    delete timer;
}

// slot (callback: this timer)
void CheckpointsModel::update() {
    emit CheckpointsHardcode(hardcode);
    emit CheckpointsAuto(hardcode);
}
