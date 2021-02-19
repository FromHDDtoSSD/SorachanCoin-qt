// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <QTimer>
#include <qt/autocheckpointsmodel.h>
#include <qt/optionsmodel.h>
#include <allocator/qtsecure.h>

constexpr int INTERVAL_AUTOCHECKPOINTS_RELOAD = 600 * 1000; // GUI refresh interval time
constexpr int INTERVAL_AUTOCHECKPOINTS_BUILDMAP = 1800 * 1000; // block generate time(180s) * 10
constexpr double TESTNET_INTERVAL_RATIO = 0.01;

CheckpointsModel::CheckpointsModel(OptionsModel *in) :
    options(in),
    hardcode(args_bool::fTestNet ? Checkpoints::manage::getMapCheckpointsTestnet(): Checkpoints::manage::getMapCheckpoints()),
    hardstake(args_bool::fTestNet ? bitkernel::getMapStakeModifierCheckpointsTestnet(): bitkernel::getMapStakeModifierCheckpoints()),
    autocheck(CAutocheckPoint::get_instance().getAutocheckpoints()) {
    timer1 = new (std::nothrow) QTimer(this);
    timer2 = new (std::nothrow) QTimer(this);
    if(!timer1 || !timer2)
        throw qt_error("CheckpointsModel out of memory.", nullptr);
    connect(timer1, SIGNAL(timeout()), this, SLOT(update()));
    timer1->start(INTERVAL_AUTOCHECKPOINTS_RELOAD*(args_bool::fTestNet ? TESTNET_INTERVAL_RATIO: 1));
    connect(timer2, SIGNAL(timeout()), this, SLOT(buildmap()));
    timer2->start(INTERVAL_AUTOCHECKPOINTS_BUILDMAP*(args_bool::fTestNet ? TESTNET_INTERVAL_RATIO: 1));
}

CheckpointsModel::~CheckpointsModel() {
    delete timer1;
    delete timer2;
}

// slot (callback: this timer1)
void CheckpointsModel::update() {
    //emit CheckpointsHardcode(hardcode, hardstake);
    emit CheckpointsAuto(autocheck);
}

// slot (callback: this timer2)
void CheckpointsModel::buildmap() {
    // under development: if CUI, should use std::thread. because no use QTimer. adopt v4 later.
    LLOCK(CAutocheckPoint::get_instance().getcs());
    CAutocheckPoint::get_instance().BuildAutocheckPoints();
    CAutocheckPoint::get_instance().Buildmap();
}
