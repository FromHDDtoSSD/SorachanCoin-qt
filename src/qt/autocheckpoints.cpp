// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/autocheckpoints.h>
#include <allocator/qtsecure.h>
#include <QStandardItemModel>

#include "ui_autocheckpoints.h"

class QStandardItem2 : public QStandardItem {
public:
    QStandardItem2() : QStandardItem() {}
    QStandardItem2 *setText(const QString &str) {((QStandardItem *const)this)->setText(str); return this;}
    QStandardItem2 *setEditable(bool flag) {((QStandardItem *const)this)->setEditable(flag); return this;}
};

AutocheckpointsWidget::AutocheckpointsWidget(QWidget *parent) :
    QWidget(parent), ui(nullptr) {
    try {
        ui = new Ui::AutocheckpointsWidget;
        model1 = new QStandardItemModel;
        model2 = new QStandardItemModel;
        ui->setupUi(this);
        ui->listviewHardcode->setModel(model1);
        ui->listviewAutocheck->setModel(model2);
    } catch (const std::bad_alloc &) {
        throw qt_error("AutocheckpointsWidget out of memory.", this);
    }
}

AutocheckpointsWidget::~AutocheckpointsWidget() {
    delete model1;
    delete model2;
    delete ui;
}

void AutocheckpointsWidget::setCheckpointsModel(CheckpointsModel *checkpointsModel) {
    assert(checkpointsModel!=nullptr);
    this->checkpointsModel = checkpointsModel;
    connect(this->checkpointsModel, SIGNAL(CheckpointsHardcode(const MapCheckpoints)), this, SLOT(update1(const MapCheckpoints)));
    connect(this->checkpointsModel, SIGNAL(CheckpointsAuto(const MapCheckpoints)), this, SLOT(update2(const MapCheckpoints)));
}

// slot (callback: AutocheckpointsModel: CheckpointsHardcode)
void AutocheckpointsWidget::update1(const MapCheckpoints &hardcode) {
    model1->clear();
    model1->setColumnCount(2);
    ui->listviewHardcode->setColumnWidth(0, 80);
    ui->listviewHardcode->setColumnWidth(1, 550);
    model1->setHorizontalHeaderItem(0, (new QStandardItem2)->setText("block"));
    model1->setHorizontalHeaderItem(1, (new QStandardItem2)->setText("Checkpoint"));

    QStringList liststr1, liststr2;
    for(const auto &ref: hardcode) {
        liststr1 << QString(std::to_string(ref.first).c_str());
        liststr2 << QString("0x") + QString(ref.second.ToString().c_str());
    }
    try {
        int n = 0;
        for(const QString &str: liststr1) {
            model1->setItem(n, 0, (new QStandardItem2)->setText(str)->setEditable(false));
            model1->setItem(n, 1, (new QStandardItem2)->setText(liststr2[n])->setEditable(false));
            ++n;
        }
    } catch (const std::bad_alloc &) {
        throw qt_error("AutocheckpointsWidget out of memory.", this);
    }
}

// slot (callback: AutocheckpointsModel: CheckpointsAuto)
void AutocheckpointsWidget::update2(const MapCheckpoints &hardcode) {

}

// slot (callback: bitcoingui mainwindow: autocheckpoints tab clicked)
void AutocheckpointsWidget::exportClicked() {}
