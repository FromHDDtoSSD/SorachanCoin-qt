// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/autocheckpoints.h>
#include <allocator/qtsecure.h>
#include <QStandardItemModel>
#include <QFont>

#include "ui_autocheckpoints.h"

namespace {
class QStandardItem2 : public QStandardItem {
public:
    QStandardItem2() : QStandardItem() {}
    QStandardItem2 *setText(const QString &str) {((QStandardItem *const)this)->setText(str); return this;}
    QStandardItem2 *setEditable(bool flag) {((QStandardItem *const)this)->setEditable(flag); return this;}
};
} // namespace

AutocheckpointsWidget::AutocheckpointsWidget(QWidget *parent) :
    QWidget(parent), ui(nullptr) {
    try {
        ui = new Ui::AutocheckpointsWidget;
        model1 = new QStandardItemModel;
        model2 = new QStandardItemModel;
        ui->setupUi(this);
        ui->listviewHardcode->setModel(model1);
        ui->listviewAutocheck->setModel(model2);

        QFont font = QApplication::font();
        font.setPointSize(font.pointSize() * 1.3);
        font.setBold(true);
        ui->labelHardcode->setFont(font);
        ui->labelAutocheck->setFont(font);
        ui->labelDiff->setFont(font);

        ui->labelHardcode->setText(tr("Below is a list of Hardcode(static) Checkpoints."));
        ui->labelAutocheck->setText(tr("Below is a list of Automatic(dynamic) Checkpoints."));
        ui->labelDiff->setText(tr("Below is Automatic(dynamic) Checkpoints counter."));
        ui->progAutocheck->setRange(0, CAutocheckPoint::GetCheckBlocks());
        ui->progAutocheck->setValue(0);
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
    connect(this->checkpointsModel, SIGNAL(CheckpointsHardcode(const MapCheckpoints, const std::map<int, unsigned int>)), this, SLOT(update1(const MapCheckpoints, const std::map<int, unsigned int>)));
    connect(this->checkpointsModel, SIGNAL(CheckpointsAuto(const AutoCheckpoints)), this, SLOT(update2(const AutoCheckpoints)));
    update1(this->checkpointsModel->getHardcode(), this->checkpointsModel->getHardstake());
    update2(this->checkpointsModel->getAutocheckpoints());
}

// slot (callback: AutocheckpointsModel: CheckpointsHardcode)
void AutocheckpointsWidget::update1(const MapCheckpoints &hardcode, const std::map<int, unsigned int> &hardstake) {
    try {
        model1->clear();
        model1->setColumnCount(3);
        ui->listviewHardcode->setColumnWidth(0, 80);
        ui->listviewHardcode->setColumnWidth(1, 50);
        ui->listviewHardcode->setColumnWidth(2, 550);
        model1->setHorizontalHeaderItem(0, (new QStandardItem2)->setText(tr("block")));
        model1->setHorizontalHeaderItem(1, (new QStandardItem2)->setText(tr("type")));
        model1->setHorizontalHeaderItem(2, (new QStandardItem2)->setText(tr("Checkpoint Blockhash or Checksum")));

        QStringList liststr1, liststr2, liststr3;
        for(const auto &ref: hardcode) {
            std::string hash = ref.second.ToString();
            liststr1 << tr(std::to_string(ref.first).c_str());
            liststr2 << (([&hash]{return (hash[0]+hash[1]+hash[2]+hash[3]==0x30*4);}()) ? tr("PoW"): tr("PoS"));
            liststr3 << tr("0x") + tr(hash.c_str());
        }
        for(const auto &ref: hardstake) {
            liststr1 << tr(std::to_string(ref.first).c_str());
            liststr2 << tr("Stake");
            liststr3 << tr("0x") + tr(tfm::format("%x", ref.second).c_str());
        }

        int n = 0;
        for(const QString &str: liststr1) {
            model1->setItem(n, 0, (new QStandardItem2)->setText(str)->setEditable(false));
            model1->setItem(n, 1, (new QStandardItem2)->setText(liststr2[n])->setEditable(false));
            model1->setItem(n, 2, (new QStandardItem2)->setText(liststr3[n])->setEditable(false));
            ++n;
        }
    } catch (const std::bad_alloc &) {
        throw qt_error("AutocheckpointsWidget out of memory.", this);
    }
}

// slot (callback: AutocheckpointsModel: CheckpointsAuto)
void AutocheckpointsWidget::update2(const AutoCheckpoints &autocheck) {
    try {
        model2->clear();
        model2->setColumnCount(3);
        ui->listviewAutocheck->setColumnWidth(0, 80);
        ui->listviewAutocheck->setColumnWidth(1, 100);
        ui->listviewAutocheck->setColumnWidth(2, 500);
        model2->setHorizontalHeaderItem(0, (new QStandardItem2)->setText(tr("block")));
        model2->setHorizontalHeaderItem(1, (new QStandardItem2)->setText(tr("type")));
        model2->setHorizontalHeaderItem(2, (new QStandardItem2)->setText(tr("Checkpoint Blockhash")));

        QStringList liststr1, liststr2, liststr3;
        for(const auto &ref: autocheck) {
            std::string hash = ref.second.hash.ToString();
            liststr1 << tr(std::to_string(ref.first).c_str());
            liststr2 << tr("dynamic cp");
            liststr3 << tr("0x") + tr(hash.c_str());
        }

        int n = 0;
        for(const QString &str: liststr1) {
            model2->setItem(n, 0, (new QStandardItem2)->setText(str)->setEditable(false));
            model2->setItem(n, 1, (new QStandardItem2)->setText(liststr2[n])->setEditable(false));
            model2->setItem(n, 2, (new QStandardItem2)->setText(liststr3[n])->setEditable(false));
            ++n;
        }

        ui->progAutocheck->setValue(n);
    } catch (const std::bad_alloc &) {
        throw qt_error("AutocheckpointsWidget out of memory.", this);
    }
}

// slot (callback: bitcoingui mainwindow: autocheckpoints tab clicked)
void AutocheckpointsWidget::exportClicked() {}
