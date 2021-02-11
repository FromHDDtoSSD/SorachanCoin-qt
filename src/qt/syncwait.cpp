// Copyright (c) 2011-2013 The Bitcoin developers
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/syncwait.h>
#include <allocator/qtsecure.h>
#include <util/time.h>
#include <QThread>
#include <qt/clientmodel.h>
#include "ui_syncview.h"

namespace {
struct sync_info {
    int64_t ctime;
    int cblockHeight;
    sync_info() {
        ctime = 0;
        cblockHeight = 0;
    }
    bool enbaled() const {
        return ctime != 0 && cblockHeight != 0;
    }
};
} // namespace

static bool fcompsync = false;

SyncWidget::SyncWidget(QWidget *parent) :
    QWidget(parent),
    ui(new(std::nothrow) Ui::SyncWidget) {
    if(! ui)
        throw qt_error("SyncWidget out of memory.", this);

    ui->setupUi(this);

    QFont font1 = QApplication::font();
    font1.setPointSize(font1.pointSize() * 3.5);
    font1.setBold(true);
    QFont font2 = QApplication::font();
    font2.setPointSize(font2.pointSize() * 2.5);
    font2.setBold(true);
    QFont font3 = QApplication::font();
    font3.setPointSize(font3.pointSize() * 1.5);
    font3.setBold(false);
    ui->labelExplain->setFont(font3);
    ui->labelStatus->setFont(font1);
    ui->labelRemain->setFont(font2);

    ui->labelExplain->setText(tr("Blockchain can't acquire the exact balance until the sync is complete.\n"
                                 "Therefore, please wait for a while until the synchronization is completed."));
    ui->progressbarSync->setValue(0);
    ui->labelStatus->setText(tr("---"));
    ui->labelRemain->setText(tr("---"));
}

SyncWidget::~SyncWidget() {
    delete ui;
}

void SyncWidget::setClientModel(ClientModel *clientModel) {
    this->clientModel = clientModel;
    connect(clientModel, SIGNAL(numBlocksChanged(int,int)), this, SLOT(progress(int,int)));
}

// slot (callback: clientModel numBlocksChanged)
void SyncWidget::progress(int count, int nTotalBlocks) {
    static sync_info gblock_info;
    if(!clientModel || clientModel->getNumConnections()==0) {
        ui->progressbarSync->setValue(0);
        ui->labelStatus->setText(tr("---"));
        ui->labelRemain->setText(tr("---"));
        return;
    }

    ui->progressbarSync->setMaximum(nTotalBlocks);
    ui->progressbarSync->setValue(count);
    if(gblock_info.enbaled()) {
        int prog = count - gblock_info.cblockHeight;
        int nRemainingBlocks = nTotalBlocks-count;
        if(0 < nRemainingBlocks) {
            int64_t time = util::GetTimeMillis() - gblock_info.ctime;
            int64_t remain = (double)nRemainingBlocks/prog * time / 1000;
            int hours = remain/3600;
            int minutes = (remain-hours*3600)/60;
            int sec = remain-hours*3600-minutes*60;
            if(clientModel->inInitialBlockDownload() && nTotalBlocks!=count) {
                ui->labelStatus->setVisible(true);
                ui->labelRemain->setVisible(true);
                ui->labelStatus->setText(tr("Synchronizing ..."));
                if(remain>0) {
                    ui->progressbarSync->setVisible(true);
                    ui->labelRemain->setText(QString(tr("until sync: %1 hours %2 min %3 sec ...")).arg(hours,2,10,QChar('0')).arg(minutes,2,10,QChar('0')).arg(sec,2,10,QChar('0')));
                } else {
                    ui->progressbarSync->setVisible(false);
                    ui->labelRemain->setText(QString(tr("---")));
                }
            }
        } else {
            if(fcompsync==false)
                emit gotoSyncToOverview(); // sync is complete.
            fcompsync = true;
        }
    }

    gblock_info.ctime = util::GetTimeMillis();
    gblock_info.cblockHeight = count;
}

// slot (callback: bitcoingui)
void SyncWidget::exportClicked() {}
