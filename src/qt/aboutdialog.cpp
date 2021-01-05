// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/aboutdialog.h>
#include <ui_aboutdialog.h>
#include <qt/dialogwindowflags.h>
#include <qt/clientmodel.h>
#include <version.h>
#include <QKeyEvent>
#include <allocator/qtsecure.h>

AboutDialog::AboutDialog(QWidget *parent/*=0*/) : QWidget(parent, DIALOGWINDOWHINTS), ui(new(std::nothrow) Ui::AboutDialog) {
    if(! ui) throw qt_error(std::string("AboutDialog: ui, out of memory"), this);
    ui->setupUi(this);
}

void AboutDialog::setModel(ClientModel *model) {
    if(model) {
        ui->versionLabel->setText(model->formatFullVersion());
    }
}

AboutDialog::~AboutDialog() {
    delete ui;
}

void AboutDialog::on_buttonBox_accepted() {
    close();
}

void AboutDialog::keyPressEvent(QKeyEvent *event) {
#ifdef ANDROID
    if(event->key() == Qt::Key_Back) {
        close();
    }
#else
    if(event->key() == Qt::Key_Escape) {
        close();
    }
#endif
}
