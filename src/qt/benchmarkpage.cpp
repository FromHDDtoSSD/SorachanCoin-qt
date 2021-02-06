// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/benchmarkpage.h>
#include <allocator/qtsecure.h>

#include "ui_benchmark.h"

BenchmarkWidget::BenchmarkWidget(QWidget *parent) : QWidget(parent), ui(new (std::nothrow) Ui::BenchmarkWidget) {
    if(! ui)
        throw qt_error("BenchmarkWidget out of memory.", this);
    ui->setupUi(this);
}

BenchmarkWidget::~BenchmarkWidget() {
    delete ui;
}
