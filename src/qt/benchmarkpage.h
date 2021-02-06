// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_BENCHMARKPAGE_H
#define SORACHANCOIN_BENCHMARKPAGE_H

#include <QWidget>

namespace Ui {
    class BenchmarkWidget;
}

class BenchmarkWidget : public QWidget
{
    Q_OBJECT
public:
    BenchmarkWidget(QWidget *parent=nullptr);
    ~BenchmarkWidget();

private:
    Ui::BenchmarkWidget *ui;
};

#endif
