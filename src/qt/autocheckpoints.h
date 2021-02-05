// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_AUTOCHECKPOINTS_H
#define SORACHANCOIN_AUTOCHECKPOINTS_H

#include <QWidget>

namespace Ui {
    class AutocheckpointsWidget;
}

class AutocheckpointsWidget : public QWidget
{
    Q_OBJECT
public:
    explicit AutocheckpointsWidget(QWidget *parent=nullptr);

public slots:
    void exportClicked();

private:
    Ui::AutocheckpointsWidget *ui;
};

#endif
