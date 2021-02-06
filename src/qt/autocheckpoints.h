// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_AUTOCHECKPOINTS_H
#define SORACHANCOIN_AUTOCHECKPOINTS_H

#include <QWidget>
#include <qt/autocheckpointsmodel.h>

namespace Ui {
    class AutocheckpointsWidget;
}
class CheckpointsModel;
class QStandardItemModel;

class AutocheckpointsWidget : public QWidget
{
    Q_OBJECT
public:
    explicit AutocheckpointsWidget(QWidget *parent);
    ~AutocheckpointsWidget();

    void setCheckpointsModel(CheckpointsModel *checkpointsModel);

public slots:
    void update1(const MapCheckpoints &hardcode);
    void update2(const MapCheckpoints &hardcode);
    void exportClicked();

private:
    Ui::AutocheckpointsWidget *ui;
    QStandardItemModel *model1, *model2;
    CheckpointsModel *checkpointsModel;
};

#endif
