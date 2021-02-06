// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_AUTOCHECKPOINTSMODEL_H
#define SORACHANCOIN_AUTOCHECKPOINTSMODEL_H

#include <QObject>
#include <checkpoints.h>
#include <prime/autocheckpoint.h>

class OptionsModel;
class QTimer;

class CheckpointsModel : public QObject {
    Q_OBJECT
public:
    explicit CheckpointsModel(OptionsModel *options);
    ~CheckpointsModel();

private slots:
    void update();

signals:
    void CheckpointsHardcode(const MapCheckpoints &hardcode);
    void CheckpointsAuto(const MapCheckpoints &hardcode);

private:
    OptionsModel *options;
    QTimer *timer;
    const MapCheckpoints &hardcode;
};

#endif
