// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORARA_DRIVEMODEL_H
#define SORARA_DRIVEMODEL_H

#include <QObject>

class DriveModel : public QObject
{
    Q_OBJECT
public:
    explicit DriveModel(const QObject *parent=nullptr);

private:

};

#endif
