// Copyright (c) 2018-2024 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GETCIPHER_WIDGET_H
#define GETCIPHER_WIDGET_H

#include <qt/rpcconsole.h>
#include <ui_interface.h>

class CipherWidget : public QObject
{
    Q_OBJECT
public slots:
    void showMessagebox(const std::string &str, QMB::status status);
};

#endif // GETCIPHER_WIDGET_H
