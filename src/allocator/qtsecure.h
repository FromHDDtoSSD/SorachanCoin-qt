// Copyright (c) 2018-2026 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QT_SECURE_H
#define QT_SECURE_H

#include <sync/lsync.h>
#include <map>
#include <QString>
#include <QDialog>
#include <QMessageBox>

// throw Qt Error
class qt_error : public std::runtime_error {
public:
    explicit qt_error(const std::string &err, QWidget *widget) : runtime_error(err) {
        if(widget)
            QMessageBox::critical(widget, QDialog::tr("Qt Error: critical"), QDialog::tr(err.c_str()));
    }
};

#endif
