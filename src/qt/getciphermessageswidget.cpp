// Copyright (c) 2018-2024 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/getciphermessageswidget.h>
#include <allocator/qtsecure.h>
#include <util.h>
#include <net.h>
#include <util/tinyformat.h>
#include <sorara/aitx.h>

void CipherWidget::showMessagebox(const std::string &str, QMB::status status) {
    QMB(status).setText(str).exec();
}
