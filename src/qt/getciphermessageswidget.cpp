// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/getciphermessageswidget.h>
#include <allocator/qtsecure.h>
#include <util.h>
#include <net.h>
#include <util/tinyformat.h>
#include <sorara/aitx.h>

static void GetCipherMessages(std::string &dest) {
    std::vector<std::pair<time_t, SecureString>> vdata;
    std::string err;
    if(!ai_cipher::getmessages(168, vdata, err)) {
        dest = err;
        return;
    }

    dest = "";
    for(const auto &d: vdata) {
        dest += "<table><tr><td>time: </td><td>";
        dest += ai_time::get_localtime_format(d.first);
        dest += "</td></tr><tr><td>";
        dest += "message: </td><td>";
        dest += std::string(d.second.c_str());
        dest += "</td></tr></table>";
        dest += "<br />";
    }
}

void GetCipherWidget::update() {
    std::string result;
    GetCipherMessages(result);
    emit getciphermessages(QString(result.c_str()), true);
}
