// Copyright (c) 2011-2013 The Bitcoin developers
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/peerswidget.h>
#include <allocator/qtsecure.h>
#include <util.h>
#include <net.h>
#include <util/tinyformat.h>

/////////////////////////////////////////////////////////////////////////
// Bitcoin API
/////////////////////////////////////////////////////////////////////////

static void GetPeersInfo(std::string &dest) {
    std::vector<CNodeStats> vstats;
    [&vstats] {
        vstats.clear();
        LOCK(net_node::cs_vNodes);
        vstats.reserve(net_node::vNodes.size());
        for(CNode *pnode: net_node::vNodes) {
            CNodeStats stats;
            pnode->copyStats(stats);
            vstats.push_back(stats);
        }
    }();

    dest = "";
    for(const CNodeStats &stats: vstats) {
        dest += "<table><tr><td>address: </td><td>";
        dest += stats.addrName;
        dest += "</td></tr><tr><td>";
        dest += "services: </td><td>";
        dest += strprintf("%08" PRIx64, stats.nServices);
        dest += "</td></tr><tr><td>";
        dest += "connection time: </td><td>";
        dest += std::to_string(std::max(stats.nLastRecv-stats.nTimeConnected, stats.nLastSend-stats.nTimeConnected));
        dest += " sec";
        dest += "</td></tr><tr><td>";
        dest += "send bytes: </td><td>";
        dest += std::to_string(stats.nSendBytes);
        dest += " bytes";
        dest += "</td></tr><tr><td>";
        dest += "recv bytes: </td><td>";
        dest += std::to_string(stats.nRecvBytes);
        dest += " bytes";
        dest += "</td></tr><tr><td>";
        dest += "version: </td><td>";
        dest += std::to_string(stats.nVersion);
        dest += "</td></tr><tr><td>";
        dest += "subversion: </td><td>";
        dest += stats.strSubVer;
        dest += "</td></tr><tr><td>";
        dest += "in/out: </td><td>";
        dest += (stats.fInbound ? "IN": "OUT");
        dest += "</td></tr></table>";
        dest += "<br />";
    }
}

/////////////////////////////////////////////////////////////////////////
// Qt
/////////////////////////////////////////////////////////////////////////

void PeersWidget::update() {
    std::string result;
    GetPeersInfo(result);
    emit newnode(false, QString(result.c_str()), true);
}

void RPCConsole::on_updatePushButton_clicked() {}
