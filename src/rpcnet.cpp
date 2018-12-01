// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bitcoinrpc.h"
#include "alert.h"
#include "wallet.h"
#include "db.h"
#include "walletdb.h"
#include "net.h"
#include "ntp.h"

json_spirit::Value CRPCTable::getconnectioncount(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 0) {
        throw std::runtime_error(
            "getconnectioncount\n"
            "Returns the number of connections to other nodes.");
    }

    LOCK(net_node::cs_vNodes);
    return (int)net_node::vNodes.size();
}

json_spirit::Value CRPCTable::getaddrmaninfo(const json_spirit::Array &params, bool fHelp)
{
    //
    // Sort function object
    //
    struct addrManItemSort
    {
        bool operator()(const CAddrInfo &leftItem, const CAddrInfo &rightItem) {
            int64_t nTime = bitsystem::GetTime();
            return leftItem.GetChance(nTime) > rightItem.GetChance(nTime);
        }
    };

    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "getaddrmaninfo [networkType]\n"
            "Returns a dump of addrman data.");
    }

    // Get a full list of "online" address items
    std::vector<CAddrInfo> vAddr = net_node::addrman.GetOnlineAddr();

    // Sort by the GetChance result backwardly
    std::sort(vAddr.begin(), vAddr.end(), addrManItemSort());

    std::string strFilterNetType = "";
    if (params.size() == 1) {
        strFilterNetType = params[0].get_str();
    }

    json_spirit::Array ret;
    BOOST_FOREACH(const CAddrInfo &addr, vAddr)
    {
        if (!addr.IsRoutable() || addr.IsLocal()) {
            continue;
        }

        json_spirit::Object addrManItem;
        addrManItem.push_back(json_spirit::Pair("address", addr.ToString()));

        std::string strNetType;
        switch(addr.GetNetwork())
        {
        case netbase::NET_TOR:
            strNetType = "tor";
            break;
        // case netbase::NET_I2P:
            // strNetType = "i2p";
            // break;
        case netbase::NET_IPV6:
            strNetType = "ipv6";
            break;
        default:
        case netbase::NET_IPV4:
            strNetType = "ipv4";
        }

        if (strFilterNetType.size() != 0 && strNetType != strFilterNetType) {
            continue;
        }

        addrManItem.push_back(json_spirit::Pair("chance", addr.GetChance(bitsystem::GetTime())));
        addrManItem.push_back(json_spirit::Pair("type", strNetType));
        addrManItem.push_back(json_spirit::Pair("time", (int64_t)addr.get_nTime()));

        ret.push_back(addrManItem);
    }

    return ret;
}

json_spirit::Value CRPCTable::getpeerinfo(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 0) {
        throw std::runtime_error(
            "getpeerinfo\n"
            "Returns data about each connected network node.");
    }

    std::vector<CNodeStats> vstats;
    [] (std::vector<CNodeStats> &vstats) {
        vstats.clear();

        LOCK(net_node::cs_vNodes);
        vstats.reserve(net_node::vNodes.size());
        BOOST_FOREACH(CNode *pnode, net_node::vNodes)
        {
            CNodeStats stats;
            pnode->copyStats(stats);
            vstats.push_back(stats);
        }
    } (vstats);
    // CopyNodeStats(vstats);

    json_spirit::Array ret;

    BOOST_FOREACH(const CNodeStats &stats, vstats)
    {
        json_spirit::Object obj;

        obj.push_back(json_spirit::Pair("addr", stats.addrName));
        obj.push_back(json_spirit::Pair("services", strprintf("%08" PRIx64, stats.nServices)));
        obj.push_back(json_spirit::Pair("lastsend", (int64_t)stats.nLastSend));
        obj.push_back(json_spirit::Pair("lastrecv", (int64_t)stats.nLastRecv));
        obj.push_back(json_spirit::Pair("bytessent", (int64_t)stats.nSendBytes));
        obj.push_back(json_spirit::Pair("bytesrecv", (int64_t)stats.nRecvBytes));
        obj.push_back(json_spirit::Pair("conntime", (int64_t)stats.nTimeConnected));
        obj.push_back(json_spirit::Pair("version", stats.nVersion));
        obj.push_back(json_spirit::Pair("subver", stats.strSubVer));
        obj.push_back(json_spirit::Pair("inbound", stats.fInbound));
        obj.push_back(json_spirit::Pair("releasetime", (int64_t)stats.nReleaseTime));
        obj.push_back(json_spirit::Pair("startingheight", stats.nStartingHeight));
        obj.push_back(json_spirit::Pair("banscore", stats.nMisbehavior));
        if (stats.fSyncNode) {
            obj.push_back(json_spirit::Pair("syncnode", true));
        }
        ret.push_back(obj);
    }

    return ret;
}

json_spirit::Value CRPCTable::addnode(const json_spirit::Array &params, bool fHelp)
{
    std::string strCommand;
    if (params.size() == 2) {
        strCommand = params[1].get_str();
    }
    if (fHelp || params.size() != 2 || (strCommand != "onetry" && strCommand != "add" && strCommand != "remove")) {
        throw std::runtime_error(
            "addnode <node> <add|remove|onetry>\n"
            "Attempts add or remove <node> from the addnode list or try a connection to <node> once.");
    }

    std::string strNode = params[0].get_str();

    if (strCommand == "onetry") {
        CAddress addr;
        net_node::OpenNetworkConnection(addr, NULL, strNode.c_str());
        return json_spirit::Value::null;
    }

    LOCK(net_node::cs_vAddedNodes);
    std::vector<std::string>::iterator it = net_node::vAddedNodes.begin();
    for(; it != net_node::vAddedNodes.end(); it++)
    {
        if (strNode == *it) {
            break;
        }
    }

    if (strCommand == "add") {
        if (it != net_node::vAddedNodes.end()) {
            throw bitjson::JSONRPCError(-23, "Error: Node already added");
        }
        net_node::vAddedNodes.push_back(strNode);
    } else if(strCommand == "remove") {
        if (it == net_node::vAddedNodes.end()) {
            throw bitjson::JSONRPCError(-24, "Error: Node has not been added.");
        }
        net_node::vAddedNodes.erase(it);
    }

    return json_spirit::Value::null;
}

json_spirit::Value CRPCTable::getaddednodeinfo(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) {
        throw std::runtime_error(
            "getaddednodeinfo <dns> [node]\n"
            "Returns information about the given added node, or all added nodes\n"
            "(note that onetry addnodes are not listed here)\n"
            "If dns is false, only a list of added nodes will be provided,\n"
            "otherwise connected information will also be available.");
    }

    bool fDns = params[0].get_bool();

    std::list<std::string> laddedNodes(0);
    if (params.size() == 1) {
        LOCK(net_node::cs_vAddedNodes);
        BOOST_FOREACH(std::string &strAddNode, net_node::vAddedNodes)
        {
            laddedNodes.push_back(strAddNode);
        }
    } else {
        std::string strNode = params[1].get_str();
        LOCK(net_node::cs_vAddedNodes);
        BOOST_FOREACH(std::string &strAddNode, net_node::vAddedNodes)
        {
            if (strAddNode == strNode) {
                laddedNodes.push_back(strAddNode);
                break;
            }
        }
        if (laddedNodes.size() == 0) {
            throw bitjson::JSONRPCError(-24, "Error: Node has not been added.");
        }
    }

    if (! fDns) {
        json_spirit::Object ret;
        BOOST_FOREACH(std::string &strAddNode, laddedNodes)
        {
            ret.push_back(json_spirit::Pair("addednode", strAddNode));
        }
        return ret;
    }

    json_spirit::Array ret;

    std::list<std::pair<std::string, std::vector<CService> > > laddedAddreses(0);
    BOOST_FOREACH(std::string &strAddNode, laddedNodes)
    {
        std::vector<CService> vservNode(0);
        if(netbase::manage::Lookup(strAddNode.c_str(), vservNode, net_basis::GetDefaultPort(), netbase::fNameLookup, 0)) {
            laddedAddreses.push_back(make_pair(strAddNode, vservNode));
        } else {
            json_spirit::Object obj;
            obj.push_back(json_spirit::Pair("addednode", strAddNode));
            obj.push_back(json_spirit::Pair("connected", false));
            json_spirit::Array addresses;
            obj.push_back(json_spirit::Pair("addresses", addresses));
        }
    }

    LOCK(net_node::cs_vNodes);
    for (std::list<std::pair<std::string, std::vector<CService> > >::iterator it = laddedAddreses.begin(); it != laddedAddreses.end(); it++)
    {
        json_spirit::Object obj;
        obj.push_back(json_spirit::Pair("addednode", it->first));

        json_spirit::Array addresses;
        bool fConnected = false;
        BOOST_FOREACH(CService &addrNode, it->second)
        {
            bool fFound = false;
            json_spirit::Object node;
            node.push_back(json_spirit::Pair("address", addrNode.ToString()));
            BOOST_FOREACH(CNode *pnode, net_node::vNodes)
            {
                if (pnode->addr == addrNode) {
                    fFound = true;
                    fConnected = true;
                    node.push_back(json_spirit::Pair("connected", pnode->fInbound ? "inbound" : "outbound"));
                    break;
                }
            }
            if (! fFound) {
                node.push_back(json_spirit::Pair("connected", "false"));
            }
            addresses.push_back(node);
        }
        obj.push_back(json_spirit::Pair("connected", fConnected));
        obj.push_back(json_spirit::Pair("addresses", addresses));
        ret.push_back(obj);
    }

    return ret;
}

//
// There is a known deadlock situation with ThreadMessageHandler
// ThreadMessageHandler: holds cs_vSend and acquiring block_process::cs_main in block_process::manage::SendMessages()
// ThreadRPCServer: holds block_process::cs_main and acquiring cs_vSend in alert.RelayTo()/PushMessage()/BeginMessage()
//
json_spirit::Value CRPCTable::sendalert(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() < 6) {
        throw std::runtime_error(
            "sendalert <message> <privatekey> <minver> <maxver> <priority> <id> [cancelupto]\n"
            "<message> is the alert text message\n"
            "<privatekey> is hex string of alert master private key\n"
            "<minver> is the minimum applicable internal client version\n"
            "<maxver> is the maximum applicable internal client version\n"
            "<priority> is integer priority number\n"
            "<id> is the alert id\n"
            "[cancelupto] cancels all alert id's up to this number\n"
            "Returns true or false.");
    }

    CAlert alert;
    CKey key;

    alert.strStatusBar = params[0].get_str();
    alert.nMinVer = params[2].get_int();
    alert.nMaxVer = params[3].get_int();
    alert.nPriority = params[4].get_int();
    alert.nID = params[5].get_int();
    if (params.size() > 6) {
        alert.nCancel = params[6].get_int();
    }

    alert.nVersion = version::PROTOCOL_VERSION;
    alert.nRelayUntil = bitsystem::GetAdjustedTime() + 365 * 24 * 60 * 60;
    alert.nExpiration = bitsystem::GetAdjustedTime() + 365 * 24 * 60 * 60;

    CDataStream sMsg(SER_NETWORK, version::PROTOCOL_VERSION);
    sMsg << (CUnsignedAlert)alert;
    alert.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

    std::vector<unsigned char> vchPrivKey = hex::ParseHex(params[1].get_str());
    key.SetPrivKey(CPrivKey(vchPrivKey.begin(), vchPrivKey.end())); // if key is not correct openssl may crash
    if (! key.Sign(hash_basis::Hash(alert.vchMsg.begin(), alert.vchMsg.end()), alert.vchSig)) {
        throw std::runtime_error("Unable to sign alert, check private key?\n");
    }
    if (! alert.ProcessAlert()) {
        throw std::runtime_error("Failed to process alert.\n");
    }

    // Relay alert
    {
        LOCK(net_node::cs_vNodes);
        BOOST_FOREACH(CNode *pnode, net_node::vNodes)
        {
            alert.RelayTo(pnode);
        }
    }

    json_spirit::Object result;
    result.push_back(json_spirit::Pair("strStatusBar", alert.strStatusBar));
    result.push_back(json_spirit::Pair("nVersion", alert.nVersion));
    result.push_back(json_spirit::Pair("nMinVer", alert.nMinVer));
    result.push_back(json_spirit::Pair("nMaxVer", alert.nMaxVer));
    result.push_back(json_spirit::Pair("nPriority", alert.nPriority));
    result.push_back(json_spirit::Pair("nID", alert.nID));
    if (alert.nCancel > 0) {
        result.push_back(json_spirit::Pair("nCancel", alert.nCancel));
    }

    return result;
}

json_spirit::Value CRPCTable::getnettotals(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 0) {
        throw std::runtime_error(
            "getnettotals\n"
            "Returns information about network traffic, including bytes in, bytes out,\n"
            "and current time.");
    }

    json_spirit::Object obj;
    obj.push_back(json_spirit::Pair("totalbytesrecv", static_cast<uint64_t>(CNode::GetTotalBytesRecv())));
    obj.push_back(json_spirit::Pair("totalbytessent", static_cast<uint64_t>(CNode::GetTotalBytesSent())));
    obj.push_back(json_spirit::Pair("timemillis", static_cast<int64_t>(util::GetTimeMillis())));
    return obj;
}

json_spirit::Value CRPCTable::ntptime(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "ntptime [ntpserver]\n"
            "Returns current time from specific or random NTP server.");
    }

    int64_t nTime;
    if (params.size() > 0) {
        std::string strHostName = params[0].get_str();
        nTime = ntp_ext::NtpGetTime(strHostName);
    } else {
        CNetAddr ip;
        nTime = ntp_ext::NtpGetTime(ip);
    }

    json_spirit::Object obj;
    switch (nTime)
    {
    case -1:
        throw std::runtime_error("Socket initialization error");
    case -2:
        throw std::runtime_error("Switching socket mode to non-blocking failed");
    case -3:
        throw std::runtime_error("Unable to send data");
    case -4:
        throw std::runtime_error("Receive timed out");
    default:
        if (nTime > 0 && nTime != 2085978496) {
            obj.push_back(json_spirit::Pair("epoch", nTime));
            obj.push_back(json_spirit::Pair("time", util::DateTimeStrFormat(nTime)));
        } else {
            throw std::runtime_error("Unexpected response");
        }
    }

    return obj;
}
