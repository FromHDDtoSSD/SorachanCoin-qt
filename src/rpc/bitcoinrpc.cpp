// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <init.h>
#include <util.h>
#include <sync/lsync.h>
#include <ui_interface.h>
#include <rpc/bitcoinrpc.h>
#include <db.h>
#include <block/block_process.h>
#include <block/block_alert.h>
#include <list>
#include <random/random.h>
#include <util/thread.h>
#include <boot/shutdown.h>
#include <block/block_process.h>
#include <block/block_alert.h>
#include <util/logging.h>
#include <util/tinyformat.h>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/shared_ptr.hpp>

const CRPCTable CRPCTable::tableRPC;
std::string bitrpc::strRPCUserColonPass;
CCriticalSection bitrpc::cs_THREAD_RPCHANDLER;

unsigned short bitrpc::GetDefaultRPCPort()
{
    return map_arg::GetBoolArg("-testnet", false) ? tcp_port::uJsonRpcTest : tcp_port::uJsonRpcMain;
}

void bitrpc::RPCTypeCheck(const json_spirit::Array &params, const std::list<json_spirit::Value_type> &typesExpected, bool fAllowNull/* =false */)
{
    unsigned int i = 0;
    for(json_spirit::Value_type t: typesExpected)
    {
        if (params.size() <= i) {
            break;
        }

        const json_spirit::Value &v = params[i];
        if (!((v.type() == t) || (fAllowNull && (v.type() == json_spirit::null_type)))) {
            std::string err = tinyformat::format("Expected type %s, got %s", json_spirit::Value_type_name[t], json_spirit::Value_type_name[v.type()]);
            throw bitjson::JSONRPCError(RPC_TYPE_ERROR, err);
        }
        i++;
    }
}

void bitrpc::RPCTypeCheck(const json_spirit::Object &o, const std::map<std::string, json_spirit::Value_type> &typesExpected, bool fAllowNull/* =false */)
{
    for(const std::pair<std::string, json_spirit::Value_type>& t: typesExpected)
    {
        const json_spirit::Value& v = find_value(o, t.first);
        if (!fAllowNull && v.type() == json_spirit::null_type) {
            throw bitjson::JSONRPCError(RPC_TYPE_ERROR, tinyformat::format("Missing %s", t.first.c_str()));
        }

        if (!((v.type() == t.second) || (fAllowNull && (v.type() == json_spirit::null_type)))) {
            std::string err = tinyformat::format("Expected type %s for %s, got %s", json_spirit::Value_type_name[t.second], t.first.c_str(), json_spirit::Value_type_name[v.type()]);
            throw bitjson::JSONRPCError(RPC_TYPE_ERROR, err);
        }
    }
}

int64_t CRPCTable::AmountFromValue(const json_spirit::Value &value)
{
    double dAmount = value.get_real();
    if (dAmount <= 0.0 || dAmount > block_params::MAX_MONEY) {
        throw bitjson::JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    }

    int64_t nAmount = util::roundint64(dAmount * util::COIN);
    if (! block_transaction::manage::MoneyRange(nAmount)) {
        throw bitjson::JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    }

    return nAmount;
}

json_spirit::Value CRPCTable::ValueFromAmount(int64_t amount)
{
    return (double)amount / (double)util::COIN;
}

std::string CRPCTable::HexBits(unsigned int nBits)
{
    union
    {
        int32_t nBits;
        char cBits[4];
    } uBits;

    uBits.nBits = htonl((int32_t)nBits);
    return util::HexStr(BEGIN(uBits.cBits), END(uBits.cBits));
}

// Note: This interface may still be subject to change.
std::string CRPCTable::help(std::string strCommand) const
{
    std::string strRet;
    std::set<rpcfn_type> setDone;
    for (std::map<std::string, const CRPCCommand *>::const_iterator mi = mapCommands.begin(); mi != mapCommands.end(); ++mi)
    {
        const CRPCCommand *pcmd = mi->second;
        std::string strMethod = mi->first;

        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod.find("label") != std::string::npos) {
            continue;
        }
        if (!strCommand.empty() && strMethod != strCommand) {
            continue;
        }

        try {
            json_spirit::Array params;
            rpcfn_type pfn = pcmd->actor;
            if (setDone.insert(pfn).second) {
                (*pfn)(params, true);
            }
        } catch (const std::exception &e) {
            // Help text is returned in an exception
            std::string strHelp = std::string(e.what());
            if (strCommand.empty()) {
                if (strHelp.find('\n') != std::string::npos) {
                    strHelp = strHelp.substr(0, strHelp.find('\n'));
                }
            }
            strRet += strHelp + "\n";
        }
    }

    if (strRet.empty()) {
        strRet = tinyformat::format("help: unknown command: %s\n", strCommand.c_str());
    }

    strRet = strRet.substr(0, strRet.size() - 1);
    return strRet;
}

json_spirit::Value CRPCTable::help(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "help [command]\n"
            "List commands, or get help for a command.");
    }

    std::string strCommand;
    if (params.size() > 0) {
        strCommand = params[0].get_str();
    }
    return CRPCTable::tableRPC.help(strCommand);
}

json_spirit::Value CRPCTable::stop(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            ("stop <detach>\n"
            "<detach> is true or false to detach the database or not for this stop only\n"
            "Stop " + std::string(strCoinName) + " server (and possibly override the detachdb config value).").c_str());
    }

    // Shutdown will take long enough that the response should get back
#ifdef USE_BERKELEYDB
    if (params.size() > 0) {
        CDBEnv::get_instance().SetDetach(params[0].get_bool());
    }
#endif

    boot::StartShutdown();
    return std::string((std::string(strCoinName) + " server stopping").c_str());
}

//
// Call Table
//
const CRPCTable::CRPCCommand CRPCTable::vRPCCommands[108] =
{ //  name                      function                 safemd  unlocked
  //  ------------------------  -----------------------  ------  --------
    { "help",                       &help,                        true,   true },
    { "stop",                       &stop,                        true,   true },
    { "getbestblockhash",           &getbestblockhash,            true,   false },
    { "getblockcount",              &getblockcount,               true,   false },
    { "getconnectioncount",         &getconnectioncount,          true,   false },
    { "getaddrmaninfo",             &getaddrmaninfo,              true,   false },
    { "getpeerinfo",                &getpeerinfo,                 true,   false },
    { "addnode",                    &addnode,                     true,   true  },
    { "getaddednodeinfo",           &getaddednodeinfo,            true,   true  },
    { "getdifficulty",              &getdifficulty,               true,   false },
    { "getinfo",                    &getinfo,                     true,   false },
    { "getsubsidy",                 &getsubsidy,                  true,   false },
    { "getmininginfo",              &getmininginfo,               true,   false },
    { "getnetworkhashps",           &getnetworkhashps,            true,   false },
    { "scaninput",                  &scaninput,                   true,   true },
    { "getnewaddress",              &getnewaddress,               true,   false },
    { "getnewethaddress",           &getnewethaddress,            true,   false },
    { "getnewqaiaddress",           &getnewqaiaddress,            true,   false },
    { "getnewschnorraddress",       &getnewschnorraddress,        true,   false },
    { "getnewcipheraddress",        &getnewcipheraddress,         true,   false },
    { "getmysentmessages",          &getmysentmessages,           true,   false },
    { "getciphermessages",          &getciphermessages,           true,   false },
    //{ "getnewethlock",              &getnewethlock,               true,   false },
    { "getkeyentangle",             &getkeyentangle,              true,   false },
    { "gethdwalletinfo",            &gethdwalletinfo,             true,   false },
    { "getqpubkey",                 &getqpubkey,                  true,   false },
    { "createhdwallet",             &createhdwallet,              true,   false },
    { "restorehdwallet",            &restorehdwallet,             true,   false },
    { "getnettotals",               &getnettotals,                true,   true  },
    { "ntptime",                    &ntptime,                     true,   true  },
    { "getaccountaddress",          &getaccountaddress,           true,   false },
    { "getaccountqaiaddress",       &getaccountqaiaddress,        true,   false },
    { "getaccountschnorraddress",   &getaccountschnorraddress,    true,   false },
    { "setaccount",                 &setaccount,                  true,   false },
    { "getaccount",                 &getaccount,                  false,  false },
    { "getaddressesbyaccount",      &getaddressesbyaccount,       true,   false },
    { "sendtoaddress",              &sendtoaddress,               false,  false },
    { "mergecoins",                 &mergecoins,                  false,  false },
    { "getreceivedbyaddress",       &getreceivedbyaddress,        false,  false },
    { "getreceivedbyaccount",       &getreceivedbyaccount,        false,  false },
    { "listreceivedbyaddress",      &listreceivedbyaddress,       false,  false },
    { "listreceivedbyaccount",      &listreceivedbyaccount,       false,  false },
    { "backupwallet",               &backupwallet,                true,   false },
    { "keypoolrefill",              &keypoolrefill,               true,   false },
    { "keypoolreset",               &keypoolreset,                true,   false },
    { "walletpassphrase",           &walletpassphrase,            true,   false },
    { "walletpassphrasechange",     &walletpassphrasechange,      false,  false },
    { "walletlock",                 &walletlock,                  true,   false },
    { "encryptwallet",              &encryptwallet,               false,  false },
    { "validateaddress",            &validateaddress,             true,   false },
    { "getbalance",                 &getbalance,                  false,  false },
    { "move",                       &movecmd,                     false,  false },
    { "sendfrom",                   &sendfrom,                    false,  false },
    { "sendethfrom",                &sendethfrom,                 false,  false },
    { "sendmany",                   &sendmany,                    false,  false },
    { "addmultisigaddress",         &addmultisigaddress,          false,  false },
    { "addredeemscript",            &addredeemscript,             false,  false },
    { "getrawmempool",              &getrawmempool,               true,   false },
    { "getblock",                   &getblock,                    false,  false },
    { "getblockbynumber",           &getblockbynumber,            false,  false },
    { "dumpblock",                  &dumpblock,                   false,  false },
    { "dumpblockbynumber",          &dumpblockbynumber,           false,  false },
    { "getblockhash",               &getblockhash,                false,  false },
    { "gettransaction",             &gettransaction,              false,  false },
    { "listtransactions",           &listtransactions,            false,  false },
    { "listaddressgroupings",       &listaddressgroupings,        false,  false },
    { "signmessage",                &signmessage,                 false,  false },
    { "verifymessage",              &verifymessage,               false,  false },
    { "getwork",                    &getwork,                     true,   false },
    { "getworkex",                  &getworkex,                   true,   false },
    { "listaccounts",               &listaccounts,                false,  false },
    { "settxfee",                   &settxfee,                    false,  false },
    { "getblocktemplate",           &getblocktemplate,            true,   false },
    { "submitblock",                &submitblock,                 false,  false },
    { "listsinceblock",             &listsinceblock,              false,  false },
    { "dumpprivkey",                &dumpprivkey,                 false,  false },
    { "dumppem",                    &dumppem,                     true,   false },
    { "dumpwallet",                 &dumpwallet,                  true,   false },
    { "importwallet",               &importwallet,                false,  false },
    { "importprivkey",              &importprivkey,               false,  false },
    { "importprivethkey",           &importprivethkey,            false,  false },
    { "importaddress",              &importaddress,               false,  true  },
    { "removeaddress",              &removeaddress,               false,  true  },
    { "listunspent",                &listunspent,                 false,  false },
    { "getrawtransaction",          &getrawtransaction,           false,  false },
    { "createrawtransaction",       &createrawtransaction,        false,  false },
    { "decoderawtransaction",       &decoderawtransaction,        false,  false },
    { "createmultisig",             &createmultisig,              false,  false },
    { "decodescript",               &decodescript,                false,  false },
    { "signrawtransaction",         &signrawtransaction,          false,  false },
    { "sendrawtransaction",         &sendrawtransaction,          false,  false },
    { "getcheckpoint",              &getcheckpoint,               true,   false },
    { "reservebalance",             &reservebalance,              false,  true},
    { "checkwallet",                &checkwallet,                 false,  true},
    { "repairwallet",               &repairwallet,                false,  true},
    { "resendtx",                   &resendtx,                    false,  true},
    { "resendwallettransactions",   &resendwallettransactions,    false,  true},
    { "makekeypair",                &makekeypair,                 false,  true},
    { "newmalleablekey",            &newmalleablekey,             false,  false},
    { "adjustmalleablekey",         &adjustmalleablekey,          false,  false},
    { "adjustmalleablepubkey",      &adjustmalleablepubkey,       false,  false},
    { "listmalleableviews",         &listmalleableviews,          false,  false},
    { "dumpmalleablekey",           &dumpmalleablekey,            false,  false},
    { "importmalleablekey",         &importmalleablekey,          true,   false },
    { "encryptdata",                &encryptdata,                 false,  false },
    { "decryptdata",                &decryptdata,                 false,  false },
    { "encryptmessage",             &encryptmessage,              false,  false },
    { "decryptmessage",             &decryptmessage,              false,  false },
    { "sendalert",                  &sendalert,                   false,  false},
};

CRPCTable::CRPCTable()
{
    for (unsigned int vcidx = 0; vcidx < (sizeof(vRPCCommands) / sizeof(vRPCCommands[0])); ++vcidx)
    {
        const CRPCCommand *pcmd = &vRPCCommands[vcidx];
        //logging::LogPrintf("CRPCTable name %s addr %p\n", pcmd->name, pcmd);
        mapCommands[pcmd->name] = pcmd;
    }
}

const CRPCTable::CRPCCommand *CRPCTable::operator[](std::string name) const
{
    std::map<std::string, const CRPCCommand *>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end()) {
        return nullptr;
    }
    return (*it).second;
}

//
// HTTP protocol
//
// This ain't Apache.  We're just using HTTP header for the length field and to be compatible with other JSON-RPC implementations.
//
std::string http::HTTPPost(const std::string &strMsg, const std::map<std::string, std::string> &mapRequestHeaders)
{
    std::ostringstream s;
    s << "POST / HTTP/1.1\r\n"
      << "User-Agent: "
      << strCoinName
      << "-json-rpc/" << format_version::FormatFullVersion() << "\r\n"
      << "Host: 127.0.0.1\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << strMsg.size() << "\r\n"
      << "Connection: close\r\n"
      << "Accept: application/json\r\n";

    for(const std::pair<std::string, std::string>&item: mapRequestHeaders)
    {
        s << item.first << ": " << item.second << "\r\n";
    }
    s << "\r\n" << strMsg;

    return s.str();
}

std::string http::HTTPReply(int nStatus, const std::string &strMsg, bool keepalive)
{
    if (nStatus == HTTP_UNAUTHORIZED) {
        return tinyformat::format(
            "HTTP/1.0 401 Authorization Required\r\n"
            "Date: %s\r\n"
            "Server: %s-json-rpc/%s\r\n"
            "WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 296\r\n"
            "\r\n"
            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\r\n"
            "\"http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd\">\r\n"
            "<HTML>\r\n"
            "<HEAD>\r\n"
            "<TITLE>Error</TITLE>\r\n"
            "<META HTTP-EQUIV='Content-Type' CONTENT='text/html; charset=ISO-8859-1'>\r\n"
            "</HEAD>\r\n"
            "<BODY><H1>401 Unauthorized.</H1></BODY>\r\n"
            "</HTML>\r\n", bitjson::rfc1123Time().c_str(), strCoinName, format_version::FormatFullVersion().c_str());
    }

    const char *cStatus = "";
    if (nStatus == HTTP_OK) { cStatus = "OK"; }
    else if (nStatus == HTTP_BAD_REQUEST) { cStatus = "Bad Request"; }
    else if (nStatus == HTTP_FORBIDDEN) { cStatus = "Forbidden"; }
    else if (nStatus == HTTP_NOT_FOUND) { cStatus = "Not Found"; }
    else if (nStatus == HTTP_INTERNAL_SERVER_ERROR) { cStatus = "Internal Server Error"; }
    else { cStatus = ""; }

    return tinyformat::format(
            "HTTP/1.1 %d %s\r\n"
            "Date: %s\r\n"
            "Connection: %s\r\n"
            "Content-Length: %" PRIszu "\r\n"
            "Content-Type: application/json\r\n"
            "Server: %s-json-rpc/%s\r\n"
            "\r\n"
            "%s",
            nStatus,
            cStatus,
            bitjson::rfc1123Time().c_str(),
            keepalive ? "keep-alive" : "close",
            strMsg.size(),
            strCoinName,
            format_version::FormatFullVersion().c_str(),
            strMsg.c_str());
}

int http::ReadHTTPStatus(std::basic_istream<char> &stream, int &proto)
{
    std::string str;
    std::getline(stream, str);

    std::vector<std::string> vWords;
    std::istringstream iss(str);
    std::copy(std::istream_iterator<std::string>(iss), std::istream_iterator<std::string>(), std::back_inserter(vWords));
    if (vWords.size() < 2) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    proto = 0;
    const char *ver = ::strstr(str.c_str(), "HTTP/1.");
    if (ver != nullptr) {
        proto = atoi(ver + 7);
    }

    return ::atoi(vWords[1].c_str());
}

int http::ReadHTTPHeader(std::basic_istream<char> &stream, std::map<std::string, std::string> &mapHeadersRet)
{
    int nLen = 0;
    for ( ; ; )
    {
        std::string str;
        std::getline(stream, str);
        if (str.empty() || str == "\r") {
            break;
        }

        std::string::size_type nColon = str.find(":");
        if (nColon != std::string::npos) {
            std::string strHeader = str.substr(0, nColon);
            boost::trim(strHeader);
            boost::to_lower(strHeader);
            std::string strValue = str.substr(nColon+1);
            boost::trim(strValue);
            mapHeadersRet[strHeader] = strValue;
            if (strHeader == "content-length") {
                nLen = atoi(strValue.c_str());
            }
        }
    }
    return nLen;
}

int http::ReadHTTP(std::basic_istream<char> &stream, std::map<std::string, std::string> &mapHeadersRet, std::string &strMessageRet)
{
    mapHeadersRet.clear();
    strMessageRet.clear();

    // Read status
    int nProto = 0;
    int nStatus = http::ReadHTTPStatus(stream, nProto);

    // Read header
    int nLen = http::ReadHTTPHeader(stream, mapHeadersRet);
    if (nLen < 0 || nLen > (int)compact_size::MAX_SIZE) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    // Read message
    if (nLen > 0) {
        std::vector<char> vch(nLen);
        stream.read(&vch[0], nLen);
        strMessageRet = std::string(vch.begin(), vch.end());
    }

    std::string sConHdr = mapHeadersRet["connection"];

    if ((sConHdr != "close") && (sConHdr != "keep-alive")) {
        if (nProto >= 1) {
            mapHeadersRet["connection"] = "keep-alive";
        } else {
            mapHeadersRet["connection"] = "close";
        }
    }

    return nStatus;
}

bool bitrpc::HTTPAuthorized(std::map<std::string, std::string> &mapHeaders)
{
    std::string strAuth = mapHeaders["authorization"];
    if (strAuth.substr(0,6) != "Basic ") {
        return false;
    }

    std::string strUserPass64 = strAuth.substr(6); boost::trim(strUserPass64);
    std::string strUserPass = strenc::DecodeBase64(strUserPass64);
    return map_arg::TimingResistantEqual(strUserPass, strRPCUserColonPass);
}

//
// JSON-RPC protocol.  Bitcoin speaks version 1.0 for maximum compatibility,
// but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
// unspecified (HTTP errors and contents of 'error').
//
// 1.0 spec: http://json-rpc.org/wiki/specification
// 1.2 spec: http://groups.google.com/group/json-rpc/web/json-rpc-over-http
// http://www.codeproject.com/KB/recipes/JSON_Spirit.aspx
//
std::string json::JSONRPCRequest(const std::string &strMethod, const json_spirit::Array &params, const json_spirit::Value &id)
{
    json_spirit::Object request;
    request.push_back(json_spirit::Pair("method", strMethod));
    request.push_back(json_spirit::Pair("params", params));
    request.push_back(json_spirit::Pair("id", id));
    return json_spirit::write_string(json_spirit::Value(request), false) + "\n";
}

json_spirit::Object json::JSONRPCReplyObj(const json_spirit::Value &result, const json_spirit::Value &error, const json_spirit::Value &id)
{
    json_spirit::Object reply;
    if (error.type() != json_spirit::null_type) {
        reply.push_back(json_spirit::Pair("result", json_spirit::Value::null));
    } else {
        reply.push_back(json_spirit::Pair("result", result));
    }
    reply.push_back(json_spirit::Pair("error", error));
    reply.push_back(json_spirit::Pair("id", id));
    return reply;
}

std::string json::JSONRPCReply(const json_spirit::Value &result, const json_spirit::Value &error, const json_spirit::Value &id)
{
    json_spirit::Object reply = JSONRPCReplyObj(result, error, id);
    return json_spirit::write_string(json_spirit::Value(reply), false) + "\n";
}

void json::ErrorReply(std::ostream &stream, const json_spirit::Object &objError, const json_spirit::Value &id)
{
    // Send error reply from json-rpc error object
    int nStatus = HTTP_INTERNAL_SERVER_ERROR;
    int code = find_value(objError, "code").get_int();
    if (code == RPC_INVALID_REQUEST) {
        nStatus = HTTP_BAD_REQUEST;
    } else if (code == RPC_METHOD_NOT_FOUND) {
        nStatus = HTTP_NOT_FOUND;
    }

    std::string strReply = JSONRPCReply(json_spirit::Value::null, objError, id);
    stream << http::HTTPReply(nStatus, strReply, false) << std::flush;
}

bool bitrpc::ClientAllowed(const boost::asio::ip::address &address)
{
    //
    // Make sure that IPv4-compatible and IPv4-mapped IPv6 addresses are treated as IPv4 addresses
    //
    if ( address.is_v6() && (address.to_v6().is_v4_compatible() || address.to_v6().is_v4_mapped()) ) {
        return bitrpc::ClientAllowed(address.to_v6().to_v4());
    }

    if (address == boost::asio::ip::address_v4::loopback()
     || address == boost::asio::ip::address_v6::loopback()
     || (address.is_v4()
      // Check whether IPv4 addresses match 127.0.0.0/8 (loopback subnet)
      && (address.to_v4().to_ulong() & 0xff000000) == 0x7f000000)) {
        return true;
    }

    const std::string strAddress = address.to_string();
    const std::vector<std::string> &vAllow = map_arg::GetMapMultiArgsString("-rpcallowip");
    for(std::string strAllow: vAllow)
    {
        if (strenc::WildcardMatch(strAddress, strAllow)) {
            return true;
        }
    }

    return false;
}

//
// IOStream device that speaks SSL but can also speak non-SSL
//
template <typename Protocol>
class SSLIOStreamDevice : public boost::iostreams::device<boost::iostreams::bidirectional>
{
public:
    SSLIOStreamDevice(boost::asio::ssl::stream<typename Protocol::socket> &streamIn, bool fUseSSLIn) : stream(streamIn) {
        fUseSSL = fUseSSLIn;
        fNeedHandshake = fUseSSLIn;
    }

    void handshake(boost::asio::ssl::stream_base::handshake_type role) {
        if (! fNeedHandshake) {
            return;
        }
        fNeedHandshake = false;
        stream.handshake(role);
    }

    std::streamsize read(char *s, std::streamsize n) {
        handshake(boost::asio::ssl::stream_base::server); // HTTPS servers read first
        if (fUseSSL) {
            return stream.read_some(boost::asio::buffer(s, n));
        }

        return stream.next_layer().read_some(boost::asio::buffer(s, n));
    }

    std::streamsize write(const char *s, std::streamsize n) {
        handshake(boost::asio::ssl::stream_base::client); // HTTPS clients write first
        if (fUseSSL) {
            return boost::asio::write(stream, boost::asio::buffer(s, n));
        }

        return boost::asio::write(stream.next_layer(), boost::asio::buffer(s, n));
    }

    bool connect(const std::string &server, const std::string &port) {
        boost::asio::ip::tcp::resolver resolver(stream.get_io_service());
        boost::asio::ip::tcp::resolver::query query(server.c_str(), port.c_str());
        boost::asio::ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
        boost::asio::ip::tcp::resolver::iterator end;
        boost::system::error_code error = boost::asio::error::host_not_found;
        while (error && endpoint_iterator != end)
        {
            stream.lowest_layer().close();
            stream.lowest_layer().connect(*endpoint_iterator++, error);
        }
        if (error) {
            return false;
        }
        return true;
    }

private:
    bool fNeedHandshake;
    bool fUseSSL;

    SSLIOStreamDevice &operator=(SSLIOStreamDevice const &)=delete;
    // SSLIOStreamDevice(const SSLIOStreamDevice &)=delete;

    boost::asio::ssl::stream<typename Protocol::socket> &stream;
};

class AcceptedConnection
{
public:
    virtual ~AcceptedConnection() {}

    virtual std::iostream& stream() = 0;
    virtual std::string peer_address_to_string() const = 0;
    virtual void close() = 0;
};

template <typename Protocol>
class AcceptedConnectionImpl : public AcceptedConnection
{
private:
    AcceptedConnectionImpl()=delete;
    AcceptedConnectionImpl(const AcceptedConnectionImpl &)=delete;
    AcceptedConnectionImpl &operator=(const AcceptedConnectionImpl &)=delete;

public:
    AcceptedConnectionImpl(boost::asio::io_service& io_service, boost::asio::ssl::context &context, bool fUseSSL) : sslStream(io_service, context), _d(sslStream, fUseSSL), _stream(_d) {}

    virtual std::iostream &stream() {
        return _stream;
    }

    virtual std::string peer_address_to_string() const {
        return peer.address().to_string();
    }

    virtual void close() {
        _stream.close();
    }

    typename Protocol::endpoint peer;
    boost::asio::ssl::stream<typename Protocol::socket> sslStream;

private:
    SSLIOStreamDevice<Protocol> _d;
    boost::iostreams::stream<SSLIOStreamDevice<Protocol> > _stream;
};

void bitrpc::ThreadRPCServer(void *parg)
{
    // Make this thread recognisable as the RPC listener
    bitthread::RenameThread((std::string(strCoinName) + "-rpclist").c_str());

    try {
        net_node::vnThreadsRunning[THREAD_RPCLISTENER]++;
        ThreadRPCServer2(parg);
        net_node::vnThreadsRunning[THREAD_RPCLISTENER]--;
    } catch (const std::exception &e) {
        net_node::vnThreadsRunning[THREAD_RPCLISTENER]--;
        excep::PrintException(&e, "ThreadRPCServer()");
    } catch (...) {
        net_node::vnThreadsRunning[THREAD_RPCLISTENER]--;
        excep::PrintException(nullptr, "ThreadRPCServer()");
    }
    logging::LogPrintf("ThreadRPCServer exited\n");
}

// Forward declaration required for RPCListen
// template <typename Protocol, typename SocketAcceptorService>
// static void RPCAcceptHandler(boost::shared_ptr<boost::asio::basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor, boost::asio::ssl::context &context, bool fUseSSL, AcceptedConnection *conn, const boost::system::error_code &error);

//
// Sets up I/O resources to accept and handle a new connection.
//
#if BOOST_VERSION >= 106600
template <typename Protocol>
void bitrpc::RPCListen(boost::shared_ptr<boost::asio::basic_socket_acceptor<Protocol> > acceptor, boost::asio::ssl::context &context, const bool fUseSSL)
{
    // Accept connection
    AcceptedConnectionImpl<Protocol> *conn = new(std::nothrow) AcceptedConnectionImpl<Protocol>(acceptor->get_io_service(), context, fUseSSL);
    if(conn == nullptr) {
        throw std::runtime_error("RPCListen memory allocate failure.");
    }

    acceptor->async_accept(
            conn->sslStream.lowest_layer(),
            conn->peer,
            boost::bind(&RPCAcceptHandler<Protocol>,
            acceptor,
            boost::ref(context),
            fUseSSL,
            conn,
            boost::asio::placeholders::error));
}
#else
template <typename Protocol, typename SocketAcceptorService>
void bitrpc::RPCListen(boost::shared_ptr<boost::asio::basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor, boost::asio::ssl::context &context, const bool fUseSSL)
{
    // Accept connection
    AcceptedConnectionImpl<Protocol> *conn = new(std::nothrow) AcceptedConnectionImpl<Protocol>(acceptor->get_io_service(), context, fUseSSL);
    if(conn == NULL) {
        throw std::runtime_error("RPCListen memory allocate failure.");
    }

    acceptor->async_accept(
            conn->sslStream.lowest_layer(),
            conn->peer,
            boost::bind(&RPCAcceptHandler<Protocol, SocketAcceptorService>,
            acceptor,
            boost::ref(context),
            fUseSSL,
            conn,
            boost::asio::placeholders::error));
}
#endif

//
// Accept and handle incoming connection.
//
#if BOOST_VERSION >= 106600
template <typename Protocol>
void bitrpc::RPCAcceptHandler(boost::shared_ptr<boost::asio::basic_socket_acceptor<Protocol> > acceptor, boost::asio::ssl::context &context, const bool fUseSSL, AcceptedConnection *conn, const boost::system::error_code &error)
{
    net_node::vnThreadsRunning[THREAD_RPCLISTENER]++;

    // Immediately start accepting new connections, except when we're cancelled or our socket is closed.
    if (error != boost::asio::error::operation_aborted && acceptor->is_open()) {
        RPCListen(acceptor, context, fUseSSL);
    }

    AcceptedConnectionImpl<boost::asio::ip::tcp> *tcp_conn = dynamic_cast<AcceptedConnectionImpl<boost::asio::ip::tcp>* >(conn);
    if(tcp_conn == nullptr) {
        throw std::runtime_error("RPCAcceptHandler AcceptedConnectionImpl, downcast Error.");
    }

    // TODO: Actually handle errors
    if (error) {
        delete conn;
    } else if (tcp_conn && !ClientAllowed(tcp_conn->peer.address())) {
        //
        // Restrict callers by IP.  It is important to
        // do this before starting client thread, to filter out
        // certain DoS and misbehaving clients.
        //
        // Only send a 403 if we're not using SSL to prevent a DoS during the SSL handshake.
        //
        if (! fUseSSL) {
            conn->stream() << http::HTTPReply(HTTP_FORBIDDEN, "", false) << std::flush;
        }
        delete conn;
    } else if (! bitthread::NewThread(bitrpc::ThreadRPCServer3, conn)) {
        //
        // start HTTP client thread
        //
        logging::LogPrintf("Failed to create RPC server client thread\n");
        delete conn;
    }

    net_node::vnThreadsRunning[THREAD_RPCLISTENER]--;
}
#else
template <typename Protocol, typename SocketAcceptorService>
void bitrpc::RPCAcceptHandler(boost::shared_ptr<boost::asio::basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor, boost::asio::ssl::context &context, const bool fUseSSL, AcceptedConnection *conn, const boost::system::error_code &error)
{
    net_node::vnThreadsRunning[THREAD_RPCLISTENER]++;

    // Immediately start accepting new connections, except when we're cancelled or our socket is closed.
    if (error != boost::asio::error::operation_aborted && acceptor->is_open()) {
        RPCListen(acceptor, context, fUseSSL);
    }

    AcceptedConnectionImpl<boost::asio::ip::tcp> *tcp_conn = dynamic_cast<AcceptedConnectionImpl<boost::asio::ip::tcp>* >(conn);
    if(tcp_conn == NULL) {
        throw std::runtime_error("RPCAcceptHandler AcceptedConnectionImpl, downcast Error.");
    }

    // TODO: Actually handle errors
    if (error) {
        delete conn;
    } else if (tcp_conn && !ClientAllowed(tcp_conn->peer.address())) {
        //
        // Restrict callers by IP.  It is important to
        // do this before starting client thread, to filter out
        // certain DoS and misbehaving clients.
        //
        // Only send a 403 if we're not using SSL to prevent a DoS during the SSL handshake.
        //
        if (! fUseSSL) {
            conn->stream() << http::HTTPReply(HTTP_FORBIDDEN, "", false) << std::flush;
        }
        delete conn;
    } else if (! bitthread::manage::NewThread(bitrpc::ThreadRPCServer3, conn)) {
        //
        // start HTTP client thread
        //
        logging::LogPrintf("Failed to create RPC server client thread\n");
        delete conn;
    }

    net_node::vnThreadsRunning[THREAD_RPCLISTENER]--;
}
#endif

void bitrpc::ThreadRPCServer2(void *parg)
{
    logging::LogPrintf("ThreadRPCServer started\n");

    strRPCUserColonPass = map_arg::GetMapArgsString("-rpcuser") + ":" + map_arg::GetMapArgsString("-rpcpassword");
    if (map_arg::GetMapArgsString("-rpcpassword").empty()) {
        unsigned char rand_pwd[32];
        RAND_bytes(rand_pwd, 32);
        std::string strWhatAmI = "To use ";
        strWhatAmI += (std::string(strCoinName) + "d").c_str();
        if (map_arg::GetMapArgsCount("-server")) {
            strWhatAmI = tinyformat::format(_("To use the %s option"), "\"-server\"");
        } else if (map_arg::GetMapArgsCount("-daemon")) {
            strWhatAmI = tinyformat::format(_("To use the %s option"), "\"-daemon\"");
        }

        CClientUIInterface::get().ThreadSafeMessageBox(tinyformat::format(
                            _("%s, you must set a rpcpassword in the configuration file:\n %s\n"
                            "It is recommended you use the following random password:\n"
                            "rpcuser=%srpc\n"
                            "rpcpassword=%s\n"
                            "(you do not need to remember this password)\n"
                            "If the file does not exist, create it with owner-readable-only file permissions.\n"),
                            strWhatAmI.c_str(),
                            iofs::GetConfigFile().string().c_str(),
                            strCoinNameL,
                            base58::manage::EncodeBase58(&rand_pwd[0], &rand_pwd[0] + 32).c_str()),

                            _("Error"), CClientUIInterface::OK | CClientUIInterface::MODAL);

        boot::StartShutdown();
        return;
    }

    const bool fUseSSL = map_arg::GetBoolArg("-rpcssl");
#if BOOST_VERSION >= 106600
    boost::asio::ssl::context context(boost::asio::ssl::context::sslv23);
#else
    boost::asio::io_service io_service;
    boost::asio::ssl::context context(io_service, boost::asio::ssl::context::sslv23);
#endif

    if (fUseSSL) {
        context.set_options(boost::asio::ssl::context::no_sslv2);

        boost::filesystem::path pathCertFile(map_arg::GetArg("-rpcsslcertificatechainfile", "server.cert"));
        if (! pathCertFile.is_complete()) {
            pathCertFile = boost::filesystem::path(iofs::GetDataDir()) / pathCertFile;
        }
        if (boost::filesystem::exists(pathCertFile)) {
            context.use_certificate_chain_file(pathCertFile.string());
        } else {
            logging::LogPrintf("ThreadRPCServer ERROR: missing server certificate file %s\n", pathCertFile.string().c_str());
        }

        boost::filesystem::path pathPKFile(map_arg::GetArg("-rpcsslprivatekeyfile", "server.pem"));

        if (! pathPKFile.is_complete()) {
            pathPKFile = boost::filesystem::path(iofs::GetDataDir()) / pathPKFile;
        }
        if (boost::filesystem::exists(pathPKFile)) {
            context.use_private_key_file(pathPKFile.string(), boost::asio::ssl::context::pem);
        } else {
            logging::LogPrintf("ThreadRPCServer ERROR: missing server private key file %s\n", pathPKFile.string().c_str());
        }

        std::string strCiphers = map_arg::GetArg("-rpcsslciphers", "TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH");
#if BOOST_VERSION >= 106600
        SSL_CTX_set_cipher_list(context.native_handle(), strCiphers.c_str());
#else
                SSL_CTX_set_cipher_list(context.impl(), strCiphers.c_str());
#endif
    }

#if BOOST_VERSION >= 106600
    boost::asio::io_context io_context;
#else
    // already boost::asio::io_service instance
#endif

    //
    // Try a dual IPv6/IPv4 socket, falling back to separate IPv4 and IPv6 sockets
    //
    const bool loopback = !map_arg::GetMapArgsCount("-rpcallowip");
    boost::asio::ip::address bindAddress = loopback ? boost::asio::ip::address_v6::loopback() : boost::asio::ip::address_v6::any();
    boost::asio::ip::tcp::endpoint endpoint(bindAddress, map_arg::GetArg("-rpcport", GetDefaultRPCPort()));
    boost::system::error_code v6_only_error;

#if BOOST_VERSION >= 106600
    boost::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor(new boost::asio::ip::tcp::acceptor(io_context));
#else
    boost::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor(new boost::asio::ip::tcp::acceptor(io_service));
#endif
    boost::signals2::signal<void ()> StopRequests;

    bool fListening = false;
    std::string strerr;
    try {
        acceptor->open(endpoint.protocol());
        acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

        //
        // Try making the socket dual IPv6/IPv4 (if listening on the "any" address)
        //
        acceptor->set_option(boost::asio::ip::v6_only(loopback), v6_only_error);

        acceptor->bind(endpoint);
        acceptor->listen(boost::asio::socket_base::max_connections);

        RPCListen(acceptor, context, fUseSSL);

        //
        // Cancel outstanding listen-requests for this acceptor when shutting down
        //
        StopRequests.connect(boost::signals2::slot<void ()>(static_cast<void (boost::asio::ip::tcp::acceptor::*)()>(&boost::asio::ip::tcp::acceptor::close), acceptor.get()).track(acceptor));

        fListening = true;
    } catch(const boost::system::system_error &e) {
        strerr = tinyformat::format(_("An error occurred while setting up the RPC port %u for listening on IPv6, falling back to IPv4: %s"), endpoint.port(), e.what());
    }

    try {
        //
        // If dual IPv6/IPv4 failed (or we're opening loopback interfaces only), open IPv4 separately
        //
        if (!fListening || loopback || v6_only_error) {
            bindAddress = loopback ? boost::asio::ip::address_v4::loopback() : boost::asio::ip::address_v4::any();
            endpoint.address(bindAddress);
#if BOOST_VERSION >= 106600
            acceptor.reset(new boost::asio::ip::tcp::acceptor(io_context));
#else
            acceptor.reset(new boost::asio::ip::tcp::acceptor(io_service));
#endif
            acceptor->open(endpoint.protocol());
            acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
            acceptor->bind(endpoint);
            acceptor->listen(boost::asio::socket_base::max_connections);

            RPCListen(acceptor, context, fUseSSL);

            //
            // Cancel outstanding listen-requests for this acceptor when shutting down
            //
            StopRequests.connect(boost::signals2::slot<void ()>( static_cast<void (boost::asio::ip::tcp::acceptor::*)()>(&boost::asio::ip::tcp::acceptor::close), acceptor.get()).track(acceptor));

            fListening = true;
        }
    } catch(const boost::system::system_error &e) {
        strerr = tinyformat::format(_("An error occurred while setting up the RPC port %u for listening on IPv4: %s"), endpoint.port(), e.what());
    }

    if (! fListening) {
        CClientUIInterface::get().ThreadSafeMessageBox(strerr, _("Error"), CClientUIInterface::OK | CClientUIInterface::MODAL);
        boot::StartShutdown();
        return;
    }

    net_node::vnThreadsRunning[THREAD_RPCLISTENER]--;
    while (! args_bool::fShutdown)
    {
#if BOOST_VERSION >= 106600
        io_context.run_one();
#else
        io_service.run_one();
#endif
    }
    net_node::vnThreadsRunning[THREAD_RPCLISTENER]++;
    StopRequests();
}

void bitjson::JSONRequest::parse(const json_spirit::Value &valRequest)
{
    //
    // Parse request
    //
    if (valRequest.type() != json_spirit::obj_type) {
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    }

    const json_spirit::Object &request = valRequest.get_obj();

    //
    // Parse id now so errors from here on will have the id
    //
    id = find_value(request, "id");

    //
    // Parse method
    //
    json_spirit::Value valMethod = find_value(request, "method");
    if (valMethod.type() == json_spirit::null_type) {
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    }
    if (valMethod.type() != json_spirit::str_type) {
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    }

    strMethod = valMethod.get_str();
    if (strMethod != "getwork" && strMethod != "getblocktemplate") {
        //logging::LogPrintf("ThreadRPCServer method=%s\n", strMethod.c_str());
    }

    //
    // Parse params
    //
    json_spirit::Value valParams = find_value(request, "params");
    if (valParams.type() == json_spirit::array_type) {
        params = valParams.get_array();
    } else if (valParams.type() == json_spirit::null_type) {
        params = json_spirit::Array();
    } else {
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array");
    }
}

json_spirit::Object bitrpc::JSONRPCExecOne(const json_spirit::Value &req)
{
    json_spirit::Object rpc_result;

    bitjson::JSONRequest jreq;
    try {
        jreq.parse(req);
        json_spirit::Value result = CRPCTable::tableRPC.execute(jreq.strMethod, jreq.params);
        rpc_result = json::JSONRPCReplyObj(result, json_spirit::Value::null, jreq.id);
    } catch (json_spirit::Object &objError) {
        rpc_result = json::JSONRPCReplyObj(json_spirit::Value::null, objError, jreq.id);
    } catch (const std::exception &e) {
        rpc_result = json::JSONRPCReplyObj(json_spirit::Value::null, bitjson::JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
    }

    return rpc_result;
}

std::string bitrpc::JSONRPCExecBatch(const json_spirit::Array &vReq)
{
    json_spirit::Array ret;
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); ++reqIdx)
    {
        ret.push_back(JSONRPCExecOne(vReq[reqIdx]));
    }

    return json_spirit::write_string(json_spirit::Value(ret), false) + "\n";
}

void bitrpc::ThreadRPCServer3(void *parg)
{
    //LOCK(cs_THREAD_RPCHANDLER);
    //logging::LogPrintf("ThreadRPCServer3 started\n");

    // Make this thread recognisable as the RPC handler
    bitthread::RenameThread((std::string(strCoinName) + "-rpchand").c_str());
    {
        LOCK(cs_THREAD_RPCHANDLER);
        ++net_node::vnThreadsRunning[THREAD_RPCHANDLER];
    }

    AcceptedConnection *conn = (AcceptedConnection *)parg;
    bool fRun = true;
    for ( ; ; )
    {
        if (args_bool::fShutdown || !fRun) {
            conn->close();
            delete conn;
            {
                LOCK(cs_THREAD_RPCHANDLER);
                --net_node::vnThreadsRunning[THREAD_RPCHANDLER];
            }
            return;
        }
        std::map<std::string, std::string> mapHeaders;
        std::string strRequest;

        http::ReadHTTP(conn->stream(), mapHeaders, strRequest);
        //logging::LogPrintf("ThreadRPCServer3 strRequest %s\n", strRequest.c_str());

        //
        // Check authorization
        //
        if (mapHeaders.count("authorization") == 0) {
            conn->stream() << http::HTTPReply(HTTP_UNAUTHORIZED, "", false) << std::flush;
            break;
        }
        if (! bitrpc::HTTPAuthorized(mapHeaders)) {
            logging::LogPrintf("ThreadRPCServer incorrect password attempt from %s\n", conn->peer_address_to_string().c_str());

            /* Deter brute-forcing short passwords. If this results in a DOS the user really shouldn't have their RPC port exposed.*/
            if (map_arg::GetMapArgsString("-rpcpassword").size() < 20) {
                util::Sleep(250);
            }

            conn->stream() << http::HTTPReply(HTTP_UNAUTHORIZED, "", false) << std::flush;
            break;
        }
        if (mapHeaders["connection"] == "close") {
            fRun = false;
        }

        // logging::LogPrintf("ThreadRPCServer3 JSON\n");
        bitjson::JSONRequest jreq;
        try {
            // Parse request
            json_spirit::Value valRequest;
            if (! read_string(strRequest, valRequest)) {
                logging::LogPrintf("ThreadRPCServer3 JSON ParseError\n");
                throw bitjson::JSONRPCError(RPC_PARSE_ERROR, "Parse error");
            }

            std::string strReply;

            // singleton request
            if (valRequest.type() == json_spirit::obj_type) {
                jreq.parse(valRequest);

                //logging::LogPrintf("ThreadRPCServer3 JSON EXE %s\n", jreq.strMethod.c_str());
                json_spirit::Value result = CRPCTable::tableRPC.execute(jreq.strMethod, jreq.params);

                // Send reply
                strReply = json::JSONRPCReply(result, json_spirit::Value::null, jreq.id);

                // array of requests
            } else if (valRequest.type() == json_spirit::array_type) {
                strReply = JSONRPCExecBatch(valRequest.get_array());
            } else {
                throw bitjson::JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");
            }

            conn->stream() << http::HTTPReply(HTTP_OK, strReply, fRun) << std::flush;
        } catch (const json_spirit::Object &objError) {
            logging::LogPrintf("ThreadRPCServer3 JSON Error1\n");
            json::ErrorReply(conn->stream(), objError, jreq.id);
            break;
        } catch (const std::exception &e) {
            logging::LogPrintf("ThreadRPCServer3 JSON Error2\n");
            json::ErrorReply(conn->stream(), bitjson::JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
            break;
        }
    }

    delete conn;
    {
        LOCK(cs_THREAD_RPCHANDLER);
        --net_node::vnThreadsRunning[THREAD_RPCHANDLER];
    }
}

json_spirit::Value CRPCTable::execute(const std::string &strMethod, const json_spirit::Array &params)
{
    //
    // Find method
    //
    const CRPCCommand *pcmd = CRPCTable::tableRPC[strMethod];
    if (! pcmd) {
        logging::LogPrintf("ThreadRPCServer3 execute Error cmd: %s\n", strMethod.c_str());
        throw bitjson::JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");
    }

    //
    // Observe safe mode
    //
    std::string strWarning = block_alert::GetWarnings("rpc");
    if (!strWarning.empty() && !map_arg::GetBoolArg("-disablesafemode") && !pcmd->okSafeMode) {
        logging::LogPrintf("ThreadRPCServer3 execute Error2 cmd: %s\n", strMethod.c_str());
        throw bitjson::JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, std::string("Safe mode: ") + strWarning);
    }

    try
    {
        // Execute
        json_spirit::Value result;
        {
            if (pcmd->unlocked) {
                result = pcmd->actor(params, false);
            } else {
                LOCK2(block_process::cs_main, entry::pwalletMain->cs_wallet);
                result = pcmd->actor(params, false);
            }
        }
        return result;
    } catch (const std::exception &e) {
        logging::LogPrintf("ThreadRPCServer3 execute Error3 cmd: %s\n", strMethod.c_str());
        throw bitjson::JSONRPCError(RPC_MISC_ERROR, e.what());
    }
}

json_spirit::Object bitrpc::CallRPC(const std::string &strMethod, const json_spirit::Array &params)
{
#ifndef CLI_MODE_ENABLE
    if (map_arg::GetMapArgsString("-rpcuser").empty() && map_arg::GetMapArgsString("-rpcpassword").empty()) {
        throw std::runtime_error(tinyformat::format(
            _("You must set rpcpassword=<password> in the configuration file:\n%s\n"
            "If the file does not exist, create it with owner-readable-only file permissions."),
            iofs::GetConfigFile().string().c_str()));
    }
#else
    {
        auto getvalue = [](const char *buf, const std::string &target, std::string &dest) {
            assert(buf != nullptr);
            std::string src = buf;
            auto pos = src.find(target);
            if(pos != std::string::npos) {
                dest.clear();
                dest.reserve(128);
                pos += target.size();
                while(pos < src.size()) {
                    if(src[pos]!='=' && src[pos]!=' ')
                        dest += src[pos];
                    ++pos;
                }
            } else {
                // do nothing (if no find, no change dest)
            }
        };

        fs::path path = iofs::GetConfigFile();
        //::fprintf(stdout, "path: %s\n", path.string().c_str());
        if(boost::filesystem::exists(path)) {
            std::string rpcuser, rpcpassword;
            boost::filesystem::ifstream file(path);
            char buf[1024];
            while(file.getline(buf, sizeof(buf))) {
                getvalue(buf, std::string("rpcuser"), rpcuser);
                getvalue(buf, std::string("rpcpassword"), rpcpassword);
                cleanse::OPENSSL_cleanse(buf, sizeof(buf));
            }
            //::fprintf(stdout, "read rpcuser: %s\n", rpcuser.c_str());
            //::fprintf(stdout, "read rpcpassword: %s\n", rpcpassword.c_str());
            file.close();

            map_arg::SetMapArgsString("-rpcuser", rpcuser);
            map_arg::SetMapArgsString("-rpcpassword", rpcpassword);
            //::fprintf(stdout, "RPC1: %s\n", map_arg::GetMapArgsString("-rpcuser").c_str());
            //::fprintf(stdout, "RPC2: %s\n", map_arg::GetMapArgsString("-rpcpassword").c_str());
        } else {
            throw std::runtime_error("couldn't read configure file");
        }

        if(map_arg::GetMapArgsString("-rpcuser").empty() && map_arg::GetMapArgsString("-rpcpassword").empty()) {
            throw std::runtime_error("rpc setting is invalid");
        }

        //util::Sleep(5000);
    }
#endif

    // Connect to localhost
    bool fUseSSL = map_arg::GetBoolArg("-rpcssl");
#if BOOST_VERSION >= 106600
    boost::asio::ssl::context context(boost::asio::ssl::context::sslv23);
#else
    boost::asio::io_service io_service;
    boost::asio::ssl::context context(io_service, boost::asio::ssl::context::sslv23);
#endif
    context.set_options(boost::asio::ssl::context::no_sslv2);
#if BOOST_VERSION >= 106600
    boost::asio::io_context io_context;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> sslStream(io_context, context);
    // Note: template<typename Arg> boost::asio::ssl::stream(Arg && arg, context & ctx)
#else
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> sslStream(io_service, context);
#endif
    SSLIOStreamDevice<boost::asio::ip::tcp> d(sslStream, fUseSSL);
    boost::iostreams::stream<SSLIOStreamDevice<boost::asio::ip::tcp> > stream(d);
    if (!d.connect(map_arg::GetArg("-rpcconnect", net_basis::strLocal), map_arg::GetArg("-rpcport", strenc::itostr(GetDefaultRPCPort())))) {
        throw std::runtime_error("couldn't connect to server");
    }

    // HTTP basic authentication
    std::string strUserPass64 = strenc::EncodeBase64(map_arg::GetMapArgsString("-rpcuser") + ":" + map_arg::GetMapArgsString("-rpcpassword"));
    std::map<std::string, std::string> mapRequestHeaders;
    mapRequestHeaders["Authorization"] = std::string("Basic ") + strUserPass64;

    // Send request
    std::string strRequest = json::JSONRPCRequest(strMethod, params, 1);
    std::string strPost = http::HTTPPost(strRequest, mapRequestHeaders);
    stream << strPost << std::flush;

    // Receive reply
    std::map<std::string, std::string> mapHeaders;
    std::string strReply;
    int nStatus = http::ReadHTTP(stream, mapHeaders, strReply);
    if (nStatus == HTTP_UNAUTHORIZED) {
        throw std::runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    } else if (nStatus >= 400 && nStatus != HTTP_BAD_REQUEST && nStatus != HTTP_NOT_FOUND && nStatus != HTTP_INTERNAL_SERVER_ERROR) {
        throw std::runtime_error(tinyformat::format("server returned HTTP error %d", nStatus));
    } else if (strReply.empty()) {
        throw std::runtime_error("no response from server");
    }

    // Parse reply
    json_spirit::Value valReply;
    if (! read_string(strReply, valReply)) {
        throw std::runtime_error("couldn't parse reply from server");
    }

    const json_spirit::Object &reply = valReply.get_obj();
    if (reply.empty()) {
        throw std::runtime_error("expected reply to have result, error and id properties");
    }

    return reply;
}

template<typename T>
void bitrpc::ConvertTo(json_spirit::Value &value, bool fAllowNull/* =false */)
{
    if (fAllowNull && value.type() == json_spirit::null_type) {
        return;
    }

    if (value.type() == json_spirit::str_type) {
        //
        // reinterpret string as unquoted json value
        //
        json_spirit::Value value2;
        std::string strJSON = value.get_str();
        if (! read_string(strJSON, value2)) {
            throw std::runtime_error(std::string("Error parsing JSON:") + strJSON);
        }

        ConvertTo<T>(value2, fAllowNull);
        value = value2;
    } else {
        value = value.get_value<T>();
    }
}

//
// Convert strings to command-specific RPC representation
//
json_spirit::Array bitrpc::RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    json_spirit::Array params;
    for(const std::string &param: strParams)
    {
        params.push_back(param);
    }

    size_t n = params.size();

    //
    // Special case non-string parameter types
    //
    if (strMethod == "stop"                   && n > 0) { ConvertTo<bool>(params[0]); }
    if (strMethod == "getaddednodeinfo"       && n > 0) { ConvertTo<bool>(params[0]); }
    if (strMethod == "sendtoaddress"          && n > 1) { ConvertTo<double>(params[1]); }
    if (strMethod == "mergecoins"             && n > 0) { ConvertTo<double>(params[0]); }
    if (strMethod == "mergecoins"             && n > 1) { ConvertTo<double>(params[1]); }
    if (strMethod == "mergecoins"             && n > 2) { ConvertTo<double>(params[2]); }
    if (strMethod == "settxfee"               && n > 0) { ConvertTo<double>(params[0]); }
    if (strMethod == "getreceivedbyaddress"   && n > 1) { ConvertTo<int64_t>(params[1]); }
    if (strMethod == "getreceivedbyaccount"   && n > 1) { ConvertTo<int64_t>(params[1]); }
    if (strMethod == "listreceivedbyaddress"  && n > 0) { ConvertTo<int64_t>(params[0]); }
    if (strMethod == "listreceivedbyaddress"  && n > 1) { ConvertTo<bool>(params[1]); }
    if (strMethod == "listreceivedbyaccount"  && n > 0) { ConvertTo<int64_t>(params[0]); }
    if (strMethod == "listreceivedbyaccount"  && n > 1) { ConvertTo<bool>(params[1]); }
    if (strMethod == "getbalance"             && n > 1) { ConvertTo<int64_t>(params[1]); }
    if (strMethod == "getblock"               && n > 1) { ConvertTo<bool>(params[1]); }
    if (strMethod == "getblockbynumber"       && n > 0) { ConvertTo<int64_t>(params[0]); }
    if (strMethod == "dumpblockbynumber"      && n > 0) { ConvertTo<int64_t>(params[0]); }
    if (strMethod == "getblockbynumber"       && n > 1) { ConvertTo<bool>(params[1]); }
    if (strMethod == "getblockhash"           && n > 0) { ConvertTo<int64_t>(params[0]); }
    if (strMethod == "move"                   && n > 2) { ConvertTo<double>(params[2]); }
    if (strMethod == "move"                   && n > 3) { ConvertTo<int64_t>(params[3]); }
    if (strMethod == "sendfrom"               && n > 2) { ConvertTo<double>(params[2]); }
    if (strMethod == "sendfrom"               && n > 3) { ConvertTo<int64_t>(params[3]); }
    if (strMethod == "sendethfrom"            && n > 2) { ConvertTo<double>(params[2]); }
    if (strMethod == "sendethfrom"            && n > 3) { ConvertTo<int64_t>(params[3]); }
    if (strMethod == "listtransactions"       && n > 1) { ConvertTo<int64_t>(params[1]); }
    if (strMethod == "listtransactions"       && n > 2) { ConvertTo<int64_t>(params[2]); }
    if (strMethod == "listaccounts"           && n > 0) { ConvertTo<int64_t>(params[0]); }
    if (strMethod == "walletpassphrase"       && n > 1) { ConvertTo<int64_t>(params[1]); }
    if (strMethod == "walletpassphrase"       && n > 2) { ConvertTo<bool>(params[2]); }
    if (strMethod == "getblocktemplate"       && n > 0) { ConvertTo<json_spirit::Object>(params[0]); }
    if (strMethod == "listsinceblock"         && n > 1) { ConvertTo<int64_t>(params[1]); }

    if (strMethod == "getnewschnorraddress"   && n > 1) { ConvertTo<int64_t>(params[1]); }
    if (strMethod == "getmysentmessages"      && n > 1) { ConvertTo<int32_t>(params[1]); }
    if (strMethod == "getciphermessages"      && n > 0) { ConvertTo<int32_t>(params[0]); }
    if (strMethod == "getnewcipheraddress"    && n > 2) { ConvertTo<int32_t>(params[2]); }
    if (strMethod == "getnewcipheraddress"    && n > 3) { ConvertTo<int32_t>(params[3]); }
    if (strMethod == "getnewcipheraddress"    && n > 4) { ConvertTo<int32_t>(params[4]); }
    if (strMethod == "getnetworkhashps"       && n > 0) { ConvertTo<int>(params[0]); }

    if (strMethod == "scaninput"              && n > 0) { ConvertTo<json_spirit::Object>(params[0]); }

    if (strMethod == "sendalert"              && n > 2) { ConvertTo<int64_t>(params[2]); }
    if (strMethod == "sendalert"              && n > 3) { ConvertTo<int64_t>(params[3]); }
    if (strMethod == "sendalert"              && n > 4) { ConvertTo<int64_t>(params[4]); }
    if (strMethod == "sendalert"              && n > 5) { ConvertTo<int64_t>(params[5]); }
    if (strMethod == "sendalert"              && n > 6) { ConvertTo<int64_t>(params[6]); }

    if (strMethod == "sendmany"               && n > 1) { ConvertTo<json_spirit::Object>(params[1]); }
    if (strMethod == "sendmany"               && n > 2) { ConvertTo<int64_t>(params[2]); }
    if (strMethod == "reservebalance"         && n > 0) { ConvertTo<bool>(params[0]); }
    if (strMethod == "reservebalance"         && n > 1) { ConvertTo<double>(params[1]); }
    if (strMethod == "addmultisigaddress"     && n > 0) { ConvertTo<int64_t>(params[0]); }
    if (strMethod == "addmultisigaddress"     && n > 1) { ConvertTo<json_spirit::Array>(params[1]); }
    if (strMethod == "listunspent"            && n > 0) { ConvertTo<int64_t>(params[0]); }
    if (strMethod == "listunspent"            && n > 1) { ConvertTo<int64_t>(params[1]); }
    if (strMethod == "listunspent"            && n > 2) { ConvertTo<json_spirit::Array>(params[2]); }
    if (strMethod == "getrawtransaction"      && n > 1) { ConvertTo<int64_t>(params[1]); }
    if (strMethod == "createrawtransaction"   && n > 0) { ConvertTo<json_spirit::Array>(params[0]); }
    if (strMethod == "createrawtransaction"   && n > 1) { ConvertTo<json_spirit::Object>(params[1]); }
    if (strMethod == "createmultisig"         && n > 0) { ConvertTo<int64_t>(params[0]); }
    if (strMethod == "createmultisig"         && n > 1) { ConvertTo<json_spirit::Array>(params[1]); }
    if (strMethod == "signrawtransaction"     && n > 1) { ConvertTo<json_spirit::Array>(params[1], true); }
    if (strMethod == "signrawtransaction"     && n > 2) { ConvertTo<json_spirit::Array>(params[2], true); }
    if (strMethod == "keypoolrefill"          && n > 0) { ConvertTo<int64_t>(params[0]); }
    if (strMethod == "keypoolreset"           && n > 0) { ConvertTo<int64_t>(params[0]); }
    if (strMethod == "importaddress"          && n > 2) { ConvertTo<bool>(params[2]); }
    if (strMethod == "importprivkey"          && n > 2) { ConvertTo<bool>(params[2]); }
    if (strMethod == "importprivethkey"       && n > 2) { ConvertTo<bool>(params[2]); }

    return params;
}

int bitrpc::CommandLineRPC(int argc, char *argv[])
{
    std::string strPrint;
    int nRet = 0;
    try {
        //
        // Skip switches
        //
        while (argc > 1 && util::IsSwitchChar(argv[1][0]))
        {
            argc--;
            argv++;
        }

        // Method
        if (argc < 2) {
            throw std::runtime_error("too few parameters");
        }
        std::string strMethod = argv[1];

        // Parameters default to strings
        std::vector<std::string> strParams(&argv[2], &argv[argc]);
        json_spirit::Array params = RPCConvertValues(strMethod, strParams);

        // Execute
        json_spirit::Object reply = CallRPC(strMethod, params);

        // Parse reply
        const json_spirit::Value &result = find_value(reply, "result");
        const json_spirit::Value &error  = find_value(reply, "error");

        if (error.type() != json_spirit::null_type) {
            // Error
            strPrint = "error: " + write_string(error, false);
            int code = find_value(error.get_obj(), "code").get_int();
            nRet = abs(code);
        } else {
            // Result
            if (result.type() == json_spirit::null_type) {
                strPrint.clear();
            } else if (result.type() == json_spirit::str_type) {
                strPrint = result.get_str();
            } else {
                strPrint = write_string(result, true);
            }
        }
    } catch (const std::exception &e) {
        strPrint = std::string("error: ") + e.what();
        nRet = 87;
    } catch (...) {
        excep::PrintException(nullptr, "CommandLineRPC()");
    }

    if (! strPrint.empty()) {
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());
    }
    return nRet;
}

#ifdef TEST
int main(int argc, char *argv[])
{
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFile("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
    ::setbuf(stdin, nullptr);
    ::setbuf(stdout, nullptr);
    ::setbuf(stderr, nullptr);

    try
    {
        if (argc >= 2 && string(argv[1]) == "-server") {
            logging::LogPrintf("server ready\n");
            bitrpc::ThreadRPCServer(nullptr);
        } else {
            return bitrpc::CommandLineRPC(argc, argv);
        }
    } catch (const std::exception &e) {
        excep::PrintException(&e, "main()");
    } catch (...) {
        excep::PrintException(NULL, "main()");
    }
    return 0;
}
#endif
