// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <init.h>
#include <util.h>
#include <sync/sync.h>
#include <ui_interface.h>
#include <rpc/bitcoinrpc.h>
#include <random/random.h>
#include <db.h>
#include <boot/shutdown.h>
#include <block/block_process.h>
#include <block/block_alert.h>
#include <list>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/filesystem/fstream.hpp>

std::map<std::string, const CRPCTable::CRPCCommand *> CRPCTable::mapCommands;
std::string bitrpc::strRPCUserColonPass;
CCriticalSection bitrpc::cs_THREAD_RPCHANDLER;
CCriticalSection CRPCTable::cs_nWalletUnlockTime;
int64_t CRPCTable::nWalletUnlockTime = 0;
CCriticalSection CRPCTable::cs_getwork;
CRPCCmd CRPCCmd::sobj;

unsigned short bitrpc::GetDefaultRPCPort() noexcept {
    return map_arg::GetBoolArg("-testnet", false) ? tcp_port::uJsonRpcTest : tcp_port::uJsonRpcMain;
}

void bitrpc::RPCTypeCheck(CBitrpcData &data, const json_spirit::Array &params, const std::list<json_spirit::Value_type> &typesExpected, bool fAllowNull/* =false */) {
    unsigned int i = 0;
    for(json_spirit::Value_type t: typesExpected) {
        if (params.size() <= i)
            break;

        const json_spirit::Value &v = params[i];
        if (!((v.type() == t) || (fAllowNull && (v.type() == json_spirit::null_type)))) {
            std::string err = strprintf("Expected type %s, got %s", json_spirit::Value_type_name[t], json_spirit::Value_type_name[v.type()]);
            data.JSONRPCError(RPC_TYPE_ERROR, err);
            return;
        }
        ++i;
    }
    data.JSONRPCSuccess(json_spirit::Value::null);
}

void bitrpc::RPCTypeCheck(CBitrpcData &data, const json_spirit::Object &o, const std::map<std::string, json_spirit::Value_type> &typesExpected, bool fAllowNull/* =false */) {
    for(const std::pair<std::string, json_spirit::Value_type> &t: typesExpected) {
        const json_spirit::Value& v = find_value(o, t.first);
        if (!fAllowNull && v.type() == json_spirit::null_type) {
            data.JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing %s", t.first.c_str()));
            return;
        }

        if (!((v.type() == t.second) || (fAllowNull && (v.type() == json_spirit::null_type)))) {
            std::string err = strprintf("Expected type %s for %s, got %s", json_spirit::Value_type_name[t.second], t.first.c_str(), json_spirit::Value_type_name[v.type()]);
            data.JSONRPCError(RPC_TYPE_ERROR, err);
            return;
        }
    }
    data.JSONRPCSuccess(json_spirit::Value::null);
}

int64_t CRPCTable::AmountFromValue(const json_spirit::Value &value, CBitrpcData &data) {
    json_spirit::json_flags status;
    double dAmount = value.get_real(status);
    if(! status.fSuccess()) {data.JSONRPCError(RPC_JSON_ERROR, status.e); return 0.0;}
    bool ret=true;
    if (dAmount <= 0.0 || dAmount > block_param::MAX_MONEY)
        ret=false;

    int64_t nAmount = util::roundint64(dAmount * util::COIN);
    if (! block_transaction::manage::MoneyRange(nAmount))
        ret=false;

    if(! ret)
        data.JSONRPCError(RPC_TYPE_ERROR, data.e + "Invalid amount");
    else
        data.JSONRPCSuccess(nAmount);

    return nAmount;
}

json_spirit::Value CRPCTable::ValueFromAmount(int64_t amount) noexcept {
    return (double)amount / (double)util::COIN;
}

std::string CRPCTable::HexBits(unsigned int nBits) {
    union
    {
        int32_t nBits;
        char cBits[4];
    } uBits;

    uBits.nBits = htonl((int32_t)nBits);
    return util::HexStr(BEGIN(uBits.cBits), END(uBits.cBits));
}

json_spirit::Value CRPCTable::help(std::string strCommand, CBitrpcData &data) {
    std::string strRet;
    std::set<rpcfn_type> setDone;
    for (const std::pair<std::string, const CRPCCommand *> &cmd: mapCommands) {
        const CRPCCommand *pcmd = cmd.second;
        std::string strMethod = cmd.first;
        if (strMethod.find("label") != std::string::npos)
            continue;
        if (!strCommand.empty() && strMethod != strCommand)
            continue;
        json_spirit::Array params;
        rpcfn_type pfn = pcmd->actor;
        json_spirit::Value vHelp;
        if (setDone.insert(pfn).second)
            vHelp = (*pfn)(params, data);
        if (data.ret != CBitrpcData::BITRPC_STATUS_OK) {
            assert(! "[bug] help return is not JSONRPCSuccess.");
            return data.e;
        }
        std::string strHelp;
        json_spirit::json_flags status;
        strHelp = vHelp.get_str(status);
        if(! status.fSuccess())
            continue;
        if (strCommand.empty()) {
            if (strHelp.find('\n') != std::string::npos)
                strHelp = strHelp.substr(0, strHelp.find('\n'));
        }
        strRet += strHelp + "\n";
    }
    if (strRet.empty())
        strRet = strprintf("help: unknown command: %s\n", strCommand.c_str());
    strRet = strRet.substr(0, strRet.size() - 1);
    return data.JSONRPCSuccess(strRet);
}

json_spirit::Value CRPCTable::help(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() > 1) {
        return data.JSONRPCSuccess(
            "help [command]\n"
            "List commands, or get help for a command.");
    }
    std::string strCommand;
    if (params.size() > 0) {
        json_spirit::json_flags status;
        strCommand = params[0].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }
    data.param = CBitrpcData::BITRPC_PARAM_HELP;
    return CRPCTable::help(strCommand, data);
}

json_spirit::Value CRPCTable::stop(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() > 1) {
        return data.JSONRPCSuccess(
            std::string("stop <detach>\n"
             "<detach> is true or false to detach the database or not for this stop only\n"
             "Stop ") + coin_param::strCoinName + " server (and possibly override the detachdb config value).");
    }

    // Shutdown will take long enough that the response should get back
    if (params.size() > 0) {
        json_spirit::json_flags status;
        CDBEnv::bitdb.SetDetach(params[0].get_bool(status));
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }
    boot::StartShutdown();
    return data.JSONRPCSuccess(std::string(coin_param::strCoinName + " server stopping"));
}

// Call Table
const CRPCTable::CRPCCommand CRPCTable::vRPCCommands[93] =
{   //  name                        function                      safemd  unlocked
    //  ------------------------    -----------------------       ------  --------
    { "help",                       &help,                        true,   true },
    { "stop",                       &stop,                        true,   true },
    { "getbestblockhash",           &getbestblockhash,            true,   false },
    { "getblockcount",              &getblockcount,               true,   false },
    { "getconnectioncount",         &getconnectioncount,          true,   false },
    { "getaddrmaninfo",             &getaddrmaninfo,              true,   false },
    { "getpeerinfo",                &getpeerinfo,                 true,   false },
    { "addnode",                    &addnode,                     true,   true },
    { "getaddednodeinfo",           &getaddednodeinfo,            true,   true },
    { "getdifficulty",              &getdifficulty,               true,   false },
    { "getinfo",                    &getinfo,                     true,   false },
    { "getsubsidy",                 &getsubsidy,                  true,   false },
    { "getmininginfo",              &getmininginfo,               true,   false },
    { "scaninput",                  &scaninput,                   true,   true },
    { "getnewaddress",              &getnewaddress,               true,   false },
    { "getnettotals",               &getnettotals,                true,   true },
    { "ntptime",                    &ntptime,                     true,   true },
    { "getaccountaddress",          &getaccountaddress,           true,   false },
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
    { "sendmany",                   &sendmany,                    false,  false },
    { "addmultisigaddress",         &addmultisigaddress,          false,  false },
    { "addredeemscript",            &addredeemscript,             false,  false },
    { "getrawmempool",              &getrawmempool,               true,   false },
    { "getblock",                   &getblock,                    false,  false },
    { "getblockbynumber",           &getblockbynumber,            false,  false },
    { "dumpblock",                  &dumpblock,                   false,  false },
    { "dumpblockbynumber",          &dumpblockbynumber,           false,  false },
    { "getblockhash",               &getblockhash,                false,  false },
    { "getblockqhash",              &getblockqhash,               false,  false },
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
    { "importaddress",              &importaddress,               false,  true },
    { "removeaddress",              &removeaddress,               false,  true },
    { "listunspent",                &listunspent,                 false,  false },
    { "getrawtransaction",          &getrawtransaction,           false,  false },
    { "createrawtransaction",       &createrawtransaction,        false,  false },
    { "decoderawtransaction",       &decoderawtransaction,        false,  false },
    { "createmultisig",             &createmultisig,              false,  false },
    { "decodescript",               &decodescript,                false,  false },
    { "signrawtransaction",         &signrawtransaction,          false,  false },
    { "sendrawtransaction",         &sendrawtransaction,          false,  false },
    { "getcheckpoint",              &getcheckpoint,               true,   false },
    { "reservebalance",             &reservebalance,              false,  true },
    { "checkwallet",                &checkwallet,                 false,  true },
    { "repairwallet",               &repairwallet,                false,  true },
    { "resendwallettransactions",   &resendwallettransactions,    false,  true },
    { "makekeypair",                &makekeypair,                 false,  true },
    { "newmalleablekey",            &newmalleablekey,             false,  false },
    { "adjustmalleablekey",         &adjustmalleablekey,          false,  false },
    { "adjustmalleablepubkey",      &adjustmalleablepubkey,       false,  false },
    { "listmalleableviews",         &listmalleableviews,          false,  false },
    { "dumpmalleablekey",           &dumpmalleablekey,            false,  false },
    { "importmalleablekey",         &importmalleablekey,          true,   false },
    { "encryptdata",                &encryptdata,                 false,  false },
    { "decryptdata",                &decryptdata,                 false,  false },
    { "encryptmessage",             &encryptmessage,              false,  false },
    { "decryptmessage",             &decryptmessage,              false,  false },
    { "sendalert",                  &sendalert,                   false,  false },
    { "getnetworkhashps",           &getnetworkhashps,            true,   false },
};

// HTTP protocol
// This ain't Apache. We're just using HTTP header for the length field and to be compatible with other JSON-RPC implementations.
std::string http::HTTPPost(const std::string &strMsg, const std::map<std::string, std::string> &mapRequestHeaders) {
    std::ostringstream s;
      s << "POST / HTTP/1.1\r\n"
        << "User-Agent: "
        << coin_param::strCoinName.c_str()
        << "-json-rpc/" << format_version::FormatFullVersion() << "\r\n"
        << "Host: 127.0.0.1\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << strMsg.size() << "\r\n"
        << "Connection: close\r\n"
        << "Accept: application/json\r\n";

    for(const std::pair<std::string, std::string> &item: mapRequestHeaders)
        s << item.first << ": " << item.second << "\r\n";

    s << "\r\n" << strMsg;
    return s.str();
}

std::string http::HTTPReply(int nStatus, const std::string &strMsg, bool keepalive) {
    if (nStatus == HTTP_UNAUTHORIZED) {
        return strprintf(
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
            "</HTML>\r\n", bitjson::rfc1123Time().c_str(), coin_param::strCoinName.c_str(), format_version::FormatFullVersion().c_str());
    }

    const char *cStatus = "";
    if (nStatus == HTTP_OK)               cStatus = "OK";
    else if (nStatus == HTTP_BAD_REQUEST) cStatus = "Bad Request";
    else if (nStatus == HTTP_FORBIDDEN)   cStatus = "Forbidden";
    else if (nStatus == HTTP_NOT_FOUND)   cStatus = "Not Found";
    else if (nStatus == HTTP_INTERNAL_SERVER_ERROR) cStatus = "Internal Server Error";
    else cStatus = "";
    return strprintf(
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
        coin_param::strCoinName.c_str(),
        format_version::FormatFullVersion().c_str(),
        strMsg.c_str());
}

int http::ReadHTTPStatus(std::basic_istream<char> &stream, int &proto) {
    std::string str;
    std::getline(stream, str);
    std::vector<std::string> vWords;
    std::istringstream iss(str);
    std::copy(std::istream_iterator<std::string>(iss), std::istream_iterator<std::string>(), std::back_inserter(vWords));
    if (vWords.size() < 2)
        return HTTP_INTERNAL_SERVER_ERROR;

    proto = 0;
    const char *ver = ::strstr(str.c_str(), "HTTP/1.");
    if (ver != nullptr)
        proto = atoi(ver + 7);

    return ::atoi(vWords[1].c_str());
}

int http::ReadHTTPHeader(std::basic_istream<char> &stream, std::map<std::string, std::string> &mapHeadersRet) {
    int nLen = 0;
    for (;;) {
        std::string str;
        std::getline(stream, str);
        if (str.empty() || str == "\r")
            break;

        std::string::size_type nColon = str.find(":");
        if (nColon != std::string::npos) {
            std::string strHeader = str.substr(0, nColon);
            boost::trim(strHeader);
            boost::to_lower(strHeader);
            std::string strValue = str.substr(nColon + 1);
            boost::trim(strValue);
            mapHeadersRet[strHeader] = strValue;
            if (strHeader == "content-length")
                nLen = atoi(strValue.c_str());
        }
    }
    return nLen;
}

int http::ReadHTTP(std::basic_istream<char> &stream, std::map<std::string, std::string> &mapHeadersRet, std::string &strMessageRet) {
    mapHeadersRet.clear();
    strMessageRet.clear();

    // Read status
    int nProto = 0;
    int nStatus = http::ReadHTTPStatus(stream, nProto);

    // Read header
    int nLen = http::ReadHTTPHeader(stream, mapHeadersRet);
    if (nLen < 0 || nLen >(int)compact_size::MAX_SIZE)
        return HTTP_INTERNAL_SERVER_ERROR;

    // Read message
    if (nLen > 0) {
        std::vector<char> vch(nLen);
        stream.read(&vch[0], nLen);
        strMessageRet = std::string(vch.begin(), vch.end());
    }

    std::string sConHdr = mapHeadersRet["connection"];
    if ((sConHdr != "close") && (sConHdr != "keep-alive")) {
        if (nProto >= 1)
            mapHeadersRet["connection"] = "keep-alive";
        else
            mapHeadersRet["connection"] = "close";
    }

    return nStatus;
}

bool bitrpc::HTTPAuthorized(std::map<std::string, std::string> &mapHeaders) {
    std::string strAuth = mapHeaders["authorization"];
    if (strAuth.substr(0, 6) != "Basic ")
        return false;

    std::string strUserPass64 = strAuth.substr(6); boost::trim(strUserPass64);
    std::string strUserPass = base64::DecodeBase64(strUserPass64);
    return map_arg::TimingResistantEqual(strUserPass, strRPCUserColonPass);
}

// JSON-RPC protocol. Bitcoin speaks version 1.0 for maximum compatibility,
// but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
// unspecified (HTTP errors and contents of 'error').
// 1.0 spec: http://json-rpc.org/wiki/specification
// 1.2 spec: http://groups.google.com/group/json-rpc/web/json-rpc-over-http
// http://www.codeproject.com/KB/recipes/JSON_Spirit.aspx
std::string json::JSONRPCRequest(const std::string &strMethod, const json_spirit::Array &params, const json_spirit::Value &id, json_spirit::json_flags &status) {
    json_spirit::Object request;
    request.push_back(json_spirit::Pair("method", strMethod));
    request.push_back(json_spirit::Pair("params", params));
    request.push_back(json_spirit::Pair("id", id));
    std::string ret = json_spirit::write_string(json_spirit::Value(request), false, status);
    if(! status.fSuccess()) return status.e;
    ret += "\n";
    return ret;
}

json_spirit::Object json::JSONRPCReplyObj(const json_spirit::Value &result, const json_spirit::Value &error, const json_spirit::Value &id) {
    json_spirit::Object reply;
    if (error.type() != json_spirit::null_type)
        reply.push_back(json_spirit::Pair("result", json_spirit::Value::null));
    else
        reply.push_back(json_spirit::Pair("result", result));

    reply.push_back(json_spirit::Pair("error", error));
    reply.push_back(json_spirit::Pair("id", id));
    return reply;
}

std::string json::JSONRPCReply(const json_spirit::Value &result, const json_spirit::Value &error, const json_spirit::Value &id, json_spirit::json_flags &status) {
    json_spirit::Object reply = JSONRPCReplyObj(result, error, id);
    std::string ret = json_spirit::write_string(json_spirit::Value(reply), false, status);
    if(! status.fSuccess()) return status.e;
    ret += "\n";
    return ret;
}

void json::ErrorReply(std::ostream &stream, const json_spirit::Object &objError, const json_spirit::Value &id, json_spirit::json_flags &status) {
    // Send error reply from json-rpc error object
    int nStatus = HTTP_INTERNAL_SERVER_ERROR;
    int code = find_value(objError, "code").get_int(status);
    if(! status.fSuccess()) return;
    if (code == RPC_INVALID_REQUEST)
        nStatus = HTTP_BAD_REQUEST;
    else if (code == RPC_METHOD_NOT_FOUND)
        nStatus = HTTP_NOT_FOUND;

    std::string strReply = JSONRPCReply(json_spirit::Value::null, objError, id, status);
    if(status.fSuccess())
        stream << http::HTTPReply(nStatus, strReply, false) << std::flush;
}

bool bitrpc::ClientAllowed(const boost::asio::ip::address &address) {
    // Make sure that IPv4-compatible and IPv4-mapped IPv6 addresses are treated as IPv4 addresses
    if (address.is_v6() && (address.to_v6().is_v4_compatible() || address.to_v6().is_v4_mapped()))
        return bitrpc::ClientAllowed(address.to_v6().to_v4());
    if (address == boost::asio::ip::address_v4::loopback()
        || address == boost::asio::ip::address_v6::loopback()
        || (address.is_v4()
            // Check whether IPv4 addresses match 127.0.0.0/8 (loopback subnet)
            && (address.to_v4().to_ulong() & 0xff000000) == 0x7f000000)) {
        return true;
    }

    const std::string strAddress = address.to_string();
    const std::vector<std::string> &vAllow = map_arg::GetMapMultiArgsString("-rpcallowip");
    for(std::string strAllow: vAllow) {
        if (match::WildcardMatch(strAddress, strAllow))
            return true;
    }
    return false;
}

// IOStream device that speaks SSL but can also speak non-SSL
template <typename Protocol>
class SSLIOStreamDevice : public boost::iostreams::device<boost::iostreams::bidirectional>
{
public:
    SSLIOStreamDevice(boost::asio::ssl::stream<typename Protocol::socket> &streamIn, bool fUseSSLIn) noexcept : stream(streamIn) {
        fUseSSL = fUseSSLIn;
        fNeedHandshake = fUseSSLIn;
    }

    void handshake(boost::asio::ssl::stream_base::handshake_type role) {
        if (! fNeedHandshake)
            return;
        fNeedHandshake = false;
        stream.handshake(role);
    }

    std::streamsize read(char *s, std::streamsize n) {
        handshake(boost::asio::ssl::stream_base::server); // HTTPS servers read first
        if (fUseSSL)
            return stream.read_some(boost::asio::buffer(s, n));
        return stream.next_layer().read_some(boost::asio::buffer(s, n));
    }

    std::streamsize write(const char *s, std::streamsize n) {
        handshake(boost::asio::ssl::stream_base::client); // HTTPS clients write first
        if (fUseSSL)
            return boost::asio::write(stream, boost::asio::buffer(s, n));
        return boost::asio::write(stream.next_layer(), boost::asio::buffer(s, n));
    }

    bool connect(const std::string &server, const std::string &port) {
#if BOOST_VERSION >= 106900
        boost::asio::ip::tcp::resolver resolver(stream.get_executor());
#else
        boost::asio::ip::tcp::resolver resolver(stream.get_io_service());
#endif
        boost::asio::ip::tcp::resolver::query query(server.c_str(), port.c_str());
        boost::asio::ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
        boost::asio::ip::tcp::resolver::iterator end;
        boost::system::error_code error = boost::asio::error::host_not_found;
        while (error && endpoint_iterator != end) {
            stream.lowest_layer().close();
            stream.lowest_layer().connect(*endpoint_iterator++, error);
        }
        return (error)? false: true;
    }

private:
    bool fNeedHandshake;
    bool fUseSSL;

    // SSLIOStreamDevice &operator=(const SSLIOStreamDevice const &)=delete;
    // SSLIOStreamDevice &operator=(SSLIOStreamDevice const &&)=delete;
    // SSLIOStreamDevice(const SSLIOStreamDevice &)=delete;
    // SSLIOStreamDevice(SSLIOStreamDevice &&)=delete;

    boost::asio::ssl::stream<typename Protocol::socket> &stream;
};

class AcceptedConnection
{
public:
    virtual ~AcceptedConnection() {}
    virtual std::iostream &stream() = 0;
    virtual std::string peer_address_to_string() const = 0;
    virtual void close() = 0;
};

template <typename Protocol>
class AcceptedConnectionImpl : public AcceptedConnection
{
private:
    AcceptedConnectionImpl()=delete;
    AcceptedConnectionImpl(const AcceptedConnectionImpl &)=delete;
    AcceptedConnectionImpl(AcceptedConnectionImpl &&)=delete;
    AcceptedConnectionImpl &operator=(const AcceptedConnectionImpl &)=delete;
    AcceptedConnectionImpl &operator=(AcceptedConnectionImpl &&)=delete;

public:
#if BOOST_VERSION >= 106900
    AcceptedConnectionImpl(boost::asio::executor &io_service, boost::asio::ssl::context &context, bool fUseSSL) : sslStream(io_service, context), _d(sslStream, fUseSSL), _stream(_d) {}
#else
    AcceptedConnectionImpl(boost::asio::io_service &io_service, boost::asio::ssl::context &context, bool fUseSSL) : sslStream(io_service, context), _d(sslStream, fUseSSL), _stream(_d) {}
#endif

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

void bitrpc::ThreadRPCServer(void *parg) {
    // Make this thread recognisable as the RPC listener
    bitthread::manage::RenameThread((coin_param::strCoinName + "-rpclist").c_str());

    arg_data darg;
    //darg.fok = false;
    darg.parg = parg;
    net_node::vnThreadsRunning[THREAD_RPCLISTENER]++;
    ThreadRPCServer2(&darg);
    //if(! darg.fok) {
        net_node::vnThreadsRunning[THREAD_RPCLISTENER]--;
        printfc(std::string(darg.e.c_str()) + " : ThreadRPCServer()");
    //} else
        //net_node::vnThreadsRunning[THREAD_RPCLISTENER]--;

    printf("ThreadRPCServer exited\n");
}

// Sets up I/O resources to accept and handle a new connection.
#if BOOST_VERSION >= 106900
template <typename Protocol>
void bitrpc::RPCListen(boost::shared_ptr<boost::asio::basic_socket_acceptor<Protocol> > acceptor, boost::asio::ssl::context &context, const bool fUseSSL, arg_data *darg) {
    // Accept connection
    AcceptedConnectionImpl<Protocol> *conn = new(std::nothrow) AcceptedConnectionImpl<Protocol>(acceptor->get_executor(), context, fUseSSL);
    if (conn == nullptr) {
        darg->e = "RPCListen memory allocate failure.";
        darg->fok = false;
        return;
    }

    acceptor->async_accept(
        conn->sslStream.lowest_layer(),
        conn->peer,
        boost::bind(&RPCAcceptHandler<Protocol>,
            acceptor,
            boost::ref(context),
            fUseSSL,
            conn,
            boost::asio::placeholders::error,
            darg));
}
#elif BOOST_VERSION >= 106600
template <typename Protocol>
void bitrpc::RPCListen(boost::shared_ptr<boost::asio::basic_socket_acceptor<Protocol> > acceptor, boost::asio::ssl::context &context, const bool fUseSSL, arg_data *darg) {
    // Accept connection
    AcceptedConnectionImpl<Protocol> *conn = new(std::nothrow) AcceptedConnectionImpl<Protocol>(acceptor->get_io_service(), context, fUseSSL);
    if (conn == nullptr) {
        darg->e = "RPCListen memory allocate failure.";
        //darg->fok = false;
        return;
    }

    acceptor->async_accept(
        conn->sslStream.lowest_layer(),
        conn->peer,
        boost::bind(&RPCAcceptHandler<Protocol>,
            acceptor,
            boost::ref(context),
            fUseSSL,
            conn,
            boost::asio::placeholders::error,
            darg));
}
#else
template <typename Protocol, typename SocketAcceptorService>
void bitrpc::RPCListen(boost::shared_ptr<boost::asio::basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor, boost::asio::ssl::context &context, const bool fUseSSL, arg_data *darg) {
    // Accept connection
    AcceptedConnectionImpl<Protocol> *conn = new(std::nothrow) AcceptedConnectionImpl<Protocol>(acceptor->get_io_service(), context, fUseSSL);
    if (conn == nullptr) {
        darg->e = "RPCListen memory allocate failure.";
        //darg->fok = false;
        return;
    }

    acceptor->async_accept(
        conn->sslStream.lowest_layer(),
        conn->peer,
        boost::bind(&RPCAcceptHandler<Protocol, SocketAcceptorService>,
            acceptor,
            boost::ref(context),
            fUseSSL,
            conn,
            boost::asio::placeholders::error,
            darg));
}
#endif

// Accept and handle incoming connection.
#if BOOST_VERSION >= 106600
template <typename Protocol>
void bitrpc::RPCAcceptHandler(boost::shared_ptr<boost::asio::basic_socket_acceptor<Protocol> > acceptor, boost::asio::ssl::context &context, const bool fUseSSL, AcceptedConnection *conn, const boost::system::error_code &error, arg_data *darg) {
    net_node::vnThreadsRunning[THREAD_RPCLISTENER]++;

    // Immediately start accepting new connections, except when we're cancelled or our socket is closed.
    if (error != boost::asio::error::operation_aborted && acceptor->is_open())
        RPCListen(acceptor, context, fUseSSL, darg);

    AcceptedConnectionImpl<boost::asio::ip::tcp> *tcp_conn = dynamic_cast<AcceptedConnectionImpl<boost::asio::ip::tcp>* >(conn);
    if (tcp_conn == nullptr) {
        darg->e = "RPCAcceptHandler AcceptedConnectionImpl, downcast Error.";
        //darg->fok = false;
        return;
    }

    darg->parg = conn;
    if (error) {
        delete conn;
    } else if (tcp_conn && !ClientAllowed(tcp_conn->peer.address())) {
        // Restrict callers by IP.  It is important to
        // do this before starting client thread, to filter out
        // certain DoS and misbehaving clients.
        // Only send a 403 if we're not using SSL to prevent a DoS during the SSL handshake.
        if (! fUseSSL)
            conn->stream() << http::HTTPReply(HTTP_FORBIDDEN, "", false) << std::flush;
        delete conn;
    } else if (! bitthread::manage::NewThread(bitrpc::ThreadRPCServer3, darg)) {
        // start HTTP client thread
        printf("Failed to create RPC server client thread\n");
        delete conn;
    }

    //darg->parg = nullptr;
    //darg->fok = true;
    net_node::vnThreadsRunning[THREAD_RPCLISTENER]--;
}
#else
template <typename Protocol, typename SocketAcceptorService>
void bitrpc::RPCAcceptHandler(boost::shared_ptr<boost::asio::basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor, boost::asio::ssl::context &context, const bool fUseSSL, AcceptedConnection *conn, const boost::system::error_code &error, arg_data *darg) {
    net_node::vnThreadsRunning[THREAD_RPCLISTENER]++;

    // Immediately start accepting new connections, except when we're cancelled or our socket is closed.
    if (error != boost::asio::error::operation_aborted && acceptor->is_open())
        RPCListen(acceptor, context, fUseSSL, darg);

    AcceptedConnectionImpl<boost::asio::ip::tcp> *tcp_conn = dynamic_cast<AcceptedConnectionImpl<boost::asio::ip::tcp>* >(conn);
    if (tcp_conn == nullptr) {
        darg->e = "RPCAcceptHandler AcceptedConnectionImpl, downcast Error.";
        //darg->fok = false;
        return;
    }

    darg->parg = conn;
    if (error) {
        delete conn;
    } else if (tcp_conn && !ClientAllowed(tcp_conn->peer.address())) {
        // Restrict callers by IP.  It is important to
        // do this before starting client thread, to filter out
        // certain DoS and misbehaving clients.
        // Only send a 403 if we're not using SSL to prevent a DoS during the SSL handshake.
        if (! fUseSSL)
            conn->stream() << http::HTTPReply(HTTP_FORBIDDEN, "", false) << std::flush;
        delete conn;
    } else if (! bitthread::manage::NewThread(bitrpc::ThreadRPCServer3, darg)) {
        // start HTTP client thread
        printf("Failed to create RPC server client thread\n");
        delete conn;
    }

    //darg->parg = nullptr;
    //darg->fok = true;
    net_node::vnThreadsRunning[THREAD_RPCLISTENER]--;
}
#endif

void bitrpc::ThreadRPCServer2(void *parg) {
    printf("ThreadRPCServer started\n");
    arg_data *darg = reinterpret_cast<arg_data *>(parg);

    strRPCUserColonPass = map_arg::GetMapArgsString("-rpcuser") + ":" + map_arg::GetMapArgsString("-rpcpassword");
    if (map_arg::GetMapArgsString("-rpcpassword").empty()) {
        unsigned char rand_pwd[32];
        latest_crypto::random::GetStrongRandBytes(rand_pwd, 32);
        std::string strWhatAmI = "To use ";
        strWhatAmI += (coin_param::strCoinName + "d").c_str();
        if (map_arg::GetMapArgsCount("-server"))
            strWhatAmI = strprintfc(_("To use the %s option"), "\"-server\"");
        else if (map_arg::GetMapArgsCount("-daemon"))
            strWhatAmI = strprintfc(_("To use the %s option"), "\"-daemon\"");

        CClientUIInterface::uiInterface.ThreadSafeMessageBox(strprintfc(
            _("%s, you must set a rpcpassword in the configuration file:\n %s\n"
            "It is recommended you use the following random password:\n"
            "rpcuser=%srpc\n"
            "rpcpassword=%s\n"
            "(you do not need to remember this password)\n"
            "If the file does not exist, create it with owner-readable-only file permissions.\n"),
            strWhatAmI.c_str(),
            iofs::GetConfigFile().string().c_str(),
            coin_param::strCoinNameL.c_str(),
            base58::manage::EncodeBase58(&rand_pwd[0], &rand_pwd[0] + 32).c_str()),
            _("Error"), CClientUIInterface::OK | CClientUIInterface::MODAL);
        boot::StartShutdown();
        darg->error();
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
        if (! pathCertFile.is_complete())
            pathCertFile = boost::filesystem::path(iofs::GetDataDir()) / pathCertFile;
        if (boost::filesystem::exists(pathCertFile))
            context.use_certificate_chain_file(pathCertFile.string());
        else
            printf("ThreadRPCServer ERROR: missing server certificate file %s\n", pathCertFile.string().c_str());

        boost::filesystem::path pathPKFile(map_arg::GetArg("-rpcsslprivatekeyfile", "server.pem"));
        if (! pathPKFile.is_complete())
            pathPKFile = boost::filesystem::path(iofs::GetDataDir()) / pathPKFile;
        if (boost::filesystem::exists(pathPKFile))
            context.use_private_key_file(pathPKFile.string(), boost::asio::ssl::context::pem);
        else
            printf("ThreadRPCServer ERROR: missing server private key file %s\n", pathPKFile.string().c_str());

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

    // Try a dual IPv6/IPv4 socket, falling back to separate IPv4 and IPv6 sockets
    const bool loopback = !map_arg::GetMapArgsCount("-rpcallowip");
    boost::asio::ip::address bindAddress = loopback ? boost::asio::ip::address_v6::loopback() : boost::asio::ip::address_v6::any();
    boost::asio::ip::tcp::endpoint endpoint(bindAddress, map_arg::GetArg("-rpcport", GetDefaultRPCPort()));
    boost::system::error_code v6_only_error;
#if BOOST_VERSION >= 106600
    boost::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor(new boost::asio::ip::tcp::acceptor(io_context));
#else
    boost::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor(new boost::asio::ip::tcp::acceptor(io_service));
#endif
    boost::signals2::signal<void()> StopRequests;
    bool fListening = false;
    std::string strerr;
    boost::system::error_code err;
    do {
        acceptor->open(endpoint.protocol(), err); if(err) break;
        acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), err); if(err) break;

        // Try making the socket dual IPv6/IPv4 (if listening on the "any" address)
        acceptor->set_option(boost::asio::ip::v6_only(loopback), v6_only_error);
        acceptor->bind(endpoint, err); if(err) break;
        acceptor->listen(boost::asio::socket_base::max_connections, err); if(err) break;
        RPCListen(acceptor, context, fUseSSL, darg);

        // Cancel outstanding listen-requests for this acceptor when shutting down
        StopRequests.connect(boost::signals2::slot<void()>(static_cast<void (boost::asio::ip::tcp::acceptor::*)()>(&boost::asio::ip::tcp::acceptor::close), acceptor.get()).track(acceptor));
        fListening = true;
    } while (false);
    if(err)
        strerr = strprintfc(_("An error occurred while setting up the RPC port %u for listening on IPv6, falling back to IPv4"), endpoint.port());

    do {
        // If dual IPv6/IPv4 failed (or we're opening loopback interfaces only), open IPv4 separately
        if (!fListening || loopback || v6_only_error) {
            bindAddress = loopback ? boost::asio::ip::address_v4::loopback() : boost::asio::ip::address_v4::any();
            endpoint.address(bindAddress);
#if BOOST_VERSION >= 106600
            acceptor.reset(new boost::asio::ip::tcp::acceptor(io_context));
#else
            acceptor.reset(new boost::asio::ip::tcp::acceptor(io_service));
#endif
            acceptor->open(endpoint.protocol(), err); if(err) break;
            acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), err); if(err) break;
            acceptor->bind(endpoint, err); if(err) break;
            acceptor->listen(boost::asio::socket_base::max_connections, err); if(err) break;
            RPCListen(acceptor, context, fUseSSL, darg);

            // Cancel outstanding listen-requests for this acceptor when shutting down
            StopRequests.connect(boost::signals2::slot<void()>(static_cast<void (boost::asio::ip::tcp::acceptor::*)()>(&boost::asio::ip::tcp::acceptor::close), acceptor.get()).track(acceptor));
            fListening = true;
        }
    } while (false);
    if(err)
        strerr = strprintfc(_("An error occurred while setting up the RPC port %u for listening on IPv4"), endpoint.port());

    if (! fListening) {
        CClientUIInterface::uiInterface.ThreadSafeMessageBox(strerr, _("Error"), CClientUIInterface::OK | CClientUIInterface::MODAL);
        boot::StartShutdown();
        darg->error(strerr.c_str());
        return;
    }

    net_node::vnThreadsRunning[THREAD_RPCLISTENER]--;
    while (! args_bool::fShutdown) {
#if BOOST_VERSION >= 106600
        io_context.run_one();
#else
        io_service.run_one();
#endif
    }
    net_node::vnThreadsRunning[THREAD_RPCLISTENER]++;
    StopRequests();
    //darg->ok();
}

bool bitjson::JSONRequest::parse(const json_spirit::Value &valRequest, CBitrpcData &data) {
    // Parse request
    if (valRequest.type() != json_spirit::obj_type) {
        data.JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
        return false;
    }

    json_spirit::json_flags status;
    const json_spirit::Object &request = valRequest.get_obj(status);
    if(! status.fSuccess()) {data.JSONRPCError(RPC_JSON_ERROR, status.e); return false;}

    // Parse id now so errors from here on will have the id
    id = find_value(request, "id");

    // Parse method
    json_spirit::Value valMethod = find_value(request, "method");
    if (valMethod.type() == json_spirit::null_type) {
        data.JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
        return false;
    }
    if (valMethod.type() != json_spirit::str_type) {
        data.JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
        return false;
    }

    strMethod = valMethod.get_str(status);
    if(! status.fSuccess()) {
        data.JSONRPCError(RPC_JSON_ERROR, status.e);
        return false;
    }

    // Parse params
    json_spirit::Value valParams = find_value(request, "params");
    if (valParams.type() == json_spirit::array_type) {
        json_spirit::json_flags status;
        params = valParams.get_array(status);
        if(! status.fSuccess()) {data.JSONRPCError(RPC_JSON_ERROR, status.e); return false;}
    } else if (valParams.type() == json_spirit::null_type)
        params = json_spirit::Array();
    else {
        data.JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array");
        return false;
    }

    return true;
}

json_spirit::Object bitrpc::JSONRPCExecOne(const json_spirit::Value &req, CBitrpcData &data) {
    json_spirit::Object rpc_result;
    bitjson::JSONRequest jreq;
    do {
        if(! jreq.parse(req, data)) break;
        json_spirit::Value result = CRPCTable::execute(jreq.strMethod, jreq.params, data);
        rpc_result = json::JSONRPCReplyObj(result, json_spirit::Value::null, jreq.id);
    } while (false);
    if (data.ret == CBitrpcData::BITRPC_STATUS_ERROR)
        rpc_result = json::JSONRPCReplyObj(json_spirit::Value::null, data.e, jreq.id);
    if (data.ret == CBitrpcData::BITRPC_STATUS_EXCEPT)
        rpc_result = json::JSONRPCReplyObj(json_spirit::Value::null, bitjson::JSONRPCError(RPC_PARSE_ERROR, data.e), jreq.id);

    return rpc_result;
}

std::string bitrpc::JSONRPCExecBatch(const json_spirit::Array &vReq, CBitrpcData &data) {
    json_spirit::Array ret;
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); ++reqIdx) {
        ret.push_back(JSONRPCExecOne(vReq[reqIdx], data));
        if(data.ret != CBitrpcData::BITRPC_STATUS_OK)
            break;
    }
    json_spirit::json_flags status;
    std::string str = json_spirit::write_string(json_spirit::Value(ret), false, status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    str += "\n";
    data.JSONRPCSuccess(str);
    return str;
}

void bitrpc::ThreadRPCServer3(void *parg) {
    printf("ThreadRPCServer3 started\n");
    arg_data *darg = reinterpret_cast<arg_data *>(parg);

    // Make this thread recognisable as the RPC handler
    bitthread::manage::RenameThread((coin_param::strCoinName + "-rpchand").c_str());

    {
        LOCK(cs_THREAD_RPCHANDLER);
        ++net_node::vnThreadsRunning[THREAD_RPCHANDLER];
    }

    AcceptedConnection *conn = reinterpret_cast<AcceptedConnection *>(darg->parg);
    bool fRun = true;
    for (;;) {
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

        // Check authorization
        if (mapHeaders.count("authorization") == 0) {
            conn->stream() << http::HTTPReply(HTTP_UNAUTHORIZED, "", false) << std::flush;
            break;
        }
        if (! bitrpc::HTTPAuthorized(mapHeaders)) {
            printf("ThreadRPCServer incorrect password attempt from %s\n", conn->peer_address_to_string().c_str());

            // Deter brute-forcing short passwords. If this results in a DOS the user really shouldn't have their RPC port exposed.
            if (map_arg::GetMapArgsString("-rpcpassword").size() < 20)
                util::Sleep(250);

            conn->stream() << http::HTTPReply(HTTP_UNAUTHORIZED, "", false) << std::flush;
            break;
        }
        if (mapHeaders["connection"] == "close")
            fRun = false;

        bitjson::JSONRequest jreq;
        //CBitrpcData &data = static_cast<CBitrpcData &>(*darg);
        CBitrpcData data;
        data.param = CBitrpcData::BITRPC_PARAM_EXEC;
        data.ret = CBitrpcData::BITRPC_STATUS_ERROR;
        do {
            // Parse request
            json_spirit::Value valRequest;
            json_spirit::json_flags status;
            if (! read_string(strRequest, valRequest, status)) {
                printf("ThreadRPCServer3 JSON ParseError\n");
                data.JSONRPCError(RPC_PARSE_ERROR, "Parse error");
                break;
            }
            if(! status.fSuccess()) {data.JSONRPCError(RPC_JSON_ERROR, status.e); break;}

            std::string strReply;

            // singleton request
            if (valRequest.type() == json_spirit::obj_type) {
                if(! jreq.parse(valRequest, data)) break;
                json_spirit::Value result = CRPCTable::execute(jreq.strMethod, jreq.params, data);

                // Send reply
                json_spirit::json_flags status;
                strReply = json::JSONRPCReply(result, json_spirit::Value::null, jreq.id, status);
                if(! status.fSuccess()) {
                    data.JSONRPCError(RPC_PARSE_ERROR, "JSONRPCReply parse error");
                    break;
                }

            // array of requests
            } else if (valRequest.type() == json_spirit::array_type) {
                const json_spirit::Array &ary = valRequest.get_array(status);
                if(! status.fSuccess()) {data.JSONRPCError(RPC_JSON_ERROR, status.e); break;}
                strReply = JSONRPCExecBatch(ary, data);
            } else {
                data.JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");
                break;
            }

            if(data.ret == CBitrpcData::BITRPC_STATUS_OK)
                conn->stream() << http::HTTPReply(HTTP_OK, strReply, fRun) << std::flush;
        } while (false);
        if(data.ret == CBitrpcData::BITRPC_STATUS_ERROR) {
            printf("ThreadRPCServer3 JSON Error1\n");
            json_spirit::json_flags status;
            json::ErrorReply(conn->stream(), bitjson::JSONRPCError(data.code, data.e), jreq.id, status);
            if(! status.fSuccess()) {
                data.JSONRPCError(RPC_PARSE_ERROR, "JSONRPCError parse error");
                break;
            }
            break;
        }
        if (data.ret == CBitrpcData::BITRPC_STATUS_EXCEPT) {
            printf("ThreadRPCServer3 JSON Error2\n");
            json_spirit::json_flags status;
            json::ErrorReply(conn->stream(), bitjson::JSONRPCError(RPC_PARSE_ERROR, data.e), jreq.id, status);
            if(! status.fSuccess()) {
                data.JSONRPCError(RPC_PARSE_ERROR, "JSONRPCError parse error");
                break;
            }
            break;
        }
    } // for(;;)

    delete conn;
    {
        LOCK(cs_THREAD_RPCHANDLER);
        --net_node::vnThreadsRunning[THREAD_RPCHANDLER];
    }
}

json_spirit::Value CRPCTable::execute(const std::string &strMethod, const json_spirit::Array &params, CBitrpcData &data) {
    // secure allocator: json_spirit::Array includes.
    const CRPCCommand *pcmd = CRPCCmd::get_instance()[strMethod];
    if (! pcmd) {
        printf("ThreadRPCServer3 execute Error1\n");
        return data.JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");
    }

    std::string strWarning = block_alert::GetWarnings("rpc");
    if (!strWarning.empty() && !map_arg::GetBoolArg("-disablesafemode") && !pcmd->okSafeMode) {
        printf("ThreadRPCServer3 execute Error2\n");
        return data.JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, std::string("Safe mode: ") + strWarning);
    }

    json_spirit::Value result;
    data.param = CBitrpcData::BITRPC_PARAM_EXEC;
    data.ret = CBitrpcData::BITRPC_STATUS_EXCEPT;
    if (pcmd->unlocked)
        result = pcmd->actor(params, data);
    else {
        LOCK2(block_process::cs_main, entry::pwalletMain->cs_wallet);
        result = pcmd->actor(params, data);
    }

    if(data.ret == CBitrpcData::BITRPC_STATUS_EXCEPT) {
        printf("ThreadRPCServer3 execute Except 3\n");
        //data.code = RPC_MISC_ERROR;
        return data.e;
    } else if (data.ret == CBitrpcData::BITRPC_STATUS_ERROR) {
        printf("ThreadRPCServer3 execute Error 3\n");
        //data.code = RPC_MISC_ERROR;
        return data.e;
    } else {
        assert(data.ret == CBitrpcData::BITRPC_STATUS_OK);
        return result;
    }
}

json_spirit::Object bitrpc::CallRPC(CBitrpcData &data, const std::string &strMethod, const json_spirit::Array &params) {
    if (map_arg::GetMapArgsString("-rpcuser").empty() && map_arg::GetMapArgsString("-rpcpassword").empty()) {
        json_spirit::json_flags status;
        return data.runtime_error(strprintfc(
            _("You must set rpcpassword=<password> in the configuration file:\n%s\n"
              "If the file does not exist, create it with owner-readable-only file permissions."),
            iofs::GetConfigFile().string().c_str()), 0).get_obj(status);
    }

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
        json_spirit::json_flags status;
        return data.runtime_error("couldn't connect to server", 0).get_obj(status);
    }

    // HTTP basic authentication
    std::string strUserPass64 = base64::EncodeBase64(map_arg::GetMapArgsString("-rpcuser") + ":" + map_arg::GetMapArgsString("-rpcpassword"));
    std::map<std::string, std::string> mapRequestHeaders;
    mapRequestHeaders["Authorization"] = std::string("Basic ") + strUserPass64;

    // Send request
    json_spirit::json_flags status;
    std::string strRequest = json::JSONRPCRequest(strMethod, params, 1, status);
    if(! status.fSuccess()) {
        json_spirit::json_flags status;
        return data.runtime_error(status.e.c_str(), 0).get_obj(status);
    }
    std::string strPost = http::HTTPPost(strRequest, mapRequestHeaders);
    stream << strPost << std::flush;

    // Receive reply
    std::map<std::string, std::string> mapHeaders;
    std::string strReply;
    int nStatus = http::ReadHTTP(stream, mapHeaders, strReply);
    if (nStatus == HTTP_UNAUTHORIZED)
        return data.runtime_error("incorrect rpcuser or rpcpassword (authorization failed)", 0).get_obj(status);
    else if (nStatus >= 400 && nStatus != HTTP_BAD_REQUEST && nStatus != HTTP_NOT_FOUND && nStatus != HTTP_INTERNAL_SERVER_ERROR)
        return data.runtime_error(strprintf("server returned HTTP error %d", nStatus), 0).get_obj(status);
    else if (strReply.empty())
        return data.runtime_error("no response from server", 0).get_obj(status);

    // Parse reply
    json_spirit::Value valReply;
    if (! read_string(strReply, valReply, status))
        return data.runtime_error("couldn't parse reply from server", 0).get_obj(status);
    if(! status.fSuccess()) return data.runtime_error(status.e, 0).get_obj(status);

    const json_spirit::Object &reply = valReply.get_obj(status);
    if(! status.fSuccess()) return data.runtime_error(status.e, 0).get_obj(status);
    if (reply.empty())
        return data.runtime_error("expected reply to have result, error and id properties", 0).get_obj(status);

    json_spirit::Object &obj = data.JSONRPCSuccess(reply).get_obj(status);
    if(! status.fSuccess()) return data.runtime_error(status.e, 0).get_obj(status);
    return obj;
}

template<typename T>
void bitrpc::ConvertTo(CBitrpcData &data, json_spirit::Value &value, bool fAllowNull/* =false */) {
    if (fAllowNull && value.type() == json_spirit::null_type) {
        data.JSONRPCSuccess(json_spirit::Value::null);
        return;
    }

    if (value.type() == json_spirit::str_type) {
        // reinterpret string as unquoted json value
        json_spirit::Value value2;
        json_spirit::json_flags status;
        std::string strJSON = value.get_str(status);
        if(! status.fSuccess()) {
            data.JSONRPCError(RPC_JSON_ERROR, status.e);
            return;
        }
        if (! read_string(strJSON, value2, status)) {
            data.runtime_error(std::string("Error parsing JSON:") + strJSON);
            return;
        }
        if(! status.fSuccess()) {
            data.JSONRPCError(RPC_JSON_ERROR, status.e);
            return;
        }

        ConvertTo<T>(data, value2, fAllowNull);
        value = value2;
    } else {
        json_spirit::json_flags status;
        value = value.get_value<T>(status);
        if(! status.fSuccess()) {
            data.JSONRPCError(RPC_JSON_ERROR, status.e);
            return;
        }
    }

    data.JSONRPCSuccess(json_spirit::Value::null);
}

// Convert strings to command-specific RPC representation
json_spirit::Array bitrpc::RPCConvertValues(CBitrpcData &data, const std::string &strMethod, const std::vector<std::string> &strParams) {
    json_spirit::Array params;
    for(const std::string &param: strParams)
        params.push_back(param);

    size_t n = params.size();

    // Special case non-string parameter types
    if (strMethod == "stop"                   && n > 0) { ConvertTo<bool>(data, params[0]); }
    if (strMethod == "getaddednodeinfo"       && n > 0) { ConvertTo<bool>(data, params[0]); }
    if (strMethod == "sendtoaddress"          && n > 1) { ConvertTo<double>(data, params[1]); }
    if (strMethod == "mergecoins"             && n > 0) { ConvertTo<double>(data, params[0]); }
    if (strMethod == "mergecoins"             && n > 1) { ConvertTo<double>(data, params[1]); }
    if (strMethod == "mergecoins"             && n > 2) { ConvertTo<double>(data, params[2]); }
    if (strMethod == "settxfee"               && n > 0) { ConvertTo<double>(data, params[0]); }
    if (strMethod == "getreceivedbyaddress"   && n > 1) { ConvertTo<int64_t>(data, params[1]); }
    if (strMethod == "getreceivedbyaccount"   && n > 1) { ConvertTo<int64_t>(data, params[1]); }
    if (strMethod == "listreceivedbyaddress"  && n > 0) { ConvertTo<int64_t>(data, params[0]); }
    if (strMethod == "listreceivedbyaddress"  && n > 1) { ConvertTo<bool>(data, params[1]); }
    if (strMethod == "listreceivedbyaccount"  && n > 0) { ConvertTo<int64_t>(data, params[0]); }
    if (strMethod == "listreceivedbyaccount"  && n > 1) { ConvertTo<bool>(data, params[1]); }
    if (strMethod == "getbalance"             && n > 1) { ConvertTo<int64_t>(data, params[1]); }
    if (strMethod == "getblock"               && n > 1) { ConvertTo<bool>(data, params[1]); }
    if (strMethod == "getblockbynumber"       && n > 0) { ConvertTo<int64_t>(data, params[0]); }
    if (strMethod == "dumpblockbynumber"      && n > 0) { ConvertTo<int64_t>(data, params[0]); }
    if (strMethod == "getblockbynumber"       && n > 1) { ConvertTo<bool>(data, params[1]); }
    if (strMethod == "getblockhash"           && n > 0) { ConvertTo<int64_t>(data, params[0]); }
    if (strMethod == "getblockqhash"          && n > 0) { ConvertTo<int64_t>(data, params[0]); }
    if (strMethod == "move"                   && n > 2) { ConvertTo<double>(data, params[2]); }
    if (strMethod == "move"                   && n > 3) { ConvertTo<int64_t>(data, params[3]); }
    if (strMethod == "sendfrom"               && n > 2) { ConvertTo<double>(data, params[2]); }
    if (strMethod == "sendfrom"               && n > 3) { ConvertTo<int64_t>(data, params[3]); }
    if (strMethod == "listtransactions"       && n > 1) { ConvertTo<int64_t>(data, params[1]); }
    if (strMethod == "listtransactions"       && n > 2) { ConvertTo<int64_t>(data, params[2]); }
    if (strMethod == "listaccounts"           && n > 0) { ConvertTo<int64_t>(data, params[0]); }
    if (strMethod == "walletpassphrase"       && n > 1) { ConvertTo<int64_t>(data, params[1]); }
    if (strMethod == "walletpassphrase"       && n > 2) { ConvertTo<bool>(data, params[2]); }
    if (strMethod == "getblocktemplate"       && n > 0) { ConvertTo<json_spirit::Object>(data, params[0]); }
    if (strMethod == "listsinceblock"         && n > 1) { ConvertTo<int64_t>(data, params[1]); }
    if (strMethod == "scaninput"              && n > 0) { ConvertTo<json_spirit::Object>(data, params[0]); }
    if (strMethod == "sendalert"              && n > 2) { ConvertTo<int64_t>(data, params[2]); }
    if (strMethod == "sendalert"              && n > 3) { ConvertTo<int64_t>(data, params[3]); }
    if (strMethod == "sendalert"              && n > 4) { ConvertTo<int64_t>(data, params[4]); }
    if (strMethod == "sendalert"              && n > 5) { ConvertTo<int64_t>(data, params[5]); }
    if (strMethod == "sendalert"              && n > 6) { ConvertTo<int64_t>(data, params[6]); }
    if (strMethod == "sendmany"               && n > 1) { ConvertTo<json_spirit::Object>(data, params[1]); }
    if (strMethod == "sendmany"               && n > 2) { ConvertTo<int64_t>(data, params[2]); }
    if (strMethod == "reservebalance"         && n > 0) { ConvertTo<bool>(data, params[0]); }
    if (strMethod == "reservebalance"         && n > 1) { ConvertTo<double>(data, params[1]); }
    if (strMethod == "addmultisigaddress"     && n > 0) { ConvertTo<int64_t>(data, params[0]); }
    if (strMethod == "addmultisigaddress"     && n > 1) { ConvertTo<json_spirit::Array>(data, params[1]); }
    if (strMethod == "listunspent"            && n > 0) { ConvertTo<int64_t>(data, params[0]); }
    if (strMethod == "listunspent"            && n > 1) { ConvertTo<int64_t>(data, params[1]); }
    if (strMethod == "listunspent"            && n > 2) { ConvertTo<json_spirit::Array>(data, params[2]); }
    if (strMethod == "getrawtransaction"      && n > 1) { ConvertTo<int64_t>(data, params[1]); }
    if (strMethod == "createrawtransaction"   && n > 0) { ConvertTo<json_spirit::Array>(data, params[0]); }
    if (strMethod == "createrawtransaction"   && n > 1) { ConvertTo<json_spirit::Object>(data, params[1]); }
    if (strMethod == "createmultisig"         && n > 0) { ConvertTo<int64_t>(data, params[0]); }
    if (strMethod == "createmultisig"         && n > 1) { ConvertTo<json_spirit::Array>(data, params[1]); }
    if (strMethod == "signrawtransaction"     && n > 1) { ConvertTo<json_spirit::Array>(data, params[1], true); }
    if (strMethod == "signrawtransaction"     && n > 2) { ConvertTo<json_spirit::Array>(data, params[2], true); }
    if (strMethod == "keypoolrefill"          && n > 0) { ConvertTo<int64_t>(data, params[0]); }
    if (strMethod == "keypoolreset"           && n > 0) { ConvertTo<int64_t>(data, params[0]); }
    if (strMethod == "importaddress"          && n > 2) { ConvertTo<bool>(data, params[2]); }
    if (strMethod == "importprivkey"          && n > 2) { ConvertTo<bool>(data, params[2]); }

    if(data.fSuccess())
        data.JSONRPCSuccess(json_spirit::Value::null);

    return params;
}

int bitrpc::CommandLineRPC(int argc, char *argv[]) {
    std::string strPrint;
    int nRet = 0;
    CBitrpcData data;
    data.param = CBitrpcData::BITRPC_PARAM_EXEC;

    // Skip switches
    while (argc > 1 && util::IsSwitchChar(argv[1][0])) {
        --argc;
        ++argv;
    }

    // Method
    if (argc < 2) {
        data.runtime_error("too few parameters");
        return 1;
    }
    std::string strMethod = argv[1];

    // Parameters default to strings
    std::vector<std::string> strParams(&argv[2], &argv[argc]);
    json_spirit::Array params = RPCConvertValues(data, strMethod, strParams);
    if(! data.fSuccess()) {
        data.runtime_error("CMD Error");
        return 2;
    }

    // Execute
    json_spirit::Object reply = CallRPC(data, strMethod, params);

    if(data.ret == CBitrpcData::BITRPC_STATUS_OK) {
        // Parse reply
        const json_spirit::Value &result = find_value(reply, "result");
        const json_spirit::Value &error = find_value(reply, "error");
        json_spirit::json_flags status;
        if (error.type() != json_spirit::null_type) {
            // Error
            std::string err = write_string(error, false, status);
            if(! status.fSuccess()) {
                data.runtime_error(status.e);
                return 4;
            }
            strPrint = "error: " + err;
            const json_spirit::Object &obj = error.get_obj(status);
            if(! status.fSuccess()) {data.JSONRPCError(RPC_JSON_ERROR, status.e); return 6;}
            int code = find_value(obj, "code").get_int(status);
            if(! status.fSuccess()) {data.JSONRPCError(RPC_JSON_ERROR, status.e); return 7;}
            nRet = abs(code);
        } else {
            // Result
            if (result.type() == json_spirit::null_type)
                strPrint.clear();
            else if (result.type() == json_spirit::str_type) {
                strPrint = result.get_str(status);
                if(! status.fSuccess()) {
                    data.runtime_error(status.e);
                    return 3;
                }
            } else {
                strPrint = write_string(result, true, status);
                if(! status.fSuccess()) {
                    data.runtime_error(status.e);
                    return 5;
                }
            }
        }
    } else if (data.ret == CBitrpcData::BITRPC_STATUS_EXCEPT) {
        strPrint = std::string("error: ") + data.e;
        nRet = 87;
    } else {
        //excep::PrintException(nullptr, "CommandLineRPC()");
        strPrint = std::string("CommandLineRPC(): ") + data.e;
        nRet = 87;
    }

    if (! strPrint.empty())
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());

    return nRet;
}
