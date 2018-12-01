// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef _BITCOINRPC_H_
#define _BITCOINRPC_H_ 1

#include <string>
#include <list>
#include <map>

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "util.h"
#include "checkpoints.h"
#include "base58.h"

//
// HTTP status codes
//
enum HTTPStatusCode
{
    HTTP_OK                    = 200,
    HTTP_BAD_REQUEST           = 400,
    HTTP_UNAUTHORIZED          = 401,
    HTTP_FORBIDDEN             = 403,
    HTTP_NOT_FOUND             = 404,
    HTTP_INTERNAL_SERVER_ERROR = 500
};

//
// Bitcoin RPC error codes
//
enum RPCErrorCode
{
    // Standard JSON-RPC 2.0 errors
    RPC_INVALID_REQUEST  = -32600,
    RPC_METHOD_NOT_FOUND = -32601,
    RPC_INVALID_PARAMS   = -32602,
    RPC_INTERNAL_ERROR   = -32603,
    RPC_PARSE_ERROR      = -32700,

    // General application defined errors
    RPC_MISC_ERROR                  = -1,  // std::exception thrown in command handling
    RPC_FORBIDDEN_BY_SAFE_MODE      = -2,  // Server is in safe mode, and command is not allowed in safe mode
    RPC_TYPE_ERROR                  = -3,  // Unexpected type was passed as parameter
    RPC_INVALID_ADDRESS_OR_KEY      = -5,  // Invalid address or key
    RPC_OUT_OF_MEMORY               = -7,  // Ran out of memory during operation
    RPC_INVALID_PARAMETER           = -8,  // Invalid, missing or duplicate parameter
    RPC_DATABASE_ERROR              = -20, // Database error
    RPC_DESERIALIZATION_ERROR       = -22, // Error parsing or validating structure in raw format

    // P2P client errors
    RPC_CLIENT_NOT_CONNECTED        = -9,  // Bitcoin is not connected
    RPC_CLIENT_IN_INITIAL_DOWNLOAD  = -10, // Still downloading initial blocks

    // Wallet errors
    RPC_WALLET_ERROR                = -4,  // Unspecified problem with wallet (key not found etc.)
    RPC_WALLET_INSUFFICIENT_FUNDS   = -6,  // Not enough funds in wallet or account
    RPC_WALLET_INVALID_ACCOUNT_NAME = -11, // Invalid account name
    RPC_WALLET_KEYPOOL_RAN_OUT      = -12, // Keypool ran out, call keypoolrefill first
    RPC_WALLET_UNLOCK_NEEDED        = -13, // Enter the wallet passphrase with walletpassphrase first
    RPC_WALLET_PASSPHRASE_INCORRECT = -14, // The wallet passphrase entered was incorrect
    RPC_WALLET_WRONG_ENC_STATE      = -15, // Command given in wrong wallet encryption state (encrypting an encrypted wallet etc.)
    RPC_WALLET_ENCRYPTION_FAILED    = -16, // Failed to encrypt the wallet
    RPC_WALLET_ALREADY_UNLOCKED     = -17  // Wallet is already unlocked
};

//
// JSON protocol
//
namespace json
{
    std::string JSONRPCRequest(const std::string &strMethod, const json_spirit::Array &params, const json_spirit::Value &id);
    json_spirit::Object JSONRPCReplyObj(const json_spirit::Value &result, const json_spirit::Value &error, const json_spirit::Value &id);
    std::string JSONRPCReply(const json_spirit::Value &result, const json_spirit::Value &error, const json_spirit::Value &id);
    void ErrorReply(std::ostream &stream, const json_spirit::Object &objError, const json_spirit::Value &id);
}

//
// HTTP protocol
//
namespace http
{
    std::string HTTPPost(const std::string &strMsg, const std::map<std::string, std::string> &mapRequestHeaders);
    std::string HTTPReply(int nStatus, const std::string &strMsg, bool keepalive);
    int ReadHTTPStatus(std::basic_istream<char> &stream, int &proto);
    int ReadHTTPHeader(std::basic_istream<char> &stream, std::map<std::string, std::string> &mapHeadersRet);
    int ReadHTTP(std::basic_istream<char> &stream, std::map<std::string, std::string> &mapHeadersRet, std::string &strMessageRet);
}

//
// JSON Basis
//
namespace bitjson
{
    inline json_spirit::Object JSONRPCError(int code, const std::string &message) {
        json_spirit::Object error;
        error.push_back(json_spirit::Pair("code", code));
        error.push_back(json_spirit::Pair("message", message));
        return error;
    }

    inline std::string rfc1123Time() {
        return util::DateTimeStrFormat("%a, %d %b %Y %H:%M:%S +0000", bitsystem::GetTime());
    }

    class JSONRequest
    {
    private:
        JSONRequest(const JSONRequest &); // {}
        JSONRequest &operator=(const JSONRequest &); // {}
    public:
        json_spirit::Value id;
        std::string strMethod;
        json_spirit::Array params;

        JSONRequest() { id = json_spirit::Value::null; }
        void parse(const json_spirit::Value &valRequest);
    };
}

//
// Utilities: convert hex-encoded Values
// (throws error if not hex).
//
class hexrpc : private no_instance
{
public:
    static uint256 ParseHashV(const json_spirit::Value &v, std::string strName) {
        std::string strHex;
        if (v.type() == json_spirit::Value_type::str_type) {
            strHex = v.get_str();
        }
        if (! hex::IsHex(strHex)) { // Note: IsHex("") is false
            throw bitjson::JSONRPCError(RPCErrorCode::RPC_INVALID_PARAMETER, strName + " must be hexadecimal string (not '" + strHex + "')");
        }

        uint256 result;
        result.SetHex(strHex);
        return result;
    }

    static uint256 ParseHashO(const json_spirit::Object &o, std::string strKey) {
        return hexrpc::ParseHashV(json_spirit::find_value(o, strKey), strKey);
    }

    static std::vector<unsigned char> ParseHexV(const json_spirit::Value &v, std::string strName) {
        std::string strHex;
        if (v.type() == json_spirit::Value_type::str_type) {
            strHex = v.get_str();
        }
        if (! hex::IsHex(strHex)) {
            throw bitjson::JSONRPCError(RPCErrorCode::RPC_INVALID_PARAMETER, strName + " must be hexadecimal string (not '" + strHex + "')");
        }
        return hex::ParseHex(strHex);
    }

    static std::vector<unsigned char> ParseHexO(const json_spirit::Object &o, std::string strKey) {
        return hexrpc::ParseHexV(json_spirit::find_value(o, strKey), strKey);
    }
};

//
// bitrpc
// Bitcoin RPC Thread
//
class AcceptedConnection;
template <typename Protocol> class AcceptedConnectionImpl;
class bitrpc : private no_instance
{
#ifdef QT_GUI
    friend class RPCExecutor;    // QT-Window Console Execute Class
#endif

private:
    static std::string strRPCUserColonPass;
    static CCriticalSection cs_THREAD_RPCHANDLER;

    static unsigned short GetDefaultRPCPort();

    static void ThreadRPCServer2(void *parg);
    static void ThreadRPCServer3(void *parg);
#if BOOST_VERSION >= 106600
    template <typename Protocol>
    static void RPCAcceptHandler(boost::shared_ptr<boost::asio::basic_socket_acceptor<Protocol> > acceptor, boost::asio::ssl::context &context, const bool fUseSSL, AcceptedConnection *conn, const boost::system::error_code &error);
#else
    template <typename Protocol, typename SocketAcceptorService>
    static void RPCAcceptHandler(boost::shared_ptr<boost::asio::basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor, boost::asio::ssl::context &context, const bool fUseSSL, AcceptedConnection *conn, const boost::system::error_code &error);
#endif

#if BOOST_VERSION >= 106600
    template <typename Protocol>
    static void RPCListen(boost::shared_ptr<boost::asio::basic_socket_acceptor<Protocol> > acceptor, boost::asio::ssl::context &context, const bool fUseSSL);
#else
    template <typename Protocol, typename SocketAcceptorService>
    static void RPCListen(boost::shared_ptr<boost::asio::basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor, boost::asio::ssl::context &context, const bool fUseSSL);
#endif

    static bool HTTPAuthorized(std::map<std::string, std::string> &mapHeaders);
    static bool ClientAllowed(const boost::asio::ip::address &address);

    static json_spirit::Object JSONRPCExecOne(const json_spirit::Value &req);
    static std::string JSONRPCExecBatch(const json_spirit::Array &vReq);

    /**
     ** Convert parameter values for RPC call from strings to command-specific JSON objects.
     */
    template<typename T> static void ConvertTo(json_spirit::Value &value, bool fAllowNull = false);
    static json_spirit::Array RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams);

    static json_spirit::Object CallRPC(const std::string &strMethod, const json_spirit::Array &params);

public:
    static void ThreadRPCServer(void* parg);
    static int CommandLineRPC(int argc, char *argv[]);

    /*
    ** Type-check arguments; throws bitjson::JSONRPCError if wrong type given. Does not check that
    ** the right number of arguments are passed, just that any passed are the correct type.
    ** Use like: RPCTypeCheck(params, boost::assign::list_of(str_type)(int_type)(obj_type));
    */
    static void RPCTypeCheck(const json_spirit::Array &params, const std::list<json_spirit::Value_type> &typesExpected, bool fAllowNull=false);

    /*
    ** Check for expected keys/value types in an Object.
    ** Use like: RPCTypeCheck(object, boost::assign::map_list_of("name", str_type)("value", int_type));
    */
    static void RPCTypeCheck(const json_spirit::Object &o, const std::map<std::string, json_spirit::Value_type> &typesExpected, bool fAllowNull=false);
};

//
// Bitcoin RPC command dispatcher.
// Singleton Class
//
class CWalletTx;
class CWalletDB;
class CAccountingEntry;
class CBlock;
class CBlockIndex;
class CRPCTable
{
#ifdef QT_GUI
public:
    class CRPCTable_GUI : private no_instance    // QT-Window call from the outside.
    {
        friend class CRPCTable;
    public:
        static double GetDifficulty(const CBlockIndex *blockindex = NULL) {
            return CRPCTable::GetDifficulty(blockindex);
        }
        static double GetPoSKernelPS() {
            return CRPCTable::GetPoSKernelPS();
        }
        static json_spirit::Value execute(const std::string &method, const json_spirit::Array &params) {
            return tableRPC.execute(method, params);
        }
    };
#endif

    friend class bitrpc;

private:
    CRPCTable(const CRPCTable &); // {}
    CRPCTable &operator=(const CRPCTable &); // {}

    CRPCTable();

    typedef json_spirit::Value (*rpcfn_type)(const json_spirit::Array &params, bool fHelp);        // Bitcoin RPC prototype
    class CRPCCommand
    {
    public:
        const char *name;
        rpcfn_type actor;
        bool okSafeMode;
        bool unlocked;
    };
    static const CRPCCommand vRPCCommands[91];    // Bitcoin RPC Command

    //
    // map command
    //
    std::map<std::string, const CRPCCommand *> mapCommands;

    //
    // Helper
    //
    struct tallyitem    // std::map<std::string, tallyitem>
    {
        int64_t nAmount;
        int nConf;
        tallyitem() {
            nAmount = 0;
            nConf = std::numeric_limits<int>::max();
        }
    };
    static std::string HelpRequiringPassphrase();
    static void EnsureWalletIsUnlocked();
    static void WalletTxToJSON(const CWalletTx &wtx, json_spirit::Object &entry);
    static std::string AccountFromValue(const json_spirit::Value &value);
    static CBitcoinAddress GetAccountAddress(std::string strAccount, bool bForceNew=false);
    static void GetAccountAddresses(std::string strAccount, std::set<CBitcoinAddress> &setAddress);
    static int64_t GetAccountBalance(CWalletDB &walletdb, const std::string &strAccount, int nMinDepth, const isminefilter &filter);
    static int64_t GetAccountBalance(const std::string &strAccount, int nMinDepth, const isminefilter &filter);
    static json_spirit::Value ListReceived(const json_spirit::Array &params, bool fByAccounts);
    static void MaybePushAddress(json_spirit::Object &entry, const CBitcoinAddress &dest);
    static void ListTransactions(const CWalletTx &wtx, const std::string &strAccount, int nMinDepth, bool fLong, json_spirit::Array &ret, const isminefilter &filter);
    static void AcentryToJSON(const CAccountingEntry &acentry, const std::string &strAccount, json_spirit::Array &ret);

    static void ScriptPubKeyToJSON(const CScript &scriptPubKey, json_spirit::Object &out, bool fIncludeHex);
    static void TxToJSON(const CTransaction &tx, const uint256 &hashBlock, json_spirit::Object &entry);

    static double GetDifficulty(const CBlockIndex *blockindex = NULL);
    static double GetPoWMHashPS();
    static double GetPoSKernelPS();
    static json_spirit::Object blockToJSON(const CBlock &block, const CBlockIndex *blockindex, bool fPrintTransactionDetail);
    static bool ExportBlock(const std::string &strBlockHash, const CDataStream &ssBlock);

    static std::string HexBits(unsigned int nBits);
    static json_spirit::Value ValueFromAmount(int64_t amount);
    static int64_t AmountFromValue(const json_spirit::Value &value);

    //
    // Thread and CCriticalSection
    //
    static CCriticalSection cs_nWalletUnlockTime;
    static int64_t nWalletUnlockTime;
    static void ThreadTopUpKeyPool(void *parg);
    static void ThreadCleanWalletPassphrase(void *parg);

    /**
     * Execute a method.
     * @param method   Method to execute
     * @param params   Array of arguments (JSON objects)
     * @returns Result of the call.
     * @throws an exception (json_spirit::Value) when an error happens.
     *
     * Note: Call for tableRPC object (Call from Singleton object directly, so No static)
     */
    json_spirit::Value execute(const std::string &method, const json_spirit::Array &params) const;
    std::string help(std::string name) const;
    const CRPCCommand *operator[](std::string name) const;

private:
    //
    // Singleton object instance, bitcoinrpc.cpp
    //
    static const CRPCTable tableRPC;

private:
    //
    // Bitcoin RPC function
    // Note: Do not call them directly.(private method)
    //
    static json_spirit::Value help(const json_spirit::Array &params, bool fHelp); // in bitcoinrpc.cpp
    static json_spirit::Value stop(const json_spirit::Array &params, bool fHelp);

    static json_spirit::Value getconnectioncount(const json_spirit::Array &params, bool fHelp); // in rpcnet.cpp
    static json_spirit::Value getpeerinfo(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getaddrmaninfo(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value addnode(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getaddednodeinfo(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value dumpwallet(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value importwallet(const json_spirit::Array &params, bool fHelp);

    static json_spirit::Value dumpprivkey(const json_spirit::Array &params, bool fHelp); // in rpcdump.cpp
    static json_spirit::Value importprivkey(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value importaddress(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value removeaddress(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getnettotals(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value ntptime(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value sendalert(const json_spirit::Array &params, bool fHelp);

    static json_spirit::Value getsubsidy(const json_spirit::Array &params, bool fHelp);    // in rpcmining.cpp
    static json_spirit::Value getmininginfo(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value scaninput(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getwork(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getworkex(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getblocktemplate(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value submitblock(const json_spirit::Array &params, bool fHelp);

    static json_spirit::Value getnewaddress(const json_spirit::Array &params, bool fHelp); // in rpcwallet.cpp
    static json_spirit::Value getaccountaddress(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value setaccount(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getaccount(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getaddressesbyaccount(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value sendtoaddress(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value signmessage(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value verifymessage(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getreceivedbyaddress(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getreceivedbyaccount(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getbalance(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value movecmd(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value sendfrom(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value sendmany(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value addmultisigaddress(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value addredeemscript(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value listreceivedbyaddress(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value listreceivedbyaccount(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value listtransactions(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value listaddressgroupings(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value listaccounts(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value listsinceblock(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value gettransaction(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value backupwallet(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value keypoolrefill(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value keypoolreset(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value walletpassphrase(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value walletpassphrasechange(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value walletlock(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value encryptwallet(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value validateaddress(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getinfo(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value reservebalance(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value checkwallet(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value repairwallet(const json_spirit::Array &params, bool fHelp);
    // static json_spirit::Value resendtx(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value resendwallettransactions(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value makekeypair(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value mergecoins(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value newmalleablekey(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value adjustmalleablekey(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value adjustmalleablepubkey(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value listmalleableviews(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value dumpmalleablekey(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value importmalleablekey(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value dumppem(const json_spirit::Array &params, bool fHelp);

    static json_spirit::Value encryptdata(const json_spirit::Array &params, bool fHelp); // in rpccrypt.cpp
    static json_spirit::Value decryptdata(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value encryptmessage(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value decryptmessage(const json_spirit::Array &params, bool fHelp);

    static json_spirit::Value getrawtransaction(const json_spirit::Array &params, bool fHelp); // in rcprawtransaction.cpp
    static json_spirit::Value listunspent(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value createrawtransaction(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value decoderawtransaction(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value createmultisig(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value decodescript(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value signrawtransaction(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value sendrawtransaction(const json_spirit::Array &params, bool fHelp);

    static json_spirit::Value getbestblockhash(const json_spirit::Array &params, bool fHelp); // in rpcblockchain.cpp
    static json_spirit::Value getblockcount(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getdifficulty(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value settxfee(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getrawmempool(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getblockhash(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getblock(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getblockbynumber(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value dumpblock(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value dumpblockbynumber(const json_spirit::Array &params, bool fHelp);
    static json_spirit::Value getcheckpoint(const json_spirit::Array &params, bool fHelp);
};

#endif
//@
