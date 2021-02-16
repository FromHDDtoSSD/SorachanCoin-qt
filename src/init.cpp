// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txdb.h>
#include <walletdb.h>
#include <rpc/bitcoinrpc.h>
#include <net.h>
#include <init.h>
#include <util.h>
#include <ipcollector.h>
#include <ui_interface.h>
#include <checkpoints.h>
#include <miner.h>
#include <boot/shutdown.h>
#include <block/block_process.h>
#include <block/block_check.h>
#include <quantum/quantum.h>
#include <prime/autocheckpoint.h>
#include <boost/format.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/convenience.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <openssl/crypto.h>
#include <util/time.h>
#include <util/logging.h>
#include <util/thread.h>
#include <libstr/cmstring.h>
#include <const/validation.h>
#include <const/net_processing.h>
#include <const/net_params.h>
#include <util/system.h>

#ifndef WIN32
# include <signal.h>
#endif

CClientUIInterface CClientUIInterface::uiInterface;
std::string entry::strWalletFileName;
CWallet *entry::pwalletMain = nullptr;
enum entry::bip66Mode entry::b66mode = entry::Bip66_ADVISORY;

//
// Shutdown
//
void entry::ExitTimeout(void *parg)
{
    (void)parg;
#ifdef WIN32
    util::Sleep(5000);
    ExitProcess(0);
#endif
}

void boot::Shutdown(void *parg)
{
    (void)parg;
    static CCriticalSection cs_Shutdown;
    static bool fTaken;

    // Make this thread recognisable as the shutdown thread
    bitthread::RenameThread(strCoinName "-shutoff");

    bool fFirstThread = false;
    {
        TRY_LOCK(cs_Shutdown, lockShutdown);
        if (lockShutdown) {
            fFirstThread = !fTaken;
            fTaken = true;
        }
    }

    static bool fExit = false;
    if (fFirstThread) {
        args_bool::fShutdown = true;
        args_bool::fRequestShutdown = true;
        block_info::nTransactionsUpdated++;
        // CTxDB().Close();
        CDBEnv::bitdb.Flush(false);
        net_node::StopNode();
        CDBEnv::bitdb.Flush(true);
        boost::filesystem::remove(iofs::GetPidFile());

        wallet_process::manage::UnregisterWallet(entry::pwalletMain);
        delete entry::pwalletMain;

        if(! bitthread::NewThread(entry::ExitTimeout, nullptr))
            bitthread::thread_error(std::string(__func__) + " :ExitTimeout");
        util::Sleep(50);
        printf("%s exited\n\n", strCoinName);
        fExit = true;
#ifndef QT_GUI
        // ensure non-UI client gets exited here, but let Bitcoin-Qt reach 'return 0;' in bitcoin.cpp
        ::exit(0);
#endif
    } else {
        while (! fExit)
        {
            util::Sleep(500);
        }
        util::Sleep(100);
        bitthread::ExitThread(0);
    }
}

#ifndef WIN32
void entry::HandleSIGTERM(int)
{
    args_bool::fRequestShutdown = true;
}

void entry::HandleSIGHUP(int)
{
    args_bool::fReopenDebugLog = true;
}
#endif

//
// Start
//
#if !defined(QT_GUI)
bool entry::AppInit(int argc, char *argv[])
{
    bool fRet = false;
    try
    {
        //
        // Parameters
        //
        // If Qt is used, parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main()
        //
        if(! map_arg::ParseParameters(argc, argv)) {
            fprintf(stderr, "Error: map_arg::ParseParameters");
            boot::Shutdown(nullptr);
        }

        std::string args_error;
        if(! ARGS.ParseParameters(argc, argv, args_error)) {
            fprintf(stderr, "Error: ARGS::ParseParameters %s", args_error.c_str());
            boot::Shutdown(nullptr);
        }

        if (! boost::filesystem::is_directory(iofs::GetDataDir(false))) {
            fprintf(stderr, "Error: Specified directory does not exist\n");
            boot::Shutdown(nullptr);
        }
        if(! map_arg::ReadConfigFile()) {
            fprintf(stderr, "Error: map_arg::ReadConfigFile()");
            boot::Shutdown(nullptr);
        }

        std::string config_error;
        if(! ARGS.ReadConfigFiles(config_error)) {
            fprintf(stderr, "Error: ARGS::ReadConfigFile() %s", config_error.c_str());
            boot::Shutdown(nullptr);
        }

        if (map_arg::GetMapArgsCount("-?") || map_arg::GetMapArgsCount("--help")) {
            //
            // First part of help message is specific to bitcoind / RPC client
            //
            std::string strUsage = std::string(_(strCoinName " version")) +
                  " " + format_version::FormatFullVersion() + "\n\n" + _("Usage:") + "\n" +
                  "  " strCoinName "d [options]                     " + "\n" +
                  "  " strCoinName "d [options] <command> [params]  " + _("Send command to -server or " strCoinName "d") + "\n" +
                  "  " strCoinName "d [options] help                " + _("List commands") + "\n" +
                  "  " strCoinName "d [options] help <command>      " + _("Get help for a command") + "\n";

            strUsage += "\n" + HelpMessage();

            fprintf(stdout, "%s", strUsage.c_str());
            return false;
        }

        //
        // Command-line RPC
        //
        for (int i = 1; i < argc; ++i)
        {
            if (!util::IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], strCoinName ":")) {
                args_bool::fCommandLine = true;
            }
        }

        if (args_bool::fCommandLine) {
            int ret = bitrpc::CommandLineRPC(argc, argv);
            exit(ret);
        }

        fRet = AppInit2();
    } catch (const std::exception &e) {
        excep::PrintException(&e, "AppInit()");
    } catch (...) {
        excep::PrintException(NULL, "AppInit()");
    }
    
    if (! fRet) {
        boot::Shutdown(nullptr);
    }
    return fRet;
}

// extern void noui_connect();
void entry::noui_connect()
{
    //
    // Connect bitcoind signal handlers
    //
    CClientUIInterface::uiInterface.ThreadSafeMessageBox.connect(CClientUIInterface::noui_ThreadSafeMessageBox);
    CClientUIInterface::uiInterface.ThreadSafeAskFee.connect(CClientUIInterface::noui_ThreadSafeAskFee);
}

int main(int argc, char *argv[])
{
    // Connect bitcoind signal handlers
    entry::noui_connect();

    bool fRet = entry::AppInit(argc, argv);

    if (fRet && args_bool::fDaemon) {
        return 0;
    }

    return 1;
}
#endif

bool entry::InitError(const std::string &str)
{
    CClientUIInterface::uiInterface.ThreadSafeMessageBox(str, _(strCoinName), CClientUIInterface::OK | CClientUIInterface::MODAL);
    return false;
}

bool entry::InitWarning(const std::string &str)
{
    CClientUIInterface::uiInterface.ThreadSafeMessageBox(str, _(strCoinName), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
    return true;
}

bool entry::Bind(const CService &addr, bool fError /* = true */)
{
    if (ext_ip::IsLimited(addr)) {
        return false;
    }

    std::string strError;
    if (! BindListenPort(addr, strError)) {
        if (fError) {
            return InitError(strError);
        }
        return false;
    }
    return true;
}

void entry::SetupServerArgs()
{
    arginit::SetupHelpOptions(ARGS);
    ARGS.AddArg("-help-debug", "Print help message with debugging options and exit", false, OptionsCategory::DEBUG_TEST); // server-only for now

    const auto defaultBaseParams = chainparamsbase::CreateBaseChainParams(chainparamsbase::CBaseChainParams::MAIN());
    const auto testnetBaseParams = chainparamsbase::CreateBaseChainParams(chainparamsbase::CBaseChainParams::TESTNET());
    const auto regtestBaseParams = chainparamsbase::CreateBaseChainParams(chainparamsbase::CBaseChainParams::REGTEST());
    const auto defaultChainParams = Chain_info::CreateChainParams(chainparamsbase::CBaseChainParams::MAIN());
    const auto testnetChainParams = Chain_info::CreateChainParams(chainparamsbase::CBaseChainParams::TESTNET());
    const auto regtestChainParams = Chain_info::CreateChainParams(chainparamsbase::CBaseChainParams::REGTEST());

    // Hidden Options
    std::vector<std::string> hidden_args = {
        "-dbcrashratio", "-forcecompactdb",
        // GUI args. These will be overwritten by SetupUIArgs for the GUI
        "-allowselfsignedrootcertificates", "-choosedatadir", "-lang=<lang>", "-min", "-resetguisettings", "-rootcertificates=<file>", "-splash", "-uiplatform"};

    // old core is only options
    ARGS.AddArg("-irc", "Find peers using internet relay chat (default: 0)", false, OptionsCategory::OPTIONS);

    ARGS.AddArg("-version", "Print version and exit", false, OptionsCategory::OPTIONS);
    ARGS.AddArg("-alertnotify=<cmd>", "Execute command when a relevant alert is received or we see a really long fork (%s in cmd is replaced by message)", false, OptionsCategory::OPTIONS);
    ARGS.AddArg("-assumevalid=<hex>", strprintf("If this block is in the chain assume that it and its ancestors are valid and potentially skip their script verification (0 to verify all, default: %s, testnet: %s)", defaultChainParams->GetConsensus().defaultAssumeValid.GetHex(), testnetChainParams->GetConsensus().defaultAssumeValid.GetHex()), false, OptionsCategory::OPTIONS);
    ARGS.AddArg("-blocksdir=<dir>", "Specify blocks directory (default: <datadir>/blocks)", false, OptionsCategory::OPTIONS);
    ARGS.AddArg("-blocknotify=<cmd>", "Execute command when the best block changes (%s in cmd is replaced by block hash)", false, OptionsCategory::OPTIONS);
    ARGS.AddArg("-blockreconstructionextratxn=<n>", strprintf("Extra transactions to keep in memory for compact block reconstructions (default: %u)", DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN), false, OptionsCategory::OPTIONS);
    ARGS.AddArg("-blocksonly", strprintf("Whether to reject transactions from network peers. Transactions from the wallet or RPC are not affected. (default: %u)", DEFAULT_BLOCKSONLY), false, OptionsCategory::OPTIONS);
    ARGS.AddArg("-conf=<file>", strprintf("Specify configuration file. Relative paths will be prefixed by datadir location. (default: %s)", lutil::BITCOIN_CONF_FILENAME().c_str()), false, OptionsCategory::OPTIONS);
    ARGS.AddArg("-datadir=<dir>", "Specify data directory", false, OptionsCategory::OPTIONS);
    //ARGS.AddArg("-dbbatchsize", strprintf("Maximum database write batch size in bytes (default: %u)", nDefaultDbBatchSize), true, OptionsCategory::OPTIONS);
    //ARGS.AddArg("-dbcache=<n>", strprintf("Maximum database cache size <n> MiB (%d to %d, default: %d). In addition, unused mempool memory is shared for this cache (see -maxmempool).", nMinDbCache, nMaxDbCache, nDefaultDbCache), false, OptionsCategory::OPTIONS);
    ARGS.AddArg("-debuglogfile=<file>", strprintf("Specify location of debug log file. Relative paths will be prefixed by a net-specific datadir location. (-nodebuglogfile to disable; default: %s)", DEFAULT_DEBUGLOGFILE), false, OptionsCategory::OPTIONS);
    //ARGS.AddArg("-feefilter", strprintf("Tell other nodes to filter invs to us by our mempool min fee (default: %u)", DEFAULT_FEEFILTER), true, OptionsCategory::OPTIONS);
    ARGS.AddArg("-includeconf=<file>", "Specify additional configuration file, relative to the -datadir path (only useable from configuration file, not command line)", false, OptionsCategory::OPTIONS);
    ARGS.AddArg("-loadblock=<file>", "Imports blocks from external blk000??.dat file on startup", false, OptionsCategory::OPTIONS);
    //ARGS.AddArg("-maxmempool=<n>", strprintf("Keep the transaction memory pool below <n> megabytes (default: %u)", DEFAULT_MAX_MEMPOOL_SIZE), false, OptionsCategory::OPTIONS);
    //ARGS.AddArg("-maxorphantx=<n>", strprintf("Keep at most <n> unconnectable transactions in memory (default: %u)", DEFAULT_MAX_ORPHAN_TRANSACTIONS), false, OptionsCategory::OPTIONS);
    //ARGS.AddArg("-mempoolexpiry=<n>", strprintf("Do not keep transactions in the mempool longer than <n> hours (default: %u)", DEFAULT_MEMPOOL_EXPIRY), false, OptionsCategory::OPTIONS);
    ARGS.AddArg("-minimumchainwork=<hex>", strprintf("Minimum work assumed to exist on a valid chain in hex (default: %s, testnet: %s)", defaultChainParams->GetConsensus().nMinimumChainWork.GetHex(), testnetChainParams->GetConsensus().nMinimumChainWork.GetHex()), true, OptionsCategory::OPTIONS);
    //ARGS.AddArg("-par=<n>", strprintf("Set the number of script verification threads (%u to %d, 0 = auto, <0 = leave that many cores free, default: %d)",
    //    -GetNumCores(), MAX_SCRIPTCHECK_THREADS, DEFAULT_SCRIPTCHECK_THREADS), false, OptionsCategory::OPTIONS);
    //ARGS.AddArg("-persistmempool", strprintf("Whether to save the mempool on shutdown and load on restart (default: %u)", DEFAULT_PERSIST_MEMPOOL), false, OptionsCategory::OPTIONS);
    //ARGS.AddArg("-pid=<file>", strprintf("Specify pid file. Relative paths will be prefixed by a net-specific datadir location. (default: %s)", BITCOIN_PID_FILENAME), false, OptionsCategory::OPTIONS);
    //ARGS.AddArg("-prune=<n>", strprintf("Reduce storage requirements by enabling pruning (deleting) of old blocks. This allows the pruneblockchain RPC to be called to delete specific blocks, and enables automatic pruning of old blocks if a target size in MiB is provided. This mode is incompatible with -txindex and -rescan. "
    //        "Warning: Reverting this setting requires re-downloading the entire blockchain. "
    //        "(default: 0 = disable pruning blocks, 1 = allow manual pruning via RPC, >=%u = automatically prune block files to stay under the specified target size in MiB)", MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024), false, OptionsCategory::OPTIONS);
    ARGS.AddArg("-reindex", "Rebuild chain state and block index from the blk*.dat files on disk", false, OptionsCategory::OPTIONS);
    ARGS.AddArg("-reindex-chainstate", "Rebuild chain state from the currently indexed blocks. When in pruning mode or if blocks on disk might be corrupted, use full -reindex instead.", false, OptionsCategory::OPTIONS);
#ifndef WIN32
    ARGS.AddArg("-sysperms", "Create new files with system default permissions, instead of umask 077 (only effective with disabled wallet functionality)", false, OptionsCategory::OPTIONS);
#else
    hidden_args.emplace_back("-sysperms");
#endif
    ARGS.AddArg("-txindex", strprintf("Maintain a full transaction index, used by the getrawtransaction rpc call (default: %u)", DEFAULT_TXINDEX), false, OptionsCategory::OPTIONS);

    ARGS.AddArg("-addnode=<ip>", "Add a node to connect to and attempt to keep the connection open (see the `addnode` RPC command help for more info). This option can be specified multiple times to add multiple nodes.", false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-banscore=<n>", strprintf("Threshold for disconnecting misbehaving peers (default: %u)", DEFAULT_BANSCORE_THRESHOLD), false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-bantime=<n>", strprintf("Number of seconds to keep misbehaving peers from reconnecting (default: %u)", DEFAULT_MISBEHAVING_BANTIME), false, OptionsCategory::CONNECTION);
    ARGS.AddArg("-bind=<addr>", "Bind to given address and always listen on it. Use [host]:port notation for IPv6", false, OptionsCategory::CONNECTION);
    ARGS.AddArg("-connect=<ip>", "Connect only to the specified node; -noconnect disables automatic connections (the rules for this peer are the same as for -addnode). This option can be specified multiple times to connect to multiple nodes.", false, OptionsCategory::CONNECTION);
    ARGS.AddArg("-discover", "Discover own IP addresses (default: 1 when listening and no -externalip or -proxy)", false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-dns", strprintf("Allow DNS lookups for -addnode, -seednode and -connect (default: %u)", DEFAULT_NAME_LOOKUP), false, OptionsCategory::CONNECTION);
    ARGS.AddArg("-dnsseed", "Query for peer addresses via DNS lookup, if low on addresses (default: 1 unless -connect used)", false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-enablebip61", strprintf("Send reject messages per BIP61 (default: %u)", DEFAULT_ENABLE_BIP61), false, OptionsCategory::CONNECTION);
    ARGS.AddArg("-externalip=<ip>", "Specify your own public address", false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-forcednsseed", strprintf("Always query for peer addresses via DNS lookup (default: %u)", DEFAULT_FORCEDNSSEED), false, OptionsCategory::CONNECTION);
    ARGS.AddArg("-listen", "Accept connections from outside (default: 1 if no -proxy or -connect)", false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-listenonion", strprintf("Automatically create Tor hidden service (default: %d)", DEFAULT_LISTEN_ONION), false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-maxconnections=<n>", strprintf("Maintain at most <n> connections to peers (default: %u)", DEFAULT_MAX_PEER_CONNECTIONS), false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-maxreceivebuffer=<n>", strprintf("Maximum per-connection receive buffer, <n>*1000 bytes (default: %u)", DEFAULT_MAXRECEIVEBUFFER), false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-maxsendbuffer=<n>", strprintf("Maximum per-connection send buffer, <n>*1000 bytes (default: %u)", DEFAULT_MAXSENDBUFFER), false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-maxtimeadjustment", strprintf("Maximum allowed median peer time offset adjustment. Local perspective of time may be influenced by peers forward or backward by this amount. (default: %u seconds)", DEFAULT_MAX_TIME_ADJUSTMENT), false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-maxuploadtarget=<n>", strprintf("Tries to keep outbound traffic under the given target (in MiB per 24h), 0 = no limit (default: %d)", DEFAULT_MAX_UPLOAD_TARGET), false, OptionsCategory::CONNECTION);
    ARGS.AddArg("-onion=<ip:port>", "Use separate SOCKS5 proxy to reach peers via Tor hidden services, set -noonion to disable (default: -proxy)", false, OptionsCategory::CONNECTION);
    ARGS.AddArg("-onlynet=<net>", "Make outgoing connections only through network <net> (ipv4, ipv6 or onion). Incoming connections are not affected by this option. This option can be specified multiple times to allow multiple networks.", false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-peerbloomfilters", strprintf("Support filtering of blocks and transaction with bloom filters (default: %u)", DEFAULT_PEERBLOOMFILTERS), false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-permitbaremultisig", strprintf("Relay non-P2SH multisig (default: %u)", DEFAULT_PERMIT_BAREMULTISIG), false, OptionsCategory::CONNECTION);
    ARGS.AddArg("-port=<port>", strprintf("Listen for connections on <port> (default: %u, testnet: %u, regtest: %u)", defaultChainParams->GetDefaultPort(), testnetChainParams->GetDefaultPort(), regtestChainParams->GetDefaultPort()), false, OptionsCategory::CONNECTION);
    ARGS.AddArg("-proxy=<ip:port>", "Connect through SOCKS5 proxy, set -noproxy to disable (default: disabled)", false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-proxyrandomize", strprintf("Randomize credentials for every proxy connection. This enables Tor stream isolation (default: %u)", DEFAULT_PROXYRANDOMIZE), false, OptionsCategory::CONNECTION);
    ARGS.AddArg("-seednode=<ip>", "Connect to a node to retrieve peer addresses, and disconnect. This option can be specified multiple times to connect to multiple nodes.", false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-timeout=<n>", strprintf("Specify connection timeout in milliseconds (minimum: 1, default: %d)", DEFAULT_CONNECT_TIMEOUT), false, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-peertimeout=<n>", strprintf("Specify p2p connection timeout in seconds. This option determines the amount of time a peer may be inactive before the connection to it is dropped. (minimum: 1, default: %d)", DEFAULT_PEER_CONNECT_TIMEOUT), true, OptionsCategory::CONNECTION);
    //ARGS.AddArg("-torcontrol=<ip>:<port>", strprintf("Tor control port to use if onion listening enabled (default: %s)", DEFAULT_TOR_CONTROL), false, OptionsCategory::CONNECTION);
    ARGS.AddArg("-torpassword=<pass>", "Tor control port password (default: empty)", false, OptionsCategory::CONNECTION);
#ifdef USE_UPNP
#if USE_UPNP
    ARGS.AddArg("-upnp", "Use UPnP to map the listening port (default: 1 when listening and no -proxy)", false, OptionsCategory::CONNECTION);
#else
    ARGS.AddArg("-upnp", strprintf("Use UPnP to map the listening port (default: %u)", 0), false, OptionsCategory::CONNECTION);
#endif
#else
    hidden_args.emplace_back("-upnp");
#endif
    ARGS.AddArg("-whitebind=<addr>", "Bind to given address and whitelist peers connecting to it. Use [host]:port notation for IPv6", false, OptionsCategory::CONNECTION);
    ARGS.AddArg("-whitelist=<IP address or network>", "Whitelist peers connecting from the given IP address (e.g. 1.2.3.4) or CIDR notated network (e.g. 1.2.3.0/24). Can be specified multiple times."
        " Whitelisted peers cannot be DoS banned", false, OptionsCategory::CONNECTION);

    //g_wallet_init_interface.AddWalletOptions();

#if ENABLE_ZMQ
    ARGS.AddArg("-zmqpubhashblock=<address>", "Enable publish hash block in <address>", false, OptionsCategory::ZMQ);
    ARGS.AddArg("-zmqpubhashtx=<address>", "Enable publish hash transaction in <address>", false, OptionsCategory::ZMQ);
    ARGS.AddArg("-zmqpubrawblock=<address>", "Enable publish raw block in <address>", false, OptionsCategory::ZMQ);
    ARGS.AddArg("-zmqpubrawtx=<address>", "Enable publish raw transaction in <address>", false, OptionsCategory::ZMQ);
    ARGS.AddArg("-zmqpubhashblockhwm=<n>", strprintf("Set publish hash block outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), false, OptionsCategory::ZMQ);
    ARGS.AddArg("-zmqpubhashtxhwm=<n>", strprintf("Set publish hash transaction outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), false, OptionsCategory::ZMQ);
    ARGS.AddArg("-zmqpubrawblockhwm=<n>", strprintf("Set publish raw block outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), false, OptionsCategory::ZMQ);
    ARGS.AddArg("-zmqpubrawtxhwm=<n>", strprintf("Set publish raw transaction outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), false, OptionsCategory::ZMQ);
#else
    hidden_args.emplace_back("-zmqpubhashblock=<address>");
    hidden_args.emplace_back("-zmqpubhashtx=<address>");
    hidden_args.emplace_back("-zmqpubrawblock=<address>");
    hidden_args.emplace_back("-zmqpubrawtx=<address>");
    hidden_args.emplace_back("-zmqpubhashblockhwm=<n>");
    hidden_args.emplace_back("-zmqpubhashtxhwm=<n>");
    hidden_args.emplace_back("-zmqpubrawblockhwm=<n>");
    hidden_args.emplace_back("-zmqpubrawtxhwm=<n>");
#endif

    //ARGS.AddArg("-checkblocks=<n>", strprintf("How many blocks to check at startup (default: %u, 0 = all)", DEFAULT_CHECKBLOCKS), true, OptionsCategory::DEBUG_TEST);
    //ARGS.AddArg("-checklevel=<n>", strprintf("How thorough the block verification of -checkblocks is: "
    //    "level 0 reads the blocks from disk, "
    //    "level 1 verifies block validity, "
    //    "level 2 verifies undo data, "
    //    "level 3 checks disconnection of tip blocks, "
    //    "and level 4 tries to reconnect the blocks, "
    //    "each level includes the checks of the previous levels "
    //    "(0-4, default: %u)", DEFAULT_CHECKLEVEL), true, OptionsCategory::DEBUG_TEST);
    ARGS.AddArg("-checkblockindex", strprintf("Do a full consistency check for mapBlockIndex, setBlockIndexCandidates, chainActive and mapBlocksUnlinked occasionally. (default: %u, regtest: %u)", defaultChainParams->DefaultConsistencyChecks(), regtestChainParams->DefaultConsistencyChecks()), true, OptionsCategory::DEBUG_TEST);
    ARGS.AddArg("-checkmempool=<n>", strprintf("Run checks every <n> transactions (default: %u, regtest: %u)", defaultChainParams->DefaultConsistencyChecks(), regtestChainParams->DefaultConsistencyChecks()), true, OptionsCategory::DEBUG_TEST);
    //ARGS.AddArg("-checkpoints", strprintf("Disable expensive verification for known chain history (default: %u)", DEFAULT_CHECKPOINTS_ENABLED), true, OptionsCategory::DEBUG_TEST);
    ARGS.AddArg("-deprecatedrpc=<method>", "Allows deprecated RPC method(s) to be used", true, OptionsCategory::DEBUG_TEST);
    ARGS.AddArg("-dropmessagestest=<n>", "Randomly drop 1 of every <n> network messages", true, OptionsCategory::DEBUG_TEST);
    //ARGS.AddArg("-stopafterblockimport", strprintf("Stop running after importing blocks from disk (default: %u)", DEFAULT_STOPAFTERBLOCKIMPORT), true, OptionsCategory::DEBUG_TEST);
    //ARGS.AddArg("-stopatheight", strprintf("Stop running after reaching the given height in the main chain (default: %u)", DEFAULT_STOPATHEIGHT), true, OptionsCategory::DEBUG_TEST);
    //ARGS.AddArg("-limitancestorcount=<n>", strprintf("Do not accept transactions if number of in-mempool ancestors is <n> or more (default: %u)", DEFAULT_ANCESTOR_LIMIT), true, OptionsCategory::DEBUG_TEST);
    //ARGS.AddArg("-limitancestorsize=<n>", strprintf("Do not accept transactions whose size with all in-mempool ancestors exceeds <n> kilobytes (default: %u)", DEFAULT_ANCESTOR_SIZE_LIMIT), true, OptionsCategory::DEBUG_TEST);
    //ARGS.AddArg("-limitdescendantcount=<n>", strprintf("Do not accept transactions if any ancestor would have <n> or more in-mempool descendants (default: %u)", DEFAULT_DESCENDANT_LIMIT), true, OptionsCategory::DEBUG_TEST);
    //ARGS.AddArg("-limitdescendantsize=<n>", strprintf("Do not accept transactions if any ancestor would have more than <n> kilobytes of in-mempool descendants (default: %u).", DEFAULT_DESCENDANT_SIZE_LIMIT), true, OptionsCategory::DEBUG_TEST);
    ARGS.AddArg("-addrmantest", "Allows to test address relay on localhost", true, OptionsCategory::DEBUG_TEST);
    ARGS.AddArg("-debug=<category>", "Output debugging information (default: -nodebug, supplying <category> is optional). "
        "If <category> is not supplied or if <category> = 1, output all debugging information. <category> can be: " + ListLogCategories() + ".", false, OptionsCategory::DEBUG_TEST);
    ARGS.AddArg("-debugexclude=<category>", strprintf("Exclude debugging information for a category. Can be used in conjunction with -debug=1 to output debug logs for all categories except one or more specified categories."), false, OptionsCategory::DEBUG_TEST);
    //ARGS.AddArg("-logips", strprintf("Include IP addresses in debug output (default: %u)", DEFAULT_LOGIPS), false, OptionsCategory::DEBUG_TEST);
    //ARGS.AddArg("-logtimestamps", strprintf("Prepend debug output with timestamp (default: %u)", DEFAULT_LOGTIMESTAMPS), false, OptionsCategory::DEBUG_TEST);
    //ARGS.AddArg("-logtimemicros", strprintf("Add microsecond precision to debug timestamps (default: %u)", DEFAULT_LOGTIMEMICROS), true, OptionsCategory::DEBUG_TEST);
    ARGS.AddArg("-mocktime=<n>", "Replace actual time with <n> seconds since epoch (default: 0)", true, OptionsCategory::DEBUG_TEST);
    //ARGS.AddArg("-maxsigcachesize=<n>", strprintf("Limit sum of signature cache and script execution cache sizes to <n> MiB (default: %u)", DEFAULT_MAX_SIG_CACHE_SIZE), true, OptionsCategory::DEBUG_TEST);
    //ARGS.AddArg("-maxtipage=<n>", strprintf("Maximum tip age in seconds to consider node in initial block download (default: %u)", DEFAULT_MAX_TIP_AGE), true, OptionsCategory::DEBUG_TEST);
    //ARGS.AddArg("-maxtxfee=<amt>", strprintf("Maximum total fees (in %s) to use in a single wallet transaction or raw transaction; setting this too low may abort large transactions (default: %s)",
    //    CURRENCY_UNIT, FormatMoney(DEFAULT_TRANSACTION_MAXFEE)), false, OptionsCategory::DEBUG_TEST);
    //ARGS.AddArg("-printpriority", strprintf("Log transaction fee per kB when mining blocks (default: %u)", DEFAULT_PRINTPRIORITY), true, OptionsCategory::DEBUG_TEST);
    ARGS.AddArg("-printtoconsole", "Send trace/debug info to console (default: 1 when no -daemon. To disable logging to file, set -nodebuglogfile)", false, OptionsCategory::DEBUG_TEST);
    ARGS.AddArg("-shrinkdebugfile", "Shrink debug.log file on client startup (default: 1 when no -debug)", false, OptionsCategory::DEBUG_TEST);
    ARGS.AddArg("-uacomment=<cmt>", "Append comment to the user agent string", false, OptionsCategory::DEBUG_TEST);

    chainparamsbase::SetupChainParamsBaseOptions();

    ARGS.AddArg("-acceptnonstdtxn", strprintf("Relay and mine \"non-standard\" transactions (%sdefault: %u)", "testnet/regtest only; ", !testnetChainParams->RequireStandard()), true, OptionsCategory::NODE_RELAY);
    //ARGS.AddArg("-incrementalrelayfee=<amt>", strprintf("Fee rate (in %s/kB) used to define cost of relay, used for mempool limiting and BIP 125 replacement. (default: %s)", CURRENCY_UNIT, FormatMoney(DEFAULT_INCREMENTAL_RELAY_FEE)), true, OptionsCategory::NODE_RELAY);
    //ARGS.AddArg("-dustrelayfee=<amt>", strprintf("Fee rate (in %s/kB) used to defined dust, the value of an output such that it will cost more than its value in fees at this fee rate to spend it. (default: %s)", CURRENCY_UNIT, FormatMoney(DUST_RELAY_TX_FEE)), true, OptionsCategory::NODE_RELAY);
    //ARGS.AddArg("-bytespersigop", strprintf("Equivalent bytes per sigop in transactions for relay and mining (default: %u)", DEFAULT_BYTES_PER_SIGOP), false, OptionsCategory::NODE_RELAY);
    //ARGS.AddArg("-datacarrier", strprintf("Relay and mine data carrier transactions (default: %u)", DEFAULT_ACCEPT_DATACARRIER), false, OptionsCategory::NODE_RELAY);
    //ARGS.AddArg("-datacarriersize", strprintf("Maximum size of data in data carrier transactions we relay and mine (default: %u)", MAX_OP_RETURN_RELAY), false, OptionsCategory::NODE_RELAY);
    //ARGS.AddArg("-mempoolreplacement", strprintf("Enable transaction replacement in the memory pool (default: %u)", DEFAULT_ENABLE_REPLACEMENT), false, OptionsCategory::NODE_RELAY);
    //ARGS.AddArg("-minrelaytxfee=<amt>", strprintf("Fees (in %s/kB) smaller than this are considered zero fee for relaying, mining and transaction creation (default: %s)",
    //    CURRENCY_UNIT, FormatMoney(DEFAULT_MIN_RELAY_TX_FEE)), false, OptionsCategory::NODE_RELAY);
    //ARGS.AddArg("-whitelistforcerelay", strprintf("Force relay of transactions from whitelisted peers even if the transactions were already in the mempool or violate local relay policy (default: %d)", DEFAULT_WHITELISTFORCERELAY), false, OptionsCategory::NODE_RELAY);
    //ARGS.AddArg("-whitelistrelay", strprintf("Accept relayed transactions received from whitelisted peers even when not relaying transactions (default: %d)", DEFAULT_WHITELISTRELAY), false, OptionsCategory::NODE_RELAY);


    //ARGS.AddArg("-blockmaxweight=<n>", strprintf("Set maximum BIP141 block weight (default: %d)", DEFAULT_BLOCK_MAX_WEIGHT), false, OptionsCategory::BLOCK_CREATION);
    //ARGS.AddArg("-blockmintxfee=<amt>", strprintf("Set lowest fee rate (in %s/kB) for transactions to be included in block creation. (default: %s)", CURRENCY_UNIT, FormatMoney(DEFAULT_BLOCK_MIN_TX_FEE)), false, OptionsCategory::BLOCK_CREATION);
    ARGS.AddArg("-blockversion=<n>", "Override block version to test forking scenarios", true, OptionsCategory::BLOCK_CREATION);

    //ARGS.AddArg("-rest", strprintf("Accept public REST requests (default: %u)", DEFAULT_REST_ENABLE), false, OptionsCategory::RPC);
    ARGS.AddArg("-rpcallowip=<ip>", "Allow JSON-RPC connections from specified source. Valid for <ip> are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24). This option can be specified multiple times", false, OptionsCategory::RPC);
    ARGS.AddArg("-rpcauth=<userpw>", "Username and HMAC-SHA-256 hashed password for JSON-RPC connections. The field <userpw> comes in the format: <USERNAME>:<SALT>$<HASH>. A canonical python script is included in share/rpcauth. The client then connects normally using the rpcuser=<USERNAME>/rpcpassword=<PASSWORD> pair of arguments. This option can be specified multiple times", false, OptionsCategory::RPC);
    ARGS.AddArg("-rpcbind=<addr>[:port]", "Bind to given address to listen for JSON-RPC connections. Do not expose the RPC server to untrusted networks such as the public internet! This option is ignored unless -rpcallowip is also passed. Port is optional and overrides -rpcport. Use [host]:port notation for IPv6. This option can be specified multiple times (default: 127.0.0.1 and ::1 i.e., localhost)", false, OptionsCategory::RPC);
    ARGS.AddArg("-rpccookiefile=<loc>", "Location of the auth cookie. Relative paths will be prefixed by a net-specific datadir location. (default: data dir)", false, OptionsCategory::RPC);
    ARGS.AddArg("-rpcpassword=<pw>", "Password for JSON-RPC connections", false, OptionsCategory::RPC);
    ARGS.AddArg("-rpcport=<port>", strprintf("Listen for JSON-RPC connections on <port> (default: %u, testnet: %u, regtest: %u)", defaultBaseParams->RPCPort(), testnetBaseParams->RPCPort(), regtestBaseParams->RPCPort()), false, OptionsCategory::RPC);
    //ARGS.AddArg("-rpcserialversion", strprintf("Sets the serialization of raw transaction or block hex returned in non-verbose mode, non-segwit(0) or segwit(1) (default: %d)", DEFAULT_RPC_SERIALIZE_VERSION), false, OptionsCategory::RPC);
    //ARGS.AddArg("-rpcservertimeout=<n>", strprintf("Timeout during HTTP requests (default: %d)", DEFAULT_HTTP_SERVER_TIMEOUT), true, OptionsCategory::RPC);
    //ARGS.AddArg("-rpcthreads=<n>", strprintf("Set the number of threads to service RPC calls (default: %d)", DEFAULT_HTTP_THREADS), false, OptionsCategory::RPC);
    ARGS.AddArg("-rpcuser=<user>", "Username for JSON-RPC connections", false, OptionsCategory::RPC);
    //ARGS.AddArg("-rpcworkqueue=<n>", strprintf("Set the depth of the work queue to service RPC calls (default: %d)", DEFAULT_HTTP_WORKQUEUE), true, OptionsCategory::RPC);
    ARGS.AddArg("-server", "Accept command line and JSON-RPC commands", false, OptionsCategory::RPC);

#if HAVE_DECL_DAEMON
    ARGS.AddArg("-daemon", "Run in the background as a daemon and accept commands", false, OptionsCategory::OPTIONS);
#else
    hidden_args.emplace_back("-daemon");
#endif

    // Add the hidden options
    ARGS.AddHiddenArgs(hidden_args);
}

// Core-specific options shared between UI and daemon
std::string entry::HelpMessage()
{
    std::string strUsage = _("Options:") + "\n" +
        "  -?                     " + _("This help message") + "\n" +
        "  -conf=<file>           " + _("Specify configuration file (default: " strCoinNameL ".conf)") + "\n" +
        "  -pid=<file>            " + _("Specify pid file (default: " strCoinNameL "d.pid)") + "\n" +
        "  -datadir=<dir>         " + _("Specify data directory") + "\n" +
        "  -wallet=<file>         " + _("Specify wallet file (within data directory)") + "\n" +
        "  -dbcache=<n>           " + _("Set database cache size in megabytes (default: 25)") + "\n" +
        "  -dblogsize=<n>         " + _("Set database disk log size in megabytes (default: 100)") + "\n" +
        "  -timeout=<n>           " + _("Specify connection timeout in milliseconds (default: 5000)") + "\n" +
        "  -proxy=<ip:port>       " + _("Connect through socks proxy") + "\n" +
        "  -socks=<n>             " + _("Select the version of socks proxy to use (4-5, default: 5)") + "\n" +
        "  -tor=<ip:port>         " + _("Use proxy to reach tor hidden services (default: same as -proxy)") + "\n"
        "  -torname=<host.onion>  " + _("Send the specified hidden service name when connecting to Tor nodes (default: none)") + "\n"
        "  -dns                   " + _("Allow DNS lookups for -addnode, -seednode and -connect") + "\n" +
        "  -port=<port>           " + _("Listen for connections on <port> (default: 21587 or testnet: 31587)") + "\n" +
        "  -maxconnections=<n>    " + _("Maintain at most <n> connections to peers (default: 125)") + "\n" +
        "  -addnode=<ip>          " + _("Add a node to connect to and attempt to keep the connection open") + "\n" +
        "  -connect=<ip>          " + _("Connect only to the specified node(s)") + "\n" +
        "  -seednode=<ip>         " + _("Connect to a node to retrieve peer addresses, and disconnect") + "\n" +
        "  -externalip=<ip>       " + _("Specify your own public address") + "\n" +
        "  -onlynet=<net>         " + _("Only connect to nodes in network <net> (IPv4, IPv6 or Onion)") + "\n" +
        "  -discover              " + _("Discover own IP address (default: 1 when listening and no -externalip)") + "\n" +
        "  -irc                   " + _("Find peers using internet relay chat (default: 1)") + "\n" +
        "  -listen                " + _("Accept connections from outside (default: 1 if no -proxy or -connect)") + "\n" +
        "  -bind=<addr>           " + _("Bind to given address. Use [host]:port notation for IPv6") + "\n" +
        "  -dnsseed               " + _("Find peers using DNS lookup (default: 1)") + "\n" +
        "  -cppolicy              " + _("Sync checkpoints policy (default: strict)") + "\n" +
        "  -banscore=<n>          " + _("Threshold for disconnecting misbehaving peers (default: 100)") + "\n" +
        "  -bantime=<n>           " + _("Number of seconds to keep misbehaving peers from reconnecting (default: 86400)") + "\n" +
        "  -maxreceivebuffer=<n>  " + _("Maximum per-connection receive buffer, <n>*1000 bytes (default: 5000)") + "\n" +
        "  -maxsendbuffer=<n>     " + _("Maximum per-connection send buffer, <n>*1000 bytes (default: 1000)") + "\n" +
#ifdef USE_UPNP
#if USE_UPNP
        "  -upnp                  " + _("Use UPnP to map the listening port (default: 1 when listening)") + "\n" +
#else
        "  -upnp                  " + _("Use UPnP to map the listening port (default: 0)") + "\n" +
#endif
#endif
        "  -detachdb              " + _("Detach block and address databases. Increases shutdown time (default: 0)") + "\n" +

#ifdef DB_LOG_IN_MEMORY
        "  -memorylog             " + _("Use in-memory logging for block index database (default: 1)") + "\n" +
#endif

        "  -paytxfee=<amt>        " + _("Fee per KB to add to transactions you send") + "\n" +
        "  -mininput=<amt>        " + str(boost::format(_("When creating transactions, ignore inputs with value less than this (default: %s)")) % bitstr::FormatMoney(block_params::MIN_TXOUT_AMOUNT)) + "\n" +
#ifdef QT_GUI
        "  -server                " + _("Accept command line and JSON-RPC commands") + "\n" +
#endif
#if !defined(WIN32) && !defined(QT_GUI)
        "  -daemon                " + _("Run in the background as a daemon and accept commands") + "\n" +
#endif
        "  -testnet               " + _("Use the test network") + "\n" +
        "  -debug                 " + _("Output extra debugging information. Implies all other -debug* options") + "\n" +
        "  -debugnet              " + _("Output extra network debugging information") + "\n" +
        "  -logtimestamps         " + _("Prepend debug output with timestamp") + "\n" +
        "  -shrinkdebugfile       " + _("Shrink debug.log file on client startup (default: 1 when no -debug)") + "\n" +
        "  -printtoconsole        " + _("Send trace/debug info to console instead of debug.log file") + "\n" +
#ifdef WIN32
        "  -printtodebugger       " + _("Send trace/debug info to debugger") + "\n" +
#endif
        "  -rpcuser=<user>        " + _("Username for JSON-RPC connections") + "\n" +
        "  -rpcpassword=<pw>      " + _("Password for JSON-RPC connections") + "\n" +
        "  -rpcport=<port>        " + _("Listen for JSON-RPC connections on <port> (default: 21588 or testnet: 31588)") + "\n" +
        "  -rpcallowip=<ip>       " + _("Allow JSON-RPC connections from specified IP address") + "\n" +
        "  -rpcconnect=<ip>       " + _("Send commands to node running on <ip> (default: 127.0.0.1)") + "\n" +
        "  -blocknotify=<cmd>     " + _("Execute command when the best block changes (%s in cmd is replaced by block hash)") + "\n" +
        "  -walletnotify=<cmd>    " + _("Execute command when a wallet transaction changes (%s in cmd is replaced by TxID)") + "\n" +
        "  -peercollector=<cmd>     " + _("Execute command to collect peer addresses") + "\n" +
        "  -confchange            " + _("Require a confirmations for change (default: 0)") + "\n" +
        "  -upgradewallet         " + _("Upgrade wallet to latest format") + "\n" +
        "  -keypool=<n>           " + _("Set key pool size to <n> (default: 100)") + "\n" +
        "  -rescan                " + _("Rescan the block chain for missing wallet transactions") + "\n" +
        "  -zapwallettxes         " + _("Clear list of wallet transactions (diagnostic tool; implies -rescan)") + "\n" +
        "  -salvagewallet         " + _("Attempt to recover private keys from a corrupt wallet.dat") + "\n" +
        "  -checkblocks=<n>       " + _("How many blocks to check at startup (default: 2500, 0 = all)") + "\n" +
        "  -checklevel=<n>        " + _("How thorough the block verification is (0-6, default: 1)") + "\n" +
        "  -par=N                 " + _("Set the number of script verification threads (1-16, 0=auto, default: 0)") + "\n" +
        "  -loadblock=<file>      " + _("Imports blocks from external blk000?.dat file") + "\n" +

        "\n" + _("Block creation options:") + "\n" +
        "  -blockminsize=<n>      "   + _("Set minimum block size in bytes (default: 0)") + "\n" +
        "  -blockmaxsize=<n>      "   + _("Set maximum block size in bytes (default: 250000)") + "\n" +
        "  -blockprioritysize=<n> "   + _("Set maximum size of high-priority/low-fee transactions in bytes (default: 27000)") + "\n" +

        "\n" + _("SSL options: (see the Bitcoin Wiki for SSL setup instructions)") + "\n" +
        "  -rpcssl                                  " + _("Use OpenSSL (https) for JSON-RPC connections") + "\n" +
        "  -rpcsslcertificatechainfile=<file.cert>  " + _("Server certificate file (default: server.cert)") + "\n" +
        "  -rpcsslprivatekeyfile=<file.pem>         " + _("Server private key (default: server.pem)") + "\n" +
        "  -rpcsslciphers=<ciphers>                 " + _("Acceptable ciphers (default: TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH)") + "\n";

    return strUsage;
}

//
// Initialize bitcoin.
// @pre Parameters should be parsed and config file should be read.
//
#define I_DEBUG_CS(str) debugcs::instance() << (str) << debugcs::endl();
bool entry::AppInit2(bool restart/*=false*/)
{
    // ********************************************************* Test and Autocheckpoint load (if DEBUG)
    CMString_test();

    // ********************************************************* Step 1: setup
    I_DEBUG_CS("Step 1: setup")

#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, ::CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
    //
    // Enable Data Execution Prevention (DEP)
    // Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008
    // A failure is non-critical and needs no further attention!
    //
 #ifndef PROCESS_DEP_ENABLE
  // We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7),
  // which is not correct. Can be removed, when GCCs winbase.h is fixed!
  #define PROCESS_DEP_ENABLE 0x00000001
 #endif

    typedef BOOL (WINAPI *PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol = (PSETPROCDEPPOL)GetProcAddress(::GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    if (setProcDEPPol != NULL) {
        setProcDEPPol(PROCESS_DEP_ENABLE);
    }

    //
    // Initialize Windows Sockets
    //
    WSADATA wsadata;
    int ret = ::WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR) {
        return InitError(strprintf("Error: TCP/IP socket library failed to start (WSAStartup returned error %d)", ret));
    }
#endif
#ifndef WIN32
    umask(077);

    //
    // Clean shutdown on SIGTERM
    //
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    //
    // Reopen debug.log on SIGHUP
    //
    struct sigaction sa_hup;
    sa_hup.sa_handler = HandleSIGHUP;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, NULL);
#endif

    // ********************************************************* Step 2: parameter interactions
    I_DEBUG_CS("Step 2: parameter interactions")

    args_uint::nNodeLifespan = map_arg::GetArgUInt("-addrlifespan", 7);
    args_bool::fUseFastIndex = map_arg::GetBoolArg("-fastindex", true);
    args_bool::fUseMemoryLog = map_arg::GetBoolArg("-memorylog", true);

    // Ping and address broadcast intervals
    block_process::manage::nPingInterval = std::max<int64_t>(10 * 60, map_arg::GetArg("-keepalive", 30 * 60));

    Checkpoints::CheckpointsMode = Checkpoints::STRICT;
    const std::string strCpMode = map_arg::GetArg("-cppolicy", "strict");
    if(strCpMode == "strict")
        Checkpoints::CheckpointsMode = Checkpoints::STRICT;
    else if(strCpMode == "advisory")
        Checkpoints::CheckpointsMode = Checkpoints::ADVISORY;
    else if(strCpMode == "permissive")
        Checkpoints::CheckpointsMode = Checkpoints::PERMISSIVE;

    entry::b66mode = entry::Bip66_ADVISORY;
    const std::string strBipMode = map_arg::GetArg("-bip66policy", "advisory");
    if(strBipMode == "strict")
        entry::b66mode = entry::Bip66_STRICT;
    else if(strBipMode == "advisory")
        entry::b66mode = entry::Bip66_ADVISORY;
    else if(strBipMode == "permissive")
        entry::b66mode = entry::Bip66_PERMISSIVE;

    args_bool::fTestNet = map_arg::GetBoolArg("-testnet");
    if (args_bool::fTestNet) {
        map_arg::SoftSetBoolArg("-irc", true);
    }

    if (map_arg::GetMapArgsCount("-bind")) {
        // when specifying an explicit binding address, you want to listen on it
        // even when -connect or -proxy is specified
        map_arg::SoftSetBoolArg("-listen", true);
    }

    if (map_arg::GetMapArgsCount("-connect") && map_arg::GetMapMultiArgsString("-connect").size() > 0) {
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        map_arg::SoftSetBoolArg("-dnsseed", false);
        map_arg::SoftSetBoolArg("-listen", false);
    }

    if (map_arg::GetMapArgsCount("-proxy")) {
        // to protect privacy, do not listen by default if a proxy server is specified
        map_arg::SoftSetBoolArg("-listen", false);
    }

    if (!map_arg::GetBoolArg("-listen", true)) {
        // do not map ports or try to retrieve public IP when not listening (pointless)
        map_arg::SoftSetBoolArg("-discover", false);
    }

    if (map_arg::GetMapArgsCount("-externalip")) {
        // if an explicit public IP is specified, do not try to find others
        map_arg::SoftSetBoolArg("-discover", false);
    }

    if (map_arg::GetBoolArg("-salvagewallet")) {
        // Rewrite just private keys: rescan to find transactions
        map_arg::SoftSetBoolArg("-rescan", true);
    }

    if (map_arg::GetBoolArg("-zapwallettxes", false)) {
        // -zapwallettx implies a rescan
        if (map_arg::SoftSetBoolArg("-rescan", true)) {
            printf("AppInit2 : parameter interaction: -zapwallettxes=1 -> setting -rescan=1\n");
        }
    }

    // ********************************************************* log open
    I_DEBUG_CS("log open")
    if(restart==false) {
        InitLogging();
        OpenDebugFile();
    }

    // ********************************************************* Step 3: parameter-to-internal-flags
    I_DEBUG_CS("Step 3: parameter-to-internal-flags")

    //
    // -par=0 means autodetect, but block_info::nScriptCheckThreads==0 means no concurrency
    //
    block_info::nScriptCheckThreads = map_arg::GetArgInt("-par", 0);
    if (block_info::nScriptCheckThreads == 0) {
        block_info::nScriptCheckThreads = boost::thread::hardware_concurrency();
    }

    if (block_info::nScriptCheckThreads <= 1) {
        block_info::nScriptCheckThreads = 0;
    } else if (block_info::nScriptCheckThreads > block_params::MAX_SCRIPTCHECK_THREADS) {
        block_info::nScriptCheckThreads = block_params::MAX_SCRIPTCHECK_THREADS;
    }

    args_bool::fDebug = map_arg::GetBoolArg("-debug");

    // -debug implies fDebug*
    if (args_bool::fDebug) {
        args_bool::fDebugNet = true;
    } else {
        args_bool::fDebugNet = map_arg::GetBoolArg("-debugnet");
    }

    CDBEnv::bitdb.SetDetach(map_arg::GetBoolArg("-detachdb", false));

#if !defined(WIN32) && !defined(QT_GUI)
    args_bool::fDaemon = map_arg::GetBoolArg("-daemon");
#else
    args_bool::fDaemon = false;
#endif

    if (args_bool::fDaemon) {
        args_bool::fServer = true;
    } else {
        args_bool::fServer = map_arg::GetBoolArg("-server");
    }

    /* force args_bool::fServer when running without GUI */
#if !defined(QT_GUI)
    args_bool::fServer = true;
#endif

    args_bool::fPrintToConsole = map_arg::GetBoolArg("-printtoconsole");
    args_bool::fPrintToDebugger = map_arg::GetBoolArg("-printtodebugger");
    args_bool::fLogTimestamps = map_arg::GetBoolArg("-logtimestamps");

    if (map_arg::GetMapArgsCount("-timeout")) {
        int nNewTimeout = map_arg::GetArgInt("-timeout", 5000);
        if (nNewTimeout > 0 && nNewTimeout < 600000) {
            netbase::nConnectTimeout = nNewTimeout;
        }
    }

    //
    // Put client version data into coinbase flags.
    //
    block_info::COINBASE_FLAGS << version::PROTOCOL_VERSION << DISPLAY_VERSION_MAJOR << DISPLAY_VERSION_MINOR << DISPLAY_VERSION_REVISION;

    if (map_arg::GetMapArgsCount("-paytxfee")) {
        if (! bitstr::ParseMoney(map_arg::GetMapArgsString("-paytxfee").c_str(), block_info::nTransactionFee)) {
            return InitError(strprintfc(_("Invalid amount for -paytxfee=<amount>: '%s'"), map_arg::GetMapArgsString("-paytxfee").c_str()));
        }
        if (block_info::nTransactionFee > 0.25 * util::COIN) {
            InitWarning(_("Warning: -paytxfee is set very high! This is the transaction fee you will pay if you send a transaction."));
        }
    }

    args_bool::fConfChange = map_arg::GetBoolArg("-confchange", false);

    if (map_arg::GetMapArgsCount("-mininput")) {
        if (! bitstr::ParseMoney(map_arg::GetMapArgsString("-mininput").c_str(), block_info::nMinimumInputValue)) {
            return InitError(strprintfc(_("Invalid amount for -mininput=<amount>: '%s'"), map_arg::GetMapArgsString("-mininput").c_str()));
        }
    }

    // ********************************************************* Step 4: application initialization: dir lock, daemonize, pidfile, debug log
    I_DEBUG_CS("Step 4: application initialization: dir lock, daemonize, pidfile, debug log")

    //I_DEBUG_CS("Step 4a: wallet filename get ...");
    std::string strDataDir = iofs::GetDataDir().string();
    strWalletFileName = map_arg::GetArg("-wallet", "wallet.dat");

    // strWalletFileName must be a plain filename without a directory
    //I_DEBUG_CS("Step 4b: wallet filename only check ...");
    if (strWalletFileName != boost::filesystem::basename(strWalletFileName) + boost::filesystem::extension(strWalletFileName)) {
        return InitError(strprintfc(_("Wallet %s resides outside data directory %s."), strWalletFileName.c_str(), strDataDir.c_str()));
    }

    //
    // Lock File
    // Make sure only a single Bitcoin process is using the data directory
    //
    //I_DEBUG_CS("Step 4c: Lock File ...");
    fs::path pathLockFile = iofs::GetDataDir() / ".lock";
    FILE *file = fopen(pathLockFile.string().c_str(), "a"); // empty lock file; created if it doesn't exist.
    if (file) {
        fclose(file);
    }
    static boost::interprocess::file_lock lock(pathLockFile.string().c_str());
    if (! lock.try_lock()) {
        if(restart==false)
            return InitError(strprintfc(_("Cannot obtain a lock on data directory %s. %s is probably already running."), strDataDir.c_str(), strCoinName));
    }

#if !defined(WIN32) && !defined(QT_GUI)
    if (args_bool::fDaemon) {
        // Daemonize
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
            return false;
        }
        if (pid > 0) {
            iofs::CreatePidFile(iofs::GetPidFile(), pid);
            return true;
        }

        pid_t sid = setsid();
        if (sid < 0) {
            fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
        }
    }
#endif

    if (map_arg::GetBoolArg("-shrinkdebugfile", !args_bool::fDebug)) {
        iofs::ShrinkDebugFile();
    }

    printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    printf("%s version %s (%s)\n", strCoinName, format_version::FormatFullVersion().c_str(), version::CLIENT_DATE.c_str());
    printf("Using OpenSSL version %s\n", SSLeay_version(SSLEAY_VERSION));
    if (! args_bool::fLogTimestamps) {
        printf("Startup time: %s\n", util::DateTimeStrFormat("%x %H:%M:%S", bitsystem::GetTime()).c_str());
    }
    printf("Default data directory %s\n", iofs::GetDefaultDataDir().string().c_str());
    printf("Used data directory %s\n", strDataDir.c_str());
    std::ostringstream strErrors;

    if (args_bool::fDaemon) {
        ::_fprintf_cs(strCoinName " server starting\n");
    }

    //I_DEBUG_CS("Step 4d: Script check ...");
    if (block_info::nScriptCheckThreads) {
        printf("Using %u threads for script verification\n", block_info::nScriptCheckThreads);
        for (int i=0; i < block_info::nScriptCheckThreads-1; ++i) {
            if(! bitthread::NewThread(block_check::thread::ThreadScriptCheck, nullptr))
                bitthread::thread_error(std::string(__func__) + " :ThreadScriptCheck");
        }
    }

    int64_t nStart;

    // ********************************************************* Step 5: verify database integrity
    I_DEBUG_CS("Step 5: verify database integrity")

    CClientUIInterface::uiInterface.InitMessage(_("Verifying database integrity..."));

    if (! CDBEnv::bitdb.Open(iofs::GetDataDir())) {
        std::string msg = strprintfc(_("Error initializing database environment %s! To recover, BACKUP THAT DIRECTORY, then remove everything from it except for wallet.dat."), strDataDir.c_str());
        return InitError(msg);
    }

    if (map_arg::GetBoolArg("-salvagewallet")) {
        // Recover readable keypairs:
        if (! CWalletDB::Recover(CDBEnv::bitdb, strWalletFileName, true)) {
            return false;
        }
    }

    if (boost::filesystem::exists(iofs::GetDataDir() / strWalletFileName)) {
        CDBEnv::VerifyResult r = CDBEnv::bitdb.Verify(strWalletFileName, CWalletDB::Recover);
        if (r == CDBEnv::RECOVER_OK) {
            std::string msg = strprintfc(_("Warning: wallet.dat corrupt, data salvaged!"
                                          " Original wallet.dat saved as wallet.{timestamp}.bak in %s; if"
                                          " your balance or transactions are incorrect you should"
                                          " restore from a backup."), strDataDir.c_str());
            CClientUIInterface::uiInterface.ThreadSafeMessageBox(msg, _(strCoinName), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        }
        if (r == CDBEnv::RECOVER_FAIL) {
            return InitError(_("wallet.dat corrupt, salvage failed"));
        }
    }

    // ********************************************************* Step 6: network initialization
    I_DEBUG_CS("Step 6: network initialization")

    int nSocksVersion = map_arg::GetArgInt("-socks", 5);

    if (nSocksVersion != 4 && nSocksVersion != 5) {
        return InitError(strprintfc(_("Unknown -socks proxy version requested: %i"), nSocksVersion));
    }

    if (map_arg::GetMapArgsCount("-onlynet")) {
        std::set<enum netbase::Network> nets;
        for(std::string snet: map_arg::GetMapMultiArgsString("-onlynet"))
        {
            enum netbase::Network net = netbase::manage::ParseNetwork(snet);
            if (net == netbase::NET_UNROUTABLE) {
                return InitError(strprintfc(_("Unknown network specified in -onlynet: '%s'"), snet.c_str()));
            }
            nets.insert(net);
        }
        for (int n = 0; n < netbase::NET_MAX; ++n)
        {
            enum netbase::Network net = (enum netbase::Network)n;
            if (! nets.count(net)) {
                ext_ip::SetLimited(net);
            }
        }
    }
#if defined(USE_IPV6)
 #if ! USE_IPV6
     else {
         ext_ip::SetLimited(netbase::NET_IPV6);
     }
 #endif
#endif

    CService addrProxy;
    bool fProxy = false;
    if (map_arg::GetMapArgsCount("-proxy")) {
        addrProxy = CService(map_arg::GetMapArgsString("-proxy"), tcp_port::uSocksDefault);
        if (! addrProxy.IsValid()) {
            return InitError(strprintfc(_("Invalid -proxy address: '%s'"), map_arg::GetMapArgsString("-proxy").c_str()));
        }

        if (! ext_ip::IsLimited(netbase::NET_IPV4)) {
            netbase::manage::SetProxy(netbase::NET_IPV4, addrProxy, nSocksVersion);
        }
        if (nSocksVersion > 4) {
#ifdef USE_IPV6
            if (! ext_ip::IsLimited(netbase::NET_IPV6)) {
                netbase::manage::SetProxy(netbase::NET_IPV6, addrProxy, nSocksVersion);
            }
#endif
            netbase::manage::SetNameProxy(addrProxy, nSocksVersion);
        }
        fProxy = true;
    }

    //
    // -tor can override normal proxy, -notor disables tor entirely
    //
    if (!(map_arg::GetMapArgsCount("-tor") && map_arg::GetMapArgsString("-tor") == "0") && (fProxy || map_arg::GetMapArgsCount("-tor"))) {
        CService addrOnion;
        if (! map_arg::GetMapArgsCount("-tor")) {
            addrOnion = addrProxy;
        } else {
            addrOnion = CService(map_arg::GetMapArgsString("-tor"), tcp_port::uSocksDefault);
        }

        if (! addrOnion.IsValid()) {
            return InitError(strprintfc(_("Invalid -tor address: '%s'"), map_arg::GetMapArgsString("-tor").c_str()));
        }

        netbase::manage::SetProxy(netbase::NET_TOR, addrOnion, 5);
        ext_ip::SetReachable(netbase::NET_TOR);
    }

    //
    // see Step 2: parameter interactions for more information about these
    //
    if (!ext_ip::IsLimited(netbase::NET_IPV4) || !ext_ip::IsLimited(netbase::NET_IPV6)) {
        args_bool::fNoListen = !map_arg::GetBoolArg("-listen", true);
        args_bool::fDiscover = map_arg::GetBoolArg("-discover", true);
        netbase::fNameLookup = map_arg::GetBoolArg("-dns", true);
#ifdef USE_UPNP
        args_bool::fUseUPnP = map_arg::GetBoolArg("-upnp", USE_UPNP);
#endif
    } else {
        // Don't listen, discover addresses or search for nodes if IPv4 and IPv6 networking is disabled.
        args_bool::fNoListen = true;
        args_bool::fDiscover = netbase::fNameLookup = false;
        map_arg::SoftSetBoolArg("-irc", false);
        map_arg::SoftSetBoolArg("-dnsseed", false);
#ifdef USE_UPNP
        args_bool::fUseUPnP = map_arg::GetBoolArg("-upnp", USE_UPNP);
#endif
    }

    bool fBound = false;
    if (! args_bool::fNoListen) {
        std::string strError;
        if (map_arg::GetMapArgsCount("-bind")) {
            for(std::string strBind: map_arg::GetMapMultiArgsString("-bind"))
            {
                CService addrBind;
                if (! netbase::manage::Lookup(strBind.c_str(), addrBind, net_basis::GetListenPort(), false)) {
                    return InitError(strprintfc(_("Cannot resolve -bind address: '%s'"), strBind.c_str()));
                }
                fBound |= Bind(addrBind);
            }
        } else {
            struct in_addr inaddr_any;
            inaddr_any.s_addr = INADDR_ANY;
#ifdef USE_IPV6
            if (! ext_ip::IsLimited(netbase::NET_IPV6)) {
                fBound |= Bind(CService(in6addr_any, net_basis::GetListenPort()), false);
            }
#endif
            if (! ext_ip::IsLimited(netbase::NET_IPV4)) {
                fBound |= Bind(CService(inaddr_any, net_basis::GetListenPort()), !fBound);
            }
        }
        if (! fBound) {
            return InitError(_("Failed to listen on any port. Use -listen=0 if you want this."));
        }
    }

    // If Tor is reachable then listen on loopback interface,
    //    to allow allow other users reach you through the hidden service
    if (!ext_ip::IsLimited(netbase::NET_TOR) && map_arg::GetMapArgsCount("-torname")) {
        std::string strError;
        struct in_addr inaddr_loopback;
        inaddr_loopback.s_addr = htonl(INADDR_LOOPBACK);

#ifdef USE_IPV6
        if (! BindListenPort(CService(in6addr_loopback, net_basis::GetListenPort()), strError)) {
            return InitError(strError);
        }
#endif
        if (! BindListenPort(CService(inaddr_loopback, net_basis::GetListenPort()), strError)) {
            return InitError(strError);
        }
    }

    if (map_arg::GetMapArgsCount("-externalip")) {
        for(std::string strAddr: map_arg::GetMapMultiArgsString("-externalip"))
        {
            CService addrLocal(strAddr, net_basis::GetListenPort(), netbase::fNameLookup);
            if (! addrLocal.IsValid()) {
                return InitError(strprintfc(_("Cannot resolve -externalip address: '%s'"), strAddr.c_str()));
            }
            ext_ip::AddLocal(CService(strAddr, net_basis::GetListenPort(), netbase::fNameLookup), LOCAL_MANUAL);
        }
    }

    if (map_arg::GetMapArgsCount("-reservebalance")) { // ppcoin: reserve balance amount
        if (! bitstr::ParseMoney(map_arg::GetMapArgsString("-reservebalance").c_str(), miner::nReserveBalance)) {
            InitError(_("Invalid amount for -reservebalance=<amount>"));
            return false;
        }
    }

    if (map_arg::GetMapArgsCount("-checkpointkey")) { // ppcoin: checkpoint master priv key
        if (! Checkpoints::manage::SetCheckpointPrivKey(map_arg::GetArg("-checkpointkey", ""))) {
            InitError(_("Unable to sign checkpoint, wrong checkpointkey?\n"));
        }
    }

    for(std::string strDest: map_arg::GetMapMultiArgsString("-seednode")) {
        shot::AddOneShot(strDest);
    }

    // ********************************************************* Step 7: load blockchain
    I_DEBUG_CS("Step 7: load blockchain")

    if (! CDBEnv::bitdb.Open(iofs::GetDataDir())) {
        std::string msg = strprintfc(_("Error initializing database environment %s! To recover, BACKUP THAT DIRECTORY, then remove everything from it except for wallet.dat."), strDataDir.c_str());
        return InitError(msg);
    }

    if (map_arg::GetBoolArg("-loadblockindextest")) {
        CTxDB txdb("r");
        txdb.LoadBlockIndex();
        CBlock_print::PrintBlockTree();
        return false;
    }

    printf("Loading block index...\n");
    bool fLoaded = false;
    while (! fLoaded)
    {
        std::string strLoadError;
        CClientUIInterface::uiInterface.InitMessage(_("Loading block index..."));

        nStart = util::GetTimeMillis();
        do 
        {
            try {
                block_load::UnloadBlockIndex();

                if (! block_load::LoadBlockIndex()) {
                    strLoadError = _("Error loading block database");
                    break;
                }
            } catch(const std::exception&) {
                strLoadError = _("Error opening block database");
                break;
            }

            fLoaded = true;
        } while(false);

        if (! fLoaded) {
            // TODO: suggest reindex here
            return InitError(strLoadError);
        }
    }

    //
    // as LoadBlockIndex can take several minutes, it's possible the user requested to kill bitcoin-qt during the last operation. 
    // If so, exit. As the program has not fully started yet, Shutdown() is possibly overkill.
    //
    if (args_bool::fRequestShutdown) {
        printf("Shutdown requested. Exiting.\n");
        return false;
    }
    printf(" block index %15" PRId64 "ms\n", util::GetTimeMillis() - nStart);

    if (map_arg::GetBoolArg("-printblockindex") || map_arg::GetBoolArg("-printblocktree")) {
        CBlock_print::PrintBlockTree();
        return false;
    }

    if (map_arg::GetMapArgsCount("-printblock")) {
        std::string strMatch = map_arg::GetMapArgsString("-printblock");
        int nFound = 0;
        for (std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.begin(); mi != block_info::mapBlockIndex.end(); ++mi)
        {
            uint256 hash = (*mi).first;
            if (::strncmp(hash.ToString().c_str(), strMatch.c_str(), strMatch.size()) == 0) {
                CBlockIndex *pindex = (*mi).second;

                CBlock block;                
                block.ReadFromDisk(pindex);
                block.BuildMerkleTree();
                block.print();
                printf("\n");
                nFound++;
            }
        }
        if (nFound == 0) {
            printf("No blocks matching %s were found\n", strMatch.c_str());
        }
        return false;
    }

    // ********************************************************* Step 8: load wallet
    I_DEBUG_CS("Step 8: load wallet")

    if (map_arg::GetBoolArg("-zapwallettxes", false)) {
        CClientUIInterface::uiInterface.InitMessage(_("Zapping all transactions from wallet..."));

        /*
        entry::pwalletMain = new CWallet(strWalletFileName);
        DBErrors nZapWalletRet = entry::pwalletMain->ZapWalletTx();
        if (nZapWalletRet != DB_LOAD_OK) {
            CClientUIInterface::uiInterface.InitMessage(_("Error loading wallet.dat: Wallet corrupted"));
            return false;
        }
        delete entry::pwalletMain;
        entry::pwalletMain = NULL;
        */

        CWallet walletMain(strWalletFileName);
        DBErrors nZapWalletRet = walletMain.ZapWalletTx();
        if (nZapWalletRet != DB_LOAD_OK) {
            CClientUIInterface::uiInterface.InitMessage(_("Error loading wallet.dat: Wallet corrupted"));
            return false;
        }
    }

    CClientUIInterface::uiInterface.InitMessage(_("Loading wallet..."));
    printf("Loading wallet...\n");
    nStart = util::GetTimeMillis();

    bool fFirstRun = true;
    entry::pwalletMain = new(std::nothrow) CWallet(strWalletFileName);
    if(! entry::pwalletMain) {
        InitError("WalletMain memory allocate failure.");
        return false;
    }

    DBErrors nLoadWalletRet = entry::pwalletMain->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DB_LOAD_OK) {
        if (nLoadWalletRet == DB_CORRUPT) {
            strErrors << _("Error loading wallet.dat: Wallet corrupted") << "\n";
        } else if (nLoadWalletRet == DB_NONCRITICAL_ERROR) {
            std::string msg(_("Warning: error reading wallet.dat! All keys read correctly, but transaction data or address book entries might be missing or incorrect."));
            CClientUIInterface::uiInterface.ThreadSafeMessageBox(msg, _(strCoinName), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        } else if (nLoadWalletRet == DB_TOO_NEW) {
            strErrors << _("Error loading wallet.dat: Wallet requires newer version of coin") << "\n";
        } else if (nLoadWalletRet == DB_NEED_REWRITE) {
            strErrors << _("Wallet needed to be rewritten: restart " strCoinName " to complete") << "\n";
            printf("%s", strErrors.str().c_str());
            return InitError(strErrors.str());
        } else {
            strErrors << _("Error loading wallet.dat") << "\n";
        }
    }

    if (map_arg::GetBoolArg("-upgradewallet", fFirstRun)) {
        int nMaxVersion = map_arg::GetArgInt("-upgradewallet", 0);
        if (nMaxVersion == 0) { // the -upgradewallet without argument case
            printf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
            nMaxVersion = version::CLIENT_VERSION;
            entry::pwalletMain->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
        } else {
            printf("Allowing wallet upgrade up to %i\n", nMaxVersion);
        }

        if (nMaxVersion < entry::pwalletMain->GetVersion()) {
            strErrors << _("Cannot downgrade wallet") << "\n";
        }
        entry::pwalletMain->SetMaxVersion(nMaxVersion);
    }

    if (fFirstRun) {
        //
        // Create new keyUser and set as default key
        //
        seed::RandAddSeedPerfmon();

        CPubKey newDefaultKey;
        if (! entry::pwalletMain->GetKeyFromPool(newDefaultKey, false)) {
            strErrors << _("Cannot initialize keypool") << "\n";
        }
        entry::pwalletMain->SetDefaultKey(newDefaultKey);
        if (! entry::pwalletMain->SetAddressBookName(pwalletMain->vchDefaultKey.GetID(), "")) {
            strErrors << _("Cannot write default address") << "\n";
        }

        /*
        CMalleableKeyView keyView = entry::pwalletMain->GenerateNewMalleableKey();
        CMalleableKey mKey;
        if (! entry::pwalletMain->GetMalleableKey(keyView, mKey))
            strErrors << _("Unable to generate new malleable key");
        if (! entry::pwalletMain->SetAddressBookName(CBitcoinAddress(keyView.GetMalleablePubKey()), ""))
            strErrors << _("Cannot write default address") << "\n";
        */
    }

    printf("%s", strErrors.str().c_str());
    printf(" wallet      %15" PRId64 "ms\n", util::GetTimeMillis() - nStart);

    wallet_process::manage::RegisterWallet(entry::pwalletMain);

    CBlockIndex *pindexRescan = block_info::pindexBest;
    if (map_arg::GetBoolArg("-rescan")) {
        pindexRescan = block_info::pindexGenesisBlock;
    } else {
        CWalletDB walletdb(strWalletFileName);
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator)) {
            pindexRescan = locator.GetBlockIndex();
        }
    }
    if (block_info::pindexBest != pindexRescan && block_info::pindexBest && pindexRescan && block_info::pindexBest->get_nHeight() > pindexRescan->get_nHeight()) {
        CClientUIInterface::uiInterface.InitMessage(_("Rescanning..."));
        printf("Rescanning last %i blocks (from block %i)...\n", block_info::pindexBest->get_nHeight() - pindexRescan->get_nHeight(), pindexRescan->get_nHeight());
        nStart = util::GetTimeMillis();
        entry::pwalletMain->ScanForWalletTransactions(pindexRescan, true);
        printf(" rescan      %15" PRId64 "ms\n", util::GetTimeMillis() - nStart);
    }

    // ********************************************************* Step 9: import blocks
    I_DEBUG_CS("Step 9: import blocks")

    if (map_arg::GetMapArgsCount("-loadblock")) {
        CClientUIInterface::uiInterface.InitMessage(_("Importing blockchain data file."));
        for(std::string strFile: map_arg::GetMapMultiArgsString("-loadblock")) {
            FILE *file = ::fopen(strFile.c_str(), "rb");
            if (file)
                block_load::LoadExternalBlockFile(file);
        }
        boot::StartShutdown();
    }

    fs::path pathBootstrap = iofs::GetDataDir() / "bootstrap.dat";
    if (fs::exists(pathBootstrap)) {
        CClientUIInterface::uiInterface.InitMessage(_("Importing bootstrap blockchain data file."));
        FILE *file = ::fopen(pathBootstrap.string().c_str(), "rb");
        if (file) {
            fs::path pathBootstrapOld = iofs::GetDataDir() / "bootstrap.dat.old";
            block_load::LoadExternalBlockFile(file);
            iofs::RenameOver(pathBootstrap, pathBootstrapOld);
        }
    }

    // ********************************************************* Step 10: load Autocheckpoints.dat
    I_DEBUG_CS("Step 10: load Autocheckpoints.dat")

    // SorachanCoin: Autocheckpoints load
    if(! CAutocheckPoint::get_instance().BuildAutocheckPoints())
        return false;

    // ********************************************************* Step 11: load peers
    I_DEBUG_CS("Step 11: load peers")

    CClientUIInterface::uiInterface.InitMessage(_("Loading addresses..."));
    printf("Loading addresses...\n");
    nStart = util::GetTimeMillis();

    {
        CAddrDB adb;
        if (! adb.Read(net_node::addrman))
            printf("Invalid or missing peers.dat; recreating\n");
    }

    printf("Loaded %i addresses from peers.dat  %" PRId64 "ms\n", net_node::addrman.size(), util::GetTimeMillis() - nStart);

    // ********************************************************* Step 12: start node
    I_DEBUG_CS("Step 12: start node")

    if (! file_open::CheckDiskSpace())
        return false;

    seed::RandAddSeedPerfmon();

    //// debug print
    printf("mapBlockIndex.size() = %" PRIszu "\n",   block_info::mapBlockIndex.size());
    printf("nBestHeight = %d\n",                     block_info::nBestHeight);
    printf("setKeyPool.size() = %" PRIszu "\n",      entry::pwalletMain->setKeyPool.size());
    printf("mapWallet.size() = %" PRIszu "\n",       entry::pwalletMain->mapWallet.size());
    printf("mapAddressBook.size() = %" PRIszu "\n",  entry::pwalletMain->mapAddressBook.size());

    if (! bitthread::NewThread(net_node::StartNode, nullptr))
        InitError(_("Error: could not start node"));

    if (args_bool::fServer) {
        if(! bitthread::NewThread(bitrpc::ThreadRPCServer, nullptr))
            bitthread::thread_error(std::string(__func__) + " :ThreadRPCServer");
    }

    // ********************************************************* Step 13: IP collection thread
    I_DEBUG_CS("Step 13: IP collection thread")

    ip_coll::strCollectorCommand = map_arg::GetArg("-peercollector", "");
    if (!args_bool::fTestNet && ip_coll::strCollectorCommand != "") {
        if(! bitthread::NewThread(ip_coll::ThreadIPCollector, nullptr))
            bitthread::thread_error(std::string(__func__) + " :ThreadIPCollector");
    }

    // ********************************************************* Step 14: finished
    I_DEBUG_CS("Step 14: finished")

    CClientUIInterface::uiInterface.InitMessage(_("Done loading"));
    printf("Done loading\n");

    if (! strErrors.str().empty())
        return InitError(strErrors.str());

    // Add wallet transactions that aren't already in a block to mapTransactions
    entry::pwalletMain->ReacceptWalletTransactions();

#if !defined(QT_GUI)
    //
    // Loop until process is exit()ed from shutdown() function,
    // called from ThreadRPCServer thread when a "stop" command is received.
    //
    for ( ; ; )
    {
        util::Sleep(5000);
    }
#endif

    return true;
}
