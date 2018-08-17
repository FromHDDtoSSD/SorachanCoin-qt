// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include "txdb.h"
#include "walletdb.h"
#include "bitcoinrpc.h"
#include "net.h"
#include "init.h"
#include "util.h"
#include "ipcollector.h"
#include "ui_interface.h"
#include "checkpoints.h"
#include "miner.h"
#include <boost/format.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/convenience.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <openssl/crypto.h>

#ifndef WIN32
#include <signal.h>
#endif

//
// static
//
CClientUIInterface CClientUIInterface::uiInterface;
std::string entry::strWalletFileName;
CWallet *entry::pwalletMain = NULL;
enum Checkpoints::CPMode entry::CheckpointsMode;

//
// Shutdown
//
void entry::ExitTimeout(void *parg)
{
#ifdef WIN32
	util::Sleep(5000);
	ExitProcess(0);
#endif
}

void entry::StartShutdown()
{
#ifdef QT_GUI
	// ensure we leave the Qt main loop for a clean GUI exit (Shutdown() is called in bitcoin.cpp afterwards)
	CClientUIInterface::uiInterface.QueueShutdown();
#else
	// Without UI, Shutdown() can simply be started in a new thread
	bitthread::manage::NewThread(net_node::Shutdown, NULL);
#endif
}

void net_node::Shutdown(void *parg)
{
	static CCriticalSection cs_Shutdown;
	static bool fTaken;

	// Make this thread recognisable as the shutdown thread
	bitthread::manage::RenameThread((coin_param::strCoinName + "-shutoff").c_str());

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

		bitthread::manage::NewThread(entry::ExitTimeout, NULL);
		util::Sleep(50);
		printf("%s exited\n\n", coin_param::strCoinName.c_str());
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
		bitthread::manage::ExitThread(0);
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
		map_arg::ParseParameters(argc, argv);
		if (! boost::filesystem::is_directory(iofs::GetDataDir(false))) {
			fprintf(stderr, "Error: Specified directory does not exist\n");
			net_node::Shutdown(NULL);
		}
		map_arg::ReadConfigFile();

		if (map_arg::GetMapArgsCount("-?") || map_arg::GetMapArgsCount("--help")) {
			//
			// First part of help message is specific to bitcoind / RPC client
			//
			std::string strUsage = _((coin_param::strCoinName + " version").c_str()) + (
				  " " + format_version::FormatFullVersion() + "\n\n" + _("Usage:") + "\n" +
				  "  " + coin_param::strCoinName + "d [options]                     " + "\n" +
				  "  " + coin_param::strCoinName + "d [options] <command> [params]  " + _(("Send command to -server or " + coin_param::strCoinName + "d").c_str()) + "\n" +
				  "  " + coin_param::strCoinName + "d [options] help                " + _("List commands") + "\n" +
				  "  " + coin_param::strCoinName + "d [options] help <command>      " + _("Get help for a command") + "\n"
				  ).c_str();

			strUsage += "\n" + HelpMessage();

			fprintf(stdout, "%s", strUsage.c_str());
			return false;
		}

		//
		// Command-line RPC
		//
		for (int i = 1; i < argc; ++i)
		{
			if (!util::IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], (coin_param::strCoinName + ":").c_str())) {
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
		net_node::Shutdown(NULL);
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
	CClientUIInterface::uiInterface.ThreadSafeMessageBox(str, _(coin_param::strCoinName.c_str()), CClientUIInterface::OK | CClientUIInterface::MODAL);
	return false;
}

bool entry::InitWarning(const std::string &str)
{
	CClientUIInterface::uiInterface.ThreadSafeMessageBox(str, _(coin_param::strCoinName.c_str()), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
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

// Core-specific options shared between UI and daemon
std::string entry::HelpMessage()
{
	std::string strUsage = _("Options:") + "\n" +
		"  -?                     " + _("This help message") + "\n" +
		"  -conf=<file>           " + _(("Specify configuration file (default: " + coin_param::strCoinNameL + ".conf)").c_str()) + "\n" +
		"  -pid=<file>            " + _(("Specify pid file (default: " + coin_param::strCoinNameL + "d.pid)").c_str()) + "\n" +
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
		"  -port=<port>           " + _(("Listen for connections on <port> (default: " + std::to_string(tcp_port::uMainnet) + "or testnet: " + std::to_string(tcp_port::uTestnet) + ")").c_str()) + "\n" +
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
		"  -mininput=<amt>        " + str(boost::format(_("When creating transactions, ignore inputs with value less than this (default: %s)")) % bitstr::FormatMoney(block_param::MIN_TXOUT_AMOUNT)) + "\n" +
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
		"  -rpcport=<port>        " + _(("Listen for JSON-RPC connections on <port> (default: " + std::to_string(tcp_port::uJsonRpcMain) + " or testnet: " + std::to_string(tcp_port::uJsonRpcTest) + ")").c_str()) + "\n" +
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
bool entry::AppInit2()
{
	// ********************************************************* Step 1: setup

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

	args_uint::nNodeLifespan = map_arg::GetArgUInt("-addrlifespan", 7);
	args_bool::fUseFastIndex = map_arg::GetBoolArg("-fastindex", true);
	args_bool::fUseMemoryLog = map_arg::GetBoolArg("-memorylog", true);

	// Ping and address broadcast intervals
	block_process::manage::nPingInterval = std::max<int64_t>(10 * 60, map_arg::GetArg("-keepalive", 30 * 60));

	entry::CheckpointsMode = Checkpoints::STRICT;
	std::string strCpMode = map_arg::GetArg("-cppolicy", "strict");

	if(strCpMode == "strict") {
		entry::CheckpointsMode = Checkpoints::STRICT;
	}

	if(strCpMode == "advisory") {
		entry::CheckpointsMode = Checkpoints::ADVISORY;
	}

	if(strCpMode == "permissive") {
		entry::CheckpointsMode = Checkpoints::PERMISSIVE;
	}

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

	// ********************************************************* Step 3: parameter-to-internal-flags

	//
	// -par=0 means autodetect, but block_info::nScriptCheckThreads==0 means no concurrency
	//
	block_info::nScriptCheckThreads = map_arg::GetArgInt("-par", 0);
	if (block_info::nScriptCheckThreads == 0) {
		block_info::nScriptCheckThreads = boost::thread::hardware_concurrency();
	}

	if (block_info::nScriptCheckThreads <= 1) {
		block_info::nScriptCheckThreads = 0;
	} else if (block_info::nScriptCheckThreads > block_param::MAX_SCRIPTCHECK_THREADS) {
		block_info::nScriptCheckThreads = block_param::MAX_SCRIPTCHECK_THREADS;
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
		if (! bitstr::ParseMoney(map_arg::GetMapArgsString("-paytxfee"), block_info::nTransactionFee)) {
			return InitError(strprintf(_("Invalid amount for -paytxfee=<amount>: '%s'"), map_arg::GetMapArgsString("-paytxfee").c_str()));
		}
		if (block_info::nTransactionFee > 0.25 * util::COIN) {
			InitWarning(_("Warning: -paytxfee is set very high! This is the transaction fee you will pay if you send a transaction."));
		}
	}

	args_bool::fConfChange = map_arg::GetBoolArg("-confchange", false);

	if (map_arg::GetMapArgsCount("-mininput")) {
		if (! bitstr::ParseMoney(map_arg::GetMapArgsString("-mininput"), block_info::nMinimumInputValue)) {
			return InitError(strprintf(_("Invalid amount for -mininput=<amount>: '%s'"), map_arg::GetMapArgsString("-mininput").c_str()));
		}
	}

	// ********************************************************* Step 4: application initialization: dir lock, daemonize, pidfile, debug log

	std::string strDataDir = iofs::GetDataDir().string();
	strWalletFileName = map_arg::GetArg("-wallet", "wallet.dat");

	// strWalletFileName must be a plain filename without a directory
	if (strWalletFileName != boost::filesystem::basename(strWalletFileName) + boost::filesystem::extension(strWalletFileName)) {
		return InitError(strprintf(_("Wallet %s resides outside data directory %s."), strWalletFileName.c_str(), strDataDir.c_str()));
	}

	//
	// Lock File
	// Make sure only a single Bitcoin process is using the data directory
	//
	boost::filesystem::path pathLockFile = iofs::GetDataDir() / ".lock";
	FILE *file = fopen(pathLockFile.string().c_str(), "a"); // empty lock file; created if it doesn't exist.
	if (file) {
		fclose(file);
	}
	static boost::interprocess::file_lock lock(pathLockFile.string().c_str());
	if (! lock.try_lock()) {
		return InitError(strprintf(_("Cannot obtain a lock on data directory %s. %s is probably already running."), strDataDir.c_str(), coin_param::strCoinName.c_str()));
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
	printf("%s version %s (%s)\n", coin_param::strCoinName.c_str(), format_version::FormatFullVersion().c_str(), version::CLIENT_DATE.c_str());
	printf("Using OpenSSL version %s\n", SSLeay_version(SSLEAY_VERSION));
    if (! args_bool::fLogTimestamps) {
		printf("Startup time: %s\n", util::DateTimeStrFormat("%x %H:%M:%S", bitsystem::GetTime()).c_str());
	}
	printf("Default data directory %s\n", iofs::GetDefaultDataDir().string().c_str());
	printf("Used data directory %s\n", strDataDir.c_str());
	std::ostringstream strErrors;

    if (args_bool::fDaemon) {
		fprintf(stdout, (coin_param::strCoinName + " server starting\n").c_str());
	}

	if (block_info::nScriptCheckThreads) {
		printf("Using %u threads for script verification\n", block_info::nScriptCheckThreads);
		for (int i=0; i < block_info::nScriptCheckThreads-1; ++i)
		{
			bitthread::manage::NewThread(block_check::thread::ThreadScriptCheck, NULL);
		}
	}

	int64_t nStart;

	// ********************************************************* Step 5: verify database integrity

	CClientUIInterface::uiInterface.InitMessage(_("Verifying database integrity..."));

	if (! CDBEnv::bitdb.Open(iofs::GetDataDir())) {
		std::string msg = strprintf(_("Error initializing database environment %s! To recover, BACKUP THAT DIRECTORY, then remove everything from it except for wallet.dat."), strDataDir.c_str());
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
			std::string msg = strprintf(_("Warning: wallet.dat corrupt, data salvaged!"
									      " Original wallet.dat saved as wallet.{timestamp}.bak in %s; if"
									      " your balance or transactions are incorrect you should"
									      " restore from a backup."), strDataDir.c_str());
			CClientUIInterface::uiInterface.ThreadSafeMessageBox(msg, _(coin_param::strCoinName.c_str()), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
		}
		if (r == CDBEnv::RECOVER_FAIL) {
			return InitError(_("wallet.dat corrupt, salvage failed"));
		}
	}

	// ********************************************************* Step 6: network initialization

	int nSocksVersion = map_arg::GetArgInt("-socks", 5);

	if (nSocksVersion != 4 && nSocksVersion != 5) {
		return InitError(strprintf(_("Unknown -socks proxy version requested: %i"), nSocksVersion));
	}

	if (map_arg::GetMapArgsCount("-onlynet")) {
		std::set<enum netbase::Network> nets;
		BOOST_FOREACH(std::string snet, map_arg::GetMapMultiArgsString("-onlynet"))
		{
			enum netbase::Network net = netbase::manage::ParseNetwork(snet);
			if (net == netbase::NET_UNROUTABLE) {
				return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet.c_str()));
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
		addrProxy = CService(map_arg::GetMapArgsString("-proxy"), nSocksDefault);
		if (! addrProxy.IsValid()) {
			return InitError(strprintf(_("Invalid -proxy address: '%s'"), map_arg::GetMapArgsString("-proxy").c_str()));
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
			addrOnion = CService(map_arg::GetMapArgsString("-tor"), nSocksDefault);
		}

		if (! addrOnion.IsValid()) {
			return InitError(strprintf(_("Invalid -tor address: '%s'"), map_arg::GetMapArgsString("-tor").c_str()));
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
			BOOST_FOREACH(std::string strBind, map_arg::GetMapMultiArgsString("-bind")) {
				CService addrBind;
				if (! netbase::manage::Lookup(strBind.c_str(), addrBind, net_basis::GetListenPort(), false)) {
					return InitError(strprintf(_("Cannot resolve -bind address: '%s'"), strBind.c_str()));
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
			if (!ext_ip::IsLimited(netbase::NET_IPV4)) {
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
		BOOST_FOREACH(std::string strAddr, map_arg::GetMapMultiArgsString("-externalip"))
		{
			CService addrLocal(strAddr, net_basis::GetListenPort(), netbase::fNameLookup);
			if (! addrLocal.IsValid()) {
				return InitError(strprintf(_("Cannot resolve -externalip address: '%s'"), strAddr.c_str()));
			}
			ext_ip::AddLocal(CService(strAddr, net_basis::GetListenPort(), netbase::fNameLookup), LOCAL_MANUAL);
		}
	}

	if (map_arg::GetMapArgsCount("-reservebalance")) { // ppcoin: reserve balance amount
		if (! bitstr::ParseMoney(map_arg::GetMapArgsString("-reservebalance"), miner::nReserveBalance)) {
			InitError(_("Invalid amount for -reservebalance=<amount>"));
			return false;
		}
	}

	if (map_arg::GetMapArgsCount("-checkpointkey")) { // ppcoin: checkpoint master priv key
		if (! Checkpoints::manage::SetCheckpointPrivKey(map_arg::GetArg("-checkpointkey", ""))) {
			InitError(_("Unable to sign checkpoint, wrong checkpointkey?\n"));
		}
	}

	BOOST_FOREACH(std::string strDest, map_arg::GetMapMultiArgsString("-seednode"))
	{
		shot::AddOneShot(strDest);
	}

	// ********************************************************* Step 7: load blockchain

	if (! CDBEnv::bitdb.Open(iofs::GetDataDir())) {
		std::string msg = strprintf(_("Error initializing database environment %s! To recover, BACKUP THAT DIRECTORY, then remove everything from it except for wallet.dat."), strDataDir.c_str());
		return InitError(msg);
	}

	if (map_arg::GetBoolArg("-loadblockindextest")) {
		CTxDB txdb("r");
		txdb.LoadBlockIndex();
		CBlock::PrintBlockTree();
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
		CBlock::PrintBlockTree();
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
			CClientUIInterface::uiInterface.ThreadSafeMessageBox(msg, _(coin_param::strCoinName.c_str()), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
		} else if (nLoadWalletRet == DB_TOO_NEW) {
			strErrors << _("Error loading wallet.dat: Wallet requires newer version of coin") << "\n";
		} else if (nLoadWalletRet == DB_NEED_REWRITE) {
			strErrors << _(("Wallet needed to be rewritten: restart " + coin_param::strCoinName + " to complete").c_str()) << "\n";
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
	if (block_info::pindexBest != pindexRescan && block_info::pindexBest && pindexRescan && block_info::pindexBest->nHeight > pindexRescan->nHeight) {
		CClientUIInterface::uiInterface.InitMessage(_("Rescanning..."));
		printf("Rescanning last %i blocks (from block %i)...\n", block_info::pindexBest->nHeight - pindexRescan->nHeight, pindexRescan->nHeight);
		nStart = util::GetTimeMillis();
		entry::pwalletMain->ScanForWalletTransactions(pindexRescan, true);
		printf(" rescan      %15" PRId64 "ms\n", util::GetTimeMillis() - nStart);
	}

	// ********************************************************* Step 9: import blocks

	if (map_arg::GetMapArgsCount("-loadblock")) {
		CClientUIInterface::uiInterface.InitMessage(_("Importing blockchain data file."));

		BOOST_FOREACH(std::string strFile, map_arg::GetMapMultiArgsString("-loadblock"))
		{
			FILE *file = ::fopen(strFile.c_str(), "rb");
			if (file) {
				block_load::LoadExternalBlockFile(file);
			}
		}
		entry::StartShutdown();
	}

	boost::filesystem::path pathBootstrap = iofs::GetDataDir() / "bootstrap.dat";
	if (boost::filesystem::exists(pathBootstrap)) {
		CClientUIInterface::uiInterface.InitMessage(_("Importing bootstrap blockchain data file."));

		FILE *file = ::fopen(pathBootstrap.string().c_str(), "rb");
		if (file) {
			boost::filesystem::path pathBootstrapOld = iofs::GetDataDir() / "bootstrap.dat.old";
			block_load::LoadExternalBlockFile(file);
			iofs::RenameOver(pathBootstrap, pathBootstrapOld);
		}
	}

	// ********************************************************* Step 10: load peers

	CClientUIInterface::uiInterface.InitMessage(_("Loading addresses..."));
	printf("Loading addresses...\n");
	nStart = util::GetTimeMillis();

	{
		CAddrDB adb;
		if (! adb.Read(net_node::addrman)) {
			printf("Invalid or missing peers.dat; recreating\n");
		}
	}

	printf("Loaded %i addresses from peers.dat  %" PRId64 "ms\n", net_node::addrman.size(), util::GetTimeMillis() - nStart);

	// ********************************************************* Step 11: start node

	if (! file_open::CheckDiskSpace()) {
		return false;
	}

	seed::RandAddSeedPerfmon();

	//// debug print
	printf("mapBlockIndex.size() = %" PRIszu "\n",   block_info::mapBlockIndex.size());
	printf("nBestHeight = %d\n",                     block_info::nBestHeight);
	printf("setKeyPool.size() = %" PRIszu "\n",      entry::pwalletMain->setKeyPool.size());
	printf("mapWallet.size() = %" PRIszu "\n",       entry::pwalletMain->mapWallet.size());
	printf("mapAddressBook.size() = %" PRIszu "\n",  entry::pwalletMain->mapAddressBook.size());

	if (! bitthread::manage::NewThread(net_node::StartNode, NULL)) {
		InitError(_("Error: could not start node"));
	}

    if (args_bool::fServer) {
		bitthread::manage::NewThread(bitrpc::ThreadRPCServer, NULL);
	}

	// ********************************************************* Step 13: IP collection thread

	ip_coll::strCollectorCommand = map_arg::GetArg("-peercollector", "");
    if (!args_bool::fTestNet && ip_coll::strCollectorCommand != "") {
		bitthread::manage::NewThread(ip_coll::ThreadIPCollector, NULL);
	}

	// ********************************************************* Step 14: finished

	CClientUIInterface::uiInterface.InitMessage(_("Done loading"));
	printf("Done loading\n");

	if (! strErrors.str().empty()) {
		return InitError(strErrors.str());
	}

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
