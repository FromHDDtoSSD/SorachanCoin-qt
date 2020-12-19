// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
#include <const/chainparamsbase.h>
#include <const/chainparams.h>
#include <util/args.h>
#include <util/tinyformat.h>

void arginit::SetupServerArgs() {
    using namespace chainparamsbase;

    SetupHelpOptions(gArgs);
    gArgs.AddArg("-help-debug", "Print help message with debugging options and exit", false, OptionsCategory::DEBUG_TEST); // server-only for now

    const auto defaultBaseParams = CreateBaseChainParams(CBaseChainParams::MAIN());
    const auto testnetBaseParams = CreateBaseChainParams(CBaseChainParams::TESTNET());
    const auto testnet2BaseParams = CreateBaseChainParams(CBaseChainParams::TESTNET2());
    const auto regtestBaseParams = CreateBaseChainParams(CBaseChainParams::REGTEST());
    const auto predictionBaseParams = CreateBaseChainParams(CBaseChainParams::PREDICTION());
    const auto defaultChainParams = CreateChainParams(CBaseChainParams::MAIN());
    const auto testnetChainParams = CreateChainParams(CBaseChainParams::TESTNET());
    const auto testnet2ChainParams = CreateChainParams(CBaseChainParams::TESTNET2());
    const auto regtestChainParams = CreateChainParams(CBaseChainParams::REGTEST());
    const auto predictionChainParams = CreateChainParams(CBaseChainParams::PREDICTION());

    // Hidden Options
    std::vector<std::string> hidden_args = {
        "-dbcrashratio", "-forcecompactdb",
        // GUI args. These will be overwritten by SetupUIArgs for the GUI
        "-allowselfsignedrootcertificates", "-choosedatadir", "-lang=<lang>", "-min", "-resetguisettings", "-rootcertificates=<file>", "-splash", "-uiplatform"};

    gArgs.AddArg("-version", "Print version and exit", false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-alertnotify=<cmd>", "Execute command when a relevant alert is received or we see a really long fork (%s in cmd is replaced by message)", false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-assumevalid=<hex>", strprintf("If this block is in the chain assume that it and its ancestors are valid and potentially skip their script verification (0 to verify all, default: %s, testnet: %s)", defaultChainParams->GetConsensus().defaultAssumeValid.GetHex(), testnetChainParams->GetConsensus().defaultAssumeValid.GetHex()), false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-blocksdir=<dir>", "Specify blocks directory (default: <datadir>/blocks)", false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-blocknotify=<cmd>", "Execute command when the best block changes (%s in cmd is replaced by block hash)", false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-blockreconstructionextratxn=<n>", strprintf("Extra transactions to keep in memory for compact block reconstructions (default: %u)", DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN), false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-blocksonly", strprintf("Whether to reject transactions from network peers. Transactions from the wallet or RPC are not affected. (default: %u)", DEFAULT_BLOCKSONLY), false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-conf=<file>", strprintf("Specify configuration file. Relative paths will be prefixed by datadir location. (default: %s)", BITCOIN_CONF_FILENAME), false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-datadir=<dir>", "Specify data directory", false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-dbbatchsize", strprintf("Maximum database write batch size in bytes (default: %u)", nDefaultDbBatchSize), true, OptionsCategory::OPTIONS);
    gArgs.AddArg("-dbcache=<n>", strprintf("Maximum database cache size <n> MiB (%d to %d, default: %d). In addition, unused mempool memory is shared for this cache (see -maxmempool).", nMinDbCache, nMaxDbCache, nDefaultDbCache), false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-debuglogfile=<file>", strprintf("Specify location of debug log file. Relative paths will be prefixed by a net-specific datadir location. (-nodebuglogfile to disable; default: %s)", DEFAULT_DEBUGLOGFILE), false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-feefilter", strprintf("Tell other nodes to filter invs to us by our mempool min fee (default: %u)", DEFAULT_FEEFILTER), true, OptionsCategory::OPTIONS);
    gArgs.AddArg("-includeconf=<file>", "Specify additional configuration file, relative to the -datadir path (only useable from configuration file, not command line)", false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-loadblock=<file>", "Imports blocks from external blk000??.dat file on startup", false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-maxmempool=<n>", strprintf("Keep the transaction memory pool below <n> megabytes (default: %u)", DEFAULT_MAX_MEMPOOL_SIZE), false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-maxorphantx=<n>", strprintf("Keep at most <n> unconnectable transactions in memory (default: %u)", DEFAULT_MAX_ORPHAN_TRANSACTIONS), false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-mempoolexpiry=<n>", strprintf("Do not keep transactions in the mempool longer than <n> hours (default: %u)", DEFAULT_MEMPOOL_EXPIRY), false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-minimumchainwork=<hex>", strprintf("Minimum work assumed to exist on a valid chain in hex (default: %s, testnet: %s)", defaultChainParams->GetConsensus().nMinimumChainWork.GetHex(), testnetChainParams->GetConsensus().nMinimumChainWork.GetHex()), true, OptionsCategory::OPTIONS);
    gArgs.AddArg("-par=<n>", strprintf("Set the number of script verification threads (%u to %d, 0 = auto, <0 = leave that many cores free, default: %d)",
        -GetNumCores(), MAX_SCRIPTCHECK_THREADS, DEFAULT_SCRIPTCHECK_THREADS), false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-persistmempool", strprintf("Whether to save the mempool on shutdown and load on restart (default: %u)", DEFAULT_PERSIST_MEMPOOL), false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-pid=<file>", strprintf("Specify pid file. Relative paths will be prefixed by a net-specific datadir location. (default: %s)", BITCOIN_PID_FILENAME), false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-prune=<n>", strprintf("Reduce storage requirements by enabling pruning (deleting) of old blocks. This allows the pruneblockchain RPC to be called to delete specific blocks, and enables automatic pruning of old blocks if a target size in MiB is provided. This mode is incompatible with -txindex and -rescan. "
            "Warning: Reverting this setting requires re-downloading the entire blockchain. "
            "(default: 0 = disable pruning blocks, 1 = allow manual pruning via RPC, >=%u = automatically prune block files to stay under the specified target size in MiB)", MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024), false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-reindex", "Rebuild chain state and block index from the blk*.dat files on disk", false, OptionsCategory::OPTIONS);
    gArgs.AddArg("-reindex-chainstate", "Rebuild chain state from the currently indexed blocks. When in pruning mode or if blocks on disk might be corrupted, use full -reindex instead.", false, OptionsCategory::OPTIONS);
#ifndef WIN32
    gArgs.AddArg("-sysperms", "Create new files with system default permissions, instead of umask 077 (only effective with disabled wallet functionality)", false, OptionsCategory::OPTIONS);
#else
    hidden_args.emplace_back("-sysperms");
#endif
    gArgs.AddArg("-txindex", strprintf("Maintain a full transaction index, used by the getrawtransaction rpc call (default: %u)", DEFAULT_TXINDEX), false, OptionsCategory::OPTIONS);

    gArgs.AddArg("-addnode=<ip>", "Add a node to connect to and attempt to keep the connection open (see the `addnode` RPC command help for more info). This option can be specified multiple times to add multiple nodes.", false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-banscore=<n>", strprintf("Threshold for disconnecting misbehaving peers (default: %u)", DEFAULT_BANSCORE_THRESHOLD), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-bantime=<n>", strprintf("Number of seconds to keep misbehaving peers from reconnecting (default: %u)", DEFAULT_MISBEHAVING_BANTIME), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-bind=<addr>", "Bind to given address and always listen on it. Use [host]:port notation for IPv6", false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-connect=<ip>", "Connect only to the specified node; -noconnect disables automatic connections (the rules for this peer are the same as for -addnode). This option can be specified multiple times to connect to multiple nodes.", false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-discover", "Discover own IP addresses (default: 1 when listening and no -externalip or -proxy)", false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-dns", strprintf("Allow DNS lookups for -addnode, -seednode and -connect (default: %u)", DEFAULT_NAME_LOOKUP), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-dnsseed", "Query for peer addresses via DNS lookup, if low on addresses (default: 1 unless -connect used)", false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-enablebip61", strprintf("Send reject messages per BIP61 (default: %u)", DEFAULT_ENABLE_BIP61), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-externalip=<ip>", "Specify your own public address", false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-forcednsseed", strprintf("Always query for peer addresses via DNS lookup (default: %u)", DEFAULT_FORCEDNSSEED), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-listen", "Accept connections from outside (default: 1 if no -proxy or -connect)", false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-listenonion", strprintf("Automatically create Tor hidden service (default: %d)", DEFAULT_LISTEN_ONION), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-maxconnections=<n>", strprintf("Maintain at most <n> connections to peers (default: %u)", DEFAULT_MAX_PEER_CONNECTIONS), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-maxreceivebuffer=<n>", strprintf("Maximum per-connection receive buffer, <n>*1000 bytes (default: %u)", DEFAULT_MAXRECEIVEBUFFER), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-maxsendbuffer=<n>", strprintf("Maximum per-connection send buffer, <n>*1000 bytes (default: %u)", DEFAULT_MAXSENDBUFFER), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-maxtimeadjustment", strprintf("Maximum allowed median peer time offset adjustment. Local perspective of time may be influenced by peers forward or backward by this amount. (default: %u seconds)", DEFAULT_MAX_TIME_ADJUSTMENT), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-maxuploadtarget=<n>", strprintf("Tries to keep outbound traffic under the given target (in MiB per 24h), 0 = no limit (default: %d)", DEFAULT_MAX_UPLOAD_TARGET), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-onion=<ip:port>", "Use separate SOCKS5 proxy to reach peers via Tor hidden services, set -noonion to disable (default: -proxy)", false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-onlynet=<net>", "Make outgoing connections only through network <net> (ipv4, ipv6 or onion). Incoming connections are not affected by this option. This option can be specified multiple times to allow multiple networks.", false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-peerbloomfilters", strprintf("Support filtering of blocks and transaction with bloom filters (default: %u)", DEFAULT_PEERBLOOMFILTERS), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-permitbaremultisig", strprintf("Relay non-P2SH multisig (default: %u)", DEFAULT_PERMIT_BAREMULTISIG), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-port=<port>", strprintf("Listen for connections on <port> (default: %u, testnet: %u, regtest: %u)", defaultChainParams->GetDefaultPort(), testnetChainParams->GetDefaultPort(), regtestChainParams->GetDefaultPort()), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-proxy=<ip:port>", "Connect through SOCKS5 proxy, set -noproxy to disable (default: disabled)", false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-proxyrandomize", strprintf("Randomize credentials for every proxy connection. This enables Tor stream isolation (default: %u)", DEFAULT_PROXYRANDOMIZE), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-seednode=<ip>", "Connect to a node to retrieve peer addresses, and disconnect. This option can be specified multiple times to connect to multiple nodes.", false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-timeout=<n>", strprintf("Specify connection timeout in milliseconds (minimum: 1, default: %d)", DEFAULT_CONNECT_TIMEOUT), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-peertimeout=<n>", strprintf("Specify p2p connection timeout in seconds. This option determines the amount of time a peer may be inactive before the connection to it is dropped. (minimum: 1, default: %d)", DEFAULT_PEER_CONNECT_TIMEOUT), true, OptionsCategory::CONNECTION);
    gArgs.AddArg("-torcontrol=<ip>:<port>", strprintf("Tor control port to use if onion listening enabled (default: %s)", DEFAULT_TOR_CONTROL), false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-torpassword=<pass>", "Tor control port password (default: empty)", false, OptionsCategory::CONNECTION);
#ifdef USE_UPNP
#if USE_UPNP
    gArgs.AddArg("-upnp", "Use UPnP to map the listening port (default: 1 when listening and no -proxy)", false, OptionsCategory::CONNECTION);
#else
    gArgs.AddArg("-upnp", strprintf("Use UPnP to map the listening port (default: %u)", 0), false, OptionsCategory::CONNECTION);
#endif
#else
    hidden_args.emplace_back("-upnp");
#endif
    gArgs.AddArg("-whitebind=<addr>", "Bind to given address and whitelist peers connecting to it. Use [host]:port notation for IPv6", false, OptionsCategory::CONNECTION);
    gArgs.AddArg("-whitelist=<IP address or network>", "Whitelist peers connecting from the given IP address (e.g. 1.2.3.4) or CIDR notated network (e.g. 1.2.3.0/24). Can be specified multiple times."
        " Whitelisted peers cannot be DoS banned", false, OptionsCategory::CONNECTION);

    g_wallet_init_interface.AddWalletOptions();

#if ENABLE_ZMQ
    gArgs.AddArg("-zmqpubhashblock=<address>", "Enable publish hash block in <address>", false, OptionsCategory::ZMQ);
    gArgs.AddArg("-zmqpubhashtx=<address>", "Enable publish hash transaction in <address>", false, OptionsCategory::ZMQ);
    gArgs.AddArg("-zmqpubrawblock=<address>", "Enable publish raw block in <address>", false, OptionsCategory::ZMQ);
    gArgs.AddArg("-zmqpubrawtx=<address>", "Enable publish raw transaction in <address>", false, OptionsCategory::ZMQ);
    gArgs.AddArg("-zmqpubhashblockhwm=<n>", strprintf("Set publish hash block outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), false, OptionsCategory::ZMQ);
    gArgs.AddArg("-zmqpubhashtxhwm=<n>", strprintf("Set publish hash transaction outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), false, OptionsCategory::ZMQ);
    gArgs.AddArg("-zmqpubrawblockhwm=<n>", strprintf("Set publish raw block outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), false, OptionsCategory::ZMQ);
    gArgs.AddArg("-zmqpubrawtxhwm=<n>", strprintf("Set publish raw transaction outbound message high water mark (default: %d)", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM), false, OptionsCategory::ZMQ);
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

    gArgs.AddArg("-checkblocks=<n>", strprintf("How many blocks to check at startup (default: %u, 0 = all)", DEFAULT_CHECKBLOCKS), true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-checklevel=<n>", strprintf("How thorough the block verification of -checkblocks is: "
        "level 0 reads the blocks from disk, "
        "level 1 verifies block validity, "
        "level 2 verifies undo data, "
        "level 3 checks disconnection of tip blocks, "
        "and level 4 tries to reconnect the blocks, "
        "each level includes the checks of the previous levels "
        "(0-4, default: %u)", DEFAULT_CHECKLEVEL), true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-checkblockindex", strprintf("Do a full consistency check for mapBlockIndex, setBlockIndexCandidates, chainActive and mapBlocksUnlinked occasionally. (default: %u, regtest: %u)", defaultChainParams->DefaultConsistencyChecks(), regtestChainParams->DefaultConsistencyChecks()), true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-checkmempool=<n>", strprintf("Run checks every <n> transactions (default: %u, regtest: %u)", defaultChainParams->DefaultConsistencyChecks(), regtestChainParams->DefaultConsistencyChecks()), true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-checkpoints", strprintf("Disable expensive verification for known chain history (default: %u)", DEFAULT_CHECKPOINTS_ENABLED), true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-deprecatedrpc=<method>", "Allows deprecated RPC method(s) to be used", true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-dropmessagestest=<n>", "Randomly drop 1 of every <n> network messages", true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-stopafterblockimport", strprintf("Stop running after importing blocks from disk (default: %u)", DEFAULT_STOPAFTERBLOCKIMPORT), true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-stopatheight", strprintf("Stop running after reaching the given height in the main chain (default: %u)", DEFAULT_STOPATHEIGHT), true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-limitancestorcount=<n>", strprintf("Do not accept transactions if number of in-mempool ancestors is <n> or more (default: %u)", DEFAULT_ANCESTOR_LIMIT), true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-limitancestorsize=<n>", strprintf("Do not accept transactions whose size with all in-mempool ancestors exceeds <n> kilobytes (default: %u)", DEFAULT_ANCESTOR_SIZE_LIMIT), true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-limitdescendantcount=<n>", strprintf("Do not accept transactions if any ancestor would have <n> or more in-mempool descendants (default: %u)", DEFAULT_DESCENDANT_LIMIT), true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-limitdescendantsize=<n>", strprintf("Do not accept transactions if any ancestor would have more than <n> kilobytes of in-mempool descendants (default: %u).", DEFAULT_DESCENDANT_SIZE_LIMIT), true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-addrmantest", "Allows to test address relay on localhost", true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-debug=<category>", "Output debugging information (default: -nodebug, supplying <category> is optional). "
        "If <category> is not supplied or if <category> = 1, output all debugging information. <category> can be: " + ListLogCategories() + ".", false, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-debugexclude=<category>", strprintf("Exclude debugging information for a category. Can be used in conjunction with -debug=1 to output debug logs for all categories except one or more specified categories."), false, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-logips", strprintf("Include IP addresses in debug output (default: %u)", DEFAULT_LOGIPS), false, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-logtimestamps", strprintf("Prepend debug output with timestamp (default: %u)", DEFAULT_LOGTIMESTAMPS), false, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-logtimemicros", strprintf("Add microsecond precision to debug timestamps (default: %u)", DEFAULT_LOGTIMEMICROS), true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-mocktime=<n>", "Replace actual time with <n> seconds since epoch (default: 0)", true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-maxsigcachesize=<n>", strprintf("Limit sum of signature cache and script execution cache sizes to <n> MiB (default: %u)", DEFAULT_MAX_SIG_CACHE_SIZE), true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-maxtipage=<n>", strprintf("Maximum tip age in seconds to consider node in initial block download (default: %u)", DEFAULT_MAX_TIP_AGE), true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-maxtxfee=<amt>", strprintf("Maximum total fees (in %s) to use in a single wallet transaction or raw transaction; setting this too low may abort large transactions (default: %s)",
        CURRENCY_UNIT, FormatMoney(DEFAULT_TRANSACTION_MAXFEE)), false, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-printpriority", strprintf("Log transaction fee per kB when mining blocks (default: %u)", DEFAULT_PRINTPRIORITY), true, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-printtoconsole", "Send trace/debug info to console (default: 1 when no -daemon. To disable logging to file, set -nodebuglogfile)", false, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-shrinkdebugfile", "Shrink debug.log file on client startup (default: 1 when no -debug)", false, OptionsCategory::DEBUG_TEST);
    gArgs.AddArg("-uacomment=<cmt>", "Append comment to the user agent string", false, OptionsCategory::DEBUG_TEST);

    SetupChainParamsBaseOptions();

    gArgs.AddArg("-acceptnonstdtxn", strprintf("Relay and mine \"non-standard\" transactions (%sdefault: %u)", "testnet/regtest only; ", !testnetChainParams->RequireStandard()), true, OptionsCategory::NODE_RELAY);
    gArgs.AddArg("-incrementalrelayfee=<amt>", strprintf("Fee rate (in %s/kB) used to define cost of relay, used for mempool limiting and BIP 125 replacement. (default: %s)", CURRENCY_UNIT, FormatMoney(DEFAULT_INCREMENTAL_RELAY_FEE)), true, OptionsCategory::NODE_RELAY);
    gArgs.AddArg("-dustrelayfee=<amt>", strprintf("Fee rate (in %s/kB) used to defined dust, the value of an output such that it will cost more than its value in fees at this fee rate to spend it. (default: %s)", CURRENCY_UNIT, FormatMoney(DUST_RELAY_TX_FEE)), true, OptionsCategory::NODE_RELAY);
    gArgs.AddArg("-bytespersigop", strprintf("Equivalent bytes per sigop in transactions for relay and mining (default: %u)", DEFAULT_BYTES_PER_SIGOP), false, OptionsCategory::NODE_RELAY);
    gArgs.AddArg("-datacarrier", strprintf("Relay and mine data carrier transactions (default: %u)", DEFAULT_ACCEPT_DATACARRIER), false, OptionsCategory::NODE_RELAY);
    gArgs.AddArg("-datacarriersize", strprintf("Maximum size of data in data carrier transactions we relay and mine (default: %u)", MAX_OP_RETURN_RELAY), false, OptionsCategory::NODE_RELAY);
    gArgs.AddArg("-mempoolreplacement", strprintf("Enable transaction replacement in the memory pool (default: %u)", DEFAULT_ENABLE_REPLACEMENT), false, OptionsCategory::NODE_RELAY);
    gArgs.AddArg("-minrelaytxfee=<amt>", strprintf("Fees (in %s/kB) smaller than this are considered zero fee for relaying, mining and transaction creation (default: %s)",
        CURRENCY_UNIT, FormatMoney(DEFAULT_MIN_RELAY_TX_FEE)), false, OptionsCategory::NODE_RELAY);
    gArgs.AddArg("-whitelistforcerelay", strprintf("Force relay of transactions from whitelisted peers even if the transactions were already in the mempool or violate local relay policy (default: %d)", DEFAULT_WHITELISTFORCERELAY), false, OptionsCategory::NODE_RELAY);
    gArgs.AddArg("-whitelistrelay", strprintf("Accept relayed transactions received from whitelisted peers even when not relaying transactions (default: %d)", DEFAULT_WHITELISTRELAY), false, OptionsCategory::NODE_RELAY);


    gArgs.AddArg("-blockmaxweight=<n>", strprintf("Set maximum BIP141 block weight (default: %d)", DEFAULT_BLOCK_MAX_WEIGHT), false, OptionsCategory::BLOCK_CREATION);
    gArgs.AddArg("-blockmintxfee=<amt>", strprintf("Set lowest fee rate (in %s/kB) for transactions to be included in block creation. (default: %s)", CURRENCY_UNIT, FormatMoney(DEFAULT_BLOCK_MIN_TX_FEE)), false, OptionsCategory::BLOCK_CREATION);
    gArgs.AddArg("-blockversion=<n>", "Override block version to test forking scenarios", true, OptionsCategory::BLOCK_CREATION);

    gArgs.AddArg("-rest", strprintf("Accept public REST requests (default: %u)", DEFAULT_REST_ENABLE), false, OptionsCategory::RPC);
    gArgs.AddArg("-rpcallowip=<ip>", "Allow JSON-RPC connections from specified source. Valid for <ip> are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24). This option can be specified multiple times", false, OptionsCategory::RPC);
    gArgs.AddArg("-rpcauth=<userpw>", "Username and HMAC-SHA-256 hashed password for JSON-RPC connections. The field <userpw> comes in the format: <USERNAME>:<SALT>$<HASH>. A canonical python script is included in share/rpcauth. The client then connects normally using the rpcuser=<USERNAME>/rpcpassword=<PASSWORD> pair of arguments. This option can be specified multiple times", false, OptionsCategory::RPC);
    gArgs.AddArg("-rpcbind=<addr>[:port]", "Bind to given address to listen for JSON-RPC connections. Do not expose the RPC server to untrusted networks such as the public internet! This option is ignored unless -rpcallowip is also passed. Port is optional and overrides -rpcport. Use [host]:port notation for IPv6. This option can be specified multiple times (default: 127.0.0.1 and ::1 i.e., localhost)", false, OptionsCategory::RPC);
    gArgs.AddArg("-rpccookiefile=<loc>", "Location of the auth cookie. Relative paths will be prefixed by a net-specific datadir location. (default: data dir)", false, OptionsCategory::RPC);
    gArgs.AddArg("-rpcpassword=<pw>", "Password for JSON-RPC connections", false, OptionsCategory::RPC);
    gArgs.AddArg("-rpcport=<port>", strprintf("Listen for JSON-RPC connections on <port> (default: %u, testnet: %u, regtest: %u)", defaultBaseParams->RPCPort(), testnetBaseParams->RPCPort(), regtestBaseParams->RPCPort()), false, OptionsCategory::RPC);
    gArgs.AddArg("-rpcserialversion", strprintf("Sets the serialization of raw transaction or block hex returned in non-verbose mode, non-segwit(0) or segwit(1) (default: %d)", DEFAULT_RPC_SERIALIZE_VERSION), false, OptionsCategory::RPC);
    gArgs.AddArg("-rpcservertimeout=<n>", strprintf("Timeout during HTTP requests (default: %d)", DEFAULT_HTTP_SERVER_TIMEOUT), true, OptionsCategory::RPC);
    gArgs.AddArg("-rpcthreads=<n>", strprintf("Set the number of threads to service RPC calls (default: %d)", DEFAULT_HTTP_THREADS), false, OptionsCategory::RPC);
    gArgs.AddArg("-rpcuser=<user>", "Username for JSON-RPC connections", false, OptionsCategory::RPC);
    gArgs.AddArg("-rpcworkqueue=<n>", strprintf("Set the depth of the work queue to service RPC calls (default: %d)", DEFAULT_HTTP_WORKQUEUE), true, OptionsCategory::RPC);
    gArgs.AddArg("-server", "Accept command line and JSON-RPC commands", false, OptionsCategory::RPC);

#if HAVE_DECL_DAEMON
    gArgs.AddArg("-daemon", "Run in the background as a daemon and accept commands", false, OptionsCategory::OPTIONS);
#else
    hidden_args.emplace_back("-daemon");
#endif

    // Add the hidden options
    gArgs.AddHiddenArgs(hidden_args);
}

*/
