// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2020-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include <wallet.h>

//
// Sora neko About Init
//
// CUI (daemon SorachanCoind):
// AppInit -> AppInit2 (Force Server-mode)
//
// Qt (Wallet mode or drive failure prediction mode):
// parameters/SorachanCoin.conf are parsed in qt/bitcoin.cpp's main() -> AppInit2
//
// Qt + BenchmarkGUI (Benchmark mode, switch from Qt to the native API):
// parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main() ->
// entry::AppInit2 ->
// SIGNAL(becnmark_start) ->
// entry::shutdown ->
// CreatePredictionSystem_benchmark() ->
// DDK load ->
// doing benchmark ->
// DestroyWindow() ->
// entry::AppInit2 ->
// It will record the benchmark results on this blockchain.
//
class entry : private no_instance
{
public:
    enum bip66Mode {
        Bip66_STRICT = 0,
        Bip66_ADVISORY = 1,
        Bip66_PERMISSIVE = 2
    };
    static enum bip66Mode b66mode;

private:
    static std::string strWalletFileName;
    static std::string strWalletqFileName;

    static bool InitError(const std::string &str);
    static bool InitWarning(const std::string &str);
    static bool Bind(const CService &addr, bool fError = true);

#ifndef WIN32
    static void HandleSIGTERM(int);
    static void HandleSIGHUP(int);
#endif

public:
    static bool BindListenPort(const CService &addrBind, std::string &strError, bool check = false);
    static CWallet *pwalletMain;

#if !defined(QT_GUI)
    static bool AppInit(int argc, char *argv[]);
    static void noui_connect();
#endif

    static void SetupServerArgs();
    static std::string HelpMessage();
    static void ExitTimeout(void *parg);
    static bool AppInit2(bool restart=false);
};

// txdb-leveldb.cpp
extern void leveldb_oldblockchain_remove_once();
extern void leveldb_to_sqlite_blockchain();
extern void sqlitedb_oldblockchain_remove_once();

#endif
