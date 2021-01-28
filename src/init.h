// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2020-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include <wallet.h>

//
// SorachanCoin About Init
//
// Note: A drive Benchmark require to unload the blockchain and
// switch from Qt to the native API due to maximize execution speed.
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

    static std::string HelpMessage();
    static void ExitTimeout(void *parg);
    static bool AppInit2();
};

//
// Prediction System
// Note: At first, Win32 supported
// Note: load independent the MessageLoop below.
//
namespace predsystem {

    enum ret_code {
        success = 0,
        error_createwindow,
        error_initddk,
        error_createobject,
        error_outofmemory,
    };

    struct result {
        intptr_t window_ret;
        ret_code ret;
        std::string e;
        std::vector<uint8_t> vch;
        result() {
            window_ret = 0;
            ret = success;
        }
    };

    extern result CreateBenchmark() noexcept;

} // namespace predsystem

#endif
