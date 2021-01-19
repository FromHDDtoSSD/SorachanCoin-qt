// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2020-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include <wallet.h>

//
// Init
// CUI: AppInit -> AppInit2 (Force Server-mode)
// Qt : parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main() -> AppInit2
// Qt + GUI : parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main() -> AppInit2 -> CreatePredictionSystem()
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
//
namespace predsystem {

    extern bool CreatePredictionSystem() noexcept;

} // namespace predsystem

#endif
