// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include "wallet.h"
#include "checkpoints.h"

//
// Init
// CUI: AppInit -> AppInit2 (Force Server-mode)
// QT : parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main() -> AppInit2
//
class entry : private no_instance
{
#ifdef QT_GUI
    friend class OptionsModel;
#endif
private:
    static const uint16_t nSocksDefault = tcp_port::uSocksDefault;

    static std::string strWalletFileName;

    static bool InitError(const std::string &str);
    static bool InitWarning(const std::string &str);
    static bool Bind(const CService &addr, bool fError = true);

#ifndef WIN32
    static void HandleSIGTERM(int);
    static void HandleSIGHUP(int);
#endif

    static bool BindListenPort(const CService &addrBind, std::string &strError);

public:
    static enum Checkpoints::CPMode CheckpointsMode;
    static CWallet *pwalletMain;

#if !defined(QT_GUI)
    static bool AppInit(int argc, char *argv[]);
    static void noui_connect();
#endif

    static std::string HelpMessage();

    static void ExitTimeout(void *parg);
    static void StartShutdown();
    static bool AppInit2();
};

#endif
//@
