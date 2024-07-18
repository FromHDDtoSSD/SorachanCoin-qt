// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ui_interface.h>
#include <init.h>
#include <rpc/bitcoinrpc.h>

int CClientUIInterface::noui_ThreadSafeMessageBox(const std::string &message, const std::string &caption, int style)
{
    logging::LogPrintf("%s: %s\n", caption.c_str(), message.c_str());
    fprintf(stderr, "%s: %s\n", caption.c_str(), message.c_str());
    return 4;
}

bool CClientUIInterface::noui_ThreadSafeAskFee(int64_t nFeeRequired, const std::string &strCaption)
{
    (void)nFeeRequired;
    (void)strCaption;
    return true;
}

/*
void CClientUIInterface::noui_ThreadSafeMessageOk(const std::string &message, const std::string &caption, const std::string &detail, unsigned int style)
{
    (void)message;
    (void)caption;
    (void)detail;
    (unsigned int)style;
}
*/

/*
bool CClientUIInterface::noui_ThreadSafeMessageAsk(const std::string &message, const std::string &caption, const std::string &detail, unsigned int style)
{
    (void)message;
    (void)caption;
    (void)detail;
    (unsigned int)style;
    return true;
}
*/
