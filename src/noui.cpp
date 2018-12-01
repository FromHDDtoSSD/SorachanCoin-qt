// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ui_interface.h"
#include "init.h"
#include "bitcoinrpc.h"

#include <string>

int CClientUIInterface::noui_ThreadSafeMessageBox(const std::string &message, const std::string &caption, int style)
{
    printf("%s: %s\n", caption.c_str(), message.c_str());
    fprintf(stderr, "%s: %s\n", caption.c_str(), message.c_str());
    return 4;
}

bool CClientUIInterface::noui_ThreadSafeAskFee(int64_t nFeeRequired, const std::string &strCaption)
{
    static_cast<int64_t>(nFeeRequired);
    static_cast<const std::string &>(strCaption);
    return true;
}
