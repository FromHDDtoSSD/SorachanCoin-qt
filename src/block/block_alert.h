// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_ALERT_H
#define BITCOIN_BLOCK_ALERT_H

#include <string>

namespace block_alert
{
    std::string GetWarnings(std::string strFor);
}

#endif // BITCOIN_BLOCK_ALERT_H
