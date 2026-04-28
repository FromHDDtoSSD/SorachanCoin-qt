// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Server/client environment: argument handling, config file parsing,
 * startup time
 */
#ifndef BITCOIN_UTIL_SYSTEM_H
#define BITCOIN_UTIL_SYSTEM_H

#if defined(HAVE_CONFIG_H)
# include <config/bitcoin-config.h>
#endif

#include <const/assumptions.h>
#include <compat.h>
#include <file_operate/fs.h>
#include <util/logging.h>
#include <sync/lsync.h>
#include <util/tinyformat.h>
#include <util/memory.h>
#include <util/time.h>
#include <atomic>
#include <exception>
#include <map>
#include <set>
#include <stdint.h>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace util {

fs::path AbsPathForConfigVal(const fs::path &path, bool net_specific=true, bool ftestnet=false);
fs::path GetDefaultDataDir();

#ifdef WIN32
fs::path GetSpecialFolderPath(int nFolder, bool fCreate = true);
#endif

void runCommand(const std::string &strCommand);

} // namespace util

#endif // BITCOIN_UTIL_SYSTEM_H
