// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/thread.h>
#include <util/logging.h>
#include <boost/thread.hpp>

void bitthread::thread_error(const std::string &e) noexcept {
    std::string err(e);
    err += " :thread_error";
    LogPrintf(err.c_str());
}

bool bitthread::manage::NewThread(void(*pfn)(void *), void *parg) noexcept {
    try {
        boost::thread(pfn, parg); // thread detaches when out of scope
    } catch (boost::thread_resource_error &e) {
        LogPrintf("Error creating thread: %s\n", e.what());
        return false;
    }
    return true;
}
