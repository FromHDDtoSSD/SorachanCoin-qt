// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/thread.h>
#include <util/logging.h>
#include <util/exception.h>
#include <boost/thread.hpp>

void bitthread::thread_error(const std::string &e) noexcept {
    std::string err(e);
    err += " :thread_error";
    logging::LogPrintf(err.c_str());
}

bool bitthread::manage::NewThread(void(*pfn)(void *), void *parg) noexcept {
    try {
        boost::thread(pfn, parg); // thread detaches when out of scope
    } catch (boost::thread_resource_error &e) {
        logging::LogPrintf("Error creating thread: %s\n", e.what());
        return false;
    }
    return true;
}

template <typename Callable>
void bitthread::TraceThread(const char *name, Callable func) {
    std::string s = tfm::format("SorachanCoin-%s", name);
    RenameThread(s.c_str());
    try {
        logging::LogPrintf("%s thread start\n", name);
        func();
        logging::LogPrintf("%s thread exit\n", name);
    } catch (const boost::thread_interrupted &) {
        logging::LogPrintf("%s thread interrupt\n", name);
        throw;
    } catch (const std::exception &e) {
        excep::PrintExceptionContinue(&e, name);
        throw;
    } catch (...) {
        excep::PrintExceptionContinue(nullptr, name);
        throw;
    }
}
