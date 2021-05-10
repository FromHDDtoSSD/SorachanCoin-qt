// Copyright (c) 2011-2012 The Bitcoin developers
// Copyright (c) 2018-2020 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//#include "sync.h"
//#include "util.h"

#ifdef DEBUG_LOCKORDER

std::string CLockLocation::ToString() const {
    return mutexName + "  " + sourceFile + ":" + ::itostr(sourceLine);
}

void CLockOnTrack::potential_deadlock_detected(const std::pair<void *, void *> &mismatch, const LockStack &s1, const LockStack &s2) {
    logging::LogPrintf("POTENTIAL DEADLOCK DETECTED\n");
    logging::LogPrintf("Previous lock order was:\n");

    for(auto i = s2.begin(); i != s2.end(); ++i)
    {
        if(i->first == mismatch.first) {
            logging::LogPrintf(" (1)");
        }
        if(i->first == mismatch.second) {
            logging::LogPrintf(" (2)");
        }

        logging::LogPrintf(" %s\n", i->second.ToString().c_str());
    }

    logging::LogPrintf("Current lock order is:\n");

    for(auto i = s1.begin(); i != s1.end(); ++i)
    {
        if(i->first == mismatch.first) {
            logging::LogPrintf(" (1)");
        }
        if(i->first == mismatch.second) {
            logging::LogPrintf(" (2)");
        }

        logging::LogPrintf(" %s\n", i->second.ToString().c_str());
    }
}

void CLockOnTrack::push_lock(void *c, const CLockLocation &locklocation, bool fTry) {
    if(lockstack.get() == nullptr) {
        lockstack.reset(new LockStack);
    }

    if(args_bool::fDebug) {
        logging::LogPrintf("Locking: %s\n", locklocation.ToString().c_str());
    }

    dd_mutex.lock();

    (*lockstack).push_back(std::make_pair(c, locklocation));

    if(! fTry) {
        for(auto i = (*lockstack).begin(); i != (*lockstack).end(); ++i)
        {
            if(i->first == c) {
                break;
            }

            std::pair<void *, void *> p1 = std::make_pair(i->first, c);
            if(lockorders.count(p1)) {
                continue;
            }

            lockorders[p1] = (*lockstack);

            std::pair<void *, void *> p2 = std::make_pair(c, i->first);
            if(lockorders.count(p2)) {
                potential_deadlock_detected(p1, lockorders[p2], lockorders[p1]);
                break;
            }
        }
    }

    dd_mutex.unlock();
}

void CLockOnTrack::pop_lock() {
    if(args_bool::fDebug) {
        const CLockLocation &locklocation = (*lockstack).rbegin()->second;
        logging::LogPrintf("Unlocked: %s\n", locklocation.ToString().c_str());
    }

    dd_mutex.lock();
    (*lockstack).pop_back();
    dd_mutex.unlock();
}

std::mutex CLockOnTrack::dd_mutex;
std::map<std::pair<void *, void *>, LockStack> CLockOnTrack::lockorders;
boost::thread_specific_ptr<LockStack> CLockOnTrack::lockstack;

#endif // DEBUG_LOCKORDER
