//
#ifndef BITCOIN_TIMESTAMPS_H
#define BITCOIN_TIMESTAMPS_H

#include <boost/assign/list_of.hpp>
#include <list>
#include "util.h"

namespace timestamps
{
    const unsigned int GENESIS_TIME_STAMP = 1533549600;                 // 06-Aug-2018 10:00:00 UTC

    const unsigned int TARGETS_SWITCH_TIME = 1556668800;                // 01-May-2019 00:00:00 UTC
    const unsigned int TARGETS_SWITCH_WORK = 1533636000;                // 07-Aug-2018 10:00:00 UTC
    const unsigned int CHECKLOCKTIMEVERIFY_SWITCH_TIME = 1556668800;    // 01-May-2019 00:00:00 UTC
    const unsigned int BLOCKS_ADMIT_HOURS_SWITCH_TIME = 1556668800;     // 01-May-2019 00:00:00 UTC
}

namespace blockreward
{
    //
    // PoW Reward (nBestHeight, coin)
    //
    const std::list<std::pair<int, int64_t> > POW_REWARD_BLOCK =
        boost::assign::list_of
        (std::make_pair(0, 1 * util::COIN))
        (std::make_pair(1000, 2 * util::COIN))
        (std::make_pair(20000, 6 * util::COIN))
        (std::make_pair(100000, 2 * util::COIN))
        (std::make_pair(500000, 1 * util::COIN));

    //
    // PoS Reward (%) (TIME, coin)
    //
    const std::list<std::pair<unsigned int, int64_t> > POS_REWARD_BLOCK =
        boost::assign::list_of
        (std::make_pair(timestamps::GENESIS_TIME_STAMP, 3 * util::CENT));           // 31-Jul-2018 20:00:00 UTC
}

#endif
//@
