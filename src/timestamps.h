//
#ifndef BITCOIN_TIMESTAMPS_H
#define BITCOIN_TIMESTAMPS_H

#include <boost/assign/list_of.hpp>
#include <list>
#include "util.h"

namespace timestamps
{
    const unsigned int GENESIS_TIME_STAMP = 1533549600;                 // 06-Aug-2018 10:00:00 UTC
    const unsigned int GENESIS_TIME_STAMP_TESTNET = 1777195800;

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

    // Only CPU Miner: const 1 mine
    const std::list<std::pair<int, int64_t> > POW_REWARD_BLOCK_SORA2 =
        boost::assign::list_of
        (std::make_pair(0, 3 * util::COIN))
        (std::make_pair(1000000, (int64_t)((15 * util::COIN) / 10)))
        (std::make_pair(2000000, (int64_t)((75 * util::COIN) / 100)))
        (std::make_pair(3000000, (int64_t)((375 * util::COIN) / 1000)))
        (std::make_pair(4000000, (int64_t)((1875 * util::COIN) / 10000)));

    //
    // PoS Reward (%) (TIME, coin)
    //
    const std::list<std::pair<unsigned int, int64_t> > POS_REWARD_BLOCK =
        boost::assign::list_of
        (std::make_pair(timestamps::GENESIS_TIME_STAMP, 3 * util::CENT));           // 31-Jul-2018 20:00:00 UTC
}

#endif
