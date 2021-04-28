// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_BLOCK_PARAMS
#define SORACHANCOIN_BLOCK_PARAMS

#include <uint256.h>
#include <util.h>
#include <timestamps.h>

namespace block_params
{
    const unsigned int MAX_BLOCK_SIZE = 1000000;
    const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE / 2;
    const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50;

    const unsigned int MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE / 100;     // allow orphan block size
    const unsigned int MAX_INV_SZ = 50000;

    const int64_t COIN_YEAR_REWARD = 3 * util::CENT;
    const int64_t MAX_MINT_PROOF_OF_WORK = 10 * util::COIN;                // find new block 10 coin PoW

    const int64_t MIN_TX_FEE = 10000;
    const int64_t MIN_RELAY_TX_FEE = MIN_TX_FEE;
    const int64_t MAX_MONEY = 8000000 * util::COIN;
    const int64_t MIN_TXOUT_AMOUNT = util::CENT / 100;

    const unsigned int LOCKTIME_THRESHOLD = 500000000;                     // Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp. Tue Nov  5 00:53:20 1985 UTC
    const int MAX_SCRIPTCHECK_THREADS = 16;                                // Maximum number of script-checking threads allowed

    const int64_t COIN_PREMINE = 860000 * util::COIN;

    //
    // Genesis
    //
    const char *const pszTimestamp = "SorachanCoin ... www.junkhdd.com 06-Aug-2018 10:00:00 UTC";
    const uint32_t nGenesisTimeMainnet = timestamps::GENESIS_TIME_STAMP;
    const uint32_t nGenesisTimeTestnet = timestamps::GENESIS_TIME_STAMP;

    const uint32_t nGenesisNonceMainnet = 1181853;
    const uint32_t nGenesisNonceTestnet = 51764;

    const uint256 hashMerkleRoot("0x56eaf6327efb5ce6ece504d585e7f802f0ed5f65b6b262350ee530e2894dce84");
    const uint256 hashGenesisBlock("0x0000030d0ed5a5492e703714059aead5e3800d02de651c1f4079b8d55e6963c7");
    const uint256 hashGenesisBlockTestNet("0x00002f6601da66030580c89a4652b44cf330102c42e2b4e06d97958df7738478");
}

static inline const uint256 &get_hashGenesisBlock(bool fTestNet) {
    return fTestNet ? block_params::hashGenesisBlockTestNet: block_params::hashGenesisBlock;
}

#endif // SORACHANCOIN_BLOCK_PARAMS
