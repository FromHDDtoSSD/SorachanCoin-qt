// Copyright (c) 2019-2021 The SorachanCoin Developers
// Copyright (c) 2021 The Sora neko Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Proof of Benchmark [PoBench] Miner logic

#ifndef POBENCH_H
#define POBENCH_H

#include <uint256.h>
#include <winapi/drivewin.h>
#include <winapi/sectorbase.h>

constexpr std::size_t PLOT_SIZE = 4096;
constexpr std::size_t POB_SECTOR_SIZE = SECTOR_SIZE_DEFAULT;
using plot_t = int64_t;

/*
ADD_SERIALIZE_METHODS
template <typename Stream, typename Operation>
inline void SerializationOp(Stream& s, Operation ser_action) {
    READWRITE(lp);
    READWRITE(rp);
    READWRITE(lv);
    READWRITE(rv);
}
*/

#pragma pack(push, 1)
struct ScriptFlat {
    unsigned char script[POB_SECTOR_SIZE];
};
struct PoBench_Plot {
    uint256 fe;
    uint256 se;
    uint256 me;
    uint256 negate;
    unsigned char reserved1[POB_SECTOR_SIZE-sizeof(uint256)*4];

    ScriptFlat scriptPubKey;
    plot_t pnext;
    plot_t pprev;
    unsigned char reserved2[PLOT_SIZE-sizeof(uint256)*4-sizeof(reserved1)-sizeof(ScriptFlat)-sizeof(plot_t)*2];
};
#pragma pack(pop)
static_assert(sizeof(PoBench_Plot)==PLOT_SIZE, "[PoBench] invalid plot_size");

class PoBench_Plot_helper
{
public:
    explicit PoBench_Plot_helper(PoBench_Plot &obj) : plot(obj) {}

private:
    PoBench_Plot &plot;
};

#endif
