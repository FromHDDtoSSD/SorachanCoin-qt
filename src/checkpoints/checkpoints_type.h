// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHECKPOINTS_TYPE
#define CHECKPOINTS_TYPE

#include <map>
#include <uint256.h>

using MapCheckpoints = std::map<int, uint256>;
using ListBannedBlocks = std::list<uint256>;
using LastCheckpointTime = unsigned int;

#endif
