// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2018-2021 The Sora neko developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_KEYHASHER_H
#define BITCOIN_BLOCK_KEYHASHER_H

#include <uint256.h>

// for std::unordered_map inner HASH
class CCoinsKeyHasher
{
private:
    uint256b salt;

public:
    CCoinsKeyHasher();

    /**
     * This *must* return size_t. With Boost 1.46 on 32-bit systems the
     * unordered_map will behave unpredictably if the custom hasher returns a
     * uint64_t, resulting in failures when syncing the chain (#4634).
     */
    std::size_t operator()(const uint256b &key) const { // even if std::unordered_map, require std::size_t
        return key.GetHash(salt);
    }
};

#endif
