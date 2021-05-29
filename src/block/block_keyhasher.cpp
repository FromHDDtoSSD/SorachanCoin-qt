// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2018-2021 The Sora neko developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <block/block_keyhasher.h>
#include <random/random.h>

CCoinsKeyHasher::CCoinsKeyHasher() : salt(latest_crypto::random::GetRandHash()) {}
