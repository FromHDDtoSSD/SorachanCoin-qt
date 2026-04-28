// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2018-2025 The SorachanCoin developers
// Copyright (c) 2025 The SS256 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <crypto/sha3_256.h>
#include <block/block_info.h>
#include <debug/debug.h>

namespace hash_basis {

uint256 Hash_impl(const unsigned char *p1begin, const unsigned char *p1end) {
    uint256 hash;
    CHash256().Write(p1begin, (p1end - p1begin) * sizeof(unsigned char)).Finalize(hash.begin());
    return hash;
}

uint256 Hash_impl(const unsigned char *p1begin, const unsigned char *p1end,
                  const unsigned char *p2begin, const unsigned char *p2end) {
    uint256 hash;
    CHash256().Write(p1begin, (p1end - p1begin) * sizeof(unsigned char)).Write(p2begin, (p2end - p2begin) * sizeof(unsigned char)).Finalize(hash.begin());
    return hash;
}

uint160 Hash160_impl(const unsigned char *pbegin, const unsigned char *pend) {
    uint160 hash;
    CHash160().Write(pbegin, (pend - pbegin) * sizeof(unsigned char)).Finalize(hash.begin());
    return hash;
}

} // namespace hash_basis
