// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_LOCATOR_H
#define BITCOIN_BLOCK_LOCATOR_H

#include <vector>
#include <map>
#include <util.h>
#include <uint256.h>
#include <serialize.h>
#include <const/block_param.h>
#include <block/block_info.h>

template <typename T> class CBlockIndex_impl;
using CBlockIndex = CBlockIndex_impl<uint256>;

// Describes a place in the block chain to another node such that if the
// other node doesn't have the same branch, it can find a recent common trunk.
// The further back it is, the further before the fork it may be.
template <typename T>
class CBlockLocator_impl
{
private:
    CBlockLocator_impl(const CBlockLocator_impl &)=delete;
    CBlockLocator_impl &operator=(const CBlockLocator_impl &)=delete;
    CBlockLocator_impl &operator=(const CBlockLocator_impl &&)=delete;
protected:
    std::vector<uint256> vHave;
public:
    CBlockLocator_impl() {}
    explicit CBlockLocator_impl(const CBlockIndex *pindex) {
        Set(pindex);
    }
    explicit CBlockLocator_impl(uint256 hashBlock) {
        std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hashBlock);
        if (mi != block_info::mapBlockIndex.end()) {
            Set((*mi).second);
        }
    }
    CBlockLocator_impl(const std::vector<uint256> &vHaveIn) {
        vHave = vHaveIn;
    }

    void SetNull() {
        vHave.clear();
    }
    bool IsNull() {
        return vHave.empty();
    }

    void Set(const CBlockIndex *pindex);
    int GetDistanceBack();
    CBlockIndex *GetBlockIndex();
    uint256 GetBlockHash();
    int GetHeight();

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH)) {
            READWRITE(nVersion);    // IMPLEMENT_SERIALIZE has argument(nVersion).
        }
        READWRITE(this->vHave);
    )
};
using CBlockLocator = CBlockLocator_impl<uint256>;

#endif
