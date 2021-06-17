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
#include <const/block_params.h>
#include <block/block_info.h>

class CBlockIndex;

// Describes a place in the block chain to another node such that if the
// other node doesn't have the same branch, it can find a recent common trunk.
// The further back it is, the further before the fork it may be.
template <typename T>
class CBlockLocator_impl
{
    CBlockLocator_impl(const CBlockLocator_impl &)=delete;
    CBlockLocator_impl &operator=(const CBlockLocator_impl &)=delete;
protected:
    std::vector<T> vHave;
public:
    CBlockLocator_impl(CBlockLocator_impl &&obj) {
        *this = std::move(obj);
    }
    CBlockLocator_impl &operator=(CBlockLocator_impl &&obj) {
        this->vHave = std::move(obj.vHave);
        obj.vHave.clear();
        return *this;
    }

    CBlockLocator_impl() {}
    explicit CBlockLocator_impl(const CBlockIndex *pindex) {
        Set(pindex);
    }
    explicit CBlockLocator_impl(T hashBlock) {
        auto mi = block_info::mapBlockIndex.find(hashBlock);
        if (mi != block_info::mapBlockIndex.end()) {
            Set((*mi).second);
        }
    }
    CBlockLocator_impl(const std::vector<T> &vHaveIn) {
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
    T GetBlockHash();
    int GetHeight();

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        int nVersion = 0;
        READWRITE(nVersion); // new core takes over old core in the nVersion (unused).

        READWRITE(this->vHave);
    }
};
using CBlockLocator = CBlockLocator_impl<uint256>;

#endif
