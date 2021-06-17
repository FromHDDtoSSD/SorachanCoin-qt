// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_AUTO_CHECKPOINT_H
#define SORACHANCOIN_AUTO_CHECKPOINT_H

#include <stdint.h>
#include <map>
#include <uint256.h>
#include <serialize.h>
#include <file_operate/fs.h>
#include <sync/lsync.h>

class CBlockIndex;

struct AutoCheckData {
    int32_t nHeight;
    uint32_t nTime;
    uint256 hash;
    AutoCheckData() {
        nHeight = 0;
        nTime = 0;
        hash = 0;
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(this->nHeight);
        READWRITE(this->nTime);
        READWRITE(this->hash);
    }
};
using AutoCheckpoints = std::map<uint32_t, AutoCheckData>;

template <typename T>
class CAutocheckPoint_impl {
    CAutocheckPoint_impl(const CAutocheckPoint_impl &)=delete;
    CAutocheckPoint_impl(CAutocheckPoint_impl &&)=delete;
    CAutocheckPoint_impl &operator=(const CAutocheckPoint_impl &)=delete;
    CAutocheckPoint_impl &operator=(CAutocheckPoint_impl &&)=delete;
private:
    constexpr static int nCheckBlocks = 25;
    mutable AutoCheckpoints mapAutocheck;
    mutable CCriticalSection cs_autocp;

    bool is_prime(int in_height) const;
    bool Write(const CBlockIndex &header, int32_t nHeight);

    CAutocheckPoint_impl();
    ~CAutocheckPoint_impl();

    bool Sign() const;
    bool Verify() const;
public:
    static CAutocheckPoint_impl &get_instance() {
        static CAutocheckPoint_impl<T> obj;
        return obj;
    }

    const AutoCheckpoints &getAutocheckpoints() const {return mapAutocheck;}
    CCriticalSection &getcs() const {return cs_autocp;}
    static int GetCheckBlocks() {return nCheckBlocks;}
    bool Check() const;

    bool Buildmap() const;
    bool BuildAutocheckPoints();
};
using CAutocheckPoint = CAutocheckPoint_impl<uint256>;

#endif // SORACHANCOIN_AUTO_CHECKPOINT_H
