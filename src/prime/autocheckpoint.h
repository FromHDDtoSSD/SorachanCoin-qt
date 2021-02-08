// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_AUTO_CHECKPOINT_H
#define SORACHANCOIN_AUTO_CHECKPOINT_H

#if defined(USE_QUANTUM)

#include <stdint.h>
#include <map>
#include <uint256.h>
#include <serialize.h>
#include <file_operate/fs.h>

template <typename T> class CBlockHeader;

struct AutoCheckData {
    uint32_t nHeight;
    uint64_t nTime;
    uint65536 hash;
    AutoCheckData() {
        nHeight = 0;
        nTime = 0;
        hash = 0;
    }
    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        LREADWRITE(this->nHeight);
        LREADWRITE(this->nTime);
        LREADWRITE(this->hash);
    }
};
using AutoCheckpoints = std::map<uint32_t, AutoCheckData>;

template <typename T>
class CAutocheckPoint_impl {
private:
    constexpr static int nCheckBlocks = 25;
    fs::path pathAddr;
    mutable AutoCheckpoints mapAutocheck;

private:
    CAutocheckPoint_impl(const CAutocheckPoint_impl &)=delete;
    CAutocheckPoint_impl(CAutocheckPoint_impl &&)=delete;
    CAutocheckPoint_impl &operator=(const CAutocheckPoint_impl &)=delete;
    CAutocheckPoint_impl &operator=(CAutocheckPoint_impl &&)=delete;

    bool is_prime(int in_height) const;
    bool Buildmap() const;
    bool Write(const CBlockHeader<T> &header, uint32_t nHeight, CAutoFile &fileout, CDataStream &whash);
    uint65536 get_hash(const CDataStream &data) const;

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
    bool Check() const;
    bool BuildAutocheckPoints();
};
using CAutocheckPoint = CAutocheckPoint_impl<uint256>;

#else

static_assert(false, "After ver3, this macro is required.");

#endif // defined(USE_QUANTUM)

#endif // SORACHANCOIN_AUTO_CHECKPOINT_H
