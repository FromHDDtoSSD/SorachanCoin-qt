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

//#ifdef WIN32
//#undef STRICT
//#undef PERMISSIVE
//#undef ADVISORY
//#endif

namespace autocheckpoint {
    //
    // Autocheck Genesis
    //
    //const char *const pszTimeStamp = "";
    //const uint65536 hashMerkleRoot("");
    //const uint65536 hashGenesisBlock("");
    //const uint65536 hashGenesisBlockTestnet("");

    //
    // dat method
    //
    const char *const datname = "autocheckpoints.dat";
}

/*
** [B] autocheckpoints.dat method
** Singleton class
*/
template <typename T>
class CAutocheckPoint_impl {
private:
    constexpr static int nCheckNum = 5;
    BIGNUM *height;
    BN_CTX *ctx;
    // Note: must be FLATDATA
    typedef struct _AutoCheckData {
        uint32_t nHeight;
        uint64_t nTime;
        uint65536 hash;
        IMPLEMENT_SERIALIZE(
            READWRITE(this->nHeight);
            READWRITE(this->nTime);
            READWRITE(this->hash);
        )
    } AutoCheckData;
    boost::filesystem::path pathAddr;
    mutable std::map<uint32_t, AutoCheckData> mapAutocheck;
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
public:
    static CAutocheckPoint_impl &get_instance() {
        static CAutocheckPoint_impl<T> obj;
        return obj;
    }
    bool Check() const;
    bool BuildAutocheckPoint();
};
using CAutocheckPoint = CAutocheckPoint_impl<uint256>;

#else

// unused
template <typename T>
class CAutocheckPoint_impl {
private:
    CAutocheckPoint_impl(const CAutocheckPoint_impl &)=delete;
    CAutocheckPoint_impl(CAutocheckPoint_impl &&)=delete;
    CAutocheckPoint_impl &operator=(const CAutocheckPoint_impl &)=delete;
    CAutocheckPoint_impl &operator=(CAutocheckPoint_impl &&)=delete;

    bool is_prime(int in_height) const {return false;}
    bool Buildmap() {return false;}
    bool Write(const CBlockHeader<T> &header, uint32_t nHeight, CAutoFile &fileout, CDataStream &whash) {return false;}
    uint65536 get_hash(const CDataStream &data) const {return uint65536(0);}

    CAutocheckPoint_impl() {}
    ~CAutocheckPoint_impl() {}
public:
    static CAutocheckPoint_impl &get_instance() {
        static CAutocheckPoint_impl<T> obj;
        return obj;
    }
    bool Check() const {return true;}
    bool BuildAutocheckPoint() {return true;}
};
using CAutocheckPoint = CAutocheckPoint_impl<uint256>;

#endif // defined(USE_QUANTUM)

#endif // SORACHANCOIN_AUTO_CHECKPOINT_H
