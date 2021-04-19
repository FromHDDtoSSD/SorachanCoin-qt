// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORA_SORARADB_H
#define SORA_SORARADB_H

#include <db.h>
//#include <winapi/sectorbase.h>

#if defined(USE_LEBRESSL) && defined(WIN32)
# include <windows.h>
# include <openssl/rand.h>
static inline int RAND_event(UINT message, WPARAM wp, LPARAM lp) {
    ::RAND_seed((char *)&message, sizeof(message)/sizeof(char));
    ::RAND_seed((char *)&wp, sizeof(wp)/sizeof(char));
    ::RAND_seed((char *)&lp, sizeof(lp)/sizeof(char));
    return 1;
}
#endif

//
// ProofOfSpace [PoSpace]
// ref: https://github.com/Chia-Network/chia-blockchain
//
class CProofOfSpace final {
    CProofOfSpace()=delete;
    CProofOfSpace(const CProofOfSpace &)=delete;
    CProofOfSpace(CProofOfSpace &&)=delete;
    CProofOfSpace &operator=(const CProofOfSpace &)=delete;
    CProofOfSpace &operator=(CProofOfSpace &&)=delete;
public:
    //CProofOfSpace &get_instance() noexcept {
    //    static CProofOfSpace obj;
    //    return obj;
    //}
private:
    //int64_t fromSectorsToGiB(sector_t sectors) const noexcept {
    //    return (int64_t)BytesPerSector * sectors / (int64_t)(1024*1024*1024);
    //}
    static int64_t get_plotsize(int k) noexcept {
        assert(k>=10);
        return (int64_t)780 * k * (2<<(k-10));
    }

    explicit CProofOfSpace(size_t BytesPerSectorIn);
    bool WriteVersion(int nVersion);
    bool ReadVersion(int &nVersion);

    size_t BytesPerSector;
    //sector_io sectorPoSpace;
    CSqliteDB sqlPoSpace;
};

class CSoraraDB final {
    CSoraraDB()=delete;
    CSoraraDB(const CSoraraDB &)=delete;
    CSoraraDB(CSoraraDB &&)=delete;
    CSoraraDB &operator=(const CSoraraDB &)=delete;
    CSoraraDB &operator=(CSoraraDB &&)=delete;
public:
    CSoraraDB(const char *mode="r+");

private:
    CSqliteDB sqldb;
};

#endif // SORA_SORARADB_H
