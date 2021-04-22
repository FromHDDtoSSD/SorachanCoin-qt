// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORA_SORARADB_H
#define SORA_SORARADB_H

#include <db.h>

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
// TARGET: HDD
// ref: https://github.com/Chia-Network/chia-blockchain
//
using pos_t = int64_t;
struct PlotHeader {
    int k;
    size_t entry_size;

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(k);
        READWRITE(entry_size);
    }
};
struct PlotEntry {
    pos_t lp;
    pos_t rp;
    uint256 lv;
    uint256 rv;
    std::vector<char> pad;

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(lp);
        READWRITE(rp);
        READWRITE(lv);
        READWRITE(rv);
    }
};

class CProofOfSpace {
    CProofOfSpace(const CProofOfSpace &)=delete;
    CProofOfSpace(CProofOfSpace &&)=delete;
    CProofOfSpace &operator=(const CProofOfSpace &)=delete;
    CProofOfSpace &operator=(CProofOfSpace &&)=delete;
    constexpr static bool debug_mode = true; // plot size is 15MB(debug) (k==20)
public:
    static CCriticalSection cs_pospace;
    static CProofOfSpace &get_instance() noexcept {
        LOCK(cs_pospace);
        static CProofOfSpace obj;
        return obj;
    }

    bool create_plot() const noexcept;

    void test(); // alternative verifier, prover

private:
    static int64_t get_plotsize(int k) noexcept {
        assert(k>=10);
        return (int64_t)780 * k * (2<<(k-10)) + ::GetSerializeSize(PlotHeader());
    }

    explicit CProofOfSpace();
    bool WriteVersion(int nVersion);
    bool ReadVersion(int &nVersion);

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

//
// PrrofOfBenchmark [PoBench]
// TARGET: SSD
//



#endif // SORA_SORARADB_H
