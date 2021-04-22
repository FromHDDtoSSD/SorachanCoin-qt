// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ProofOfSpace [PoSpace]
// ref: https://github.com/Chia-Network/chia-blockchain

#include <sorara/soraradb.h>
#include <key/privkey.h>
#include <key/pubkey.h>

CCriticalSection CProofOfSpace::cs_pospace;

CProofOfSpace::CProofOfSpace() : sqlPoSpace(CSqliteDBEnv::getname_pospacedb(), "r+", true) {} // secure mode

bool CProofOfSpace::WriteVersion(int nVersion) {
    return sqlPoSpace.Write(std::string("PoSpaceVersion"), nVersion);
}

bool CProofOfSpace::ReadVersion(int &nVersion) {
    return sqlPoSpace.Read(std::string("PoSpaceVersion"), nVersion);
}

bool CProofOfSpace::create_plot() const noexcept {
    // filename
    unsigned char rnd[32];
    latest_crypto::random::GetStrongRandBytes(rnd, sizeof(rnd));
    uint256 rndhash = hash_basis::Hash(BEGIN(rnd), END(rnd));

    // create directory
    fs::path pospacedir = iofs::GetDataDir() / "PoSpace";
    if(! fsbridge::dir_create(pospacedir))
        return false;

    // filepath
    fs::path plotname = iofs::GetDataDir() / pospacedir / (std::string(rndhash.ToString()) + ".plot");

    // require k
    const int k = debug_mode ? 24: 32;

    // plot size
    const size_t size = get_plotsize(k);

    // create plot
    const size_t entry_size = ::GetSerializeSize(PlotEntry());
    PlotHeader header;
    header.k = k;
    header.entry_size = entry_size;
    CAutoFile plot = CAutoFile(plotname, "r+");
    if(plot==nullptr)
        return false;
    plot << header;
    const int num = (size - ::GetSerializeSize(header))/entry_size;
    const int remain = (size-::GetSerializeSize(header))-num*entry_size;
    debugcs::instance() << "[CProofOfSpace] remain: " << remain << debugcs::endl();
    assert(remain==0);
    for(int i=0; i < num; ++i) {
        PlotEntry entry;
        plot << entry;
    }

    return true;
}



CSoraraDB::CSoraraDB(const char *mode/*="r+"*/) : sqldb(CSqliteDBEnv::getname_soraradb(), mode) {}
