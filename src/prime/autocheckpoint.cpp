// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(USE_QUANTUM)

#include <prime/autocheckpoint.h>
#include <prevector/prevector.h>
#include <block/block.h>
#include <util.h>
#include <random/random.h>
#include <file_operate/fs.h>
#include <debugcs/debugcs.h>

static const char *datname = "autocheckpoints.dat";

#ifdef BLOCK_PREVECTOR_ENABLE
    using vAuto = prevector<PREVECTOR_BLOCK_N, uint8_t>;
#else
    using vAuto = std::vector<uint8_t>;
#endif
template <typename T>
bool CAutocheckPoint_impl<T>::is_prime(int in_height) const { /* true: Prime number, false: Composite number */
    if(in_height<=440000||in_height>=15000000) // out of range in Autocheckpoints.
        return false;
    if(in_height%2==0 || in_height%3==0)
        return false;
    for(int i=5; i*i<=in_height; i+=6) {
        if(in_height%i==0) return false;
        if(in_height%(i+2)==0) return false;
    }
    return true;
}

template <typename T>
bool CAutocheckPoint_impl<T>::Buildmap() const {
    CAutoFile filein = CAutoFile(pathAddr, "rb", 0, 0);
    if(! filein) return false;
    int fileSize = filein.getfilesize();
    int dataSize = fileSize - sizeof(uint65536);
    if(dataSize<=0) return true;

    std::vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint65536 hashIn;
    try {
        filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    } catch(const std::exception &) {
        return false;
    }
    filein.fclose();

    CDataStream ssda(vchData);
    uint65536 hashTmp = get_hash(ssda);
    if(hashIn != hashTmp) return false;

    mapAutocheck.clear();
    while(! ssda.eof()) {
        AutoCheckData data;
        ssda >> data;
        mapAutocheck.insert(std::pair<uint32_t, AutoCheckData>(data.nHeight, data));
    }
    return true;
}

template <typename T>
bool CAutocheckPoint_impl<T>::Write(const CBlockHeader<T> &header, uint32_t nHeight, CAutoFile &fileout, CDataStream &whash) {
    AutoCheckData data;
    try {
        {
            std::memset(&data, 0, sizeof(data));
            data.nHeight = nHeight;
            data.nTime = header.get_nTime();
            CDataStream ssheader;
            ssheader << FLATDATA(header);
            data.hash = get_hash(ssheader);
        }

        CDataStream ssda;
        ssda << FLATDATA(data);
        fileout << ssda;
    } catch(const std::exception &) {
        return false;
    }

    whash << FLATDATA(data);
    return true;
}

template <typename T>
uint65536 CAutocheckPoint_impl<T>::get_hash(const CDataStream &data) const {
    return hash_basis::Hash65536(data.begin(), data.end());
}

template <typename T>
CAutocheckPoint_impl<T>::CAutocheckPoint_impl() {
    mapAutocheck.clear();
    pathAddr = iofs::GetDataDir() / datname;
}

template <typename T>
CAutocheckPoint_impl<T>::~CAutocheckPoint_impl() {}

template <typename T>
bool CAutocheckPoint_impl<T>::Check() const {
    try {
        if(! Buildmap())
            return false;
        const CBlockIndex_impl<T> *block = block_info::mapBlockIndex[block_info::hashBestChain];
        for(const auto &mapdata: mapAutocheck) {
            while(mapdata.first != block->get_nHeight())
                block=block_info::mapBlockIndex[block->get_hashPrevBlock()];
            CDataStream ssda;
            ssda << FLATDATA(*static_cast<const CBlockHeader<T> *>(block));
            if(mapdata.second.hash != get_hash(ssda))
                return false;
        }
        return true;
    } catch(const std::exception &) {
        return false;
    }
}

template <typename T>
bool CAutocheckPoint_impl<T>::Sign() const {

    //


    return false;
}

template <typename T>
bool CAutocheckPoint_impl<T>::Verify() const {

    //


    return false;
}

template <typename T>
bool CAutocheckPoint_impl<T>::BuildAutocheckPoints() {
    unsigned short randv = 0;
    latest_crypto::random::GetStrongRandBytes((unsigned char *)&randv, sizeof(randv));
    std::string tmpfn = tfm::format("%s.%4x", datname, randv);
    fs::path pathTmp = iofs::GetDataDir() / tmpfn;
    CAutoFile fileout = CAutoFile(::fopen(pathTmp.string().c_str(), "wb"), 0, 0);
    if(! fileout) return false;

    CDataStream whash;
    const CBlockIndex_impl<T> *block = block_info::mapBlockIndex[block_info::hashBestChain];
    int counter = nCheckNum;
    assert(0<counter);
    for(;;) {
        if(block->get_nHeight()<=0) break;
        if(is_prime(block->get_nHeight())) {
            if(! Write(*static_cast<const CBlockHeader<T> *>(block), block->get_nHeight(), fileout, whash)) return false;
            if(--counter==0) break;
        }
        block = block_info::mapBlockIndex[block->get_hashPrevBlock()];
    }

    CDataStream dhash;
    dhash << get_hash(whash);
    try {
        fileout << dhash;
    } catch(const std::exception &) {
        return false;
    }

    iofs::FileCommit(fileout);
    fileout.fclose();
    return iofs::RenameOver(pathTmp, pathAddr);
}

template class CAutocheckPoint_impl<uint256>;

#endif // defined(USE_QUANTUM)
