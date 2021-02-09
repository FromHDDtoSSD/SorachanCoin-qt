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
static constexpr int lowerBlockHeight = 440000; // mainnet and testnet
#define CP_DEBUG_CS(str) debugcs::instance() << (str) << debugcs::endl();

#ifdef BLOCK_PREVECTOR_ENABLE
    using vAuto = prevector<PREVECTOR_BLOCK_N, uint8_t>;
#else
    using vAuto = std::vector<uint8_t>;
#endif
template <typename T>
bool CAutocheckPoint_impl<T>::is_prime(int in_height) const { /* true: Prime number, false: Composite number */
    if(in_height<=lowerBlockHeight||in_height>=15000000) // out of range in Autocheckpoints.
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
    if(! filein)
        return false;
    const size_t fileSize = filein.getfilesize();
    const size_t dataSize = fileSize - sizeof(uint65536);
    if(dataSize<=0)
        return false;

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
    if(hashIn != hashTmp)
        return false;

    mapAutocheck.clear();
    while(! ssda.eof()) {
        AutoCheckData data;
        ssda >> data;
        CP_DEBUG_CS(tfm::format("Autocheckpoint buildmap: %d %d %s", data.nHeight, data.nTime, data.hash.ToString().substr(0, 64)))
        mapAutocheck.insert(std::make_pair(data.nHeight, data));
    }
    return true;
}

template <typename T>
bool CAutocheckPoint_impl<T>::Write(const CBlockHeader<T> &header, uint32_t nHeight, CAutoFile &fileout, CDataStream &whash) {
    AutoCheckData data;
    try {
        {
            data.nHeight = nHeight;
            data.nTime = header.get_nTime();
            CDataStream ssheader;
            ssheader << header;
            data.hash = get_hash(ssheader);
        }

        CP_DEBUG_CS(tfm::format("Autocheckpoint Write: %d %d %s", data.nHeight, data.nTime, data.hash.ToString().substr(0, 64)))
        CDataStream ssda;
        ssda << data;
        fileout << ssda;

        whash << data;
        return true;
    } catch(const std::exception &) {
        return false;
    }
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
bool CAutocheckPoint_impl<T>::Check() const { // nCheckBlocks blocks, autocheckpoints qhash(uint65536) check
    try {
        if(block_info::mapBlockIndex.empty())
            return false;

        const CBlockIndex_impl<T> *const bestBlock = block_info::mapBlockIndex[block_info::hashBestChain];
        for (int i=0; i < nCheckBlocks; ++i) {
            const auto &autocpValue = mapAutocheck.find(bestBlock->get_nHeight()-i);
            if(autocpValue==mapAutocheck.end()) continue;

            const CBlockIndex_impl<T> *target = bestBlock;
            for(;;) {
                if(bestBlock->get_nHeight()-i!=target->get_nHeight())
                    target = block_info::mapBlockIndex[target->get_pprev()->GetBlockHash()];
                else
                    break;
            }

            CDataStream ssda;
            ssda << *static_cast<const CBlockHeader<T> *>(target);
            CP_DEBUG_CS(tfm::format("Autochekpoint Check %s, %s", autocpValue->second.hash.ToString().substr(0, 64), get_hash(ssda).ToString().substr(0, 64)))
            if(autocpValue->second.hash != get_hash(ssda))
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
    CP_DEBUG_CS(tfm::format("BuildAutocheckPoints path: %s, fileout: %d", pathTmp.string().c_str(), (uintptr_t)(FILE *)fileout))
    if(! fileout)
        return false;

    const CBlockIndex_impl<T> *block = block_info::mapBlockIndex[block_info::hashBestChain];

    /* checked mapBlockIndex
    for(const auto &ref: block_info::mapBlockIndex) {
        CP_DEBUG_CS(tfm::format("block_info::mapBlockIndex hash: %s", ref.first.ToString()))
        CP_DEBUG_CS(tfm::format("block_info::mapBlockIndex blockHeight: %d", ref.second->get_nHeight()))
        CP_DEBUG_CS(tfm::format("block_info::mapBlockIndex prev: %s", ref.second->get_hashPrevBlock().ToString()))
        CP_DEBUG_CS(tfm::format("block_info::mapBlockIndex prev2: %s", ref.second->get_pprev()->get_phashBlock()->ToString()))
    }
    */

    assert(block);
    CP_DEBUG_CS(tfm::format("CBlockIndex_impl<T> *block: %d", (uintptr_t)block))
    CP_DEBUG_CS(tfm::format("block addr: %s", block->get_hashPrevBlock().ToString()))
    int counter = nCheckBlocks;
    if(block->get_hashPrevBlock()==0) { // genesis block
        iofs::FileCommit(fileout);
        fileout.fclose();
        return iofs::RenameOver(pathTmp, pathAddr);
    }
    assert(0<counter);
    CDataStream whash; // output
    for(;;) {
        CP_DEBUG_CS(tfm::format("block check: %d", block->get_nHeight()))
        if(block->get_nHeight()<=lowerBlockHeight)
            break;
        if(is_prime(block->get_nHeight())) {
            CP_DEBUG_CS(tfm::format("block is_prime: %d", block->get_nHeight()))
            if(! Write(*static_cast<const CBlockHeader<T> *>(block), block->get_nHeight(), fileout, whash))
                return false;
            if(--counter==0)
                break;
        }
        if(block->get_hashPrevBlock()==0)
            break;
        block = block_info::mapBlockIndex[block->get_hashPrevBlock()];
    }
    if(whash.begin()==whash.end()) {
        iofs::FileCommit(fileout);
        fileout.fclose();
        return iofs::RenameOver(pathTmp, pathAddr);
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
    return iofs::RenameOver(pathTmp, pathAddr) && Buildmap() && Check();
}

template class CAutocheckPoint_impl<uint256>;

#endif // defined(USE_QUANTUM)
