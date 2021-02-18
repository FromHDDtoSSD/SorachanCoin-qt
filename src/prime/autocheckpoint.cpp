// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <prime/autocheckpoint.h>
#include <prevector/prevector.h>
#include <block/block.h>
#include <util.h>
#include <random/random.h>
#include <file_operate/fs.h>
#include <scrypt.h>
#include <debugcs/debugcs.h>

static const char *dirname = "autocheckpoints";
static const char *datname = "autocheckpoints.dat";
static constexpr int lowerBlockHeight = 440000; // mainnet and testnet
#define CP_DEBUG_CS(str) debugcs::instance() << (str) << debugcs::endl()

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
    LLOCK(cs_autocp);
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

    // check: checksum hash_65536
    CDataStream ssda(vchData);
    if(hashIn != get_hash_65536(ssda))
        return false;

    mapAutocheck.clear();
    while(! ssda.eof()) {
        AutoCheckData data;
        ssda >> data;
        CP_DEBUG_CS(tfm::format("Autocheckpoint buildmap: %d %d %s", data.nHeight, data.nTime, data.hash.ToString()));
        const char *s = (const char *)&data.sig;
        if(s[0]=='d' && s[1]=='o' && s[2]=='g' && s[3]=='e')
            mapAutocheck.insert(std::make_pair(data.nHeight, data));
        else
            return false;
    }
    return true;
}

template <typename T>
bool CAutocheckPoint_impl<T>::Write(const CBlockIndex_impl<T> &header, int32_t nHeight, CAutoFile &fileout, CDataStream &whash) {
    AutoCheckData data;
    assert(header.get_hashPrevBlock()!=0);
    try {
        data.nHeight = nHeight;
        data.nTime = header.get_nTime();
        data.hash = header.GetBlockHash();

        CP_DEBUG_CS(tfm::format("Autocheckpoint Write: %d %d %s", data.nHeight, data.nTime, data.hash.ToString()));
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
uint65536 CAutocheckPoint_impl<T>::get_hash_65536(const CDataStream &data) const {
    return hash_basis::Hash65536(data.begin(), data.end());
}

template <typename T>
CAutocheckPoint_impl<T>::CAutocheckPoint_impl() {
    mapAutocheck.clear();
    if(! fsbridge::dir_create(iofs::GetDataDir() / dirname))
        throw std::runtime_error("Autocheckpoint path error.");
    pathAddr = iofs::GetDataDir() / dirname / datname;
}

template <typename T>
CAutocheckPoint_impl<T>::~CAutocheckPoint_impl() {}

template <typename T>
bool CAutocheckPoint_impl<T>::Check() const { // nCheckBlocks blocks, autocheckpoints qhash(uint65536) check
    LLOCK(cs_autocp);
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

            CP_DEBUG_CS(tfm::format("Autochekpoint Check %s, %s", autocpValue->second.hash.ToString(), target->GetBlockHash().ToString()));
            if(autocpValue->second.hash != target->GetBlockHash())
                return false;
        }
        return true;
    } catch(const std::exception &) {
        return false;
    }
}

template <typename T>
bool CAutocheckPoint_impl<T>::Sign() const {
    LLOCK(cs_autocp);
    // under development (v3, instead of checksum hash_65536)

    return false;
}

template <typename T>
bool CAutocheckPoint_impl<T>::Verify() const {
    LLOCK(cs_autocp);
    // under development (v3, instead of checksum hash_65536)

    return false;
}

template <typename T>
bool CAutocheckPoint_impl<T>::BuildAutocheckPoints() {
    LLOCK(cs_autocp);
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
    CP_DEBUG_CS(tfm::format("CBlockIndex_impl<T> *block: %d", (uintptr_t)block));
    CP_DEBUG_CS(tfm::format("block addr: %s", block->get_hashPrevBlock().ToString()));
    if(block->get_hashPrevBlock()==0) { // genesis block
        return true;
    }

    int counter = nCheckBlocks;
    bool fprime=false;
    assert(0<counter);
    for(;;) {
        if(block->get_nHeight()<=lowerBlockHeight)
            break;
        if(is_prime(block->get_nHeight())) {
            fprime = true;
            if(--counter==0 || fprime)
                break;
        }
        if(block->get_hashPrevBlock()==0)
            break;
        block = block_info::mapBlockIndex[block->get_hashPrevBlock()];
    }
    if(fprime==false)
        return true;

    int randv = latest_crypto::random::GetRandInt(999999);
    std::string tmpfn = tfm::format("%s.%d", datname, randv);
    fs::path pathTmp = iofs::GetDataDir() / tmpfn;
    CAutoFile fileout = CAutoFile(::fopen(pathTmp.string().c_str(), "wb"), 0, 0);
    CP_DEBUG_CS(tfm::format("BuildAutocheckPoints path: %s, fileout: %d", pathTmp.string().c_str(), (uintptr_t)(FILE *)fileout));
    if(! fileout)
        return false;

    block = block_info::mapBlockIndex[block_info::hashBestChain];
    counter = nCheckBlocks;
    assert(0<counter);
    CDataStream whash; // output data (for checksum hash_65536)
    for(;;) {
        CP_DEBUG_CS(tfm::format("block check: %d", block->get_nHeight()));
        if(block->get_nHeight()<=lowerBlockHeight)
            break;
        if(is_prime(block->get_nHeight())) {
            CP_DEBUG_CS(tfm::format("block is_prime: %d", block->get_nHeight()));
            assert(block->get_hashPrevBlock()==block->get_pprev()->GetBlockHash());
            if(! Write(*block, block->get_nHeight(), fileout, whash)) {
                iofs::FileCommit(fileout);
                fileout.fclose();
                return false;
            }
            if(--counter==0)
                break;
        }
        if(block->get_hashPrevBlock()==0)
            break;
        block = block_info::mapBlockIndex[block->get_hashPrevBlock()];
    }

    // checksum hash_65536
    CDataStream dhash;
    dhash << get_hash_65536(whash);
    try {
        fileout << dhash;
    } catch(const std::exception &) {
        iofs::FileCommit(fileout);
        fileout.fclose();
        return false;
    }

    iofs::FileCommit(fileout);
    fileout.fclose();
    return iofs::RenameOver(pathTmp, pathAddr) && Buildmap() && Check();
}

template class CAutocheckPoint_impl<uint256>;
