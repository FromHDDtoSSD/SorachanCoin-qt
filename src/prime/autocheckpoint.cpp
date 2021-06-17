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
#include <db.h>
#include <debugcs/debugcs.h>

static constexpr int lowerBlockHeight = 440000; // mainnet and testnet
#ifdef DEBUG
//# define CP_DEBUG_CS(str) debugcs::instance() << (str) << debugcs::endl()
# define CP_DEBUG_CS(str)
#else
# define CP_DEBUG_CS(str)
#endif

namespace {
class CAcpDB final {
    CAcpDB(const CAcpDB &)=delete;
    CAcpDB(CAcpDB &&)=delete;
    CAcpDB &operator=(const CAcpDB &)=delete;
    CAcpDB &operator=(CAcpDB &&)=delete;
public:
    explicit CAcpDB(const char *mode="r+") : sqldb(CSqliteDBEnv::getname_autocheckpoints(), mode, false) {}
    ~CAcpDB() {}

    bool Write(const AutoCheckData &data) {
        CDataStream ssData;
        ssData.reserve(10000);
        ssData << data;
        CDataStream ssKey;
        ssKey.reserve(1000);
        ssKey << hash_basis::Hash(&ssData[0], &ssData[0]+ssData.size());
        if(! sqldb.Write(std::make_pair(std::string("qhash"), ssKey), ssData))
            return false;
        CSqliteDBEnv::get_instance().Flush(CSqliteDBEnv::getname_autocheckpoints());
        return true;
    }
    bool Read(std::vector<AutoCheckData> &dest) {
        dest.clear();
        IDB::DbIterator ite = sqldb.GetIteCursor();
        CDataStream ssKey;
        ssKey.reserve(1000);
        CDataStream ssValue;
        ssValue.reserve(10000);
        int ret;
        while((ret=IDB::ReadAtCursor(ite, ssKey, ssValue))!=DB_NOTFOUND) {
            if(ret!=0)
                break;
            std::string str;
            uint256 hash;
            ssKey >> str;
            ssKey >> hash;
            if(str!="qhash" && hash!=hash_basis::Hash(&ssValue[0], &ssValue[0]+ssValue.size()))
                return false;
            AutoCheckData value;
            ssValue >> value;
            dest.emplace_back(value);
        }
        return true;
    }
private:
    CSqliteDB sqldb;
};
} // namespace

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
    LOCK(cs_autocp);
    std::vector<AutoCheckData> acp;
    if(! CAcpDB("r").Read(acp))
        return false;
    mapAutocheck.clear();
    for(const auto &data: acp) {
        CP_DEBUG_CS(tfm::format("Autocheckpoint buildmap: %d %d %s", data.nHeight, data.nTime, data.hash.ToString()));
        mapAutocheck.insert(std::make_pair(data.nHeight, data));
    }
    return true;
}

template <typename T>
bool CAutocheckPoint_impl<T>::Write(const CBlockIndex &header, int32_t nHeight) {
    LOCK(cs_autocp);
    assert(header.get_hashPrevBlock()!=0);
    AutoCheckData data;
    data.nHeight = nHeight;
    data.nTime = header.get_nTime();
    data.hash = header.GetBlockHash();
    CP_DEBUG_CS(tfm::format("Autocheckpoint Write: %d %d %s", data.nHeight, data.nTime, data.hash.ToString()));
    return CAcpDB().Write(data);
}

template <typename T>
CAutocheckPoint_impl<T>::CAutocheckPoint_impl() {
    mapAutocheck.clear();
}

template <typename T>
CAutocheckPoint_impl<T>::~CAutocheckPoint_impl() {}

template <typename T>
bool CAutocheckPoint_impl<T>::Check() const { // nCheckBlocks blocks, autocheckpoints qhash(uint65536) check
    LOCK(cs_autocp);
    try {
        if(block_info::mapBlockIndex.empty())
            return false;

        const CBlockIndex *const bestBlock = block_info::mapBlockIndex[block_info::hashBestChain];
        for (int i=0; i < nCheckBlocks; ++i) {
            const auto &autocpValue = mapAutocheck.find(bestBlock->get_nHeight()-i);
            if(autocpValue==mapAutocheck.end())
                continue;

            const CBlockIndex *target = bestBlock;
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
    LOCK(cs_autocp);
    // under development (v3, instead of checksum sha256)

    return false;
}

template <typename T>
bool CAutocheckPoint_impl<T>::Verify() const {
    LOCK(cs_autocp);
    // under development (v3, instead of checksum sha256)

    return false;
}

template <typename T>
bool CAutocheckPoint_impl<T>::BuildAutocheckPoints() {
    LOCK(cs_autocp);
    const CBlockIndex *block = block_info::mapBlockIndex[block_info::hashBestChain];

    assert(block);
    CP_DEBUG_CS(tfm::format("CBlockIndex *block: %d", (uintptr_t)block));
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

    block = block_info::mapBlockIndex[block_info::hashBestChain];
    counter = nCheckBlocks;
    assert(0<counter);
    for(;;) {
        CP_DEBUG_CS(tfm::format("block check: %d", block->get_nHeight()));
        if(block->get_nHeight()<=lowerBlockHeight)
            break;
        if(is_prime(block->get_nHeight())) {
            CP_DEBUG_CS(tfm::format("block is_prime: %d", block->get_nHeight()));
            assert(block->get_hashPrevBlock()==block->get_pprev()->GetBlockHash());
            if(! Write(*block, block->get_nHeight()))
                return false;
            if(--counter==0)
                break;
        }
        if(block->get_hashPrevBlock()==0)
            break;
        block = block_info::mapBlockIndex[block->get_hashPrevBlock()];
    }

    return Buildmap() && Check();
}

template class CAutocheckPoint_impl<uint256>;
