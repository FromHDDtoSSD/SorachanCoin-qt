// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <db_addr.h>
#include <block/block_info.h>
#include <file_operate/fs.h>

CAddrDB::CAddrDB() : sqldb(CSqliteDBEnv::getname_peers(), "r+") {
    const fs::path peers_v1 = iofs::GetDataDir() / "peers.dat.v1.old";
    const fs::path peers = iofs::GetDataDir() / "peers.dat";
    fsbridge::file_safe_remove(peers_v1);
    fsbridge::file_safe_remove(peers);
}

bool CAddrDB::Write(const CAddrMan &addr) {
    addrdb_info adi;
    adi.message.insert(adi.message.end(), BEGIN(block_info::gpchMessageStart), END(block_info::gpchMessageStart));
    CDBStream ssAddr(&adi.addr, 10000);
    ::Serialize(ssAddr, addr);

    CDataStream ssHash;
    ssHash.reserve(10000);
    ssHash << adi;
    uint256 checksum = hash_basis::Hash(ssHash.begin(), ssHash.end());

    if(! sqldb.Write(std::string("addrdb"), std::make_pair(adi, checksum)))
        return logging::error("CAddrman::Write() : I/O error");

    debugcs::instance() << "CAddrDB Write() success" << debugcs::endl();
    return true;
}

bool CAddrDB::Read(CAddrMan &addr) {

    CDataStream ssKey;
    ssKey.reserve(1000);
    CDataStream ssValue;
    ssValue.reserve(10000);
    if(IDB::ReadAtCursor(std::move(sqldb.GetIteCursor(std::string("%addrdb%"))), ssKey, ssValue)!=0)
        return logging::error("CAddrman::Read() : no data");

    std::string str;
    ssKey >> str;

    addrdb_info adi;
    uint256 checksum;
    ssValue >> adi;
    ssValue >> checksum;
    CDataStream ssHash;
    ssHash.reserve(1000);
    ssHash << adi;

    const size_t gpchMessageSize = (END(block_info::gpchMessageStart)-BEGIN(block_info::gpchMessageStart))/sizeof(unsigned char);

    if(str!="addrdb")
        return logging::error("CAddrman::Read() : invalid db key");
    if(checksum!=hash_basis::Hash(ssHash.begin(), ssHash.end()))
        return logging::error("CAddrman::Read() : checksum mismatch; data corrupted");
    if(gpchMessageSize!=adi.message.size())
        return logging::error("CAddrman::Read() : invalid network magic number size");
    if(std::memcmp(adi.message.data(), block_info::gpchMessageStart, adi.message.size())!=0)
        return logging::error("CAddrman::Read() : invalid network magic number");

    CDBStream ssAddr(&adi.addr);
    ::Unserialize(ssAddr, addr);
    debugcs::instance() << "CAddrDB Read() success" << debugcs::endl();
    return true;
}
