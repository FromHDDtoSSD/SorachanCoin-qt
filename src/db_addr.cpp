// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <db_addr.h>
#include <block/block_info.h>
#include <random/random.h>
//#include <file_operate/fs.h>

CAddrDB::CAddrDB()
{
    const std::string suffix(".v1.old");
    const fs::path addr = iofs::GetDataDir() / "peers.dat";
    const fs::path old_addr = fs::system_complete(addr.string() + suffix);
    if(fsbridge::file_exists(addr) && !fsbridge::file_exists(old_addr)) {
        fsbridge::file_rename(addr, old_addr);
    }

    pathAddr = addr;
}

bool CAddrDB::Write(const CAddrMan &addr)
{
    // Generate random temporary filename
    unsigned short randv = 0;
    latest_crypto::random::GetStrongRandBytes((unsigned char *)&randv, sizeof(randv));
    std::string tmpfn = tfm::format("peers.dat.%04x", randv);

    // serialize addresses, checksum data up to that point, then append csum
    CDataStream ssPeers(0, 0);
    ssPeers << FLATDATA(block_info::gpchMessageStart);
    ssPeers << addr;
    uint256 hash = hash_basis::Hash(ssPeers.begin(), ssPeers.end());
    ssPeers << hash;

    // open temp output file, and associate with CAutoFile
    boost::filesystem::path pathTmp = iofs::GetDataDir() / tmpfn;
    CAutoFile fileout = CAutoFile(::fopen(pathTmp.string().c_str(), "wb"), 0, 0);
    if(! fileout) {
        return logging::error("CAddrman::Write() : open failed");
    }

    // Write and commit header, data
    try {
        fileout << ssPeers;
    } catch(const std::exception &) {
        return logging::error("CAddrman::Write() : I/O error");
    }

    iofs::FileCommit(fileout);
    fileout.fclose();

    // replace existing peers.dat, if any, with new peers.dat.XXXX
    if(! iofs::RenameOver(pathTmp, pathAddr)) {
        return logging::error("CAddrman::Write() : Rename-into-place failed");
    }
    return true;
}

bool CAddrDB::Read(CAddrMan &addr)
{
    // open input file, and associate with CAutoFile
    CAutoFile filein = CAutoFile(::fopen(pathAddr.string().c_str(), "rb"), 0, 0);
    if(! filein) {
        return logging::error("CAddrman::Read() : open failed");
    }

    // use file size to size memory buffer
    int fileSize = iofs::GetFilesize(filein);
    int dataSize = fileSize - sizeof(uint256);

    // Don't try to resize to a negative number if file is small
    if(dataSize < 0) { dataSize = 0; }
    addrdb_vector vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    } catch(const std::exception &) {
        return logging::error("CAddrman::Read() 2 : I/O error or stream data corrupted");
    }
    filein.fclose();

    CDataStream ssPeers(vchData, 0, 0);

    // verify stored checksum matches input data
    uint256 hashTmp = hash_basis::Hash(ssPeers.begin(), ssPeers.end());
    if(hashIn != hashTmp) {
        return logging::error("CAddrman::Read() : checksum mismatch; data corrupted");
    }

    unsigned char pchMsgTmp[4];
    try {
        // de-serialize file header (block_info::gpchMessageStart magic number) and
        ssPeers >> FLATDATA(pchMsgTmp);

        // verify the network matches ours
        if(::memcmp(pchMsgTmp, block_info::gpchMessageStart, sizeof(pchMsgTmp))) {
            return logging::error("CAddrman::Read() : invalid network magic number");
        }

        // de-serialize address data into one CAddrMan object
        ssPeers >> addr;
    } catch(const std::exception &) {
        return logging::error("CAddrman::Read() : I/O error or stream data corrupted");
    }
    return true;
}
