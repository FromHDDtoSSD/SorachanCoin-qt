// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORA_BLOCKDATA_DB_H
#define SORA_BLOCKDATA_DB_H

// Blockchain file system by SQL database
// step1(v3.7.10): replaced from CAutoFile to CBlockDataDB
// step2(v4): like NTFS, will implement large block data I/O system

#include <serialize.h>
#include <block/block.h>
#include <db.h>

/*
 * replaced from CAutoFile to CBlockDataDB
 */

class CBlockDataDB final {
    CBlockDataDB(const CBlockDataDB &)=delete;
    CBlockDataDB(CBlockDataDB &&)=delete;
    CBlockDataDB &operator=(const CBlockDataDB &)=delete;
    CBlockDataDB &operator=(CBlockDataDB &&)=delete;

    constexpr static int nFile = 1; // fixed nFile number

public:
    CBlockDataDB(const char *mode="r+") : sqldb(CSqliteDBEnv::getname_maindata(), mode) {}
    ~CBlockDataDB() {}

    template <typename HASH>
    bool Write(const CBlock_impl<HASH> &data, unsigned int &nFileRet, unsigned int &nBlockPosRet) {
        unsigned int blklastpos; // CAutoFile: offset bytes CBlockdataDB: number (start 0)
        if(! sqldb.Exists(std::string("blklastpos"))) {
            blklastpos = 0;
        } else {
            if(! sqldb.Read(std::string("blklastpos"), blklastpos))
                return false;
            ++blklastpos;
        }
        if(! sqldb.Write(std::make_pair(std::string("blkdata"), blklastpos), data))
            return false;
       nFileRet = nFile;
       nBlockPosRet = blklastpos;
       return true;
    }

    template <typename HASH>
    bool Read(CBlock_impl<HASH> &data, unsigned int nFile, unsigned int nBlockPos) {
        (void)nFile;
        return sqldb.Read(std::make_pair(std::string("blkdata"), nBlockPos), data);
    }

    template <typename HASH>
    bool Read(CTransaction_impl<HASH> &tx, unsigned int nFile, unsigned int nBlockPos, unsigned int nTxPos) {
        (void)nFile;
        std::vector<char> vchKey;
        CDBStream ssKey(&vchKey);
        ::Serialize(ssKey, std::make_pair(std::string("blkdata"), nBlockPos));
        IDB::DbIterator ite = sqldb.GetIteCursor(std::string(vchKey.begin(), vchKey.end()));
        std::vector<char> vchKey2;
        CDBStream ssKey2(&vchKey2);
        std::vector<char> vchValue;
        CDBStream ssValue(&vchValue, 10000);
        if(CSqliteDB::ReadAtCursor(ite, ssKey2, ssValue)!=0)
            return false;
        CDBStream ssTx(&vchValue[nTxPos]);
        ::Unserialize(ssTx, tx);
        return true;
    }

private:
    CSqliteDB sqldb;
};

#endif // SORA_BLOCKDATA_DB_H
