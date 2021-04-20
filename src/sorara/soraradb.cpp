// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ProofOfSpace [PoSpace]
// ref: https://github.com/Chia-Network/chia-blockchain

#include <sorara/soraradb.h>

CProofOfSpace::CProofOfSpace() : sqlPoSpace(CSqliteDBEnv::getname_pospacedb(), "r+", true) {} // secure mode

bool CProofOfSpace::WriteVersion(int nVersion) {
    return sqlPoSpace.Write(std::string("PoSpaceVersion"), nVersion);
}

bool CProofOfSpace::ReadVersion(int &nVersion) {
    return sqlPoSpace.Read(std::string("PoSpaceVersion"), nVersion);
}

CSoraraDB::CSoraraDB(const char *mode/*="r+"*/) : sqldb(CSqliteDBEnv::getname_soraradb(), mode) {}
