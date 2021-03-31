// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ADDR_H
#define BITCOIN_ADDR_H

#include <main.h>
#include <addrman.h>
#include <string>
#include <vector>
#include <db.h>

/*
 * Access to the (IP) address database (SQLite: peers_sql.dat)
 */
#ifdef CSCRIPT_PREVECTOR_ENABLE
using addrdb_vector = prevector<PREVECTOR_N, uint8_t>;
#else
using addrdb_vector = std::vector<uint8_t>;
#endif
class CAddrDB
{
    CAddrDB(const CAddrDB &)=delete;
    CAddrDB(CAddrDB &&)=delete;
    CAddrDB &operator=(const CAddrDB &)=delete;
    CAddrDB &operator=(CAddrDB &&)=delete;
public:
    struct addrdb_info {
        std::vector<char> message;
        std::vector<char> addr;

        ADD_SERIALIZE_METHODS
        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream &s, Operation ser_action) {
            READWRITE(message);
            READWRITE(addr);
        }
    };
	CAddrDB();
	bool Write(const CAddrMan &addr);
	bool Read(CAddrMan &addr);
private:
    CSqliteDB sqldb;
};

#endif
