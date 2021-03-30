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
#ifdef USE_BERKELEYDB
# include <db_cxx.h>
#endif
#include <file_operate/fs.h>
//#include <boost/filesystem.hpp>
//#include <boost/filesystem/fstream.hpp>

/*
 * Access to the (IP) address database (peers.dat)
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
private:
    fs::path pathAddr;

public:
	CAddrDB();
	bool Write(const CAddrMan &addr);
	bool Read(CAddrMan &addr);
};

#endif
