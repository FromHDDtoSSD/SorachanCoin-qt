// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2020 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//

#ifndef BITCOIN_ADDR_H
#define BITCOIN_ADDR_H

#include "main.h"

#include <string>
#include <vector>
#include <db_cxx.h>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

/**
** Access to the (IP) address database (peers.dat)
*/
#ifdef CSCRIPT_PREVECTOR_ENABLE
typedef prevector<PREVECTOR_N, uint8_t> addrdb_vector;
#else
typedef std::vector<uint8_t> addrdb_vector;
#endif
class CAddrDB
{
private:
	CAddrDB(const CAddrDB &); // {}
	CAddrDB(const CAddrDB &&); // {}
	CAddrDB &operator=(const CAddrDB &); // {}
	CAddrDB &operator=(const CAddrDB &&); // {}

	boost::filesystem::path pathAddr;

public:
	CAddrDB();
	bool Write(const CAddrMan &addr);
	bool Read(CAddrMan &addr);
};

#endif
