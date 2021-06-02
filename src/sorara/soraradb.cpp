// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sorara/soraradb.h>
#include <key/privkey.h>
#include <key/pubkey.h>

CSoraraDB::CSoraraDB(const char *mode/*="r+"*/) : sqldb(CSqliteDBEnv::getname_soraradb(), mode) {}
