// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <block/witness.h>
#include <util/strencodings.h>

std::string CScriptWitness::ToString() const
{
    std::string ret = "CScriptWitness(";
    for (unsigned int i = 0; i < stack.size(); i++) {
        if (i) {
            ret += ", ";
        }
        ret += strenc::HexStr(stack[i]);
    }
    return ret + ")";
}

std::string CScriptQai::ToString() const
{
    std::string ret = "CQaiTransaction(";
    for (unsigned int i = 0; i < stack.size(); i++) {
        if (i) {
            ret += ", ";
        }
        ret += strenc::HexStr(stack[i]);
    }
    return ret + ")";
}
