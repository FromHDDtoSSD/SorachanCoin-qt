// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/strencodings.h>
#include <address/hasheth.h>
#include <hash.h>

///////////////////////////////////////////////////////////////////////////////////
// Note:
// When get a Eth style key, Must NOT use ToString(), GetHex(), SetHex() in uint160
// using HexStr(std::vector<unsigned char>)
//
// e.g. hex is '9abcdef5'
// ToString(): f5debc9a
// HexStr: 9abcdef5 -> this style is Eth style key.
///////////////////////////////////////////////////////////////////////////////////

std::string hasheth::HexStr(const CEthID &id) {
    return std::string("0x") + strenc::HexStr(id.begin(), id.end());
}

CEthID hasheth::ParseHex(const std::string &hexstr) {
    std::string hextmp = hexstr;
    if(hexstr[0]=='0' && hexstr[1]=='x')
        hextmp.erase(0, 2);

    strenc::hex_vector hex = strenc::ParseHex(hextmp);
    if(hex.size() != sizeof(CEthID))
        return CEthID();

    CEthID ethid;
    ::memcpy(ethid.begin(), hex.data(), sizeof(CEthID));
    return ethid;
}

std::string hasheth::EncodeHashEth(const CPubKey &pubkey) {
    key_vector vcheth = pubkey.GetPubEth();
    return EncodeHashEth(vcheth.data(), vcheth.data() + vcheth.size());
}

std::string hasheth::EncodeHashEth(const unsigned char *pbegin, const unsigned char *pend) {
    uint160 hash;
    latest_crypto::CHashEth().Write(pbegin, (size_t)(pend - pbegin)).Finalize((unsigned char *)&hash);
    std::string str = "0x";
    str += strenc::HexStr(key_vector(hash.begin(), hash.end()));
    return str;
}

std::string hasheth::EncodeHashEth2(const CPubKey &pubkey) {
    key_vector vcheth = pubkey.GetPubEth();
    return EncodeHashEth2(vcheth.data(), vcheth.data() + vcheth.size());
}

std::string hasheth::EncodeHashEth2(const unsigned char *pbegin, const unsigned char *pend) {
    uint160 hash;
    latest_crypto::CHashEth().Write(pbegin, (size_t)(pend - pbegin)).Finalize((unsigned char *)&hash);
    uint160 hash2;
    latest_crypto::CHashEth().Write(hash.begin(), hash.size()).Finalize((unsigned char *)&hash2);
    std::string str = "0x";
    str += strenc::HexStr(key_vector(hash2.begin(), hash2.end()));
    return str;
}
