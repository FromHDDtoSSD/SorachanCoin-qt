
#include <util/strencodings.h>
#include <address/hasheth.h>
#include <hash.h>

///////////////////////////////////////////////////////////////////////////
// Note:
// When get a Eth style key, Must NOT use ToString(), GetHex() in uint160
// using HexStr(std::vector<unsigned char>)
//
// e.g. hex is '9abcdef5'
// ToString(): f5debc9a
// HexStr: 9abcdef5 -> this style is Eth style key.
///////////////////////////////////////////////////////////////////////////

std::string hasheth::HexStr(const CEthID &id) {
    return strenc::HexStr(id.begin(), id.end());
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
