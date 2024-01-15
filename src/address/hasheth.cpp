
#include <util/strencodings.h>
#include <address/hasheth.h>
#include <hash.h>

std::string hasheth::EncodeHashEth(const CPubKey &pubkey) {
    key_vector vcheth = pubkey.GetPubEth();
    return EncodeHashEth(vcheth.data(), vcheth.data() + vcheth.size());
}

std::string hasheth::EncodeHashEth(const unsigned char *pbegin, const unsigned char *pend) {
    uint160 hash;
    latest_crypto::CHashEth().Write(pbegin, (size_t)(pend - pbegin)).Finalize((unsigned char *)&hash);
    std::string str = "0x";
    str += hash.GetHex();
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
    str += hash2.GetHex();
    return str;
}
