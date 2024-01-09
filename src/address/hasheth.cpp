
#include <util/strencodings.h>
#include <address/hasheth.h>
#include <hash.h>

std::string hasheth::EncodeHashEth(const unsigned char *pbegin, const unsigned char *pend) {
    uint160 hash;
    latest_crypto::CHashEth().Write(pbegin, (size_t)(pend - pbegin)).Finalize((unsigned char *)&hash);
    std::string str = "0x";
    str += strenc::HexStr(std::vector<unsigned char>(hash.begin(), hash.end()));
    return str;
}
