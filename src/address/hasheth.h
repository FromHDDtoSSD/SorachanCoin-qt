#ifndef BITCOIN_HASHETH_H
#define BITCOIN_HASHETH_H

#include <string>
#include <vector>
#include <key/pubkey.h>

namespace hasheth {
    std::string HexStr(const CEthID &id);
    CEthID ParseHex(const std::string &hexstr);
    std::string EncodeHashEth(const CPubKey &pubkey);
    std::string EncodeHashEth(const unsigned char *pbegin, const unsigned char *pend);

    std::string EncodeHashEth2(const CPubKey &pubkey);
    std::string EncodeHashEth2(const unsigned char *pbegin, const unsigned char *pend);
} // namespace hasheth

#endif // BITCOIN_HASHETH_H
