#ifndef BITCOIN_HASHETH_H
#define BITCOIN_HASHETH_H

#include <string>
#include <vector>

namespace hasheth {
    std::string EncodeHashEth(const unsigned char *pbegin, const unsigned char *pend);
} // namespace hasheth

#endif // BITCOIN_HASHETH_H