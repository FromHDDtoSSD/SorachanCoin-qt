// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_C_OVERLOAD_H
#define BITCOIN_C_OVERLOAD_H

#include <string>
#include <stdlib.h>

namespace util {
    inline int abs(int n) {
        return ::abs(n);
    }
    inline int64_t abs64(int64_t n) {
        return (n >= 0 ? n : -n);
    }
}

namespace strenc {
    inline int32_t strtol(const std::string &str) {
        return ::strtol(str.c_str(), nullptr, 10);
    }

    inline uint32_t strtoul(const std::string &str) {
        return ::strtoul(str.c_str(), nullptr, 10);
    }
}

#endif
