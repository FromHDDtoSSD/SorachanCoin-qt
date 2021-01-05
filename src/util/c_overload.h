// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_C_OVERLOAD_H
#define BITCOIN_C_OVERLOAD_H

#include <string>
#include <stdlib.h>

/* port to strencodings.h
inline std::string i64tostr(int64_t n) {
    return strprintf("%" PRId64, n);
}

inline std::string itostr(int n) {
    return strprintf("%d", n);
}

inline int64_t atoi64(const char *psz) {
#ifdef _MSC_VER
    return ::_atoi64(psz);
#else
    return ::strtoll(psz, nullptr, 10);
#endif
}

inline int64_t atoi64(const std::string &str) {
#ifdef _MSC_VER
    return ::_atoi64(str.c_str());
#else
    return ::strtoll(str.c_str(), nullptr, 10);
#endif
}

inline int32_t strtol(const char *psz) {
    return ::strtol(psz, nullptr, 10);
}

inline uint32_t strtoul(const char *psz) {
    return ::strtoul(psz, nullptr, 10);
}

inline int atoi(const std::string &str) {
    return ::atoi(str.c_str());
}
*/

namespace strenc {
    inline int32_t strtol(const std::string &str) {
        return ::strtol(str.c_str(), nullptr, 10);
    }

    inline uint32_t strtoul(const std::string &str) {
        return ::strtoul(str.c_str(), nullptr, 10);
    }
}

#endif
