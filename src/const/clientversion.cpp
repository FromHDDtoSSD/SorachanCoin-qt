// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <version.h>
#include <util/tinyformat.h>

std::string format_version::FormatVersion(int nVersion) {
    if (nVersion % 100 == 0) {
        return tfm::format("%d.%d.%d", nVersion/1000000, (nVersion/10000)%100, (nVersion/100)%100);
    } else {
        return tfm::format("%d.%d.%d.%d", nVersion/1000000, (nVersion/10000)%100, (nVersion/100)%100, nVersion%100);
    }
}

std::string format_version::FormatFullVersion() {
    return version::CLIENT_BUILD;
}

// Format the subversion field according to BIP 14 spec (https://en.bitcoin.it/wiki/BIP_0014)
std::string format_version::FormatSubVersion(const std::string &name, int nClientVersion, const std::vector<std::string> &comments) {
    std::ostringstream ss;
    ss << "/";
    ss << name << ":" << FormatVersion(nClientVersion);
    if (! comments.empty()) {
        std::vector<std::string>::const_iterator it(comments.begin());
        ss << "(" << *it;
        for(++it; it != comments.end(); ++it)
            ss << "; " << *it;
        ss << ")";
    }
    ss << "/";
    return ss.str();
}
