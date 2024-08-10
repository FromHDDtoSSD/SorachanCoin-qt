// Copyright (c) 2012 The Bitcoin developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

#include <const/clientversion.h>
#include <const/no_instance.h>
#include <string>
#include <vector>

//
// coin name
//
#define strCoinName  "SorachanCoin"
#define strCoinNameL "sorachancoin"

namespace version
{
    //
    // Name of client reported in the 'version' message. Report the same name
    // for both bitcoind and bitcoin-qt, to make it harder for attackers to
    // target servers or GUI users specifically.
    //
#ifdef ONLY_TESTNET_MODE
    const std::string CLIENT_NAME("Satoshi only testnet");
#else
    const std::string CLIENT_NAME("Satoshi");
#endif
    //const std::string CLIENT_NAME("Satoshi");

    //
    // client versioning
    //
    const int CLIENT_VERSION =
                               1000000 * CLIENT_VERSION_MAJOR
                             +   10000 * CLIENT_VERSION_MINOR
                             +     100 * CLIENT_VERSION_REVISION
                             +       1 * CLIENT_VERSION_BUILD;

    //
    // database format versioning
    //
    const int DATABASE_VERSION = 70707;

    //
    // network protocol versioning
    //
    const int PROTOCOL_VERSION = 60011;

    //
    // earlier versions not supported as of Feb 2012, and are disconnected
    //
    const int MIN_PROTO_VERSION = 209;

    //
    // nTime field added to CAddress, starting with this version;
    // if possible, avoid requesting addresses nodes older than this
    //
    const int CADDR_TIME_VERSION = 31402;

    //
    // only request blocks from nodes outside this range of versions
    //
    const int NOBLKS_VERSION_START = 60002;
    const int NOBLKS_VERSION_END = 60006;

    // version.cpp
    extern const std::string CLIENT_BUILD;
    extern const std::string CLIENT_DATE;
}

// clientversion.cpp
class format_version : private no_instance
{
private:
    static std::string FormatVersion(int nVersion);
public:
    static std::string FormatFullVersion();
    static std::string FormatSubVersion(const std::string &name, int nClientVersion, const std::vector<std::string> &comments);
};

// display version
#define DISPLAY_VERSION_MAJOR        3
#define DISPLAY_VERSION_MINOR        92
#define DISPLAY_VERSION_REVISION     15

#endif
