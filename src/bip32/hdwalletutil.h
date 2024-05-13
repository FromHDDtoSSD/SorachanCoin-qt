// Copyright (c) 2017-2018 The Bitcoin Core developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_WALLETUTIL_H
#define BITCOIN_WALLET_WALLETUTIL_H

#include <file_operate/fs.h>

#include <vector>

namespace rapidsync {

bool urlsplit(std::string url, std::string &host, std::string &path);
bool GetData(std::string host, std::string path, std::vector<unsigned char> &responseBody, int32_t limit = 0);

bool GetRapidTime(time_t &time, std::string url) {
    constexpr int32_t limit = 1 * 1024 * 1024;
    std::string host;
    std::string target;
    urlsplit(url, host, target);
    std::vector<unsigned char> compress_data;
    time = ::time(nullptr);
    if(! GetData(host, target, compress_data, limit))
        return false;
    if(compress_data.size() < 32 * 1024)
        return false;
    time = ::time(nullptr) - time;
    return true;
}

} // namespace rapidsync

namespace hdwalletutil {

//! Get the path of the wallet directory.
fs::path GetWalletDir();

//! Get wallets in wallet directory.
std::vector<fs::path> ListWalletDir();

//! The WalletLocation class provides wallet information.
class WalletLocation final
{
    std::string m_name;
    fs::path m_path;

public:
    explicit WalletLocation() {}
    explicit WalletLocation(const std::string &name);

    //! Get wallet name.
    const std::string &GetName() const { return m_name; }

    //! Get wallet absolute path.
    const fs::path &GetPath() const { return m_path; }

    //! Return whether the wallet exists.
    bool Exists() const;
};

} // namespace hdwalletutil

#endif // BITCOIN_WALLET_WALLETUTIL_H
