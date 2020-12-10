// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_WALLETUTIL_H
#define BITCOIN_WALLET_WALLETUTIL_H

#include <file_operate/fs.h>

#include <vector>

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
    explicit WalletLocation() noexcept {}
    explicit WalletLocation(const std::string &name);

    //! Get wallet name.
    const std::string &GetName() const noexcept { return m_name; }

    //! Get wallet absolute path.
    const fs::path &GetPath() const noexcept { return m_path; }

    //! Return whether the wallet exists.
    bool Exists() const;
};

} // namespace hdwalletutil

#endif // BITCOIN_WALLET_WALLETUTIL_H
