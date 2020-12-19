// Copyright (c) 2014-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAINPARAMSBASE_H
#define BITCOIN_CHAINPARAMSBASE_H

#include <memory>
#include <string>
#include <vector>

namespace chainparamsbase {

/**
 * CBaseChainParams defines the base parameters (shared between bitcoin-cli and bitcoind)
 * of a given instance of the Bitcoin system.
 */
class CBaseChainParams
{
public:
    /** BIP70 chain name strings (main, test or regtest) */
    static std::string MAIN() {return "main";}
    static std::string TESTNET() {return "test";}
    static std::string REGTEST() {return "regtest";}

    /** SorachanCoin chain name strings (test2, prediction) */
    static std::string TESTNET2() {return "test2";}
    static std::string PREDICTION() {return "prediction";}

    const std::string &DataDir() const noexcept { return strDataDir_; }
    int RPCPort() const noexcept { return nRPCPort_; }

    CBaseChainParams()=delete;
    CBaseChainParams(const CBaseChainParams &)=delete;
    CBaseChainParams(CBaseChainParams &&)=delete;
    CBaseChainParams &operator=(const CBaseChainParams &)=delete;
    CBaseChainParams &operator=(CBaseChainParams &&)=delete;
    CBaseChainParams(const std::string &data_dir, int rpc_port) noexcept :
        nRPCPort_(rpc_port), strDataDir_(data_dir) {}

private:
    int nRPCPort_;
    std::string strDataDir_;
};

/**
 * Creates and returns a std::unique_ptr<CBaseChainParams> of the chosen chain.
 * @returns a CBaseChainParams* of the chosen chain.
 * @throws a std::runtime_error if the chain is not supported.
 */
std::unique_ptr<CBaseChainParams> CreateBaseChainParams(const std::string &chain);

/**
 *Set the arguments for chainparams
 */
void SetupChainParamsBaseOptions();

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */
const CBaseChainParams &BaseParams() noexcept;

/** Sets the params returned by Params() to those for the given network. */
void SelectBaseParams(const std::string &chain);

} // namespace chainparamsbase

#endif // BITCOIN_CHAINPARAMSBASE_H
