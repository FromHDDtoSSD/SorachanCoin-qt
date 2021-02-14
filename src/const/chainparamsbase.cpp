// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <const/chainparamsbase.h>

#include <util/tinyformat.h>
#include <util/system.h>
#include <util/memory.h>

#include <util/args.h>
#include <assert.h>

void chainparamsbase::SetupChainParamsBaseOptions() {
    ARGS.AddArg("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                                   "This is intended for regression testing tools and app development.", true, OptionsCategory::CHAINPARAMS);
    ARGS.AddArg("-testnet", "Use the test chain", false, OptionsCategory::CHAINPARAMS);
    ARGS.AddArg("-vbparams=deployment:start:end", "Use given start/end times for specified version bits deployment (regtest-only)", true, OptionsCategory::CHAINPARAMS);
}

static std::unique_ptr<chainparamsbase::CBaseChainParams> globalChainBaseParams;

const chainparamsbase::CBaseChainParams &chainparamsbase::BaseParams() noexcept {
    assert(globalChainBaseParams);
    return *globalChainBaseParams;
}

std::unique_ptr<chainparamsbase::CBaseChainParams> chainparamsbase::CreateBaseChainParams(const std::string &chain) {
    if (chain == CBaseChainParams::MAIN())
        return MakeUnique<CBaseChainParams>("", 21587);
    else if (chain == CBaseChainParams::TESTNET())
        return MakeUnique<CBaseChainParams>("testnet2", 31587);
    else if (chain == CBaseChainParams::REGTEST())
        return MakeUnique<CBaseChainParams>("regtest", 41587);
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void chainparamsbase::SelectBaseParams(const std::string &chain) {
    globalChainBaseParams = CreateBaseChainParams(chain);
    ARGS.SelectConfigNetwork(chain);
}
