// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include <stdio.h>
#include <sync/sync.h>
#include <serialize.h>
#include <block/block.h>

class CWallet;
template <typename T> class CTransaction_impl;
using CTransaction = CTransaction_impl<uint256>;

//
// block_load
//
namespace block_load
{
    void UnloadBlockIndex();
    bool LoadBlockIndex(bool fAllowNew=true);    // start
    bool LoadExternalBlockFile(FILE *fileIn);    // bootstrap
}

//
// wallet_process
//
namespace wallet_process
{
    class manage : private no_instance
    {
    private:
        static CCriticalSection cs_setpwalletRegistered;
    public:
        static void RegisterWallet(CWallet *pwalletIn);
        static void UnregisterWallet(CWallet *pwalletIn);
        static void SyncWithWallets(const CTransaction &tx, const CBlock *pblock = nullptr, bool fUpdate = false, bool fConnect = true);
    };
}

#endif
