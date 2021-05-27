// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Copyright (c) 2018-2021 The Sora neko developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <block/block_check.h>
#include <net.h>
#include <txdb.h>
#include <util/thread.h>
#include <script/script.h>
#include <random/random.h>

CCheckQueue<CScriptCheck> block_check::thread::scriptcheckqueue(128);
unsigned int block_check::nStakeMinAge = block_check::mainnet::nStakeMinAge;
unsigned int block_check::nStakeTargetSpacing = block_check::mainnet::nStakeTargetSpacing;
unsigned int block_check::nPowTargetSpacing = block_check::mainnet::nPowTargetSpacing;
unsigned int block_check::nModifierInterval = block_check::mainnet::nModifierInterval;

bool CScriptCompressor::IsToKeyID(CKeyID &hash) const {
    using namespace ScriptOpcodes;
    if (script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 && script[2] == 20 && script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG) {
        std::memcpy(&hash, &script[3], 20);
        return true;
    }
    return false;
}

bool CScriptCompressor::IsToScriptID(CScriptID &hash) const {
    using namespace ScriptOpcodes;
    if (script.size() == 23 && script[0] == OP_HASH160 && script[1] == 20 && script[22] == OP_EQUAL) {
        std::memcpy(&hash, &script[2], 20);
        return true;
    }
    return false;
}

bool CScriptCompressor::IsToPubKey(CPubKey &pubkey) const {
    using namespace ScriptOpcodes;
    if (script.size() == 35 && script[0] == 33 && script[34] == OP_CHECKSIG && (script[1] == 0x02 || script[1] == 0x03)) {
        pubkey.Set(&script[1], &script[34]);
        return true;
    }
    if (script.size() == 67 && script[0] == 65 && script[66] == OP_CHECKSIG && script[1] == 0x04) {
        pubkey.Set(&script[1], &script[66]);
        return pubkey.IsFullyValid(); // if not fully valid, a case that would not be compressible
    }
    return false;
}

bool CScriptCompressor::Compress(std::vector<unsigned char> &out) const {
    CKeyID keyID;
    if (IsToKeyID(keyID)) {
        out.resize(21);
        out[0] = 0x00;
        std::memcpy(&out[1], &keyID, 20);
        return true;
    }
    CScriptID scriptID;
    if (IsToScriptID(scriptID)) {
        out.resize(21);
        out[0] = 0x01;
        std::memcpy(&out[1], &scriptID, 20);
        return true;
    }
    CPubKey pubkey;
    if (IsToPubKey(pubkey)) {
        out.resize(33);
        std::memcpy(&out[1], &pubkey[1], 32);
        if (pubkey[0] == 0x02 || pubkey[0] == 0x03) {
            out[0] = pubkey[0];
            return true;
        } else if (pubkey[0] == 0x04) {
            out[0] = 0x04 | (pubkey[64] & 0x01);
            return true;
        }
    }
    return false;
}

unsigned int CScriptCompressor::GetSpecialSize(unsigned int nSize) const {
    if (nSize == 0 || nSize == 1)
        return 20;
    if (nSize == 2 || nSize == 3 || nSize == 4 || nSize == 5)
        return 32;
    return 0;
}

bool CScriptCompressor::Decompress(unsigned int nSize, const std::vector<unsigned char> &in) {
    using namespace ScriptOpcodes;
    switch (nSize) {
    case 0x00:
        script.resize(25);
        script[0] = OP_DUP;
        script[1] = OP_HASH160;
        script[2] = 20;
        std::memcpy(&script[3], &in[0], 20);
        script[23] = OP_EQUALVERIFY;
        script[24] = OP_CHECKSIG;
        return true;
    case 0x01:
        script.resize(23);
        script[0] = OP_HASH160;
        script[1] = 20;
        std::memcpy(&script[2], &in[0], 20);
        script[22] = OP_EQUAL;
        return true;
    case 0x02:
    case 0x03:
        script.resize(35);
        script[0] = 33;
        script[1] = nSize;
        std::memcpy(&script[2], &in[0], 32);
        script[34] = OP_CHECKSIG;
        return true;
    case 0x04:
    case 0x05:
        unsigned char vch[33] = {};
        vch[0] = nSize - 2;
        std::memcpy(&vch[1], &in[0], 32);
        CPubKey pubkey(&vch[0], &vch[33]);
        if (!pubkey.Decompress())
            return false;
        assert(pubkey.size() == 65);
        script.resize(67);
        script[0] = 65;
        std::memcpy(&script[1], pubkey.begin(), 65);
        script[66] = OP_CHECKSIG;
        return true;
    }
    return false;
}

// Amount compression:
// * If the amount is 0, output 0
// * first, divide the amount (in base units) by the largest power of 10 possible; call the exponent e (e is max 9)
// * if e<9, the last digit of the resulting number cannot be 0; store it as d, and drop it (divide by 10)
//   * call the result n
//   * output 1 + 10*(9*n + d - 1) + e
// * if e==9, we only know the resulting number is not zero, so output 1 + 10*(n - 1) + 9
// (this is decodable, as d is in [1-9] and e is in [0-9])

uint64_t CCompressAmount::CompressAmount(uint64_t n)
{
    if (n == 0)
        return 0;
    int e = 0;
    while (((n % 10) == 0) && e < 9) {
        n /= 10;
        e++;
    }
    if (e < 9) {
        int d = (n % 10);
        assert(d >= 1 && d <= 9);
        n /= 10;
        return 1 + (n * 9 + d - 1) * 10 + e;
    } else {
        return 1 + (n - 1) * 10 + 9;
    }
}

uint64_t CCompressAmount::DecompressAmount(uint64_t x)
{
    // x = 0  OR  x = 1+10*(9*n + d - 1) + e  OR  x = 1+10*(n - 1) + 9
    if (x == 0)
        return 0;
    x--;
    // x = 10*(9*n + d - 1) + e
    int e = x % 10;
    x /= 10;
    uint64_t n = 0;
    if (e < 9) {
        // x = 9*n + d - 1
        int d = (x % 9) + 1;
        x /= 9;
        // x = n
        n = x * 10 + d;
    } else {
        n = x + 1;
    }
    while (e) {
        n *= 10;
        e--;
    }
    return n;
}

template <typename T>
void CCoins_impl<T>::FromTx(const CTransaction_impl<T> &tx, int nHeightIn) {
    fCoinBase = tx.IsCoinBase();
    fCoinStake = tx.IsCoinStake();
    fCoinPoSpace = tx.IsCoinPoSpace();
    fCoinMasternode = tx.IsCoinMasternode();
    vout = tx.get_vout();
    nHeight = nHeightIn;
    nVersion = tx.get_nVersion();
    ClearUnspendable();
}

template <typename T>
void CCoins_impl<T>::Clear() {
    fCoinBase = false;
    fCoinStake = false;
    fCoinPoSpace = false;
    fCoinMasternode = false;
    std::vector<CTxOut_impl<T>>().swap(vout);
    nHeight = 0;
    nVersion = 0;
}

template <typename T>
void CCoins_impl<T>::Cleanup() {
    while (vout.size() > 0 && vout.back().IsNull())
        vout.pop_back();
    if (vout.empty())
        std::vector<CTxOut_impl<T>>().swap(vout);
}

template <typename T>
void CCoins_impl<T>::ClearUnspendable() {
    for (CTxOut_impl<T> &txout: vout) {
        if (txout.get_scriptPubKey().IsUnspendable())
            txout.SetNull();
    }
    Cleanup();
}

template <typename T>
bool CCoins_impl<T>::IsPruned() const {
    for (const CTxOut_impl<T> &out: vout) {
        if (! out.IsNull())
            return false;
    }
    return true;
}

template <typename T>
bool CCoins_impl<T>::Spend(const COutPoint_impl<T> &out, CTxInUndo_impl<T> &undo) {
    if (out.get_n() >= vout.size())
        return false;
    if (vout[out.get_n()].IsNull())
        return false;
    undo = CTxInUndo_impl<T>(vout[out.get_n()]);
    vout[out.get_n()].SetNull();
    Cleanup();
    if (vout.size() == 0) {
        undo.nHeight = nHeight;
        undo.fCoinBase = fCoinBase;
        undo.fCoinStake = fCoinStake;
        undo.fCoinPoSpace = fCoinPoSpace;
        undo.fCoinMasternode = fCoinMasternode;
        undo.nVersion = this->nVersion;
    }
    return true;
}

template <typename T>
bool CCoins_impl<T>::Spend(int nPos) {
    CTxInUndo_impl<T> undo;
    COutPoint_impl<T> out(0, nPos);
    return Spend(out, undo);
}

template <typename T>
bool CCoins_impl<T>::IsAvailable(unsigned int nPos) const {
    return (nPos < vout.size() && !vout[nPos].IsNull() && !vout[nPos].get_scriptPubKey().IsZerocoinMint());
}

/**
 * calculate number of bytes for the bitmask, and its number of non-zero bytes
 * each bit in the bitmask represents the availability of one output, but the
 * availabilities of the first two outputs are encoded separately
 */
template <typename T>
void CCoins_impl<T>::CalcMaskSize(unsigned int &nBytes, unsigned int &nNonzeroBytes) const
{
    unsigned int nLastUsedByte = 0;
    for (unsigned int b = 0; 2 + b * 8 < vout.size(); b++) {
        bool fZero = true;
        for (unsigned int i = 0; i < 8 && 2 + b * 8 + i < vout.size(); i++) {
            if (!vout[2 + b * 8 + i].IsNull()) {
                fZero = false;
                continue;
            }
        }
        if (!fZero) {
            nLastUsedByte = b + 1;
            nNonzeroBytes++;
        }
    }
    nBytes += nLastUsedByte;
}

CCoinsKeyHasher::CCoinsKeyHasher() : salt(latest_crypto::random::GetRandHash()) {}



template <typename T>
void block_check::manage<T>::InvalidChainFound(CBlockIndex_impl<T> *pindexNew)
{
    if (pindexNew->get_nChainTrust() > block_info::nBestInvalidTrust) {
        block_info::nBestInvalidTrust = pindexNew->get_nChainTrust();
        CTxDB().WriteBestInvalidTrust(CBigNum(block_info::nBestInvalidTrust));
        CClientUIInterface::uiInterface.NotifyBlocksChanged();
    }

    uint256 nBestInvalidBlockTrust = pindexNew->get_nChainTrust() - pindexNew->get_pprev()->get_nChainTrust();
    uint256 nBestBlockTrust = block_info::pindexBest->get_nHeight() != 0 ? (block_info::pindexBest->get_nChainTrust() - block_info::pindexBest->get_pprev()->get_nChainTrust()) : block_info::pindexBest->get_nChainTrust();

    logging::LogPrintf("block_check::manage::InvalidChainFound: invalid block=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
            pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->get_nHeight(),
            CBigNum(pindexNew->get_nChainTrust()).ToString().c_str(), nBestInvalidBlockTrust.Get64(),
            util::DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()).c_str());
    logging::LogPrintf("block_check::manage::InvalidChainFound:  current best=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
            block_info::hashBestChain.ToString().substr(0,20).c_str(), block_info::nBestHeight,
            CBigNum(block_info::pindexBest->get_nChainTrust()).ToString().c_str(),
            nBestBlockTrust.Get64(),
            util::DateTimeStrFormat("%x %H:%M:%S", block_info::pindexBest->GetBlockTime()).c_str());
}

template <typename T>
bool block_check::manage<T>::VerifySignature(const CTransaction &txFrom, const CTransaction &txTo, unsigned int nIn, unsigned int flags, int nHashType)
{
    return CScriptCheck(txFrom, txTo, nIn, flags, nHashType)();    // Call by functor
}

template <typename T>
bool block_check::manage<T>::Reorganize(CTxDB_impl<T> &txdb, CBlockIndex_impl<T> *pindexNew)
{
    logging::LogPrintf("REORGANIZE\n");

    // Find the fork
    CBlockIndex *pfork = block_info::pindexBest;
    CBlockIndex *plonger = pindexNew;
    while (pfork != plonger) {
        while (plonger->get_nHeight() > pfork->get_nHeight()) {
            if ((plonger = plonger->set_pprev()) == nullptr)
                return logging::error("block_check::manage::Reorganize() : plonger->pprev is null");
        }
        if (pfork == plonger)
            break;
        if ((pfork = pfork->set_pprev()) == nullptr)
            return logging::error("block_check::manage::Reorganize() : pfork->pprev is null");
    }

    // List of what to disconnect
    std::vector<CBlockIndex *> vDisconnect;
    for (CBlockIndex *pindex = block_info::pindexBest; pindex != pfork; pindex = pindex->set_pprev())
        vDisconnect.push_back(pindex);

    // List of what to connect
    std::vector<CBlockIndex *> vConnect;
    for (CBlockIndex *pindex = pindexNew; pindex != pfork; pindex = pindex->set_pprev())
        vConnect.push_back(pindex);

    reverse(vConnect.begin(), vConnect.end());
    logging::LogPrintf("REORGANIZE: Disconnect %" PRIszu " blocks; %s..%s\n", vDisconnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), block_info::pindexBest->GetBlockHash().ToString().substr(0,20).c_str());
    logging::LogPrintf("REORGANIZE: Connect %" PRIszu " blocks; %s..%s\n", vConnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->GetBlockHash().ToString().substr(0,20).c_str());

    // Disconnect shorter branch
    std::vector<CTransaction> vResurrect;
    for(CBlockIndex *pindex: vDisconnect) {
        CBlock_impl<T> block;
        if (! block.ReadFromDisk(pindex))
            return logging::error("block_check::manage::Reorganize() : ReadFromDisk for disconnect failed");
        if (! block.DisconnectBlock(txdb, pindex))
            return logging::error("block_check::manage::Reorganize() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());

        // Queue memory transactions to resurrect
        for(const CTransaction &tx: block.get_vtx()) {
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
                vResurrect.push_back(tx);
        }
    }

    // Connect longer branch
    std::vector<CTransaction> vDelete;
    for (unsigned int i = 0; i < vConnect.size(); ++i) {
        CBlockIndex *pindex = vConnect[i];
        CBlock_impl<T> block;
        if (! block.ReadFromDisk(pindex))
            return logging::error("block_check::manage::Reorganize() : ReadFromDisk for connect failed");
        if (! block.ConnectBlock(txdb, pindex)) // Invalid block
            return logging::error("block_check::manage::Reorganize() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());

        // Queue memory transactions to delete
        for(const CTransaction &tx: block.get_vtx())
            vDelete.push_back(tx);
    }
    if (! txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
        return logging::error("block_check::manage::Reorganize() : WriteHashBestChain failed");

    // Make sure it's successfully written to disk before changing memory structure
    if (! txdb.TxnCommit())
        return logging::error("block_check::manage::Reorganize() : TxnCommit failed");

    // Disconnect shorter branch
    for(CBlockIndex *pindex: vDisconnect) {
        if (pindex->get_pprev())
            pindex->set_pprev()->set_pnext(nullptr);
    }

    // Connect longer branch
    for(CBlockIndex *pindex: vConnect) {
        if (pindex->get_pprev())
            pindex->set_pprev()->set_pnext(pindex);
    }

    // Resurrect memory transactions that were in the disconnected branch
    for(CTransaction &tx: vResurrect)
        tx.AcceptToMemoryPool(txdb, false);

    // Delete redundant memory transactions that are in the connected branch
    for(CTransaction &tx: vDelete)
        CTxMemPool::mempool.remove(tx);

    logging::LogPrintf("REORGANIZE: done\n");
    return true;
}

void block_check::thread::ThreadScriptCheck(void *)
{
    bitthread::tracethread trace(strCoinName "-scriptch");
    net_node::vnThreadsRunning[THREAD_SCRIPTCHECK]++;
    bitthread::RenameThread(strCoinName "-scriptch");
    scriptcheckqueue.Thread();
    net_node::vnThreadsRunning[THREAD_SCRIPTCHECK]--;
}

void block_check::thread::ThreadScriptCheckQuit()
{
    scriptcheckqueue.Quit();
}

template class CCoins_impl<uint256>;
template class block_check::manage<uint256>;
