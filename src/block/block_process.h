// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_PROCESS_H
#define BITCOIN_BLOCK_PROCESS_H

#include <file_operate/file_open.h>
#include <block/block.h>
#include <prevector/prevector.h>
#include <debug/debug.h>

class CNode;
class CInv;

// T == uint256
namespace block_process
{
    extern CCriticalSection cs_main;
    extern std::map<uint256, CBlock *> mapOrphanBlocks;
    extern std::map<uint256, uint256> mapProofOfStake;
    class manage : private no_instance
    {
    private:
        static std::multimap<uint256, CBlock *> mapOrphanBlocksByPrev;
        static std::set<std::pair<COutPoint, unsigned int> > setStakeSeenOrphan;
        static std::map<uint256, CTransaction> mapOrphanTransactions;
        static std::map<uint256, std::set<uint256> > mapOrphanTransactionsByPrev;
        static CMedianFilter<int> cPeerBlockCounts;                    // Amount of blocks that other nodes claim to have

        static bool ProcessMessage(CNode *pfrom, std::string strCommand, CDataStream &vRecv);

        static uint256 GetOrphanRoot(const CBlock *pblock);            // Work back to the first block in the orphan chain
        static bool ReserealizeBlockSignature(CBlock *pblock);
        static bool IsCanonicalBlockSignature(CBlock *pblock);
        static bool AlreadyHave(CTxDB &txdb, const CInv &inv);
        static void Inventory(const uint256 &hash);
        static bool AddOrphanTx(const CTransaction &tx);
        static void EraseOrphanTx(uint256 hash);
        static unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans);
    public:
        static int64_t nPingInterval;

        static bool ProcessMessages(CNode *pfrom);
        static bool SendMessages(CNode *pto);

        static uint256 WantedByOrphan(const CBlock *pblockOrphan);    // Work back to the first block in the orphan chain
        static void ResendWalletTransactions(bool fForceResend = false);
        static bool ProcessBlock(CNode *pfrom, CBlock *pblock);
        static int GetNumBlocksOfPeers();
    };
}

#endif // BITCOIN_BLOCK_PROCESS_H
