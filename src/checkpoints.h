// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef BITCOIN_CHECKPOINT_H
#define  BITCOIN_CHECKPOINT_H

#include <map>
#include "util.h"
#include "net.h"

#ifdef WIN32
#undef STRICT
#undef PERMISSIVE
#undef ADVISORY
#endif

class uint256;
class CBlockIndex;

//
// ppcoin: synchronized checkpoint
//
class CUnsignedSyncCheckpoint
{
//private:
    // CUnsignedSyncCheckpoint(const CUnsignedSyncCheckpoint &); // {}
    // CUnsignedSyncCheckpoint &operator=(const CUnsignedSyncCheckpoint &); // {}

public:
    int nVersion;
    uint256 hashCheckpoint;      // checkpoint block

    CUnsignedSyncCheckpoint() {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(this->hashCheckpoint);
    )

    void SetNull() {
        nVersion = 1;
        hashCheckpoint = 0;
    }

    std::string ToString() const {
        return strprintf(
                "CSyncCheckpoint(\n"
                "    nVersion       = %d\n"
                "    hashCheckpoint = %s\n"
                ")\n",
                nVersion,
                hashCheckpoint.ToString().c_str());
    }
};

class CSyncCheckpoint : public CUnsignedSyncCheckpoint
{
private:
    CSyncCheckpoint(const CSyncCheckpoint &); // {}
    // CSyncCheckpoint &operator=(const CSyncCheckpoint &); // {}

public:
    static const std::string strMasterPubKey;
    static std::string strMasterPrivKey;

    std::vector<unsigned char> vchMsg;
    std::vector<unsigned char> vchSig;

    CSyncCheckpoint() {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->vchMsg);
        READWRITE(this->vchSig);
    )

    void SetNull() {
        // CUnsignedSyncCheckpoint::SetNull();
        vchMsg.clear();
        vchSig.clear();
    }

    bool IsNull() const {
        return (hashCheckpoint == 0);
    }

    uint256 GetHash() const {
        return hash_basis::SerializeHash(*this);
    }

    bool RelayTo(CNode *pnode) const {    // returns true if wasn't already sent
        if (pnode->hashCheckpointKnown != hashCheckpoint) {
            pnode->hashCheckpointKnown = hashCheckpoint;
            pnode->PushMessage("checkpoint", *this);
            return true;
        }
        return false;
    }

    bool CheckSignature();
    bool ProcessSyncCheckpoint(CNode *pfrom);
};

//
// Block-chain checkpoints are compiled-in sanity checks.
// They are updated every release or three.
//
typedef std::map<int, uint256> MapCheckpoints;
typedef std::list<uint256> ListBannedBlocks;
typedef unsigned int LastCheckpointTime;
namespace Checkpoints
{
    enum CPMode
    {
        STRICT = 0,        // Scrict checkpoints policy, perform conflicts verification and resolve conflicts
        ADVISORY = 1,      // Advisory checkpoints policy, perform conflicts verification but don't try to resolve them
        PERMISSIVE = 2     // Permissive checkpoints policy, don't perform any checking
    };

    extern CCriticalSection cs_hashSyncCheckpoint;
    extern uint256 hashPendingCheckpoint;// = 0;

    extern CSyncCheckpoint checkpointMessage;
    extern CSyncCheckpoint checkpointMessagePending;

    class manage : private no_instance
    {
    private:
        // max 1 hour before latest block
        static const int64_t CHECKPOINT_MAX_SPAN = util::nOneHour;

        static const MapCheckpoints mapCheckpoints;
        static const MapCheckpoints mapCheckpointsTestnet;
        static const ListBannedBlocks listBanned;
        static const LastCheckpointTime CheckpointLastTime;
        static const LastCheckpointTime CheckpointLastTimeTestnet;

        // ppcoin: synchronized checkpoint (centrally broadcasted)
        static uint256 hashSyncCheckpoint;
        static uint256 hashInvalidCheckpoint;

        static uint256 AutoSelectSyncCheckpoint();
        static bool SendSyncCheckpoint(uint256 hashCheckpoint);
    public:
        static bool CheckHardened(int nHeight, const uint256 &hash);    // Returns true if block passes checkpoint checks
        static bool CheckBanned(const uint256 &nHash);                  // Returns true if block passes banlist checks

        static int GetTotalBlocksEstimate();                            // Return conservative estimate of total number of blocks, 0 if unknown
        static unsigned int GetLastCheckpointTime();                    // Returns last checkpoint timestamp

        static CBlockIndex *GetLastSyncCheckpoint();
        static bool ValidateSyncCheckpoint(uint256 hashCheckpoint);
        static bool WriteSyncCheckpoint(const uint256 &hashCheckpoint);
        static bool AcceptPendingSyncCheckpoint();
        static bool CheckSync(const uint256 &hashBlock, const CBlockIndex *pindexPrev);
        static bool WantedByPendingSyncCheckpoint(uint256 hashBlock);
        static bool ResetSyncCheckpoint();
        static void AskForPendingSyncCheckpoint(CNode *pfrom);
        static bool SetCheckpointPrivKey(std::string strPrivKey);
        
        static CBlockIndex *GetLastCheckpoint(const std::map<uint256, CBlockIndex *> &mapBlockIndex);    // Returns last CBlockIndex* in mapBlockIndex that is a checkpoint
        static bool AutoSendSyncCheckpoint();
        static bool IsMatureSyncCheckpoint();

        static uint256 &getHashSyncCheckpoint() {
            return Checkpoints::manage::hashSyncCheckpoint;
        }
        static uint256 &getHashInvalidCheckpoint() {
            return Checkpoints::manage::hashInvalidCheckpoint;
        }
        //static void setHashSyncCheckpoint(const uint256 &sync) {
        //    Checkpoints::manage::hashSyncCheckpoint = sync;
        //}
        static void setHashInvalidCheckpoint(const uint256 &invalid) {
            Checkpoints::manage::hashInvalidCheckpoint = invalid;
        }
    };
}

#endif
//@
