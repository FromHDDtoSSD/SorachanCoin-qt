// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>
#include <algorithm>

#include "checkpoints.h"

#include "txdb.h"
#include "main.h"
#include "uint256.h"

uint256 Checkpoints::manage::hashSyncCheckpoint = 0;
uint256 Checkpoints::manage::hashInvalidCheckpoint = 0;
CCriticalSection Checkpoints::cs_hashSyncCheckpoint;
uint256 Checkpoints::hashPendingCheckpoint = 0;
CSyncCheckpoint Checkpoints::checkpointMessage;
CSyncCheckpoint Checkpoints::checkpointMessagePending;

//
// ppcoin: sync-checkpoint master key
//
const std::string CSyncCheckpoint::strMasterPubKey = "04fe7e627322f81286be111dd5280f32827911128d20d1f54c5078a9bcbb31e41d94e625b9623dca5e3879edb9268a2037954a61d78d539b3d2355f1160f1c87eb";
std::string CSyncCheckpoint::strMasterPrivKey = "";

//
// checkpoint and checkpoint last time
//
const MapCheckpoints Checkpoints::manage::mapCheckpoints = 
        boost::assign::map_list_of
        ( 0, block_param::hashGenesisBlock )
        ( 1275, uint256("0x000000dd7de58fad01cfa1799b5809df4c1d9c164fc49da39eb2954531e1a36c") )    // 1533654441
        ( 4930, uint256("0x000000153d5cf5fed61add322826c8ec6f32ffe5f99a714fcbf5ac53aee09b14") )    // 1534233069
        ( 6624, uint256("0x5130b59e93325dd0a2332f99edb763cdb4189a4e6b0cc481023d1a21fe2327c5") )    // 1534481948
        ( 18370, uint256("0x00000000f02a6a28449fbec9b50f7eb9e1ccd283ee7130e3ef159111aee803e9") )   // 1536369343
        ( 26720, uint256("0x00000001edb4be82456835ed10942e0c49e2820021b01753872787738f556562") )   // 1537575003
        ( 46092, uint256("0x000000003f7e00cee468b4f8ba08cdf804480b8f31315295fa1db223d4183718") )   // 1540469131
        ( 60880, uint256("0x0000000032ecb49115ca08061cdc29ca7bc9036549d81ecb8f47fd6630cd584e") )   // 1543067199
        ( 71270, uint256("0x000000001ff29e42c75e57fde60b0fd624c2522bd782a792016fa89f4f0a40c7") )   // 1544927452
        ;

const MapCheckpoints Checkpoints::manage::mapCheckpointsTestnet = 
        boost::assign::map_list_of
        ( 0, block_param::hashGenesisBlockTestNet )
        ( 5330, uint256("0x000011410a666bec2c474fe25c847ea903279f96d47422ebe4dda1fd44450406") )    // 1533660799
        ;

const LastCheckpointTime Checkpoints::manage::CheckpointLastTime = 1544927452;
const LastCheckpointTime Checkpoints::manage::CheckpointLastTimeTestnet = 1533660799;

//
// Banned
//
const ListBannedBlocks Checkpoints::manage::listBanned;
    // boost::assign::list_of
    // ( uint256("0x ... ") );

bool Checkpoints::manage::CheckHardened(int nHeight, const uint256 &hash)
{
    const MapCheckpoints &checkpoints = (args_bool::fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

    MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
    if (i == checkpoints.end()) {
        return true;
    }

    return hash == i->second;
}

bool Checkpoints::manage::CheckBanned(const uint256 &nHash)
{
    if (args_bool::fTestNet) {        // Testnet has no banned blocks
        return true;
    }

    ListBannedBlocks::const_iterator it = std::find(Checkpoints::manage::listBanned.begin(), Checkpoints::manage::listBanned.end(), nHash);
    return it == listBanned.end();
}

int Checkpoints::manage::GetTotalBlocksEstimate()
{
    const MapCheckpoints &checkpoints = (args_bool::fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

    return checkpoints.rbegin()->first;
}

unsigned int Checkpoints::manage::GetLastCheckpointTime()
{
    // const MapCheckpoints &checkpoints = (args_bool::fTestNet ? mapCheckpointsTestnet : mapCheckpoints);
    // return checkpoints.rbegin()->second.second;

    return (args_bool::fTestNet ? CheckpointLastTimeTestnet : CheckpointLastTime);
}

CBlockIndex *Checkpoints::manage::GetLastCheckpoint(const std::map<uint256, CBlockIndex *> &mapBlockIndex)
{
    const MapCheckpoints &checkpoints = (args_bool::fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

    BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type &i, checkpoints)
    {
        const uint256 &hash = i.second;
        std::map<uint256, CBlockIndex *>::const_iterator t = mapBlockIndex.find(hash);
        if (t != mapBlockIndex.end()) {
            return t->second;
        }
    }
    return NULL;
}

// ppcoin: get last synchronized checkpoint
CBlockIndex *Checkpoints::manage::GetLastSyncCheckpoint()
{
    LOCK(Checkpoints::cs_hashSyncCheckpoint);
    if (! block_info::mapBlockIndex.count(Checkpoints::manage::hashSyncCheckpoint)) {
        print::error("Checkpoints::manage::GetSyncCheckpoint: block index missing for current sync-checkpoint %s", Checkpoints::manage::hashSyncCheckpoint.ToString().c_str());
    } else {
        return block_info::mapBlockIndex[Checkpoints::manage::hashSyncCheckpoint];
    }
    return NULL;
}

// ppcoin: only descendant of current sync-checkpoint is allowed
bool Checkpoints::manage::ValidateSyncCheckpoint(uint256 hashCheckpoint)
{
    if (! block_info::mapBlockIndex.count(Checkpoints::manage::hashSyncCheckpoint)) {
        return print::error("Checkpoints::manage::ValidateSyncCheckpoint: block index missing for current sync-checkpoint %s", Checkpoints::manage::hashSyncCheckpoint.ToString().c_str());
    }
    if (! block_info::mapBlockIndex.count(hashCheckpoint)) {
        return print::error("Checkpoints::manage::ValidateSyncCheckpoint: block index missing for received sync-checkpoint %s", hashCheckpoint.ToString().c_str());
    }

    CBlockIndex *pindexSyncCheckpoint = block_info::mapBlockIndex[Checkpoints::manage::hashSyncCheckpoint];
    CBlockIndex *pindexCheckpointRecv = block_info::mapBlockIndex[hashCheckpoint];

    if (pindexCheckpointRecv->nHeight <= pindexSyncCheckpoint->nHeight) {
        // Received an older checkpoint, trace back from current checkpoint
        // to the same height of the received checkpoint to verify
        // that current checkpoint should be a descendant block
        CBlockIndex *pindex = pindexSyncCheckpoint;
        while (pindex->nHeight > pindexCheckpointRecv->nHeight)
        {
            if ((pindex = pindex->pprev) == NULL) {
                return print::error("Checkpoints::manage::ValidateSyncCheckpoint: pprev null - block index structure failure");
            }
        }
        if (pindex->GetBlockHash() != hashCheckpoint) {
            Checkpoints::manage::hashInvalidCheckpoint = hashCheckpoint;
            return print::error("Checkpoints::manage::ValidateSyncCheckpoint: new sync-checkpoint %s is conflicting with current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), Checkpoints::manage::hashSyncCheckpoint.ToString().c_str());
        }
        return false; // ignore older checkpoint
    }

    // Received checkpoint should be a descendant block of the current
    // checkpoint. Trace back to the same height of current checkpoint to verify.
    CBlockIndex *pindex = pindexCheckpointRecv;
    while (pindex->nHeight > pindexSyncCheckpoint->nHeight)
    {
        if ((pindex = pindex->pprev) == NULL) {
            return print::error("Checkpoints::manage::ValidateSyncCheckpoint: pprev2 null - block index structure failure");
        }
    }
    if (pindex->GetBlockHash() != Checkpoints::manage::hashSyncCheckpoint) {
        Checkpoints::manage::hashInvalidCheckpoint = hashCheckpoint;
        return print::error("Checkpoints::manage::ValidateSyncCheckpoint: new sync-checkpoint %s is not a descendant of current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());
    }
    return true;
}

bool Checkpoints::manage::WriteSyncCheckpoint(const uint256 &hashCheckpoint)
{
    CTxDB txdb;
    txdb.TxnBegin();
    if (! txdb.WriteSyncCheckpoint(hashCheckpoint)) {
        txdb.TxnAbort();
        return print::error("Checkpoints::manage::WriteSyncCheckpoint(): failed to write to db sync checkpoint %s", hashCheckpoint.ToString().c_str());
    }
    if (! txdb.TxnCommit()) {
        return print::error("Checkpoints::manage::WriteSyncCheckpoint(): failed to commit to db sync checkpoint %s", hashCheckpoint.ToString().c_str());
    }

#ifndef USE_LEVELDB
    txdb.Close();
#endif

    Checkpoints::manage::hashSyncCheckpoint = hashCheckpoint;
    return true;
}

bool Checkpoints::manage::AcceptPendingSyncCheckpoint()
{
    LOCK(Checkpoints::cs_hashSyncCheckpoint);
    if (Checkpoints::hashPendingCheckpoint != 0 && block_info::mapBlockIndex.count(Checkpoints::hashPendingCheckpoint)) {
        if (! Checkpoints::manage::ValidateSyncCheckpoint(Checkpoints::hashPendingCheckpoint)) {
            Checkpoints::hashPendingCheckpoint = 0;
            Checkpoints::checkpointMessagePending.SetNull();
            return false;
        }

        CTxDB txdb;
        CBlockIndex *pindexCheckpoint = block_info::mapBlockIndex[Checkpoints::hashPendingCheckpoint];
        if (! pindexCheckpoint->IsInMainChain()) {
            CBlock block;
            if (! block.ReadFromDisk(pindexCheckpoint)) {
                return print::error("Checkpoints::manage::AcceptPendingSyncCheckpoint: ReadFromDisk failed for sync checkpoint %s", Checkpoints::hashPendingCheckpoint.ToString().c_str());
            }
            if (! block.SetBestChain(txdb, pindexCheckpoint)) {
                Checkpoints::manage::hashInvalidCheckpoint = Checkpoints::hashPendingCheckpoint;
                return print::error("Checkpoints::manage::AcceptPendingSyncCheckpoint: SetBestChain failed for sync checkpoint %s", Checkpoints::hashPendingCheckpoint.ToString().c_str());
            }
        }

#ifndef USE_LEVELDB
        txdb.Close();
#endif
        if (! Checkpoints::manage::WriteSyncCheckpoint(Checkpoints::hashPendingCheckpoint)) {
            return print::error("Checkpoints::manage::AcceptPendingSyncCheckpoint(): failed to write sync checkpoint %s", Checkpoints::hashPendingCheckpoint.ToString().c_str());
        }

        Checkpoints::hashPendingCheckpoint = 0;
        Checkpoints::checkpointMessage = Checkpoints::checkpointMessagePending;
        Checkpoints::checkpointMessagePending.SetNull();
        printf("Checkpoints::manage::AcceptPendingSyncCheckpoint : sync-checkpoint at %s\n", Checkpoints::manage::hashSyncCheckpoint.ToString().c_str());

        // relay the checkpoint
        if (! Checkpoints::checkpointMessage.IsNull()) {
            for (std::vector<CNode *>::iterator it = net_node::vNodes.begin(); it != net_node::vNodes.end(); ++it)
            {
                Checkpoints::checkpointMessage.RelayTo(*it);
            }
        }
        return true;
    }
    return false;
}

// Automatically select a suitable sync-checkpoint
uint256 Checkpoints::manage::AutoSelectSyncCheckpoint()
{
    const CBlockIndex *pindex = block_info::pindexBest;

    // Search backward for a block within max span and maturity window
    while (pindex->pprev && (pindex->GetBlockTime() + CHECKPOINT_MAX_SPAN > block_info::pindexBest->GetBlockTime() || pindex->nHeight + 8 > block_info::pindexBest->nHeight))
    {
        pindex = pindex->pprev;
    }
    return pindex->GetBlockHash();
}

// Check against synchronized checkpoint
bool Checkpoints::manage::CheckSync(const uint256 &hashBlock, const CBlockIndex *pindexPrev)
{
    if (args_bool::fTestNet) {
        return true; // Testnet has no checkpoints
    }

    int nHeight = pindexPrev->nHeight + 1;

    LOCK(Checkpoints::cs_hashSyncCheckpoint);

    // sync-checkpoint should always be accepted block
    // printf("Checkpoints::manage::CheckSync: pindexSync - block Checkpoints::manage::hashSyncCheckpoint_%s\n", Checkpoints::manage::hashSyncCheckpoint.ToString().c_str());
    // printf("Checkpoints::manage::CheckSync: pindexSync - block block_info::mapBlockIndex.count_%d\n", block_info::mapBlockIndex.count(Checkpoints::manage::hashSyncCheckpoint));
    assert(block_info::mapBlockIndex.count(Checkpoints::manage::hashSyncCheckpoint));
    const CBlockIndex *pindexSync = block_info::mapBlockIndex[Checkpoints::manage::hashSyncCheckpoint];

    if (nHeight > pindexSync->nHeight) {
        // trace back to same height as sync-checkpoint
        const CBlockIndex *pindex = pindexPrev;
        while (pindex->nHeight > pindexSync->nHeight)
        {
            if ((pindex = pindex->pprev) == NULL) {
                return print::error("Checkpoints::manage::CheckSync: pprev null - block index structure failure");
            }
        }
        if (pindex->nHeight < pindexSync->nHeight || pindex->GetBlockHash() != Checkpoints::manage::hashSyncCheckpoint) {
            return false; // only descendant of sync-checkpoint can pass check
        }
    }
    if (nHeight == pindexSync->nHeight && hashBlock != Checkpoints::manage::hashSyncCheckpoint) {
        return false; // same height with sync-checkpoint
    }
    if (nHeight < pindexSync->nHeight && !block_info::mapBlockIndex.count(hashBlock)) {
        return false; // lower height than sync-checkpoint
    }
    return true;
}

bool Checkpoints::manage::WantedByPendingSyncCheckpoint(uint256 hashBlock)
{
    LOCK(Checkpoints::cs_hashSyncCheckpoint);
    if (Checkpoints::hashPendingCheckpoint == 0) {
        return false;
    }
    if (hashBlock == Checkpoints::hashPendingCheckpoint) {
        return true;
    }
    if (block_process::mapOrphanBlocks.count(Checkpoints::hashPendingCheckpoint) && hashBlock == block_process::manage::WantedByOrphan(block_process::mapOrphanBlocks[Checkpoints::hashPendingCheckpoint])) {
        return true;
    }
    return false;
}

//
// ppcoin: reset synchronized checkpoint to last hardened checkpoint
// 
bool Checkpoints::manage::ResetSyncCheckpoint()
{
    LOCK(Checkpoints::cs_hashSyncCheckpoint);

    const uint256 &hash = Checkpoints::manage::mapCheckpoints.rbegin()->second;
    if (block_info::mapBlockIndex.count(hash) && !block_info::mapBlockIndex[hash]->IsInMainChain()) {
        //
        // checkpoint block accepted but not yet in main chain
        //
        printf("Checkpoints::manage::ResetSyncCheckpoint: SetBestChain to hardened checkpoint %s\n", hash.ToString().c_str());
        CTxDB txdb;
        CBlock block;
        if (! block.ReadFromDisk(block_info::mapBlockIndex[hash])) {
            return print::error("Checkpoints::manage::ResetSyncCheckpoint: ReadFromDisk failed for hardened checkpoint %s", hash.ToString().c_str());
        }
        if (! block.SetBestChain(txdb, block_info::mapBlockIndex[hash])) {
            return print::error("Checkpoints::manage::ResetSyncCheckpoint: SetBestChain failed for hardened checkpoint %s", hash.ToString().c_str());
        }

#ifndef USE_LEVELDB
        txdb.Close();
#endif
    } else if (! block_info::mapBlockIndex.count(hash)) {
        //
        // checkpoint block not yet accepted
        //
        Checkpoints::hashPendingCheckpoint = hash;
        Checkpoints::checkpointMessagePending.SetNull();
        printf("Checkpoints::manage::ResetSyncCheckpoint: pending for sync-checkpoint %s\n", Checkpoints::hashPendingCheckpoint.ToString().c_str());
    }

    BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type &i, Checkpoints::manage::mapCheckpoints)
    {
        const uint256 &hash = i.second;
        if (block_info::mapBlockIndex.count(hash) && block_info::mapBlockIndex[hash]->IsInMainChain()) {
            if (! Checkpoints::manage::WriteSyncCheckpoint(hash)) {
                return print::error("Checkpoints::manage::ResetSyncCheckpoint: failed to write sync checkpoint %s", hash.ToString().c_str());
            }

            printf("Checkpoints::manage::ResetSyncCheckpoint: sync-checkpoint reset to %s\n", Checkpoints::manage::hashSyncCheckpoint.ToString().c_str());
            return true;
        }
    }

    return false;
}

void Checkpoints::manage::AskForPendingSyncCheckpoint(CNode *pfrom)
{
    LOCK(Checkpoints::cs_hashSyncCheckpoint);
    if (pfrom && Checkpoints::hashPendingCheckpoint != 0 && (!block_info::mapBlockIndex.count(hashPendingCheckpoint)) && (!block_process::mapOrphanBlocks.count(Checkpoints::hashPendingCheckpoint))) {
        pfrom->AskFor(CInv(_CINV_MSG_TYPE::MSG_BLOCK, Checkpoints::hashPendingCheckpoint));
    }
}

bool Checkpoints::manage::SetCheckpointPrivKey(std::string strPrivKey)
{
    // Test signing a sync-checkpoint with genesis block
    CSyncCheckpoint checkpoint;
    checkpoint.hashCheckpoint = (!args_bool::fTestNet) ? block_param::hashGenesisBlock : block_param::hashGenesisBlockTestNet;

    CDataStream sMsg(SER_NETWORK, version::PROTOCOL_VERSION);
    sMsg << (CUnsignedSyncCheckpoint)checkpoint;
    checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

    std::vector<unsigned char> vchPrivKey = hex::ParseHex(strPrivKey);

    CKey key;
    key.SetPrivKey(CPrivKey(vchPrivKey.begin(), vchPrivKey.end())); // if key is not correct openssl may crash
    if (! key.Sign(hash_basis::Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig)) {
        return false;
    }

    // Test signing successful, proceed
    CSyncCheckpoint::strMasterPrivKey = strPrivKey;
    return true;
}

bool Checkpoints::manage::SendSyncCheckpoint(uint256 hashCheckpoint)
{
    CSyncCheckpoint checkpoint;
    checkpoint.hashCheckpoint = hashCheckpoint;

    CDataStream sMsg(SER_NETWORK, version::PROTOCOL_VERSION);
    sMsg << (CUnsignedSyncCheckpoint)checkpoint;
    checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

    if (CSyncCheckpoint::strMasterPrivKey.empty()) {
        return print::error("Checkpoints::manage::SendSyncCheckpoint: Checkpoint master key unavailable.");
    }
    std::vector<unsigned char> vchPrivKey = hex::ParseHex(CSyncCheckpoint::strMasterPrivKey);

    CKey key;
    key.SetPrivKey(CPrivKey(vchPrivKey.begin(), vchPrivKey.end())); // if key is not correct openssl may crash
    if (! key.Sign(hash_basis::Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig)) {
        return print::error("Checkpoints::manage::SendSyncCheckpoint: Unable to sign checkpoint, check private key?");
    }

    if(! checkpoint.ProcessSyncCheckpoint(NULL)) {
        printf("WARNING: Checkpoints::manage::SendSyncCheckpoint: Failed to process checkpoint.\n");
        return false;
    }

    // Relay checkpoint
    {
        LOCK(net_node::cs_vNodes);
        for (std::vector<CNode*>::iterator it = net_node::vNodes.begin(); it != net_node::vNodes.end(); ++it)
        {
            checkpoint.RelayTo(*it);
        }
    }
    return true;
}

bool Checkpoints::manage::AutoSendSyncCheckpoint()
{
    return Checkpoints::manage::SendSyncCheckpoint(Checkpoints::manage::AutoSelectSyncCheckpoint());
}

// Is the sync-checkpoint outside maturity window?
bool Checkpoints::manage::IsMatureSyncCheckpoint()
{
    LOCK(Checkpoints::cs_hashSyncCheckpoint);

    // sync-checkpoint should always be accepted block
    assert(block_info::mapBlockIndex.count(Checkpoints::manage::hashSyncCheckpoint));
    const CBlockIndex *pindexSync = block_info::mapBlockIndex[hashSyncCheckpoint];
    return (block_info::nBestHeight >= pindexSync->nHeight + block_transaction::nCoinbaseMaturity || pindexSync->GetBlockTime() + block_check::nStakeMinAge < bitsystem::GetAdjustedTime());
}

// ppcoin: verify signature of sync-checkpoint message
bool CSyncCheckpoint::CheckSignature()
{
    CPubKey key(hex::ParseHex(CSyncCheckpoint::strMasterPubKey));
    if (! key.Verify(hash_basis::Hash(vchMsg.begin(), vchMsg.end()), vchSig)) {
        return print::error("CSyncCheckpoint::CheckSignature() : verify signature failed");
    }

    // Now unserialize the data
    CDataStream sMsg(vchMsg, SER_NETWORK, version::PROTOCOL_VERSION);
    sMsg >> *(CUnsignedSyncCheckpoint*)this;
    return true;
}

// process synchronized checkpoint
bool CSyncCheckpoint::ProcessSyncCheckpoint(CNode *pfrom)
{
    if (! CheckSignature()) {
        return false;
    }

    LOCK(Checkpoints::cs_hashSyncCheckpoint);
    if (! block_info::mapBlockIndex.count(hashCheckpoint))
    {
        // We haven't received the checkpoint chain, keep the checkpoint as pending
        Checkpoints::hashPendingCheckpoint = hashCheckpoint;
        Checkpoints::checkpointMessagePending = *this;
        printf("CSyncCheckpoint::ProcessSyncCheckpoint: pending for sync-checkpoint %s\n", hashCheckpoint.ToString().c_str());

        // Ask this guy to fill in what we're missing
        if (pfrom) {
            pfrom->PushGetBlocks(block_info::pindexBest, hashCheckpoint);

            // ask directly as well in case rejected earlier by duplicate
            // proof-of-stake because getblocks may not get it this time
            pfrom->AskFor(CInv(_CINV_MSG_TYPE::MSG_BLOCK, block_process::mapOrphanBlocks.count(hashCheckpoint)? block_process::manage::WantedByOrphan(block_process::mapOrphanBlocks[hashCheckpoint]) : hashCheckpoint));
        }
        return false;
    }

    if (! Checkpoints::manage::ValidateSyncCheckpoint(hashCheckpoint)) {
        return false;
    }

    CTxDB txdb;
    CBlockIndex *pindexCheckpoint = block_info::mapBlockIndex[hashCheckpoint];
    if (! pindexCheckpoint->IsInMainChain()) {
        // checkpoint chain received but not yet main chain
        CBlock block;
        if (! block.ReadFromDisk(pindexCheckpoint))
            return print::error("CSyncCheckpoint::ProcessSyncCheckpoint: ReadFromDisk failed for sync checkpoint %s", hashCheckpoint.ToString().c_str());
        if (! block.SetBestChain(txdb, pindexCheckpoint)) {
            Checkpoints::manage::setHashInvalidCheckpoint(hashCheckpoint);
            return print::error("CSyncCheckpoint::ProcessSyncCheckpoint: SetBestChain failed for sync checkpoint %s", hashCheckpoint.ToString().c_str());
        }
    }

#ifndef USE_LEVELDB
    txdb.Close();
#endif

    if (! Checkpoints::manage::WriteSyncCheckpoint(hashCheckpoint)) {
        return print::error("CSyncCheckpoint::ProcessSyncCheckpoint(): failed to write sync checkpoint %s", hashCheckpoint.ToString().c_str());
    }

    Checkpoints::checkpointMessage = *this;
    Checkpoints::hashPendingCheckpoint = 0;
    Checkpoints::checkpointMessagePending.SetNull();
    printf("CSyncCheckpoint::ProcessSyncCheckpoint: sync-checkpoint at %s\n", hashCheckpoint.ToString().c_str());
    return true;
}
