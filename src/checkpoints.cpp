// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/foreach.hpp>
#include <algorithm>
#include <checkpoints.h>
#include <block/block_process.h>
#include <block/block_check.h>
#include <txdb.h>
#include <main.h>
#include <uint256.h>
#include <util/strencodings.h>

uint256 Checkpoints::manage::hashSyncCheckpoint = 0;
uint256 Checkpoints::manage::hashInvalidCheckpoint = 0;
CCriticalSection Checkpoints::cs_hashSyncCheckpoint;
uint256 Checkpoints::hashPendingCheckpoint = 0;
CSyncCheckpoint Checkpoints::checkpointMessage;
CSyncCheckpoint Checkpoints::checkpointMessagePending;
enum Checkpoints::CPMode Checkpoints::CheckpointsMode = Checkpoints::STRICT;

//
// ppcoin: sync-checkpoint master key
//
const std::string CSyncCheckpoint::strMasterPubKey = "04fe7e627322f81286be111dd5280f32827911128d20d1f54c5078a9bcbb31e41d94e625b9623dca5e3879edb9268a2037954a61d78d539b3d2355f1160f1c87eb";
std::string CSyncCheckpoint::strMasterPrivKey = "";

//
// checkpoint and checkpoint last time
//
const MapCheckpoints Checkpoints::manage::mapCheckpoints = 
    {
        { 0, block_params::hashGenesisBlock },
        { 1275, uint256("0x000000dd7de58fad01cfa1799b5809df4c1d9c164fc49da39eb2954531e1a36c") },    // 1533654441
        { 4930, uint256("0x000000153d5cf5fed61add322826c8ec6f32ffe5f99a714fcbf5ac53aee09b14") },    // 1534233069
        { 6624, uint256("0x5130b59e93325dd0a2332f99edb763cdb4189a4e6b0cc481023d1a21fe2327c5") },    // 1534481948
        { 18370, uint256("0x00000000f02a6a28449fbec9b50f7eb9e1ccd283ee7130e3ef159111aee803e9") },   // 1536369343
        { 26720, uint256("0x00000001edb4be82456835ed10942e0c49e2820021b01753872787738f556562") },   // 1537575003
        { 46092, uint256("0x000000003f7e00cee468b4f8ba08cdf804480b8f31315295fa1db223d4183718") },   // 1540469131
        { 60880, uint256("0x0000000032ecb49115ca08061cdc29ca7bc9036549d81ecb8f47fd6630cd584e") },   // 1543067199
        { 71270, uint256("0x000000001ff29e42c75e57fde60b0fd624c2522bd782a792016fa89f4f0a40c7") },   // 1544927452
        { 155369, uint256("0x000000065f542624a28575f960ba5d049f8a9be17996767c0911b20cf508177e") },  // 1560485640
        { 239007, uint256("0x0000000000ea3dad03ca3273aa758085933d6e01ea7fc0a560b81c8c137e21c3") },  // 1574467654
        { 351634, uint256("0x00000000000084b537f65746dbd28a0abc87adadad97231c7b8bb054027a31f6") },  // 1594278898
        { 434550, uint256("0x0000000000060688d53e999a30ad6165fe2d18262820b597aab2f68eaea91359") },  // 1609580025
        { 565694, uint256("0x06604fd50f43cd8b77ada61c5a761a7e0d1ac0c0b2989a751e3089bb6fcc3748") },  // 1634996637
        { 627453, uint256("0x27e250658705ddb55129e94f615b36f344f0de1648f1ec286b5562d85befe96a") },  // 1647145568
        { 681173, uint256("0x4b2d44382fb57a2e94c2134840edeeed007b462511fc6e4f5e80aa79507cb895") }   // 1658537348
    };

const MapCheckpoints Checkpoints::manage::mapCheckpointsTestnet = 
    {
        { 0, block_params::hashGenesisBlockTestNet },
        { 5330, uint256("0x000011410a666bec2c474fe25c847ea903279f96d47422ebe4dda1fd44450406") },    // 1533660799
        { 1488851, uint256("0x000019df8993b5c0dd756a25be579f76c08b3f10eeaa2b97b667f0bd1de80c7a") }  // 1619607581
        //{ 15330, uint256("0x000011410a666bec2c474fe25c847ea903279f96d47422ebe4dda1fd44450406") }  // [OK] NG test 1533660799
    };

const LastCheckpointTime Checkpoints::manage::CheckpointLastTime = 1658537348;
const LastCheckpointTime Checkpoints::manage::CheckpointLastTimeTestnet = 1619607581;

//
// Banned
//
const ListBannedBlocks Checkpoints::manage::listBanned;
    // { uint256("0x ... ") };

bool Checkpoints::manage::CheckHardened(int nHeight, const uint256 &hash) {
    const MapCheckpoints &checkpoints = (args_bool::fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

    MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
    if (i == checkpoints.end()) {
        return true;
    }

    return hash == i->second;
}

bool Checkpoints::manage::CheckBanned(const uint256 &nHash) {
    if (args_bool::fTestNet) { // Testnet has no banned blocks
        return true;
    }

    ListBannedBlocks::const_iterator it = std::find(Checkpoints::manage::listBanned.begin(), Checkpoints::manage::listBanned.end(), nHash);
    return it == listBanned.end();
}

int Checkpoints::manage::GetTotalBlocksEstimate() {
    const MapCheckpoints &checkpoints = (args_bool::fTestNet ? mapCheckpointsTestnet : mapCheckpoints);
    return checkpoints.rbegin()->first;
}

unsigned int Checkpoints::manage::GetLastCheckpointTime() {
    // const MapCheckpoints &checkpoints = (args_bool::fTestNet ? mapCheckpointsTestnet : mapCheckpoints);
    // return checkpoints.rbegin()->second.second;
    return (args_bool::fTestNet ? CheckpointLastTimeTestnet : CheckpointLastTime);
}

CBlockIndex *Checkpoints::manage::GetLastCheckpoint(const std::map<uint256, CBlockIndex *> &mapBlockIndex) {
    const MapCheckpoints &checkpoints = (args_bool::fTestNet ? mapCheckpointsTestnet : mapCheckpoints);
    BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type &i, checkpoints)
    {
        const uint256 &hash = i.second;
        auto t = mapBlockIndex.find(hash);
        if (t != mapBlockIndex.end()) {
            return t->second;
        }
    }
    return nullptr;
}

//! Guess how far we are in the verification process at the given block index
/*
template <typename T>
double Checkpoints::GuessVerificationProgress(CBlockIndex *pindex, bool fSigchecks)
{
    if (pindex == nullptr)
        return 0.0;

    int64_t nNow = ::time(nullptr);

    double fSigcheckVerificationFactor = fSigchecks ? SIGCHECK_VERIFICATION_FACTOR : 1.0;
    double fWorkBefore = 0.0; // Amount of work done before pindex
    double fWorkAfter = 0.0;  // Amount of work left after pindex (estimated)
    // Work is defined as: 1.0 per transaction before the last checkpoint, and
    // fSigcheckVerificationFactor per transaction after.

    const CCheckpointData& data = Params().Checkpoints();

    if (pindex->nChainTx <= data.nTransactionsLastCheckpoint) {
        double nCheapBefore = pindex->nChainTx;
        double nCheapAfter = data.nTransactionsLastCheckpoint - pindex->nChainTx;
        double nExpensiveAfter = (nNow - data.nTimeLastCheckpoint) / 86400.0 * data.fTransactionsPerDay;
        fWorkBefore = nCheapBefore;
        fWorkAfter = nCheapAfter + nExpensiveAfter * fSigcheckVerificationFactor;
    } else {
        double nCheapBefore = data.nTransactionsLastCheckpoint;
        double nExpensiveBefore = pindex->nChainTx - data.nTransactionsLastCheckpoint;
        double nExpensiveAfter = (nNow - pindex->GetBlockTime()) / 86400.0 * data.fTransactionsPerDay;
        fWorkBefore = nCheapBefore + nExpensiveBefore * fSigcheckVerificationFactor;
        fWorkAfter = nExpensiveAfter * fSigcheckVerificationFactor;
    }

    return fWorkBefore / (fWorkBefore + fWorkAfter);
}
*/

// ppcoin: get last synchronized checkpoint
CBlockIndex *Checkpoints::manage::GetLastSyncCheckpoint() {
    LOCK(Checkpoints::cs_hashSyncCheckpoint);
    if (! block_info::mapBlockIndex.count(Checkpoints::manage::hashSyncCheckpoint)) {
        bool ret = logging::error("Checkpoints::manage::GetSyncCheckpoint: block index missing for current sync-checkpoint %s", Checkpoints::manage::hashSyncCheckpoint.ToString().c_str());
        (void)ret;
    } else {
        return block_info::mapBlockIndex[Checkpoints::manage::hashSyncCheckpoint];
    }
    return nullptr;
}

// ppcoin: only descendant of current sync-checkpoint is allowed
bool Checkpoints::manage::ValidateSyncCheckpoint(uint256 hashCheckpoint) {
    if (! block_info::mapBlockIndex.count(Checkpoints::manage::hashSyncCheckpoint)) {
        return logging::error("Checkpoints::manage::ValidateSyncCheckpoint: block index missing for current sync-checkpoint %s", Checkpoints::manage::hashSyncCheckpoint.ToString().c_str());
    }
    if (! block_info::mapBlockIndex.count(hashCheckpoint)) {
        return logging::error("Checkpoints::manage::ValidateSyncCheckpoint: block index missing for received sync-checkpoint %s", hashCheckpoint.ToString().c_str());
    }

    CBlockIndex *pindexSyncCheckpoint = block_info::mapBlockIndex[Checkpoints::manage::hashSyncCheckpoint];
    CBlockIndex *pindexCheckpointRecv = block_info::mapBlockIndex[hashCheckpoint];

    if (pindexCheckpointRecv->get_nHeight() <= pindexSyncCheckpoint->get_nHeight()) {
        // Received an older checkpoint, trace back from current checkpoint
        // to the same height of the received checkpoint to verify
        // that current checkpoint should be a descendant block
        CBlockIndex *pindex = pindexSyncCheckpoint;
        while (pindex->get_nHeight() > pindexCheckpointRecv->get_nHeight()) {
            if ((pindex = pindex->set_pprev()) == nullptr) {
                return logging::error("Checkpoints::manage::ValidateSyncCheckpoint: pprev null - block index structure failure");
            }
        }
        if (pindex->GetBlockHash() != hashCheckpoint) {
            Checkpoints::manage::hashInvalidCheckpoint = hashCheckpoint;
            return logging::error("Checkpoints::manage::ValidateSyncCheckpoint: new sync-checkpoint %s is conflicting with current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), Checkpoints::manage::hashSyncCheckpoint.ToString().c_str());
        }
        return false; // ignore older checkpoint
    }

    // Received checkpoint should be a descendant block of the current
    // checkpoint. Trace back to the same height of current checkpoint to verify.
    CBlockIndex *pindex = pindexCheckpointRecv;
    while (pindex->get_nHeight() > pindexSyncCheckpoint->get_nHeight()) {
        if ((pindex = pindex->set_pprev()) == nullptr) {
            return logging::error("Checkpoints::manage::ValidateSyncCheckpoint: pprev2 null - block index structure failure");
        }
    }
    if (pindex->GetBlockHash() != Checkpoints::manage::hashSyncCheckpoint) {
        Checkpoints::manage::hashInvalidCheckpoint = hashCheckpoint;
        return logging::error("Checkpoints::manage::ValidateSyncCheckpoint: new sync-checkpoint %s is not a descendant of current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());
    }
    return true;
}

bool Checkpoints::manage::WriteSyncCheckpoint(const uint256 &hashCheckpoint) {
    CTxDB txdb;
    txdb.TxnBegin();
    if (! txdb.WriteSyncCheckpoint(hashCheckpoint)) {
        txdb.TxnAbort();
        return logging::error("Checkpoints::manage::WriteSyncCheckpoint(): failed to write to db sync checkpoint %s", hashCheckpoint.ToString().c_str());
    }
    if (! txdb.TxnCommit()) {
        return logging::error("Checkpoints::manage::WriteSyncCheckpoint(): failed to commit to db sync checkpoint %s", hashCheckpoint.ToString().c_str());
    }

    Checkpoints::manage::hashSyncCheckpoint = hashCheckpoint;
    return true;
}

bool Checkpoints::manage::AcceptPendingSyncCheckpoint() {
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
                return logging::error("Checkpoints::manage::AcceptPendingSyncCheckpoint: ReadFromDisk failed for sync checkpoint %s", Checkpoints::hashPendingCheckpoint.ToString().c_str());
            }
            if (! block.SetBestChain(txdb, pindexCheckpoint)) {
                Checkpoints::manage::hashInvalidCheckpoint = Checkpoints::hashPendingCheckpoint;
                return logging::error("Checkpoints::manage::AcceptPendingSyncCheckpoint: SetBestChain failed for sync checkpoint %s", Checkpoints::hashPendingCheckpoint.ToString().c_str());
            }
        }


        if (! Checkpoints::manage::WriteSyncCheckpoint(Checkpoints::hashPendingCheckpoint)) {
            return logging::error("Checkpoints::manage::AcceptPendingSyncCheckpoint(): failed to write sync checkpoint %s", Checkpoints::hashPendingCheckpoint.ToString().c_str());
        }

        Checkpoints::hashPendingCheckpoint = 0;
        Checkpoints::checkpointMessage = Checkpoints::checkpointMessagePending;
        Checkpoints::checkpointMessagePending.SetNull();
        logging::LogPrintf("Checkpoints::manage::AcceptPendingSyncCheckpoint : sync-checkpoint at %s\n", Checkpoints::manage::hashSyncCheckpoint.ToString().c_str());

        // relay the checkpoint
        if (! Checkpoints::checkpointMessage.IsNull()) {
            for (std::vector<CNode *>::iterator it = net_node::vNodes.begin(); it != net_node::vNodes.end(); ++it)
                Checkpoints::checkpointMessage.RelayTo(*it);
        }
        return true;
    }
    return false;
}

// Automatically select a suitable sync-checkpoint
uint256 Checkpoints::manage::AutoSelectSyncCheckpoint() {
    const CBlockIndex *pindex = block_info::pindexBest;

    // Search backward for a block within max span and maturity window
    while (pindex->get_pprev() && (pindex->GetBlockTime() + CHECKPOINT_MAX_SPAN > block_info::pindexBest->GetBlockTime() || pindex->get_nHeight() + 8 > block_info::pindexBest->get_nHeight()))
        pindex = pindex->get_pprev();

    return pindex->GetBlockHash();
}

// Check against synchronized checkpoint
bool Checkpoints::manage::CheckSync(const uint256 &hashBlock, const CBlockIndex *pindexPrev) {
    if (args_bool::fTestNet) {
        return true; // Testnet has no checkpoints
    }

    int nHeight = pindexPrev->get_nHeight() + 1;

    LOCK(Checkpoints::cs_hashSyncCheckpoint);

    // sync-checkpoint should always be accepted block
    // logging::LogPrintf("Checkpoints::manage::CheckSync: pindexSync - block Checkpoints::manage::hashSyncCheckpoint_%s\n", Checkpoints::manage::hashSyncCheckpoint.ToString().c_str());
    // logging::LogPrintf("Checkpoints::manage::CheckSync: pindexSync - block block_info::mapBlockIndex.count_%d\n", block_info::mapBlockIndex.count(Checkpoints::manage::hashSyncCheckpoint));
    assert(block_info::mapBlockIndex.count(Checkpoints::manage::hashSyncCheckpoint));
    const CBlockIndex *pindexSync = block_info::mapBlockIndex[Checkpoints::manage::hashSyncCheckpoint];

    if (nHeight > pindexSync->get_nHeight()) {
        // trace back to same height as sync-checkpoint
        const CBlockIndex *pindex = pindexPrev;
        while (pindex->get_nHeight() > pindexSync->get_nHeight()) {
            if ((pindex = pindex->get_pprev()) == nullptr) {
                return logging::error("Checkpoints::manage::CheckSync: pprev null - block index structure failure");
            }
        }
        if (pindex->get_nHeight() < pindexSync->get_nHeight() || pindex->GetBlockHash() != Checkpoints::manage::hashSyncCheckpoint) {
            return false; // only descendant of sync-checkpoint can pass check
        }
    }
    if (nHeight == pindexSync->get_nHeight() && hashBlock != Checkpoints::manage::hashSyncCheckpoint) {
        return false; // same height with sync-checkpoint
    }
    if (nHeight < pindexSync->get_nHeight() && !block_info::mapBlockIndex.count(hashBlock)) {
        return false; // lower height than sync-checkpoint
    }
    return true;
}

bool Checkpoints::manage::WantedByPendingSyncCheckpoint(uint256 hashBlock) {
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

// ppcoin: reset synchronized checkpoint to last hardened checkpoint
bool Checkpoints::manage::ResetSyncCheckpoint() {
    LOCK(Checkpoints::cs_hashSyncCheckpoint);

    const uint256 &hash = Checkpoints::manage::mapCheckpoints.rbegin()->second;
    if (block_info::mapBlockIndex.count(hash) && !block_info::mapBlockIndex[hash]->IsInMainChain()) {
        //
        // checkpoint block accepted but not yet in main chain
        //
        logging::LogPrintf("Checkpoints::manage::ResetSyncCheckpoint: SetBestChain to hardened checkpoint %s\n", hash.ToString().c_str());
        CTxDB txdb;
        CBlock block;
        if (! block.ReadFromDisk(block_info::mapBlockIndex[hash])) {
            return logging::error("Checkpoints::manage::ResetSyncCheckpoint: ReadFromDisk failed for hardened checkpoint %s", hash.ToString().c_str());
        }
        if (! block.SetBestChain(txdb, block_info::mapBlockIndex[hash])) {
            return logging::error("Checkpoints::manage::ResetSyncCheckpoint: SetBestChain failed for hardened checkpoint %s", hash.ToString().c_str());
        }
    } else if (! block_info::mapBlockIndex.count(hash)) {
        //
        // checkpoint block not yet accepted
        //
        Checkpoints::hashPendingCheckpoint = hash;
        Checkpoints::checkpointMessagePending.SetNull();
        logging::LogPrintf("Checkpoints::manage::ResetSyncCheckpoint: pending for sync-checkpoint %s\n", Checkpoints::hashPendingCheckpoint.ToString().c_str());
    }

    BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type &i, Checkpoints::manage::mapCheckpoints)
    {
        const uint256 &hash = i.second;
        if (block_info::mapBlockIndex.count(hash) && block_info::mapBlockIndex[hash]->IsInMainChain()) {
            if (! Checkpoints::manage::WriteSyncCheckpoint(hash)) {
                return logging::error("Checkpoints::manage::ResetSyncCheckpoint: failed to write sync checkpoint %s", hash.ToString().c_str());
            }

            logging::LogPrintf("Checkpoints::manage::ResetSyncCheckpoint: sync-checkpoint reset to %s\n", Checkpoints::manage::hashSyncCheckpoint.ToString().c_str());
            return true;
        }
    }

    return false;
}

void Checkpoints::manage::AskForPendingSyncCheckpoint(CNode *pfrom) {
    LOCK(Checkpoints::cs_hashSyncCheckpoint);
    if (pfrom && Checkpoints::hashPendingCheckpoint != 0 && (!block_info::mapBlockIndex.count(hashPendingCheckpoint)) && (!block_process::mapOrphanBlocks.count(Checkpoints::hashPendingCheckpoint))) {
        pfrom->AskFor(CInv(_CINV_MSG_TYPE::MSG_BLOCK, Checkpoints::hashPendingCheckpoint));
    }
}

bool Checkpoints::manage::SetCheckpointPrivKey(std::string strPrivKey) {
    // Test signing a sync-checkpoint with genesis block
    CSyncCheckpoint checkpoint( (!args_bool::fTestNet) ? block_params::hashGenesisBlock : block_params::hashGenesisBlockTestNet );

    CDataStream sMsg(SER_NETWORK, version::PROTOCOL_VERSION);
    sMsg << (CUnsignedSyncCheckpoint)checkpoint;
    checkpoint.Set_vchMsg(sMsg.begin(), sMsg.end());

    checkpoints_vector vchPrivKey = strenc::ParseHex(strPrivKey);

    CKey key;
    key.SetPrivKey(CPrivKey(vchPrivKey.begin(), vchPrivKey.end())); // if key is not correct openssl may crash
    if (! key.Sign(hash_basis::Hash(checkpoint.Get_vchMsg_begin(), checkpoint.Get_vchMsg_end()), checkpoint.Set_vchSig())) {
        return false;
    }

    // Test signing successful, proceed
    CSyncCheckpoint::Set_strMasterPrivKey(strPrivKey);
    return true;
}

bool Checkpoints::manage::SendSyncCheckpoint(uint256 hashCheckpoint) {
    CSyncCheckpoint checkpoint(hashCheckpoint);

    CDataStream sMsg(SER_NETWORK, version::PROTOCOL_VERSION);
    sMsg << (CUnsignedSyncCheckpoint)checkpoint;
    checkpoint.Set_vchMsg(sMsg.begin(), sMsg.end());

    if (CSyncCheckpoint::Get_strMasterPrivKey().empty()) {
        return logging::error("Checkpoints::manage::SendSyncCheckpoint: Checkpoint master key unavailable.");
    }
    checkpoints_vector vchPrivKey = strenc::ParseHex(CSyncCheckpoint::Get_strMasterPrivKey());

    CKey key;
    key.SetPrivKey(CPrivKey(vchPrivKey.begin(), vchPrivKey.end())); // if key is not correct openssl may crash
    if (! key.Sign(hash_basis::Hash(checkpoint.Get_vchMsg_begin(), checkpoint.Get_vchMsg_end()), checkpoint.Set_vchSig())) {
        return logging::error("Checkpoints::manage::SendSyncCheckpoint: Unable to sign checkpoint, check private key?");
    }

    if(! checkpoint.ProcessSyncCheckpoint(nullptr)) {
        logging::LogPrintf("WARNING: Checkpoints::manage::SendSyncCheckpoint: Failed to process checkpoint.\n");
        return false;
    }

    // Relay checkpoint
    {
        LOCK(net_node::cs_vNodes);
        for (std::vector<CNode*>::iterator it = net_node::vNodes.begin(); it != net_node::vNodes.end(); ++it)
            checkpoint.RelayTo(*it);
    }
    return true;
}

bool Checkpoints::manage::AutoSendSyncCheckpoint() {
    return Checkpoints::manage::SendSyncCheckpoint(Checkpoints::manage::AutoSelectSyncCheckpoint());
}

// Is the sync-checkpoint outside maturity window?
bool Checkpoints::manage::IsMatureSyncCheckpoint() {
    LOCK(Checkpoints::cs_hashSyncCheckpoint);

    // sync-checkpoint should always be accepted block
    assert(block_info::mapBlockIndex.count(Checkpoints::manage::hashSyncCheckpoint));
    const CBlockIndex *pindexSync = block_info::mapBlockIndex[hashSyncCheckpoint];
    return (block_info::nBestHeight >= pindexSync->get_nHeight() + block_transaction::nCoinbaseMaturity || pindexSync->GetBlockTime() + block_check::nStakeMinAge < bitsystem::GetAdjustedTime());
}

// ppcoin: verify signature of sync-checkpoint message
bool CSyncCheckpoint::CheckSignature() {
    CPubKey key(strenc::ParseHex(CSyncCheckpoint::strMasterPubKey));
    if (! key.Verify(hash_basis::Hash(vchMsg.begin(), vchMsg.end()), vchSig)) {
        return logging::error("CSyncCheckpoint::CheckSignature() : verify signature failed");
    }

    // Now unserialize the data
    CDataStream sMsg(vchMsg, SER_NETWORK, version::PROTOCOL_VERSION);
    sMsg >> *(CUnsignedSyncCheckpoint*)this;
    return true;
}

// process synchronized checkpoint
bool CSyncCheckpoint::ProcessSyncCheckpoint(CNode *pfrom) {
    if (! CheckSignature()) {
        return false;
    }

    LOCK(Checkpoints::cs_hashSyncCheckpoint);
    if (! block_info::mapBlockIndex.count(hashCheckpoint)) {
        // We haven't received the checkpoint chain, keep the checkpoint as pending
        Checkpoints::hashPendingCheckpoint = hashCheckpoint;
        Checkpoints::checkpointMessagePending = *this;
        logging::LogPrintf("CSyncCheckpoint::ProcessSyncCheckpoint: pending for sync-checkpoint %s\n", hashCheckpoint.ToString().c_str());

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
            return logging::error("CSyncCheckpoint::ProcessSyncCheckpoint: ReadFromDisk failed for sync checkpoint %s", hashCheckpoint.ToString().c_str());
        if (! block.SetBestChain(txdb, pindexCheckpoint)) {
            Checkpoints::manage::setHashInvalidCheckpoint(hashCheckpoint);
            return logging::error("CSyncCheckpoint::ProcessSyncCheckpoint: SetBestChain failed for sync checkpoint %s", hashCheckpoint.ToString().c_str());
        }
    }

    if (! Checkpoints::manage::WriteSyncCheckpoint(hashCheckpoint)) {
        return logging::error("CSyncCheckpoint::ProcessSyncCheckpoint(): failed to write sync checkpoint %s", hashCheckpoint.ToString().c_str());
    }

    Checkpoints::checkpointMessage = *this;
    Checkpoints::hashPendingCheckpoint = 0;
    Checkpoints::checkpointMessagePending.SetNull();
    logging::LogPrintf("CSyncCheckpoint::ProcessSyncCheckpoint: sync-checkpoint at %s\n", hashCheckpoint.ToString().c_str());
    return true;
}
