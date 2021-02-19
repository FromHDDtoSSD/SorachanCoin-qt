// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <block/block_process.h>
#include <miner/diff.h>
#include <init.h>
#include <kernel.h>
#include <checkpoints.h>
#include <alert.h>
#include <txdb.h>
#include <wallet.h>
#include <util/time.h>

std::multimap<uint256, CBlock *> block_process::manage::mapOrphanBlocksByPrev;
std::set<std::pair<COutPoint, unsigned int> > block_process::manage::setStakeSeenOrphan;
std::map<uint256, CTransaction> block_process::manage::mapOrphanTransactions;
std::map<uint256, std::set<uint256> > block_process::manage::mapOrphanTransactionsByPrev;
CMedianFilter<int> block_process::manage::cPeerBlockCounts(5, 0);
int64_t block_process::manage::nPingInterval = 30 * 60;
CCriticalSection block_process::cs_main;
std::map<uint256, CBlock *> block_process::mapOrphanBlocks;
std::map<uint256, uint256> block_process::mapProofOfStake;

// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
// unsigned char gpchMessageStart[4] = { 0xe4, 0xe8, 0xe9, 0xe5 };
bool block_process::manage::ProcessMessage(CNode *pfrom, std::string strCommand, CDataStream &vRecv)
{
    static std::map<CService, CPubKey> mapReuseKey;
    seed::RandAddSeedPerfmon();
    if (args_bool::fDebug)
        logging::LogPrintf("received: %s (%" PRIszu " bytes)\n", strCommand.c_str(), vRecv.size());
    if (map_arg::GetMapArgsCount("-dropmessagestest") && bitsystem::GetRand(strenc::atoi(map_arg::GetMapArgsString("-dropmessagestest"))) == 0) {
        logging::LogPrintf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

    if (strCommand == "version") {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0) {
            pfrom->Misbehaving(1);
            debugcs::instance() << "receive version message failure: nVersion=" << pfrom->nVersion << debugcs::endl();
            return false;
        }

        int64_t nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64_t nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion < version::MIN_PROTO_VERSION) {
            // Since February 20, 2012, the protocol is initiated at version 209,
            // and earlier versions are no longer supported
            logging::LogPrintf("partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return false;
        }
        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;

        if (! vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (! vRecv.empty())
            vRecv >> pfrom->strSubVer;
        if (! vRecv.empty())
            vRecv >> pfrom->nStartingHeight;
        if (pfrom->fInbound && addrMe.IsRoutable()) {
            pfrom->addrLocal = addrMe;
            ext_ip::SeenLocal(addrMe);
        }

        // Disconnect if we connected to ourself
        if (nNonce == bitsocket::nLocalHostNonce && nNonce > 1) {
            logging::LogPrintf("connected to self at %s, disconnecting\n", pfrom->addr.ToString().c_str());
            pfrom->fDisconnect = true;
            return true;
        }
        if (pfrom->nVersion < 60010) {
            logging::LogPrintf("partner %s using a buggy client %d, disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return true;
        }

        // record my external IP reported by peer
        if (addrFrom.IsRoutable() && addrMe.IsRoutable())
            bitsocket::addrSeenByPeer = addrMe;

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
            pfrom->PushVersion();

        pfrom->fClient = !(pfrom->nServices & protocol::NODE_NETWORK);
        bitsystem::AddTimeData(pfrom->addr, nTime);

        // Change version
        pfrom->PushMessage("verack");
        pfrom->vSend.SetVersion(std::min(pfrom->nVersion, version::PROTOCOL_VERSION));
        if (! pfrom->fInbound) {
            // Advertise our address
            if (!args_bool::fNoListen && !block_notify::IsInitialBlockDownload()) {
                CAddress addr = ext_ip::GetLocalAddress(&pfrom->addr);
                if (addr.IsRoutable()) pfrom->PushAddress(addr);
            }
            // Get recent addresses
            if (pfrom->fOneShot || pfrom->nVersion >= version::CADDR_TIME_VERSION || net_node::addrman.size() < 1000) {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
            net_node::addrman.Good(pfrom->addr);
        } else {
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom) {
                net_node::addrman.Add(addrFrom, addrFrom);
                net_node::addrman.Good(addrFrom);
            }
        }

        // Ask the first connected node for block updates
        static int nAskedForBlocks = 0;
        if (!pfrom->fClient &&
            !pfrom->fOneShot &&
            (pfrom->nStartingHeight > (block_info::nBestHeight - 144)) &&
            (pfrom->nVersion < version::NOBLKS_VERSION_START || pfrom->nVersion >= version::NOBLKS_VERSION_END) &&
            (nAskedForBlocks < 1 || net_node::vNodes.size() <= 1)) {
            ++nAskedForBlocks;
            pfrom->PushGetBlocks(block_info::pindexBest, uint256(0));
        }

        // Relay alerts
        {
            LOCK(CUnsignedAlert::cs_mapAlerts);
            for(std::pair<const uint256, CAlert> &item: CAlert::mapAlerts)
                item.second.RelayTo(pfrom);
        }

        // Relay sync-checkpoint
        {
            LLOCK(Checkpoints::cs_hashSyncCheckpoint);
            if (! Checkpoints::checkpointMessage.IsNull())
                Checkpoints::checkpointMessage.RelayTo(pfrom);
        }

        pfrom->fSuccessfullyConnected = true;
        logging::LogPrintf("receive version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", pfrom->nVersion, pfrom->nStartingHeight, addrMe.ToString().c_str(), addrFrom.ToString().c_str(), pfrom->addr.ToString().c_str());
        cPeerBlockCounts.input(pfrom->nStartingHeight);

        // ppcoin: ask for pending sync-checkpoint if any
        if (! block_notify::IsInitialBlockDownload())
            Checkpoints::manage::AskForPendingSyncCheckpoint(pfrom);
    } else if (pfrom->nVersion == 0) {
        // Must have a version message before anything else
        debugcs::instance() << "receive version message: pfrom->nVersion == 0 Misbehaving" << debugcs::endl();
        pfrom->Misbehaving(1);
        return false;
    } else if (strCommand == "verack") {
        pfrom->vRecv.SetVersion(std::min(pfrom->nVersion, version::PROTOCOL_VERSION));
    } else if (strCommand == "addr") {
        std::vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < version::CADDR_TIME_VERSION && net_node::addrman.size() > 1000)
            return true;
        if (vAddr.size() > 1000) {
            pfrom->Misbehaving(20);
            return logging::error("message addr size() = %" PRIszu "", vAddr.size());
        }

        // Store the new addresses
        std::vector<CAddress> vAddrOk;
        int64_t nNow = bitsystem::GetAdjustedTime();
        int64_t nSince = nNow - 10 * 60;
        for(CAddress& addr: vAddr) {
            if (args_bool::fShutdown)
                return true;
            if (addr.get_nTime() <= 100000000 || addr.get_nTime() > nNow + 10 * 60)
                addr.set_nTime( nNow - 5 * util::nOneDay );
            pfrom->AddAddressKnown(addr);
            bool fReachable = ext_ip::IsReachable(addr);
            if (addr.get_nTime() > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable()) {
                // Relay to a limited number of other nodes
                {
                    LOCK(net_node::cs_vNodes);

                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                    static uint256 hashSalt;
                    if (hashSalt == 0) hashSalt = bitsystem::GetRandHash();
                    uint64_t hashAddr = addr.GetHash();
                    uint256 hashRand = hashSalt ^ (hashAddr<<32) ^ ((bitsystem::GetTime() + hashAddr) / util::nOneDay);
                    hashRand = hash_basis::Hash(BEGIN(hashRand), END(hashRand));
                    std::multimap<uint256, CNode *> mapMix;
                    for(CNode* pnode: net_node::vNodes) {
                        if (pnode->nVersion < version::CADDR_TIME_VERSION)
                            continue;
                        unsigned int nPointer;
                        std::memcpy(&nPointer, &pnode, sizeof(nPointer));
                        uint256 hashKey = hashRand ^ nPointer;
                        hashKey = hash_basis::Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(std::make_pair(hashKey, pnode));
                    }

                    int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
                    for (std::multimap<uint256, CNode *>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                        ((*mi).second)->PushAddress(addr);
                }
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }

        net_node::addrman.Add(vAddrOk, pfrom->addr, 2 * util::nOneHour);
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot)
            pfrom->fDisconnect = true;
    } else if (strCommand == "inv") {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > block_params::MAX_INV_SZ) {
            pfrom->Misbehaving(20);
            return logging::error("message inv size() = %" PRIszu "", vInv.size());
        }

        // find last block in inv vector
        size_t nLastBlock = std::numeric_limits<size_t>::max();
        for (size_t nInv = 0; nInv < vInv.size(); ++nInv) {
            if (vInv[vInv.size() - 1 - nInv].get_type() == _CINV_MSG_TYPE::MSG_BLOCK) {
                nLastBlock = vInv.size() - 1 - nInv;
                break;
            }
        }

        CTxDB txdb("r");
        for (size_t nInv = 0; nInv < vInv.size(); ++nInv) {
            const CInv &inv = vInv[nInv];
            if (args_bool::fShutdown)
                return true;
            pfrom->AddInventoryKnown(inv);
            bool fAlreadyHave = block_process::manage::AlreadyHave(txdb, inv);
            if (args_bool::fDebug)
                logging::LogPrintf("  got inventory: %s  %s\n", inv.ToString().c_str(), fAlreadyHave ? "have" : "new");
            if (! fAlreadyHave)
                pfrom->AskFor(inv);
            else if (inv.get_type() == _CINV_MSG_TYPE::MSG_BLOCK && block_process::mapOrphanBlocks.count(inv.get_hash()))
                pfrom->PushGetBlocks(block_info::pindexBest, block_process::manage::GetOrphanRoot(block_process::mapOrphanBlocks[inv.get_hash()]));
            else if (nInv == nLastBlock) {
                // In case we are on a very long side-chain, it is possible that we already have
                // the last block in an inv bundle sent in response to getblocks. Try to detect
                // this situation and push another getblocks to continue.
                pfrom->PushGetBlocks(block_info::mapBlockIndex[inv.get_hash()], uint256(0));
                if (args_bool::fDebug) logging::LogPrintf("force request: %s\n", inv.ToString().c_str());
            }

            // Track requests for our stuff
            block_process::manage::Inventory(inv.get_hash());
        }
    } else if (strCommand == "getdata") {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > block_params::MAX_INV_SZ) {
            pfrom->Misbehaving(20);
            return logging::error("message getdata size() = %" PRIszu "", vInv.size());
        }
        if (args_bool::fDebugNet || (vInv.size() != 1))
            logging::LogPrintf("received getdata (%" PRIszu " invsz)\n", vInv.size());

        for(const CInv &inv: vInv) {
            if (args_bool::fShutdown)
                return true;
            if (args_bool::fDebugNet || (vInv.size() == 1))
                logging::LogPrintf("received getdata for: %s\n", inv.ToString().c_str());
            if (inv.get_type() == _CINV_MSG_TYPE::MSG_BLOCK) {
                // Send block from disk
                std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(inv.get_hash());
                if (mi != block_info::mapBlockIndex.end()) {
                    CBlock block;
                    block.ReadFromDisk((*mi).second);
                    pfrom->PushMessage("block", block);

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.get_hash() == pfrom->hashContinue) {
                        // ppcoin: send latest proof-of-work block to allow the
                        // download node to accept as orphan (proof-of-stake
                        // block might be rejected by stake connection check)
                        std::vector<CInv> vInv;
                        vInv.push_back(CInv(_CINV_MSG_TYPE::MSG_BLOCK, diff::spacing::GetLastBlockIndex(block_info::pindexBest, false)->GetBlockHash()));
                        pfrom->PushMessage("inv", vInv);
                        pfrom->hashContinue = 0;
                    }
                }
            } else if (inv.IsKnownType()) {
                // Send stream from relay memory
                bool pushed = false;
                {
                    LOCK(net_node::cs_mapRelay);
                    std::map<CInv, CDataStream>::iterator mi = net_node::mapRelay.find(inv);
                    if (mi != net_node::mapRelay.end()) {
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        pushed = true;
                    }
                }
                if (!pushed && inv.get_type() == _CINV_MSG_TYPE::MSG_TX) {
                    LOCK(CTxMemPool::mempool.get_cs());
                    if (CTxMemPool::mempool.exists(inv.get_hash())) {
                        CTransaction tx = CTxMemPool::mempool.lookup(inv.get_hash());
                        CDataStream ss(SER_NETWORK, version::PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << tx;
                        pfrom->PushMessage("tx", ss);
                    }
                }
            }

            // Track requests for our stuff
            block_process::manage::Inventory(inv.get_hash());
        }
    } else if (strCommand == "getblocks") {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        // Find the last block the caller has in the main chain
        CBlockIndex *pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->set_pnext();

        int nLimit = 500;
        logging::LogPrintf("getblocks %d to %s limit %d\n", (pindex ? pindex->get_nHeight() : -1), hashStop.ToString().substr(0,20).c_str(), nLimit);
        for (; pindex; pindex = pindex->set_pnext()) {
            if (pindex->GetBlockHash() == hashStop) {
                logging::LogPrintf("  getblocks stopping at %d %s\n", pindex->get_nHeight(), pindex->GetBlockHash().ToString().substr(0,20).c_str());
                // ppcoin: tell downloading node about the latest block if it's
                // without risk being rejected due to stake connection check
                if (hashStop != block_info::hashBestChain && pindex->GetBlockTime() + block_check::nStakeMinAge > block_info::pindexBest->GetBlockTime())
                    pfrom->PushInventory(CInv(_CINV_MSG_TYPE::MSG_BLOCK, block_info::hashBestChain));
                break;
            }

            pfrom->PushInventory(CInv(_CINV_MSG_TYPE::MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0) {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                logging::LogPrintf("  getblocks stopping at limit %d %s\n", pindex->get_nHeight(), pindex->GetBlockHash().ToString().substr(0,20).c_str());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    } else if (strCommand == "checkpoint") {
        CSyncCheckpoint checkpoint;
        vRecv >> checkpoint;

        if (checkpoint.ProcessSyncCheckpoint(pfrom)) {
            // Relay
            pfrom->hashCheckpointKnown = checkpoint.Get_hashCheckpoint();
            LOCK(net_node::cs_vNodes);
            for(CNode* pnode: net_node::vNodes)
                checkpoint.RelayTo(pnode);
        }
    } else if (strCommand == "getheaders") {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        CBlockIndex *pindex = nullptr;
        if (locator.IsNull()) {
            // If locator is null, return the hashStop block
            std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hashStop);
            if (mi == block_info::mapBlockIndex.end())
                return true;
            pindex = (*mi).second;
        } else {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();
            if (pindex)
                pindex = pindex->set_pnext();
        }

        std::vector<CBlock> vHeaders;
        int nLimit = 2000;
        logging::LogPrintf("getheaders %d to %s\n", (pindex ? pindex->get_nHeight() : -1), hashStop.ToString().substr(0,20).c_str());
        for (; pindex; pindex = pindex->set_pnext()) {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        pfrom->PushMessage("headers", vHeaders);
    } else if (strCommand == "tx") {
        std::vector<uint256> vWorkQueue;
        std::vector<uint256> vEraseQueue;
        CDataStream vMsg(vRecv);
        CTxDB txdb("r");
        CTransaction tx;
        vRecv >> tx;

        CInv inv(_CINV_MSG_TYPE::MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);
        bool fMissingInputs = false;
        if (tx.AcceptToMemoryPool(txdb, true, &fMissingInputs)) {
            wallet_process::manage::SyncWithWallets(tx, NULL, true);
            bitrelay::RelayTransaction(tx, inv.get_hash());
            net_node::mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.get_hash());
            vEraseQueue.push_back(inv.get_hash());

            // Recursively process any orphan transactions that depended on this one
            for (unsigned int i = 0; i < vWorkQueue.size(); ++i) {
                uint256 hashPrev = vWorkQueue[i];
                for (std::set<uint256>::iterator mi = mapOrphanTransactionsByPrev[hashPrev].begin();
                     mi != mapOrphanTransactionsByPrev[hashPrev].end(); ++mi) {
                    const uint256& orphanTxHash = *mi;
                    CTransaction& orphanTx = mapOrphanTransactions[orphanTxHash];
                    bool fMissingInputs2 = false;

                    if (orphanTx.AcceptToMemoryPool(txdb, true, &fMissingInputs2)) {
                        logging::LogPrintf("   accepted orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                        wallet_process::manage::SyncWithWallets(tx, NULL, true);
                        bitrelay::RelayTransaction(orphanTx, orphanTxHash);
                        net_node::mapAlreadyAskedFor.erase(CInv(_CINV_MSG_TYPE::MSG_TX, orphanTxHash));
                        vWorkQueue.push_back(orphanTxHash);
                        vEraseQueue.push_back(orphanTxHash);
                    } else if (!fMissingInputs2) {
                        // invalid orphan
                        vEraseQueue.push_back(orphanTxHash);
                        logging::LogPrintf("   removed invalid orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                    }
                }
            }

            for(uint256 hash: vEraseQueue)
                block_process::manage::EraseOrphanTx(hash);
        } else if (fMissingInputs) {
            if(! block_process::manage::AddOrphanTx(tx)) {
                logging::LogPrintf("mapOrphan overflow\n");
                return false;    // add
            }

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            unsigned int nEvicted = block_process::manage::LimitOrphanTxSize(block_params::MAX_ORPHAN_TRANSACTIONS);
            if (nEvicted > 0) logging::LogPrintf("mapOrphan overflow, removed %u tx\n", nEvicted);
        }
        if (tx.nDoS)
            pfrom->Misbehaving(tx.nDoS);
    } else if (strCommand == "block") {
        CBlock block;
        vRecv >> block;
        uint256 hashBlock = block.GetHash();

        logging::LogPrintf("received block %s\n", hashBlock.ToString().substr(0,20).c_str());
        // block.print();

        CInv inv(_CINV_MSG_TYPE::MSG_BLOCK, hashBlock);
        pfrom->AddInventoryKnown(inv);
        if (block_process::manage::ProcessBlock(pfrom, &block))
            net_node::mapAlreadyAskedFor.erase(inv);
        if (block.get_nDoS())
            pfrom->Misbehaving(block.get_nDoS());
    } else if ((strCommand == "getaddr") && (pfrom->fInbound)) {
        // This asymmetric behavior for inbound and outbound connections was introduced
        // to prevent a fingerprinting attack: an attacker can send specific fake addresses
        // to users' AddrMan and later request them by sending getaddr messages.
        // Making users (which are behind NAT and can only make outgoing connections) ignore
        // getaddr message mitigates the attack.
        // Don't return addresses older than nCutOff timestamp
        int64_t nCutOff = bitsystem::GetTime() - (args_uint::nNodeLifespan * util::nOneDay);
        pfrom->vAddrToSend.clear();
        std::vector<CAddress> vAddr = net_node::addrman.GetAddr();
        for(const CAddress &addr: vAddr) {
            if(addr.get_nTime() > nCutOff)
                pfrom->PushAddress(addr);
        }
    } else if (strCommand == "mempool") {
        std::vector<uint256> vtxid;
        CTxMemPool::mempool.queryHashes(vtxid);
        std::vector<CInv> vInv;
        for (unsigned int i = 0; i < vtxid.size(); ++i) {
            CInv inv(_CINV_MSG_TYPE::MSG_TX, vtxid[i]);
            vInv.push_back(inv);
            if (i == (block_params::MAX_INV_SZ - 1))
                break;
        }
        if (vInv.size() > 0)
            pfrom->PushMessage("inv", vInv);
    } else if (strCommand == "checkorder") {
        uint256 hashReply;
        vRecv >> hashReply;
        if (! map_arg::GetBoolArg("-allowreceivebyip")) {
            pfrom->PushMessage("reply", hashReply, 2, std::string(""));
            return true;
        }

        CWalletTx order;
        vRecv >> order;
        /// we have a chance to check the order here

        // Keep giving the same key to the same ip until they use it
        if (! mapReuseKey.count(pfrom->addr))
            entry::pwalletMain->GetKeyFromPool(mapReuseKey[pfrom->addr], true);

        // Send back approval of order and pubkey to use
        CScript scriptPubKey;
        scriptPubKey << mapReuseKey[pfrom->addr] << ScriptOpcodes::OP_CHECKSIG;
        pfrom->PushMessage("reply", hashReply, 0, scriptPubKey);
    } else if (strCommand == "reply") {
        uint256 hashReply;
        vRecv >> hashReply;

        CRequestTracker tracker;
        {
            LOCK(pfrom->cs_mapRequests);
            std::map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
            if (mi != pfrom->mapRequests.end()) {
                tracker = (*mi).second;
                pfrom->mapRequests.erase(mi);
            }
        }
        if (! tracker.IsNull())
            tracker.fn(tracker.param1, vRecv);
    } else if (strCommand == "ping") {
        uint64_t nonce = 0;
        vRecv >> nonce;
        // Echo the message back with the nonce. This allows for two useful features:
        //
        // 1) A remote node can quickly check if the connection is operational
        // 2) Remote nodes can measure the latency of the network thread. If this node
        //    is overloaded it won't respond to pings quickly and the remote node can
        //    avoid sending us more work, like chain download requests.
        //
        // The nonce stops the remote getting confused between different pings: without
        // it, if the remote node sends a ping once per second and this node takes 5
        // seconds to respond to each, the 5th ping the remote sends would appear to
        // return very quickly.
        pfrom->PushMessage("pong", nonce);
    } else if (strCommand == "alert") {
        CAlert alert;
        vRecv >> alert;

        uint256 alertHash = alert.GetHash();
        if (pfrom->setKnown.count(alertHash) == 0) {
            if (alert.ProcessAlert()) {
                // Relay
                pfrom->setKnown.insert(alertHash);
                {
                    LOCK(net_node::cs_vNodes);
                    for(CNode *pnode: net_node::vNodes)
                       alert.RelayTo(pnode);
                }
            } else {
                // Small DoS penalty so peers that send us lots of
                // duplicate/expired/invalid-signature/whatever alerts
                // eventually get banned.
                // This isn't a Misbehaving(100) (immediate ban) because the
                // peer might be an older or different implementation with
                // a different signature key, etc.
                pfrom->Misbehaving(10);
            }
        }
    } else {
        // Ignore unknown commands for extensibility
    }

    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode) {
        if (strCommand == "version" || strCommand == "addr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
            net_node::AddressCurrentlyConnected(pfrom->addr);
    }

    return true;
}

bool block_process::manage::ProcessMessages(CNode *pfrom)
{
    CDataStream& vRecv = pfrom->vRecv;
    if (vRecv.empty())
        return true;

    ////////////////////////////////////////////////////////////
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    ////////////////////////////////////////////////////////////
    for (;;) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->vSend.size() >= net_node::SendBufferSize())
            break;

        // Scan for message start
        CDataStream::iterator pstart = search(vRecv.begin(), vRecv.end(), BEGIN(block_info::gpchMessageStart), END(block_info::gpchMessageStart));
        int nHeaderSize = vRecv.GetSerializeSize(CMessageHeader());
        if (vRecv.end() - pstart < nHeaderSize) {
            if ((int)vRecv.size() > nHeaderSize) {
                logging::LogPrintf("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n");
                vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
            }
            break;
        }
        if (pstart - vRecv.begin() > 0)
            logging::LogPrintf("\n\nPROCESSMESSAGE SKIPPED %" PRIpdd " BYTES\n\n", pstart - vRecv.begin());

        vRecv.erase(vRecv.begin(), pstart);

        // Read header
        std::vector<char> vHeaderSave(vRecv.begin(), vRecv.begin() + nHeaderSize);
        CMessageHeader hdr;
        vRecv >> hdr;
        if (! hdr.IsValid()) {
            logging::LogPrintf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        std::string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.GetMessageSize();
        if (nMessageSize > compact_size::MAX_SIZE) {
            logging::LogPrintf("block_process::manage::ProcessMessages(%s, %u bytes) : nMessageSize > compact_size::MAX_SIZE\n", strCommand.c_str(), nMessageSize);
            continue;
        }
        if (nMessageSize > vRecv.size()) {
            // Rewind and wait for rest of message
            vRecv.insert(vRecv.begin(), vHeaderSave.begin(), vHeaderSave.end());
            break;
        }

        // Checksum
        uint256 hash = hash_basis::Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
        unsigned int nChecksum = 0;
        std::memcpy(&nChecksum, &hash, sizeof(nChecksum));
        if (nChecksum != hdr.GetChecksum()) {
            logging::LogPrintf("block_process::manage::ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n", strCommand.c_str(), nMessageSize, nChecksum, hdr.GetChecksum());
            continue;
        }

        // Copy message to its own buffer
        CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.GetType(), vRecv.GetVersion());
        vRecv.ignore(nMessageSize);

        // Process message
        bool fRet = false;
        try {
            {
                LOCK(block_process::cs_main);
                fRet = block_process::manage::ProcessMessage(pfrom, strCommand, vMsg);
            }
            if (args_bool::fShutdown)
                return true;
        } catch (std::ios_base::failure &e) {
            if (::strstr(e.what(), "end of data")) {
                // Allow exceptions from under-length message on vRecv
                logging::LogPrintf("block_process::manage::ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
            } else if (strstr(e.what(), "size too large")) {
                // Allow exceptions from over-long size
                logging::LogPrintf("block_process::manage::ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
            } else
                excep::PrintExceptionContinue(&e, "block_process::manage::ProcessMessages()");
        } catch (std::exception &e) {
            excep::PrintExceptionContinue(&e, "block_process::manage::ProcessMessages()");
        } catch (...) {
            excep::PrintExceptionContinue(NULL, "block_process::manage::ProcessMessages()");
        }
        if (! fRet)
            logging::LogPrintf("block_process::manage::ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(), nMessageSize);
    }

    vRecv.Compact();
    return true;
}

bool block_process::manage::SendMessages(CNode *pto)
{
    TRY_LOCK(block_process::cs_main, lockMain);
    if (lockMain) {
        // Current time in microseconds
        int64_t nNow = util::GetTimeMicros();

        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return true;

        // Keep-alive ping. We send a nonce of zero because we don't use it anywhere
        // right now.
        if (pto->nLastSend && bitsystem::GetTime() - pto->nLastSend > block_process::manage::nPingInterval && pto->vSend.empty()) {
            uint64_t nonce = 0;
            pto->PushMessage("ping", nonce);
        }

        // Start block sync
        if (pto->fStartSync) {
            pto->fStartSync = false;
            pto->PushGetBlocks(block_info::pindexBest, uint256(0));
        }

        // Resend wallet transactions that haven't gotten in a block yet
        block_process::manage::ResendWalletTransactions();

        // Address refresh broadcast
        if (! block_notify::IsInitialBlockDownload() && pto->nNextLocalAddrSend < nNow) {
            ext_ip::AdvertiseLocal(pto);
            pto->nNextLocalAddrSend = future_time::PoissonNextSend(nNow, util::nOneDay);
        }

        // Message: addr
        if (pto->nNextAddrSend < nNow) {
            pto->nNextAddrSend = future_time::PoissonNextSend(nNow, 30);
            std::vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            for(const CAddress& addr: pto->vAddrToSend) {
                if (pto->setAddrKnown.insert(addr).second) {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000) {
                        pto->PushMessage("addr", vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (! vAddr.empty())
                pto->PushMessage("addr", vAddr);
        }

        // Message: inventory
        std::vector<CInv> vInv;
        std::vector<CInv> vInvWait;
        {
            bool fSendTrickle = false;
            if (pto->nNextInvSend < nNow) {
                fSendTrickle = true;
                pto->nNextInvSend = future_time::PoissonNextSend(nNow, 5);
            }

            LOCK(pto->cs_inventory);
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            for(const CInv &inv: pto->vInventoryToSend) {
                if (pto->setInventoryKnown.count(inv))
                    continue;

                // trickle out tx inv to protect privacy
                if (inv.get_type() == _CINV_MSG_TYPE::MSG_TX && !fSendTrickle) {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = bitsystem::GetRandHash();

                    uint256 hashRand = inv.get_hash() ^ hashSalt;
                    hashRand = hash_basis::Hash(BEGIN(hashRand), END(hashRand));
                    bool fTrickleWait = ((hashRand & 3) != 0);
                    if (fTrickleWait) {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second) {
                    vInv.push_back(inv);
                    if (vInv.size() >= 1000) {
                        pto->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (! vInv.empty())
            pto->PushMessage("inv", vInv);

        // Message: getdata
        std::vector<CInv> vGetData;
        CTxDB txdb("r");
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow) {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (! block_process::manage::AlreadyHave(txdb, inv)) {
                if (args_bool::fDebugNet)
                    logging::LogPrintf("sending getdata: %s\n", inv.ToString().c_str());

                vGetData.push_back(inv);
                if (vGetData.size() >= 1000) {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
                net_node::mapAlreadyAskedFor[inv] = nNow;
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (! vGetData.empty())
            pto->PushMessage("getdata", vGetData);
    }
    return true;
}

// ppcoin: find block wanted by given orphan block
uint256 block_process::manage::GetOrphanRoot(const CBlock *pblock)
{
    // Work back to the first block in the orphan chain
    while (block_process::mapOrphanBlocks.count(pblock->get_hashPrevBlock()))
        pblock = block_process::mapOrphanBlocks[pblock->get_hashPrevBlock()];
    return pblock->GetHash();
}

bool block_process::manage::ReserealizeBlockSignature(CBlock *pblock)
{
    if (pblock->IsProofOfWork()) {
        pblock->set_vchBlockSig().clear();
        return true;
    }
    return CPubKey::ReserealizeSignature(pblock->set_vchBlockSig());
}

bool block_process::manage::IsCanonicalBlockSignature(CBlock *pblock)
{
    if (pblock->IsProofOfWork())
        return pblock->get_vchBlockSig().empty();
    return Script_util::IsDERSignature(pblock->get_vchBlockSig());
}

bool block_process::manage::AlreadyHave(CTxDB &txdb, const CInv &inv)
{
    switch (inv.get_type())
    {
    case _CINV_MSG_TYPE::MSG_TX:
        {
            bool txInMap = false;
            {
                LOCK(CTxMemPool::mempool.get_cs());
                txInMap = (CTxMemPool::mempool.exists(inv.get_hash()));
            }
            return  txInMap ||
                    mapOrphanTransactions.count(inv.get_hash()) ||
                    txdb.ContainsTx(inv.get_hash());
        }
    case _CINV_MSG_TYPE::MSG_BLOCK:
        return  block_info::mapBlockIndex.count(inv.get_hash()) ||
                block_process::mapOrphanBlocks.count(inv.get_hash());
    case _CINV_MSG_TYPE::MSG_ERROR:
        break; // do nothing
    }

    // Don't know what it is, just say we already got one
    return true;
}

// notify wallets about an incoming inventory (for request counts)
void block_process::manage::Inventory(const uint256 &hash)
{
    for(CWallet *pwallet: block_info::setpwalletRegistered)
        pwallet->Inventory(hash);
}

// mapOrphanTransactions
bool block_process::manage::AddOrphanTx(const CTransaction &tx)
{
    uint256 hash = tx.GetHash();
    if (block_process::manage::mapOrphanTransactions.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is at most 500 megabytes of orphans
    size_t nSize = tx.GetSerializeSize();
    if (nSize > block_transaction::MAX_ORPHAN_SERIALIZESIZE) {
        logging::LogPrintf("ignoring large orphan tx (size: %" PRIszu ", hash: %s)\n", nSize, hash.ToString().substr(0,10).c_str());
        return false;
    }

    block_process::manage::mapOrphanTransactions[hash] = tx;
    for(const CTxIn &txin: tx.get_vin())
        block_process::manage::mapOrphanTransactionsByPrev[txin.get_prevout().get_hash()].insert(hash);

    logging::LogPrintf("stored orphan tx %s (mapsz %" PRIszu ")\n", hash.ToString().substr(0,10).c_str(), mapOrphanTransactions.size());
    return true;
}

void block_process::manage::EraseOrphanTx(uint256 hash)
{
    if (! block_process::manage::mapOrphanTransactions.count(hash))
        return;
    const CTransaction &tx = block_process::manage::mapOrphanTransactions[hash];
    for(const CTxIn &txin: tx.get_vin()) {
        block_process::manage::mapOrphanTransactionsByPrev[txin.get_prevout().get_hash()].erase(hash);
        if (block_process::manage::mapOrphanTransactionsByPrev[txin.get_prevout().get_hash()].empty())
            block_process::manage::mapOrphanTransactionsByPrev.erase(txin.get_prevout().get_hash());
    }
    block_process::manage::mapOrphanTransactions.erase(hash);
}

unsigned int block_process::manage::LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;
    while (block_process::manage::mapOrphanTransactions.size() > nMaxOrphans) {
        // Evict a random orphan:
        uint256 randomhash = bitsystem::GetRandHash();
        std::map<uint256, CTransaction>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        block_process::manage::EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}

uint256 block_process::manage::WantedByOrphan(const CBlock *pblockOrphan)
{
    // Work back to the first block in the orphan chain
    while (block_process::mapOrphanBlocks.count(pblockOrphan->get_hashPrevBlock()))
        pblockOrphan = block_process::mapOrphanBlocks[pblockOrphan->get_hashPrevBlock()];
    return pblockOrphan->get_hashPrevBlock();
}

// ask wallets to resend their transactions
void block_process::manage::ResendWalletTransactions(bool fForceResend /*= false*/)
{
    for(CWallet *pwallet: block_info::setpwalletRegistered)
        pwallet->ResendWalletTransactions(fForceResend);
}

bool block_process::manage::ProcessBlock(CNode *pfrom, CBlock *pblock)
{
    uint256 hash = pblock->GetHash();

    // Check for duplicate
    if (block_info::mapBlockIndex.count(hash))
        return logging::error("block_process::manage::ProcessBlock() : already have block %d %s", block_info::mapBlockIndex[hash]->get_nHeight(), hash.ToString().substr(0,20).c_str());
    if (block_process::mapOrphanBlocks.count(hash))
        return logging::error("block_process::manage::ProcessBlock() : already have block (orphan) %s", hash.ToString().substr(0,20).c_str());
    // Check that block isn't listed as unconditionally banned.
    if (! Checkpoints::manage::CheckBanned(hash)) {
        if (pfrom)
            pfrom->Misbehaving(100);
        return logging::error("block_process::manage::ProcessBlock() : block %s is rejected by hard-coded banlist", hash.GetHex().substr(0,20).c_str());
    }

    // Check proof-of-stake
    // Limited duplicity on stake: prevents block flood attack
    // Duplicate stake allowed only when there is orphan child block
    if (pblock->IsProofOfStake() && block_info::setStakeSeen.count(pblock->GetProofOfStake()) && !block_process::manage::mapOrphanBlocksByPrev.count(hash) && !Checkpoints::manage::WantedByPendingSyncCheckpoint(hash))
        return logging::error("block_process::manage::ProcessBlock() : duplicate proof-of-stake (%s, %d) for block %s", pblock->GetProofOfStake().first.ToString().c_str(), pblock->GetProofOfStake().second, hash.ToString().c_str());

    // Strip the garbage from newly received blocks, if we found some
    if (! block_process::manage::IsCanonicalBlockSignature(pblock)) {
        if (! block_process::manage::ReserealizeBlockSignature(pblock))
            logging::LogPrintf("WARNING: ProcessBlock() : ReserealizeBlockSignature FAILED\n");
    }

    // Preliminary checks
    if (! pblock->CheckBlock(true, true, (pblock->get_nTime() > Checkpoints::manage::GetLastCheckpointTime())))
        return logging::error("block_process::manage::ProcessBlock() : CheckBlock FAILED");

    // ppcoin: verify hash target and signature of coinstake tx
    if (pblock->IsProofOfStake()) {
        uint256 hashProofOfStake = 0, targetProofOfStake = 0;
        if (! bitkernel::CheckProofOfStake(pblock->get_vtx(1), pblock->get_nBits(), hashProofOfStake, targetProofOfStake)) {
            logging::LogPrintf("WARNING: block_process::manage::ProcessBlock(): check proof-of-stake failed for block %s\n", hash.ToString().c_str());
            return false; // do not error here as we expect this during initial block download
        }
        if (! block_process::mapProofOfStake.count(hash)) // add to mapProofOfStake
            block_process::mapProofOfStake.insert(std::make_pair(hash, hashProofOfStake));
    }

    CBlockIndex *pcheckpoint = Checkpoints::manage::GetLastSyncCheckpoint();
    if (pcheckpoint && pblock->get_hashPrevBlock() != block_info::hashBestChain && !Checkpoints::manage::WantedByPendingSyncCheckpoint(hash)) {
        // Extra checks to prevent "fill up memory by spamming with bogus blocks"
        int64_t deltaTime = pblock->GetBlockTime() - pcheckpoint->get_nTime();
        CBigNum bnNewBlock;
        bnNewBlock.SetCompact(pblock->get_nBits());
        CBigNum bnRequired;
        if (pblock->IsProofOfStake())
            bnRequired.SetCompact(diff::amount::ComputeMinStake(diff::spacing::GetLastBlockIndex(pcheckpoint, true)->get_nBits(), deltaTime, pblock->get_nTime()));
        else
            bnRequired.SetCompact(diff::amount::ComputeMinWork(diff::spacing::GetLastBlockIndex(pcheckpoint, false)->get_nBits(), deltaTime));

        if (bnNewBlock > bnRequired) {
            if (pfrom)
                pfrom->Misbehaving(100);
            return logging::error("block_process::manage::ProcessBlock() : block with too little %s", pblock->IsProofOfStake()? "proof-of-stake" : "proof-of-work");
        }
    }

    // ppcoin: ask for pending sync-checkpoint if any
    if (! block_notify::IsInitialBlockDownload())
        Checkpoints::manage::AskForPendingSyncCheckpoint(pfrom);

    // If don't already have its previous block, shunt it off to holding area until we get it
    if (! block_info::mapBlockIndex.count(pblock->get_hashPrevBlock())) {
        logging::LogPrintf("block_process::manage::ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->get_hashPrevBlock().ToString().substr(0,20).c_str());

        // ppcoin: check proof-of-stake
        if (pblock->IsProofOfStake()) {
            // Limited duplicity on stake: prevents block flood attack
            // Duplicate stake allowed only when there is orphan child block
            if (block_process::manage::setStakeSeenOrphan.count(pblock->GetProofOfStake()) && !block_process::manage::mapOrphanBlocksByPrev.count(hash) && !Checkpoints::manage::WantedByPendingSyncCheckpoint(hash))
                return logging::error("block_process::manage::ProcessBlock() : duplicate proof-of-stake (%s, %d) for orphan block %s", pblock->GetProofOfStake().first.ToString().c_str(), pblock->GetProofOfStake().second, hash.ToString().c_str());
            else
                block_process::manage::setStakeSeenOrphan.insert(pblock->GetProofOfStake());
        }

        CBlock *pblock2 = new (std::nothrow) CBlock(*pblock);
        if(! pblock2)
            return logging::error("block_process::manage::ProcessBlock() : bad alloc for orphan block");

        block_process::mapOrphanBlocks.insert(std::make_pair(hash, pblock2));
        block_process::manage::mapOrphanBlocksByPrev.insert(std::make_pair(pblock2->get_hashPrevBlock(), pblock2));

        // Ask this guy to fill in what we're missing
        if (pfrom) {
            pfrom->PushGetBlocks(block_info::pindexBest, block_process::manage::GetOrphanRoot(pblock2));

            // ppcoin: getblocks may not obtain the ancestor block rejected
            // earlier by duplicate-stake check so we ask for it again directly
            if (! block_notify::IsInitialBlockDownload())
                pfrom->AskFor(CInv(_CINV_MSG_TYPE::MSG_BLOCK, block_process::manage::WantedByOrphan(pblock2)));
        }
        return true;
    }

    // Store to disk
    if (! pblock->AcceptBlock())
        return logging::error("block_process::manage::ProcessBlock() : AcceptBlock FAILED");

    // Recursively process any orphan blocks that depended on this one
    std::vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (unsigned int i = 0; i < vWorkQueue.size(); ++i) {
        uint256 hashPrev = vWorkQueue[i];
        for (std::multimap<uint256, CBlock *>::iterator mi = block_process::manage::mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != block_process::manage::mapOrphanBlocksByPrev.upper_bound(hashPrev); ++mi) {
            CBlock *pblockOrphan = (*mi).second;
            if (pblockOrphan->AcceptBlock())
                vWorkQueue.push_back(pblockOrphan->GetHash());

            block_process::mapOrphanBlocks.erase(pblockOrphan->GetHash());
            block_process::manage::setStakeSeenOrphan.erase(pblockOrphan->GetProofOfStake());
            delete pblockOrphan;    // manage::mapOrphanBlocksByPrev.insert(std::make_pair(first, second) ...
        }
        block_process::manage::mapOrphanBlocksByPrev.erase(hashPrev);
    }

    logging::LogPrintf("block_process::manage::ProcessBlock: ACCEPTED\n");

    // ppcoin: if responsible for sync-checkpoint send it
    if (pfrom && !CSyncCheckpoint::Get_strMasterPrivKey().empty())
        Checkpoints::manage::AutoSendSyncCheckpoint();

    return true;
}

// Return maximum amount of blocks that other nodes claim to have
int block_process::manage::GetNumBlocksOfPeers()
{
    return std::max(cPeerBlockCounts.median(), Checkpoints::manage::GetTotalBlocksEstimate());
}
