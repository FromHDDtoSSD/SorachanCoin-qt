// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <db.h>
#include <txdb.h>
#include <init.h>
#include <miner.h>
#include <kernel.h>
#include <rpc/bitcoinrpc.h>
#include <block/block_process.h>
#include <miner/diff.h>
#include <block/block_alert.h>
#include <boost/format.hpp>
#include <util/strencodings.h>

CCriticalSection CRPCTable::cs_getwork;

json_spirit::Value CRPCTable::getsubsidy(const json_spirit::Array &params, bool fHelp) {
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "getsubsidy [nTarget]\n"
            "Returns proof-of-work subsidy value for the specified value of target.");
    }

    unsigned int nBits = 0;
    if (params.size() != 0) {
        CBigNum bnTarget(uint256(params[0].get_str()));
        nBits = bnTarget.GetCompact();
    } else
        nBits = diff::spacing::GetNextTargetRequired(block_info::pindexBest, false);

    return (uint64_t)diff::reward::GetProofOfWorkReward(nBits);
}

json_spirit::Value CRPCTable::getmininginfo(const json_spirit::Array &params, bool fHelp) {
    if (fHelp || params.size() != 0) {
        throw std::runtime_error(
            "getmininginfo\n"
            "Returns an object containing mining-related information.");
    }

    json_spirit::Object obj, diff;
    obj.push_back(json_spirit::Pair("blocks", (int)block_info::nBestHeight));
    obj.push_back(json_spirit::Pair("currentblocksize", (uint64_t)block_info::nLastBlockSize));
    obj.push_back(json_spirit::Pair("currentblocktx", (uint64_t)block_info::nLastBlockTx));

    diff.push_back(json_spirit::Pair("proof-of-work", GetDifficulty()));
    diff.push_back(json_spirit::Pair("proof-of-stake", GetDifficulty(diff::spacing::GetLastBlockIndex(block_info::pindexBest, true))));
    diff.push_back(json_spirit::Pair("search-interval", (int)block_info::nLastCoinStakeSearchInterval));
    obj.push_back(json_spirit::Pair("difficulty", diff));

    obj.push_back(json_spirit::Pair("blockvalue", (uint64_t)diff::reward::GetProofOfWorkReward(diff::spacing::GetLastBlockIndex(block_info::pindexBest, false)->get_nBits())));
    obj.push_back(json_spirit::Pair("netmhashps", GetPoWMHashPS()));
    obj.push_back(json_spirit::Pair("netstakeweight", GetPoSKernelPS()));
    obj.push_back(json_spirit::Pair("errors", block_alert::GetWarnings("statusbar")));
    obj.push_back(json_spirit::Pair("pooledtx", (uint64_t)CTxMemPool::mempool.size()));

    obj.push_back(json_spirit::Pair("stakeinputs", (uint64_t)miner::nStakeInputsMapSize));
    obj.push_back(json_spirit::Pair("stakeinterest", diff::reward::GetProofOfStakeReward(0, diff::spacing::GetLastBlockIndex(block_info::pindexBest, true)->get_nBits(), diff::spacing::GetLastBlockIndex(block_info::pindexBest, true)->get_nTime(), true)));

    obj.push_back(json_spirit::Pair("testnet", (bool)args_bool::fTestNet));

    return obj;
}

// scaninput '{"txid":"95d640426fe66de866a8cf2d0601d2c8cf3ec598109b4d4ffa7fd03dad6d35ce","difficulty":0.01, "days":10}'
json_spirit::Value CRPCTable::scaninput(const json_spirit::Array &params, bool fHelp) {
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            "scaninput '{\"txid\":\"txid\", \"vout\":[vout1, vout2, ..., voutN], \"difficulty\":difficulty, \"days\":days}'\n"
            "Scan specified transaction or input for suitable kernel solutions.\n"
            "    difficulty - upper limit for difficulty, current difficulty by default;\n"
            "    days - time window, 90 days by default.\n"
        );
    }

    bitrpc::RPCTypeCheck(params, boost::assign::list_of(json_spirit::obj_type));

    json_spirit::Object scanParams = params[0].get_obj();
    const json_spirit::Value &txid_v = find_value(scanParams, "txid");
    if (txid_v.type() != json_spirit::str_type)
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing txid key");

    std::string txid = txid_v.get_str();
    if (! strenc::IsHex(txid))
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected hex txid");

    uint256 hash(txid);
    int32_t nDays = 90;
    uint32_t nBits = diff::spacing::GetNextTargetRequired(block_info::pindexBest, true);
    const json_spirit::Value &diff_v = find_value(scanParams, "difficulty");
    if (diff_v.type() == json_spirit::real_type || diff_v.type() == json_spirit::int_type) {
        double dDiff = diff_v.get_real();
        if (dDiff <= 0)
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, diff must be greater than zero");

        CBigNum bnTarget(diff::nPoWBase);
        bnTarget *= 1000;
        bnTarget /= (int) (dDiff * 1000);
        nBits = bnTarget.GetCompact();
    }

    const json_spirit::Value &days_v = find_value(scanParams, "days");
    if (days_v.type() == json_spirit::int_type) {
        nDays = days_v.get_int();
        if (nDays <= 0)
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, interval length must be greater than zero");
    }

    CTransaction tx;
    uint256 hashBlock = 0;
    if (block_transaction::manage::GetTransaction(hash, tx, hashBlock)) {
        if (hashBlock == 0)
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to find transaction in the blockchain");

        std::vector<int> vInputs(0);
        const json_spirit::Value &inputs_v = find_value(scanParams, "vout");
        if (inputs_v.type() == json_spirit::array_type) {
            json_spirit::Array inputs = inputs_v.get_array();
            for(const json_spirit::Value &v_out: inputs) {
                int nOut = v_out.get_int();
                if (nOut < 0 || nOut > (int)tx.get_vout().size() - 1) {
                    std::stringstream strErrorMsg;
                    strErrorMsg << boost::format("Invalid parameter, input number %d is out of range") % nOut;
                    throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, strErrorMsg.str());
                }
                vInputs.push_back(nOut);
            }
        } else if(inputs_v.type() == json_spirit::int_type) {
            int nOut = inputs_v.get_int();
            if (nOut < 0 || nOut > (int)tx.get_vout().size() - 1) {
                std::stringstream strErrorMsg;
                strErrorMsg << boost::format("Invalid parameter, input number %d is out of range") % nOut;
                throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, strErrorMsg.str());
            }
            vInputs.push_back(nOut);
        } else {
            for (size_t i = 0; i != tx.get_vout().size(); ++i)
                vInputs.push_back(i);
        }

        CTxDB txdb("r");
        CBlock block;
        CTxIndex txindex;

        // Load transaction index item
        if (! txdb.ReadTxIndex(tx.GetHash(), txindex))
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to read block index item");

        // Read block header
        if (! block.ReadFromDisk(txindex.get_pos().get_nFile(), txindex.get_pos().get_nBlockPos(), false))
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "CBlock::ReadFromDisk() failed");

        uint64_t nStakeModifier = 0;
        if (! bitkernel::GetKernelStakeModifier(block.GetPoHash(), nStakeModifier))
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No kernel stake modifier generated yet");

        std::pair<uint32_t, uint32_t> interval;
        interval.first = bitsystem::GetTime();

        // Only count coins meeting min age requirement
        if (block_check::nStakeMinAge + block.get_nTime() > interval.first)
            interval.first += (block_check::nStakeMinAge + block.get_nTime() - interval.first);
        interval.second = interval.first + nDays * util::nOneDay;

        json_spirit::Array results;
        for(const int &nOut: vInputs) {
            // Check for spent flag
            // It doesn't make sense to scan spent inputs.
            if (! txindex.get_vSpent(nOut).IsNull())
                continue;

            // Skip zero value outputs
            if (tx.get_vout(nOut).get_nValue() == 0)
                continue;

            // Build static part of kernel
            CDataStream ssKernel;
            ssKernel << nStakeModifier;
            ssKernel << block.get_nTime() << (txindex.get_pos().get_nTxPos() - txindex.get_pos().get_nBlockPos()) << tx.get_nTime() << nOut;
            CDataStream::const_iterator itK = ssKernel.begin();
            std::vector<std::pair<uint256, uint32_t> > result;
            if (bitkernel::ScanKernelForward((unsigned char *)&itK[0], nBits, tx.get_nTime(), tx.get_vout(nOut).get_nValue(), interval, result)) {
                for(const std::pair<uint256, uint32_t> solution: result) {
                    json_spirit::Object item;
                    item.push_back(json_spirit::Pair("nout", nOut));
                    item.push_back(json_spirit::Pair("hash", solution.first.GetHex()));
                    item.push_back(json_spirit::Pair("time", util::DateTimeStrFormat(solution.second)));
                    results.push_back(item);
                }
            }
        }
        if (results.size() == 0)
            return false;

        return results;
    } else
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");
}

json_spirit::Value CRPCTable::getworkex(const json_spirit::Array &params, bool fHelp) {
    using mapNewBlock_t = std::map<uint256, std::pair<CBlock *, CScript> >;
    static mapNewBlock_t mapNewBlock;
    static std::vector<CBlock *> vNewBlock;
    static CReserveKey reservekey(entry::pwalletMain);

    if (fHelp || params.size() > 2) {
        throw std::runtime_error(
            "getworkex [data, coinbase]\n"
            "If [data, coinbase] is not specified, returns extended work data.\n"
        );
    }

    LOCK(CRPCTable::cs_getwork);
    if (net_node::vNodes.empty())
        throw bitjson::JSONRPCError(-9, strCoinName " is not connected!");
    if (block_notify::IsInitialBlockDownload())
        throw bitjson::JSONRPCError(-10, strCoinName " is downloading blocks...");
    if (params.size() == 0) {
        // Update block
        static unsigned int nTransactionsUpdatedLast = 0;
        static CBlockIndex *pindexPrev = nullptr;
        static int64_t nStart = 0;
        static CBlock *pblock = nullptr;

        if (pindexPrev != block_info::pindexBest || (block_info::nTransactionsUpdated != nTransactionsUpdatedLast && bitsystem::GetTime() - nStart > 60)) {
            if (pindexPrev != block_info::pindexBest) {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
                for(CBlock *pblock: vNewBlock)
                    delete pblock;
                vNewBlock.clear();
            }

            nTransactionsUpdatedLast = block_info::nTransactionsUpdated;
            pindexPrev = block_info::pindexBest;
            nStart = bitsystem::GetTime();

            // Create new block
            pblock = miner::CreateNewBlock(entry::pwalletMain);
            if (! pblock)
                throw bitjson::JSONRPCError(-7, "Out of memory");
            vNewBlock.push_back(pblock);
        }

        // Update nTime
        pblock->set_nTime(std::max(pindexPrev->GetMedianTimePast()+1, bitsystem::GetAdjustedTime()));
        pblock->set_nNonce(0);

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;
        miner::IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->get_hashMerkleRoot()] = std::make_pair(pblock, pblock->get_vtx(0).get_vin(0).get_scriptSig());

        // Prebuild hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        miner::FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        uint256 hashTarget = CBigNum().SetCompact(pblock->get_nBits()).getuint256();
        CTransaction coinbaseTx = pblock->get_vtx(0);
        auto merkle = pblock->GetMerkleBranch(0);
        json_spirit::Object result;
        result.push_back(json_spirit::Pair("data",     util::HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(json_spirit::Pair("target",   util::HexStr(BEGIN(hashTarget), END(hashTarget))));

        CDataStream ssTx;
        ssTx << coinbaseTx;
        result.push_back(json_spirit::Pair("coinbase", util::HexStr(ssTx.begin(), ssTx.end())));
        json_spirit::Array merkle_arr;
        for(uint256 merkleh: merkle)
            merkle_arr.push_back(util::HexStr(BEGIN(merkleh), END(merkleh)));

        result.push_back(json_spirit::Pair("merkle", merkle_arr));
        return result;
    } else {
        // Parse parameters
        std::string str = params[0].get_str();
        rpctable_vector vchData = strenc::ParseHex(str);
        rpctable_vector coinbase;
        if(params.size() == 2) {
            str = params[1].get_str();
            coinbase = strenc::ParseHex(str);
        }
        if (vchData.size() != 128)
            throw bitjson::JSONRPCError(-8, "Invalid parameter");

        CBlockHeader *pdata = (CBlockHeader *)&vchData[0];

        // Byte reverse
        for (int i = 0; i < 128 / 4; ++i)
            ((unsigned int *)pdata)[i] = util::ByteReverse(((unsigned int *)pdata)[i]);

        // Get saved block
        if (! mapNewBlock.count(pdata->get_hashMerkleRoot()))
            return false;

        CBlock *pblock = mapNewBlock[pdata->get_hashMerkleRoot()].first;
        pblock->set_nTime(pdata->get_nTime());
        pblock->set_nNonce(pdata->get_nNonce());
        if(coinbase.size() == 0)
            pblock->set_vtx(0).set_vin(0).set_scriptSig(mapNewBlock[pdata->get_hashMerkleRoot()].second);
        else {
            // check vtx size
            CTransaction ctx;
            CDataStream(coinbase, SER_NETWORK, version::PROTOCOL_VERSION) >> ctx; // [OK] FIXME - HACK!
            pblock->set_vtx(0) = ctx;
        }

        pblock->set_hashMerkleRoot(pblock->BuildMerkleTree());
        return miner::CheckWork(pblock, *entry::pwalletMain, reservekey);
    }
}

json_spirit::Value CRPCTable::getwork(const json_spirit::Array &params, bool fHelp) {
    using mapNewBlock_t = std::map<uint256, std::pair<CBlock *, CScript> >;
    static mapNewBlock_t mapNewBlock;
    static std::vector<CBlock *> vNewBlock;
    static CReserveKey reservekey(entry::pwalletMain);

    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "getwork [data]\n"
            "If [data] is not specified, returns formatted hash data to work on:\n"
            "  \"midstate\" : precomputed hash state after hashing the first half of the data (DEPRECATED)\n" // deprecated
            "  \"data\" : block data\n"
            "  \"hash1\" : formatted hash buffer for second hash (DEPRECATED)\n" // deprecated
            "  \"target\" : little endian hash target\n"
            "If [data] is specified, tries to solve the block and returns true if it was successful.");
    }

    LOCK(CRPCTable::cs_getwork);
    if (net_node::vNodes.empty())
        throw bitjson::JSONRPCError(RPC_CLIENT_NOT_CONNECTED, strCoinName " is not connected!");
    if (block_notify::IsInitialBlockDownload())
        throw bitjson::JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, strCoinName " is downloading blocks...");
    if (params.size() == 0) {
        // Update block
        static unsigned int nTransactionsUpdatedLast = 0;
        static CBlockIndex *pindexPrev = nullptr;
        static int64_t nStart = 0;
        static CBlock *pblock = nullptr;

        if (pindexPrev != block_info::pindexBest ||
           (block_info::nTransactionsUpdated != nTransactionsUpdatedLast && bitsystem::GetTime() - nStart > 60)) {
            if (pindexPrev != block_info::pindexBest) {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
                for(CBlock *pblock: vNewBlock)
                    delete pblock;
                vNewBlock.clear();
            }

            // Clear pindexPrev so future getworks make a new block, despite any failures from here on
            pindexPrev = nullptr;

            // Store the block_info::pindexBest used before miner::CreateNewBlock, to avoid races
            nTransactionsUpdatedLast = block_info::nTransactionsUpdated;
            CBlockIndex *pindexPrevNew = block_info::pindexBest;
            nStart = bitsystem::GetTime();

            // Create new block
            //logging::LogPrintf("ThreadRPCServer3 getwork new Block\n");
            pblock = miner::CreateNewBlock(entry::pwalletMain);
            if (! pblock)
                return bitjson::JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
            vNewBlock.push_back(pblock);

            // Need to update only after we know miner::CreateNewBlock succeeded
            pindexPrev = pindexPrevNew;
        }

        // Update nTime
        pblock->UpdateTime(pindexPrev);
        pblock->set_nNonce(0);

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;
        miner::IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->get_hashMerkleRoot()] = std::make_pair(pblock, pblock->get_vtx(0).get_vin(0).get_scriptSig());

        // Pre-build hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        miner::FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        uint256 hashTarget = CBigNum().SetCompact(pblock->get_nBits()).getuint256();
        json_spirit::Object result;
        result.push_back(json_spirit::Pair("midstate", util::HexStr(BEGIN(pmidstate), END(pmidstate)))); // deprecated
        result.push_back(json_spirit::Pair("data",     util::HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(json_spirit::Pair("hash1",    util::HexStr(BEGIN(phash1), END(phash1)))); // deprecated
        result.push_back(json_spirit::Pair("target",   util::HexStr(BEGIN(hashTarget), END(hashTarget))));
        return result;
    } else {
        // Parse parameters
        std::string str = params[0].get_str();
        rpctable_vector vchData = strenc::ParseHex(str);
        if (vchData.size() != 128)
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");

        CBlockHeader *pdata = (CBlockHeader *)&vchData[0];

        // Byte reverse
        for (int i = 0; i < 128 / 4; ++i)
            ((unsigned int *)pdata)[i] = util::ByteReverse(((unsigned int *)pdata)[i]);

        // Get saved block
        if (! mapNewBlock.count(pdata->get_hashMerkleRoot()))
            return false;

        CBlock *pblock = mapNewBlock[pdata->get_hashMerkleRoot()].first;
        pblock->set_nTime(pdata->get_nTime());
        pblock->set_nNonce(pdata->get_nNonce());
        pblock->set_vtx(0).set_vin(0).set_scriptSig(mapNewBlock[pdata->get_hashMerkleRoot()].second);
        pblock->set_hashMerkleRoot(pblock->BuildMerkleTree());
        return miner::CheckWork(pblock, *entry::pwalletMain, reservekey);
    }
}

using mapGbtNewBlock_t = std::map<uint256, std::pair<CBlock *, CScript> >;
static mapGbtNewBlock_t mapGbtNewBlock;
json_spirit::Value CRPCTable::getblocktemplate(const json_spirit::Array &params, bool fHelp) {
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "getblocktemplate [params]\n"
            "Returns data needed to construct a block to work on:\n"
            "  \"version\" : block version\n"
            "  \"previousblockhash\" : hash of current highest block\n"
            "  \"transactions\" : contents of non-coinbase transactions that should be included in the next block\n"
            "  \"coinbaseaux\" : data that should be included in coinbase\n"
            "  \"coinbasevalue\" : maximum allowable input to coinbase transaction, including the generation award and transaction fees\n"
            "  \"target\" : hash target\n"
            "  \"mintime\" : minimum timestamp appropriate for next block\n"
            "  \"curtime\" : current timestamp\n"
            "  \"mutable\" : list of ways the block template may be changed\n"
            "  \"noncerange\" : range of valid nonces\n"
            "  \"sigoplimit\" : limit of sigops in blocks\n"
            "  \"sizelimit\" : limit of block size\n"
            "  \"bits\" : compressed target of next block\n"
            "  \"height\" : height of the next block\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");
    }

    LOCK(CRPCTable::cs_getwork);

    //
    // bip0022 bip0023: Getblocktemplate capabilities flags
    // Note: when mining getblocktemplate, submitblock require "CTransaction txCoinbase vtx[0]".
    // capabilities contains "conbasetxn", Getblocktemplate in result require Hex of "txCoinbase".
    // Acctually, this logic receive RPC in submitblock, but vtx[0] is empty, result in rejected, then "boo".
    // ref: https://en.bitcoin.it/wiki/Getblocktemplate
    // ref: https://en.bitcoin.it/wiki/BIP_0023
    //
    /*
    auto is_bip0023 = [&](){
        const json_spirit::Object &oparam = params[0].get_obj();
        for(const auto &od: oparam) { // checking ... capabilities [bip0023: "coinbasetxn", "workid"]
            debugcs::instance() << "Bip0023 getblocktemplate param: " << od.name_.c_str() << debugcs::endl();
            if(od.value_.type()==json_spirit::array_type) {
                const json_spirit::Array &aod = od.value_.get_array();
                for(const auto &bod: aod) {
                    const std::string &str = bod.get_str().c_str();
                    debugcs::instance() << "Bip0023 getblocktemplate attr: " << str.c_str() << debugcs::endl();
                    if(str=="coinbasetxn") {
                        return true;
                    }
                }
            }
        }
        return false;
    };
    */

    if(params.size()==0)
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Getblocktemplate params[0] is NULL.");
    //bool fBip0023 = is_bip0023(); // if false, bip0022
    const bool fBip0023 = true;
    //debugcs::instance() << "Bip0023 flag: " << (int)fBip0023 << debugcs::endl();

    std::string strMode = "template";
    if (params.size() > 0) { // json_spirit::null_type do nothing
        const json_spirit::Object &oparam = params[0].get_obj();
        const json_spirit::Value &modeval = find_value(oparam, "mode");
        if (modeval.type() == json_spirit::str_type) {
            strMode = modeval.get_str();
        } else if (modeval.type() == json_spirit::null_type) {
            /* Do nothing */
        } else
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode 1");
    }
    debugcs::instance() << "Getblocktemplate strMode: " << strMode.c_str() << debugcs::endl();

    if (strMode != "template")
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode 2");
    if (net_node::vNodes.empty())
        throw bitjson::JSONRPCError(RPC_CLIENT_NOT_CONNECTED, strCoinName " is not connected!");
    if (block_notify::IsInitialBlockDownload())
        throw bitjson::JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, strCoinName " is downloading blocks...");

    //static CReserveKey reservekey(entry::pwalletMain);

    // Update block
    static unsigned int nTransactionsUpdatedLast = 0;
    static CBlockIndex *pindexPrev = nullptr;
    static int64_t nStart = 0;
    static CBlock *pblock = nullptr;
    if (pindexPrev != block_info::pindexBest || (block_info::nTransactionsUpdated != nTransactionsUpdatedLast && bitsystem::GetTime() - nStart > 5)) {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = nullptr;

        // Store the block_info::pindexBest used before miner::CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = block_info::nTransactionsUpdated;
        CBlockIndex *pindexPrevNew = block_info::pindexBest;
        nStart = bitsystem::GetTime();

        // Create new block
        if(pblock) {
            mapGbtNewBlock.clear();
            delete pblock;
            pblock = nullptr;
        }

        pblock = miner::CreateNewBlock(entry::pwalletMain);
        if (! pblock)
            throw bitjson::JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know miner::CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }

    // Update nTime
    pblock->UpdateTime(pindexPrev);
    pblock->set_nNonce(0);

    // Update nExtraNonce
    static unsigned int nExtraNonce = 0;
    miner::IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

    // Save
    mapGbtNewBlock[pblock->get_hashMerkleRoot()] = std::make_pair(pblock, pblock->get_vtx(0).get_vin(0).get_scriptSig());

    json_spirit::Array transactions;
    {
        std::map<uint256, int64_t> setTxIndex;
        int i = 0;
        CTxDB txdb("r");
        //std::vector<CTransaction> &vtx = pblock->set_vtx();
        for(CTransaction &tx: pblock->set_vtx()) {
            uint256 txHash = tx.GetHash();
            setTxIndex[txHash] = i++;
            if (tx.IsCoinBase() || tx.IsCoinStake())
                continue;

            json_spirit::Object entry;
            entry.push_back(json_spirit::Pair("data", tx_util::EncodeHexTx(tx)));
            entry.push_back(json_spirit::Pair("hash", txHash.GetHex()));

            MapPrevTx mapInputs;
            std::map<uint256, CTxIndex> mapUnused;
            bool fInvalid = false;
            if (tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid)) {
                entry.push_back(json_spirit::Pair("fee", (int64_t)(tx.GetValueIn(mapInputs) - tx.GetValueOut())));
                json_spirit::Array deps;
                for(MapPrevTx::value_type &inp: mapInputs) {
                    if (setTxIndex.count(inp.first))
                        deps.push_back(setTxIndex[inp.first]);
                }
                entry.push_back(json_spirit::Pair("depends", deps));

                int64_t nSigOps = tx.GetLegacySigOpCount();
                nSigOps += tx.GetP2SHSigOpCount(mapInputs);
                entry.push_back(json_spirit::Pair("sigops", nSigOps));
            }

            transactions.push_back(entry);
        }
    }

    json_spirit::Array coinbasetxn;
    if(fBip0023) {
        std::map<uint256, int64_t> setTxIndex;
        int j = 0;
        CTxDB txdb("r");
        for (CTransaction &tx: pblock->set_vtx()) {
            if(tx.IsCoinBase()){
                debugcs::instance() << "bip23 coinbase tx" << debugcs::endl();
                uint256 txHash = tx.GetHash();
                setTxIndex[txHash] = j++;

                json_spirit::Object entry;
                entry.push_back(json_spirit::Pair("data", tx_util::EncodeHexTx(tx)));
                entry.push_back(json_spirit::Pair("hash", txHash.GetHex()));

                json_spirit::Array deps;
                for (const CTxIn &in: tx.get_vin()) {
                    if (setTxIndex.count(in.get_prevout().get_hash()))
                        deps.push_back(setTxIndex[in.get_prevout().get_hash()]);
                }
                entry.push_back(json_spirit::Pair("depends", deps));

                MapPrevTx mapInputs;
                std::map<uint256, CTxIndex> mapUnused;
                bool fInvalid = false;
                if (tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid)) {
                    debugcs::instance() << "bip23 coinbase tx FetchInputs" << debugcs::endl();
                    entry.push_back(json_spirit::Pair("fee", (int64_t)(tx.GetValueIn(mapInputs) - tx.GetValueOut())));

                    int64_t nSigOps = tx.GetLegacySigOpCount();
                    nSigOps += tx.GetP2SHSigOpCount(mapInputs);
                    entry.push_back(json_spirit::Pair("sigops", nSigOps));
                }

                coinbasetxn.push_back(entry);
            }
        }
    }

    json_spirit::Object aux;
    aux.push_back(json_spirit::Pair("flags", util::HexStr(block_info::COINBASE_FLAGS.begin(), block_info::COINBASE_FLAGS.end())));

    uint256 hashTarget = CBigNum().SetCompact(pblock->get_nBits()).getuint256();
    static json_spirit::Array aMutable;
    if (aMutable.empty()) {
        aMutable.push_back("time");
        aMutable.push_back("transactions");
        aMutable.push_back("prevblock");
    }

    json_spirit::Object result;
    result.push_back(json_spirit::Pair("version", pblock->get_nVersion()));
    result.push_back(json_spirit::Pair("previousblockhash", pblock->get_hashPrevBlock().GetHex()));
    result.push_back(json_spirit::Pair("transactions", transactions));
    result.push_back(json_spirit::Pair("coinbaseaux", aux));
    result.push_back(json_spirit::Pair("coinbasevalue", (int64_t)pblock->get_vtx(0).get_vout(0).get_nValue()));
    result.push_back(json_spirit::Pair("target", hashTarget.GetHex()));
    result.push_back(json_spirit::Pair("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1));
    result.push_back(json_spirit::Pair("mutable", aMutable));
    result.push_back(json_spirit::Pair("noncerange", "00000000ffffffff"));
    result.push_back(json_spirit::Pair("sigoplimit", (int64_t)block_params::MAX_BLOCK_SIGOPS));
    result.push_back(json_spirit::Pair("sizelimit", (int64_t)block_params::MAX_BLOCK_SIZE));
    result.push_back(json_spirit::Pair("curtime", (int64_t)pblock->get_nTime()));
    result.push_back(json_spirit::Pair("bits", HexBits(pblock->get_nBits())));
    result.push_back(json_spirit::Pair("height", (int64_t)(pindexPrev->get_nHeight()+1)));

    if(fBip0023) {
        result.push_back(json_spirit::Pair("coinbasetxn", coinbasetxn[0])); // coinbase is only [0]
    }

    return result;
}

json_spirit::Value CRPCTable::submitblock(const json_spirit::Array &params, bool fHelp) {
    if (fHelp || params.size() < 1 || params.size() > 2) {
        throw std::runtime_error(
            "submitblock <hex data> [optional-params-obj]\n"
            "[optional-params-obj] parameter is currently ignored.\n"
            "Attempts to submit new block to network.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");
    }

    LOCK(CRPCTable::cs_getwork);

    std::string hex = params[0].get_str();
    if(hex.size() < 2*80) {
        return false;
    }

    // CBlockHeader
    std::string header_hex = hex.substr(0, 2*80);
    CDataStream ssBlockHeader(strenc::ParseHex(header_hex), SER_NETWORK, version::PROTOCOL_VERSION);
    CBlockHeader blockheader;
    try {
        ssBlockHeader >> blockheader;
    } catch (const std::exception &) {
        return false;
    }

    // CTransactionVch
    std::string txs_hex = hex.substr(2*80);
    CDataStream ssTxs(strenc::ParseHex(txs_hex), SER_NETWORK, version::PROTOCOL_VERSION);
    CTransactionVch txsvch;
    try {
        ssTxs >> txsvch;
    } catch (const std::exception &) {
        return false;
    }

    CBlock block;
    block.set_nVersion(blockheader.get_nVersion());
    block.set_hashPrevBlock(blockheader.get_hashPrevBlock());
    block.set_hashMerkleRoot(blockheader.get_hashMerkleRoot());
    block.set_nTime(blockheader.get_nTime());
    block.set_nBits(blockheader.get_nBits());
    block.set_nNonce(blockheader.get_nNonce());
    block.set_vtx() = txsvch.vtx;

    // debug
    debugcs::instance() << "block: " << block.get_hashMerkleRoot().GetHex() << debugcs::endl();
    for(const auto &d: mapGbtNewBlock)
        debugcs::instance() << "mapBlock: " << d.second.first->get_hashMerkleRoot().GetHex() << debugcs::endl();

    // reward (coinbase)
    if(block.get_vtx(0).get_vout().size()==0) {
        CTransaction txCoinBase;
        txCoinBase.set_vin().resize(1);
        txCoinBase.set_vin(0).set_prevout().SetNull();
        txCoinBase.set_vout().resize(1);
        CReserveKey reservekey(entry::pwalletMain);
        txCoinBase.set_vout(0).set_scriptPubKey().SetDestination(reservekey.GetReservedKey().GetID());
        block.set_vtx().clear();
        block.set_vtx().push_back(txCoinBase);
        block.set_vtx(0).set_vout(0).set_nValue(diff::reward::GetProofOfWorkReward(block.get_nBits(), 0));
        return false;
    }

    static CReserveKey reservekey(entry::pwalletMain);
    bool fAccepted = miner::CheckWork(&block, *entry::pwalletMain, reservekey);
    if (! fAccepted) {
        return false;
    }

    return json_spirit::Value::null;
}

/*
json_spirit::Value CRPCTable::submitblock(const json_spirit::Array &params, bool fHelp) {
    if (fHelp || params.size() < 1 || params.size() > 2) {
        throw std::runtime_error(
            "submitblock <hex data> [optional-params-obj]\n"
            "[optional-params-obj] parameter is currently ignored.\n"
            "Attempts to submit new block to network.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");
    }

    LOCK(CRPCTable::cs_getwork);

    //if(! args_bool::fTestNet) {
    //    return false; // checking testnet
    //}

    std::string hex = params[0].get_str();
    if(hex.size() < 2*80) {
        return false;
        //throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "rejected");
        //throw bitjson::JSONRPCError(RPC_DESERIALIZATION_ERROR, "invalid size");
    }

    std::string header_hex = hex.substr(0, 2*80);
    CDataStream ssBlockHeader(strenc::ParseHex(header_hex), SER_NETWORK, version::PROTOCOL_VERSION);
    CBlockHeader blockheader;
    try {
        ssBlockHeader >> blockheader;
    } catch (const std::exception &) {
        return false;
        //throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "rejected");
        //throw bitjson::JSONRPCError(RPC_DESERIALIZATION_ERROR, "BlockHeader decode failed");
    }

    CBlockHeader *pdata = &blockheader;

    // debug
    debugcs::instance() << pdata->get_hashMerkleRoot().GetHex() << debugcs::endl();
    for(const auto &d: mapGbtNewBlock)
        debugcs::instance() << d.second.first->get_hashMerkleRoot().GetHex() << debugcs::endl();

    // Get saved block
    if (! mapGbtNewBlock.count(pdata->get_hashMerkleRoot())) {
        return false;
        //throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "rejected");
    }

    CBlock *pblock = mapGbtNewBlock[pdata->get_hashMerkleRoot()].first;
    pblock->set_nTime(pdata->get_nTime());
    pblock->set_nNonce(pdata->get_nNonce());
    pblock->set_vtx(0).set_vin(0).set_scriptSig(mapGbtNewBlock[pdata->get_hashMerkleRoot()].second);
    pblock->set_hashMerkleRoot(pblock->BuildMerkleTree());

    // reward (coinbase)
    if(pblock->get_vtx(0).get_vout().size()==0) {
        CTransaction txCoinBase;
        txCoinBase.set_vin().resize(1);
        txCoinBase.set_vin(0).set_prevout().SetNull();
        txCoinBase.set_vout().resize(1);
        CReserveKey reservekey(entry::pwalletMain);
        txCoinBase.set_vout(0).set_scriptPubKey().SetDestination(reservekey.GetReservedKey().GetID());
        pblock->set_vtx().clear();
        pblock->set_vtx().push_back(txCoinBase);
        pblock->set_vtx(0).set_vout(0).set_nValue(diff::reward::GetProofOfWorkReward(pblock->get_nBits(), 0));
        return false;
        //throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "rejected");
    }

    static CReserveKey reservekey(entry::pwalletMain);
    bool fAccepted = miner::CheckWork(pblock, *entry::pwalletMain, reservekey);
    if (! fAccepted) {
        return false;
        //throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "rejected");
    }

    //debugcs::instance() << "submitblock: accepted" << debugcs::endl();
    return json_spirit::Value::null;
}
*/

/*
// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <main.h>
#include <db.h>
#include <txdb.h>
#include <init.h>
#include <miner.h>
#include <kernel.h>
#include <rpc/bitcoinrpc.h>
#include <block/block_process.h>
#include <miner/diff.h>
#include <block/block_alert.h>
#include <boost/format.hpp>
#include <boost/assign/list_of.hpp>
#include <util/strencodings.h>

json_spirit::Value CRPCTable::getsubsidy(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "getsubsidy [nTarget]\n"
            "Returns proof-of-work subsidy value for the specified value of target.");
    }

    unsigned int nBits = 0;

    if (params.size() != 0) {
        CBigNum bnTarget(uint256(params[0].get_str()));
        nBits = bnTarget.GetCompact();
    } else {
        nBits = diff::spacing::GetNextTargetRequired(block_info::pindexBest, false);
    }

    return (uint64_t)diff::reward::GetProofOfWorkReward(nBits);
}

json_spirit::Value CRPCTable::getmininginfo(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 0) {
        throw std::runtime_error(
            "getmininginfo\n"
            "Returns an object containing mining-related information.");
    }

    json_spirit::Object obj, diff;
    obj.push_back(json_spirit::Pair("blocks", (int)block_info::nBestHeight));
    obj.push_back(json_spirit::Pair("currentblocksize", (uint64_t)block_info::nLastBlockSize));
    obj.push_back(json_spirit::Pair("currentblocktx", (uint64_t)block_info::nLastBlockTx));

    diff.push_back(json_spirit::Pair("proof-of-work", GetDifficulty()));
    diff.push_back(json_spirit::Pair("proof-of-stake", GetDifficulty(diff::spacing::GetLastBlockIndex(block_info::pindexBest, true))));
    diff.push_back(json_spirit::Pair("search-interval", (int)block_info::nLastCoinStakeSearchInterval));
    obj.push_back(json_spirit::Pair("difficulty", diff));

    obj.push_back(json_spirit::Pair("blockvalue", (uint64_t)diff::reward::GetProofOfWorkReward(diff::spacing::GetLastBlockIndex(block_info::pindexBest, false)->get_nBits())));
    obj.push_back(json_spirit::Pair("netmhashps", GetPoWMHashPS()));
    obj.push_back(json_spirit::Pair("netstakeweight", GetPoSKernelPS()));
    obj.push_back(json_spirit::Pair("errors", block_alert::GetWarnings("statusbar")));
    obj.push_back(json_spirit::Pair("pooledtx", (uint64_t)CTxMemPool::mempool.size()));

    obj.push_back(json_spirit::Pair("stakeinputs", (uint64_t)miner::nStakeInputsMapSize));
    obj.push_back(json_spirit::Pair("stakeinterest", diff::reward::GetProofOfStakeReward(0, diff::spacing::GetLastBlockIndex(block_info::pindexBest, true)->get_nBits(), diff::spacing::GetLastBlockIndex(block_info::pindexBest, true)->get_nTime(), true)));

    obj.push_back(json_spirit::Pair("testnet", (bool)args_bool::fTestNet));
    return obj;
}

// scaninput '{"txid":"95d640426fe66de866a8cf2d0601d2c8cf3ec598109b4d4ffa7fd03dad6d35ce","difficulty":0.01, "days":10}'
json_spirit::Value CRPCTable::scaninput(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            "scaninput '{\"txid\":\"txid\", \"vout\":[vout1, vout2, ..., voutN], \"difficulty\":difficulty, \"days\":days}'\n"
            "Scan specified transaction or input for suitable kernel solutions.\n"
            "    difficulty - upper limit for difficulty, current difficulty by default;\n"
            "    days - time window, 90 days by default.\n"
        );
    }

    bitrpc::RPCTypeCheck(params, boost::assign::list_of(json_spirit::obj_type));

    json_spirit::Object scanParams = params[0].get_obj();

    const json_spirit::Value &txid_v = find_value(scanParams, "txid");
    if (txid_v.type() != json_spirit::str_type) {
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing txid key");
    }

    std::string txid = txid_v.get_str();
    if (! strenc::IsHex(txid)) {
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected hex txid");
    }

    uint256 hash(txid);
    int32_t nDays = 90;
    uint32_t nBits = diff::spacing::GetNextTargetRequired(block_info::pindexBest, true);

    const json_spirit::Value &diff_v = find_value(scanParams, "difficulty");
    if (diff_v.type() == json_spirit::real_type || diff_v.type() == json_spirit::int_type) {
        double dDiff = diff_v.get_real();
        if (dDiff <= 0) {
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, diff must be greater than zero");
        }

        CBigNum bnTarget(diff::nPoWBase);
        bnTarget *= 1000;
        bnTarget /= (int) (dDiff * 1000);
        nBits = bnTarget.GetCompact();
    }

    const json_spirit::Value &days_v = find_value(scanParams, "days");
    if (days_v.type() == json_spirit::int_type) {
        nDays = days_v.get_int();
        if (nDays <= 0) {
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, interval length must be greater than zero");
        }
    }

    CTransaction tx;
    uint256 hashBlock = 0;
    if (block_transaction::manage::GetTransaction(hash, tx, hashBlock)) {
        if (hashBlock == 0) {
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to find transaction in the blockchain");
        }

        std::vector<int> vInputs(0);
        const json_spirit::Value &inputs_v = find_value(scanParams, "vout");
        if (inputs_v.type() == json_spirit::array_type) {
            json_spirit::Array inputs = inputs_v.get_array();
            for(const json_spirit::Value &v_out: inputs)
            {
                int nOut = v_out.get_int();
                if (nOut < 0 || nOut > (int)tx.get_vout().size() - 1) {
                    std::stringstream strErrorMsg;
                    strErrorMsg << boost::format("Invalid parameter, input number %d is out of range") % nOut;
                    throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, strErrorMsg.str());
                }

                vInputs.push_back(nOut);
            }
        } else if(inputs_v.type() == json_spirit::int_type) {
            int nOut = inputs_v.get_int();
            if (nOut < 0 || nOut > (int)tx.get_vout().size() - 1) {
                std::stringstream strErrorMsg;
                strErrorMsg << boost::format("Invalid parameter, input number %d is out of range") % nOut;
                throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, strErrorMsg.str());
            }

            vInputs.push_back(nOut);
        } else {
            for (size_t i = 0; i != tx.get_vout().size(); ++i)
            {
                vInputs.push_back(i);
            }
        }

        CTxDB txdb("r");

        CBlock block;
        CTxIndex txindex;

        // Load transaction index item
        if (! txdb.ReadTxIndex(tx.GetHash(), txindex)) {
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to read block index item");
        }

        // Read block header
        if (! block.ReadFromDisk(txindex.get_pos().get_nFile(), txindex.get_pos().get_nBlockPos(), false)) {
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "CBlock::ReadFromDisk() failed");
        }

        uint64_t nStakeModifier = 0;
        if (! bitkernel::GetKernelStakeModifier(block.GetPoHash(), nStakeModifier)) {
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No kernel stake modifier generated yet");
        }

        std::pair<uint32_t, uint32_t> interval;
        interval.first = bitsystem::GetTime();

        //
        // Only count coins meeting min age requirement
        //
        if (block_check::nStakeMinAge + block.get_nTime() > interval.first) {
            interval.first += (block_check::nStakeMinAge + block.get_nTime() - interval.first);
        }
        interval.second = interval.first + nDays * util::nOneDay;

        json_spirit::Array results;
        for(const int &nOut: vInputs)
        {
            // Check for spent flag
            // It doesn't make sense to scan spent inputs.
            if (! txindex.get_vSpent(nOut).IsNull()) {
                continue;
            }

            // Skip zero value outputs
            if (tx.get_vout(nOut).get_nValue() == 0) {
                continue;
            }

            // Build static part of kernel
            CDataStream ssKernel(SER_GETHASH, 0);
            ssKernel << nStakeModifier;
            ssKernel << block.get_nTime() << (txindex.get_pos().get_nTxPos() - txindex.get_pos().get_nBlockPos()) << tx.get_nTime() << nOut;
            CDataStream::const_iterator itK = ssKernel.begin();

            std::vector<std::pair<uint256, uint32_t> > result;
            if (bitkernel::ScanKernelForward((unsigned char *)&itK[0], nBits, tx.get_nTime(), tx.get_vout(nOut).get_nValue(), interval, result)) {
                for(const std::pair<uint256, uint32_t> solution: result)
                {
                    json_spirit::Object item;
                    item.push_back(json_spirit::Pair("nout", nOut));
                    item.push_back(json_spirit::Pair("hash", solution.first.GetHex()));
                    item.push_back(json_spirit::Pair("time", util::DateTimeStrFormat(solution.second)));

                    results.push_back(item);
                }
            }
        }

        if (results.size() == 0) {
            return false;
        }

        return results;
    } else {
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");
    }
}

json_spirit::Value CRPCTable::getworkex(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 2) {
        throw std::runtime_error(
            "getworkex [data, coinbase]\n"
            "If [data, coinbase] is not specified, returns extended work data.\n"
        );
    }

    if (net_node::vNodes.empty()) {
        throw bitjson::JSONRPCError(-9, (std::string(strCoinName) + " is not connected!").c_str());
    }

    if (block_notify::IsInitialBlockDownload()) {
        throw bitjson::JSONRPCError(-10, (std::string(strCoinName) + " is downloading blocks...").c_str());
    }

    typedef std::map<uint256, std::pair<CBlock *, CScript> > mapNewBlock_t;
    static mapNewBlock_t mapNewBlock;
    static std::vector<CBlock *> vNewBlock;
    static CReserveKey reservekey(entry::pwalletMain);

    if (params.size() == 0) {
        //
        // Update block
        //
        static unsigned int nTransactionsUpdatedLast = 0;
        static CBlockIndex *pindexPrev = nullptr;
        static int64_t nStart = 0;
        static CBlock *pblock = nullptr;

        if (pindexPrev != block_info::pindexBest || (block_info::nTransactionsUpdated != nTransactionsUpdatedLast && bitsystem::GetTime() - nStart > 60)) {
            if (pindexPrev != block_info::pindexBest) {
                //
                // Deallocate old blocks since they're obsolete now
                //
                mapNewBlock.clear();
                for(CBlock *pblock: vNewBlock)
                {
                    delete pblock;
                }
                vNewBlock.clear();
            }

            nTransactionsUpdatedLast = block_info::nTransactionsUpdated;
            pindexPrev = block_info::pindexBest;
            nStart = bitsystem::GetTime();

            //
            // Create new block
            //
            pblock = miner::CreateNewBlock(entry::pwalletMain);
            if (! pblock) {
                throw bitjson::JSONRPCError(-7, "Out of memory");
            }
            vNewBlock.push_back(pblock);
        }

        // Update nTime
        pblock->set_nTime(std::max(pindexPrev->GetMedianTimePast()+1, bitsystem::GetAdjustedTime()));
        pblock->set_nNonce(0);

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;
        miner::IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->get_hashMerkleRoot()] = std::make_pair(pblock, pblock->get_vtx(0).get_vin(0).get_scriptSig());

        // Prebuild hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        miner::FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        uint256 hashTarget = CBigNum().SetCompact(pblock->get_nBits()).getuint256();

        CTransaction coinbaseTx = pblock->get_vtx(0);
        std::vector<uint256> merkle = pblock->GetMerkleBranch(0);

        json_spirit::Object result;
        result.push_back(json_spirit::Pair("data",     util::HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(json_spirit::Pair("target",   util::HexStr(BEGIN(hashTarget), END(hashTarget))));

        CDataStream ssTx(SER_NETWORK, version::PROTOCOL_VERSION);
        ssTx << coinbaseTx;
        result.push_back(json_spirit::Pair("coinbase", util::HexStr(ssTx.begin(), ssTx.end())));

        json_spirit::Array merkle_arr;

        for(uint256 merkleh: merkle)
        {
            merkle_arr.push_back(util::HexStr(BEGIN(merkleh), END(merkleh)));
        }

        result.push_back(json_spirit::Pair("merkle", merkle_arr));
        return result;
    } else {
        //
        // Parse parameters
        //
        strenc::hex_vector vchData = strenc::ParseHex(params[0].get_str());
        strenc::hex_vector coinbase;

        if(params.size() == 2) {
            coinbase = strenc::ParseHex(params[1].get_str());
        }

        if (vchData.size() != 128) {
            throw bitjson::JSONRPCError(-8, "Invalid parameter");
        }

        CBlock *pdata = (CBlock *)&vchData[0];

        // Byte reverse
        for (int i = 0; i < 128 / 4; ++i)
        {
            ((unsigned int *)pdata)[i] = util::ByteReverse(((unsigned int *)pdata)[i]);
        }

        // Get saved block
        if (! mapNewBlock.count(pdata->get_hashMerkleRoot())) {
            return false;
        }
        CBlock *pblock = mapNewBlock[pdata->get_hashMerkleRoot()].first;

        pblock->set_nTime(pdata->get_nTime());
        pblock->set_nNonce(pdata->get_nNonce());

        if(coinbase.size() == 0) {
            pblock->set_vtx(0).set_vin(0).set_scriptSig(mapNewBlock[pdata->get_hashMerkleRoot()].second);
        } else {
            // CDataStream(coinbase, SER_NETWORK, version::PROTOCOL_VERSION) >> pblock->vtx[0]; // FIXME - HACK!
            // check vtx size
            CTransaction ctx;
            CDataStream(coinbase, SER_NETWORK, version::PROTOCOL_VERSION) >> ctx; // [OK] FIXME - HACK!
            pblock->set_vtx(0) = ctx;
        }

        pblock->set_hashMerkleRoot(pblock->BuildMerkleTree());
        return miner::CheckWork(pblock, *entry::pwalletMain, reservekey);
    }
}

json_spirit::Value CRPCTable::getwork(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "getwork [data]\n"
            "If [data] is not specified, returns formatted hash data to work on:\n"
            "  \"midstate\" : precomputed hash state after hashing the first half of the data (DEPRECATED)\n" // deprecated
            "  \"data\" : block data\n"
            "  \"hash1\" : formatted hash buffer for second hash (DEPRECATED)\n" // deprecated
            "  \"target\" : little endian hash target\n"
            "If [data] is specified, tries to solve the block and returns true if it was successful.");
    }

    if (net_node::vNodes.empty()) {
        throw bitjson::JSONRPCError(RPC_CLIENT_NOT_CONNECTED, (std::string(strCoinName) + " is not connected!").c_str());
    }
    if (block_notify::IsInitialBlockDownload()) {
        throw bitjson::JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, (std::string(strCoinName) + " is downloading blocks...").c_str());
    }

    typedef std::map<uint256, std::pair<CBlock *, CScript> > mapNewBlock_t;
    static mapNewBlock_t mapNewBlock;    // FIXME: thread safety
    static std::vector<CBlock *> vNewBlock;
    static CReserveKey reservekey(entry::pwalletMain);

    if (params.size() == 0) {
        //
        // Update block
        //
        static unsigned int nTransactionsUpdatedLast = 0;
        static CBlockIndex *pindexPrev = nullptr;
        static int64_t nStart = 0;
        static CBlock *pblock = nullptr;

        if (pindexPrev != block_info::pindexBest ||
           (block_info::nTransactionsUpdated != nTransactionsUpdatedLast && bitsystem::GetTime() - nStart > 60)) {
            if (pindexPrev != block_info::pindexBest) {
                //
                // Deallocate old blocks since they're obsolete now
                //
                mapNewBlock.clear();
                for(CBlock *pblock: vNewBlock)
                {
                    delete pblock;
                }
                vNewBlock.clear();
            }

            // Clear pindexPrev so future getworks make a new block, despite any failures from here on
            pindexPrev = nullptr;

            // Store the block_info::pindexBest used before miner::CreateNewBlock, to avoid races
            nTransactionsUpdatedLast = block_info::nTransactionsUpdated;
            CBlockIndex* pindexPrevNew = block_info::pindexBest;
            nStart = bitsystem::GetTime();

            // Create new block
            //printf("ThreadRPCServer3 getwork new Block\n");
            pblock = miner::CreateNewBlock(entry::pwalletMain);
            if (! pblock) {
                throw bitjson::JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
            }
            vNewBlock.push_back(pblock);

            // Need to update only after we know miner::CreateNewBlock succeeded
            pindexPrev = pindexPrevNew;
        }

        //printf("ThreadRPCServer3 getwork Save\n");

        // Update nTime
        pblock->UpdateTime(pindexPrev);
        pblock->set_nNonce(0);

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;
        miner::IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->get_hashMerkleRoot()] = std::make_pair(pblock, pblock->get_vtx(0).get_vin(0).get_scriptSig());

        //printf("ThreadRPCServer3 getwork hash\n");

        // Pre-build hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        miner::FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        //printf("ThreadRPCServer3 getwork hash target\n");

        uint256 hashTarget = CBigNum().SetCompact(pblock->get_nBits()).getuint256();

        json_spirit::Object result;
        result.push_back(json_spirit::Pair("midstate", util::HexStr(BEGIN(pmidstate), END(pmidstate)))); // deprecated
        result.push_back(json_spirit::Pair("data",     util::HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(json_spirit::Pair("hash1",    util::HexStr(BEGIN(phash1), END(phash1)))); // deprecated
        result.push_back(json_spirit::Pair("target",   util::HexStr(BEGIN(hashTarget), END(hashTarget))));
        return result;
    } else {
        //
        // Parse parameters
        //
        strenc::hex_vector vchData = strenc::ParseHex(params[0].get_str());
        if (vchData.size() != 128) {
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        }
        CBlock *pdata = (CBlock *)&vchData[0];

        // Byte reverse
        for (int i = 0; i < 128 / 4; ++i)
        {
            ((unsigned int *)pdata)[i] = util::ByteReverse(((unsigned int *)pdata)[i]);
        }

        // Get saved block
        if (! mapNewBlock.count(pdata->get_hashMerkleRoot())) {
            return false;
        }
        CBlock *pblock = mapNewBlock[pdata->get_hashMerkleRoot()].first;

        pblock->set_nTime(pdata->get_nTime());
        pblock->set_nNonce(pdata->get_nNonce());
        pblock->set_vtx(0).set_vin(0).set_scriptSig(mapNewBlock[pdata->get_hashMerkleRoot()].second);
        pblock->set_hashMerkleRoot(pblock->BuildMerkleTree());

        return miner::CheckWork(pblock, *entry::pwalletMain, reservekey);
    }
}

json_spirit::Value CRPCTable::getblocktemplate(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "getblocktemplate [params]\n"
            "Returns data needed to construct a block to work on:\n"
            "  \"version\" : block version\n"
            "  \"previousblockhash\" : hash of current highest block\n"
            "  \"transactions\" : contents of non-coinbase transactions that should be included in the next block\n"
            "  \"coinbaseaux\" : data that should be included in coinbase\n"
            "  \"coinbasevalue\" : maximum allowable input to coinbase transaction, including the generation award and transaction fees\n"
            "  \"target\" : hash target\n"
            "  \"mintime\" : minimum timestamp appropriate for next block\n"
            "  \"curtime\" : current timestamp\n"
            "  \"mutable\" : list of ways the block template may be changed\n"
            "  \"noncerange\" : range of valid nonces\n"
            "  \"sigoplimit\" : limit of sigops in blocks\n"
            "  \"sizelimit\" : limit of block size\n"
            "  \"bits\" : compressed target of next block\n"
            "  \"height\" : height of the next block\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");
    }

    std::string strMode = "template";
    if (params.size() > 0) {
        const json_spirit::Object &oparam = params[0].get_obj();
        const json_spirit::Value &modeval = find_value(oparam, "mode");
        if (modeval.type() == json_spirit::str_type) {
            strMode = modeval.get_str();
        } else if (modeval.type() == json_spirit::null_type) {
            // Do nothing
        } else {
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        }
    }

    if (strMode != "template") {
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
    }
    if (net_node::vNodes.empty()) {
        throw bitjson::JSONRPCError(RPC_CLIENT_NOT_CONNECTED, (std::string(strCoinName) + " is not connected!").c_str());
    }
    if (block_notify::IsInitialBlockDownload()) {
        throw bitjson::JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, (std::string(strCoinName) + " is downloading blocks...").c_str());
    }

    static CReserveKey reservekey(entry::pwalletMain);

    //
    // Update block
    //
    static unsigned int nTransactionsUpdatedLast = 0;
    static CBlockIndex *pindexPrev = nullptr;
    static int64_t nStart = 0;
    static CBlock *pblock = nullptr;

    if (pindexPrev != block_info::pindexBest || (block_info::nTransactionsUpdated != nTransactionsUpdatedLast && bitsystem::GetTime() - nStart > 5)) {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = nullptr;

        // Store the block_info::pindexBest used before miner::CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = block_info::nTransactionsUpdated;
        CBlockIndex *pindexPrevNew = block_info::pindexBest;
        nStart = bitsystem::GetTime();

        // Create new block
        if(pblock) {
            delete pblock;
            pblock = nullptr;
        }

        pblock = miner::CreateNewBlock(entry::pwalletMain);
        if (! pblock) {
            throw bitjson::JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
        }

        // Need to update only after we know miner::CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }

    // Update nTime
    pblock->UpdateTime(pindexPrev);
    pblock->set_nNonce(0);

    json_spirit::Array transactions;
    std::map<uint256, int64_t> setTxIndex;
    int i = 0;
    CTxDB txdb("r");
    for(CTransaction &tx: pblock->set_vtx())
    {
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase() || tx.IsCoinStake()) {
            continue;
        }

        json_spirit::Object entry;

        CDataStream ssTx(SER_NETWORK, version::PROTOCOL_VERSION);
        ssTx << tx;
        entry.push_back(json_spirit::Pair("data", util::HexStr(ssTx.begin(), ssTx.end())));
        entry.push_back(json_spirit::Pair("hash", txHash.GetHex()));

        MapPrevTx mapInputs;
        std::map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        if (tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid)) {
            entry.push_back(json_spirit::Pair("fee", (int64_t)(tx.GetValueIn(mapInputs) - tx.GetValueOut())));

            json_spirit::Array deps;
            for(MapPrevTx::value_type& inp: mapInputs)
            {
                if (setTxIndex.count(inp.first)) {
                    deps.push_back(setTxIndex[inp.first]);
                }
            }
            entry.push_back(json_spirit::Pair("depends", deps));

            int64_t nSigOps = tx.GetLegacySigOpCount();
            nSigOps += tx.GetP2SHSigOpCount(mapInputs);
            entry.push_back(json_spirit::Pair("sigops", nSigOps));
        }

        transactions.push_back(entry);
    }

    json_spirit::Object aux;
    aux.push_back(json_spirit::Pair("flags", util::HexStr(block_info::COINBASE_FLAGS.begin(), block_info::COINBASE_FLAGS.end())));

    uint256 hashTarget = CBigNum().SetCompact(pblock->get_nBits()).getuint256();

    static json_spirit::Array aMutable;
    if (aMutable.empty()) {
        aMutable.push_back("time");
        aMutable.push_back("transactions");
        aMutable.push_back("prevblock");
    }

    json_spirit::Object result;
    result.push_back(json_spirit::Pair("version", pblock->get_nVersion()));
    result.push_back(json_spirit::Pair("previousblockhash", pblock->get_hashPrevBlock().GetHex()));
    result.push_back(json_spirit::Pair("transactions", transactions));
    result.push_back(json_spirit::Pair("coinbaseaux", aux));
    result.push_back(json_spirit::Pair("coinbasevalue", (int64_t)pblock->get_vtx(0).get_vout(0).get_nValue()));
    result.push_back(json_spirit::Pair("target", hashTarget.GetHex()));
    result.push_back(json_spirit::Pair("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1));
    result.push_back(json_spirit::Pair("mutable", aMutable));
    result.push_back(json_spirit::Pair("noncerange", "00000000ffffffff"));
    result.push_back(json_spirit::Pair("sigoplimit", (int64_t)block_params::MAX_BLOCK_SIGOPS));
    result.push_back(json_spirit::Pair("sizelimit", (int64_t)block_params::MAX_BLOCK_SIZE));
    result.push_back(json_spirit::Pair("curtime", (int64_t)pblock->get_nTime()));
    result.push_back(json_spirit::Pair("bits", HexBits(pblock->get_nBits())));
    result.push_back(json_spirit::Pair("height", (int64_t)(pindexPrev->get_nHeight()+1)));

    return result;
}

json_spirit::Value CRPCTable::submitblock(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) {
        throw std::runtime_error(
            "submitblock <hex data> [optional-params-obj]\n"
            "[optional-params-obj] parameter is currently ignored.\n"
            "Attempts to submit new block to network.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");
    }

    strenc::hex_vector blockData(strenc::ParseHex(params[0].get_str()));
    CDataStream ssBlock(blockData, SER_NETWORK, version::PROTOCOL_VERSION);

    CBlock block;
    try {
        ssBlock >> block;
    } catch (const std::exception &) {
        throw bitjson::JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    bool fAccepted = block_process::manage::ProcessBlock(nullptr, &block);
    if (! fAccepted) {
        return "rejected";
    }
    return json_spirit::Value::null;
}
*/
