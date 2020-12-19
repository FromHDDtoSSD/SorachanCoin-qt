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

json_spirit::Value CRPCTable::getsubsidy(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() > 1) {
        return data.JSONRPCSuccess(
            "getsubsidy [nTarget]\n"
            "Returns proof-of-work subsidy value for the specified value of target.");
    }

    unsigned int nBits = 0;
    if (params.size() != 0) {
        json_spirit::json_flags status;
        std::string str = params[0].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        CBigNum bnTarget(uint256(str.c_str()));
        nBits = bnTarget.GetCompact();
    } else
        nBits = diff::spacing::GetNextTargetRequired(block_info::pindexBest, false);

    return data.JSONRPCSuccess((uint64_t)diff::reward::GetProofOfWorkReward(nBits));
}

json_spirit::Value CRPCTable::getmininginfo(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() != 0) {
        return data.JSONRPCSuccess(
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
    return data.JSONRPCSuccess(obj);
}

// scaninput '{"txid":"95d640426fe66de866a8cf2d0601d2c8cf3ec598109b4d4ffa7fd03dad6d35ce","difficulty":0.01, "days":10}'
json_spirit::Value CRPCTable::scaninput(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "scaninput '{\"txid\":\"txid\", \"vout\":[vout1, vout2, ..., voutN], \"difficulty\":difficulty, \"days\":days}'\n"
            "Scan specified transaction or input for suitable kernel solutions.\n"
            "    difficulty - upper limit for difficulty, current difficulty by default;\n"
            "    days - time window, 90 days by default.\n"
        );
    }

    bitrpc::RPCTypeCheck(data, params, boost::assign::list_of(json_spirit::obj_type));
    if(! data.fSuccess()) return data.JSONRPCError();

    json_spirit::json_flags status;
    json_spirit::Object scanParams = params[0].get_obj(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    const json_spirit::Value &txid_v = find_value(scanParams, "txid");
    if (txid_v.type() != json_spirit::str_type)
        return data.JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing txid key");

    std::string txid = txid_v.get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if (! hex::IsHex(txid))
        return data.JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected hex txid");

    uint256 hash(txid);
    int32_t nDays = 90;
    uint32_t nBits = diff::spacing::GetNextTargetRequired(block_info::pindexBest, true);
    const json_spirit::Value &diff_v = find_value(scanParams, "difficulty");
    if (diff_v.type() == json_spirit::real_type || diff_v.type() == json_spirit::int_type) {
        double dDiff = diff_v.get_real(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        if (dDiff <= 0)
            return data.JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, diff must be greater than zero");

        CBigNum bnTarget(diff::nPoWBase);
        bnTarget *= 1000;
        bnTarget /= (int) (dDiff * 1000);
        nBits = bnTarget.GetCompact();
    }

    const json_spirit::Value &days_v = find_value(scanParams, "days");
    if (days_v.type() == json_spirit::int_type) {
        nDays = days_v.get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        if (nDays <= 0)
            return data.JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, interval length must be greater than zero");
    }

    CTransaction tx;
    uint256 hashBlock = 0;
    if (block_transaction::manage::GetTransaction(hash, tx, hashBlock)) {
        if (hashBlock == 0)
            return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to find transaction in the blockchain");

        std::vector<int> vInputs(0);
        const json_spirit::Value &inputs_v = find_value(scanParams, "vout");
        if (inputs_v.type() == json_spirit::array_type) {
            json_spirit::Array inputs = inputs_v.get_array(status);
            if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
            for(const json_spirit::Value &v_out: inputs) {
                int nOut = v_out.get_int(status);
                if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
                if (nOut < 0 || nOut > (int)tx.get_vout().size() - 1) {
                    std::stringstream strErrorMsg;
                    strErrorMsg << boost::format("Invalid parameter, input number %d is out of range") % nOut;
                    return data.JSONRPCError(RPC_INVALID_PARAMETER, strErrorMsg.str());
                }
                vInputs.push_back(nOut);
            }
        } else if(inputs_v.type() == json_spirit::int_type) {
            int nOut = inputs_v.get_int(status);
            if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
            if (nOut < 0 || nOut > (int)tx.get_vout().size() - 1) {
                std::stringstream strErrorMsg;
                strErrorMsg << boost::format("Invalid parameter, input number %d is out of range") % nOut;
                return data.JSONRPCError(RPC_INVALID_PARAMETER, strErrorMsg.str());
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
            return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to read block index item");

        // Read block header
        if (! block.ReadFromDisk(txindex.get_pos().get_nFile(), txindex.get_pos().get_nBlockPos(), false))
            return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "CBlock::ReadFromDisk() failed");

        uint64_t nStakeModifier = 0;
        if (! bitkernel::GetKernelStakeModifier(block.GetHash(), nStakeModifier))
            return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No kernel stake modifier generated yet");

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
            return data.JSONRPCSuccess(false);

        return data.JSONRPCSuccess(results);
    } else
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");
}

json_spirit::Value CRPCTable::getworkex(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() > 2) {
        return data.JSONRPCSuccess(
            "getworkex [data, coinbase]\n"
            "If [data, coinbase] is not specified, returns extended work data.\n"
        );
    }

    LOCK(CRPCTable::cs_getwork);
    if (net_node::vNodes.empty())
        return data.JSONRPCError(-9, sts_c(coin_param::strCoinName + " is not connected!"));
    if (block_notify::IsInitialBlockDownload())
        return data.JSONRPCError(-10, sts_c(coin_param::strCoinName + " is downloading blocks..."));

    using mapNewBlock_t = std::map<uint256, std::pair<CBlock *, CScript> >;
    static mapNewBlock_t mapNewBlock;
    static std::vector<CBlock *> vNewBlock;
    static CReserveKey reservekey(entry::pwalletMain);
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
                return data.JSONRPCError(-7, "Out of memory");
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
        return data.JSONRPCSuccess(result);
    } else {
        // Parse parameters
        json_spirit::json_flags status;
        std::string str = params[0].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        rpctable_vector vchData = hex::ParseHex(str);
        rpctable_vector coinbase;
        if(params.size() == 2) {
            str = params[1].get_str(status);
            if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
            coinbase = hex::ParseHex(str);
        }
        if (vchData.size() != 128)
            return data.JSONRPCError(-8, "Invalid parameter");

        CBlock *pdata = (CBlock *)&vchData[0];

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
        return data.JSONRPCSuccess(miner::CheckWork(pblock, *entry::pwalletMain, reservekey));
    }
}

json_spirit::Value CRPCTable::getwork(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() > 1) {
        return data.JSONRPCSuccess(
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
        return data.JSONRPCError(RPC_CLIENT_NOT_CONNECTED, sts_c(coin_param::strCoinName + " is not connected!"));
    if (block_notify::IsInitialBlockDownload())
        return data.JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, sts_c(coin_param::strCoinName + " is downloading blocks..."));

    using mapNewBlock_t = std::map<uint256, std::pair<CBlock *, CScript> >;
    static mapNewBlock_t mapNewBlock;
    static std::vector<CBlock *> vNewBlock;
    static CReserveKey reservekey(entry::pwalletMain);
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
            CBlockIndex* pindexPrevNew = block_info::pindexBest;
            nStart = bitsystem::GetTime();

            // Create new block
            //printf("ThreadRPCServer3 getwork new Block\n");
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
        return data.JSONRPCSuccess(result);
    } else {
        // Parse parameters
        json_spirit::json_flags status;
        std::string str = params[0].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        rpctable_vector vchData = hex::ParseHex(str);
        if (vchData.size() != 128)
            return data.JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");

        CBlock *pdata = (CBlock *)&vchData[0];

        // Byte reverse
        for (int i = 0; i < 128 / 4; ++i)
            ((unsigned int *)pdata)[i] = util::ByteReverse(((unsigned int *)pdata)[i]);

        // Get saved block
        if (! mapNewBlock.count(pdata->get_hashMerkleRoot()))
            return data.JSONRPCSuccess(false);

        CBlock *pblock = mapNewBlock[pdata->get_hashMerkleRoot()].first;
        pblock->set_nTime(pdata->get_nTime());
        pblock->set_nNonce(pdata->get_nNonce());
        pblock->set_vtx(0).set_vin(0).set_scriptSig(mapNewBlock[pdata->get_hashMerkleRoot()].second);
        pblock->set_hashMerkleRoot(pblock->BuildMerkleTree());
        return data.JSONRPCSuccess(miner::CheckWork(pblock, *entry::pwalletMain, reservekey));
    }
}

json_spirit::Value CRPCTable::getblocktemplate(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() > 1) {
        return data.JSONRPCSuccess(
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
    std::string strMode = "template";
    if (params.size() > 0) { // json_spirit::null_type do nothing
        json_spirit::json_flags status;
        const json_spirit::Object &oparam = params[0].get_obj(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        const json_spirit::Value &modeval = find_value(oparam, "mode");
        if (modeval.type() == json_spirit::str_type) {
            strMode = modeval.get_str(status);
            if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        } else
            return data.JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
    }

    if (strMode != "template")
        return data.JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
    if (net_node::vNodes.empty())
        return data.JSONRPCError(RPC_CLIENT_NOT_CONNECTED, sts_c(coin_param::strCoinName + " is not connected!"));
    if (block_notify::IsInitialBlockDownload())
        return data.JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, sts_c(coin_param::strCoinName + " is downloading blocks..."));

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
            delete pblock;
            pblock = nullptr;
        }

        pblock = miner::CreateNewBlock(entry::pwalletMain);
        if (! pblock)
            return data.JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

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
    for(CTransaction &tx: pblock->set_vtx()) {
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;
        if (tx.IsCoinBase() || tx.IsCoinStake())
            continue;

        json_spirit::Object entry;
        CDataStream ssTx;
        ssTx << tx;
        entry.push_back(json_spirit::Pair("data", util::HexStr(ssTx.begin(), ssTx.end())));
        entry.push_back(json_spirit::Pair("hash", txHash.GetHex()));

        MapPrevTx mapInputs;
        std::map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        if (tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid)) {
            entry.push_back(json_spirit::Pair("fee", (int64_t)(tx.GetValueIn(mapInputs) - tx.GetValueOut())));
            json_spirit::Array deps;
            for(MapPrevTx::value_type& inp: mapInputs) {
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
    result.push_back(json_spirit::Pair("sigoplimit", (int64_t)block_param::MAX_BLOCK_SIGOPS));
    result.push_back(json_spirit::Pair("sizelimit", (int64_t)block_param::MAX_BLOCK_SIZE));
    result.push_back(json_spirit::Pair("curtime", (int64_t)pblock->get_nTime()));
    result.push_back(json_spirit::Pair("bits", HexBits(pblock->get_nBits())));
    result.push_back(json_spirit::Pair("height", (int64_t)(pindexPrev->get_nHeight()+1)));

    return data.JSONRPCSuccess(result);
}

json_spirit::Value CRPCTable::submitblock(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() < 1 || params.size() > 2) {
        return data.JSONRPCSuccess(
            "submitblock <hex data> [optional-params-obj]\n"
            "[optional-params-obj] parameter is currently ignored.\n"
            "Attempts to submit new block to network.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");
    }

    LOCK(CRPCTable::cs_getwork);
    json_spirit::json_flags status;
    std::string hex = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    rpctable_vector blockData(hex::ParseHex(hex));
    CDataStream ssBlock(blockData, SER_NETWORK, version::PROTOCOL_VERSION);
    CBlock block;
    //try {
        ssBlock >> block;
    //} catch (const std::exception &) {
    //    return data.JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    //}

    bool fAccepted = block_process::manage::ProcessBlock(nullptr, &block);
    if (! fAccepted)
        return data.JSONRPCSuccess("rejected");

    return data.JSONRPCSuccess(json_spirit::Value::null);
}
