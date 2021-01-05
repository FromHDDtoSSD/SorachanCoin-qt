// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <main.h>
#include <rpc/bitcoinrpc.h>
#include <init.h>
#include <boost/filesystem.hpp>
#include <boost/iostreams/device/file.hpp>
#include <boost/iostreams/stream.hpp>
#include <ostream>
#include <thread> // CWaitforthread
#include <miner/diff.h>

double CRPCTable::GetDifficulty(const CBlockIndex *blockindex/* = nullptr */) noexcept {
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == nullptr) {
        if (block_info::pindexBest == nullptr)
            return 1.0;
        else
            blockindex = diff::spacing::GetLastBlockIndex(block_info::pindexBest, false);
    }

    int nShift = (blockindex->get_nBits() >> 24) & 0xff;
    double dDiff = (double)0x0000ffff / (double)(blockindex->get_nBits() & 0x00ffffff);
    while (nShift < 29) {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29) {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

double CRPCTable::GetPoWMHashPS() noexcept {
    int nPoWInterval = 72;
    int64_t nTargetSpacingWorkMin = 30, nTargetSpacingWork = 30;

    CBlockIndex *pindex = block_info::pindexGenesisBlock;
    CBlockIndex *pindexPrevWork = block_info::pindexGenesisBlock;
    while (pindex) {
        if (pindex->IsProofOfWork()) {
            int64_t nActualSpacingWork = pindex->GetBlockTime() - pindexPrevWork->GetBlockTime();
            nTargetSpacingWork = ((nPoWInterval - 1) * nTargetSpacingWork + nActualSpacingWork + nActualSpacingWork) / (nPoWInterval + 1);
            nTargetSpacingWork = std::max(nTargetSpacingWork, nTargetSpacingWorkMin);
            pindexPrevWork = pindex;
        }

        pindex = pindex->set_pnext();
    }

    return GetDifficulty() * 4294.967296 / nTargetSpacingWork;
}

double CRPCTable::GetPoSKernelPS() noexcept {
    int nPoSInterval = 72;
    double dStakeKernelsTriedAvg = 0;
    int nStakesHandled = 0, nStakesTime = 0;

    CBlockIndex *pindex = block_info::pindexBest;
    CBlockIndex *pindexPrevStake = nullptr;
    while (pindex && nStakesHandled < nPoSInterval) {
        if (pindex->IsProofOfStake()) {
            dStakeKernelsTriedAvg += GetDifficulty(pindex) * 4294967296.0;
            nStakesTime += pindexPrevStake ? (pindexPrevStake->get_nTime() - pindex->get_nTime()) : 0;
            pindexPrevStake = pindex;
            nStakesHandled++;
        }

        pindex = pindex->set_pprev();
    }
    if (! nStakesHandled)
        return 0;

    return dStakeKernelsTriedAvg / nStakesTime;
}

json_spirit::Object CRPCTable::blockToJSON(const CBlock &block, const CBlockIndex *blockindex, bool fPrintTransactionDetail) {
    json_spirit::Object result;
    result.push_back(json_spirit::Pair("hash", block.GetHash().GetHex()));

    CMerkleTx txGen(block.get_vtx(0));
    txGen.SetMerkleBranch(&block);

    result.push_back(json_spirit::Pair("confirmations", (int)txGen.GetDepthInMainChain()));
    result.push_back(json_spirit::Pair("size", (int)::GetSerializeSize(block)));
    result.push_back(json_spirit::Pair("height", blockindex->get_nHeight()));
    result.push_back(json_spirit::Pair("version", block.get_nVersion()));
    result.push_back(json_spirit::Pair("merkleroot", block.get_hashMerkleRoot().GetHex()));
    result.push_back(json_spirit::Pair("mint", ValueFromAmount(blockindex->get_nMint())));
    result.push_back(json_spirit::Pair("time", (int64_t)block.GetBlockTime()));
    result.push_back(json_spirit::Pair("nonce", (uint64_t)block.get_nNonce()));
    result.push_back(json_spirit::Pair("bits", HexBits(block.get_nBits())));
    result.push_back(json_spirit::Pair("difficulty", GetDifficulty(blockindex)));
    result.push_back(json_spirit::Pair("blocktrust", util::leftTrim(blockindex->GetBlockTrust().GetHex(), '0')));
    result.push_back(json_spirit::Pair("chaintrust", util::leftTrim(blockindex->get_nChainTrust().GetHex(), '0')));
    if (blockindex->get_pprev())
        result.push_back(json_spirit::Pair("previousblockhash", blockindex->get_pprev()->GetBlockHash().GetHex()));
    if (blockindex->get_pnext())
        result.push_back(json_spirit::Pair("nextblockhash", blockindex->get_pnext()->GetBlockHash().GetHex()));

    result.push_back(json_spirit::Pair("flags", strprintf("%s%s", blockindex->IsProofOfStake()? "proof-of-stake" : "proof-of-work", blockindex->GeneratedStakeModifier()? " stake-modifier": "")));
    result.push_back(json_spirit::Pair("proofhash", blockindex->IsProofOfStake()? blockindex->get_hashProofOfStake().GetHex() : blockindex->GetBlockHash().GetHex()));
    result.push_back(json_spirit::Pair("entropybit", (int)blockindex->GetStakeEntropyBit()));
    result.push_back(json_spirit::Pair("modifier", strprintf("%016" PRIx64, blockindex->get_nStakeModifier())));
    result.push_back(json_spirit::Pair("modifierchecksum", strprintf("%08x", blockindex->get_nStakeModifierChecksum())));

    json_spirit::Array txinfo;
    for (const CTransaction &tx: block.get_vtx()) {
        if (fPrintTransactionDetail) {
            CDataStream ssTx(SER_NETWORK, version::PROTOCOL_VERSION);
            ssTx << tx;
            std::string strHex = util::HexStr(ssTx.begin(), ssTx.end());

            txinfo.push_back(strHex);
        } else
            txinfo.push_back(tx.GetHash().GetHex());
    }

    result.push_back(json_spirit::Pair("tx", txinfo));
    if (block.IsProofOfStake())
        result.push_back(json_spirit::Pair("signature", util::HexStr(block.get_vchBlockSig().begin(), block.get_vchBlockSig().end())));

    return result;
}

json_spirit::Value CRPCTable::getbestblockhash(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() != 0) {
        return data.JSONRPCSuccess(
            "getbestblockhash\n"
            "Returns the hash of the best block in the longest block chain.");
    }

    return data.JSONRPCSuccess(block_info::hashBestChain.GetHex());
}

json_spirit::Value CRPCTable::getblockcount(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() != 0) {
        return data.JSONRPCSuccess(
            "getblockcount\n"
            "Returns the number of blocks in the longest block chain.",
            "(numeric) The current block count.\n",
            "\"getblockcount\", \"\"\n");
    }

    return data.JSONRPCSuccess(block_info::nBestHeight);
}

/*
class CWaitforthread {
private:
    mutable std::thread th;
public:
    CWaitforthread() noexcept : th([]{::Sleep(100);}) {}
    void wait() const noexcept {th.join();}
};

// waitforblock
*/

json_spirit::Value CRPCTable::getdifficulty(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() != 0) {
        return data.JSONRPCSuccess(
            "getdifficulty\n"
            "Returns the difficulty as a multiple of the minimum difficulty.");
    }

    json_spirit::Object obj;
    obj.push_back(json_spirit::Pair("proof-of-work", GetDifficulty()));
    obj.push_back(json_spirit::Pair("proof-of-stake", GetDifficulty(diff::spacing::GetLastBlockIndex(block_info::pindexBest, true))));
    obj.push_back(json_spirit::Pair("search-interval", (int)block_info::nLastCoinStakeSearchInterval));
    return data.JSONRPCSuccess(obj);
}

json_spirit::Value CRPCTable::settxfee(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    data.e = "amount";
    if (data.fHelp() || params.size() < 1 || params.size() > 1 || AmountFromValue(params[0], data) < block_param::MIN_TX_FEE) {
        return data.JSONRPCSuccess(
            "settxfee <amount>\n"
            "<amount> is a real and is rounded to the nearest " + bitstr::FormatMoney(block_param::MIN_TX_FEE));
    }
    if(! data.fSuccess()) return data.JSONRPCError();

    data.e = "Transaction";
    block_info::nTransactionFee = AmountFromValue(params[0], data);
    if(! data.fSuccess()) return data.JSONRPCError();
    block_info::nTransactionFee = (block_info::nTransactionFee / block_param::MIN_TX_FEE) * block_param::MIN_TX_FEE;  // round to minimum fee
    return data.JSONRPCSuccess(true);
}

json_spirit::Value CRPCTable::getrawmempool(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 0) {
        return data.JSONRPCSuccess(
            "getrawmempool\n"
            "Returns all transaction ids in memory pool.");
    }

    std::vector<uint256> vtxid;
    CTxMemPool::mempool.queryHashes(vtxid);
    json_spirit::Array a;
    for(const uint256 &hash: vtxid)
        a.push_back(hash.ToString());

    return data.JSONRPCSuccess(a);
}

json_spirit::Value CRPCTable::getblockhash(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "getblockhash <index>\n"
            "Returns hash of block in best-block-chain at <index>.");
    }

    json_spirit::json_flags status;
    int nHeight = params[0].get_int(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if (nHeight < 0 || nHeight > block_info::nBestHeight)
        return data.runtime_error("Block number out of range.");

    CBlockIndex *pblockindex = block_transaction::manage::FindBlockByHeight(nHeight);
    return data.JSONRPCSuccess(pblockindex->get_phashBlock()->GetHex());
}

// SorachanCoin: QHASH65536
json_spirit::Value CRPCTable::getblockqhash(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "getblockqhash <index>\n"
            "Returns QHASH65536 of block in best-block-chain at <index>.");
    }

    json_spirit::json_flags status;
    int nHeight = params[0].get_int(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if (nHeight < 0 || nHeight > block_info::nBestHeight)
        return data.runtime_error("Block number out of range.");

    CBlockIndex *pblockindex = block_transaction::manage::FindBlockByHeight(nHeight);
    uint65536 tt = bitscrypt::scrypt_blockhash_65536((const uint8_t *)pblockindex);
    return data.JSONRPCSuccess(tt.GetHex());
}

json_spirit::Value CRPCTable::getblock(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 1 || params.size() > 2) {
        return data.JSONRPCSuccess(
            "getblock <hash> [txinfo]\n"
            "txinfo optional to print more detailed tx info\n"
            "Returns details of a block with given block-hash.");
    }

    json_spirit::json_flags status;
    std::string strHash = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    uint256 hash(strHash);
    if (block_info::mapBlockIndex.count(hash) == 0)
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex *pblockindex = block_info::mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex, true);
    bool fparam1 = params[1].get_bool(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    return data.JSONRPCSuccess(blockToJSON(block, pblockindex, params.size() > 1 ? fparam1 : false));
}

json_spirit::Value CRPCTable::getblockbynumber(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 1 || params.size() > 2) {
        return data.JSONRPCSuccess(
            "getblockbynumber <number> [txinfo]\n"
            "txinfo optional to print more detailed tx info\n"
            "Returns details of a block with given block-number.");
    }

    json_spirit::json_flags status;
    int nHeight = params[0].get_int(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if (nHeight < 0 || nHeight > block_info::nBestHeight)
        return data.runtime_error("Block number out of range.");

    CBlock block;
    CBlockIndex *pblockindex = block_info::mapBlockIndex[block_info::hashBestChain];
    while (pblockindex->get_nHeight() > nHeight)
        pblockindex = pblockindex->set_pprev();

    pblockindex = block_info::mapBlockIndex[*pblockindex->get_phashBlock()];
    block.ReadFromDisk(pblockindex, true);
    bool fparam1 = params[1].get_bool(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    return data.JSONRPCSuccess(blockToJSON(block, pblockindex, params.size() > 1 ? fparam1 : false));
}

bool CRPCTable::ExportBlock(const std::string &strBlockHash, const CDataStream &ssBlock) {
    boost::filesystem::path pathDest = iofs::GetDataDir() / strBlockHash;
    if (boost::filesystem::is_directory(pathDest))
        pathDest /= strBlockHash;

    try {
        boost::iostreams::stream_buffer<boost::iostreams::file_sink> buf(pathDest.string());
        std::ostream exportStream(&buf);
        exportStream << util::HexStr(ssBlock.begin(), ssBlock.end());
        exportStream.flush();

        printf("Successfully exported block to %s\n", pathDest.string().c_str());
        return true;
    } catch(const boost::filesystem::filesystem_error &e) {
        printf("error exporting the block data %s (%s)\n", pathDest.string().c_str(), e.what());
        return false;
    }
}

json_spirit::Value CRPCTable::dumpblock(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 1 || params.size() > 2) {
        return data.JSONRPCSuccess(
            "dumpblock <hash> [destination]\n"
            "Returns serialized contents of a block with given block-hash.");
    }

    json_spirit::json_flags status;
    std::string strHash = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    uint256 hash(strHash);
    if (block_info::mapBlockIndex.count(hash) == 0)
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex *pblockindex = block_info::mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex, true);
    CDataStream ssBlock(SER_NETWORK, version::PROTOCOL_VERSION);
    ssBlock << block;
    if (params.size() > 1) {
        json_spirit::json_flags status;
        std::string str = params[1].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        return data.JSONRPCSuccess(ExportBlock(str, ssBlock));
    }

    return data.JSONRPCSuccess(util::HexStr(ssBlock.begin(), ssBlock.end()));
}

json_spirit::Value CRPCTable::dumpblockbynumber(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 1 || params.size() > 2) {
        return data.JSONRPCSuccess(
            "dumpblockbynumber <number>  [destination]\n"
            "Returns serialized contents of a block with given block-number.");
    }

    json_spirit::json_flags status;
    int nHeight = params[0].get_int(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if (nHeight < 0 || nHeight > block_info::nBestHeight)
        return data.runtime_error("Block number out of range.");

    CBlock block;
    CBlockIndex *pblockindex = block_info::mapBlockIndex[block_info::hashBestChain];
    while (pblockindex->get_nHeight() > nHeight)
        pblockindex = pblockindex->set_pprev();

    pblockindex = block_info::mapBlockIndex[*pblockindex->get_phashBlock()];
    block.ReadFromDisk(pblockindex, true);
    CDataStream ssBlock(SER_NETWORK, version::PROTOCOL_VERSION);
    ssBlock << block;
    if (params.size() > 1) {
        json_spirit::json_flags status;
        std::string str = params[1].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        return data.JSONRPCSuccess(ExportBlock(str, ssBlock));
    }

    return data.JSONRPCSuccess(util::HexStr(ssBlock.begin(), ssBlock.end()));
}

// get information of sync-checkpoint
json_spirit::Value CRPCTable::getcheckpoint(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 0) {
        return data.JSONRPCSuccess(
            "getcheckpoint\n"
            "Show info of synchronized checkpoint.\n");
    }

    json_spirit::Object result;
    result.push_back(json_spirit::Pair("synccheckpoint", Checkpoints::manage::getHashSyncCheckpoint().ToString().c_str()));

    CBlockIndex *pindexCheckpoint = block_info::mapBlockIndex[Checkpoints::manage::getHashSyncCheckpoint()];
    result.push_back(json_spirit::Pair("height", pindexCheckpoint->get_nHeight()));
    result.push_back(json_spirit::Pair("timestamp", util::DateTimeStrFormat(pindexCheckpoint->GetBlockTime()).c_str()));
    if (Checkpoints::checkpointMessage.Get_vchSig().size() != 0) {
        json_spirit::Object msgdata;
        CUnsignedSyncCheckpoint checkpoint;

        CDataStream sMsg(Checkpoints::checkpointMessage.Get_vchMsg(), SER_NETWORK, version::PROTOCOL_VERSION);
        sMsg >> checkpoint;

        json_spirit::Object parsed; // message version and data (block hash)
        parsed.push_back(json_spirit::Pair("version", checkpoint.Get_nVersion()));
        parsed.push_back(json_spirit::Pair("hash", checkpoint.Get_hashCheckpoint().GetHex().c_str()));
        msgdata.push_back(json_spirit::Pair("parsed", parsed));

        json_spirit::Object raw; // raw checkpoint message data
        raw.push_back(json_spirit::Pair("data", util::HexStr(Checkpoints::checkpointMessage.Get_vchMsg()).c_str()));
        raw.push_back(json_spirit::Pair("signature", util::HexStr(Checkpoints::checkpointMessage.Get_vchSig()).c_str()));
        msgdata.push_back(json_spirit::Pair("raw", raw));

        result.push_back(json_spirit::Pair("data", msgdata));
    }

    // Check that the block satisfies synchronized checkpoint
    if (entry::CheckpointsMode == Checkpoints::STRICT)
        result.push_back(json_spirit::Pair("policy", "strict"));
    if (entry::CheckpointsMode == Checkpoints::ADVISORY)
        result.push_back(json_spirit::Pair("policy", "advisory"));
    if (entry::CheckpointsMode == Checkpoints::PERMISSIVE)
        result.push_back(json_spirit::Pair("policy", "permissive"));
    if (map_arg::GetMapArgsCount("-checkpointkey"))
        result.push_back(json_spirit::Pair("checkpointmaster", true));

    return data.JSONRPCSuccess(result);
}
