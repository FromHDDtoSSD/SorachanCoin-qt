// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2025 The SorachanCoin developers
// Copyright (c) 2025 The SS256 SORA2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet.h>
#include <rpc/bitcoinrpc.h>
#include <init.h>
#include <address/base58.h>
#include <crypto/sora2.h>
#include <thread>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <openssl/evp.h>
#include <miner.h>
#include <miner/diff.h>
#include <block/block_process.h>

json_spirit::Value CRPCTable::encryptdata(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 2) {
        throw std::runtime_error(
            "encryptdata <public key> <hex data>\n"
            "Encrypt octet stream with provided public key..\n");
    }

    CPubKey pubKey(strenc::ParseHex(params[0].get_str()));

    key_vector vchEncrypted;
    pubKey.EncryptData(strenc::ParseHex(params[1].get_str()), vchEncrypted);

    return util::HexStr(vchEncrypted);
}

json_spirit::Value CRPCTable::decryptdata(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 2) {
        throw std::runtime_error(
            "decryptdata <coin address or private key> <encrypted stream>\n"
            "Decrypt octet stream.\n");
    }

    EnsureWalletIsUnlocked();
    CFirmKey key;
    CBitcoinAddress addr(params[0].get_str());
    if (addr.IsValid()) {
        CKeyID keyID;
        addr.GetKeyID(keyID);
        if (! entry::pwalletMain->GetKey(keyID, key)) {
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "We have no private key for this address");
        }
    } else {
        CBitcoinSecret vchSecret;
        if (! vchSecret.SetString(params[0].get_str())) {
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Provided private key is inconsistent.");
        }
        bool fCompressed;
        CSecret secret = vchSecret.GetSecret(fCompressed);
        key.SetSecret(secret, fCompressed);
    }

    key_vector vchDecrypted;
    key.DecryptData(strenc::ParseHex(params[1].get_str()), vchDecrypted);

    return util::HexStr(vchDecrypted);
}

json_spirit::Value CRPCTable::encryptmessage(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 2) {
        throw std::runtime_error(
            "encryptmessage <public key> <message string>\n"
            "Encrypt message with provided public key.\n");
    }

    CPubKey pubKey(strenc::ParseHex(params[0].get_str()));

    key_vector vchEncrypted;
    //std::string strData = params[1].get_str();
    //pubKey.EncryptData(std::vector<unsigned char>(strData.begin(), strData.end()), vchEncrypted);
    pubKey.EncryptData(strenc::ParseHex(params[1].get_str()), vchEncrypted);

    return base58::manage::EncodeBase58Check(vchEncrypted);
}

json_spirit::Value CRPCTable::decryptmessage(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 2) {
        throw std::runtime_error(
            "decryptmessage <coin address or private key> <encrypted message>\n"
            "Decrypt message string.\n");
    }

    EnsureWalletIsUnlocked();

    CFirmKey key;
    CBitcoinAddress addr(params[0].get_str());
    if (addr.IsValid()) {
        CKeyID keyID;
        addr.GetKeyID(keyID);
        if (! entry::pwalletMain->GetKey(keyID, key)) {
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "We have no private key for this address");
        }
    } else {
        CBitcoinSecret vchSecret;
        if (! vchSecret.SetString(params[0].get_str())) {
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Provided private key is inconsistent.");
        }

        bool fCompressed;
        CSecret secret = vchSecret.GetSecret(fCompressed);
        key.SetSecret(secret, fCompressed);
    }

    key_vector vchEncrypted;
    if (! base58::manage::DecodeBase58Check(params[1].get_str(), vchEncrypted)) {
        throw std::runtime_error("Incorrect string");
    }

    key_vector vchDecrypted;
    key.DecryptData(vchEncrypted, vchDecrypted);

    return std::string((const char *)&vchDecrypted[0], vchDecrypted.size());
}

json_spirit::Value CRPCTable::sora2hash(const json_spirit::Array &params, bool fHelp) {
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            "sora2hash <target message>\n"
            "SORA2 hash string.\n");
    }

    std::string message = params[0].get_str();

    uint256 hash;
    CSORA2_256().Write((const unsigned char *)message.c_str(), message.size()).Finalize(hash.begin());
    return std::string(util::HexStr(BEGIN(hash), END(hash)));
}

json_spirit::Value CRPCTable::sha2hash(const json_spirit::Array &params, bool fHelp) {
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            "sha2hash <target message>\n"
            "SHA-256 hash string.\n");
    }

    std::string message = params[0].get_str();

    uint256 hash;
    CSHA256().Write((const unsigned char *)message.c_str(), message.size()).Finalize(hash.begin());
    return std::string(util::HexStr(BEGIN(hash), END(hash)));
}

static std::string base64_encode(const std::string &input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, input.c_str(), (int)input.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length - 1);
    BIO_free_all(bio);
    return result;
}

json_spirit::Object ConnectRpc(const std::string &host, const std::string &port, const std::string &rpcuser, const std::string &rpcpassword, const std::string &method, const json_spirit::Array &params) {
    using tcp = boost::asio::ip::tcp;
    namespace http = boost::beast::http;

    boost::asio::io_context ioc;
    tcp::resolver resolver(ioc);
    tcp::socket socket(ioc);
    auto const results = resolver.resolve(host, port);
    boost::asio::connect(socket, results.begin(), results.end());

    json_spirit::Object body;
    body.push_back(json_spirit::Pair("method", method));
    body.push_back(json_spirit::Pair("params", params));
    body.push_back(json_spirit::Pair("id", 1));
    std::string send_str = json_spirit::write_string(json_spirit::Value(body), false);

    http::request<http::string_body> req{http::verb::post, "/", 11};
    req.set(http::field::host, host);
    req.set(http::field::content_type, "application/json");
    req.body() = send_str;
    req.prepare_payload();
    debugcs::instance() << "send str: " << send_str << debugcs::endl();

    // Basic Authentication
    std::string auth_raw = rpcuser + ":" + rpcpassword;
    std::string auth_encoded = base64_encode(auth_raw);
    req.set(http::field::authorization, "Basic " + auth_encoded);

    http::write(socket, req);

    boost::beast::flat_buffer buffer;
    http::response<http::dynamic_body> res;
    http::read(socket, buffer, res);

    std::string result_str = boost::beast::buffers_to_string(res.body().data());
    socket.shutdown(tcp::socket::shutdown_both);
    debugcs::instance() << "recv str: " << result_str << debugcs::endl();

    json_spirit::Value v;
    json_spirit::read_string(result_str, v);
    return v.get_obj();
}

struct SORA2_MINING_INFO {
    std::thread t;
    bool connect;
    uint64_t counter;
    uint32_t time;
    SORA2_MINING_INFO() {
        connect = false;
        counter = 0;
        time = 0;
    }
    ~SORA2_MINING_INFO() {
        if(connect) {
            connect = false;
        }
    }
} g_sora2mining_info;

/*
static bool sora2mining_getblocktemplate() {
    std::string host = "127.0.0.1";
    std::string port = map_arg::GetMapArgsString("-rpcport");
    std::string user = map_arg::GetMapArgsString("-rpcuser");
    std::string pass = map_arg::GetMapArgsString("-rpcpassword");
    std::string server = map_arg::GetMapArgsString("-server");
    if(server != "1") {
        debugcs::instance() << "sora2mining_start: Require Server mode" << debugcs::endl();
        return false;
    }
    if(port.empty()) {
        port = "31588";
    }

    // Connect getblocktemplate
    json_spirit::Array params;
    params.clear();
    json_spirit::Object rpc_obj_gbt;
    try {
        rpc_obj_gbt = ConnectRpc(host, port, user, pass, "getblocktemplate", params);
    } catch (const boost::exception &) {
        debugcs::instance() << "sora2mining_start: Failure Connection" << debugcs::endl();
        return false;
    }

    try {
        json_spirit::Value recv_v_version = json_spirit::find_value(json_spirit::find_value(rpc_obj_gbt, "result").get_obj(), "version");
        json_spirit::Value recv_v_prevblockhash = json_spirit::find_value(json_spirit::find_value(rpc_obj_gbt, "result").get_obj(), "previousblockhash");
        json_spirit::Value recv_v_target = json_spirit::find_value(json_spirit::find_value(rpc_obj_gbt, "result").get_obj(), "target");
        json_spirit::Value recv_v_curtime = json_spirit::find_value(json_spirit::find_value(rpc_obj_gbt, "result").get_obj(), "curtime");
        json_spirit::Value recv_v_bits = json_spirit::find_value(json_spirit::find_value(rpc_obj_gbt, "result").get_obj(), "bits");
        if (recv_v_version.type() != json_spirit::int_type ||
            recv_v_prevblockhash.type() != json_spirit::str_type ||
            recv_v_target.type() != json_spirit::str_type ||
            recv_v_curtime.type() != json_spirit::int_type ||
            recv_v_bits.type() != json_spirit::str_type) {
            debugcs::instance() << "sora2mining_start: Invalid RPC" << debugcs::endl();
            return false;
        }

        // build Coinbase Transaction
        CTransaction txCoinBase;
        txCoinBase.set_vin().resize(1);
        txCoinBase.set_vin(0).set_prevout().SetNull();
        uint32_t nExtraNonce = 0;
        int32_t nHeight = block_info::nBestHeight + 1;
        txCoinBase.set_vin(0).set_scriptSig((CScript() << nHeight << CBigNum(nExtraNonce)) + block_info::COINBASE_FLAGS);
        txCoinBase.set_vout().resize(1);
        static CReserveKey reservekey(entry::pwalletMain);
        txCoinBase.set_vout(0).set_scriptPubKey().SetDestination(reservekey.GetReservedKey().GetID());
        txCoinBase.set_vout(0).set_nValue(2 * util::COIN);

        // build CBlockHeader
        CBlockHeader blockHeader;
        blockHeader.set_nVersion(recv_v_version.get_int());
        blockHeader.set_nTime(recv_v_curtime.get_int());
        blockHeader.set_nBits(::strtol(recv_v_bits.get_str().c_str(), nullptr, 16));
        blockHeader.set_hashMerkleRoot(txCoinBase.GetHash());
        uint256 prevblock;
        prevblock.SetHex(recv_v_prevblockhash.get_str());
        blockHeader.set_hashPrevBlock(prevblock);
        blockHeader.set_nNonce(0);
        debugcs::instance() << "sora2mining_start nVersion: " << blockHeader.get_nVersion() << debugcs::endl();
        debugcs::instance() << "sora2mining_start nTime: " << blockHeader.get_nTime() << debugcs::endl();

        // CPU mining
        uint256 target1;
        target1.SetHex(recv_v_target.get_str());
        uint256 target2 = CBigNum().SetCompact(blockHeader.get_nBits()).getuint256();
        if(target1 != target2) {
            debugcs::instance() << "sora2mining_start: Invalid target" << debugcs::endl();
            return false;
        }
        debugcs::instance() << "target: " << target1.ToString() << debugcs::endl();
        uint32_t nonce = 0;
        uint256 hash = 0;
        for(;;) {
            if(! g_sora2mining_info.connect) {
                debugcs::instance() << "sora2mining_start: Stop mining" << debugcs::endl();
                return false;
            }

            g_sora2mining_info.counter++;
            hash = bitmining::scrypt_blockhash(&blockHeader);
            if(hash < target1) {
                debugcs::instance() << "sora2mining_start, HIT: " << hash.ToString() << debugcs::endl();
                break;
            } else {
                blockHeader.set_nNonce(++nonce);
            }
        }

        // Accept
        CBlock block;
        block.set_nVersion(blockHeader.get_nVersion());
        block.set_hashPrevBlock(blockHeader.get_hashPrevBlock());
        block.set_hashMerkleRoot(blockHeader.get_hashMerkleRoot());
        block.set_nTime(blockHeader.get_nTime());
        block.set_nBits(blockHeader.get_nBits());
        block.set_nNonce(blockHeader.get_nNonce());
        if(block.GetPoHash() != hash) {
            debugcs::instance() << "sora2mining_start: Invalid block hash" << debugcs::endl();
            return false;
        }
        CTransactionVch txsvch;
        txsvch.vtx.emplace_back(txCoinBase);
        block.set_vtx() = txsvch.vtx;
        bool fAccepted = miner::CheckWork(&block, *entry::pwalletMain, reservekey);
        if (! fAccepted) {
            debugcs::instance() << "sora2mining_start: Invalid block" << debugcs::endl();
            return true;
        }
    } catch (const std::exception &) {
        debugcs::instance() << "sora2mining_start: Failure Mining" << debugcs::endl();
        return false;
    }

    debugcs::instance() << "sora2mining_start: Valid block, Accepted" << debugcs::endl();
    return true;
}
*/

/*
static bool sora2mining_getwork() {
    std::string host = "127.0.0.1";
    std::string port = map_arg::GetMapArgsString("-rpcport");
    std::string user = map_arg::GetMapArgsString("-rpcuser");
    std::string pass = map_arg::GetMapArgsString("-rpcpassword");
    std::string server = map_arg::GetMapArgsString("-server");
    if(server != "1") {
        debugcs::instance() << "sora2mining_start: Require Server mode" << debugcs::endl();
        return false;
    }
    if(port.empty()) {
        port = "31588";
    }

    json_spirit::Array params;
    params.clear();
    json_spirit::Object recv_obj;
    try {
        recv_obj = ConnectRpc(host, port, user, pass, "getwork", params);
    } catch (const boost::exception &) {
        debugcs::instance() << "sora2mining_start: Failure Connection" << debugcs::endl();
        return false;
    }

    try {
        json_spirit::Value recv_v_data = json_spirit::find_value(json_spirit::find_value(recv_obj, "result").get_obj(), "data");
        json_spirit::Value recv_v_target = json_spirit::find_value(json_spirit::find_value(recv_obj, "result").get_obj(), "target");
        if(recv_v_data.type() != json_spirit::str_type || recv_v_target.type() != json_spirit::str_type) {
            debugcs::instance() << "sora2mining_start: Require str_type" << debugcs::endl();
            return false;
        }
        debugcs::instance() << "sora2mining_start: " << recv_v_data.get_str() << debugcs::endl();
        debugcs::instance() << "sora2mining_start: " << recv_v_target.get_str() << debugcs::endl();

        strenc::hex_vector recv_data_vch = strenc::ParseHex(recv_v_data.get_str());
        debugcs::instance() << "sora2mining_start size: " << recv_data_vch.size() << debugcs::endl();
        recv_data_vch.resize(80);
        for (unsigned int i = 0; i < recv_data_vch.size() / 4; ++i) {
            ((unsigned int *)&recv_data_vch.front())[i] = util::ByteReverse(((unsigned int *)&recv_data_vch.front())[i]);
        }

        CBlockHeader blockHeader;
        try {
            CDataStream ssBlockHeader(recv_data_vch);
            ssBlockHeader >> blockHeader;
        } catch (const std::exception &) {
            debugcs::instance() << "sora2mining_start: Invalid Block" << debugcs::endl();
            return false;
        }
        debugcs::instance() << "sora2mining_start, nVersion: " << blockHeader.get_nVersion() << debugcs::endl();
        debugcs::instance() << "sora2mining_start, nTime: " << blockHeader.get_nTime() << debugcs::endl();
        debugcs::instance() << "sora2mining_start, nonce: " << blockHeader.get_nNonce() << debugcs::endl();

        uint256 recv_target;
        recv_target.SetHex(recv_v_target.get_str());
        std::reverse(std::begin(recv_target), std::end(recv_target));
        uint256 target = CBigNum().SetCompact(blockHeader.get_nBits()).getuint256();
        debugcs::instance() << "sora2mining_start, recv_target: " << recv_target.ToString() << debugcs::endl();
        debugcs::instance() << "sora2mining_start,      target: " << target.ToString() << debugcs::endl();
        if(recv_target != target) {
            debugcs::instance() << "sora2mining_start: Invalid target" << debugcs::endl();
            return false;
        }

        uint256 hash = 0;
        uint32_t nonce = 0;
        blockHeader.set_nNonce(nonce);
        for(;;) {
            if(! g_sora2mining_info.connect) {
                debugcs::instance() << "sora2mining_start: Stop mining" << debugcs::endl();
                return false;
            }

            g_sora2mining_info.counter++;
            hash = bitmining::scrypt_blockhash(&blockHeader);
            //debugcs::instance() << hash.ToString() << debugcs::endl();
            if(hash < target) {
                debugcs::instance() << "sora2mining_start, HIT: " << hash.ToString() << debugcs::endl();
                break;
            } else {
                blockHeader.set_nNonce(++nonce);
            }
        }
        debugcs::instance() << "sora2mining_start, nVersion: " << blockHeader.get_nVersion() << debugcs::endl();
        debugcs::instance() << "sora2mining_start, nTime: " << blockHeader.get_nTime() << debugcs::endl();
        debugcs::instance() << "sora2mining_start, nonce: " << blockHeader.get_nNonce() << debugcs::endl();

        //Accept
        CBlock block;
        block.set_nVersion(blockHeader.get_nVersion());
        block.set_hashPrevBlock(blockHeader.get_hashPrevBlock());
        block.set_hashMerkleRoot(blockHeader.get_hashMerkleRoot());
        block.set_nTime(blockHeader.get_nTime());
        block.set_nBits(blockHeader.get_nBits());
        block.set_nNonce(blockHeader.get_nNonce());
        if(block.GetPoHash() != hash) {
            debugcs::instance() << "sora2mining_start: Invalid block hash" << debugcs::endl();
            return false;
        }
        bool fAccepted = block_process::manage::ProcessBlock(nullptr, &block);
        if (! fAccepted) {
            debugcs::instance() << "sora2mining_start: Invalid Block" << debugcs::endl();
            return true;
        }
    } catch (const std::exception &) {
        debugcs::instance() << "sora2mining_start: Failure Mining" << debugcs::endl();
        return false;
    }

    debugcs::instance() << "sora2mining_start: Valid block, Accepted" << debugcs::endl();
    return true;
}
*/

static bool sora2mining_getinfo(std::map<std::string, std::string> &result, CBlock **next_tx_block) {
    using mapNewBlock_t = std::map<uint256, std::pair<CBlock *, CScript> >;
    static mapNewBlock_t mapNewBlock;
    static std::vector<CBlock *> vNewBlock;
    assert(next_tx_block != nullptr);

    LOCK(CRPCTable::cs_getwork);
    if (net_node::vNodes.empty()) {
        debugcs::instance() << "sora2mining_getinfo: Not connected!" << debugcs::endl();
        return false;
    }
    if (block_notify::IsInitialBlockDownload()) {
        debugcs::instance() << "sora2mining_getinfo: downloading blocks..." << debugcs::endl();
        return false;
    }

    // Update block
    static unsigned int nTransactionsUpdatedLast = 0;
    static CBlockIndex *pindexPrev = nullptr;
    static int64_t nStart = 0;

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
        *next_tx_block = miner::CreateNewBlock(entry::pwalletMain);
        if (! *next_tx_block) {
            debugcs::instance() << "sora2mining_getinfo: Out of memory" << debugcs::endl();
            return false;
        }
        vNewBlock.push_back(*next_tx_block);

        // Need to update only after we know miner::CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }

    // Update nTime
    (*next_tx_block)->UpdateTime(pindexPrev);
    (*next_tx_block)->set_nNonce(0);

    // Update nExtraNonce
    static unsigned int nExtraNonce = 0;
    miner::IncrementExtraNonce(*next_tx_block, pindexPrev, nExtraNonce);

    // Save
    mapNewBlock[(*next_tx_block)->get_hashMerkleRoot()] = std::make_pair(*next_tx_block, (*next_tx_block)->get_vtx(0).get_vin(0).get_scriptSig());

    // Pre-build hash buffers
    char pmidstate[32];
    char pdata[128];
    char phash1[64];
    miner::FormatHashBuffers(*next_tx_block, pmidstate, pdata, phash1);

    uint256 hashTarget = CBigNum().SetCompact((*next_tx_block)->get_nBits()).getuint256();
    result.insert(std::make_pair(std::string("midstate"), util::HexStr(BEGIN(pmidstate), END(pmidstate)))); // deprecated
    result.insert(std::make_pair(std::string("data"), util::HexStr(BEGIN(pdata), END(pdata))));
    result.insert(std::make_pair(std::string("hash1"), util::HexStr(BEGIN(phash1), END(phash1)))); // deprecated
    result.insert(std::make_pair(std::string("target"), util::HexStr(BEGIN(hashTarget), END(hashTarget))));
    return true;
}

static bool sora2mining_local_getwork() {
    std::map<std::string, std::string> result;
    CBlock *next_tx_block;
    if(! sora2mining_getinfo(result, &next_tx_block)) {
        debugcs::instance() << "sora2mining_local_getwork: Failure sora2mining_rpc_getwork" << debugcs::endl();
        return false;
    }
    if(!result.count(std::string("data")) || !result.count(std::string("target"))) {
        debugcs::instance() << "sora2mining_local_getwork: Invalid sora2mining_rpc_getwork" << debugcs::endl();
        return false;
    }
    debugcs::instance() << "sora2mining_local_getwork data: " << result["data"] << debugcs::endl();
    debugcs::instance() << "sora2mining_local_getwork target: " << result["target"] << debugcs::endl();
    strenc::hex_vector data_vch = strenc::ParseHex(result["data"]);
    data_vch.resize(80);
    for (unsigned int i = 0; i < data_vch.size() / 4; ++i) {
        ((unsigned int *)&data_vch.front())[i] = util::ByteReverse(((unsigned int *)&data_vch.front())[i]);
    }

    // Unserialize CBlockHeader
    CBlockHeader blockHeader;
    try {
        CDataStream ssBlockHeader(data_vch);
        ssBlockHeader >> blockHeader;
    } catch (const std::exception &) {
        debugcs::instance() << "sora2mining_local_getwork: Invalid Block" << debugcs::endl();
        return false;
    }

    // build Coinbase Transaction
    CTransaction txCoinBase;
    txCoinBase.set_vin().resize(1);
    txCoinBase.set_vin(0).set_prevout().SetNull();
    uint32_t nExtraNonce = 0;
    int32_t nHeight = block_info::nBestHeight + 1;
    txCoinBase.set_vin(0).set_scriptSig((CScript() << nHeight << CBigNum(nExtraNonce)) + block_info::COINBASE_FLAGS);
    txCoinBase.set_vout().resize(1);
    static CReserveKey reservekey(entry::pwalletMain);
    txCoinBase.set_vout(0).set_scriptPubKey().SetDestination(reservekey.GetReservedKey().GetID());
    txCoinBase.set_vout(0).set_nValue(diff::reward::GetProofOfWorkReward(blockHeader.get_nBits()));

    // build transactions
    CTransactionVch txsvch;
    txsvch.vtx.push_back(txCoinBase);
    for(CTransaction &tx: next_tx_block->set_vtx()) {
        if (tx.IsCoinBase() || tx.IsCoinStake())
            continue;
        debugcs::instance() << "txid: " << tx.GetHash().ToString() << debugcs::endl();
        txsvch.vtx.emplace_back(tx);
    }

    // build CBlock and CBlockHeader
    CBlock block;
    block.set_vtx() = txsvch.vtx;
    blockHeader.set_nNonce(0);
    blockHeader.set_hashMerkleRoot(block.BuildMerkleTree());
    debugcs::instance() << "sora2mining_local_getwork, nVersion: " << blockHeader.get_nVersion() << debugcs::endl();
    debugcs::instance() << "sora2mining_local_getwork, nTime: " << blockHeader.get_nTime() << debugcs::endl();

    // build target
    uint256 recv_target;
    recv_target.SetHex(result["target"]);
    std::reverse(std::begin(recv_target), std::end(recv_target));
    uint256 target = CBigNum().SetCompact(blockHeader.get_nBits()).getuint256();
    debugcs::instance() << "sora2mining_local_getwork, recv_target: " << recv_target.ToString() << debugcs::endl();
    debugcs::instance() << "sora2mining_local_getwork,      target: " << target.ToString() << debugcs::endl();
    if(recv_target != target) {
        debugcs::instance() << "sora2mining_local_getwork: Invalid target" << debugcs::endl();
        return false;
    }

    // CPU mining
    uint64_t nonce = 0;
    blockHeader.set_nNonce(nonce);
    uint256 hash = 0;
    uint32_t t1 = ::time(nullptr);
    for(;;) {
        if(! g_sora2mining_info.connect) {
            return false;
        }

        g_sora2mining_info.counter++;
        if(args_bool::fTestNet) {
            hash = bitmining::sha3d_blockhash(&blockHeader);
        } else {
            hash = bitmining::scrypt_blockhash(&blockHeader);
        }
        g_sora2mining_info.time += ::time(nullptr) - t1;
        t1 = ::time(nullptr);
        if(hash < target) {
            debugcs::instance() << "sora2mining_local_getwork HIT: " << hash.ToString() << debugcs::endl();
            break;
        } else {
            blockHeader.set_nNonce(++nonce);
        }
    }

    // Accept
    block.set_nVersion(blockHeader.get_nVersion());
    block.set_hashPrevBlock(blockHeader.get_hashPrevBlock());
    block.set_hashMerkleRoot(blockHeader.get_hashMerkleRoot());
    block.set_nTime(blockHeader.get_nTime());
    block.set_nBits(blockHeader.get_nBits());
    block.set_nNonce(blockHeader.get_nNonce());
    if(block.GetPoHash() != hash) {
        debugcs::instance() << "sora2mining_local_getwork: Invalid block hash" << debugcs::endl();
        return false;
    }
    bool fAccepted = block_process::manage::ProcessBlock(nullptr, &block);
    if (! fAccepted) {
        debugcs::instance() << "sora2mining_local_getwork: Invalid Block" << debugcs::endl();
        return true;
    }

    debugcs::instance() << "sora2mining_local_getwork: Accepted Block" << debugcs::endl();
    return true;
}

static void sora2mining_worker() {
    for(;;) {
        if(! sora2mining_local_getwork()) {
            g_sora2mining_info.connect = false;
        }

        if(! g_sora2mining_info.connect) {
            break;
        }
    }
}

static bool sora2mining_start() {
    if(g_sora2mining_info.connect) {
        return true;
    }
    g_sora2mining_info.connect = true;
    std::thread t1(sora2mining_worker);
    g_sora2mining_info.t = std::move(t1);
    g_sora2mining_info.t.detach();
    return true;
}

static bool sora2mining_stop() {
    if(! g_sora2mining_info.connect) {
        return true;
    }
    g_sora2mining_info.connect = false;
    return true;
}

static double sora2mining_benchmark() {
    return (double)g_sora2mining_info.counter / (double)g_sora2mining_info.time;
}

static bool sora2mining_status() {
    return g_sora2mining_info.connect;
}

json_spirit::Value CRPCTable::sora2mining(const json_spirit::Array &params, bool fHelp) {
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            "sora2mining <start, stop, status, algo>\n"
            "SORA2 CPU mining.\n");
    }

    std::string status = params[0].get_str();

    if(status == "start") {
        bool fThread = sora2mining_start();
        return fThread ? std::string("Ok: sora2 mining started"): std::string("Failure: sora2 mining started");
    } else if (status == "stop") {
        bool fThread = sora2mining_stop();
        return fThread ? std::string("Ok: sora2 mining stopped"): std::string("Failure: sora2 mining stopped");
    } else if (status == "status") {
        std::string info = sora2mining_status() ? std::string("Running: sora2 mining"): std::string("Stopped: sora2 mining");
        if(sora2mining_status()) {
            info += std::string(", time: ") + std::to_string(g_sora2mining_info.time) + std::string("s ") + std::string(", hash benchmark: ") + std::to_string(uint32_t(sora2mining_benchmark())) + std::string(" H/s");
        }
        return info;
    } else if (status == "algo") {
        if(args_bool::fTestNet) {
            return std::string("SORA2");
        } else {
            return std::string("Scrypt");
        }
    } else {
        return std::string("Invalid parameter");
    }
}
