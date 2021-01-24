// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp>
#include <address/base58.h>
#include <rpc/bitcoinrpc.h>
#include <txdb.h>
#include <init.h>
#include <main.h>
#include <net.h>
#include <wallet.h>

void CRPCTable::ScriptPubKeyToJSON(const CScript &scriptPubKey, json_spirit::Object &out, bool fIncludeHex) {
    TxnOutputType::txnouttype type;
    std::vector<CTxDestination> addresses;
    int nRequired;

    out.push_back(json_spirit::Pair("asm", scriptPubKey.ToString()));
    if (fIncludeHex)
        out.push_back(json_spirit::Pair("hex", util::HexStr(scriptPubKey.begin(), scriptPubKey.end())));
    if (! Script_util::ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
        out.push_back(json_spirit::Pair("type", TxnOutputType::GetTxnOutputType(TxnOutputType::TX_NONSTANDARD)));
        return;
    }

    if (type != TxnOutputType::TX_NULL_DATA) {
        out.push_back(json_spirit::Pair("reqSigs", nRequired));
        out.push_back(json_spirit::Pair("type", TxnOutputType::GetTxnOutputType(type)));
        if (type == TxnOutputType::TX_PUBKEY_DROP) {
            Script_util::statype vSolutions;
            Script_util::Solver(scriptPubKey, type, vSolutions);
            out.push_back(json_spirit::Pair("keyVariant", util::HexStr(vSolutions[0])));
            out.push_back(json_spirit::Pair("R", util::HexStr(vSolutions[1])));

            CMalleableKeyView view;
            if (entry::pwalletMain->CheckOwnership(CPubKey(vSolutions[0]), CPubKey(vSolutions[1]), view))
                out.push_back(json_spirit::Pair("pubkeyPair", CBitcoinAddress(view.GetMalleablePubKey()).ToString()));
        } else {
            json_spirit::Array a;
            for(const CTxDestination &addr: addresses)
                a.push_back(CBitcoinAddress(addr).ToString());

            out.push_back(json_spirit::Pair("addresses", a));
        }
    } else
        out.push_back(json_spirit::Pair("type", TxnOutputType::GetTxnOutputType(type)));
}

void CRPCTable::TxToJSON(const CTransaction &tx, const uint256 &hashBlock, json_spirit::Object &entry) {
    entry.push_back(json_spirit::Pair("txid", tx.GetHash().GetHex()));
    entry.push_back(json_spirit::Pair("version", tx.get_nVersion()));
    entry.push_back(json_spirit::Pair("time", (int64_t)tx.get_nTime()));
    entry.push_back(json_spirit::Pair("locktime", (int64_t)tx.get_nLockTime()));

    json_spirit::Array vin;
    for(const CTxIn &txin: tx.get_vin()) {
        json_spirit::Object in;
        if (tx.IsCoinBase())
            in.push_back(json_spirit::Pair("coinbase", util::HexStr(txin.get_scriptSig().begin(), txin.get_scriptSig().end())));
        else {
            in.push_back(json_spirit::Pair("txid", txin.get_prevout().get_hash().GetHex()));
            in.push_back(json_spirit::Pair("vout", (int64_t)txin.get_prevout().get_n()));

            json_spirit::Object o;
            o.push_back(json_spirit::Pair("asm", txin.get_scriptSig().ToString()));
            o.push_back(json_spirit::Pair("hex", util::HexStr(txin.get_scriptSig().begin(), txin.get_scriptSig().end())));
            in.push_back(json_spirit::Pair("scriptSig", o));
        }
        in.push_back(json_spirit::Pair("sequence", (int64_t)txin.get_nSequence()));
        vin.push_back(in);
    }

    entry.push_back(json_spirit::Pair("vin", vin));
    
    json_spirit::Array vout;
    for (unsigned int i = 0; i < tx.get_vout().size(); ++i) {
        const CTxOut& txout = tx.get_vout(i);
        
        json_spirit::Object out;
        out.push_back(json_spirit::Pair("value", ValueFromAmount(txout.get_nValue())));
        out.push_back(json_spirit::Pair("n", (int64_t)i));

        json_spirit::Object o;
        ScriptPubKeyToJSON(txout.get_scriptPubKey(), o, true);
        out.push_back(json_spirit::Pair("scriptPubKey", o));
        vout.push_back(out);
    }
    entry.push_back(json_spirit::Pair("vout", vout));

    if (hashBlock != 0) {
        entry.push_back(json_spirit::Pair("blockhash", hashBlock.GetHex()));
        std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hashBlock);
        if (mi != block_info::mapBlockIndex.end() && (*mi).second) {
            CBlockIndex *pindex = (*mi).second;
            if (pindex->IsInMainChain()) {
                entry.push_back(json_spirit::Pair("confirmations", 1 + block_info::nBestHeight - pindex->get_nHeight()));
                entry.push_back(json_spirit::Pair("time", (int64_t)pindex->get_nTime()));
                entry.push_back(json_spirit::Pair("blocktime", (int64_t)pindex->get_nTime()));
            } else
                entry.push_back(json_spirit::Pair("confirmations", 0));
        }
    }
}

json_spirit::Value CRPCTable::getrawtransaction(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 1 || params.size() > 2) {
        return data.JSONRPCSuccess(
            "getrawtransaction <txid> [verbose=0]\n"
            "If verbose=0, returns a string that is\n"
            "serialized, hex-encoded data for <txid>.\n"
            "If verbose is non-zero, returns an Object\n"
            "with information about <txid>.");
    }

    uint256 hash;
    json_spirit::json_flags status;
    hash.SetHex(params[0].get_str(status));
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    bool fVerbose = false;
    if (params.size() > 1) {
        fVerbose = (params[1].get_int(status) != 0);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    CTransaction tx;
    uint256 hashBlock = 0;
    if (! block_transaction::manage::GetTransaction(hash, tx, hashBlock))
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");

    CDataStream ssTx(SER_NETWORK, version::PROTOCOL_VERSION);
    ssTx << tx;
    std::string strHex = util::HexStr(ssTx.begin(), ssTx.end());
    if (! fVerbose)
        return data.JSONRPCSuccess(strHex);

    json_spirit::Object result;
    result.push_back(json_spirit::Pair("hex", strHex));
    TxToJSON(tx, hashBlock, result);
    return data.JSONRPCSuccess(result);
}

json_spirit::Value CRPCTable::listunspent(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 3) {
        return data.JSONRPCSuccess(
            "listunspent [minconf=1] [maxconf=9999999]  [\"address\",...]\n"
            "Returns array of unspent transaction outputs\n"
            "with between minconf and maxconf (inclusive) confirmations.\n"
            "Optionally filtered to only include txouts paid to specified addresses.\n"
            "Results are an array of Objects, each of which has:\n"
            "{txid, vout, scriptPubKey, amount, confirmations}");
    }

    bitrpc::RPCTypeCheck(data, params, boost::assign::list_of(json_spirit::int_type)(json_spirit::int_type)(json_spirit::array_type));
    if(! data.fSuccess()) return data.JSONRPCError();

    int nMinDepth = 1;
    json_spirit::json_flags status;
    if (params.size() > 0) {
        nMinDepth = params[0].get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    int nMaxDepth = 9999999;
    if (params.size() > 1) {
        nMaxDepth = params[1].get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    std::set<CBitcoinAddress> setAddress;
    if (params.size() > 2) {
        json_spirit::Array inputs = params[2].get_array(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        for(json_spirit::Value &input: inputs) {
            json_spirit::json_flags status;
            std::string str = input.get_str(status);
            if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
            CBitcoinAddress address(str);
            if (! address.IsValid())
                return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid " strCoinName " address: ") + str);
            if (setAddress.count(address))
                return data.JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + str);
            setAddress.insert(address);
        }
    }

    json_spirit::Array results;
    std::vector<COutput> vecOutputs;
    entry::pwalletMain->AvailableCoins(vecOutputs, false);
    for(const COutput &out: vecOutputs) {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;
        if(setAddress.size()) {
            CTxDestination address;
            if(! Script_util::ExtractDestination(out.tx->get_vout(out.i).get_scriptPubKey(), address))
                continue;
            if (! setAddress.count(address))
                continue;
        }

        int64_t nValue = out.tx->get_vout(out.i).get_nValue();
        const CScript &pk = out.tx->get_vout(out.i).get_scriptPubKey();

        json_spirit::Object entry;
        entry.push_back(json_spirit::Pair("txid", out.tx->GetHash().GetHex()));
        entry.push_back(json_spirit::Pair("vout", out.i));
        CTxDestination address;
        if (Script_util::ExtractDestination(out.tx->get_vout(out.i).get_scriptPubKey(), address)) {
            entry.push_back(json_spirit::Pair("address", CBitcoinAddress(address).ToString()));
            if (entry::pwalletMain->mapAddressBook.count(address))
                entry.push_back(json_spirit::Pair("account", entry::pwalletMain->mapAddressBook[address]));
        }

        entry.push_back(json_spirit::Pair("scriptPubKey", util::HexStr(pk.begin(), pk.end())));
        if (pk.IsPayToScriptHash()) {
            CTxDestination address;
            if (Script_util::ExtractDestination(pk, address)) {
                const CScriptID &hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (entry::pwalletMain->GetCScript(hash, redeemScript))
                    entry.push_back(json_spirit::Pair("redeemScript", util::HexStr(redeemScript.begin(), redeemScript.end())));
            }
        }

        entry.push_back(json_spirit::Pair("amount",ValueFromAmount(nValue)));
        entry.push_back(json_spirit::Pair("confirmations",out.nDepth));
        entry.push_back(json_spirit::Pair("spendable", out.fSpendable));
        results.push_back(entry);
    }

    return data.JSONRPCSuccess(results);
}

json_spirit::Value CRPCTable::createrawtransaction(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 3 || params.size() < 2) {
        return data.JSONRPCSuccess(
            "createrawtransaction <'[{\"txid\":txid,\"vout\":n},...]'> <'{address:amount,...}'> [hex data]\n"
            "Create a transaction spending given inputs\n"
            "(array of objects containing transaction id and output number),\n"
            "sending to given address(es),\n"
            "optional data to add into data-carrying output.\n"
            "Returns hex-encoded raw transaction.\n"
            "Note that the transaction's inputs are not signed, and\n"
            "it is not stored in the wallet or transmitted to the network.");
    }

    bitrpc::RPCTypeCheck(data, params, boost::assign::list_of(json_spirit::array_type)(json_spirit::obj_type));
    if(! data.fSuccess()) return data.JSONRPCError();

    json_spirit::json_flags status;
    json_spirit::Array inputs = params[0].get_array(status);
    json_spirit::Object sendTo = params[1].get_obj(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CTransaction rawTx;
    for(json_spirit::Value &input: inputs) {
        json_spirit::json_flags status;
        const json_spirit::Object &o = input.get_obj(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        const json_spirit::Value &txid_v = find_value(o, "txid");
        if (txid_v.type() != json_spirit::str_type)
            return data.JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing txid key");
        
        std::string txid = txid_v.get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        if (! hex::IsHex(txid))
            return data.JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected hex txid");

        const json_spirit::Value& vout_v = find_value(o, "vout");
        if (vout_v.type() != json_spirit::int_type)
            return data.JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");

        int nOutput = vout_v.get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        if (nOutput < 0)
            return data.JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        CTxIn in(COutPoint(uint256(txid), nOutput));
        rawTx.set_vin().push_back(in);
    }

    std::set<CBitcoinAddress> setAddress;
    for(const json_spirit::Pair &s: sendTo) {
        // Create output destination script
        CScript scriptPubKey;
        CBitcoinAddress address(s.name_);
        if (address.IsValid()) {
            scriptPubKey.SetAddress(address);
            // Don't perform duplication checking for pubkey-pair addresses
            if (! address.IsPair()) {
                if (setAddress.count(address))
                    return data.JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ")+s.name_);
                setAddress.insert(address);
            }
        } else
            return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid output destination: ")+s.name_);

        data.e = "RawTransaction value ";
        int64_t nAmount = AmountFromValue(s.value_, data);
        if(! data.fSuccess()) return data.JSONRPCError();
        CTxOut out(nAmount, scriptPubKey);
        rawTx.set_vout().push_back(out);
    }

    if (params.size() == 3) {
        // Data carrying output
        CScript scriptPubKey;
        json_spirit::json_flags status;
        std::string str = params[2].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        scriptPubKey << ScriptOpcodes::OP_RETURN << hex::ParseHex(str);
        CTxOut out(0, scriptPubKey);
        rawTx.set_vout().push_back(out);
    }

    CDataStream ss(SER_NETWORK, version::PROTOCOL_VERSION);
    ss << rawTx;
    return data.JSONRPCSuccess(util::HexStr(ss.begin(), ss.end()));
}

json_spirit::Value CRPCTable::decoderawtransaction(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "decoderawtransaction <hex string>\n"
            "Return a JSON object representing the serialized, hex-encoded transaction.");
    }

    bitrpc::RPCTypeCheck(data, params, boost::assign::list_of(json_spirit::str_type));
    if(! data.fSuccess()) return data.JSONRPCError();

    json_spirit::json_flags status;
    std::string str = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    rpctable_vector txData(hex::ParseHex(str));
    CDataStream ssData(txData, SER_NETWORK, version::PROTOCOL_VERSION);
    CTransaction tx;
    try {
        ssData >> tx;
    } catch (const std::exception &) {
        return data.JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    json_spirit::Object result;
    TxToJSON(tx, 0, result);
    return data.JSONRPCSuccess(result);
}

json_spirit::Value CRPCTable::decodescript(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "decodescript <hex string>\n"
            "Decode a hex-encoded script.");
    }

    bitrpc::RPCTypeCheck(data, params, boost::assign::list_of(json_spirit::str_type));
    if(! data.fSuccess()) return data.JSONRPCError();

    json_spirit::Object r;
    CScript script;
    json_spirit::json_flags status;
    std::string str = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if (str.size() > 0){
        rpctable_vector scriptData(hexrpc::ParseHexV(params[0], "argument", data));
        if(! data.fSuccess()) return data.JSONRPCError();
        script = CScript(scriptData.begin(), scriptData.end());
    } else {
        // Empty scripts are valid
    }
    ScriptPubKeyToJSON(script, r, false);

    r.push_back(json_spirit::Pair("p2sh", CBitcoinAddress(script.GetID()).ToString()));
    return data.JSONRPCSuccess(r);
}

json_spirit::Value CRPCTable::signrawtransaction(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 1 || params.size() > 4) {
        return data.JSONRPCSuccess(
            "signrawtransaction <hex string> '[{\"txid\":txid,\"vout\":n,\"scriptPubKey\":hex,\"redeemScript\":hex},...]' '[<privatekey1>,...]' [sighashtype=\"ALL\"]\n"
            "Sign inputs for raw transaction (serialized, hex-encoded).\n"
            "Second optional argument (may be null) is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the blockchain.\n"
            "Third optional argument (may be null) is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"
            "Fourth optional argument is a string that is one of six values; ALL, NONE, SINGLE or\n"
            "ALL|ANYONECANPAY, NONE|ANYONECANPAY, SINGLE|ANYONECANPAY.\n"
            "Returns json object with keys:\n"
            "  hex : raw transaction with signature(s) (hex-encoded string)\n"
            "  complete : 1 if transaction has a complete set of signature (0 if not)"
            + HelpRequiringPassphrase());
    }

    bitrpc::RPCTypeCheck(data, params, boost::assign::list_of(json_spirit::str_type)(json_spirit::array_type)(json_spirit::array_type)(json_spirit::str_type), true);
    if(! data.fSuccess()) return data.JSONRPCError();

    json_spirit::json_flags status;
    std::string str = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    rpctable_vector txData(hex::ParseHex(str));
    CDataStream ssData(txData, SER_NETWORK, version::PROTOCOL_VERSION);
    std::vector<CTransaction> txVariants;
    while (! ssData.empty()) {
        try {
            CTransaction tx;
            ssData >> tx;
            txVariants.push_back(tx);
        } catch (const std::exception &) {
            return data.JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
        }
    }
    if (txVariants.empty())
        return data.JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transaction");

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx
    CTransaction mergedTx(txVariants[0]);
    bool fComplete = true;

    // Fetch previous transactions (inputs)
    std::map<COutPoint, CScript> mapPrevOut;
    for (unsigned int i = 0; i < mergedTx.get_vin().size(); ++i) {
        CTransaction tempTx;
        MapPrevTx mapPrevTx;
        CTxDB txdb("r");
        std::map<uint256, CTxIndex> unused;
        bool fInvalid;

        // FetchInputs aborts on failure, so we go one at a time
        tempTx.set_vin().push_back(mergedTx.get_vin(i));
        tempTx.FetchInputs(txdb, unused, false, false, mapPrevTx, fInvalid);

        // Copy results into mapPrevOut
        for(const CTxIn &txin: tempTx.get_vin()) {
            const uint256 &prevHash = txin.get_prevout().get_hash();
            if (mapPrevTx.count(prevHash) && mapPrevTx[prevHash].second.get_vout().size()>txin.get_prevout().get_n())
                mapPrevOut[txin.get_prevout()] = mapPrevTx[prevHash].second.get_vout(txin.get_prevout().get_n()).get_scriptPubKey();
        }
    }

    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    if (params.size() > 2 && params[2].type() != json_spirit::null_type) {
        fGivenKeys = true;
        json_spirit::json_flags status;
        json_spirit::Array keys = params[2].get_array(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        for(json_spirit::Value k: keys) {
            CBitcoinSecret vchSecret;
            json_spirit::json_flags status;
            std::string str = k.get_str(status);
            if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
            bool fGood = vchSecret.SetString(str);
            if (! fGood)
                return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");

            CKey key;
            bool fCompressed;
            CSecret secret = vchSecret.GetSecret(fCompressed);
            key.SetSecret(secret, fCompressed);
            tempKeystore.AddKey(key);
        }
    } else {
        EnsureWalletIsUnlocked(data);
        if(! data.fSuccess()) return data.JSONRPCError();
    }

    // Add previous txouts given in the RPC call
    if (params.size() > 1 && params[1].type() != json_spirit::null_type) {
        json_spirit::json_flags status;
        json_spirit::Array prevTxs = params[1].get_array(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        for(json_spirit::Value &p: prevTxs) {
            if (p.type() != json_spirit::obj_type)
                return data.JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");

            json_spirit::Object prevOut = p.get_obj(status);
            if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
            bitrpc::RPCTypeCheck(data, prevOut, boost::assign::map_list_of("txid", json_spirit::str_type)("vout", json_spirit::int_type)("scriptPubKey", json_spirit::str_type));
            if(! data.fSuccess()) return data.JSONRPCError();

            json_spirit::json_flags status;
            std::string txidHex = find_value(prevOut, "txid").get_str(status);
            if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
            if (! hex::IsHex(txidHex))
                return data.JSONRPCError(RPC_DESERIALIZATION_ERROR, "txid must be hexadecimal");

            uint256 txid;
            txid.SetHex(txidHex);
            int nOut = find_value(prevOut, "vout").get_int(status);
            if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
            if (nOut < 0)
                return data.JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");

            std::string pkHex = find_value(prevOut, "scriptPubKey").get_str(status);
            if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
            if (! hex::IsHex(pkHex))
                return data.JSONRPCError(RPC_DESERIALIZATION_ERROR, "scriptPubKey must be hexadecimal");

            rpctable_vector pkData(hex::ParseHex(pkHex));
            CScript scriptPubKey(pkData.begin(), pkData.end());
            COutPoint outpoint(txid, nOut);
            if (mapPrevOut.count(outpoint)) {
                // Complain if scriptPubKey doesn't match
                if (mapPrevOut[outpoint] != scriptPubKey) {
                    std::string err("Previous output scriptPubKey mismatch:\n");
                    err = err + mapPrevOut[outpoint].ToString() + "\nvs:\n"+ scriptPubKey.ToString();
                    return data.JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
                }
            } else
                mapPrevOut[outpoint] = scriptPubKey;

            // if redeemScript given and not using the local wallet (private keys given), add redeemScript to the tempKeystore so it can be signed
            json_spirit::Value v = find_value(prevOut, "redeemScript");
            if (fGivenKeys && scriptPubKey.IsPayToScriptHash()) {
                bitrpc::RPCTypeCheck(data, prevOut, boost::assign::map_list_of("txid", json_spirit::str_type)("vout", json_spirit::int_type)("scriptPubKey", json_spirit::str_type)("redeemScript", json_spirit::str_type));
                if(! data.fSuccess()) return data.JSONRPCError();

                json_spirit::Value v = find_value(prevOut, "redeemScript");
                if (!(v == json_spirit::Value::null)) {
                    rpctable_vector rsData(hexrpc::ParseHexV(v, "redeemScript", data));
                    if(! data.fSuccess()) return data.JSONRPCError();
                    CScript redeemScript(rsData.begin(), rsData.end());
                    tempKeystore.AddCScript(redeemScript);
                }
            }
        }
    }

    const CKeyStore &keystore = (fGivenKeys ? tempKeystore : *entry::pwalletMain);
    int nHashType = Script_param::SIGHASH_ALL;
    if (params.size() > 3 && params[3].type() != json_spirit::null_type) {
        static std::map<std::string, int> mapSigHashValues =
            boost::assign::map_list_of
            (std::string("ALL"), int(Script_param::SIGHASH_ALL))
            (std::string("ALL|ANYONECANPAY"), int(Script_param::SIGHASH_ALL | Script_param::SIGHASH_ANYONECANPAY))
            (std::string("NONE"), int(Script_param::SIGHASH_NONE))
            (std::string("NONE|ANYONECANPAY"), int(Script_param::SIGHASH_NONE | Script_param::SIGHASH_ANYONECANPAY))
            (std::string("SINGLE"), int(Script_param::SIGHASH_SINGLE))
            (std::string("SINGLE|ANYONECANPAY"), int(Script_param::SIGHASH_SINGLE | Script_param::SIGHASH_ANYONECANPAY))
            ;
        json_spirit::json_flags status;
        std::string strHashType = params[3].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        if (mapSigHashValues.count(strHashType))
            nHashType = mapSigHashValues[strHashType];
        else
            return data.JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
    }

    bool fHashSingle = ((nHashType & ~Script_param::SIGHASH_ANYONECANPAY) == Script_param::SIGHASH_SINGLE);

    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.get_vin().size(); ++i) {
        CTxIn &txin = mergedTx.set_vin(i);
        if (mapPrevOut.count(txin.get_prevout()) == 0) {
            fComplete = false;
            continue;
        }
        const CScript &prevPubKey = mapPrevOut[txin.get_prevout()];

        txin.set_scriptSig().clear();
        // Only sign Script_param::SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mergedTx.get_vout().size()))
            Script_util::SignSignature(keystore, prevPubKey, mergedTx, i, nHashType);

        // ... and merge in other signatures:
        for(const CTransaction &txv: txVariants)
            txin.set_scriptSig(Script_util::CombineSignatures(prevPubKey, mergedTx, i, txin.get_scriptSig(), txv.get_vin(i).get_scriptSig()));

        if (! Script_util::VerifyScript(txin.get_scriptSig(), prevPubKey, mergedTx, i, Script_param::STRICT_FLAGS, 0))
            fComplete = false;
    }

    json_spirit::Object result;
    CDataStream ssTx(SER_NETWORK, version::PROTOCOL_VERSION);
    ssTx << mergedTx;
    result.push_back(json_spirit::Pair("hex", util::HexStr(ssTx.begin(), ssTx.end())));
    result.push_back(json_spirit::Pair("complete", fComplete));
    return data.JSONRPCSuccess(result);
}

json_spirit::Value CRPCTable::sendrawtransaction(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 1 || params.size() > 1) {
        return data.JSONRPCSuccess(
            "sendrawtransaction <hex string>\n"
            "Submits raw transaction (serialized, hex-encoded) to local node and network.");
    }

    bitrpc::RPCTypeCheck(data, params, boost::assign::list_of(json_spirit::str_type));
    if(! data.fSuccess()) return data.JSONRPCError();

    // parse hex string from parameter
    json_spirit::json_flags status;
    std::string hex = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    rpctable_vector txData(hex::ParseHex(hex));
    CDataStream ssData(txData, SER_NETWORK, version::PROTOCOL_VERSION);
    CTransaction tx;

    // deserialize binary data stream
    try {
        ssData >> tx;
    } catch (const std::exception &) {
        return data.JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }
    uint256 hashTx = tx.GetHash();

    // See if the transaction is already in a block
    // or in the memory pool:
    CTransaction existingTx;
    uint256 hashBlock = 0;
    if (block_transaction::manage::GetTransaction(hashTx, existingTx, hashBlock)) {
        if (hashBlock != 0)
            return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("transaction already in block ")+hashBlock.GetHex());
        // Not in block, but already in the memory pool; will drop
        // through to re-relay it.
    } else {
        // push to local node
        CTxDB txdb("r");
        if (! tx.AcceptToMemoryPool(txdb))
            return data.JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX rejected");

        wallet_process::manage::SyncWithWallets(tx, nullptr, true);
    }
    bitrelay::RelayTransaction(tx, hashTx);

    return data.JSONRPCSuccess(hashTx.GetHex());
}

json_spirit::Value CRPCTable::createmultisig(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 2 || params.size() > 3) {
        return data.JSONRPCSuccess(
            "createmultisig <nrequired> <'[\"key\",\"key\"]'>\n"
            "\nCreates a multi-signature address with n signature of m keys required.\n"
            "It returns a json object with the address and redeemScript.");
    }

    json_spirit::json_flags status;
    int nRequired = params[0].get_int(status);
    const json_spirit::Array &keys = params[1].get_array(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);

    // Gather public keys
    if (nRequired < 1)
        return data.runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        return data.runtime_error(strprintf("not enough keys supplied (got %" PRIszu " keys, but need at least %d to redeem)", keys.size(), nRequired));
    if (keys.size() > 16)
        return data.runtime_error("Number of addresses involved in the multisignature address creation > 16\nReduce the number");

    std::vector<CPubKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); ++i) {
        json_spirit::json_flags status;
        const std::string &ks = keys[i].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        CBitcoinAddress address(ks);
        if (address.IsValid()) {
            // Case 1: Bitcoin address and we have full public key
            CKeyID keyID;
            if (! address.GetKeyID(keyID))
                return data.runtime_error(strprintf("%s does not refer to a key", ks.c_str()));

            CPubKey vchPubKey;
            if (! entry::pwalletMain->GetPubKey(keyID, vchPubKey))
                return data.runtime_error(strprintf("no full public key for address %s", ks.c_str()));

            if (! vchPubKey.IsFullyValid())
                return data.runtime_error(std::string(" Invalid public key: ") + ks);

            pubkeys[i] = vchPubKey;
        } else if (hex::IsHex(ks)) {
            // Case 2: hex public key
            CPubKey vchPubKey(hex::ParseHex(ks));
            if (! vchPubKey.IsFullyValid())
                return data.runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        } else
            return data.runtime_error(" Invalid public key: "+ks);
    }

    // Construct using pay-to-script-hash
    CScript inner;
    inner.SetMultisig(nRequired, pubkeys);
    if (inner.size() > Script_const::MAX_SCRIPT_ELEMENT_SIZE)
        return data.runtime_error(strprintf("redeemScript exceeds size limit: %" PRIszu " > %d", inner.size(), Script_const::MAX_SCRIPT_ELEMENT_SIZE));

    CScriptID innerID = inner.GetID();
    CBitcoinAddress address(innerID);

    json_spirit::Object result;
    result.push_back(json_spirit::Pair("address", address.ToString()));
    result.push_back(json_spirit::Pair("redeemScript", util::HexStr(inner.begin(), inner.end())));
    return data.JSONRPCSuccess(result);
}
