// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet.h>
#include <rpc/bitcoinrpc.h>
#include <init.h>
#include <address/base58.h>

json_spirit::Value CRPCTable::encryptdata(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() != 2) {
        return data.JSONRPCSuccess(
            "encryptdata <public key> <hex data>\n"
            "Encrypt octet stream with provided public key..\n");
    }

    json_spirit::json_flags status;
    std::string hex = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CPubKey pubKey(hex::ParseHex(hex));
    rpctable_vector vchEncrypted;
    hex = params[1].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    pubKey.EncryptData(hex::ParseHex(hex), vchEncrypted);
    return data.JSONRPCSuccess(util::HexStr(vchEncrypted));
}

json_spirit::Value CRPCTable::decryptdata(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() != 2) {
        return data.JSONRPCSuccess(
            "decryptdata <coin address or private key> <encrypted stream>\n"
            "Decrypt octet stream.\n");
    }

    json_spirit::Value jv = EnsureWalletIsUnlocked(data);
    if(! data.fSuccess()) return jv;
    CKey key;
    json_spirit::json_flags status;
    std::string str = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CBitcoinAddress addr(str);
    if (addr.IsValid()) {
        CKeyID keyID;
        addr.GetKeyID(keyID);
        if (! entry::pwalletMain->GetKey(keyID, key))
            return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "We have no private key for this address");
    } else {
        CBitcoinSecret vchSecret;
        str = params[0].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        if (! vchSecret.SetString(str))
            return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Provided private key is inconsistent.");
        bool fCompressed;
        CSecret secret = vchSecret.GetSecret(fCompressed);
        key.SetSecret(secret, fCompressed);
    }

    rpctable_vector vchDecrypted;
    str = params[1].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    key.DecryptData(hex::ParseHex(str), vchDecrypted);
    return data.JSONRPCSuccess(util::HexStr(vchDecrypted));
}

json_spirit::Value CRPCTable::encryptmessage(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() != 2) {
        return data.JSONRPCSuccess(
            "encryptmessage <public key> <message string>\n"
            "Encrypt message with provided public key.\n");
    }

    json_spirit::json_flags status;
    std::string hex = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CPubKey pubKey(hex::ParseHex(hex));
    rpctable_vector vchEncrypted;
    std::string strData = params[1].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    pubKey.EncryptData(rpctable_vector(strData.begin(), strData.end()), vchEncrypted);
    return data.JSONRPCSuccess(base58::manage::EncodeBase58Check(vchEncrypted));
}

json_spirit::Value CRPCTable::decryptmessage(const json_spirit::Array &params, CBitrpcData &data) noexcept {
    if (data.fHelp() || params.size() != 2) {
        return data.JSONRPCSuccess(
            "decryptmessage <coin address or private key> <encrypted message>\n"
            "Decrypt message string.\n");
    }

    EnsureWalletIsUnlocked(data);
    if(! data.fSuccess()) return data.JSONRPCError();

    CKey key;
    json_spirit::json_flags status;
    std::string str = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CBitcoinAddress addr(str);
    if (addr.IsValid()) {
        CKeyID keyID;
        addr.GetKeyID(keyID);
        if (! entry::pwalletMain->GetKey(keyID, key))
            return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "We have no private key for this address");
    } else {
        CBitcoinSecret vchSecret;
        str = params[0].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        if (! vchSecret.SetString(str))
            return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Provided private key is inconsistent.");

        bool fCompressed;
        CSecret secret = vchSecret.GetSecret(fCompressed);
        key.SetSecret(secret, fCompressed);
    }

    rpctable_vector vchEncrypted;
    str = params[1].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if (! base58::manage::DecodeBase58Check(str, vchEncrypted))
        return data.runtime_error("Incorrect string");

    rpctable_vector vchDecrypted;
    key.DecryptData(vchEncrypted, vchDecrypted);
    return data.JSONRPCSuccess(std::string((const char *)&vchDecrypted[0], vchDecrypted.size()));
}
