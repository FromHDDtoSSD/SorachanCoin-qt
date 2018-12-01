// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet.h"
#include "bitcoinrpc.h"
#include "init.h"
#include "base58.h"

json_spirit::Value CRPCTable::encryptdata(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 2) {
        throw std::runtime_error(
            "encryptdata <public key> <hex data>\n"
            "Encrypt octet stream with provided public key..\n");
    }

    CPubKey pubKey(hex::ParseHex(params[0].get_str()));

    std::vector<unsigned char> vchEncrypted;
    pubKey.EncryptData(hex::ParseHex(params[1].get_str()), vchEncrypted);

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
    CKey key;
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

    std::vector<unsigned char> vchDecrypted;
    key.DecryptData(hex::ParseHex(params[1].get_str()), vchDecrypted);

    return util::HexStr(vchDecrypted);
}

json_spirit::Value CRPCTable::encryptmessage(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 2) {
        throw std::runtime_error(
            "encryptmessage <public key> <message string>\n"
            "Encrypt message with provided public key.\n");
    }

    CPubKey pubKey(hex::ParseHex(params[0].get_str()));

    std::vector<unsigned char> vchEncrypted;
    std::string strData = params[1].get_str();
    pubKey.EncryptData(std::vector<unsigned char>(strData.begin(), strData.end()), vchEncrypted);

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

    CKey key;
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

    std::vector<unsigned char> vchEncrypted;
    if (! base58::manage::DecodeBase58Check(params[1].get_str(), vchEncrypted)) {
        throw std::runtime_error("Incorrect string");
    }

    std::vector<unsigned char> vchDecrypted;
    key.DecryptData(vchEncrypted, vchDecrypted);

    return std::string((const char *)&vchDecrypted[0], vchDecrypted.size());
}
