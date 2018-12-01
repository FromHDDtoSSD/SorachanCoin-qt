// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h" // for entry::pwalletMain
#include "bitcoinrpc.h"
#include "ui_interface.h"
#include "base58.h"

class CTxDump
{
private:
    CTxDump(); // {}
    CTxDump(const CTxDump &); // {}
    CTxDump &operator=(const CTxDump &); // {}

public:
    CBlockIndex *pindex;
    int64_t nValue;
    bool fSpent;
    CWalletTx *ptx;
    int nOut;
    CTxDump(CWalletTx *ptxIn = NULL, int nOutIn = -1) {
        pindex = NULL;
        nValue = 0;
        fSpent = false;
        ptx = ptxIn;
        nOut = nOutIn;
    }
};

json_spirit::Value CRPCTable::importprivkey(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3) {
        throw std::runtime_error(
            "importprivkey <privkey> [label] [rescan=true]\n"
            "Adds a private key (as returned by dumpprivkey) to your wallet.");
    }

    EnsureWalletIsUnlocked();

    std::string strSecret = params[0].get_str();
    std::string strLabel = "";
    if (params.size() > 1) {
        strLabel = params[1].get_str();
    }

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2) {
        fRescan = params[2].get_bool();
    }

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (! fGood) { 
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    }
    if (CWallet::fWalletUnlockMintOnly) {    // ppcoin: no importprivkey in mint-only mode
        throw bitjson::JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");
    }

    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, fCompressed);
    CKeyID keyid = key.GetPubKey().GetID();
    CBitcoinAddress addr = CBitcoinAddress(keyid);

    {
        LOCK2(block_process::cs_main, entry::pwalletMain->cs_wallet);

        //
        // Don't throw error in case a key is already there
        //
        if (entry::pwalletMain->HaveKey(keyid)) {
            return json_spirit::Value::null;
        }

        entry::pwalletMain->mapKeyMetadata[addr].nCreateTime = 1;
        if (! entry::pwalletMain->AddKey(key)) {
            throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");
        }

        entry::pwalletMain->MarkDirty();
        entry::pwalletMain->SetAddressBookName(addr, strLabel);

        if (fRescan) {
            //
            // whenever a key is imported, we need to scan the whole chain
            //
            entry::pwalletMain->nTimeFirstKey = 1; // 0 would be considered 'no value'

            entry::pwalletMain->ScanForWalletTransactions(block_info::pindexGenesisBlock, true);
            entry::pwalletMain->ReacceptWalletTransactions();
        }
    }

    return json_spirit::Value::null;
}

json_spirit::Value CRPCTable::importaddress(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3) {
        throw std::runtime_error(
            "importaddress <address> [label] [rescan=true]\n"
            "Adds an address or script (in hex) that can be watched as if it were in your wallet but cannot be used to spend.");
    }

    CScript script;
    CBitcoinAddress address(params[0].get_str());
    if (address.IsValid()) {
        if (address.IsPair()) {
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "It's senseless to import pubkey pair address.");
        }
        script.SetAddress(address);
    } else if (hex::IsHex(params[0].get_str())) {
        std::vector<unsigned char> data(hex::ParseHex(params[0].get_str()));
        script = CScript(data.begin(), data.end());
    } else {
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, ("Invalid " + coin_param::strCoinName + " address or script").c_str());
    }

    std::string strLabel = "";
    if (params.size() > 1) {
        strLabel = params[1].get_str();
    }

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2) {
        fRescan = params[2].get_bool();
    }

    {
        LOCK2(block_process::cs_main, entry::pwalletMain->cs_wallet);
        //if (::IsMine(*entry::pwalletMain, script) == MINE_SPENDABLE) {
        if (Script_util::IsMine(*entry::pwalletMain, script) == MINE_SPENDABLE) {
            throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");
        }

        // Don't throw error in case an address is already there
        if (entry::pwalletMain->HaveWatchOnly(script)) {
            return json_spirit::Value::null;
        }

        entry::pwalletMain->MarkDirty();

        if (address.IsValid()) {
            entry::pwalletMain->SetAddressBookName(address, strLabel);
        }
        if (! entry::pwalletMain->AddWatchOnly(script)) {
            throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");
        }
        if (fRescan) {
            entry::pwalletMain->ScanForWalletTransactions(block_info::pindexGenesisBlock, true);
            entry::pwalletMain->ReacceptWalletTransactions();
        }
    }

    return json_spirit::Value::null;
}

json_spirit::Value CRPCTable::removeaddress(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            "removeaddress 'address'\n"
            "\nRemoves watch-only address or script (in hex) added by importaddress.\n"
            "\nArguments:\n"
            "1. 'address' (string, required) The address\n"
            "\nExamples:\n"
            "\nremoveaddress 4EqHMPgEAf56CQmU6ZWS8Ug4d7N3gsQVQA\n"
            "\nRemove watch-only address 4EqHMPgEAf56CQmU6ZWS8Ug4d7N3gsQVQA\n");
    }

    CScript script;

    CBitcoinAddress address(params[0].get_str());
    if (address.IsValid()) {
        if (address.IsPair()) {
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey pair addresses aren't supported.");
        }
        script.SetAddress(address);
    } else if (hex::IsHex(params[0].get_str())) {
        std::vector<unsigned char> data(hex::ParseHex(params[0].get_str()));
        script = CScript(data.begin(), data.end());
    } else {
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address or script");
    }

    // if (::IsMine(*entry::pwalletMain, script) == MINE_SPENDABLE) {
    if (Script_util::IsMine(*entry::pwalletMain, script) == MINE_SPENDABLE) {
        throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "The wallet contains the private key for this address or script - can't remove it");
    }

    if (! entry::pwalletMain->HaveWatchOnly(script)) {
        throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "The wallet does not contain this address or script");
    }

    LOCK2(block_process::cs_main, entry::pwalletMain->cs_wallet);

    entry::pwalletMain->MarkDirty();

    if (! entry::pwalletMain->RemoveWatchOnly(script)) {
        throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "Error removing address from wallet");
    }

    return json_spirit::Value::null;
}

json_spirit::Value CRPCTable::importwallet(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            "importwallet <filename>\n"
            "Imports keys from a wallet dump file (see dumpwallet)."
            + HelpRequiringPassphrase());
    }

    EnsureWalletIsUnlocked();

    if(! wallet_dispatch::ImportWallet(entry::pwalletMain, params[0].get_str().c_str())) {
       throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys to wallet");
    }

    return json_spirit::Value::null;
}

json_spirit::Value CRPCTable::dumpprivkey(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            "dumpprivkey <coinaddress>\n"
            "Reveals the private key corresponding to <coinaddress>.");
    }

    EnsureWalletIsUnlocked();

    std::string strAddress = params[0].get_str();
    CBitcoinAddress address;
    if (! address.SetString(strAddress)) {
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, ("Invalid " + coin_param::strCoinName + " address").c_str());
    }
    if (CWallet::fWalletUnlockMintOnly) {
        throw bitjson::JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");
    }

    CKeyID keyID;
    if (! address.GetKeyID(keyID)) {
        throw bitjson::JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    }

    CSecret vchSecret;
    bool fCompressed;
    if (! entry::pwalletMain->GetSecret(keyID, vchSecret, fCompressed)) {
        throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    }

    return CBitcoinSecret(vchSecret, fCompressed).ToString();
}

json_spirit::Value CRPCTable::dumppem(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 3) {
        throw std::runtime_error(
            "dumppem <coinaddress> <filename> <passphrase>\n"
            "Dump the key pair corresponding to <coinaddress> and store it as encrypted PEM file."
            + HelpRequiringPassphrase());
    }

    EnsureWalletIsUnlocked();

    std::string strAddress = params[0].get_str();
    SecureString strPassKey;
    strPassKey.reserve(100);
    strPassKey = params[2].get_str().c_str();

    CBitcoinAddress address;
    if (! address.SetString(strAddress)) {
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, ("Invalid " + coin_param::strCoinName + " address").c_str());
    }
    if (CWallet::fWalletUnlockMintOnly) {
        throw bitjson::JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");
    }

    CKeyID keyID;
    if (! address.GetKeyID(keyID)) {
        throw bitjson::JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    }
    if (! entry::pwalletMain->GetPEM(keyID, params[1].get_str(), strPassKey)) {
        throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "Error dumping key pair to file");
    }

    return json_spirit::Value::null;
}

json_spirit::Value CRPCTable::dumpwallet(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            "dumpwallet <filename>\n"
            "Dumps all wallet keys in a human-readable format."
            + HelpRequiringPassphrase());
    }

    EnsureWalletIsUnlocked();

    if(! wallet_dispatch::DumpWallet(entry::pwalletMain, params[0].get_str().c_str() )) {
        throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "Error dumping wallet keys to file");
    }

    return json_spirit::Value::null;
}

json_spirit::Value CRPCTable::dumpmalleablekey(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error (
            "dumpmalleablekey <Key view>\n"
            "Dump the private and public key pairs, which correspond to provided key view.\n");
    }

    EnsureWalletIsUnlocked();

    CMalleableKey mKey;
    CMalleableKeyView keyView;
    keyView.SetString(params[0].get_str());

    if (! entry::pwalletMain->GetMalleableKey(keyView, mKey)) {
        throw std::runtime_error("There is no such item in the wallet");
    }

    json_spirit::Object result;
    result.push_back(json_spirit::Pair("PrivatePair", mKey.ToString()));
    result.push_back(json_spirit::Pair("Address", CBitcoinAddress(mKey.GetMalleablePubKey()).ToString()));

    return result;
}

json_spirit::Value CRPCTable::importmalleablekey(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error (
            "importmalleablekey <Key data>\n"
            "Imports the private key pair into your wallet.\n");
    }

    EnsureWalletIsUnlocked();

    CMalleableKey mKey;
    bool fSuccess = mKey.SetString(params[0].get_str());

    json_spirit::Object result;

    if (fSuccess) {
        fSuccess = entry::pwalletMain->AddKey(mKey);
        result.push_back(json_spirit::Pair("Successful", fSuccess));
        result.push_back(json_spirit::Pair("Address", CBitcoinAddress(mKey.GetMalleablePubKey()).ToString()));
        result.push_back(json_spirit::Pair("KeyView", CMalleableKeyView(mKey).ToString()));
    } else {
        result.push_back(json_spirit::Pair("Successful", false));
    }

    return result;
}
