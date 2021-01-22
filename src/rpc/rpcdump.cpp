// Copyright (c) 2009-2012 Bitcoin Developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h" // for entry::pwalletMain
#include "bitcoinrpc.h"
#include "ui_interface.h"
#include "address/base58.h"
#include <block/block_process.h>

class CTxDump
{
private:
    CTxDump()=delete;
    CTxDump(const CTxDump &)=delete;
    CTxDump &operator=(const CTxDump &)=delete;
    CTxDump &operator=(const CTxDump &&)=delete;
public:
    CBlockIndex *pindex;
    int64_t nValue;
    bool fSpent;
    CWalletTx *ptx;
    int nOut;
    CTxDump(CWalletTx *ptxIn = nullptr, int nOutIn = -1) {
        pindex = nullptr;
        nValue = 0;
        fSpent = false;
        ptx = ptxIn;
        nOut = nOutIn;
    }
};

json_spirit::Value CRPCTable::importprivkey(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 1 || params.size() > 3) {
        return data.JSONRPCSuccess(
            "importprivkey <privkey> [label] [rescan=true]\n"
            "Adds a private key (as returned by dumpprivkey) to your wallet.");
    }

    json_spirit::Value jv = EnsureWalletIsUnlocked(data);
    if(! data.fSuccess()) return jv;
    json_spirit::json_flags status;
    std::string strSecret = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    std::string strLabel = "";
    if (params.size() > 1) {
        strLabel = params[1].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2) {
        fRescan = params[2].get_bool(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);
    if (! fGood)
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    if (CWallet::fWalletUnlockMintOnly)    // ppcoin: no importprivkey in mint-only mode
        return data.JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");

    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, fCompressed);
    CKeyID keyid = key.GetPubKey().GetID();
    CBitcoinAddress addr = CBitcoinAddress(keyid);
    {
        LOCK2(block_process::cs_main, entry::pwalletMain->cs_wallet);

        // Don't throw error in case a key is already there
        if (entry::pwalletMain->HaveKey(keyid))
            return data.JSONRPCSuccess(json_spirit::Value::null);

        entry::pwalletMain->mapKeyMetadata[addr].nCreateTime = 1;
        if (! entry::pwalletMain->AddKey(key))
            return data.JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        entry::pwalletMain->MarkDirty();
        entry::pwalletMain->SetAddressBookName(addr, strLabel);
        if (fRescan) {
            // whenever a key is imported, we need to scan the whole chain
            entry::pwalletMain->nTimeFirstKey = 1; // 0 would be considered 'no value'
            entry::pwalletMain->ScanForWalletTransactions(block_info::pindexGenesisBlock, true);
            entry::pwalletMain->ReacceptWalletTransactions();
        }
    }
    return data.JSONRPCSuccess(json_spirit::Value::null);
}

json_spirit::Value CRPCTable::importaddress(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 1 || params.size() > 3) {
        return data.JSONRPCSuccess(
            "importaddress <address> [label] [rescan=true]\n"
            "Adds an address or script (in hex) that can be watched as if it were in your wallet but cannot be used to spend.");
    }

    CScript script;
    json_spirit::json_flags status;
    const std::string hexparam0 = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CBitcoinAddress address(hexparam0);
    if (address.IsValid()) {
        if (address.IsPair())
            return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "It's senseless to import pubkey pair address.");
        script.SetAddress(address);
    } else if (hex::IsHex(hexparam0)) {
        rpctable_vector data(hex::ParseHex(hexparam0));
        script = CScript(data.begin(), data.end());
    } else
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid " + coin_param::strCoinName + " address or script");

    std::string strLabel = "";
    if (params.size() > 1) {
        strLabel = params[1].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2) {
        fRescan = params[2].get_bool(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    {
        LOCK2(block_process::cs_main, entry::pwalletMain->cs_wallet);
        if (Script_util::IsMine(*entry::pwalletMain, script) == MINE_SPENDABLE)
            return data.JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");

        // Don't throw error in case an address is already there
        if (entry::pwalletMain->HaveWatchOnly(script))
            return data.JSONRPCSuccess(json_spirit::Value::null);

        entry::pwalletMain->MarkDirty();
        if (address.IsValid())
            entry::pwalletMain->SetAddressBookName(address, strLabel);
        if (! entry::pwalletMain->AddWatchOnly(script))
            return data.JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");
        if (fRescan) {
            entry::pwalletMain->ScanForWalletTransactions(block_info::pindexGenesisBlock, true);
            entry::pwalletMain->ReacceptWalletTransactions();
        }
    }

    return data.JSONRPCSuccess(json_spirit::Value::null);
}

json_spirit::Value CRPCTable::removeaddress(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "removeaddress 'address'\n"
            "\nRemoves watch-only address or script (in hex) added by importaddress.\n"
            "\nArguments:\n"
            "1. 'address' (string, required) The address\n"
            "\nExamples:\n"
            "\nremoveaddress 4EqHMPgEAf56CQmU6ZWS8Ug4d7N3gsQVQA\n"
            "\nRemove watch-only address 4EqHMPgEAf56CQmU6ZWS8Ug4d7N3gsQVQA\n");
    }

    CScript script;
    json_spirit::json_flags status;
    std::string hexparam0 = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CBitcoinAddress address(hexparam0);
    if (address.IsValid()) {
        if (address.IsPair())
            return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey pair addresses aren't supported.");
        script.SetAddress(address);
    } else if (hex::IsHex(hexparam0)) {
        rpctable_vector data(hex::ParseHex(hexparam0));
        script = CScript(data.begin(), data.end());
    } else
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address or script");

    if (Script_util::IsMine(*entry::pwalletMain, script) == MINE_SPENDABLE)
        return data.JSONRPCError(RPC_WALLET_ERROR, "The wallet contains the private key for this address or script - can't remove it");

    if (! entry::pwalletMain->HaveWatchOnly(script))
        return data.JSONRPCError(RPC_WALLET_ERROR, "The wallet does not contain this address or script");

    LOCK2(block_process::cs_main, entry::pwalletMain->cs_wallet);
    entry::pwalletMain->MarkDirty();
    if (! entry::pwalletMain->RemoveWatchOnly(script))
        return data.JSONRPCError(RPC_WALLET_ERROR, "Error removing address from wallet");
    return data.JSONRPCSuccess(json_spirit::Value::null);
}

json_spirit::Value CRPCTable::importwallet(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "importwallet <filename>\n"
            "Imports keys from a wallet dump file (see dumpwallet)."
            + HelpRequiringPassphrase());
    }

    json_spirit::Value jv = EnsureWalletIsUnlocked(data);
    if(! data.fSuccess()) return jv;
    json_spirit::json_flags status;
    std::string str = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if(! wallet_dispatch::ImportWallet(entry::pwalletMain, str.c_str()))
       return data.JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys to wallet");
    return data.JSONRPCSuccess(json_spirit::Value::null);
}

json_spirit::Value CRPCTable::dumpprivkey(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "dumpprivkey <coinaddress>\n"
            "Reveals the private key corresponding to <coinaddress>.");
    }

    json_spirit::Value jv = EnsureWalletIsUnlocked(data);
    if(! data.fSuccess()) return jv;
    json_spirit::json_flags status;
    std::string strAddress = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CBitcoinAddress address;
    if (! address.SetString(strAddress))
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid " + coin_param::strCoinName + " address");
    if (CWallet::fWalletUnlockMintOnly)
        return data.JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");

    CKeyID keyID;
    if (! address.GetKeyID(keyID))
        return data.JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");

    CSecret vchSecret;
    bool fCompressed;
    if (! entry::pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
        return data.JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");

    return data.JSONRPCSuccess(CBitcoinSecret(vchSecret, fCompressed).ToString());
}

json_spirit::Value CRPCTable::dumppem(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 3) {
        return data.JSONRPCSuccess(
            "dumppem <coinaddress> <filename> <passphrase>\n"
            "Dump the key pair corresponding to <coinaddress> and store it as encrypted PEM file."
            + HelpRequiringPassphrase());
    }

    json_spirit::Value jv = EnsureWalletIsUnlocked(data);
    if(! data.fSuccess()) return jv;

    json_spirit::json_flags status;
    std::string strAddress = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    SecureString strPassKey;
    strPassKey.reserve(100);
    strPassKey(const_cast<std::string &>(params[2].get_str(status))); // Note: should operate () (SecureAllocator)
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);

    CBitcoinAddress address;
    if (! address.SetString(strAddress))
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid " + coin_param::strCoinName + " address");
    if (CWallet::fWalletUnlockMintOnly)
        return data.JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");

    CKeyID keyID;
    if (! address.GetKeyID(keyID))
        return data.JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");

    std::string str = params[1].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if (! entry::pwalletMain->GetPEM(keyID, str, strPassKey))
        return data.JSONRPCError(RPC_WALLET_ERROR, "Error dumping key pair to file");

    return data.JSONRPCSuccess(json_spirit::Value::null);
}

json_spirit::Value CRPCTable::dumpwallet(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "dumpwallet <filename>\n"
            "Dumps all wallet keys in a human-readable format."
            + HelpRequiringPassphrase());
    }

    json_spirit::Value jv = EnsureWalletIsUnlocked(data);
    if(! data.fSuccess()) return jv;
    json_spirit::json_flags status;
    std::string str = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if(! wallet_dispatch::DumpWallet(entry::pwalletMain, str.c_str()))
        return data.JSONRPCError(RPC_WALLET_ERROR, "Error dumping wallet keys to file");
    return data.JSONRPCSuccess(json_spirit::Value::null);
}

json_spirit::Value CRPCTable::dumpmalleablekey(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "dumpmalleablekey <Key view>\n"
            "Dump the private and public key pairs, which correspond to provided key view.\n");
    }

    json_spirit::Value jv = EnsureWalletIsUnlocked(data);
    if(! data.fSuccess()) return jv;
    CMalleableKey mKey;
    CMalleableKeyView keyView;
    json_spirit::json_flags status;
    std::string str = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    keyView.SetString(str);
    if (! entry::pwalletMain->GetMalleableKey(keyView, mKey))
        return data.runtime_error("There is no such item in the wallet");

    json_spirit::Object result;
    result.push_back(json_spirit::Pair("PrivatePair", mKey.ToString()));
    result.push_back(json_spirit::Pair("Address", CBitcoinAddress(mKey.GetMalleablePubKey()).ToString()));
    return data.JSONRPCSuccess(result);
}

json_spirit::Value CRPCTable::importmalleablekey(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "importmalleablekey <Key data>\n"
            "Imports the private key pair into your wallet.\n");
    }

    json_spirit::Value jv = EnsureWalletIsUnlocked(data);
    if(! data.fSuccess()) return jv;

    CMalleableKey mKey;
    json_spirit::json_flags status;
    std::string str = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    bool fSuccess = mKey.SetString(str);

    json_spirit::Object result;
    if (fSuccess) {
        fSuccess = entry::pwalletMain->AddKey(mKey);
        result.push_back(json_spirit::Pair("Successful", fSuccess));
        result.push_back(json_spirit::Pair("Address", CBitcoinAddress(mKey.GetMalleablePubKey()).ToString()));
        result.push_back(json_spirit::Pair("KeyView", CMalleableKeyView(mKey).ToString()));
    } else
        result.push_back(json_spirit::Pair("Successful", false));

    return data.JSONRPCSuccess(result);
}
