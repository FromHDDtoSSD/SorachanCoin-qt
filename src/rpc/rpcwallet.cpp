// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet.h>
#include <walletdb.h>
#include <rpc/bitcoinrpc.h>
#include <init.h>
#include <util.h>
#include <ntp.h>
#include <address/base58.h>
#include <miner.h>
#include <boot/shutdown.h>
#include <block/block_process.h>
#include <miner/diff.h>
#include <block/block_alert.h>
#include <util/time.h>
#include <util/strencodings.h> // HexStr (Witness)
#include <util/thread.h>

std::string CRPCTable::HelpRequiringPassphrase() noexcept {
    return entry::pwalletMain->IsCrypted()
        ? "\n\nRequires wallet passphrase to be set with walletpassphrase first"
        : "";
}

json_spirit::Value CRPCTable::EnsureWalletIsUnlocked(CBitrpcData &data) noexcept {
    if (entry::pwalletMain->IsLocked())
        return data.JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    if (CWallet::fWalletUnlockMintOnly)
        return data.JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Wallet unlocked for block minting only.");
    return data.JSONRPCSuccess(json_spirit::Value::null);
}

void CRPCTable::WalletTxToJSON(const CWalletTx &wtx, json_spirit::Object &entry) {
    int confirms = wtx.GetDepthInMainChain();
    entry.push_back(json_spirit::Pair("confirmations", confirms));
    if (wtx.IsCoinBase() || wtx.IsCoinStake())
        entry.push_back(json_spirit::Pair("generated", true));

    if (confirms) {
        entry.push_back(json_spirit::Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(json_spirit::Pair("blockindex", wtx.nIndex));
        entry.push_back(json_spirit::Pair("blocktime", (int64_t)(block_info::mapBlockIndex[wtx.hashBlock]->get_nTime())));
    }
    entry.push_back(json_spirit::Pair("txid", wtx.GetHash().GetHex()));
    entry.push_back(json_spirit::Pair("time", (int64_t)wtx.GetTxTime()));
    entry.push_back(json_spirit::Pair("timereceived", (int64_t)wtx.nTimeReceived));
    for(const std::pair<std::string, std::string> &item: wtx.mapValue)
        entry.push_back(json_spirit::Pair(item.first, item.second));
}

bool CRPCTable::TopUpKeyPool(CBitrpcData &data, unsigned int nSize/* = 0*/) {
    bool ret = entry::pwalletMain->TopUpKeyPool(nSize);
    if(! ret) data.runtime_error("TopUpKeyPool() : writing generated key failed");
    return ret;
}

std::string CRPCTable::AccountFromValue(const json_spirit::Value &value, CBitrpcData &data) {
    json_spirit::json_flags status;
    std::string strAccount = value.get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    bool ret = (strAccount == "*")? false: true;
    if(ret)
        data.JSONRPCSuccess(strAccount);
    else
        data.JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, data.e + "Invalid account name");

    return strAccount;
}

json_spirit::Value CRPCTable::getinfo(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 0) {
        return data.JSONRPCSuccess(
            "getinfo\n"
            "Returns an object containing various state info.");
    }

    netbase::proxyType proxy;
    netbase::manage::GetProxy(netbase::NET_IPV4, proxy);

    json_spirit::Object obj, diff, timestamping;
    obj.push_back(json_spirit::Pair("version", format_version::FormatFullVersion()));
    obj.push_back(json_spirit::Pair("protocolversion",(int)version::PROTOCOL_VERSION));
    obj.push_back(json_spirit::Pair("walletversion", entry::pwalletMain->GetVersion()));
    obj.push_back(json_spirit::Pair("balance", ValueFromAmount(entry::pwalletMain->GetBalance())));
    obj.push_back(json_spirit::Pair("unspendable", ValueFromAmount(entry::pwalletMain->GetWatchOnlyBalance())));
    obj.push_back(json_spirit::Pair("newmint", ValueFromAmount(entry::pwalletMain->GetNewMint())));
    obj.push_back(json_spirit::Pair("stake", ValueFromAmount(entry::pwalletMain->GetStake())));
    obj.push_back(json_spirit::Pair("blocks", (int)block_info::nBestHeight));

    timestamping.push_back(json_spirit::Pair("systemclock", bitsystem::GetTime()));
    timestamping.push_back(json_spirit::Pair("adjustedtime", bitsystem::GetAdjustedTime()));

    int64_t nNtpOffset = ntp_ext::GetNtpOffset(),
            nP2POffset = bitsystem::GetNodesOffset();

    timestamping.push_back(json_spirit::Pair("ntpoffset", nNtpOffset != INT64_MAX ? nNtpOffset : json_spirit::Value::null));
    timestamping.push_back(json_spirit::Pair("p2poffset", nP2POffset != INT64_MAX ? nP2POffset : json_spirit::Value::null));

    obj.push_back(json_spirit::Pair("timestamping", timestamping));

    obj.push_back(json_spirit::Pair("moneysupply", ValueFromAmount(block_info::pindexBest->get_nMoneySupply())));
    obj.push_back(json_spirit::Pair("connections", (int)net_node::vNodes.size()));
    obj.push_back(json_spirit::Pair("proxy", (proxy.first.IsValid() ? proxy.first.ToStringIPPort() : std::string())));
    obj.push_back(json_spirit::Pair("ip", bitsocket::addrSeenByPeer.ToStringIP()));

    diff.push_back(json_spirit::Pair("proof-of-work", GetDifficulty()));
    diff.push_back(json_spirit::Pair("proof-of-stake", GetDifficulty(diff::spacing::GetLastBlockIndex(block_info::pindexBest, true))));
    obj.push_back(json_spirit::Pair("difficulty", diff));

    obj.push_back(json_spirit::Pair("testnet", (bool)args_bool::fTestNet));
    obj.push_back(json_spirit::Pair("keypoololdest", (int64_t)entry::pwalletMain->GetOldestKeyPoolTime()));
    obj.push_back(json_spirit::Pair("keypoolsize", (int)entry::pwalletMain->GetKeyPoolSize()));
    obj.push_back(json_spirit::Pair("paytxfee", ValueFromAmount(block_info::nTransactionFee)));
    obj.push_back(json_spirit::Pair("mininput", ValueFromAmount(block_info::nMinimumInputValue)));
    if (entry::pwalletMain->IsCrypted())
        obj.push_back(json_spirit::Pair("unlocked_until", (int64_t)nWalletUnlockTime / 1000));

    obj.push_back(json_spirit::Pair("errors", block_alert::GetWarnings("statusbar")));
    return data.JSONRPCSuccess(obj);
}

json_spirit::Value CRPCTable::getnetworkhashps(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 0) {
        return data.JSONRPCSuccess(
            "getnetworkhashps\n"
            "Return a networkhashps.");
    }

    json_spirit::Object obj;
    std::ostringstream stream;
    stream << (double)((double)((int64_t)((double)GetPoWMHashPS()*1000*1000*10))/10);
    obj.push_back(json_spirit::Pair("networkhashps", stream.str().c_str()));
    return data.JSONRPCSuccess(obj);
}

json_spirit::Value CRPCTable::getkernelps(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 0) {
        return data.JSONRPCSuccess(
            "getkernelps\n"
            "Return a kernelps.");
    }

    json_spirit::Object obj;
    std::ostringstream stream;
    stream << (double)GetPoSKernelPS();
    obj.push_back(json_spirit::Pair("getkernelps", stream.str().c_str()));
    return data.JSONRPCSuccess(obj);
}

json_spirit::Value CRPCTable::getblockchaininfo(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 0) {
        return data.JSONRPCSuccess(
            "getblockchaininfo\n"
            "Returns an object containing various state info regarding blockchain processing.");
    }

    json_spirit::Object obj, diff;
    obj.push_back(json_spirit::Pair("chain", args_bool::fTestNet? "testnet": "main"));
    obj.push_back(json_spirit::Pair("blocks", (int)block_info::nBestHeight));
    obj.push_back(json_spirit::Pair("headers", (int)block_info::nBestHeight));
    obj.push_back(json_spirit::Pair("bestblockhash", block_info::hashBestChain.ToString()));

    diff.push_back(json_spirit::Pair("proof-of-work", GetDifficulty()));
    diff.push_back(json_spirit::Pair("proof-of-stake", GetDifficulty(diff::spacing::GetLastBlockIndex(block_info::pindexBest, true))));
    diff.push_back(json_spirit::Pair("search-interval", (int)block_info::nLastCoinStakeSearchInterval));
    obj.push_back(json_spirit::Pair("difficulty", diff));

    const CBlockIndex *block = block_info::mapBlockIndex[block_info::hashBestChain];
    obj.push_back(json_spirit::Pair("mediantime", block->GetMedianTimePast()));
    obj.push_back(json_spirit::Pair("verificationprogress", (double)1.0)); // under development
    obj.push_back(json_spirit::Pair("initialblockdownload", block_notify<uint256>::IsInitialBlockDownload()));

    obj.push_back(json_spirit::Pair("chainwork", block_info::nBestChainTrust.ToString()));
    obj.push_back(json_spirit::Pair("size_on_disk", 0)); // under development
    obj.push_back(json_spirit::Pair("pruned", false)); // under development

    auto forks_info = [](const char *id, int version, bool freject) {
        json_spirit::Object bip, rej;
        rej.push_back(json_spirit::Pair("status", freject));
        bip.push_back(json_spirit::Pair("id", id));
        bip.push_back(json_spirit::Pair("version", version));
        bip.push_back(json_spirit::Pair("reject", rej));
        return bip;
    };

    json_spirit::Array softforks;
    softforks.push_back(forks_info("bip34", 2, false)); // under development
    softforks.push_back(forks_info("bip66", 3, true));
    softforks.push_back(forks_info("bip65", 4, true));
    obj.push_back(json_spirit::Pair("softforks", softforks));

    auto bip9_forks_info = [](bool status, uint64_t start, uint64_t timeout, uint64_t since) {
        json_spirit::Object bip;
        bip.push_back(json_spirit::Pair("status", status? "active": "inactive"));
        bip.push_back(json_spirit::Pair("startTime", start));
        bip.push_back(json_spirit::Pair("timeout", timeout));
        bip.push_back(json_spirit::Pair("since", since));
        return bip;
    };

    // under development
    json_spirit::Object bip9;
    bip9.push_back(json_spirit::Pair("csv", bip9_forks_info(false, 0, 0, 0)));
    bip9.push_back(json_spirit::Pair("segwit", bip9_forks_info(false, 0, 0, 0)));
    obj.push_back(json_spirit::Pair("bip9_softforks", bip9));

    // under development
    obj.push_back(json_spirit::Pair("warning", ""));
    return data.JSONRPCSuccess(obj);
}

json_spirit::Value CRPCTable::getnetworkinfo(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 0) {
        return data.JSONRPCSuccess(
            "getnetworkinfo\n"
            "Returns an object containing various state info regarding P2P networking.");
    }

    json_spirit::Object obj;
    return data.JSONRPCSuccess(obj);
}

json_spirit::Value CRPCTable::getwalletinfo(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 0) {
        return data.JSONRPCSuccess(
            "getwalletinfo\n"
            "Returns an object containing various wallet state info.");
    }

    json_spirit::Object obj;
    return data.JSONRPCSuccess(obj);
}

json_spirit::Value CRPCTable::getnewaddress(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 1) {
        return data.JSONRPCSuccess(
            "getnewaddress [account]\n"
            "Returns a new " strCoinName " address for receiving payments.  "
            "If [account] is specified (recommended), it is added to the address book "
            "so payments received with the address will be credited to [account].");
    }

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount;
    if (params.size() > 0)
        strAccount = AccountFromValue(params[0], data);
    if(! data.fSuccess()) return data.JSONRPCError();
    if (! entry::pwalletMain->IsLocked()) {
        if(! TopUpKeyPool(data))
            return data.runtime_error();
    }

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (! entry::pwalletMain->GetKeyFromPool(newKey, false))
        return data.JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    CBitcoinAddress address(newKey.GetID()); // PublicKey => BitcoinAddress (SHA256, Base58)
    entry::pwalletMain->SetAddressBookName(address, strAccount);
    return data.JSONRPCSuccess(address.ToString());
}

CBitcoinAddress CRPCTable::GetAccountAddress(CBitrpcData &data, std::string strAccount, bool bForceNew/* =false */, bool *ret/*=nullptr*/) {
    CWalletDB walletdb(entry::pwalletMain->strWalletFile);
    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    bool bKeyUsed = false;
    // Check if the current key has been used
    if (account.vchPubKey.IsValid()) {
        CScript scriptPubKey;
        scriptPubKey.SetDestination(account.vchPubKey.GetID());
        for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end() && account.vchPubKey.IsValid(); ++it) {
            const CWalletTx &wtx = (*it).second;
            for(const CTxOut &txout: wtx.get_vout()) {
                if (txout.get_scriptPubKey() == scriptPubKey)
                    bKeyUsed = true;
            }
        }
    }

    // Generate a new key
    if (!account.vchPubKey.IsValid() || bForceNew || bKeyUsed) {
        if (! entry::pwalletMain->GetKeyFromPool(account.vchPubKey, false)) {
            data.JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
            return CBitcoinAddress("0");
        }

        entry::pwalletMain->SetAddressBookName(account.vchPubKey.GetID(), strAccount);
        walletdb.WriteAccount(strAccount, account);
    }

    CBitcoinAddress addr = CBitcoinAddress(account.vchPubKey.GetID());
    data.JSONRPCSuccess(addr.ToString());
    return addr;
}

json_spirit::Value CRPCTable::getaccountaddress(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "getaccountaddress <account>\n"
            "Returns the current " strCoinName " address for receiving payments to this account.");
    }

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount = AccountFromValue(params[0], data);
    if(! data.fSuccess()) return data.JSONRPCError();
    CBitcoinAddress addr = GetAccountAddress(data, strAccount);
    if(! data.fSuccess()) return data.JSONRPCError();
    return data.JSONRPCSuccess(addr.ToString());
}

json_spirit::Value CRPCTable::setaccount(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 1 || params.size() > 2) {
        return data.JSONRPCSuccess(
            "setaccount <coinaddress> <account>\n"
            "Sets the account associated with the given address.");
    }

    json_spirit::json_flags status;
    std::string str = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CBitcoinAddress address(str);
    if (! address.IsValid())
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid " strCoinName " address");

    std::string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1], data);
    if(! data.fSuccess()) return data.JSONRPCError();

    // Detect when changing the account of an address that is the 'unused current key' of another account:
    if (entry::pwalletMain->mapAddressBook.count(address)) {
        std::string strOldAccount = entry::pwalletMain->mapAddressBook[address];
        CBitcoinAddress cadr = GetAccountAddress(data, strOldAccount);
        if(! data.fSuccess()) return data.JSONRPCError();
        if (address == cadr) {
            GetAccountAddress(data, strOldAccount, true);
            if(! data.fSuccess()) return data.JSONRPCError();
        }
    }

    entry::pwalletMain->SetAddressBookName(address, strAccount);
    return data.JSONRPCSuccess(json_spirit::Value::null);
}

json_spirit::Value CRPCTable::getaccount(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "getaccount <coinaddress>\n"
            "Returns the account associated with the given address.");
    }

    json_spirit::json_flags status;
    std::string str = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CBitcoinAddress address(str);
    if (! address.IsValid())
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid " strCoinName " address");

    std::string strAccount;
    std::map<CBitcoinAddress, std::string>::iterator mi = entry::pwalletMain->mapAddressBook.find(address);
    if (mi != entry::pwalletMain->mapAddressBook.end() && !(*mi).second.empty())
        strAccount = (*mi).second;

    return data.JSONRPCSuccess(strAccount);
}

json_spirit::Value CRPCTable::getaddressesbyaccount(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "getaddressesbyaccount <account>\n"
            "Returns the list of addresses for the given account.");
    }

    std::string strAccount = AccountFromValue(params[0], data);
    if(! data.fSuccess()) return data.JSONRPCError();

    // Find all addresses that have the given account
    json_spirit::Array ret;
    for(const std::pair<CBitcoinAddress, std::string> &item: entry::pwalletMain->mapAddressBook) {
        const CBitcoinAddress &address = item.first;
        const std::string &strName = item.second;
        if (strName == strAccount)
            ret.push_back(address.ToString());
    }
    return data.JSONRPCSuccess(ret);
}

json_spirit::Value CRPCTable::mergecoins(const json_spirit::Array& params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 3) {
        return data.JSONRPCSuccess(
            "mergecoins <amount> <minvalue> <outputvalue>\n"
            "<amount> is resulting inputs sum\n"
            "<minvalue> is minimum value of inputs which are used in join process\n"
            "<outputvalue> is resulting value of inputs which will be created\n"
            "All values are real and and rounded to the nearest " + strenc::FormatMoney(block_info::nMinimumInputValue)
            + HelpRequiringPassphrase());
    }

    if (entry::pwalletMain->IsLocked())
        return data.JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    // Total amount
    data.e = "Total";
    int64_t nAmount = AmountFromValue(params[0], data);
    if(! data.fSuccess()) return data.JSONRPCError();

    // Min input amount
    data.e = "Min input";
    int64_t nMinValue = AmountFromValue(params[1], data);
    if(! data.fSuccess()) return data.JSONRPCError();

    // Output amount
    data.e = "Output";
    int64_t nOutputValue = AmountFromValue(params[2], data);
    if(! data.fSuccess()) return data.JSONRPCError();

    if (nAmount < block_info::nMinimumInputValue)
        return data.JSONRPCError(RPC_WALLET_AMOUNT_TOO_SMALL, "Send amount too small");
    if (nMinValue < block_info::nMinimumInputValue)
        return data.JSONRPCError(RPC_WALLET_AMOUNT_TOO_SMALL, "Max value too small");
    if (nOutputValue < block_info::nMinimumInputValue)
        return data.JSONRPCError(RPC_WALLET_AMOUNT_TOO_SMALL, "Output value too small");
    if (nOutputValue < nMinValue)
        return data.JSONRPCError(RPC_WALLET_AMOUNT_TOO_SMALL, "Output value is lower than min value");

    std::list<uint256> listMerged;
    if (! entry::pwalletMain->MergeCoins(nAmount, nMinValue, nOutputValue, listMerged))
        return data.JSONRPCSuccess(json_spirit::Value::null);

    json_spirit::Array mergedHashes;
    for(const uint256 txHash: listMerged)
        mergedHashes.push_back(txHash.GetHex());

    return data.JSONRPCSuccess(mergedHashes);
}

json_spirit::Value CRPCTable::sendtoaddress(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 2 || params.size() > 4) {
        return data.JSONRPCSuccess(
            "sendtoaddress <coinaddress> <amount> [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest " + strenc::FormatMoney(block_info::nMinimumInputValue)
            + HelpRequiringPassphrase());
    }

    // Parse address
    CScript scriptPubKey;
    json_spirit::json_flags status;
    std::string strAddress = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CBitcoinAddress address(strAddress);
    if (address.IsValid())
        scriptPubKey.SetAddress(address);
    else
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid " strCoinName " address");

    // Amount
    int64_t nAmount = AmountFromValue(params[1], data);
    if(! data.fSuccess()) return data.JSONRPCError();
    if (nAmount < block_info::nMinimumInputValue)
        return data.JSONRPCError(RPC_WALLET_AMOUNT_TOO_SMALL, "Send amount too small");

    // Wallet comments
    std::string jparam2 = params[2].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    std::string jparam3 = params[3].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CWalletTx wtx;
    if (params.size() > 2 && params[2].type() != json_spirit::null_type && !jparam2.empty())
        wtx.mapValue["comment"] = jparam2;
    if (params.size() > 3 && params[3].type() != json_spirit::null_type && !jparam3.empty())
        wtx.mapValue["to"] = jparam3;
    if (entry::pwalletMain->IsLocked())
        return data.JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    std::string strError = entry::pwalletMain->SendMoney(scriptPubKey, nAmount, wtx);
    if (! strError.empty())
        return data.JSONRPCError(RPC_WALLET_ERROR, strError);

    return data.JSONRPCSuccess(wtx.GetHash().GetHex());
}

json_spirit::Value CRPCTable::listaddressgroupings(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp()) {
        return data.JSONRPCSuccess(
            "listaddressgroupings\n"
            "Lists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions");
    }

    json_spirit::Array jsonGroupings;
    std::map<CBitcoinAddress, int64_t> balances = entry::pwalletMain->GetAddressBalances();
    for(std::set<CBitcoinAddress> grouping: entry::pwalletMain->GetAddressGroupings()) {
        json_spirit::Array jsonGrouping;
        for(CBitcoinAddress address: grouping) {
            json_spirit::Array addressInfo;
            addressInfo.push_back(address.ToString());
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                LOCK(entry::pwalletMain->cs_wallet);
                if (entry::pwalletMain->mapAddressBook.find(address) != entry::pwalletMain->mapAddressBook.end())
                    addressInfo.push_back(entry::pwalletMain->mapAddressBook.find(address)->second);
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return data.JSONRPCSuccess(jsonGroupings);
}

json_spirit::Value CRPCTable::signmessage(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 2) {
        return data.JSONRPCSuccess(
            "signmessage <coinaddress> <message>\n"
            "Sign a message with the private key of an address");
    }

    json_spirit::Value jv = EnsureWalletIsUnlocked(data);
    if(! data.fSuccess()) return jv;
    json_spirit::json_flags status;
    std::string strAddress = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    std::string strMessage = params[1].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);

    CBitcoinAddress addr(strAddress);
    if (! addr.IsValid())
        return data.JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (! addr.GetKeyID(keyID))
        return data.JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    CKey key;
    if (! entry::pwalletMain->GetKey(keyID, key))
        return data.JSONRPCError(RPC_WALLET_ERROR, "Private key not available");

    CDataStream ss;
    ss << block_info::strMessageMagic;
    ss << strMessage;

    std::vector<unsigned char> vchSig;
    if (! key.SignCompact(hash_basis::Hash(ss.begin(), ss.end()), vchSig))
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return data.JSONRPCSuccess(strenc::EncodeBase64(&vchSig[0], vchSig.size()));
}

json_spirit::Value CRPCTable::verifymessage(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 3) {
        return data.JSONRPCSuccess(
            "verifymessage <coinaddress> <signature> <message>\n"
            "Verify a signed message");
    }

    json_spirit::json_flags status;
    std::string strAddress  = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    std::string strSign     = params[1].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    std::string strMessage  = params[2].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);

    CBitcoinAddress addr(strAddress);
    if (! addr.IsValid())
        return data.JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (! addr.GetKeyID(keyID))
        return data.JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = strenc::DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CDataStream ss;
    ss << block_info::strMessageMagic;
    ss << strMessage;

    CPubKey key;
    if (! key.SetCompactSignature(hash_basis::Hash(ss.begin(), ss.end()), vchSig))
        return data.JSONRPCSuccess(false);

    return data.JSONRPCSuccess(key.GetID() == keyID);
}

json_spirit::Value CRPCTable::getreceivedbyaddress(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 1 || params.size() > 2) {
        return data.JSONRPCSuccess(
            "getreceivedbyaddress <coinaddress> [minconf=1]\n"
            "Returns the total amount received by <coinaddress> in transactions with at least [minconf] confirmations.");
    }

    // Bitcoin address
    json_spirit::json_flags status;
    std::string str = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CBitcoinAddress address = CBitcoinAddress(str);
    if (! address.IsValid())
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid " strCoinName " address");
    if (! Script_util::IsMine(*entry::pwalletMain,address))
        return data.JSONRPCSuccess(0.0);

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1) {
        nMinDepth = params[1].get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    int64_t nAmount = 0;
    for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); ++it) {
        const CWalletTx &wtx = (*it).second;
        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !wtx.IsFinal())
            continue;

        for(const CTxOut &txout: wtx.get_vout()) {
            CBitcoinAddress addressRet;
            if (! Script_util::ExtractAddress(*entry::pwalletMain, txout.get_scriptPubKey(), addressRet))
                continue;
            if (addressRet == address) {
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.get_nValue();
            }
        }
    }
    return data.JSONRPCSuccess(ValueFromAmount(nAmount));
}

void CRPCTable::GetAccountAddresses(std::string strAccount, std::set<CBitcoinAddress> &setAddress) {
    for(const std::pair<CBitcoinAddress, std::string> &item: entry::pwalletMain->mapAddressBook) {
        const CBitcoinAddress &address = item.first;
        const std::string &strName = item.second;
        if (strName == strAccount)
            setAddress.insert(address);
    }
}

json_spirit::Value CRPCTable::getreceivedbyaccount(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 1 || params.size() > 2) {
        return data.JSONRPCSuccess(
            "getreceivedbyaccount <account> [minconf=1]\n"
            "Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.");
    }

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1) {
        json_spirit::json_flags status;
        nMinDepth = params[1].get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    // Get the set of pub keys assigned to account
    std::string strAccount = AccountFromValue(params[0], data);
    if(! data.fSuccess()) return data.JSONRPCError();
    std::set<CBitcoinAddress> setAddress;
    GetAccountAddresses(strAccount, setAddress);

    // Tally
    int64_t nAmount = 0;
    for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); ++it) {
        const CWalletTx &wtx = (*it).second;
        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !wtx.IsFinal())
            continue;

        for(const CTxOut &txout: wtx.get_vout()) {
            CBitcoinAddress address;
            if (Script_util::ExtractAddress(*entry::pwalletMain, txout.get_scriptPubKey(), address) && Script_util::IsMine(*entry::pwalletMain, address) && setAddress.count(address)) {
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.get_nValue();
            }
        }
    }

    return data.JSONRPCSuccess((double)nAmount / (double)util::COIN);
}


int64_t CRPCTable::GetAccountBalance(CWalletDB &walletdb, const std::string &strAccount, int nMinDepth, const isminefilter &filter) {
    int64_t nBalance = 0;

    // Tally wallet transactions
    for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); ++it) {
        const CWalletTx &wtx = (*it).second;
        if (! wtx.IsFinal())
            continue;

        int64_t nGenerated, nReceived, nSent, nFee;
        wtx.GetAccountAmounts(strAccount, nGenerated, nReceived, nSent, nFee, filter);
        if (nReceived != 0 && wtx.GetDepthInMainChain() >= nMinDepth)
            nBalance += nReceived;

        nBalance += nGenerated - nSent - nFee;
    }

    // Tally internal accounting entries
    nBalance += walletdb.GetAccountCreditDebit(strAccount);
    return nBalance;
}

int64_t CRPCTable::GetAccountBalance(const std::string &strAccount, int nMinDepth, const isminefilter &filter) {
    CWalletDB walletdb(entry::pwalletMain->strWalletFile);
    return GetAccountBalance(walletdb, strAccount, nMinDepth, filter);
}

json_spirit::Value CRPCTable::getbalance(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 2) {
        return data.JSONRPCSuccess(
            "getbalance [account] [minconf=1] [watchonly=0]\n"
            "If [account] is not specified, returns the server's total available balance.\n"
            "If [account] is specified, returns the balance in the account.\n"
            "if [includeWatchonly] is specified, include balance in watchonly addresses (see 'importaddress').");
    }

    if (params.size() == 0)
        return data.JSONRPCSuccess(ValueFromAmount(entry::pwalletMain->GetBalance()));

    int nMinDepth = 1;
    json_spirit::json_flags status;
    if (params.size() > 1) {
        nMinDepth = params[1].get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    isminefilter filter = MINE_SPENDABLE;
    if(params.size() > 2) {
        if(params[2].get_bool(status))
            filter = filter | MINE_WATCH_ONLY;
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    std::string str = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if (str == "*") {
        // Calculate total balance a different way from GetBalance()
        // (GetBalance() sums up all unspent TxOuts)
        // getbalance and getbalance '*' 0 should return the same number.
        int64_t nBalance = 0;
        for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); ++it) {
            const CWalletTx& wtx = (*it).second;
            if (! wtx.IsTrusted())
                continue;

            int64_t allGeneratedImmature, allGeneratedMature, allFee;
            allGeneratedImmature = allGeneratedMature = allFee = 0;

            std::string strSentAccount;
            std::list<std::pair<CBitcoinAddress, int64_t> > listReceived;
            std::list<std::pair<CBitcoinAddress, int64_t> > listSent;
            wtx.GetAmounts(allGeneratedImmature, allGeneratedMature, listReceived, listSent, allFee, strSentAccount, filter);
            if (wtx.GetDepthInMainChain() >= nMinDepth) {
                for(const std::pair<CBitcoinAddress, int64_t> &r: listReceived)
                    nBalance += r.second;
            }
            for(const std::pair<CBitcoinAddress, int64_t> &r: listSent)
                nBalance -= r.second;

            nBalance -= allFee;
            nBalance += allGeneratedMature;
        }
        return data.JSONRPCSuccess(ValueFromAmount(nBalance));
    }

    std::string strAccount = AccountFromValue(params[0], data);
    if(! data.fSuccess()) return data.JSONRPCError();
    int64_t nBalance = GetAccountBalance(strAccount, nMinDepth, filter);
    return data.JSONRPCSuccess(ValueFromAmount(nBalance));
}

json_spirit::Value CRPCTable::movecmd(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 3 || params.size() > 5) {
        return data.JSONRPCSuccess(
            "move <fromaccount> <toaccount> <amount> [minconf=1] [comment]\n"
            "Move from one account in your wallet to another.");
    }

    data.e = "fromaccount ";
    std::string strFrom = AccountFromValue(params[0], data);
    if(! data.fSuccess()) return data.JSONRPCError();
    data.e = "toaccount ";
    std::string strTo = AccountFromValue(params[1], data);
    if(! data.fSuccess()) return data.JSONRPCError();
    data.e = "amount ";
    int64_t nAmount = AmountFromValue(params[2], data);
    if(! data.fSuccess()) return data.JSONRPCError();
    if (nAmount < block_info::nMinimumInputValue)
        return data.JSONRPCError(RPC_WALLET_AMOUNT_TOO_SMALL, "Send amount too small");

    json_spirit::json_flags status;
    if (params.size() > 3) { // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)params[3].get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    std::string strComment;
    if (params.size() > 4) {
        strComment = params[4].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    CWalletDB walletdb(entry::pwalletMain->strWalletFile);
    if (! walletdb.TxnBegin())
        return data.JSONRPCError(RPC_DATABASE_ERROR, "database error");

    int64_t nNow = bitsystem::GetAdjustedTime();

    // Debit
    CAccountingEntry debit;
    debit.nOrderPos = entry::pwalletMain->IncOrderPosNext(&walletdb);
    debit.strAccount = strFrom;
    debit.nCreditDebit = -nAmount;
    debit.nTime = nNow;
    debit.strOtherAccount = strTo;
    debit.strComment = strComment;
    walletdb.WriteAccountingEntry(debit);

    // Credit
    CAccountingEntry credit;
    credit.nOrderPos = entry::pwalletMain->IncOrderPosNext(&walletdb);
    credit.strAccount = strTo;
    credit.nCreditDebit = nAmount;
    credit.nTime = nNow;
    credit.strOtherAccount = strFrom;
    credit.strComment = strComment;
    walletdb.WriteAccountingEntry(credit);

    if (! walletdb.TxnCommit())
        return data.JSONRPCError(RPC_DATABASE_ERROR, "database error");

    return data.JSONRPCSuccess(true);
}

json_spirit::Value CRPCTable::sendfrom(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 3 || params.size() > 6) {
        return data.JSONRPCSuccess(
            "sendfrom <from account> <to coinaddress> <amount> [minconf=1] [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest " + strenc::FormatMoney(block_info::nMinimumInputValue)
            + HelpRequiringPassphrase());
    }

    std::string strAccount = AccountFromValue(params[0], data);
    if(! data.fSuccess()) return data.JSONRPCError();

    // Parse address
    CScript scriptPubKey;
    json_spirit::json_flags status;
    std::string strAddress = params[1].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);

    CBitcoinAddress address(strAddress);
    if (address.IsValid())
        scriptPubKey.SetAddress(address);
    else
        return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid " strCoinName " address");

    int64_t nAmount = AmountFromValue(params[2], data);
    if(! data.fSuccess()) return data.JSONRPCError();
    if (nAmount < block_info::nMinimumInputValue)
        return data.JSONRPCError(RPC_WALLET_AMOUNT_TOO_SMALL, "Send amount too small");

    int nMinDepth = 1;
    if (params.size() > 3) {
        nMinDepth = params[3].get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    std::string jparam4 = params[4].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    std::string jparam5 = params[5].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if (params.size() > 4 && params[4].type() != json_spirit::null_type && !jparam4.empty())
        wtx.mapValue["comment"] = jparam4;
    if (params.size() > 5 && params[5].type() != json_spirit::null_type && !jparam5.empty())
        wtx.mapValue["to"]      = jparam5;

    EnsureWalletIsUnlocked(data);
    if(! data.fSuccess()) return data.JSONRPCError();

    // Check funds
    int64_t nBalance = GetAccountBalance(strAccount, nMinDepth, MINE_SPENDABLE);
    if (nAmount > nBalance)
        return data.JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    std::string strError = entry::pwalletMain->SendMoney(scriptPubKey, nAmount, wtx);
    if (! strError.empty())
        return data.JSONRPCError(RPC_WALLET_ERROR, strError);

    return data.JSONRPCSuccess(wtx.GetHash().GetHex());
}

json_spirit::Value CRPCTable::sendmany(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 2 || params.size() > 4) {
        return data.JSONRPCSuccess(
            "sendmany <fromaccount> '{address:amount,...}' [minconf=1] [comment]\n"
            "amounts are double-precision floating point numbers"
            + HelpRequiringPassphrase());
    }

    std::string strAccount = AccountFromValue(params[0], data);
    if(! data.fSuccess()) return data.JSONRPCError();
    json_spirit::json_flags status;
    json_spirit::Object sendTo = params[1].get_obj(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    int nMinDepth = 1;
    if (params.size() > 2) {
        nMinDepth = params[2].get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    std::string jparam3 = params[3].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if (params.size() > 3 && params[3].type() != json_spirit::null_type && !jparam3.empty())
        wtx.mapValue["comment"] = jparam3;

    std::set<CBitcoinAddress> setAddress;
    std::vector<std::pair<CScript, int64_t> > vecSend;
    int64_t totalAmount = 0;
    for(const json_spirit::Pair &s: sendTo) {
        CBitcoinAddress address(s.name_);
        if (! address.IsValid())
            return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid " strCoinName " address: ") + s.name_);
        if (! address.IsPair()) {
            if (setAddress.count(address))
                return data.JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + s.name_);
            setAddress.insert(address);
        }

        CScript scriptPubKey;
        scriptPubKey.SetAddress(address);
        int64_t nAmount = AmountFromValue(s.value_, data);
        if(! data.fSuccess()) return data.JSONRPCError();
        if (nAmount < block_info::nMinimumInputValue)
            return bitjson::JSONRPCError(-101, "Send amount too small");

        totalAmount += nAmount;
        vecSend.push_back(std::make_pair(scriptPubKey, nAmount));
    }

    json_spirit::Value jv = EnsureWalletIsUnlocked(data);
    if(! data.fSuccess()) return jv;

    // Check funds
    int64_t nBalance = GetAccountBalance(strAccount, nMinDepth, MINE_SPENDABLE);
    if (totalAmount > nBalance)
        return data.JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    CReserveKey keyChange(entry::pwalletMain);
    int64_t nFeeRequired = 0;
    bool fCreated = entry::pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired);
    if (! fCreated) {
        int64_t nTotal = entry::pwalletMain->GetBalance(), nWatchOnly = entry::pwalletMain->GetWatchOnlyBalance();
        if (totalAmount + nFeeRequired > nTotal - nWatchOnly)
            return data.JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");
        return data.JSONRPCError(RPC_WALLET_ERROR, "Transaction creation failed");
    }
    if (! entry::pwalletMain->CommitTransaction(wtx, keyChange))
        return data.JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");

    return data.JSONRPCSuccess(wtx.GetHash().GetHex());
}

json_spirit::Value CRPCTable::addmultisigaddress(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 2 || params.size() > 3) {
        return data.JSONRPCSuccess(
            "addmultisigaddress <nrequired> <'[\"key\",\"key\"]'> [account]\n"
            "Add a nrequired-to-sign multisignature address to the wallet\"\n"
            "each key is a " strCoinName " address or hex-encoded public key\n"
            "If [account] is specified, assign address to [account].");
    }

    json_spirit::json_flags status;
    int nRequired = params[0].get_int(status);
    const json_spirit::Array &keys = params[1].get_array(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    std::string strAccount;
    if (params.size() > 2)
        strAccount = AccountFromValue(params[2], data);
    if(! data.fSuccess()) return data.JSONRPCError();

    // Gather public keys
    if (nRequired < 1)
        return data.runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        return data.runtime_error(tfm::format("not enough keys supplied (got %" PRIszu " keys, but need at least %d to redeem)", keys.size(), nRequired));
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
                return data.runtime_error(tfm::format("%s does not refer to a key", ks.c_str()));

            CPubKey vchPubKey;
            if (! entry::pwalletMain->GetPubKey(keyID, vchPubKey))
                return data.runtime_error(tfm::format("no full public key for address %s", ks.c_str()));
            if (! vchPubKey.IsValid())
                return data.runtime_error(std::string(" Invalid public key: ") + ks);
            pubkeys[i] = vchPubKey;
        } else if (strenc::IsHex(ks)) {
            // Case 2: hex public key
            CPubKey vchPubKey(strenc::ParseHex(ks));
            if (! vchPubKey.IsValid())
                return data.runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        } else
            return data.runtime_error(" Invalid public key: "+ks);
    }

    // BIP16: Construct using pay-to-script-hash:
    CScript inner;
    inner.SetMultisig(nRequired, pubkeys);
    if (inner.size() > Script_const::MAX_SCRIPT_ELEMENT_SIZE)
        return data.runtime_error(tfm::format("redeemScript exceeds size limit: %" PRIszu " > %d", inner.size(), Script_const::MAX_SCRIPT_ELEMENT_SIZE));

    entry::pwalletMain->AddCScript(inner);
    CBitcoinAddress address(inner.GetID());
    entry::pwalletMain->SetAddressBookName(address, strAccount);
    return data.JSONRPCSuccess(address.ToString());
}

json_spirit::Value CRPCTable::addredeemscript(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() < 1 || params.size() > 2) {
        return data.JSONRPCSuccess("addredeemscript <redeemScript> [account]\n"
            "Add a P2SH address with a specified redeemScript to the wallet.\n"
            "If [account] is specified, assign address to [account].");
    }

    std::string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1], data);
    if(! data.fSuccess()) return data.JSONRPCError();

    // BIP16: Construct using pay-to-script-hash:
    rpctable_vector innerData = hexrpc::ParseHexV(params[0], "redeemScript", data);
    if(! data.fSuccess()) return data.JSONRPCError();
    CScript inner(innerData.begin(), innerData.end());
    entry::pwalletMain->AddCScript(inner);
    CBitcoinAddress address(inner.GetID());

    entry::pwalletMain->SetAddressBookName(address, strAccount);
    return data.JSONRPCSuccess(address.ToString());
}

json_spirit::Value CRPCTable::ListReceived(const json_spirit::Array &params, bool fByAccounts, CBitrpcData &data) noexcept {
    // Minimum confirmations
    int nMinDepth = 1;
    json_spirit::json_flags status;
    if (params.size() > 0)
        nMinDepth = params[0].get_int(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (params.size() > 1)
        fIncludeEmpty = params[1].get_bool(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);

    // Tally
    std::map<CBitcoinAddress, tallyitem> mapTally;
    for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); ++it) {
        const CWalletTx &wtx = (*it).second;
        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !wtx.IsFinal())
            continue;
        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth)
            continue;
        for(const CTxOut &txout: wtx.get_vout()) {
            CTxDestination address;
            if (!Script_util::ExtractDestination(txout.get_scriptPubKey(), address) || !Script_util::IsMine(*entry::pwalletMain, address))
                continue;
            tallyitem &item = mapTally[address];
            item.nAmount += txout.get_nValue();
            item.nConf = std::min(item.nConf, nDepth);
        }
    }

    // Reply
    json_spirit::Array ret;
    std::map<std::string, tallyitem> mapAccountTally;
    for(const std::pair<CBitcoinAddress, std::string> &item: entry::pwalletMain->mapAddressBook) {
        const CBitcoinAddress &address = item.first;
        const std::string &strAccount = item.second;
        std::map<CBitcoinAddress, tallyitem>::iterator it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty)
            continue;
        int64_t nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        if (it != mapTally.end()) {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
        }
        if (fByAccounts) {
            tallyitem &item = mapAccountTally[strAccount];
            item.nAmount += nAmount;
            item.nConf = std::min(item.nConf, nConf);
        } else {
            json_spirit::Object obj;
            obj.push_back(json_spirit::Pair("address",       address.ToString()));
            obj.push_back(json_spirit::Pair("account",       strAccount));
            obj.push_back(json_spirit::Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(json_spirit::Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            ret.push_back(obj);
        }
    }
    if (fByAccounts) {
        for (std::map<std::string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it) {
            int64_t nAmount = (*it).second.nAmount;
            int nConf = (*it).second.nConf;

            json_spirit::Object obj;
            obj.push_back(json_spirit::Pair("account",       (*it).first));
            obj.push_back(json_spirit::Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(json_spirit::Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            ret.push_back(obj);
        }
    }

    return data.JSONRPCSuccess(ret);
}

json_spirit::Value CRPCTable::listreceivedbyaddress(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 2) {
        return data.JSONRPCSuccess(
            "listreceivedbyaddress [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include addresses that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"address\" : receiving address\n"
            "  \"account\" : the account of the receiving address\n"
            "  \"amount\" : total amount received by the address\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");
    }

    json_spirit::Value ret = ListReceived(params, false, data);
    return data.fSuccess()? data.JSONRPCSuccess(ret): data.JSONRPCError();
}

json_spirit::Value CRPCTable::listreceivedbyaccount(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 2) {
        return data.JSONRPCSuccess(
            "listreceivedbyaccount [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include accounts that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"account\" : the account of the receiving addresses\n"
            "  \"amount\" : total amount received by addresses with this account\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");
    }

    json_spirit::Value ret = ListReceived(params, true, data);
    return data.fSuccess()? data.JSONRPCSuccess(ret): data.JSONRPCError();
}

void CRPCTable::MaybePushAddress(json_spirit::Object &entry, const CBitcoinAddress &dest) noexcept {
    entry.push_back(json_spirit::Pair("address", dest.ToString()));
}

void CRPCTable::ListTransactions(const CWalletTx &wtx, const std::string &strAccount, int nMinDepth, bool fLong, json_spirit::Array &ret, const isminefilter &filter) {
    int64_t nGeneratedImmature, nGeneratedMature, nFee;
    std::string strSentAccount;
    std::list<std::pair<CBitcoinAddress, int64_t> > listReceived;
    std::list<std::pair<CBitcoinAddress, int64_t> > listSent;

    wtx.GetAmounts(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount, filter);

    bool fAllAccounts = (strAccount == std::string("*"));
    bool involvesWatchonly = wtx.IsFromMe(MINE_WATCH_ONLY);

    // Generated blocks assigned to account ""
    if ((nGeneratedMature+nGeneratedImmature) != 0 && (fAllAccounts || strAccount.empty())) {
        json_spirit::Object entry;
        entry.push_back(json_spirit::Pair("account", std::string("")));
        if (nGeneratedImmature) {
            entry.push_back(json_spirit::Pair("category", wtx.GetDepthInMainChain() ? "immature" : "orphan"));
            entry.push_back(json_spirit::Pair("amount", ValueFromAmount(nGeneratedImmature)));
        } else {
            entry.push_back(json_spirit::Pair("category", "generate"));
            entry.push_back(json_spirit::Pair("amount", ValueFromAmount(nGeneratedMature)));
        }
        if (fLong)
            WalletTxToJSON(wtx, entry);

        ret.push_back(entry);
    }

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount)) {
        for(const std::pair<CBitcoinAddress, int64_t> &s: listSent) {
            json_spirit::Object entry;
            entry.push_back(json_spirit::Pair("account", strSentAccount));
            if(involvesWatchonly || (Script_util::IsMine(*entry::pwalletMain, s.first) & MINE_WATCH_ONLY))
                entry.push_back(json_spirit::Pair("involvesWatchonly", true));

            MaybePushAddress(entry, s.first);
            if (wtx.GetDepthInMainChain() < 0)
                entry.push_back(json_spirit::Pair("category", "conflicted"));
            else
                entry.push_back(json_spirit::Pair("category", "send"));

            entry.push_back(json_spirit::Pair("amount", ValueFromAmount(-s.second)));
            entry.push_back(json_spirit::Pair("fee", ValueFromAmount(-nFee)));
            if (fLong)
                WalletTxToJSON(wtx, entry);

            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth) {
        for(const std::pair<CBitcoinAddress, int64_t> &r: listReceived) {
            std::string account;
            if (entry::pwalletMain->mapAddressBook.count(r.first))
                account = entry::pwalletMain->mapAddressBook[r.first];
            if (fAllAccounts || (account == strAccount)) {
                json_spirit::Object entry;
                entry.push_back(json_spirit::Pair("account", account));
                // if(involvesWatchonly || (::IsMine(*entry::pwalletMain, r.first) & MINE_WATCH_ONLY)) {
                if(involvesWatchonly || (Script_util::IsMine(*entry::pwalletMain, r.first) & MINE_WATCH_ONLY))
                    entry.push_back(json_spirit::Pair("involvesWatchonly", true));

                MaybePushAddress(entry, r.first);
                if (wtx.IsCoinBase()) {
                    if (wtx.GetDepthInMainChain() < 1)
                        entry.push_back(json_spirit::Pair("category", "orphan"));
                    else if (wtx.GetBlocksToMaturity() > 0)
                        entry.push_back(json_spirit::Pair("category", "immature"));
                    else
                        entry.push_back(json_spirit::Pair("category", "generate"));
                } else
                    entry.push_back(json_spirit::Pair("category", "receive"));

                entry.push_back(json_spirit::Pair("amount", ValueFromAmount(r.second)));
                if (fLong)
                    WalletTxToJSON(wtx, entry);

                ret.push_back(entry);
            }
        }
    }
}

void CRPCTable::AcentryToJSON(const CAccountingEntry &acentry, const std::string &strAccount, json_spirit::Array &ret) {
    bool fAllAccounts = (strAccount == std::string("*"));
    if (fAllAccounts || acentry.strAccount == strAccount) {
        json_spirit::Object entry;
        entry.push_back(json_spirit::Pair("account", acentry.strAccount));
        entry.push_back(json_spirit::Pair("category", "move"));
        entry.push_back(json_spirit::Pair("time", (int64_t)acentry.nTime));
        entry.push_back(json_spirit::Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
        entry.push_back(json_spirit::Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(json_spirit::Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}

json_spirit::Value CRPCTable::listtransactions(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 3) {
        return data.JSONRPCSuccess(
            "listtransactions [account] [count=10] [from=0]\n"
            "Returns up to [count] most recent transactions skipping the first [from] transactions for account [account].");
    }

    std::string strAccount = "*";
    json_spirit::json_flags status;
    if (params.size() > 0) {
        strAccount = params[0].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    int nCount = 10;
    if (params.size() > 1) {
        nCount = params[1].get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    int nFrom = 0;
    if (params.size() > 2) {
        nFrom = params[2].get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    isminefilter filter = MINE_SPENDABLE;
    if(params.size() > 3) {
        if(params[3].get_bool(status))
            filter = filter | MINE_WATCH_ONLY;
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    if (nCount < 0)
        return data.JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        return data.JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    json_spirit::Array ret;
    std::list<CAccountingEntry> acentries;
    CWallet::TxItems txOrdered = entry::pwalletMain->OrderedTxItems(acentries, strAccount);

    // iterate backwards until we have nCount items to return:
    for (CWallet::TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it) {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListTransactions(*pwtx, strAccount, 0, true, ret, filter);

        CAccountingEntry *const pacentry = (*it).second.second;
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret);
        if ((int)ret.size() >= (nCount+nFrom))
            break;
    }
    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    json_spirit::Array::iterator first = ret.begin();
    std::advance(first, nFrom);
    json_spirit::Array::iterator last = ret.begin();
    std::advance(last, nFrom+nCount);
    if (last != ret.end())
        ret.erase(last, ret.end());
    if (first != ret.begin())
        ret.erase(ret.begin(), first);

    std::reverse(ret.begin(), ret.end()); // Return oldest to newest
    return data.JSONRPCSuccess(ret);
}

json_spirit::Value CRPCTable::listaccounts(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 1) {
        return data.JSONRPCSuccess(
            "listaccounts [minconf=1]\n"
            "Returns Object that has account names as keys, account balances as values.");
    }

    int nMinDepth = 1;
    json_spirit::json_flags status;
    if (params.size() > 0) {
        nMinDepth = params[0].get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    isminefilter includeWatchonly = MINE_SPENDABLE;
    if(params.size() > 1) {
        if(params[1].get_bool(status))
            includeWatchonly = includeWatchonly | MINE_WATCH_ONLY;
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    std::map<std::string, int64_t> mapAccountBalances;
    for(const std::pair<CBitcoinAddress, std::string> &entry: entry::pwalletMain->mapAddressBook) {
        if (Script_util::IsMine(*entry::pwalletMain, entry.first))    // This address belongs to me
            mapAccountBalances[entry.second] = 0;
    }
    for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); ++it) {
        const CWalletTx& wtx = (*it).second;
        int64_t nGeneratedImmature, nGeneratedMature, nFee;
        std::string strSentAccount;
        std::list<std::pair<CBitcoinAddress, int64_t> > listReceived;
        std::list<std::pair<CBitcoinAddress, int64_t> > listSent;
        wtx.GetAmounts(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount, includeWatchonly);
        mapAccountBalances[strSentAccount] -= nFee;
        for(const std::pair<CBitcoinAddress, int64_t> &s: listSent)
            mapAccountBalances[strSentAccount] -= s.second;

        if (wtx.GetDepthInMainChain() >= nMinDepth) {
            mapAccountBalances[""] += nGeneratedMature;
            for(const std::pair<CBitcoinAddress, int64_t> &r: listReceived) {
                if (entry::pwalletMain->mapAddressBook.count(r.first))
                    mapAccountBalances[entry::pwalletMain->mapAddressBook[r.first]] += r.second;
                else
                    mapAccountBalances[""] += r.second;
            }
        }
    }

    std::list<CAccountingEntry> acentries;
    CWalletDB(entry::pwalletMain->strWalletFile).ListAccountCreditDebit("*", acentries);
    for(const CAccountingEntry &entry: acentries)
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

    json_spirit::Object ret;
    for(const std::pair<std::string, int64_t> &accountBalance: mapAccountBalances)
        ret.push_back(json_spirit::Pair(accountBalance.first, ValueFromAmount(accountBalance.second)));

    return data.JSONRPCSuccess(ret);
}

json_spirit::Value CRPCTable::listsinceblock(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp()) {
        return data.JSONRPCSuccess(
            "listsinceblock [blockhash] [target-confirmations]\n"
            "Get all transactions in blocks since block [blockhash], or all transactions if omitted");
    }

    CBlockIndex *pindex = nullptr;
    int target_confirms = 1;
    isminefilter filter = MINE_SPENDABLE;
    json_spirit::json_flags status;
    if (params.size() > 0) {
        uint256 blockId = 0;
        std::string str = params[0].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        blockId.SetHex(str);
        pindex = CBlockLocator(blockId).GetBlockIndex();
    }
    if (params.size() > 1) {
        target_confirms = params[1].get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        if (target_confirms < 1)
            return data.JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }
    if(params.size() > 2) {
        if(params[2].get_bool(status))
            filter = filter | MINE_WATCH_ONLY;
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    int depth = pindex ? (1 + block_info::nBestHeight - pindex->get_nHeight()) : -1;
    json_spirit::Array transactions;
    for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); ++it) {
        CWalletTx tx = (*it).second;
        if (depth == -1 || tx.GetDepthInMainChain() < depth)
            ListTransactions(tx, "*", 0, true, transactions, filter);
    }

    uint256 lastblock;
    if (target_confirms == 1)
        lastblock = block_info::hashBestChain;
    else {
        int target_height = block_info::pindexBest->get_nHeight() + 1 - target_confirms;
        CBlockIndex *block;
        for (block = block_info::pindexBest; block && block->get_nHeight() > target_height; block = block->set_pprev()) {}
        lastblock = block ? block->GetBlockHash() : 0;
    }

    json_spirit::Object ret;
    ret.push_back(json_spirit::Pair("transactions", transactions));
    ret.push_back(json_spirit::Pair("lastblock", lastblock.GetHex()));
    return data.JSONRPCSuccess(ret);
}

json_spirit::Value CRPCTable::gettransaction(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "gettransaction <txid>\n"
            "Get detailed information about <txid>");
    }

    uint256 hash;
    json_spirit::json_flags status;
    std::string str = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    hash.SetHex(str);
    isminefilter filter = MINE_SPENDABLE;
    if(params.size() > 1) {
        if(params[1].get_bool(status))
            filter = filter | MINE_WATCH_ONLY;
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    json_spirit::Object entry;
    if (entry::pwalletMain->mapWallet.count(hash)) {
        const CWalletTx &wtx = entry::pwalletMain->mapWallet[hash];
        TxToJSON(wtx, 0, entry);
        int64_t nCredit = wtx.GetCredit(filter);
        int64_t nDebit = wtx.GetDebit(filter);
        int64_t nNet = nCredit - nDebit;
        int64_t nFee = (wtx.IsFromMe(filter) ? wtx.GetValueOut() - nDebit : 0);
        entry.push_back(json_spirit::Pair("amount", ValueFromAmount(nNet - nFee)));
        if (wtx.IsFromMe(filter))
            entry.push_back(json_spirit::Pair("fee", ValueFromAmount(nFee)));

        WalletTxToJSON(wtx, entry);
        json_spirit::Array details;
        ListTransactions(entry::pwalletMain->mapWallet[hash], "*", 0, false, details, filter);
        entry.push_back(json_spirit::Pair("details", details));
    } else {
        CTransaction tx;
        uint256 hashBlock = 0;
        if (block_transaction::manage::GetTransaction(hash, tx, hashBlock)) {
            TxToJSON(tx, 0, entry);
            if (hashBlock == 0)
                entry.push_back(json_spirit::Pair("confirmations", 0));
            else {
                entry.push_back(json_spirit::Pair("blockhash", hashBlock.GetHex()));
                std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hashBlock);
                if (mi != block_info::mapBlockIndex.end() && (*mi).second) {
                    CBlockIndex* pindex = (*mi).second;
                    if (pindex->IsInMainChain())
                        entry.push_back(json_spirit::Pair("confirmations", 1 + block_info::nBestHeight - pindex->get_nHeight()));
                    else
                        entry.push_back(json_spirit::Pair("confirmations", 0));
                }
            }
        } else
            return data.JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");
    }

    return data.JSONRPCSuccess(entry);
}

json_spirit::Value CRPCTable::backupwallet(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "backupwallet <destination>\n"
            "Safely copies wallet.dat to destination, which can be a directory or a path with filename.");
    }

    json_spirit::json_flags status;
    std::string strDest = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if (! wallet_dispatch::BackupWallet(*entry::pwalletMain, strDest))
        return data.JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");

    return data.JSONRPCSuccess(json_spirit::Value::null);
}

json_spirit::Value CRPCTable::keypoolrefill(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 1) {
        return data.JSONRPCSuccess(
            "keypoolrefill [new-size]\n"
            "Fills the keypool.\n"
            "IMPORTANT: Any previous backups you have made of your wallet file "
            "should be replaced with the newly generated one."
            + HelpRequiringPassphrase());
    }

    unsigned int nSize = std::max<unsigned int>(map_arg::GetArgUInt("-keypool", 100), 0);
    json_spirit::json_flags status;
    if (params.size() > 0) {
        if (params[0].get_int(status) < 0)
            return data.JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size");
        nSize = (unsigned int) params[0].get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    json_spirit::Value jv = EnsureWalletIsUnlocked(data);
    if(! data.fSuccess()) return jv;
    if(! TopUpKeyPool(data, nSize))
        return data.runtime_error();
    if (entry::pwalletMain->GetKeyPoolSize() < nSize)
        return data.JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");

    return data.JSONRPCSuccess(json_spirit::Value::null);
}

json_spirit::Value CRPCTable::keypoolreset(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 1) {
        return data.JSONRPCSuccess(
            "keypoolreset [new-size]\n"
            "Resets the keypool.\n"
            "IMPORTANT: Any previous backups you have made of your wallet file "
            "should be replaced with the newly generated one."
            + HelpRequiringPassphrase());
    }

    unsigned int nSize = std::max<unsigned int>(map_arg::GetArgUInt("-keypool", 100), 0);
    json_spirit::json_flags status;
    if (params.size() > 0) {
        if (params[0].get_int(status) < 0)
            return data.JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size");
        nSize = (unsigned int) params[0].get_int(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    json_spirit::Value jv = EnsureWalletIsUnlocked(data);
    if(! data.fSuccess()) return jv;
    entry::pwalletMain->NewKeyPool(nSize);
    if (entry::pwalletMain->GetKeyPoolSize() < nSize)
        return data.JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");

    return data.JSONRPCSuccess(json_spirit::Value::null);
}

void CRPCTable::ThreadTopUpKeyPool(void *parg) {
    (void)parg;
    // Make this thread recognisable as the key-topping-up thread
    bitthread::RenameThread(strCoinName "-key-top");
    entry::pwalletMain->TopUpKeyPool();
}

void CRPCTable::ThreadCleanWalletPassphrase(void *parg) {
    // Make this thread recognisable as the wallet relocking thread
    // parg: int64_t *, dynamic object
    bitthread::RenameThread(strCoinName "-lock-wa");
    int64_t nMyWakeTime = util::GetTimeMillis() + *((int64_t *)parg) * 1000;

    ENTER_CRITICAL_SECTION(cs_nWalletUnlockTime);
    if (nWalletUnlockTime == 0) {
        nWalletUnlockTime = nMyWakeTime;
        for (;;) {
            if (nWalletUnlockTime == 0)
                break;

            int64_t nToSleep = nWalletUnlockTime - util::GetTimeMillis();
            if (nToSleep <= 0)
                break;

            LEAVE_CRITICAL_SECTION(cs_nWalletUnlockTime);
            util::Sleep(nToSleep);
            ENTER_CRITICAL_SECTION(cs_nWalletUnlockTime);
        }
        if (nWalletUnlockTime) {
            nWalletUnlockTime = 0;
            entry::pwalletMain->Lock();
        }
    } else {
        if (nWalletUnlockTime < nMyWakeTime)
            nWalletUnlockTime = nMyWakeTime;
    }

    LEAVE_CRITICAL_SECTION(cs_nWalletUnlockTime);
    delete (int64_t*)parg;
}

json_spirit::Value CRPCTable::walletpassphrase(const json_spirit::Array &params, CBitrpcData &data) {
    if (entry::pwalletMain->IsCrypted() && (data.fHelp() || params.size() < 2 || params.size() > 3)) {
        return data.JSONRPCSuccess(
            "walletpassphrase <passphrase> <timeout> [mintonly]\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.\n"
            "mintonly is optional true/false allowing only block minting.");
    }
    if (data.fHelp())
        return data.JSONRPCSuccess(true);
    if (! entry::pwalletMain->IsCrypted())
        return data.JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");
    if (! entry::pwalletMain->IsLocked())
        return data.JSONRPCError(RPC_WALLET_ALREADY_UNLOCKED, "Error: Wallet is already unlocked, use walletlock first if need to change unlock settings.");

    SecureString strWalletPass;
    strWalletPass.reserve(100);
    json_spirit::json_flags status;
    strWalletPass(const_cast<std::string &>(params[0].get_str(status))); // Note: should be operate () (SecureAllocator)
    {   // SorachanCoin: SecureString operator () check OK.
        std::string __str = params[0].get_str(status);
        assert(status.fSuccess());
        for(const char &c: __str) {
            assert(c=='\0'); // OpenSSL_cleanse operate OK.
        }
        //debugcs::instance() << "[SecureString operator ()] str: " << __str.c_str() << " size: " << __str.size() << debugcs::endl();
    }
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if (strWalletPass.length() > 0) {
        if (! entry::pwalletMain->Unlock(strWalletPass))
            return data.JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    } else
        return data.runtime_error(
            "walletpassphrase <passphrase> <timeout> [mintonly]\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.\n"
            "mintonly is optional true/false allowing only block minting.");

    if(! bitthread::NewThread(ThreadTopUpKeyPool, nullptr))
        return data.runtime_error("walletpassphrase ThreadTopUpKeyPool create failure.");
    int64_t *pnSleepTime = new(std::nothrow) int64_t(params[1].get_int64(status));
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if(pnSleepTime == nullptr)
        return data.runtime_error("walletpassphrase memory allocate failure.");
    if(! bitthread::NewThread(ThreadCleanWalletPassphrase, pnSleepTime)) // this thread, delete pnSleepTime.
        return data.runtime_error("walletpassphrase ThreadCleanWalletPassphrase create failure.");

    // ppcoin: if user OS account compromised prevent trivial sendmoney commands
    if (params.size() > 2) {
        CWallet::fWalletUnlockMintOnly = params[2].get_bool(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    } else
        CWallet::fWalletUnlockMintOnly = false;

    return data.JSONRPCSuccess(json_spirit::Value::null);
}

json_spirit::Value CRPCTable::walletpassphrasechange(const json_spirit::Array &params, CBitrpcData &data) {
    if (entry::pwalletMain->IsCrypted() && (data.fHelp() || params.size() != 2)) {
        return data.JSONRPCSuccess(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");
    }
    if (data.fHelp())
        return data.JSONRPCSuccess(true);
    if (! entry::pwalletMain->IsCrypted())
        return data.JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");

    // Note: should be operator () (SecureAllocator)
    json_spirit::json_flags status;
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass(const_cast<std::string &>(params[0].get_str(status)));
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass(const_cast<std::string &>(params[1].get_str(status)));
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1) {
        return data.runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");
    }
    if (! entry::pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
        return data.JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

    return data.JSONRPCSuccess(json_spirit::Value::null);
}

json_spirit::Value CRPCTable::walletlock(const json_spirit::Array &params, CBitrpcData &data) {
    if (entry::pwalletMain->IsCrypted() && (data.fHelp() || params.size() != 0)) {
        return data.JSONRPCSuccess(
            "walletlock\n"
            "Removes the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.");
    }
    if (data.fHelp())
        return data.JSONRPCSuccess(true);
    if (! entry::pwalletMain->IsCrypted())
        return data.JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");

    {
        LOCK(cs_nWalletUnlockTime);
        entry::pwalletMain->Lock();
        nWalletUnlockTime = 0;
    }

    return data.JSONRPCSuccess(json_spirit::Value::null);
}

json_spirit::Value CRPCTable::encryptwallet(const json_spirit::Array &params, CBitrpcData &data) {
    if (!entry::pwalletMain->IsCrypted() && (data.fHelp() || params.size() != 1)) {
        return data.JSONRPCSuccess(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");
    }
    if (data.fHelp())
        return data.JSONRPCSuccess(true);
    if (entry::pwalletMain->IsCrypted())
        return data.JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");

    SecureString strWalletPass;
    strWalletPass.reserve(100);
    json_spirit::json_flags status;
    strWalletPass(const_cast<std::string &>(params[0].get_str(status))); // Note: should be operator () (SecureAllocator)
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    if (strWalletPass.length() < 1) {
        return data.runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");
    }
    if (! entry::pwalletMain->EncryptWallet(strWalletPass))
        return data.JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");

    // TODO: BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys. So:
    boot::StartShutdown();
    return data.JSONRPCSuccess(strCoinName " wallet encrypted; server stopping, restart to run with encrypted wallet.  The keypool has been flushed, you need to make a new backup.");
}

namespace {
class JSON_DescribeAddressVisitor : public boost::static_visitor<json_spirit::Object>
{
public:
    explicit JSON_DescribeAddressVisitor() {}

    json_spirit::Object operator()(const CNoDestination &dest) const {
        (void)dest;
        return json_spirit::Object();
    }

    json_spirit::Object operator()(const CKeyID &keyID) const {
        (void)keyID;
        json_spirit::Object obj;
        obj.push_back(json_spirit::Pair("isscript", false));
        obj.push_back(json_spirit::Pair("iswitness", false));
        return obj;
    }

    json_spirit::Object operator()(const CScriptID &scriptID) const {
        (void)scriptID;
        json_spirit::Object obj;
        obj.push_back(json_spirit::Pair("isscript", true));
        obj.push_back(json_spirit::Pair("iswitness", false));
        return obj;
    }

    json_spirit::Object operator()(const WitnessV0KeyHash &id) const {
        json_spirit::Object obj;
        obj.push_back(json_spirit::Pair("isscript", false));
        obj.push_back(json_spirit::Pair("iswitness", true));
        obj.push_back(json_spirit::Pair("witness_version", 0));
        obj.push_back(json_spirit::Pair("witness_program", strenc::HexStr(id.begin(), id.end())));
        return obj;
    }

    json_spirit::Object operator()(const WitnessV0ScriptHash &id) const {
        json_spirit::Object obj;
        obj.push_back(json_spirit::Pair("isscript", true));
        obj.push_back(json_spirit::Pair("iswitness", true));
        obj.push_back(json_spirit::Pair("witness_version", 0));
        obj.push_back(json_spirit::Pair("witness_program", strenc::HexStr(id.begin(), id.end())));
        return obj;
    }

    json_spirit::Object operator()(const WitnessUnknown &id) const {
        json_spirit::Object obj;
        obj.push_back(json_spirit::Pair("iswitness", true));
        obj.push_back(json_spirit::Pair("witness_version", (int)id.version));
        obj.push_back(json_spirit::Pair("witness_program", strenc::HexStr(id.program, id.program + id.length)));
        return obj;
    }
};

void DescribeAddress(const CTxDestination &dest, json_spirit::Object &obj) {
    json_spirit::Object ret = boost::apply_visitor(JSON_DescribeAddressVisitor(), dest);
    for(const json_spirit::Pair &data: ret)
        obj.push_back(data);
}

class DescribeAddressVisitor : public boost::static_visitor<json_spirit::Object>
{
private:
    isminetype mine;
    CWallet *const pwallet;

    void ProcessSubScript(const CScript &subscript, json_spirit::Object &obj) const {
        // Always present: script type and redeemscript
        Script_util::statype solutions_data;
        TxnOutputType::txnouttype which_type;
        if(! Script_util::Solver(subscript, which_type, solutions_data)) return;
        obj.push_back(json_spirit::Pair("script", TxnOutputType::GetTxnOutputType(which_type)));
        obj.push_back(json_spirit::Pair("hex", strenc::HexStr(subscript.begin(), subscript.end())));

        CTxDestination embedded;
        if (Script_util::ExtractDestination(subscript, embedded)) {
            // Only when the script corresponds to an address.
            json_spirit::Object subobj;
            DescribeAddress(embedded, subobj);
            subobj << (const json_spirit::Object &)boost::apply_visitor(*this, embedded);

            //subobj.push_back(json_spirit::Pair("address", EncodeDestination(embedded)));

            subobj.push_back(json_spirit::Pair("scriptPubKey", strenc::HexStr(subscript.begin(), subscript.end())));
            // Always report the pubkey at the top level, so that `getnewaddress()['pubkey']` always works.
            if (subobj.exists("pubkey")) obj.push_back(json_spirit::Pair("pubkey", subobj["pubkey"]));
            obj.push_back(json_spirit::Pair("embedded", subobj));
        } else if (which_type == TxnOutputType::TX_MULTISIG) {
            // Also report some information on multisig scripts (which do not have a corresponding address).
            // TODO: abstract out the common functionality between this logic and ExtractDestinations.
            obj.push_back(json_spirit::Pair("sigsrequired", solutions_data[0][0]));
            json_spirit::Array pubkeys;
            for (size_t i = 1; i < solutions_data.size() - 1; ++i) {
                CPubKey key(solutions_data[i].begin(), solutions_data[i].end());
                pubkeys.push_back(strenc::HexStr(key.begin(), key.end()));
            }
            obj.push_back(json_spirit::Pair("pubkeys", pubkeys));
        }
    }

public:
    explicit DescribeAddressVisitor(isminetype mineIn) noexcept : mine(mineIn), pwallet(nullptr) {}
    explicit DescribeAddressVisitor(CWallet *walletIn) noexcept : pwallet(walletIn) {}

    json_spirit::Object operator()(const CNoDestination &dest) const {
        (void)dest;
        return json_spirit::Object();
    }

    json_spirit::Object operator()(const CKeyID &keyID) const {
        json_spirit::Object obj;
        CPubKey vchPubKey;
        entry::pwalletMain->GetPubKey(keyID, vchPubKey);
        obj.push_back(json_spirit::Pair("isscript", false));
        if (mine == MINE_SPENDABLE) {
            entry::pwalletMain->GetPubKey(keyID, vchPubKey);
            obj.push_back(json_spirit::Pair("pubkey", util::HexStr(vchPubKey.begin(), vchPubKey.end())));
            obj.push_back(json_spirit::Pair("iscompressed", vchPubKey.IsCompressed()));
        }
        return obj;
    }

    json_spirit::Object operator()(const CScriptID &scriptID) const {
        json_spirit::Object obj;
        obj.push_back(json_spirit::Pair("isscript", true));
        if (mine == MINE_SPENDABLE) {
            CScript subscript;
            entry::pwalletMain->GetCScript(scriptID, subscript);
            std::vector<CTxDestination> addresses;
            TxnOutputType::txnouttype whichType;
            int nRequired;
            Script_util::ExtractDestinations(subscript, whichType, addresses, nRequired);
            obj.push_back(json_spirit::Pair("script", TxnOutputType::GetTxnOutputType(whichType)));
            obj.push_back(json_spirit::Pair("hex", util::HexStr(subscript.begin(), subscript.end())));
            json_spirit::Array a;
            for(const CTxDestination &addr: addresses)
                a.push_back(CBitcoinAddress(addr).ToString());

            obj.push_back(json_spirit::Pair("addresses", a));
            if (whichType == TxnOutputType::TX_MULTISIG)
                obj.push_back(json_spirit::Pair("sigsrequired", nRequired));
        }
        return obj;
    }

    json_spirit::Object operator()(const WitnessV0KeyHash &id) const {
        json_spirit::Object obj;
        CPubKey pubkey;
        if (pwallet && pwallet->GetPubKey(CKeyID(id), pubkey)) {
            obj.push_back(json_spirit::Pair("pubkey", strenc::HexStr(pubkey)));
        }
        return obj;
    }

    json_spirit::Object operator()(const WitnessV0ScriptHash &id) const {
        json_spirit::Object obj;
        CScript subscript;
        latest_crypto::CRIPEMD160 hasher;
        uint160 hash;
        hasher.Write(id.begin(), 32).Finalize(hash.begin());
        if (pwallet && pwallet->GetCScript(CScriptID(hash), subscript)) {
            ProcessSubScript(subscript, obj);
        }
        return obj;
    }

    json_spirit::Object operator()(const WitnessUnknown &id) const {
        (void)id;
        return json_spirit::Object();
    }
};
} // namespace

json_spirit::Value CRPCTable::validateaddress(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 1) {
        return data.JSONRPCSuccess(
            "validateaddress <coinaddress>\n"
            "Return information about <coinaddress>.");
    }

    json_spirit::json_flags status;
    std::string str = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CBitcoinAddress address(str);
    bool isValid = address.IsValid();
    json_spirit::Object ret;
    ret.push_back(json_spirit::Pair("isvalid", isValid));
    if (isValid) {
        if (address.IsPair()) {
            CMalleablePubKey mpk;
            mpk.setvch(address.GetData());
            ret.push_back(json_spirit::Pair("ispair", true));

            CMalleableKeyView view;
            bool isMine = entry::pwalletMain->GetMalleableView(mpk, view);
            ret.push_back(json_spirit::Pair("ismine", isMine));
            ret.push_back(json_spirit::Pair("PubkeyPair", mpk.ToString()));

            if (isMine)
                ret.push_back(json_spirit::Pair("KeyView", view.ToString()));
        } else {
            std::string currentAddress = address.ToString();
            CTxDestination dest = address.Get();
            ret.push_back(json_spirit::Pair("address", currentAddress));
            isminetype mine = entry::pwalletMain ? Script_util::IsMine(*entry::pwalletMain, address) : MINE_NO;
            ret.push_back(json_spirit::Pair("ismine", mine != MINE_NO));
            if (mine != MINE_NO) {
                ret.push_back(json_spirit::Pair("watchonly", mine == MINE_WATCH_ONLY));
                json_spirit::Object detail = boost::apply_visitor(DescribeAddressVisitor(mine), dest);
                ret.insert(ret.end(), detail.begin(), detail.end());
            }
            if (entry::pwalletMain->mapAddressBook.count(address))
                ret.push_back(json_spirit::Pair("account", entry::pwalletMain->mapAddressBook[address]));
        }
    }
    return data.JSONRPCSuccess(ret);
}

// ppcoin: reserve balance from being staked for network protection
json_spirit::Value CRPCTable::reservebalance(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 2) {
        return data.JSONRPCSuccess(
            "reservebalance [<reserve> [amount]]\n"
            "<reserve> is true or false to turn balance reserve on or off.\n"
            "<amount> is a real and rounded to cent.\n"
            "Set reserve amount not participating in network protection.\n"
            "If no parameters provided current setting is printed.\n");
    }

    bitrpc::RPCTypeCheck(data, params, {{json_spirit::bool_type},{json_spirit::real_type}});
    if(! data.fSuccess()) return data.JSONRPCError();

    if (params.size() > 0) {
        json_spirit::json_flags status;
        bool fReserve = params[0].get_bool(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
        if (fReserve) {
            if (params.size() == 1)
                return data.runtime_error("must provide amount to reserve balance.\n");

            int64_t nAmount = AmountFromValue(params[1], data);
            if(! data.fSuccess()) return data.JSONRPCError();
            nAmount = (nAmount / util::CENT) * util::CENT;  // round to cent
            if (nAmount < 0)
                return data.runtime_error("amount cannot be negative.\n");

            map_arg::SetMapArgsString("-reservebalance", strenc::FormatMoney(nAmount));
        } else {
            if (params.size() > 1)
                return data.runtime_error("cannot specify amount to turn off reserve.\n");

            map_arg::SetMapArgsString("-reservebalance", "0");
        }
    }

    debugcs::instance() << "RPC, reservebalance: " << strenc::FormatMoney(1000).c_str() << debugcs::endl();

    json_spirit::Object result;
    if (map_arg::GetMapArgsCount("-reservebalance") &&
        !strenc::ParseMoney(map_arg::GetMapArgsString("-reservebalance").c_str(), miner::nReserveBalance))
        return data.runtime_error("invalid reserve balance amount\n");

    result.push_back(json_spirit::Pair("reserve", (miner::nReserveBalance > 0)));
    result.push_back(json_spirit::Pair("amount", ValueFromAmount(miner::nReserveBalance)));
    return data.JSONRPCSuccess(result);
}

// ppcoin: check wallet integrity
json_spirit::Value CRPCTable::checkwallet(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 0) {
        return data.JSONRPCSuccess(
            "checkwallet\n"
            "Check wallet for integrity.\n");
    }

    int nMismatchSpent;
    int64_t nBalanceInQuestion;
    entry::pwalletMain->FixSpentCoins(nMismatchSpent, nBalanceInQuestion, true);
    json_spirit::Object result;
    if (nMismatchSpent == 0)
        result.push_back(json_spirit::Pair("wallet check passed", true));
    else {
        result.push_back(json_spirit::Pair("mismatched spent coins", nMismatchSpent));
        result.push_back(json_spirit::Pair("amount in question", ValueFromAmount(nBalanceInQuestion)));
    }
    return data.JSONRPCSuccess(result);
}

// ppcoin: repair wallet
json_spirit::Value CRPCTable::repairwallet(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 0) {
        return data.JSONRPCSuccess(
            "repairwallet\n"
            "Repair wallet if checkwallet reports any problem.\n");
    }

    int nMismatchSpent;
    int64_t nBalanceInQuestion;
    entry::pwalletMain->FixSpentCoins(nMismatchSpent, nBalanceInQuestion);
    json_spirit::Object result;
    if (nMismatchSpent == 0)
        result.push_back(json_spirit::Pair("wallet check passed", true));
    else {
        result.push_back(json_spirit::Pair("mismatched spent coins", nMismatchSpent));
        result.push_back(json_spirit::Pair("amount affected by repair", ValueFromAmount(nBalanceInQuestion)));
    }
    return data.JSONRPCSuccess(result);
}

// ppcoin: resend unconfirmed wallet transactions
json_spirit::Value CRPCTable::resendtx(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 1) {
        return data.JSONRPCSuccess(
            "resendtx\n"
            "Re-send unconfirmed transactions.\n");
    }

    block_process::manage::ResendWalletTransactions(true);
    return data.JSONRPCSuccess(json_spirit::Value::null);
}

json_spirit::Value CRPCTable::resendwallettransactions(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 0) {
        return data.JSONRPCSuccess(
            "resendwallettransactions\n"
            "Immediately re-broadcast unconfirmed wallet transactions to all peers.\n"
            "Intended only for testing; the wallet code periodically re-broadcasts\n"
            "automatically.\n"
            "Returns array of transaction ids that were re-broadcast.\n");
    }

    LOCK2(block_process::cs_main, entry::pwalletMain->cs_wallet);
    std::vector<uint256> txids = entry::pwalletMain->ResendWalletTransactionsBefore(bitsystem::GetTime());
    json_spirit::Array result;
    for(const uint256 &txid: txids)
        result.push_back(txid.ToString());

    return data.JSONRPCSuccess(result);
}

// Make a public-private key pair
json_spirit::Value CRPCTable::makekeypair(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 0) {
        return data.JSONRPCSuccess(
            "makekeypair\n"
            "Make a public/private key pair.\n");
    }

    std::string strPrefix = "";
    if (params.size() > 0) {
        json_spirit::json_flags status;
        strPrefix = params[0].get_str(status);
        if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    }

    CKey key;
    key.MakeNewKey(true);

    CPrivKey vchPrivKey = key.GetPrivKey();
    json_spirit::Object result;
    result.push_back(json_spirit::Pair("PrivateKey", util::HexStr<CPrivKey::iterator>(vchPrivKey.begin(), vchPrivKey.end())));

    bool fCompressed;
    CSecret vchSecret = key.GetSecret(fCompressed);
    CPubKey vchPubKey = key.GetPubKey();
    result.push_back(json_spirit::Pair("Secret", util::HexStr<CSecret::iterator>(vchSecret.begin(), vchSecret.end())));
    result.push_back(json_spirit::Pair("PublicKey", util::HexStr(vchPubKey.begin(), vchPubKey.end())));
    return data.JSONRPCSuccess(result);
}

json_spirit::Value CRPCTable::newmalleablekey(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 1) {
        return data.JSONRPCSuccess(
            "newmalleablekey\n"
            "Make a malleable public/private key pair.\n");
    }

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount;
    if (params.size() > 0)
        strAccount = AccountFromValue(params[0], data);
    if(! data.fSuccess()) return data.JSONRPCError();

    CMalleableKeyView keyView = entry::pwalletMain->GenerateNewMalleableKey();
    CMalleableKey mKey;
    if (! entry::pwalletMain->GetMalleableKey(keyView, mKey))
        return data.runtime_error("Unable to generate new malleable key");

    CMalleablePubKey mPubKey = mKey.GetMalleablePubKey();
    CBitcoinAddress address(mPubKey);
    entry::pwalletMain->SetAddressBookName(address, strAccount);
    json_spirit::Object result;
    result.push_back(json_spirit::Pair("PublicPair", mPubKey.ToString()));
    result.push_back(json_spirit::Pair("PublicBytes", util::HexStr(mPubKey.Raw())));
    result.push_back(json_spirit::Pair("Address", address.ToString()));
    result.push_back(json_spirit::Pair("KeyView", keyView.ToString()));
    return data.JSONRPCSuccess(result);
}

json_spirit::Value CRPCTable::adjustmalleablekey(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 3) {
        return data.JSONRPCSuccess(
            "adjustmalleablekey <Malleable key data> <Public key variant data> <R data>\n"
            "Calculate new private key using provided malleable key, public key and R data.\n");
    }

    json_spirit::json_flags status;
    std::string jparam0 = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    std::string jparam1 = params[1].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    std::string jparam2 = params[2].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CMalleableKey malleableKey;
    malleableKey.SetString(jparam0);
    CKey privKeyVariant;
    CPubKey vchPubKeyVariant = CPubKey(strenc::ParseHex(jparam1));
    CPubKey R(strenc::ParseHex(jparam2));
    if (! malleableKey.CheckKeyVariant(R,vchPubKeyVariant, privKeyVariant))
        return data.runtime_error("Unable to calculate the private key");

    json_spirit::Object result;
    bool fCompressed;
    CSecret vchPrivKeyVariant = privKeyVariant.GetSecret(fCompressed);
    result.push_back(json_spirit::Pair("PrivateKey", CBitcoinSecret(vchPrivKeyVariant, fCompressed).ToString()));
    return data.JSONRPCSuccess(result);
}

json_spirit::Value CRPCTable::adjustmalleablepubkey(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() > 2 || params.size() == 0) {
        return data.JSONRPCSuccess(
            "adjustmalleablepubkey <Malleable address, key view or public key pair>\n"
            "Calculate new public key using provided data.\n");
    }

    json_spirit::json_flags status;
    std::string strData = params[0].get_str(status);
    if(! status.fSuccess()) return data.JSONRPCError(RPC_JSON_ERROR, status.e);
    CMalleablePubKey malleablePubKey;

    do {
        CBitcoinAddress addr(strData);
        if (addr.IsValid() && addr.IsPair()) {
            // Initialize malleable pubkey with address data
            malleablePubKey = CMalleablePubKey(addr.GetData());
            break;
        }

        CMalleableKeyView viewTmp(strData);
        if (viewTmp.IsValid()) {
            // Shazaam, we have a valid key view here.
            malleablePubKey = viewTmp.GetMalleablePubKey();
            break;
        }
        if (malleablePubKey.SetString(strData))
            break; // A valid public key pair

        return data.runtime_error("Though your data seems a valid Base58 string, we were unable to recognize it.");
    } while(false);

    CPubKey R, vchPubKeyVariant;
    malleablePubKey.GetVariant(R, vchPubKeyVariant);

    json_spirit::Object result;
    result.push_back(json_spirit::Pair("R", util::HexStr(R.begin(), R.end())));
    result.push_back(json_spirit::Pair("PubkeyVariant", util::HexStr(vchPubKeyVariant.begin(), vchPubKeyVariant.end())));
    result.push_back(json_spirit::Pair("KeyVariantID", CBitcoinAddress(vchPubKeyVariant.GetID()).ToString()));
    return data.JSONRPCSuccess(result);
}

json_spirit::Value CRPCTable::listmalleableviews(const json_spirit::Array &params, CBitrpcData &data) {
    if (data.fHelp() || params.size() != 0) {
        return data.JSONRPCSuccess(
            "listmalleableviews\n"
            "Get list of views for generated malleable keys.\n");
    }

    std::list<CMalleableKeyView> keyViewList;
    entry::pwalletMain->ListMalleableViews(keyViewList);

    json_spirit::Array result;
    for(const CMalleableKeyView &keyView: keyViewList)
        result.push_back(keyView.ToString());

    return data.JSONRPCSuccess(result);
}
