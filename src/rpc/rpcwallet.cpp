// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2024 The SorachanCoin developers
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
#include <bip32/hdchain.h>
#include <sorara/aitx.h>
#include <address/bech32.h>
#include <thread/threadqai.h>

CCriticalSection CRPCTable::cs_nWalletUnlockTime;
int64_t CRPCTable::nWalletUnlockTime = 0;

std::string CRPCTable::HelpRequiringPassphrase()
{
    return entry::pwalletMain->IsCrypted()
        ? "\n\nRequires wallet passphrase to be set with walletpassphrase first"
        : "";
}

void CRPCTable::EnsureWalletIsUnlocked()
{
    if (entry::pwalletMain->IsLocked()) {
        throw bitjson::JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }
    if (CWallet::fWalletUnlockMintOnly) {
        throw bitjson::JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Wallet unlocked for block minting only.");
    }
}

void CRPCTable::WalletTxToJSON(const CWalletTx &wtx, json_spirit::Object &entry)
{
    int confirms = wtx.GetDepthInMainChain();
    entry.push_back(json_spirit::Pair("confirmations", confirms));
    if (wtx.IsCoinBase() || wtx.IsCoinStake()) {
        entry.push_back(json_spirit::Pair("generated", true));
    }

    if (confirms) {
        entry.push_back(json_spirit::Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(json_spirit::Pair("blockindex", wtx.nIndex));
        entry.push_back(json_spirit::Pair("blocktime", (int64_t)(block_info::mapBlockIndex[wtx.hashBlock]->get_nTime())));
    }
    entry.push_back(json_spirit::Pair("txid", wtx.GetHash().GetHex()));
    entry.push_back(json_spirit::Pair("time", (int64_t)wtx.GetTxTime()));
    entry.push_back(json_spirit::Pair("timereceived", (int64_t)wtx.nTimeReceived));
    for(const std::pair<std::string, std::string>& item: wtx.mapValue)
    {
        entry.push_back(json_spirit::Pair(item.first, item.second));
    }
}

std::string CRPCTable::AccountFromValue(const json_spirit::Value &value)
{
    std::string strAccount = value.get_str();
    if (strAccount == "*") {
        throw bitjson::JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    }
    return strAccount;
}

json_spirit::Value CRPCTable::getinfo(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 0) {
        throw std::runtime_error(
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
    if (entry::pwalletMain->IsCrypted()) {
        obj.push_back(json_spirit::Pair("unlocked_until", (int64_t)nWalletUnlockTime / 1000));
    }

    obj.push_back(json_spirit::Pair("errors", block_alert::GetWarnings("statusbar")));
    return obj;
}

json_spirit::Value CRPCTable::getnewaddress(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            ("getnewaddress [account]\n"
            "Returns a new " + std::string(strCoinName) + " address for receiving payments.  "
            "If [account] is specified (recommended), it is added to the address book "
            "so payments received with the address will be credited to [account].").c_str());
    }

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount;
    if (params.size() > 0) {
        strAccount = AccountFromValue(params[0]);
    }
    if (! entry::pwalletMain->IsLocked()) {
        entry::pwalletMain->TopUpKeyPool();
    }

    //
    // Generate a new key that is added to wallet
    //
    CPubKey newKey;
    if (! entry::pwalletMain->GetKeyFromPool(newKey, false)) {
        throw bitjson::JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }
    CBitcoinAddress address(newKey.GetID());    // PublicKey => BitcoinAddress (SHA256, Base58)

    entry::pwalletMain->SetAddressBookName(address, strAccount);

    return address.ToString();
}

json_spirit::Value CRPCTable::getnewethaddress(const json_spirit::Array &params, bool fHelp)
{
    using namespace ScriptOpcodes;
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "getnewethaddress [account]\n"
            "Returns a new ETH style address for receiving payments.  "
            "If [account] is specified (recommended), it is added to the address book "
            "so payments received with the address will be credited to [account].");
    }

    if(! hd_wallet::get().enable)
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, "Error: HD Wallet disable");

    //if(! args_bool::fTestNet)
    //    throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, ("Invalid " + std::string(strCoinName) + " only testnet now").c_str());

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount;
    if (params.size() > 0) {
        strAccount = AccountFromValue(params[0]);
    }
    if (! entry::pwalletMain->IsLocked()) {
        entry::pwalletMain->TopUpKeyPool();
    }

    //
    // Generate a new key that is added to wallet
    //
    CPubKey newKey;
    if (! entry::pwalletMain->GetKeyFromPool(newKey, false)) {
        throw bitjson::JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }

    newKey.Compress();
    if(newKey.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE)
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: public key is invalid");

    CScript redeemScript = CScript() << OP_1 << newKey.GetPubVch() << OP_1 << OP_CHECKMULTISIG;
    entry::pwalletMain->AddCScript(redeemScript, newKey);
    CBitcoinAddress address(redeemScript.GetID());

    // redeemScript checking
    {
        //debugcs::instance() << "redeemScript size: " << redeemScript.size() << debugcs::endl();
        CScript redeemScript2;
        CKeyID keyid2;
        CEthID ethid2;
        if(! entry::pwalletMain->GetCScript(redeemScript.GetID(), redeemScript2, keyid2, ethid2))
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: redeemScript is invalid");
        if(redeemScript != redeemScript2)
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: redeemScript is invalid");
        if(newKey.GetID() != keyid2)
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: keyid is invalid");
    }

    //debugcs::instance() << "address: " << address.ToString() << debugcs::endl();
    entry::pwalletMain->SetAddressBookName(address, strAccount);
    return hasheth::EncodeHashEth(newKey);
}

json_spirit::Value CRPCTable::getnewqaiaddress(const json_spirit::Array &params, bool fHelp)
{
    using namespace ScriptOpcodes;
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "getnewqaiaddress [account]\n"
            "Returns a new sora quantum and AI resistance style address for receiving payments.  "
            "If [account] is specified (recommended), it is added to the address book "
            "so payments received with the address will be credited to [account].");
    }

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount;
    if (params.size() > 0) {
        strAccount = AccountFromValue(params[0]);
    }

    CBitcoinAddress address = CreateNewQaiAddress();
    entry::pwalletMain->SetAddressBookName(address, strAccount);
    return address.ToString();
}

json_spirit::Value CRPCTable::getnewschnorraddress(const json_spirit::Array &params, bool fHelp)
{
    using namespace ScriptOpcodes;
    if (fHelp || params.size() > 2) {
        throw std::runtime_error(
            "getnewschnorraddress [account] [aggregation size]\n"
            "If you want to specify the number of Schnorr aggregations, "
            "please set a value between 50 and 80,000 in [aggregation size].\n"
            "If omitted, the default is 5000.\n"
            "Returns a new sora quantum and AI resistance style address for receiving payments.  "
            "If [account] is specified (recommended), it is added to the address book "
            "so payments received with the address will be credited to [account].");
    }

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount;
    if (params.size() > 0) {
        strAccount = AccountFromValue(params[0]);
    }

    int agg_size = (int)XOnlyAggWalletInfo::DEF_AGG_XONLY_KEYS;
    if (params.size() > 1) {
        agg_size = params[1].get_int();
        if (agg_size < 50 || agg_size > 80000) {
            throw std::runtime_error("aggregation size out of range.");
        }
    }

    CBitcoinAddress address = CreateNewSchnorrAddress((size_t)agg_size);
    entry::pwalletMain->SetAddressBookName(address, strAccount);
    return address.ToString();
}

json_spirit::Value CRPCTable::getkeyentangle(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            "getkeyentangle [Eth style address]\n"
            "Returns a hidden address for receiving payments.\n"
            "This hidden address is recorded in the block explorer,\n"
            "and SORA's address and Ethereum address entangle through this hidden address.");
    }

    if(! hd_wallet::get().enable)
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, "Error: HD Wallet disable");

    std::string strhex = params[0].get_str();
    if(! (strhex.size() == sizeof(uint160) * 2 || strhex.size() == sizeof(uint160) * 2 + 2))
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: CEthID is invalid");

    CEthID ethid = hasheth::ParseHex(strhex);
    CKeyID keyid;
    if(! entry::pwalletMain->GetKeyID(ethid, keyid))
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: CKeyID is invalid");

    CBitcoinAddress address(keyid);
    return address.ToString(true);
}

json_spirit::Value CRPCTable::gethdwalletinfo(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 0) {
        throw std::runtime_error(
            "gethdwalletinfo\n"
            "Returns the status of HD Wallet, encryption and locked as enabled or disabled in JSON format.");
    }

    json_spirit::Object obj;
    obj.push_back(json_spirit::Pair("enabled", hd_wallet::get().enable ? true: false));
    obj.push_back(json_spirit::Pair("encryption", entry::pwalletMain->IsCrypted() ? true: false));
    obj.push_back(json_spirit::Pair("locked", entry::pwalletMain->IsLocked() ? true: false));
    return obj;
}

json_spirit::Value CRPCTable::getqpubkey(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 0) {
        throw std::runtime_error(
            "getqpubkey\n"
            "Return the quantum resistance public key in SORA.");
    }

    if(! hd_wallet::get().enable)
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, "Error: HD Wallet disable");

    EnsureWalletIsUnlocked();

    CqPubKey qpubkey = hd_wallet::get().GetPubKey();
    if(! qpubkey.IsFullyValid_BIP66())
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, "Error: CqPubKey is invalid");

    CqKeyID qid = qpubkey.GetID();
    std::string addr = std::string("0x") + qid;
    return addr;
}

json_spirit::Value CRPCTable::createhdwallet(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 0) {
        throw std::runtime_error(
            "createhdwallet\n"
            "Building SORA Integrate Wallet (BIP32 HD Wallet + Quantum + Random Wallet by importprivkey)\n"
            "Currently must be 0 balance. Otherwise, createhdwallet will be failure.");
    }

#ifdef WALLET_SQL_MODE
    bool ret = hd_create::CreateHDWallet(true, CSeedSecret());
    return ret;
#else
    return false;
#endif
}

json_spirit::Value CRPCTable::restorehdwallet(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 16) {
        throw std::runtime_error(
            "restorehdwallet [16 passphrase]\n"
            "Building and Restoring SORA Integrate Wallet (BIP32 HD Wallet + Quantum + Random Wallet by importprivkey)\n"
            "Currently must be 0 balance. Otherwise, restorehdwallet will be failure.");
    }

#ifdef WALLET_SQL_MODE
    std::vector<SecureString> vstr;
    vstr.resize(16);
    for(int i=0; i < 16; ++i) {
        vstr[i] = std::move(const_cast<std::string &>(params[i].get_str()));
    }
    CSeedSecret seed = hd_create::CreateSeed(vstr);
    bool ret = hd_create::CreateHDWallet(false, seed);
    return ret;
#else
    return false;
#endif
}

CBitcoinAddress CRPCTable::GetAccountAddress(std::string strAccount, bool bForceNew/* =false */)
{
    //CWalletDB walletdb(entry::pwalletMain->strWalletFile);
    CWalletDB walletdb(entry::pwalletMain->strWalletFile, entry::pwalletMain->strWalletLevelDB, entry::pwalletMain->strWalletSqlFile);

    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    bool bKeyUsed = false;

    // Check if the current key has been used
    if (account.vchPubKey.IsValid()) {
        CScript scriptPubKey;
        scriptPubKey.SetDestination(account.vchPubKey.GetID());
        for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end() && account.vchPubKey.IsValid(); ++it)
        {
            const CWalletTx &wtx = (*it).second;
            for(const CTxOut &txout: wtx.get_vout())
            {
                if (txout.get_scriptPubKey() == scriptPubKey) {
                    bKeyUsed = true;
                }
            }
        }
    }

    // Generate a new key
    if (!account.vchPubKey.IsValid() || bForceNew || bKeyUsed) {
        if (! entry::pwalletMain->GetKeyFromPool(account.vchPubKey, false)) {
            throw bitjson::JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
        }

        entry::pwalletMain->SetAddressBookName(account.vchPubKey.GetID(), strAccount);
        walletdb.WriteAccount(strAccount, account);
    }

    return CBitcoinAddress(account.vchPubKey.GetID());
}

json_spirit::Value CRPCTable::getaccountaddress(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            ("getaccountaddress <account>\n"
            "Returns the current " + std::string(strCoinName) + " address for receiving payments to this account.").c_str());
    }

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount = AccountFromValue(params[0]);

    json_spirit::Value ret;
    ret = GetAccountAddress(strAccount).ToString();

    return ret;
}

CBitcoinAddress CRPCTable::CreateNewQaiAddress(CScript *create_redeem/* = nullptr */) {
    using namespace ScriptOpcodes;

    if(! hd_wallet::get().enable)
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, "Error: HD Wallet disable");
    if (entry::pwalletMain->IsLocked())
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, "Error: HD Wallet locked");

    //
    // Generate a new key that is added to wallet
    //
    CPubKey newKey;
    if (! entry::pwalletMain->GetKeyFromPool(newKey, false)) {
        throw bitjson::JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }
    newKey.Compress();
    if(newKey.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE)
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: public key is invalid");

    script_vector qhashvch = hd_wallet::get().GetPubKeyQai().GetQaiHash();
    script_vector qrandvch = hd_wallet::get().GetPubKeyQai().GetRandHash();

    // SORA L1 Quantum and AI resistance transaction:
    // CScript() << OP_1 << ECDSA public key << Quantum and AI resistance public key hash << QAI rand hash << OP_3 << OP_CHECKMULTISIG
    CScript redeemScript = CScript() << OP_1 << newKey.GetPubVch() << qhashvch << qrandvch << OP_3 << OP_CHECKMULTISIG;
    entry::pwalletMain->AddCScript(redeemScript, newKey);
    CBitcoinAddress address(redeemScript.GetID());
    if(create_redeem)
        *create_redeem = redeemScript;

    // qsig check
    // if changed 1 byte in signature, verify firmly is failure.
    CqKey qkey(hd_wallet::get().GetSecretKey());
    if(qkey.IsValid()) {
        std::string check = redeemScript.ToString();
        uint256 h256;
        latest_crypto::CHash256().Write((const unsigned char *)check.data(), check.size()).Finalize(h256.begin());
        qkey_vector sig;
        qkey.SignQai(h256, sig);
        if(sig.size() == 128) {
            CqPubKey qpubkey = hd_wallet::get().GetPubKeyQai();
            bool ret1 = qpubkey.VerifyQai(h256, sig);
            bool ret2[128];
            for(int i=0; i < 128; ++i) {
                sig[i] += 0x2f;
                ret2[i] = qpubkey.VerifyQai(h256, sig);
            }
            bool ret3 = true;
            for(int i=0; i < 128; ++i) {
                if(ret2[i] != false) {
                    ret3 = false;
                    break;
                }
            }
            if(!(ret1 && ret3)) {
                throw bitjson::JSONRPCError(RPC_INTERNAL_ERROR, "Error: quantum and AI public key is invalid");
            }
        } else {
            throw bitjson::JSONRPCError(RPC_INTERNAL_ERROR, "Error: quantum and AI public sig size is invalid");
        }
    }

    return address;
}

CBitcoinAddress CRPCTable::CreateNewSchnorrAddress(size_t agg_size/* = XOnlyAggWalletInfo::DEF_AGG_XONLY_KEYS */, CScript *create_redeem/* = nullptr */) {
    using namespace ScriptOpcodes;

    if(! hd_wallet::get().enable)
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, "Error: HD Wallet disable");
    if (entry::pwalletMain->IsLocked())
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, "Error: HD Wallet locked");

    //
    // Generate a new key that is added to wallet
    //
    CPubKey newKey;
    if (! entry::pwalletMain->GetKeyFromPool(newKey, false)) {
        throw bitjson::JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }
    newKey.Compress();
    if(newKey.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE)
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: public key is invalid");

    //
    // Generate a new XOnlyPubKey that is added to wallet
    //
    XOnlyAggWalletInfo xonly_agg_wallet;
    if(!xonly_agg_wallet.LoadFromWalletInfo())
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: XOnlyAggWalletInfo is invalid");

    uint160 hash;
    if(!xonly_agg_wallet.MakeNewKey(hash, agg_size))
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: XonlyKey MakeNewKey is invalid");

    XOnlyPubKeys xonly_pubkeys;
    if(!xonly_agg_wallet.GetXOnlyPubKeys(hash, xonly_pubkeys))
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: XOnlyPubKeys is invalid");

    script_vector qhashvch = hd_wallet::get().GetPubKeyQai().GetQaiHash();
    XOnlyPubKey xonly_agg_pubkey = xonly_pubkeys.GetXOnlyPubKey();
    script_vector qrandvch = xonly_agg_pubkey.GetSchnorrHash();
    assert(qrandvch.size() == 33);

    // SORA L1 Quantum and AI resistance transaction:
    // CScript() << OP_1 << ECDSA public key << Quantum and AI resistance public key hash << QAI rand hash << OP_3 << OP_CHECKMULTISIG
    CScript redeemScript = CScript() << OP_1 << newKey.GetPubVch() << qhashvch << qrandvch << OP_3 << OP_CHECKMULTISIG;
    entry::pwalletMain->AddCScript(redeemScript, newKey);
    CBitcoinAddress address(redeemScript.GetID());
    if(create_redeem)
        *create_redeem = redeemScript;

    return address;
}

json_spirit::Value CRPCTable::getmysentmessages(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 2) {
        throw std::runtime_error(
            "getmysentmessages [recipient cipher message public key] [time(hours)] "
            "Outputs the messages you sent to recipient cipher message address. "
            "If omitted, it defaults to 168 hours (7 days).");
    }

    std::string recipient_address = params[0].get_str();
    const int hours = (params.size() > 0) ? params[1].get_int() : 168;
    std::string err;
    std::vector<std::pair<time_t, SecureString>> vdata;
    if(!ai_cipher::getsentmymessages(hours, recipient_address, vdata, err))
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, err.c_str());

    json_spirit::Object result;
    int num = 0;
    for(const auto &d: vdata) {
        json_spirit::Array obj;
        obj.emplace_back(ai_time::get_localtime_format(d.first));
        obj.emplace_back(std::string(d.second.c_str()));
        result.emplace_back(json_spirit::Pair(std::to_string(++num), obj));
    }

    return result;
}

json_spirit::Value CRPCTable::getciphermessages(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "getciphermessages [time(hours)]\n"
            "Specify the time you want to retrieve retrospectively in hours. "
            "If omitted, it defaults to 168 hours (7 days).");
    }

    const int hours = (params.size() > 0) ? params[0].get_int() : 168;
    std::string err;
    std::vector<std::tuple<time_t, std::string, SecureString>> vdata;
    if(!ai_cipher::getmessages(hours, vdata, err))
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, err.c_str());

    json_spirit::Object result;
    int num = 0;
    for(const auto &d: vdata) {
        json_spirit::Array obj;
        obj.emplace_back(ai_time::get_localtime_format(std::get<0>(d)));
        obj.emplace_back(std::string(std::get<1>(d)));
        obj.emplace_back(std::string(std::get<2>(d).c_str()));
        result.emplace_back(json_spirit::Pair(std::to_string(++num), obj));
    }

    return result;
}

json_spirit::Value CRPCTable::getnewcipheraddress(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 5) {
        throw std::runtime_error(
            "getnewcipheraddress or "
            "getnewcipheraddress [recipient address] [cipher message] (Stealth)\n"
            "If no arguments are provided, it can obtain a dedicated address for receiving encrypted messages. "
            "This is a special address that starts with cipher1.  "
            "If arguments are provided, please pass the address of the recipient "
            "it want to send the ciphertext to (an address starting with cipher1) "
            "followed by the ciphertext you wish to embed. "
            "If Stealth is 1, Stealth is enabled. (Optional and disabled by default.) ");
    }

    //! If no arguments, it can obtain a dedicated address for receiving encrypted messages
    if(params.size() == 0) {
        std::string cipher_address;
        std::string err;
        if(!ai_cipher::getmycipheraddress(cipher_address, err)) {
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, err.c_str());
        }
        return cipher_address;
    }

    //! If arguments are provided
    //! Creation SORA-QAI qai-v3 cipher message transaction
    if(params.size() >= 2) {
        std::string recipient_pubkey = params[0].get_str();
        SecureString cipher = const_cast<std::string &&>(params[1].get_str());
        bool stealth = false;
        int32_t wallet_lock = 0; // hyde option (locked wallet by transaction thread)
        int32_t mint_only = 0; // hyde option (locked wallet by transaction thread)
        if(params.size() >= 3) {
            if(params[2].get_int() == 1)
                stealth = true;
        }
        if(params.size() >= 4) {
            if(params[3].get_int() == 1)
                wallet_lock = 1;
        }
        if(params.size() >= 5) {
            if(params[4].get_int() == 1)
                mint_only = 1;
        }
        CBitcoinAddress address = CreateNewCipherAddress(recipient_pubkey, cipher, stealth);

        /*
        uint160 rand_hash;
        unsigned char buf[32];
        latest_crypto::random::GetRandBytes(buf, sizeof(buf));
        latest_crypto::CHash160().Write(buf, sizeof(buf)).Finalize(rand_hash.begin());
        std::string acc_hash = "cipher_" + rand_hash.GetHex();
        entry::pwalletMain->SetAddressBookName(address, acc_hash);
        */

        CThread thread;
        CDataStream stream;
        double fee = 0.1;
        int64_t nAmount = util::roundint64(fee * util::COIN);
        stream << address.ToString() << nAmount << (int32_t)1 << wallet_lock << mint_only;
        CThread::THREAD_INFO info(&stream, aitx_thread::wait_for_confirm_transaction);
        if(thread.BeginThread(info))
            thread.Detach();
        else
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: failed to begin aitx transactions");

        return address.ToString();
    }

    throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: params is invalid");
    return std::string("");
}

CBitcoinAddress CRPCTable::CreateNewCipherAddress(const std::string &recipient_pubkey, const SecureString &cipher, bool stealth) {
    using namespace ScriptOpcodes;

    if(!hd_wallet::get().enable)
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, "Error: HD Wallet disable");
    if (entry::pwalletMain->IsLocked())
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, "Error: HD Wallet locked");

    //
    // Generate a new key that is added to wallet
    //
    CPubKey newKey;
    if (! entry::pwalletMain->GetKeyFromPool(newKey, false)) {
        throw bitjson::JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }
    newKey.Compress();
    if(newKey.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE)
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: public key is invalid");

    //
    // Generate a new XOnlyPubKeys that is added to wallet
    // XOnlyKeys is used by SymmetricKey
    //
    XOnlyAggWalletInfo xonly_agg_wallet;
    if(!xonly_agg_wallet.LoadFromWalletInfo())
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: XOnlyAggWalletInfo is invalid");

    uint160 hash;
    if(!xonly_agg_wallet.MakeNewKey(hash, ai_cipher::cipher_agg_size))
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: XonlyKey MakeNewKey is invalid");

    XOnlyPubKeys my_xonly_schnorr_pubkeys;
    XOnlyKeys my_xonly_schnorr_keys;
    if(!xonly_agg_wallet.GetXOnlyKeys(hash, my_xonly_schnorr_pubkeys, my_xonly_schnorr_keys))
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: XOnlyPubKeys is invalid");

    //
    // Compute SymmetricKey
    //
    const std::pair<std::string, bech32_vector> b32recipient_key = bech32::Decode(recipient_pubkey);
    if(b32recipient_key.first != GetHrpCipher())
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: recipient_address is invalid");

    bech32_vector recipient_agg_pubkey = DecodeFromSoraL1QAItxBech32(b32recipient_key.second);
    // When decoding 32 bytes with bech32, a 0x00 is added at the end, making it 33 bytes.
    if(recipient_agg_pubkey.size() != XOnlyPubKey::XONLY_PUBLIC_KEY_SIZE + 1)
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: recipient_address is invalid");
    recipient_agg_pubkey.pop_back(); // erase at the end (0x00)

    CSecret my_agg_key;
    if(!my_xonly_schnorr_keys.GetSecret(my_agg_key))
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: fail to compute in XOnlyKey");

    secp256k1_symmetrickey symmetrickey;
    if(SymmetricKey::secp256k1_schnorrsig_symmetrickey(NULL,  my_agg_key.data(), recipient_agg_pubkey.data(), &symmetrickey) != 1)
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: fail to compute in SymmetricKey");
    SymmetricKey symkey(symmetrickey);

    //
    // from my cipher public key
    //
    bech32_vector b32_my_cipher_xonly_agg_pubkey;
    if(!stealth) {
        XOnlyPubKeys my_cipher_xonly_agg_pubkeys;
        if(!XOnlyAggWalletInfo::GetAggPublicKeys(ai_cipher::cipher_begin_index, ai_cipher::cipher_agg_size, my_cipher_xonly_agg_pubkeys))
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: my cipher XOnlyPubKeys is invalid");
        XOnlyPubKey my_cipher_xonly_agg_pubkey = my_cipher_xonly_agg_pubkeys.GetXOnlyPubKey();
        b32_my_cipher_xonly_agg_pubkey = my_cipher_xonly_agg_pubkey.GetPubVch();
        if(b32_my_cipher_xonly_agg_pubkey.size() != XOnlyPubKey::XONLY_PUBLIC_KEY_SIZE)
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: my cipher XOnlyPubKeys size is invalid");
    }

    //
    // Build aitx and qrandhash
    //
    std::string recipient_agg_pubhex;
    if(!stealth) {
        recipient_agg_pubhex.reserve(66);
        recipient_agg_pubhex = std::string("[");
        recipient_agg_pubhex += strenc::HexStr(b32_my_cipher_xonly_agg_pubkey);
        recipient_agg_pubhex += std::string("]");
        if(recipient_agg_pubhex.size() != (XOnlyPubKey::XONLY_PUBLIC_KEY_SIZE * 2) + 2)
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: recipient_address hex is invalid");
    } else {
        recipient_agg_pubhex.reserve(2);
        recipient_agg_pubhex = std::string("[");
        recipient_agg_pubhex += std::string("]");
    }
    SecureString cipher_and_pubkey = cipher;
    cipher_and_pubkey += std::move(recipient_agg_pubhex);
    CAITransaction03 aitx;
    if(!aitx.PushTokenMessage(symkey, cipher_and_pubkey))
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: fail to compute in CAITransaction03");
    aitx.SetSchnorrAggregateKeyID(my_xonly_schnorr_pubkeys.GetXOnlyPubKey());

    //
    // Build qai hash
    //
    script_vector qhashvch = hd_wallet::get().GetPubKeyQai().GetQaiHash();
    std::pair<qkey_vector, bool> qrand = aitx.GetSchnorrHash();
    if(!qrand.second)
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: qrandvch is invalid");
    script_vector qrandvch = qrand.first;
    assert(qrandvch.size() == 33);

    //
    // Serialize from aitx to wallet (for bind)
    //
    {
        CWalletDB walletdb(entry::pwalletMain->strWalletFile, entry::pwalletMain->strWalletLevelDB, entry::pwalletMain->strWalletSqlFile);
        LOCK(entry::pwalletMain->cs_wallet);
        if(walletdb.ExistsAitx03(qrandvch))
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: Aitx has been already bind to wallet");
        if(!walletdb.WriteAitx03(qrandvch, aitx))
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMS, "Error: failed to bind from aitx to wallet");
    }

    // SORA L1 Quantum and AI resistance transaction:
    // CScript() << OP_1 << ECDSA public key << Quantum and AI resistance public key hash << QAI rand hash << OP_3 << OP_CHECKMULTISIG
    CScript redeemScript = CScript() << OP_1 << newKey.GetPubVch() << qhashvch << qrandvch << OP_3 << OP_CHECKMULTISIG;
    entry::pwalletMain->AddCScript(redeemScript, newKey);
    CBitcoinAddress address(redeemScript.GetID());
    return address;
}

CBitcoinAddress CRPCTable::GetAccountQaiAddress(std::string strAccount, bool bForceNew/* =false */)
{
    CWalletDB walletdb(entry::pwalletMain->strWalletFile, entry::pwalletMain->strWalletLevelDB, entry::pwalletMain->strWalletSqlFile);
    CAccountqai account;

    walletdb.ReadQaiAccount(strAccount, account);
    bool bKeyUsed = false;

    // Check if the current key has been used
    if (account.redeemScript != CScript()) {
        CScript scriptPubKey;
        scriptPubKey.SetDestination(account.redeemScript.GetID());
        for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); ++it)
        {
            const CWalletTx &wtx = (*it).second;
            for(const CTxOut &txout: wtx.get_vout())
            {
                if (scriptPubKey == txout.get_scriptPubKey()) {
                    bKeyUsed = true;
                    break;
                }
            }
            if(bKeyUsed)
                break;
        }
    }

    // Generate a new key
    if (account.redeemScript == CScript() || bForceNew || bKeyUsed) {
        CBitcoinAddress address = CreateNewQaiAddress(&account.redeemScript);
        entry::pwalletMain->SetAddressBookName(address, strAccount);
        walletdb.WriteQaiAccount(strAccount, account);
        return address;
    }

    return CBitcoinAddress(account.redeemScript.GetID());
}

json_spirit::Value CRPCTable::getaccountqaiaddress(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            ("getaccountqaiaddress <account>\n"
            "Returns the current " + std::string(strCoinName) + " address for receiving payments to this account.").c_str());
    }

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount = AccountFromValue(params[0]);

    json_spirit::Value ret;
    ret = GetAccountQaiAddress(strAccount).ToString();

    return ret;
}

CBitcoinAddress CRPCTable::GetAccountSchnorrAddress(std::string strAccount, bool bForceNew/* =false */)
{
    CWalletDB walletdb(entry::pwalletMain->strWalletFile, entry::pwalletMain->strWalletLevelDB, entry::pwalletMain->strWalletSqlFile);
    CAccountqai account;

    walletdb.ReadQaiAccount(strAccount, account);
    bool bKeyUsed = false;

    // Check if the current key has been used
    if (account.redeemScript != CScript()) {
        CScript scriptPubKey;
        scriptPubKey.SetDestination(account.redeemScript.GetID());
        for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); ++it)
        {
            const CWalletTx &wtx = (*it).second;
            for(const CTxOut &txout: wtx.get_vout())
            {
                if (scriptPubKey == txout.get_scriptPubKey()) {
                    bKeyUsed = true;
                    break;
                }
            }
            if(bKeyUsed)
                break;
        }
    }

    // Generate a new key
    if (account.redeemScript == CScript() || bForceNew || bKeyUsed) {
        CBitcoinAddress address = CreateNewSchnorrAddress(XOnlyAggWalletInfo::DEF_AGG_XONLY_KEYS, &account.redeemScript);
        entry::pwalletMain->SetAddressBookName(address, strAccount);
        walletdb.WriteQaiAccount(strAccount, account);
        return address;
    }

    return CBitcoinAddress(account.redeemScript.GetID());
}

json_spirit::Value CRPCTable::getaccountschnorraddress(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            ("getaccountschnorraddress <account>\n"
            "Returns the current " + std::string(strCoinName) + " address for receiving payments to this account.").c_str());
    }

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount = AccountFromValue(params[0]);

    json_spirit::Value ret;
    ret = GetAccountSchnorrAddress(strAccount).ToString();

    return ret;
}

json_spirit::Value CRPCTable::setaccount(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) {
        throw std::runtime_error(
            "setaccount <coinaddress> <account>\n"
            "Sets the account associated with the given address.");
    }

    CBitcoinAddress address(params[0].get_str());
    if (! address.IsValid()) {
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, ("Invalid " + std::string(strCoinName) + " address").c_str());
    }

    std::string strAccount;
    if (params.size() > 1) {
        strAccount = AccountFromValue(params[1]);
    }

    // Detect when changing the account of an address that is the 'unused current key' of another account:
    if (entry::pwalletMain->mapAddressBook.count(address)) {
        std::string strOldAccount = entry::pwalletMain->mapAddressBook[address];
        if (address == GetAccountAddress(strOldAccount)) {
            GetAccountAddress(strOldAccount, true);
        }
    }

    entry::pwalletMain->SetAddressBookName(address, strAccount);

    return json_spirit::Value::null;
}

json_spirit::Value CRPCTable::getaccount(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            "getaccount <coinaddress>\n"
            "Returns the account associated with the given address.");
    }

    CBitcoinAddress address(params[0].get_str());
    if (! address.IsValid()) {
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, ("Invalid " + std::string(strCoinName) + " address").c_str());
    }

    std::string strAccount;
    std::map<CBitcoinAddress, std::string>::iterator mi = entry::pwalletMain->mapAddressBook.find(address);
    if (mi != entry::pwalletMain->mapAddressBook.end() && !(*mi).second.empty()) {
        strAccount = (*mi).second;
    }
    return strAccount;
}

json_spirit::Value CRPCTable::getaddressesbyaccount(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            "getaddressesbyaccount <account>\n"
            "Returns the list of addresses for the given account.");
    }

    std::string strAccount = AccountFromValue(params[0]);

    //
    // Find all addresses that have the given account
    //
    json_spirit::Array ret;
    for(const std::pair<CBitcoinAddress, std::string>&item: entry::pwalletMain->mapAddressBook)
    {
        const CBitcoinAddress &address = item.first;
        const std::string &strName = item.second;
        if (strName == strAccount) {
            ret.push_back(address.ToString());
        }
    }
    return ret;
}

json_spirit::Value CRPCTable::mergecoins(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3) {
        throw std::runtime_error(
            "mergecoins <amount> <minvalue> <outputvalue>\n"
            "<amount> is resulting inputs sum\n"
            "<minvalue> is minimum value of inputs which are used in join process\n"
            "<outputvalue> is resulting value of inputs which will be created\n"
            "All values are real and and rounded to the nearest " + strenc::FormatMoney(block_info::nMinimumInputValue)
            + HelpRequiringPassphrase());
    }

    if (entry::pwalletMain->IsLocked()) {
        throw bitjson::JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }

    // Total amount
    int64_t nAmount = AmountFromValue(params[0]);

    // Min input amount
    int64_t nMinValue = AmountFromValue(params[1]);

    // Output amount
    int64_t nOutputValue = AmountFromValue(params[2]);

    if (nAmount < block_info::nMinimumInputValue) {
        throw bitjson::JSONRPCError(-101, "Send amount too small");
    }
    if (nMinValue < block_info::nMinimumInputValue) {
        throw bitjson::JSONRPCError(-101, "Max value too small");
    }
    if (nOutputValue < block_info::nMinimumInputValue) {
        throw bitjson::JSONRPCError(-101, "Output value too small");
    }
    if (nOutputValue < nMinValue) {
        throw bitjson::JSONRPCError(-101, "Output value is lower than min value");
    }

    std::list<uint256> listMerged;
    if (! entry::pwalletMain->MergeCoins(nAmount, nMinValue, nOutputValue, listMerged)) {
        return json_spirit::Value::null;
    }

    json_spirit::Array mergedHashes;
    for(const uint256 txHash: listMerged)
    {
        mergedHashes.push_back(txHash.GetHex());
    }

    return mergedHashes;
}

json_spirit::Value CRPCTable::sendtoaddress(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4) {
        throw std::runtime_error(
            "sendtoaddress <coinaddress> <amount> [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest " + strenc::FormatMoney(block_info::nMinimumInputValue)
            + HelpRequiringPassphrase());
    }

    // Parse address
    CScript scriptPubKey;
    std::string strAddress = params[0].get_str();

    CBitcoinAddress address(strAddress);
    if (address.IsValid()) {
        scriptPubKey.SetAddress(address);
    } else {
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, ("Invalid " + std::string(strCoinName) + " address").c_str());
    }

    // Amount
    int64_t nAmount = AmountFromValue(params[1]);

    if (nAmount < block_info::nMinimumInputValue) {
        throw bitjson::JSONRPCError(-101, "Send amount too small");
    }

    // Wallet comments
    CWalletTx wtx;
    if (params.size() > 2 && params[2].type() != json_spirit::null_type && !params[2].get_str().empty()) {
        wtx.mapValue["comment"] = params[2].get_str();
    }
    if (params.size() > 3 && params[3].type() != json_spirit::null_type && !params[3].get_str().empty()) {
        wtx.mapValue["to"] = params[3].get_str();
    }

    if (entry::pwalletMain->IsLocked()) {
        throw bitjson::JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }

    std::string strError = entry::pwalletMain->SendMoney(scriptPubKey, nAmount, wtx);
    if (! strError.empty()) {
        throw bitjson::JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    return wtx.GetHash().GetHex();
}

json_spirit::Value CRPCTable::listaddressgroupings(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp) {
        throw std::runtime_error(
            "listaddressgroupings\n"
            "Lists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions");
    }

    json_spirit::Array jsonGroupings;
    std::map<CBitcoinAddress, int64_t> balances = entry::pwalletMain->GetAddressBalances();
    for(std::set<CBitcoinAddress> grouping: entry::pwalletMain->GetAddressGroupings())
    {
        json_spirit::Array jsonGrouping;
        for(CBitcoinAddress address: grouping)
        {
            json_spirit::Array addressInfo;
            addressInfo.push_back(address.ToString());
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                LOCK(entry::pwalletMain->cs_wallet);
                if (entry::pwalletMain->mapAddressBook.find(address) != entry::pwalletMain->mapAddressBook.end()) {
                    addressInfo.push_back(entry::pwalletMain->mapAddressBook.find(address)->second);
                }
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
}

json_spirit::Value CRPCTable::signmessage(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 2) {
        throw std::runtime_error(
            "signmessage <coinaddress> <message>\n"
            "Sign a message with the private key of an address");
    }

    EnsureWalletIsUnlocked();

    std::string strAddress = params[0].get_str();
    std::string strMessage = params[1].get_str();

    CBitcoinAddress addr(strAddress);
    if (! addr.IsValid()) {
        throw bitjson::JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }

    CKeyID keyID;
    if (! addr.GetKeyID(keyID)) {
        throw bitjson::JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
    }

    CFirmKey key;
    if (! entry::pwalletMain->GetKey(keyID, key)) {
        throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "Private key not available");
    }

    CDataStream ss(SER_GETHASH, 0);
    ss << block_info::strMessageMagic;
    ss << strMessage;

    key_vector vchSig;
    if (! key.SignCompact(hash_basis::Hash(ss.begin(), ss.end()), vchSig)) {
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");
    }
    return strenc::EncodeBase64(&vchSig[0], vchSig.size());
}

json_spirit::Value CRPCTable::verifymessage(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 3) {
        throw std::runtime_error(
            "verifymessage <coinaddress> <signature> <message>\n"
            "Verify a signed message");
    }

    std::string strAddress  = params[0].get_str();
    std::string strSign     = params[1].get_str();
    std::string strMessage  = params[2].get_str();

    CBitcoinAddress addr(strAddress);
    if (! addr.IsValid()) {
        throw bitjson::JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }

    CKeyID keyID;
    if (! addr.GetKeyID(keyID)) {
        throw bitjson::JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
    }

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = strenc::DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid) {
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");
    }

    CDataStream ss(SER_GETHASH, 0);
    ss << block_info::strMessageMagic;
    ss << strMessage;

    CPubKey key;
    if (! key.SetCompactSignature(hash_basis::Hash(ss.begin(), ss.end()), vchSig)) {
        return false;
    }
    return (key.GetID() == keyID);
}

json_spirit::Value CRPCTable::getreceivedbyaddress(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) {
        throw std::runtime_error(
            "getreceivedbyaddress <coinaddress> [minconf=1]\n"
            "Returns the total amount received by <coinaddress> in transactions with at least [minconf] confirmations.");
    }

    // Bitcoin address
    CBitcoinAddress address = CBitcoinAddress(params[0].get_str());
    if (! address.IsValid()) {
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, ("Invalid " + std::string(strCoinName) + " address").c_str());
    }
    if (! Script_util::IsMine(*entry::pwalletMain,address)) {
        return 0.0;
    }

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1) {
        nMinDepth = params[1].get_int();
    }

    int64_t nAmount = 0;
    for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx &wtx = (*it).second;
        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !wtx.IsFinal()) {
            continue;
        }

        for(const CTxOut &txout: wtx.get_vout())
        {
            CBitcoinAddress addressRet;
            if (! Script_util::ExtractAddress(*entry::pwalletMain, txout.get_scriptPubKey(), addressRet)) {
                continue;
            }
            if (addressRet == address) {
                if (wtx.GetDepthInMainChain() >= nMinDepth) {
                    nAmount += txout.get_nValue();
                }
            }
        }
    }

    return  ValueFromAmount(nAmount);
}

void CRPCTable::GetAccountAddresses(std::string strAccount, std::set<CBitcoinAddress> &setAddress)
{
    for(const std::pair<CBitcoinAddress, std::string>&item: entry::pwalletMain->mapAddressBook)
    {
        const CBitcoinAddress &address = item.first;
        const std::string &strName = item.second;
        if (strName == strAccount) {
            setAddress.insert(address);
        }
    }
}

json_spirit::Value CRPCTable::getreceivedbyaccount(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) {
        throw std::runtime_error(
            "getreceivedbyaccount <account> [minconf=1]\n"
            "Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.");
    }

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1) {
        nMinDepth = params[1].get_int();
    }

    // Get the set of pub keys assigned to account
    std::string strAccount = AccountFromValue(params[0]);
    std::set<CBitcoinAddress> setAddress;
    GetAccountAddresses(strAccount, setAddress);

    // Tally
    int64_t nAmount = 0;
    for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx &wtx = (*it).second;
        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !wtx.IsFinal()) {
            continue;
        }

        for(const CTxOut &txout: wtx.get_vout())
        {
            CBitcoinAddress address;
            if (Script_util::ExtractAddress(*entry::pwalletMain, txout.get_scriptPubKey(), address) && Script_util::IsMine(*entry::pwalletMain, address) && setAddress.count(address)) {
                if (wtx.GetDepthInMainChain() >= nMinDepth) {
                    nAmount += txout.get_nValue();
                }
            }
        }
    }

    return (double)nAmount / (double)util::COIN;
}


int64_t CRPCTable::GetAccountBalance(CWalletDB &walletdb, const std::string &strAccount, int nMinDepth, const isminefilter &filter)
{
    int64_t nBalance = 0;

    // Tally wallet transactions
    for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx &wtx = (*it).second;
        if (! wtx.IsFinal()) {
            continue;
        }

        int64_t nGenerated, nReceived, nSent, nFee;
        wtx.GetAccountAmounts(strAccount, nGenerated, nReceived, nSent, nFee, filter);

        if (nReceived != 0 && wtx.GetDepthInMainChain() >= nMinDepth) {
            nBalance += nReceived;
        }
        nBalance += nGenerated - nSent - nFee;
    }

    // Tally internal accounting entries
    nBalance += walletdb.GetAccountCreditDebit(strAccount);

    return nBalance;
}

int64_t CRPCTable::GetAccountBalance(const std::string &strAccount, int nMinDepth, const isminefilter &filter)
{
    //CWalletDB walletdb(entry::pwalletMain->strWalletFile);
    CWalletDB walletdb(entry::pwalletMain->strWalletFile, entry::pwalletMain->strWalletLevelDB, entry::pwalletMain->strWalletSqlFile);
    return GetAccountBalance(walletdb, strAccount, nMinDepth, filter);
}

json_spirit::Value CRPCTable::getbalance(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 2) {
        throw std::runtime_error(
            "getbalance [account] [minconf=1] [watchonly=0]\n"
            "If [account] is not specified, returns the server's total available balance.\n"
            "If [account] is specified, returns the balance in the account.\n"
            "if [includeWatchonly] is specified, include balance in watchonly addresses (see 'importaddress').");
    }

    if (params.size() == 0) {
        return ValueFromAmount(entry::pwalletMain->GetBalance());
    }

    int nMinDepth = 1;
    if (params.size() > 1) {
        nMinDepth = params[1].get_int();
    }

    isminefilter filter = MINE_SPENDABLE;
    if(params.size() > 2) {
        if(params[2].get_bool()) {
            filter = filter | MINE_WATCH_ONLY;
        }
    }

    if (params[0].get_str() == "*") {
        //
        // Calculate total balance a different way from GetBalance()
        // (GetBalance() sums up all unspent TxOuts)
        // getbalance and getbalance '*' 0 should return the same number.
        //
        int64_t nBalance = 0;
        for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = (*it).second;
            if (! wtx.IsTrusted()) {
                continue;
            }

            int64_t allGeneratedImmature, allGeneratedMature, allFee;
            allGeneratedImmature = allGeneratedMature = allFee = 0;

            std::string strSentAccount;
            std::list<std::pair<CBitcoinAddress, int64_t> > listReceived;
            std::list<std::pair<CBitcoinAddress, int64_t> > listSent;
            wtx.GetAmounts(allGeneratedImmature, allGeneratedMature, listReceived, listSent, allFee, strSentAccount, filter);
            if (wtx.GetDepthInMainChain() >= nMinDepth) {
                for(const std::pair<CBitcoinAddress,int64_t>&r: listReceived)
                {
                    nBalance += r.second;
                }
            }
            for(const std::pair<CBitcoinAddress,int64_t>& r: listSent)
            {
                nBalance -= r.second;
            }

            nBalance -= allFee;
            nBalance += allGeneratedMature;
        }
        return ValueFromAmount(nBalance);
    }

    std::string strAccount = AccountFromValue(params[0]);

    int64_t nBalance = GetAccountBalance(strAccount, nMinDepth, filter);

    return ValueFromAmount(nBalance);
}

json_spirit::Value CRPCTable::movecmd(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 5) {
        throw std::runtime_error(
            "move <fromaccount> <toaccount> <amount> [minconf=1] [comment]\n"
            "Move from one account in your wallet to another.");
    }

    std::string strFrom = AccountFromValue(params[0]);
    std::string strTo = AccountFromValue(params[1]);
    int64_t nAmount = AmountFromValue(params[2]);

    if (nAmount < block_info::nMinimumInputValue) {
        throw bitjson::JSONRPCError(-101, "Send amount too small");
    }

    if (params.size() > 3) {
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)params[3].get_int();
    }

    std::string strComment;
    if (params.size() > 4) {
        strComment = params[4].get_str();
    }

    //CWalletDB walletdb(entry::pwalletMain->strWalletFile);
    CWalletDB walletdb(entry::pwalletMain->strWalletFile, entry::pwalletMain->strWalletLevelDB, entry::pwalletMain->strWalletSqlFile);
    if (! walletdb.TxnBegin()) {
        throw bitjson::JSONRPCError(RPC_DATABASE_ERROR, "database error");
    }

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

    if (! walletdb.TxnCommit()) {
        throw bitjson::JSONRPCError(RPC_DATABASE_ERROR, "database error");
    }

    return true;
}

json_spirit::Value CRPCTable::sendfrom(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 6) {
        throw std::runtime_error(
            "sendfrom <from account> <to coinaddress> <amount> [minconf=1] [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest " + strenc::FormatMoney(block_info::nMinimumInputValue)
            + HelpRequiringPassphrase());
    }

    std::string strAccount = AccountFromValue(params[0]);

    // Parse address
    CScript scriptPubKey;
    std::string strAddress = params[1].get_str();

    CBitcoinAddress address(strAddress);
    if (address.IsValid()) {
        scriptPubKey.SetAddress(address);
    } else {
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, ("Invalid " + std::string(strCoinName) + " address").c_str());
    }

    int64_t nAmount = AmountFromValue(params[2]);
    if (nAmount < block_info::nMinimumInputValue) {
        throw bitjson::JSONRPCError(-101, "Send amount too small");
    }

    int nMinDepth = 1;
    if (params.size() > 3) {
        nMinDepth = params[3].get_int();
    }

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 4 && params[4].type() != json_spirit::null_type && !params[4].get_str().empty()) {
        wtx.mapValue["comment"] = params[4].get_str();
    }
    if (params.size() > 5 && params[5].type() != json_spirit::null_type && !params[5].get_str().empty()) {
        wtx.mapValue["to"]      = params[5].get_str();
    }

    EnsureWalletIsUnlocked();

    // Check funds
    int64_t nBalance = GetAccountBalance(strAccount, nMinDepth, MINE_SPENDABLE);
    if (nAmount > nBalance) {
        throw bitjson::JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");
    }

    // Send
    std::string strError = entry::pwalletMain->SendMoney(scriptPubKey, nAmount, wtx);
    if (! strError.empty()) {
        throw bitjson::JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    return wtx.GetHash().GetHex();
}

json_spirit::Value CRPCTable::sendethfrom(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 6) {
        throw std::runtime_error(
            "sendfrom <from account> <to ETH type coinaddress> <amount> [minconf=1] [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest " + strenc::FormatMoney(block_info::nMinimumInputValue)
            + HelpRequiringPassphrase());
    }

    if(! hd_wallet::get().enable)
        throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, "Error: HD Wallet disable");

    //if(! args_bool::fTestNet)
    //    throw bitjson::JSONRPCError(RPC_INVALID_REQUEST, ("Invalid " + std::string(strCoinName) + " only testnet now").c_str());

    std::string strAccount = AccountFromValue(params[0]);

    // Parse address
    CScript scriptPubKey;
    std::string strAddress = params[1].get_str();
    CEthID ethid;
    ethid.SetHex(strAddress.c_str());
    CScriptID scriptid;
    if(! entry::pwalletMain->GetScriptID(ethid, scriptid))
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, ("Invalid " + std::string(strCoinName) + " EthID").c_str());

    CBitcoinAddress address(scriptid);
    if (address.IsValid()) {
        scriptPubKey.SetAddress(address);
    } else {
        throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, ("Invalid " + std::string(strCoinName) + " address").c_str());
    }

    int64_t nAmount = AmountFromValue(params[2]);
    if (nAmount < block_info::nMinimumInputValue) {
        throw bitjson::JSONRPCError(-101, "Send amount too small");
    }

    int nMinDepth = 1;
    if (params.size() > 3) {
        nMinDepth = params[3].get_int();
    }

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 4 && params[4].type() != json_spirit::null_type && !params[4].get_str().empty()) {
        wtx.mapValue["comment"] = params[4].get_str();
    }
    if (params.size() > 5 && params[5].type() != json_spirit::null_type && !params[5].get_str().empty()) {
        wtx.mapValue["to"]      = params[5].get_str();
    }

    EnsureWalletIsUnlocked();

    // Check funds
    int64_t nBalance = GetAccountBalance(strAccount, nMinDepth, MINE_SPENDABLE);
    if (nAmount > nBalance) {
        throw bitjson::JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");
    }

    // Send
    std::string strError = entry::pwalletMain->SendMoney(scriptPubKey, nAmount, wtx);
    if (! strError.empty()) {
        throw bitjson::JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    return wtx.GetHash().GetHex();
}

json_spirit::Value CRPCTable::sendmany(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4) {
        throw std::runtime_error(
            "sendmany <fromaccount> '{address:amount,...}' [minconf=1] [comment]\n"
            "amounts are double-precision floating point numbers"
            + HelpRequiringPassphrase());
    }

    std::string strAccount = AccountFromValue(params[0]);
    json_spirit::Object sendTo = params[1].get_obj();
    int nMinDepth = 1;
    if (params.size() > 2) {
        nMinDepth = params[2].get_int();
    }

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 3 && params[3].type() != json_spirit::null_type && !params[3].get_str().empty()) {
        wtx.mapValue["comment"] = params[3].get_str();
    }

    std::set<CBitcoinAddress> setAddress;
    std::vector<std::pair<CScript, int64_t> > vecSend;

    int64_t totalAmount = 0;
    for(const json_spirit::Pair &s: sendTo)
    {
        CBitcoinAddress address(s.name_);
        if (! address.IsValid()) {
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string(("Invalid " + std::string(strCoinName) + " address: ").c_str()) + s.name_);
        }

        if (! address.IsPair()) {
            if (setAddress.count(address)) {
                throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + s.name_);
            }
            setAddress.insert(address);
        }

        CScript scriptPubKey;
        scriptPubKey.SetAddress(address);
        int64_t nAmount = AmountFromValue(s.value_);

        if (nAmount < block_info::nMinimumInputValue) {
            throw bitjson::JSONRPCError(-101, "Send amount too small");
        }

        totalAmount += nAmount;

        vecSend.push_back(std::make_pair(scriptPubKey, nAmount));
    }

    EnsureWalletIsUnlocked();

    // Check funds
    int64_t nBalance = GetAccountBalance(strAccount, nMinDepth, MINE_SPENDABLE);
    if (totalAmount > nBalance) {
        throw bitjson::JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");
    }

    // Send
    CReserveKey keyChange(entry::pwalletMain);
    int64_t nFeeRequired = 0;
    bool fCreated = entry::pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired);
    if (! fCreated) {
        int64_t nTotal = entry::pwalletMain->GetBalance(), nWatchOnly = entry::pwalletMain->GetWatchOnlyBalance();
        if (totalAmount + nFeeRequired > nTotal - nWatchOnly) {
            throw bitjson::JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");
        }
        throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "Transaction creation failed");
    }
    if (! entry::pwalletMain->CommitTransaction(wtx, keyChange)) {
        throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");
    }

    return wtx.GetHash().GetHex();
}

json_spirit::Value CRPCTable::addmultisigaddress(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3) {
        throw std::runtime_error(("addmultisigaddress <nrequired> <'[\"key\",\"key\"]'> [account]\n"
            "Add a nrequired-to-sign multisignature address to the wallet\"\n"
            "each key is a " + std::string(strCoinName) + " address or hex-encoded public key\n"
            "If [account] is specified, assign address to [account].").c_str());
    }

    int nRequired = params[0].get_int();
    const json_spirit::Array &keys = params[1].get_array();
    std::string strAccount;
    if (params.size() > 2) {
        strAccount = AccountFromValue(params[2]);
    }

    // Gather public keys
    if (nRequired < 1) {
        throw std::runtime_error("a multisignature address must require at least one key to redeem");
    }
    if ((int)keys.size() < nRequired) {
        throw std::runtime_error(tfm::format("not enough keys supplied (got %" PRIszu " keys, but need at least %d to redeem)", keys.size(), nRequired));
    }
    if (keys.size() > 16) {
        throw std::runtime_error("Number of addresses involved in the multisignature address creation > 16\nReduce the number");
    }

    std::vector<CPubKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); ++i)
    {
        const std::string &ks = keys[i].get_str();

        CBitcoinAddress address(ks);
        if (address.IsValid()) {
            //
            // Case 1: Bitcoin address and we have full public key
            //
            CKeyID keyID;
            if (! address.GetKeyID(keyID)) {
                throw std::runtime_error(tfm::format("%s does not refer to a key",ks.c_str()));
            }

            CPubKey vchPubKey;
            if (! entry::pwalletMain->GetPubKey(keyID, vchPubKey)) {
                throw std::runtime_error(tfm::format("no full public key for address %s",ks.c_str()));
            }

            if (! vchPubKey.IsValid()) {
                throw std::runtime_error(" Invalid public key: "+ks);
            }

            pubkeys[i] = vchPubKey;
        } else if (strenc::IsHex(ks)) {
            //
            // Case 2: hex public key
            //
            CPubKey vchPubKey(strenc::ParseHex(ks));
            if (! vchPubKey.IsValid()) {
                throw std::runtime_error(" Invalid public key: "+ks);
            }
            pubkeys[i] = vchPubKey;
        } else {
            throw std::runtime_error(" Invalid public key: "+ks);
        }
    }

    // Construct using pay-to-script-hash:
    CScript inner;
    inner.SetMultisig(nRequired, pubkeys);

    if (inner.size() > Script_const::MAX_SCRIPT_ELEMENT_SIZE) {
        throw std::runtime_error(tfm::format("redeemScript exceeds size limit: %" PRIszu " > %d", inner.size(), Script_const::MAX_SCRIPT_ELEMENT_SIZE));
    }

    entry::pwalletMain->AddCScript(inner);
    CBitcoinAddress address(inner.GetID());

    entry::pwalletMain->SetAddressBookName(address, strAccount);
    return address.ToString();
}

json_spirit::Value CRPCTable::addredeemscript(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2) {
        throw std::runtime_error("addredeemscript <redeemScript> [account]\n"
            "Add a P2SH address with a specified redeemScript to the wallet.\n"
            "If [account] is specified, assign address to [account].");
    }

    std::string strAccount;
    if (params.size() > 1) {
        strAccount = AccountFromValue(params[1]);
    }

    // Construct using pay-to-script-hash:
    hexrpc_vector innerData = hexrpc::ParseHexV(params[0], "redeemScript");
    CScript inner(innerData.begin(), innerData.end());
    entry::pwalletMain->AddCScript(inner);
    CBitcoinAddress address(inner.GetID());

    entry::pwalletMain->SetAddressBookName(address, strAccount);
    return address.ToString();
}

json_spirit::Value CRPCTable::ListReceived(const json_spirit::Array &params, bool fByAccounts)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 0) {
        nMinDepth = params[0].get_int();
    }

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (params.size() > 1) {
        fIncludeEmpty = params[1].get_bool();
    }

    // Tally
    std::map<CBitcoinAddress, tallyitem> mapTally;
    for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx &wtx = (*it).second;

        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !wtx.IsFinal()) {
            continue;
        }

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth) {
            continue;
        }

        for(const CTxOut &txout: wtx.get_vout())
        {
            CTxDestination address;
            if (!Script_util::ExtractDestination(txout.get_scriptPubKey(), address) || !Script_util::IsMine(*entry::pwalletMain, address)) {
                continue;
            }

            tallyitem& item = mapTally[address];
            item.nAmount += txout.get_nValue();
            item.nConf = std::min(item.nConf, nDepth);
        }
    }

    // Reply
    json_spirit::Array ret;
    std::map<std::string, tallyitem> mapAccountTally;
    for(const std::pair<CBitcoinAddress, std::string>&item: entry::pwalletMain->mapAddressBook)
    {
        const CBitcoinAddress &address = item.first;
        const std::string &strAccount = item.second;
        std::map<CBitcoinAddress, tallyitem>::iterator it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty) {
            continue;
        }

        int64_t nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        if (it != mapTally.end()) {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
        }

        if (fByAccounts) {
            tallyitem& item = mapAccountTally[strAccount];
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
        for (std::map<std::string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it)
        {
            int64_t nAmount = (*it).second.nAmount;
            int nConf = (*it).second.nConf;

            json_spirit::Object obj;
            obj.push_back(json_spirit::Pair("account",       (*it).first));
            obj.push_back(json_spirit::Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(json_spirit::Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            ret.push_back(obj);
        }
    }

    return ret;
}

json_spirit::Value CRPCTable::listreceivedbyaddress(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 2) {
        throw std::runtime_error(
            "listreceivedbyaddress [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include addresses that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"address\" : receiving address\n"
            "  \"account\" : the account of the receiving address\n"
            "  \"amount\" : total amount received by the address\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");
    }

    return ListReceived(params, false);
}

json_spirit::Value CRPCTable::listreceivedbyaccount(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 2) {
        throw std::runtime_error(
            "listreceivedbyaccount [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include accounts that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"account\" : the account of the receiving addresses\n"
            "  \"amount\" : total amount received by addresses with this account\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");
    }

    return ListReceived(params, true);
}

void CRPCTable::MaybePushAddress(json_spirit::Object &entry, const CBitcoinAddress &dest)
{
    entry.push_back(json_spirit::Pair("address", dest.ToString()));
}

void CRPCTable::ListTransactions(const CWalletTx &wtx, const std::string &strAccount, int nMinDepth, bool fLong, json_spirit::Array &ret, const isminefilter &filter)
{
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
        if (fLong) {
            WalletTxToJSON(wtx, entry);
        }
        ret.push_back(entry);
    }

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount)) {
        for(const std::pair<CBitcoinAddress, int64_t>&s: listSent)
        {
            json_spirit::Object entry;
            entry.push_back(json_spirit::Pair("account", strSentAccount));
            //if(involvesWatchonly || (::IsMine(*entry::pwalletMain, s.first) & MINE_WATCH_ONLY)) {
            if(involvesWatchonly || (Script_util::IsMine(*entry::pwalletMain, s.first) & MINE_WATCH_ONLY)) {
                entry.push_back(json_spirit::Pair("involvesWatchonly", true));
            }
            MaybePushAddress(entry, s.first);

            if (wtx.GetDepthInMainChain() < 0) {
                entry.push_back(json_spirit::Pair("category", "conflicted"));
            } else {
                entry.push_back(json_spirit::Pair("category", "send"));
            }

            entry.push_back(json_spirit::Pair("amount", ValueFromAmount(-s.second)));
            entry.push_back(json_spirit::Pair("fee", ValueFromAmount(-nFee)));
            if (fLong) {
                WalletTxToJSON(wtx, entry);
            }
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth) {
        for(const std::pair<CBitcoinAddress, int64_t>&r: listReceived)
        {
            std::string account;
            if (entry::pwalletMain->mapAddressBook.count(r.first)) {
                account = entry::pwalletMain->mapAddressBook[r.first];
            }
            if (fAllAccounts || (account == strAccount)) {
                json_spirit::Object entry;
                entry.push_back(json_spirit::Pair("account", account));
                // if(involvesWatchonly || (::IsMine(*entry::pwalletMain, r.first) & MINE_WATCH_ONLY)) {
                if(involvesWatchonly || (Script_util::IsMine(*entry::pwalletMain, r.first) & MINE_WATCH_ONLY)) {
                    entry.push_back(json_spirit::Pair("involvesWatchonly", true));
                }
                MaybePushAddress(entry, r.first);

                if (wtx.IsCoinBase()) {
                    if (wtx.GetDepthInMainChain() < 1) {
                        entry.push_back(json_spirit::Pair("category", "orphan"));
                    } else if (wtx.GetBlocksToMaturity() > 0) {
                        entry.push_back(json_spirit::Pair("category", "immature"));
                    } else {
                        entry.push_back(json_spirit::Pair("category", "generate"));
                    }
                } else {
                    entry.push_back(json_spirit::Pair("category", "receive"));
                }

                entry.push_back(json_spirit::Pair("amount", ValueFromAmount(r.second)));
                if (fLong) {
                    WalletTxToJSON(wtx, entry);
                }
                ret.push_back(entry);
            }
        }
    }
}

void CRPCTable::AcentryToJSON(const CAccountingEntry &acentry, const std::string &strAccount, json_spirit::Array &ret)
{
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

json_spirit::Value CRPCTable::listtransactions(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 3) {
        throw std::runtime_error(
            "listtransactions [account] [count=10] [from=0]\n"
            "Returns up to [count] most recent transactions skipping the first [from] transactions for account [account].");
    }

    std::string strAccount = "*";
    if (params.size() > 0) {
        strAccount = params[0].get_str();
    }

    int nCount = 10;
    if (params.size() > 1) {
        nCount = params[1].get_int();
    }

    int nFrom = 0;
    if (params.size() > 2) {
        nFrom = params[2].get_int();
    }

    isminefilter filter = MINE_SPENDABLE;
    if(params.size() > 3) {
        if(params[3].get_bool()) {
            filter = filter | MINE_WATCH_ONLY;
        }
    }

    if (nCount < 0) {
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    }
    if (nFrom < 0) {
        throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");
    }

    json_spirit::Array ret;

    std::list<CAccountingEntry> acentries;
    CWallet::TxItems txOrdered = entry::pwalletMain->OrderedTxItems(acentries, strAccount);

    // iterate backwards until we have nCount items to return:
    for (CWallet::TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0) {
            ListTransactions(*pwtx, strAccount, 0, true, ret, filter);
        }

        CAccountingEntry *const pacentry = (*it).second.second;
        if (pacentry != 0) {
            AcentryToJSON(*pacentry, strAccount, ret);
        }

        if ((int)ret.size() >= (nCount+nFrom)) {
            break;
        }
    }
    // ret is newest to oldest

    if (nFrom > (int)ret.size()) {
        nFrom = ret.size();
    }
    if ((nFrom + nCount) > (int)ret.size()) {
        nCount = ret.size() - nFrom;
    }

    json_spirit::Array::iterator first = ret.begin();
    std::advance(first, nFrom);
    json_spirit::Array::iterator last = ret.begin();
    std::advance(last, nFrom+nCount);

    if (last != ret.end()) {
        ret.erase(last, ret.end());
    }
    if (first != ret.begin()) {
        ret.erase(ret.begin(), first);
    }

    std::reverse(ret.begin(), ret.end()); // Return oldest to newest

    return ret;
}

json_spirit::Value CRPCTable::listaccounts(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "listaccounts [minconf=1]\n"
            "Returns Object that has account names as keys, account balances as values.");
    }

    int nMinDepth = 1;
    if (params.size() > 0) {
        nMinDepth = params[0].get_int();
    }

    isminefilter includeWatchonly = MINE_SPENDABLE;
    if(params.size() > 1) {
        if(params[1].get_bool()) {
            includeWatchonly = includeWatchonly | MINE_WATCH_ONLY;
        }
    }

    std::map<std::string, int64_t> mapAccountBalances;
    for(const std::pair<CBitcoinAddress, std::string>&entry: entry::pwalletMain->mapAddressBook)
    {
        if (Script_util::IsMine(*entry::pwalletMain, entry.first)) {    // This address belongs to me
            mapAccountBalances[entry.second] = 0;
        }
    }

    for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        int64_t nGeneratedImmature, nGeneratedMature, nFee;
        std::string strSentAccount;
        std::list<std::pair<CBitcoinAddress, int64_t> > listReceived;
        std::list<std::pair<CBitcoinAddress, int64_t> > listSent;
        wtx.GetAmounts(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount, includeWatchonly);
        mapAccountBalances[strSentAccount] -= nFee;
        for(const std::pair<CBitcoinAddress, int64_t>&s: listSent)
        {
            mapAccountBalances[strSentAccount] -= s.second;
        }

        if (wtx.GetDepthInMainChain() >= nMinDepth) {
            mapAccountBalances[""] += nGeneratedMature;
            for(const std::pair<CBitcoinAddress, int64_t>&r: listReceived)
            {
                if (entry::pwalletMain->mapAddressBook.count(r.first)) {
                    mapAccountBalances[entry::pwalletMain->mapAddressBook[r.first]] += r.second;
                } else {
                    mapAccountBalances[""] += r.second;
                }
            }
        }
    }

    std::list<CAccountingEntry> acentries;
    //CWalletDB(entry::pwalletMain->strWalletFile).ListAccountCreditDebit("*", acentries);
    CWalletDB(entry::pwalletMain->strWalletFile, entry::pwalletMain->strWalletLevelDB, entry::pwalletMain->strWalletSqlFile).ListAccountCreditDebit("*", acentries);
    for(const CAccountingEntry &entry: acentries)
    {
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;
    }

    json_spirit::Object ret;
    for(const std::pair<std::string, int64_t>&accountBalance: mapAccountBalances)
    {
        ret.push_back(json_spirit::Pair(accountBalance.first, ValueFromAmount(accountBalance.second)));
    }
    return ret;
}

json_spirit::Value CRPCTable::listsinceblock(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp) {
        throw std::runtime_error(
            "listsinceblock [blockhash] [target-confirmations]\n"
            "Get all transactions in blocks since block [blockhash], or all transactions if omitted");
    }

    CBlockIndex *pindex = nullptr;
    int target_confirms = 1;
    isminefilter filter = MINE_SPENDABLE;

    if (params.size() > 0) {
        uint256 blockId = 0;

        blockId.SetHex(params[0].get_str());
        pindex = CBlockLocator(blockId).GetBlockIndex();
    }

    if (params.size() > 1) {
        target_confirms = params[1].get_int();

        if (target_confirms < 1) {
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        }
    }

    if(params.size() > 2) {
        if(params[2].get_bool()) {
            filter = filter | MINE_WATCH_ONLY;
        }
    }

    int depth = pindex ? (1 + block_info::nBestHeight - pindex->get_nHeight()) : -1;

    json_spirit::Array transactions;

    for (std::map<uint256, CWalletTx>::iterator it = entry::pwalletMain->mapWallet.begin(); it != entry::pwalletMain->mapWallet.end(); it++)
    {
        CWalletTx tx = (*it).second;

        if (depth == -1 || tx.GetDepthInMainChain() < depth) {
            ListTransactions(tx, "*", 0, true, transactions, filter);
        }
    }

    uint256 lastblock;

    if (target_confirms == 1) {
        lastblock = block_info::hashBestChain;
    } else {
        int target_height = block_info::pindexBest->get_nHeight() + 1 - target_confirms;

        CBlockIndex *block;
        for (block = block_info::pindexBest; block && block->get_nHeight() > target_height; block = block->set_pprev()) {}

        lastblock = block ? block->GetBlockHash() : 0;
    }

    json_spirit::Object ret;
    ret.push_back(json_spirit::Pair("transactions", transactions));
    ret.push_back(json_spirit::Pair("lastblock", lastblock.GetHex()));

    return ret;
}

json_spirit::Value CRPCTable::gettransaction(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            "gettransaction <txid>\n"
            "Get detailed information about <txid>");
    }

    uint256 hash;
    hash.SetHex(params[0].get_str());

    isminefilter filter = MINE_SPENDABLE;
    if(params.size() > 1) {
        if(params[1].get_bool()) {
            filter = filter | MINE_WATCH_ONLY;
        }
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
        if (wtx.IsFromMe(filter)) {
            entry.push_back(json_spirit::Pair("fee", ValueFromAmount(nFee)));
        }

        WalletTxToJSON(wtx, entry);

        json_spirit::Array details;
        ListTransactions(entry::pwalletMain->mapWallet[hash], "*", 0, false, details, filter);
        entry.push_back(json_spirit::Pair("details", details));
    } else {
        CTransaction tx;
        uint256 hashBlock = 0;
        if (block_transaction::manage::GetTransaction(hash, tx, hashBlock)) {
            TxToJSON(tx, 0, entry);
            if (hashBlock == 0) {
                entry.push_back(json_spirit::Pair("confirmations", 0));
            } else {
                entry.push_back(json_spirit::Pair("blockhash", hashBlock.GetHex()));
                auto mi = block_info::mapBlockIndex.find(hashBlock);
                if (mi != block_info::mapBlockIndex.end() && (*mi).second) {
                    CBlockIndex* pindex = (*mi).second;
                    if (pindex->IsInMainChain()) {
                        entry.push_back(json_spirit::Pair("confirmations", 1 + block_info::nBestHeight - pindex->get_nHeight()));
                    } else {
                        entry.push_back(json_spirit::Pair("confirmations", 0));
                    }
                }
            }
        } else {
            throw bitjson::JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");
        }
    }

    return entry;
}


json_spirit::Value CRPCTable::backupwallet(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            "backupwallet <destination>\n"
            "Safely copies wallet.dat to destination, which can be a directory or a path with filename.");
    }

    std::string strDest = params[0].get_str();
    if (! wallet_dispatch::BackupWallet(*entry::pwalletMain, strDest)) {
        throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");
    }
    return json_spirit::Value::null;
}


json_spirit::Value CRPCTable::keypoolrefill(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "keypoolrefill [new-size]\n"
            "Fills the keypool.\n"
            "IMPORTANT: Any previous backups you have made of your wallet file "
            "should be replaced with the newly generated one."
            + HelpRequiringPassphrase());
    }

    unsigned int nSize = std::max<unsigned int>(map_arg::GetArgUInt("-keypool", 100), 0);
    if (params.size() > 0) {
        if (params[0].get_int() < 0) {
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size");
        }
        nSize = (unsigned int) params[0].get_int();
    }

    EnsureWalletIsUnlocked();

    entry::pwalletMain->TopUpKeyPool(nSize);

    if (entry::pwalletMain->GetKeyPoolSize() < nSize) {
        throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");
    }

    return json_spirit::Value::null;
}

json_spirit::Value CRPCTable::keypoolreset(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "keypoolreset [new-size]\n"
            "Resets the keypool.\n"
            "IMPORTANT: Any previous backups you have made of your wallet file "
            "should be replaced with the newly generated one."
            + HelpRequiringPassphrase());
    }

    unsigned int nSize = std::max<unsigned int>(map_arg::GetArgUInt("-keypool", 100), 0);
    if (params.size() > 0) {
        if (params[0].get_int() < 0) {
            throw bitjson::JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size");
        }
        nSize = (unsigned int) params[0].get_int();
    }

    EnsureWalletIsUnlocked();

    entry::pwalletMain->NewKeyPool(nSize);

    if (entry::pwalletMain->GetKeyPoolSize() < nSize) {
        throw bitjson::JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");
    }

    return json_spirit::Value::null;
}

void CRPCTable::ThreadTopUpKeyPool(void *parg)
{
    // Make this thread recognisable as the key-topping-up thread
    bitthread::RenameThread((std::string(strCoinName) + "-key-top").c_str());

    entry::pwalletMain->TopUpKeyPool();
}

void CRPCTable::ThreadCleanWalletPassphrase(void *parg)
{
    //
    // Make this thread recognisable as the wallet relocking thread
    // parg: int64_t *, dynamic object
    //
    bitthread::RenameThread((std::string(strCoinName) + "-lock-wa").c_str());

    int64_t nMyWakeTime = util::GetTimeMillis() + *((int64_t *)parg) * 1000;

    ENTER_CRITICAL_SECTION(cs_nWalletUnlockTime);

    if (nWalletUnlockTime == 0) {
        nWalletUnlockTime = nMyWakeTime;

        for ( ; ; )
        {
            if (nWalletUnlockTime == 0) {
                break;
            }

            int64_t nToSleep = nWalletUnlockTime - util::GetTimeMillis();
            if (nToSleep <= 0) {
                break;
            }

            LEAVE_CRITICAL_SECTION(cs_nWalletUnlockTime);
            util::Sleep(nToSleep);
            ENTER_CRITICAL_SECTION(cs_nWalletUnlockTime);
        };

        if (nWalletUnlockTime) {
            nWalletUnlockTime = 0;
            entry::pwalletMain->Lock();
        }
    } else {
        if (nWalletUnlockTime < nMyWakeTime) {
            nWalletUnlockTime = nMyWakeTime;
        }
    }

    LEAVE_CRITICAL_SECTION(cs_nWalletUnlockTime);
    delete (int64_t*)parg;
}

json_spirit::Value CRPCTable::walletpassphrase(const json_spirit::Array &params, bool fHelp)
{
    if (entry::pwalletMain->IsCrypted() && (fHelp || params.size() < 2 || params.size() > 3)) {
        throw std::runtime_error(
            "walletpassphrase <passphrase> <timeout> [mintonly]\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.\n"
            "mintonly is optional true/false allowing only block minting.");
    }
    if (fHelp) {
        return true;
    }
    if (! entry::pwalletMain->IsCrypted()) {
        throw bitjson::JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");
    }

    if (! entry::pwalletMain->IsLocked()) {
        throw bitjson::JSONRPCError(RPC_WALLET_ALREADY_UNLOCKED, "Error: Wallet is already unlocked, use walletlock first if need to change unlock settings.");
    }

    //
    // Note that the walletpassphrase is stored in params[0] which is not mlock()'d
    //
    SecureString strWalletPass;
    strWalletPass.reserve(100);

    strWalletPass(const_cast<std::string &>(params[0].get_str()));

    if (strWalletPass.length() > 0) {
        if (! entry::pwalletMain->Unlock(strWalletPass)) {
            throw bitjson::JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
        }
    } else {
        throw std::runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");
    }

    if(! bitthread::NewThread(ThreadTopUpKeyPool, nullptr))
        throw std::runtime_error("walletpassphrase begin thread failure.");

    int64_t *pnSleepTime = new(std::nothrow) int64_t(params[1].get_int64());
    if(pnSleepTime == nullptr) {
        throw std::runtime_error("walletpassphrase memory allocate failure.");
    }

    if(! bitthread::NewThread(ThreadCleanWalletPassphrase, pnSleepTime))    // this thread, delete pnSleepTime.
        throw std::runtime_error("walletpassphrase begin thread failure.");

    // ppcoin: if user OS account compromised prevent trivial sendmoney commands
    if (params.size() > 2) {
        CWallet::fWalletUnlockMintOnly = params[2].get_bool();
    } else {
        CWallet::fWalletUnlockMintOnly = false;
    }

    return json_spirit::Value::null;
}

json_spirit::Value CRPCTable::walletpassphrasechange(const json_spirit::Array &params, bool fHelp)
{
    if (entry::pwalletMain->IsCrypted() && (fHelp || params.size() != 2)) {
        throw std::runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");
    }
    if (fHelp) {
        return true;
    }
    if (! entry::pwalletMain->IsCrypted()) {
        throw bitjson::JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");
    }

    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass(const_cast<std::string &>(params[0].get_str()));

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass(const_cast<std::string &>(params[1].get_str()));

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1) {
        throw std::runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");
    }

    if (! entry::pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass)) {
        throw bitjson::JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }

    return json_spirit::Value::null;
}

json_spirit::Value CRPCTable::walletlock(const json_spirit::Array &params, bool fHelp)
{
    if (entry::pwalletMain->IsCrypted() && (fHelp || params.size() != 0)) {
        throw std::runtime_error(
            "walletlock\n"
            "Removes the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.");
    }
    if (fHelp) {
        return true;
    }
    if (! entry::pwalletMain->IsCrypted()) {
        throw bitjson::JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");
    }

    {
        LOCK(cs_nWalletUnlockTime);
        entry::pwalletMain->Lock();
        nWalletUnlockTime = 0;
    }

    return json_spirit::Value::null;
}

json_spirit::Value CRPCTable::encryptwallet(const json_spirit::Array &params, bool fHelp)
{
    if (!entry::pwalletMain->IsCrypted() && (fHelp || params.size() != 1)) {
        throw std::runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");
    }
    if (fHelp) {
        return true;
    }
    if (entry::pwalletMain->IsCrypted()) {
        throw bitjson::JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");
    }

    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass(const_cast<std::string &>(params[0].get_str()));

    if (strWalletPass.length() < 1) {
        throw std::runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");
    }

    if (! entry::pwalletMain->EncryptWallet(strWalletPass)) {
        throw bitjson::JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");
    }

#ifdef WALLET_SQL_MODE
    return json_spirit::Value::null;
#else
    //
    // BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys. So:
    //
    boot::StartShutdown();
    return (std::string(strCoinName) + " wallet encrypted; server stopping, restart to run with encrypted wallet.  The keypool has been flushed, you need to make a new backup.").c_str();
#endif
}

class DescribeAddressVisitor : public boost::static_visitor<json_spirit::Object>
{
private:
    DescribeAddressVisitor(const DescribeAddressVisitor &)=delete;
    DescribeAddressVisitor &operator=(const DescribeAddressVisitor &)=delete;

    isminetype mine;
public:
    DescribeAddressVisitor(isminetype mineIn) : mine(mineIn) {}

    json_spirit::Object operator()(const CNoDestination &dest) const {
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
            {
                a.push_back(CBitcoinAddress(addr).ToString());
            }
            obj.push_back(json_spirit::Pair("addresses", a));
            if (whichType == TxnOutputType::TX_MULTISIG) {
                obj.push_back(json_spirit::Pair("sigsrequired", nRequired));
            }
        }
        return obj;
    }

    json_spirit::Object operator()(const WitnessV0ScriptHash &dest) const {return json_spirit::Object();}

    json_spirit::Object operator()(const WitnessV0KeyHash &dest) const {return json_spirit::Object();}

    json_spirit::Object operator()(const WitnessUnknown &dest) const {return json_spirit::Object();}
};

json_spirit::Value CRPCTable::validateaddress(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 1) {
        throw std::runtime_error(
            "validateaddress <coinaddress>\n"
            "Return information about <coinaddress>.");
    }

    CBitcoinAddress address(params[0].get_str());
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

            if (isMine) {
                ret.push_back(json_spirit::Pair("KeyView", view.ToString()));
            }
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
            if (entry::pwalletMain->mapAddressBook.count(address)) {
                ret.push_back(json_spirit::Pair("account", entry::pwalletMain->mapAddressBook[address]));
            }
        }
    }
    return ret;
}

//
// ppcoin: reserve balance from being staked for network protection
//
json_spirit::Value CRPCTable::reservebalance(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 2) {
        throw std::runtime_error(
            "reservebalance [<reserve> [amount]]\n"
            "<reserve> is true or false to turn balance reserve on or off.\n"
            "<amount> is a real and rounded to cent.\n"
            "Set reserve amount not participating in network protection.\n"
            "If no parameters provided current setting is printed.\n");
    }

    if (params.size() > 0) {
        bool fReserve = params[0].get_bool();
        if (fReserve) {
            if (params.size() == 1) {
                throw std::runtime_error("must provide amount to reserve balance.\n");
            }

            int64_t nAmount = AmountFromValue(params[1]);
            nAmount = (nAmount / util::CENT) * util::CENT;  // round to cent
            if (nAmount < 0) {
                throw std::runtime_error("amount cannot be negative.\n");
            }

            map_arg::SetMapArgsString("-reservebalance", strenc::FormatMoney(nAmount));
        } else {
            if (params.size() > 1) {
                throw std::runtime_error("cannot specify amount to turn off reserve.\n");
            }

            map_arg::SetMapArgsString("-reservebalance", "0");
        }
    }

    json_spirit::Object result;
    if (map_arg::GetMapArgsCount("-reservebalance") && !strenc::ParseMoney(map_arg::GetMapArgsString("-reservebalance").c_str(), miner::nReserveBalance)) {
        throw std::runtime_error("invalid reserve balance amount\n");
    }

    result.push_back(json_spirit::Pair("reserve", (miner::nReserveBalance > 0)));
    result.push_back(json_spirit::Pair("amount", ValueFromAmount(miner::nReserveBalance)));
    return result;
}

//
// ppcoin: check wallet integrity
//
json_spirit::Value CRPCTable::checkwallet(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 0) {
        throw std::runtime_error(
            "checkwallet\n"
            "Check wallet for integrity.\n");
    }

    int nMismatchSpent;
    int64_t nBalanceInQuestion;
    entry::pwalletMain->FixSpentCoins(nMismatchSpent, nBalanceInQuestion, true);
    json_spirit::Object result;
    if (nMismatchSpent == 0) {
        result.push_back(json_spirit::Pair("wallet check passed", true));
    } else {
        result.push_back(json_spirit::Pair("mismatched spent coins", nMismatchSpent));
        result.push_back(json_spirit::Pair("amount in question", ValueFromAmount(nBalanceInQuestion)));
    }
    return result;
}

//
// ppcoin: repair wallet
//
json_spirit::Value CRPCTable::repairwallet(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 0) {
        throw std::runtime_error(
            "repairwallet\n"
            "Repair wallet if checkwallet reports any problem.\n");
    }

    int nMismatchSpent;
    int64_t nBalanceInQuestion;
    entry::pwalletMain->FixSpentCoins(nMismatchSpent, nBalanceInQuestion);
    json_spirit::Object result;
    if (nMismatchSpent == 0) {
        result.push_back(json_spirit::Pair("wallet check passed", true));
    } else {
        result.push_back(json_spirit::Pair("mismatched spent coins", nMismatchSpent));
        result.push_back(json_spirit::Pair("amount affected by repair", ValueFromAmount(nBalanceInQuestion)));
    }
    return result;
}

//
// ppcoin: resend unconfirmed wallet transactions
//
json_spirit::Value CRPCTable::resendtx(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "resendtx\n"
            "Re-send unconfirmed transactions.\n");
    }
    block_process::manage::ResendWalletTransactions(true);
    return json_spirit::Value::null;
}

json_spirit::Value CRPCTable::resendwallettransactions(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 0) {
        throw std::runtime_error(
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
    {
        result.push_back(txid.ToString());
    }
    return result;
}

//
// Make a public-private key pair
//
json_spirit::Value CRPCTable::makekeypair(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 0) {
        throw std::runtime_error(
            "makekeypair\n"
            "Make a public/private key pair.\n");
    }

    std::string strPrefix = "";
    if (params.size() > 0) {
        strPrefix = params[0].get_str();
    }

    CFirmKey key;
    key.MakeNewKey(true);

    CPrivKey vchPrivKey = key.GetPrivKey();
    json_spirit::Object result;
    result.push_back(json_spirit::Pair("PrivateKey", util::HexStr<CPrivKey::iterator>(vchPrivKey.begin(), vchPrivKey.end())));

    bool fCompressed;
    CSecret vchSecret = key.GetSecret(fCompressed);
    CPubKey vchPubKey = key.GetPubKey();
    result.push_back(json_spirit::Pair("Secret", util::HexStr<CSecret::iterator>(vchSecret.begin(), vchSecret.end())));
    result.push_back(json_spirit::Pair("PublicKey", util::HexStr(vchPubKey.begin(), vchPubKey.end())));
    return result;
}

json_spirit::Value CRPCTable::newmalleablekey(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 1) {
        throw std::runtime_error(
            "newmalleablekey\n"
            "Make a malleable public/private key pair.\n");
    }

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount;
    if (params.size() > 0) {
        strAccount = AccountFromValue(params[0]);
    }

    CMalleableKeyView keyView = entry::pwalletMain->GenerateNewMalleableKey();

    CMalleableKey mKey;
    if (! entry::pwalletMain->GetMalleableKey(keyView, mKey)) {
        throw std::runtime_error("Unable to generate new malleable key");
    }

    CMalleablePubKey mPubKey = mKey.GetMalleablePubKey();
    CBitcoinAddress address(mPubKey);

    entry::pwalletMain->SetAddressBookName(address, strAccount);

    json_spirit::Object result;
    result.push_back(json_spirit::Pair("PublicPair", mPubKey.ToString()));
    result.push_back(json_spirit::Pair("PublicBytes", util::HexStr(mPubKey.Raw())));
    result.push_back(json_spirit::Pair("Address", address.ToString()));
    result.push_back(json_spirit::Pair("KeyView", keyView.ToString()));

    return result;
}

json_spirit::Value CRPCTable::adjustmalleablekey(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 3) {
        throw std::runtime_error(
            "adjustmalleablekey <Malleable key data> <Public key variant data> <R data>\n"
            "Calculate new private key using provided malleable key, public key and R data.\n");
    }

    CMalleableKey malleableKey;
    malleableKey.SetString(params[0].get_str());

    CFirmKey privKeyVariant;
    CPubKey vchPubKeyVariant = CPubKey(strenc::ParseHex(params[1].get_str()));

    CPubKey R(strenc::ParseHex(params[2].get_str()));

    if (! malleableKey.CheckKeyVariant(R,vchPubKeyVariant, privKeyVariant)) {
        throw std::runtime_error("Unable to calculate the private key");
    }

    json_spirit::Object result;
    bool fCompressed;
    CSecret vchPrivKeyVariant = privKeyVariant.GetSecret(fCompressed);

    result.push_back(json_spirit::Pair("PrivateKey", CBitcoinSecret(vchPrivKeyVariant, fCompressed).ToString()));

    return result;
}

json_spirit::Value CRPCTable::adjustmalleablepubkey(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() > 2 || params.size() == 0) {
        throw std::runtime_error(
            "adjustmalleablepubkey <Malleable address, key view or public key pair>\n"
            "Calculate new public key using provided data.\n");
    }

    std::string strData = params[0].get_str();
    CMalleablePubKey malleablePubKey;

    do
    {
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
        if (malleablePubKey.SetString(strData)) {
            break; // A valid public key pair
        }

        throw std::runtime_error("Though your data seems a valid Base58 string, we were unable to recognize it.");
    } while(false);

    CPubKey R, vchPubKeyVariant;
    malleablePubKey.GetVariant(R, vchPubKeyVariant);

    json_spirit::Object result;
    result.push_back(json_spirit::Pair("R", util::HexStr(R.begin(), R.end())));
    result.push_back(json_spirit::Pair("PubkeyVariant", util::HexStr(vchPubKeyVariant.begin(), vchPubKeyVariant.end())));
    result.push_back(json_spirit::Pair("KeyVariantID", CBitcoinAddress(vchPubKeyVariant.GetID()).ToString()));

    return result;
}

json_spirit::Value CRPCTable::listmalleableviews(const json_spirit::Array &params, bool fHelp)
{
    if (fHelp || params.size() != 0) {
        throw std::runtime_error(
            "listmalleableviews\n"
            "Get list of views for generated malleable keys.\n");
    }

    std::list<CMalleableKeyView> keyViewList;
    entry::pwalletMain->ListMalleableViews(keyViewList);

    json_spirit::Array result;
    for(const CMalleableKeyView &keyView: keyViewList)
    {
        result.push_back(keyView.ToString());
    }

    return result;
}
