// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sorara/aitx.h>
#include <crypto/aes.h>
#include <hash.h>
#include <util/time.h>
#include <init.h>
#include <ctime>

namespace {

constexpr static int HASH160_DIGEST_LENGTH = sizeof(uint160);

// Function to build the Merkle tree and compute the Merkle root
void hash160_get_merkle_root(uint160 &merkle_root, const std::vector<uint160> &vhashes) {
    auto compute_hash160 = [](const unsigned char *data, size_t len, unsigned char *hash) {
        latest_crypto::CHash160().Write(data, len).Finalize(hash);
    };

    if (vhashes.size() == 0) {
        merkle_root = uint160(0);
        return;
    }
    size_t num_hashes = vhashes.size();

    // Copy the current level's hashes
    std::vector<uint160> current_level;
    current_level.resize(num_hashes);
    for (size_t i = 0; i < num_hashes; i++)
        ::memcpy(current_level[i].begin(), vhashes[i].begin(), HASH160_DIGEST_LENGTH);

    // Build the Merkle tree
    while (num_hashes > 1) {
        size_t new_num_hashes = (num_hashes + 1) / 2;
        std::vector<uint160> next_level;
        next_level.resize(new_num_hashes);
        for (size_t i = 0; i < new_num_hashes; i++) {
            if (2 * i + 1 < num_hashes) {
                // Combine two child hashes and compute the parent hash
                unsigned char combined[2 * HASH160_DIGEST_LENGTH];
                ::memcpy(combined, current_level[2 * i].begin(), HASH160_DIGEST_LENGTH);
                ::memcpy(combined + HASH160_DIGEST_LENGTH, current_level[2 * i + 1].begin(), HASH160_DIGEST_LENGTH);
                compute_hash160(combined, 2 * HASH160_DIGEST_LENGTH, next_level[i].begin());
            } else {
                // Odd number of hashes, so copy the last hash
                ::memcpy(next_level[i].begin(), current_level[2 * i].begin(), HASH160_DIGEST_LENGTH);
            }
        }

        // Move to the next level
        current_level.clear();
        current_level = std::move(next_level);
        num_hashes = new_num_hashes;
    }

    // The root hash is the only hash in the final level
    ::memcpy(merkle_root.begin(), current_level[0].begin(), HASH160_DIGEST_LENGTH);
}

} // namespace

bool CAIToken03::IsValid() const {
    return crypto.size() > 0;
}

bool CAIToken03::SetTokenMessage(const SymmetricKey &key, const SecureString &message) {
    std::pair<CSecureBytes, bool> cipher;
    latest_crypto::CAES256CBCPKCS7(key.data(), key.size()).Encrypt((const unsigned char *)message.data(), message.size()).Finalize(cipher);
    if(!cipher.second)
        return false;
    crypto = std::move(cipher.first);
    return true;
}

bool CAIToken03::GetTokenMessage(const SymmetricKey &key, SecureString &message) const {
    if(crypto.size() == 0)
        return false;
    std::pair<CSecureBytes, bool> plain;
    latest_crypto::CAES256CBCPKCS7(key.data(), key.size()).Decrypt(crypto.data(), crypto.size()).Finalize(plain);
    if(!plain.second)
        return false;
    message.clear();
    message.shrink_to_fit();
    //message.insert(message.end(), plain.first.begin(), plain.first.end());
    message.insert(0, (const char *)plain.first.data(), plain.first.size());
    return true;
}

std::pair<uint160, bool> CAIToken03::GetHash() const {
    if(crypto.size() == 0)
        return std::make_pair(uint160(0), false);
    uint160 hash;
    latest_crypto::CHash160().Write(crypto.data(), crypto.size()).Finalize(hash.begin());
    return std::make_pair(hash, true);
}

bool CAITransaction::IsValid() const {
    return hashes.size() > 0 && nTime != 0 && schnorrsigHash != CKeyID(0);
}

void CAITransaction::PushTokenHash(uint160 hash) {
    hashes.emplace_back(hash);
}

void CAITransaction::SetSchnorrAggregateKeyID(const XOnlyPubKey &xonly_pubkey) {
    nTime = bitsystem::GetAdjustedTime();
    schnorrsigHash = xonly_pubkey.GetID();
}

CKeyID CAITransaction::GetID() const {
    return schnorrsigHash;
}

void CAITransaction::ClearTx() {
    nTime = 0;
    schnorrsigHash = CKeyID(0);
    hashes.clear();
}

std::pair<uint160, bool> CAITransaction::GetMerkleRoot() const {
    if(!IsValid())
        return std::make_pair(uint160(0), false);
    std::vector<uint160> target = hashes;
    target.push_back(schnorrsigHash);
    uint160 merkle_root;
    hash160_get_merkle_root(merkle_root, target);
    return std::make_pair(merkle_root, true);
}

std::pair<qkey_vector, bool> CAITransaction::GetSchnorrHash() const {
    qkey_vector buf;
    buf.resize(33); // size is CPubKey::COMPRESSED_PUBLIC_KEY_SIZE
    ::memset(&buf.front(), 0xFF, 33);
    buf[0] = 0x02;
    buf[1] = qaiVersion;
    std::pair<uint160, bool> merkle_root = GetMerkleRoot();
    if(!merkle_root.second)
        return std::make_pair(qkey_vector(), false);
    ::memcpy(&buf[2], merkle_root.first.begin(), 20);
    return std::make_pair(buf, true);
}

bool CAITransaction03::IsValid() const {
    return aitx.IsValid();
}

bool CAITransaction03::PushTokenMessage(const SymmetricKey &key, const SecureString &message) {
    CAIToken03 token;
    if(!token.SetTokenMessage(key, message))
        return false;
    std::pair<uint160, bool> hash = token.GetHash();
    if(!hash.second)
        return false;
    aitx.PushTokenHash(hash.first);
    tokens.emplace_back(token);
    return true;
}

void CAITransaction03::SetSchnorrAggregateKeyID(const XOnlyPubKey &xonly_pubkey) {
    aitx.SetSchnorrAggregateKeyID(xonly_pubkey);
}

void CAITransaction03::ClearTokens() {
    tokens.clear();
    aitx.ClearTx();
}

uint32_t CAITransaction03::SizeTokens() const {
    return tokens.size();
}

const CAIToken03 &CAITransaction03::operator[](uint32_t index) const {
    return tokens.at(index);
}

CAIToken03 *CAITransaction03::begin() {
    return &tokens[0];
}

CAIToken03 *CAITransaction03::end() {
    return &tokens[0] + tokens.size();
}

const CAIToken03 *CAITransaction03::begin() const {
    return &tokens[0];
}

const CAIToken03 *CAITransaction03::end() const {
    return &tokens[0] + tokens.size();
}

std::pair<uint160, bool> CAITransaction03::GetMerkleRoot() const {
    return aitx.GetMerkleRoot();
}

std::pair<qkey_vector, bool> CAITransaction03::GetSchnorrHash() const {
    return aitx.GetSchnorrHash();
}

CKeyID CAITransaction03::GetID() const {
    return aitx.GetID();
}

//#ifdef QT_GUI
//# include <QMessageBox>
//#endif
namespace aitx_thread {

#if defined(QT_GUI) && defined(WIN32)
class QMB
{
public:
    enum status {
        M_OK,
        M_ERROR
    };

    QMB() = delete;
    QMB(status s) {
        if(s == M_OK) {
            title = "Confirmation";
            icon = MB_ICONINFORMATION;
        } else if (s == M_ERROR) {
            title = "Error";
            icon = MB_ICONWARNING;
        } else {
            assert(!"QMB ERROR");
            title = "";
            icon = 0;
        }
    }

    QMB &setText(const std::string &text) {
        message = text;
        return *this;
    }

    int exec() {
        ::MessageBoxA(nullptr, message.c_str(), title.c_str(), MB_OK | icon);
        return 0;
    }

private:

    std::string title;
    std::string message;
    UINT icon;
};

//!
//! TODO: Currently replaced with WIN32API. Will replace with Qt in the future.
//!
/*
class QMB
{
public:
    enum status {
        M_OK,
        M_ERROR
    };

    QMB() = delete;
    QMB(status s) {
        if(s == M_OK) {
            qbox.setWindowTitle(_("Confirmation").c_str());
            qbox.setIcon(QMessageBox::Information);
            qbox.setStandardButtons(QMessageBox::Ok);
            qbox.setDefaultButton(QMessageBox::Ok);
        } else if (s == M_ERROR) {
            qbox.setWindowTitle(_("Error").c_str());
            qbox.setIcon(QMessageBox::Critical);
            qbox.setStandardButtons(QMessageBox::Ok);
            qbox.setDefaultButton(QMessageBox::Ok);
        }
    }

    QMB &setText(const std::string &text) {
        qbox.setText(QString(text.c_str()));
        return *this;
    }

    int exec() {
        qbox.exec();
        return 0;
    }

private:
    QMessageBox qbox;
};
*/
#else
class QMB
{
public:
    enum status {
        M_OK,
        M_ERROR
    };

    QMB() = delete;
    QMB(status s) {}

    QMB &setText(const std::string &) {
        return *this;
    }

    int exec() {
        return 0;
    }
};
#endif

void wait_for_confirm_transaction(std::shared_ptr<CDataStream> stream) {
    //! get the SORA-QAI cipher address qai_address ans account hash
    std::string qai_address;
    std::string acc_hash;
    int64_t nAmount;
    int32_t fMessage;
    try {
       (*stream) >> qai_address >> acc_hash >> nAmount >> fMessage;
    } catch (const std::exception &) {
        fMessage ? QMB(QMB::M_ERROR).setText(_("Failed to read from CDataStream.")).exec(): 0;
        return;
    }

    print_str("qai_address", qai_address);
    print_str("acc_hash", acc_hash);
    print_num("nAmount", nAmount);

    if(!hd_wallet::get().enable) {
        fMessage ? QMB(QMB::M_ERROR).setText(_("The HD Wallet disable.")).exec(): 0;
        return;
    }
    if(entry::pwalletMain->IsLocked()) {
        fMessage ? QMB(QMB::M_ERROR).setText(_("The Wallet is locked.")).exec(): 0;
        return;
    }

    {
        //! get the scriptPubKey
        CBitcoinAddress address(qai_address);
        CScript scriptPubKey;
        scriptPubKey.SetAddress(address);
        print_str("scruptPubKey", scriptPubKey.ToString());

        //! send to SORA-QAI cipher scriptPubKey
        CWalletTx wtx;
        wtx.strFromAccount = std::string("");
        std::string strError = entry::pwalletMain->SendMoney(scriptPubKey, nAmount, wtx);
        if (!strError.empty()) {
            fMessage ? QMB(QMB::M_ERROR).setText(strError).exec(): 0;
            fMessage ? QMB(QMB::M_ERROR).setText(_("[A] The balance is likely insufficient. Please ensure a balance of at least 1 SORA.")).exec(): 0;
            return;
        }

        const uint256 txid = wtx.GetHash();
        do {
            if(entry::pwalletMain->mapWallet.count(txid)) {
                const CWalletTx &new_wtx = entry::pwalletMain->mapWallet[txid];
                const int confirms = new_wtx.GetDepthInMainChain();
                if(confirms > 0)
                    break;
            }
            util::Sleep(300);
            if(args_bool::fShutdown)
                return;
        } while(true);
    }

    {
        //! get the reserved public key
        CPubKey reserved_pubkey = hd_wallet::get().reserved_pubkey[0];
        if(!reserved_pubkey.IsFullyValid_BIP66()) {
            fMessage ? QMB(QMB::M_ERROR).setText(_("Detected an anomaly in the public key.")).exec(): 0;
            return;
        }

        //! get the scriptPubKey
        CBitcoinAddress address(reserved_pubkey.GetID());
        CScript scriptPubKey;
        scriptPubKey.SetAddress(address);

        //! send to reservedkey scriptPubKey
        CWalletTx wtx;
        wtx.strFromAccount = acc_hash;
        std::string strError = entry::pwalletMain->SendMoney(scriptPubKey, nAmount / 2, wtx);
        if (!strError.empty()) {
            fMessage ? QMB(QMB::M_ERROR).setText(strError).exec(): 0;
            fMessage ? QMB(QMB::M_ERROR).setText(_("[B] The balance is likely insufficient. Please ensure a balance of at least 1 SORA.")).exec(): 0;
            return;
        }

        const uint256 txid = wtx.GetHash();
        do {
            if(entry::pwalletMain->mapWallet.count(txid)) {
                const CWalletTx &new_wtx = entry::pwalletMain->mapWallet[txid];
                const int confirms = new_wtx.GetDepthInMainChain();
                if(confirms > 0)
                    break;
            }
            util::Sleep(500);
            if(args_bool::fShutdown)
                return;
        } while(true);
    }

    fMessage ? QMB(QMB::M_OK).setText(_("Successfully verified the encrypted message transaction.")).exec(): 0;
}

} // aitx_thread

namespace ai_script {

bool aitx03_script_store(CScript &script, const CAITransaction03 &aitx) {
    constexpr int32_t cs = Script_const::MAX_SCRIPT_ELEMENT_SIZE;
    constexpr int num = 13;
    int32_t ser_size = (int32_t)aitx.GetSerializeSize();
    if(ser_size > cs * num)
        return false;

    script.clear();
    CDataStream stream;
    stream << aitx;
    CDataStream::const_iterator pc = stream.begin();
    for(int i=0; i < num; ++i) {
        if(ser_size < cs) {
            script << script_vector(pc + (i * cs), pc + (i * cs) + ser_size);
            for(int k=i + 1; k < num; ++k) {
                script << ScriptOpcodes::OP_0;
            }
            break;
        } else {
            script << script_vector(pc + (i * cs), pc + (i * cs) + cs);
            ser_size -= cs;
        }
    }

    return true;
}

bool aitx03_script_load(CAITransaction03 &aitx, const CScript &script) {
    constexpr int32_t cs = Script_const::MAX_SCRIPT_ELEMENT_SIZE;
    constexpr int num = 13;
    int32_t script_size = (int32_t)script.size();
    if(script_size > cs * num)
        return false;

    CDataStream stream;
    stream.resize(script_size);
    CScript::const_iterator pc = script.begin();
    CDataStream::const_iterator csc = stream.begin();
    unsigned char *pds = (unsigned char *)const_cast<char *>(&(*csc));
    uint32_t offset = 0;
    for(int i=0; i < num; ++i) {
        script_vector vch;
        ScriptOpcodes::opcodetype opcode = ScriptOpcodes::OP_NOP;
        if(!script.GetOp(pc, opcode, vch))
            return false;
        if(opcode == ScriptOpcodes::OP_0)
            break;
        ::memcpy(pds + offset, vch.data(), vch.size());
        offset += vch.size();
    }

    aitx.ClearTokens();
    stream >> aitx;
    return true;
}

} // ai_script

namespace ai_time {

std::string get_localtime_format(time_t time) {
    struct tm *localTime = std::localtime(&time);
    std::string ret =
            std::to_string(localTime->tm_year + 1900) + std::string(" - ") +
            tinyformat::format("%d", localTime->tm_mon + 1) + std::string("/") +
            tinyformat::format("%d", localTime->tm_mday) + std::string(" - ") +
            tinyformat::format("%.2d", localTime->tm_hour) + std::string(":") +
            tinyformat::format("%.2d", localTime->tm_min);
    return ret;
}

} // ai_time

namespace ai_cipher {

bool getmessages(uint32_t hours, std::vector<std::pair<time_t, SecureString>> &result, std::string &err) {
    auto IsQairand03 = [](const CScript &scriptSig) {
        const uint32_t qaisize = 33 + 1 + 1; // [qairand(33)][OP_3(1)][OP_CHECKMULTISIG(1)]
        if(scriptSig.size() < qaisize)
            return false;
        if(scriptSig.back() != ScriptOpcodes::OP_CHECKMULTISIG)
            return false;
        CScript::const_iterator pc = scriptSig.begin() + (scriptSig.size() - qaisize);
        qkey_vector randvch;
        randvch.insert(randvch.end(), pc, pc + 33);
        return CqPubKey::IsRandHash(randvch) && randvch[1] == 0x03;
    };

    auto Error = [&err](const char *c_err) {
        err = std::string(c_err);
        return false;
    };

    int block_begin = block_info::nBestHeight - (hours * 20);
    if (block_begin < 0 || block_begin > block_info::nBestHeight)
        return Error("Error: Block number out of range.");

    //
    // get CAITransaction03
    //
    std::vector<std::tuple<int, uint32_t, key_vector, CAITransaction03>> vaitx;
    for (int nHeight = block_begin; nHeight <= block_info::nBestHeight; ++nHeight) {
        CBlockIndex *pblockindex = block_info::mapBlockIndex[block_info::hashBestChain];
        while (pblockindex->get_nHeight() > nHeight)
            pblockindex = pblockindex->set_pprev();

        pblockindex = block_info::mapBlockIndex[*pblockindex->get_phashBlock()];
        CBlock block;
        if(!block.ReadFromDisk(pblockindex, true))
            return Error("Error: failed to read from disk.");

        for(const CTransaction &tx: block.get_vtx()) {
            for(const CTxIn &txin: tx.get_vin()) {
                if(IsQairand03(txin.get_scriptSig())) {
                    script_vector vch;
                    ScriptOpcodes::opcodetype opcode;
                    script_vector::const_iterator pc = txin.get_scriptSig().begin();
                    int i=0;
                    CScript aiscript;
                    while(txin.get_scriptSig().GetOp(pc, opcode, vch)) {
                        aiscript << vch;
                        if(++i == 13)
                            break;
                    }

                    int pos_xonly_pubkey = 0;
                    key_vector recipient_agg_pubkey;
                    while(txin.get_scriptSig().GetOp(pc, opcode, vch)) {
                        if(++pos_xonly_pubkey == 2) {
                            recipient_agg_pubkey = std::move(vch);
                            break;
                        }
                    }
                    if(recipient_agg_pubkey.size() != XOnlyPubKey::XONLY_PUBLIC_KEY_SIZE)
                        return Error("Error: xonly_agg_pubkey is invalid.");
                    XOnlyPubKey xonly_pubkey(recipient_agg_pubkey);

                    CAITransaction03 aitx;
                    if(!ai_script::aitx03_script_load(aitx, aiscript))
                        return Error("Error: failed to load in CAITransaction03.");
                    if(!aitx.IsValid())
                        return Error("Error: CAITransaction03 is invalid.");
                    if(aitx.GetID() != xonly_pubkey.GetID())
                        return Error("Error: Schnorr signature public key for SymmetricKey is invalid.");
                    vaitx.emplace_back(std::make_tuple(nHeight, tx.get_nTime(), recipient_agg_pubkey, aitx));
                }
            }
        }
    }

    //
    // Compute SymmetricKey and decrypto messages
    //
    XOnlyKeys my_xonly_keys;
    if(!XOnlyAggWalletInfo::GetAggKeys(cipher_begin_index, cipher_agg_size, my_xonly_keys))
        return Error("Error: SymmetricKey is invalid.");
    CSecret my_agg_key;
    my_xonly_keys.GetSecret(my_agg_key);
    for(const auto &d: vaitx) {
        const key_vector &recipient_agg_pubkey = std::get<2>(d);
        secp256k1_symmetrickey symmetrickey;
        if(SymmetricKey::secp256k1_schnorrsig_symmetrickey(NULL,  my_agg_key.data(), recipient_agg_pubkey.data(), &symmetrickey) != 1)
            return Error("Error: failed to compute in SymmetricKey");
        SymmetricKey symkey(symmetrickey);

        const CAITransaction03 &aitx = std::get<3>(d);
        for(const auto &token: aitx) {
            SecureString message;
            if(token.GetTokenMessage(symkey, message)) {
                result.emplace_back(std::make_pair(std::get<1>(d), message));
            }
        }
    }

    err = std::string("");
    return true;
}

} // ai_cipher

/*
namespace ai_lang {

#ifdef QT_GUI

std::string utf8_to_sjis(const std::string &utf8Str) {
    const int32_t wideCharLen = ::MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, nullptr, 0);
    std::wstring wideStr(wideCharLen, 0);
    ::MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, &wideStr[0], wideCharLen);
    wideStr.pop_back(); // erase "\0"

    const int32_t sjisCharLen = ::WideCharToMultiByte(CP_ACP, 0, wideStr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string sjisStr(sjisCharLen, 0);
    ::WideCharToMultiByte(CP_ACP, 0, wideStr.c_str(), -1, &sjisStr[0], sjisCharLen, nullptr, nullptr);
    sjisStr.pop_back(); // erase "\0"
    return sjisStr;
}

#else

std::string utf8_to_sjis(const std::string &utf8Str) {
    return utf8Str;
}

#endif

} // ai_lang
*/
