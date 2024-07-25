// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORA_QAI_AITX_H
#define SORA_QAI_AITX_H

#include <uint256.h>
#include <key/privkey.h>
#include <key/pubkey.h>
#include <bip32/hdchain.h>

//! SORA-QAI ver3: crypto message
class CAIToken03
{
private:
    CSecureBytes crypto;

public:
    CAIToken03() {}

    bool IsValid() const;

    bool SetTokenMessage(const SymmetricKey &key, const SecureString &message);
    bool GetTokenMessage(const SymmetricKey &key, SecureString &message) const;

    std::pair<uint160, bool> GetHash() const;

    friend bool operator==(const CAIToken03 &a, const CAIToken03 &b) {
        return a.crypto == b.crypto;
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(crypto);
    }
};

//! A dedicated worker thread for CAITransaction
namespace aitx_thread {
    void wait_for_confirm_transaction(std::shared_ptr<CDataStream> stream);
} // aitx_thread

//! SORA-QAI CKeyID: uint160 merkle tree
class CAITransaction
{
private:
    unsigned char qaiVersion;
    int64_t nTime;
    CKeyID schnorrsigHash;
    std::vector<uint160> hashes;

public:
    CAITransaction() = delete;
    CAITransaction(unsigned char qaiVersionIn) :
    qaiVersion(qaiVersionIn), nTime(0), schnorrsigHash(CKeyID(0)) {}

    bool IsValid() const;

    void PushTokenHash(uint160 hash);
    void SetSchnorrAggregateKeyID(const XOnlyPubKey &xonly_pubkey);
    CKeyID GetID() const;

    int64_t GetTime() const;

    void ClearTx();

    std::pair<uint160, bool> GetMerkleRoot() const;
    std::pair<qkey_vector, bool> GetSchnorrHash() const;

    uint32_t GetSerializeSize() const {
        CSizeComputer sc((int)qaiVersion);
        sc << (*this);
        return sc.size();
    }

    friend bool operator==(const CAITransaction &a, const CAITransaction &b) {
        return a.qaiVersion == b.qaiVersion && a.nTime == b.nTime &&
               a.schnorrsigHash == b.schnorrsigHash && a.hashes == b.hashes;
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(qaiVersion);
        READWRITE(nTime);
        READWRITE(schnorrsigHash);
        READWRITE(hashes);
    }
};

//! SORA-QAI ver3: CAITransaction03
class CAITransaction03
{
private:
    constexpr static unsigned char QaiVersion = 0x03;

    //! Place the AI tokens here in PushTokenMessage.
    //! Additionally, please add one Schnorr aggregated signature with XOnlyPubKey and SetSchnorrAggregateKeyID.
    std::vector<CAIToken03> tokens;

    //! Each token hash (tokens) and the hash of the Schnorr aggregated signature
    //! must be inserted to be validated.
    //! If not activated, the retrieval of the Merkle root will fail.
    CAITransaction aitx;

public:
    CAITransaction03() : aitx(QaiVersion) {}

    bool IsValid() const;

    bool PushTokenMessage(const SymmetricKey &key, const SecureString &message);
    void SetSchnorrAggregateKeyID(const XOnlyPubKey &xonly_pubkey);

    void ClearTokens();
    uint32_t SizeTokens() const;

    const CAIToken03 &operator[](uint32_t index) const;
    CAIToken03 *begin();
    CAIToken03 *end();
    const CAIToken03 *begin() const;
    const CAIToken03 *end() const;

    std::pair<uint160, bool> GetMerkleRoot() const;
    std::pair<qkey_vector, bool> GetSchnorrHash() const;
    CKeyID GetID() const;

    int64_t GetTime() const;

    uint32_t GetSerializeSize() const {
        CSizeComputer sc((int)QaiVersion);
        sc << (*this);
        return sc.size();
    }

    friend bool operator==(const CAITransaction03 &a, const CAITransaction03 &b) {
        return a.tokens == b.tokens && a.aitx == b.aitx;
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(tokens);
        READWRITE(aitx);
    }
};

namespace ai_script {

bool aitx03_script_store(CScript &script, const CAITransaction03 &aitx);
bool aitx03_script_load(CAITransaction03 &aitx, const CScript &script);

} // ai_script

namespace ai_time {

std::string get_localtime_format(time_t time);

} // ai_time

const std::string hrp_cipher_main = "cipher";
const std::string hrp_cipher_testnet = "ciphertest";
static std::string GetHrpCipher() {
    return args_bool::fTestNet ? hrp_cipher_testnet: hrp_cipher_main;
}

namespace ai_cipher {

constexpr unsigned int cipher_begin_index = hdkeys_child_regenerate + 1;
constexpr size_t cipher_agg_size = XOnlyAggWalletInfo::DEF_AGG_XONLY_KEYS;

bool getmycipheraddress(std::string &cipher_address, std::string &err);
bool getmessages(uint32_t hours, std::vector<std::tuple<time_t, std::string, SecureString>> &result, std::string &err);
bool sendciphermessage(const std::string &recipient_pubkey, std::string &&cipher, bool stealth, bool mintflag);

bool getsentmymessages(uint32_t hours, const std::string &recipient_address, std::vector<std::pair<time_t, SecureString>> &result, std::string &err);

} // ai_cipher

namespace ai_ecdsa {
    bool qai_to_ecdsa_move_tx();
} // ai_ecdsa

#endif // SORA_QAI_AITX_H
