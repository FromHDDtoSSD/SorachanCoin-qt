// Copyright (c) 2014-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <address/key_io.h>
#include <script/script.h>
#include <util/strencodings.h>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>
#include <assert.h>
#include <string.h>
#include <algorithm>

namespace {
template <typename ENC, typename VER>
class CBitcoinAddressVisitor : public boost::static_visitor<bool>
{
private:
    CBitcoinAddressVisitor();
    CBitcoinAddressVisitor(const CBitcoinAddressVisitor &);
    CBitcoinAddressVisitor(CBitcoinAddressVisitor &&);
    CBitcoinAddressVisitor &operator=(const CBitcoinAddressVisitor &);
    CBitcoinAddressVisitor &operator=(CBitcoinAddressVisitor &&);
    CBitcoinAddress_impl<ENC, VER> *addr;
public:
    CBitcoinAddressVisitor(CBitcoinAddress_impl<ENC, VER> *addrIn) : addr(addrIn) {}
    bool operator()(const CKeyID &id) const              { return addr->Set(id); }
    bool operator()(const CScriptID &id) const           { return addr->Set(id); }
    bool operator()(const CMalleablePubKey &mpk) const   { return addr->Set(mpk); }
    bool operator()(const CNoDestination &id) const      { (void)id; return false; }
    bool operator()(const WitnessV0KeyHash &id) const    {return false;}
    bool operator()(const WitnessV0ScriptHash &id) const {return false;}
    bool operator()(const WitnessUnknown &id) const      {return false;}
};
} // namespace

template <typename ENC, typename VER>
bool CBitcoinAddress_impl<ENC, VER>::Set(const CTxDestination &dest) {
    return boost::apply_visitor(CBitcoinAddressVisitor<ENC, VER>(this), dest);
}

template <typename ENC, typename VER>
bool CBitcoinAddress_impl<ENC, VER>::Set(const CKeyID &id) {
    ENC::SetData(args_bool::fTestNet ? VER::PUBKEY_ADDRESS_TEST : VER::PUBKEY_ADDRESS, &id, 20);
    return true;
}

template <typename ENC, typename VER>
bool CBitcoinAddress_impl<ENC, VER>::Set(const CScriptID &id) {
    ENC::SetData(args_bool::fTestNet ? VER::SCRIPT_ADDRESS_TEST : VER::SCRIPT_ADDRESS, &id, 20);
    return true;
}

template <typename ENC, typename VER>
bool CBitcoinAddress_impl<ENC, VER>::Set(const CMalleablePubKey &mpk) {
    key_vector vchPubkeyPair = mpk.Raw();
    ENC::SetData(args_bool::fTestNet ? VER::PUBKEY_PAIR_ADDRESS_TEST : VER::PUBKEY_PAIR_ADDRESS, &vchPubkeyPair[0], 68);
    return true;
}

template <typename ENC, typename VER>
bool CBitcoinAddress_impl<ENC, VER>::IsValid() const {
    unsigned int nExpectedSize = 20;
    bool fExpectTestNet = false;
    bool fSimple = true;

    switch(ENC::getVersion())
    {
    case VER::PUBKEY_PAIR_ADDRESS:
        nExpectedSize = 68; // Serialized pair of public keys
        fExpectTestNet = false;
        fSimple = false;
        break;
    case VER::PUBKEY_ADDRESS:
        nExpectedSize = 20; // Hash of public key
        fExpectTestNet = false;
        break;
    case VER::SCRIPT_ADDRESS:
        nExpectedSize = 20; // Hash of CScript
        fExpectTestNet = false;
        break;
    case VER::PUBKEY_PAIR_ADDRESS_TEST:
        nExpectedSize = 68;
        fExpectTestNet = true;
        fSimple = false;
        break;
    case VER::PUBKEY_ADDRESS_TEST:
        nExpectedSize = 20;
        fExpectTestNet = true;
        break;
    case VER::SCRIPT_ADDRESS_TEST:
        nExpectedSize = 20;
        fExpectTestNet = true;
        break;
    default:
        return false;
    }

    // Basic format sanity check
    bool fSeemsSane = (fExpectTestNet == args_bool::fTestNet && ENC::getvchData().size() == nExpectedSize);

    if (fSeemsSane && !fSimple) {
        // Perform dditional checking
        // for pubkey pair addresses
        CMalleablePubKey mpk;
        mpk.setvch(ENC::getvchData());
        return mpk.IsValid();
    } else {
        return fSeemsSane;
    }
}

template <typename ENC, typename VER>
CTxDestination CBitcoinAddress_impl<ENC, VER>::Get() const {
    if (! IsValid()) {
        return CNoDestination();
    }

    switch (ENC::getVersion())
    {
    case VER::PUBKEY_ADDRESS:
    case VER::PUBKEY_ADDRESS_TEST:
        {
            uint160 id;
            std::memcpy(&id, ENC::getvchArray(), 20);
            return CKeyID(id);
        }
        break;
    case VER::SCRIPT_ADDRESS:
    case VER::SCRIPT_ADDRESS_TEST:
        {
            uint160 id;
            std::memcpy(&id, ENC::getvchArray(), 20);
            return CScriptID(id);
        }
        break;
    default:
        break;
    }
    return CNoDestination();
}

template <typename ENC, typename VER>
bool CBitcoinAddress_impl<ENC, VER>::GetKeyID(CKeyID &keyID) const {
    if (! IsValid()) {
        return false;
    }

    switch (ENC::getVersion())
    {
    case VER::PUBKEY_ADDRESS:
    case VER::PUBKEY_ADDRESS_TEST:
        {
            uint160 id;
            std::memcpy(&id, ENC::getvchArray(), 20);
            keyID = CKeyID(id);
            return true;
        }
        break;
    case VER::PUBKEY_PAIR_ADDRESS:
    case VER::PUBKEY_PAIR_ADDRESS_TEST:
        {
            CMalleablePubKey mPubKey;
            mPubKey.setvch(ENC::getvchData());
            keyID = mPubKey.GetID();
            return true;
        }
        break;
    default:
        return false;
    }
}

template <typename ENC, typename VER>
bool CBitcoinAddress_impl<ENC, VER>::IsScript() const {
    if (! IsValid()) {
        return false;
    }

    switch (ENC::getVersion())
    {
    case VER::SCRIPT_ADDRESS:
    case VER::SCRIPT_ADDRESS_TEST:
        return true;
    default:
        return false;
    }
    return false;
}

template <typename ENC, typename VER>
bool CBitcoinAddress_impl<ENC, VER>::IsPubKey() const {
    if (! IsValid()) {
        return false;
    }

    switch (ENC::getVersion())
    {
    case VER::PUBKEY_ADDRESS:
    case VER::PUBKEY_ADDRESS_TEST:
        return true;
    default:
        return false;
    }
    return false;
}

template <typename ENC, typename VER>
bool CBitcoinAddress_impl<ENC, VER>::IsPair() const {
    if (! IsValid()) {
        return false;
    }

    switch (ENC::getVersion())
    {
    case VER::PUBKEY_PAIR_ADDRESS:
    case VER::PUBKEY_PAIR_ADDRESS_TEST:
        return true;
    default:
        return false;
    }
}

template class CBitcoinAddress_impl<CBase58Data, VERBase58>;
template class CBitcoinAddress_impl<CBech32Data, VERBech32>;
template class CBitcoinSecret_impl<CBase58Data, VERBase58>;
template class CBitcoinSecret_impl<CBech32Data, VERBech32>;



// latest core logic
namespace {
class DestinationEncoder : public boost::static_visitor<std::string>
{
private:
    const CChainParams &m_params;

public:
    explicit DestinationEncoder(const CChainParams &params) : m_params(params) {}

    std::string operator()(const CKeyID &id) const {
        base58_vector data = m_params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return base58::manage::EncodeBase58Check(data);
    }

    std::string operator()(const CScriptID &id) const {
        base58_vector data = m_params.Base58Prefix(CChainParams::SCRIPT_ADDRESS2);
        data.insert(data.end(), id.begin(), id.end());
        return base58::manage::EncodeBase58Check(data);
    }

    std::string operator()(const WitnessV0KeyHash &id) const {
        bech32_vector data; data.clear();
        data.reserve(33);
        strenc::ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.begin(), id.end());
        return bech32::Encode(m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessV0ScriptHash &id) const {
        bech32_vector data; data.clear();
        data.reserve(53);
        strenc::ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.begin(), id.end());
        return bech32::Encode(m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessUnknown &id) const {
        if (id.version < 1 || id.version > 16 || id.length < 2 || id.length > 40) {
            return {};
        }
        bech32_vector data; data.clear();
        data.push_back((unsigned char)id.version);
        data.reserve(1 + (id.length * 8 + 4) / 5);
        strenc::ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.program, id.program + id.length);
        return bech32::Encode(m_params.Bech32HRP(), data);
    }

    std::string operator()(const CNoDestination &no) const { (void)no; return {}; }
};
} // namespace

static CTxDestination DecodeDestination(const std::string &str, const CChainParams &params) {
    base58_vector data;
    uint160 hash;
    if (base58::manage::DecodeBase58Check(str, data)) {
        // base58-encoded Bitcoin addresses.
        // Public-key-hash-addresses have version 0 (or 111 testnet).
        // The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
        const chainparams_vector &pubkey_prefix = params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        if (data.size() == hash.size() + pubkey_prefix.size() && std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), data.begin())) {
            std::copy(data.begin() + pubkey_prefix.size(), data.end(), hash.begin());
            return CKeyID(hash);
        }
        // Script-hash-addresses have version 5 for 3 prefix (or 196 testnet).
        // The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
        const chainparams_vector &script_prefix = params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        if (data.size() == hash.size() + script_prefix.size() && std::equal(script_prefix.begin(), script_prefix.end(), data.begin())) {
            std::copy(data.begin() + script_prefix.size(), data.end(), hash.begin());
            return CScriptID(hash);
        }
        // Script-hash-addresses have version 5 for M prefix (or 196 testnet).
        // The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
        const chainparams_vector &script_prefix2 = params.Base58Prefix(CChainParams::SCRIPT_ADDRESS2);
        if (data.size() == hash.size() + script_prefix2.size() && std::equal(script_prefix2.begin(), script_prefix2.end(), data.begin())) {
            std::copy(data.begin() + script_prefix2.size(), data.end(), hash.begin());
            return CScriptID(hash);
        }
    }
    data.clear();
    auto bech = bech32::Decode(str);
    if (bech.second.size() > 0 && bech.first == params.Bech32HRP()) {
        // Bech32 decoding
        int version = bech.second[0]; // The first 5 bit symbol is the witness version (0-16)
        // The rest of the symbols are converted witness program bytes.
        data.reserve(((bech.second.size() - 1) * 5) / 8);
        if (strenc::ConvertBits<5, 8, false>([&](unsigned char c) { data.push_back(c); }, bech.second.begin() + 1, bech.second.end())) {
            if (version == 0) {
                {
                    WitnessV0KeyHash keyid;
                    if (data.size() == keyid.size()) {
                        std::copy(data.begin(), data.end(), keyid.begin());
                        return keyid;
                    }
                }
                {
                    WitnessV0ScriptHash scriptid;
                    if (data.size() == scriptid.size()) {
                        std::copy(data.begin(), data.end(), scriptid.begin());
                        return scriptid;
                    }
                }
                return CNoDestination();
            }
            if (version > 16 || data.size() < 2 || data.size() > 40) {
                return CNoDestination();
            }

            WitnessUnknown unk;
            unk.version = version;
            std::copy(data.begin(), data.end(), unk.program);
            unk.length = data.size();
            return unk;
            //return CNoDestination();
        }
    }
    return CNoDestination();
}

CFirmKey key_io::DecodeSecret(const std::string &str) {
    CFirmKey key;
    base58_vector data;
    if (base58::manage::DecodeBase58Check(str, data)) {
        const chainparams_vector &privkey_prefix = Chain_info::Params().Base58Prefix(CChainParams::SECRET_KEY);
        if ((data.size() == 32 + privkey_prefix.size() || (data.size() == 33 + privkey_prefix.size() && data.back() == 1)) &&
            std::equal(privkey_prefix.begin(), privkey_prefix.end(), data.begin())) {
            bool compressed = data.size() == 33 + privkey_prefix.size();
            key.Set(data.begin() + privkey_prefix.size(), data.begin() + privkey_prefix.size() + 32, compressed);
        }
    }
    if (! data.empty()) {
        cleanse::OPENSSL_cleanse(data.data(), data.size());
    }
    return key;
}

std::string key_io::EncodeSecret(const CFirmKey &key) {
    assert(key.IsValid());
    chainparams_vector data = Chain_info::Params().Base58Prefix(CChainParams::SECRET_KEY);
    data.insert(data.end(), key.begin(), key.end());
    if (key.IsCompressed()) {
        data.push_back(1);
    }
    std::string ret = base58::manage::EncodeBase58Check(data);
    cleanse::OPENSSL_cleanse(data.data(), data.size());
    return ret;
}

CExtPubKey key_io::DecodeExtPubKey(const std::string &str) {
    CExtPubKey key;
    base58_vector data;
    if (base58::manage::DecodeBase58Check(str, data)) {
        const chainparams_vector &prefix = Chain_info::Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
        if (data.size() == CExtPubKey::BIP32_EXTKEY_SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
            key.Decode(data.data() + prefix.size());
        }
    }
    if(! data.empty()) {
        cleanse::memory_cleanse(data.data(), data.size());
    }
    return key;
}

std::string key_io::EncodeExtPubKey(const CExtPubKey &extkey) {
    chainparams_vector data = Chain_info::Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
    const size_t size = data.size();
    data.resize(size + CExtPubKey::BIP32_EXTKEY_SIZE);
    extkey.Encode(data.data() + size);
    std::string ret = base58::manage::EncodeBase58Check(data);
    cleanse::memory_cleanse(data.data(), data.size());
    return ret;
}

CExtFirmKey key_io::DecodeExtKey(const std::string &str) {
    CExtFirmKey key;
    chainparams_vector data;
    if (base58::manage::DecodeBase58Check(str, data)) {
        const chainparams_vector &prefix = Chain_info::Params().Base58Prefix(CChainParams::EXT_SECRET_KEY);
        if (data.size() == CExtPubKey::BIP32_EXTKEY_SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
            key.Decode(data.data() + prefix.size());
        }
    }
    if(! data.empty()) {
        cleanse::memory_cleanse(data.data(), data.size());
    }
    return key;
}

std::string key_io::EncodeExtKey(const CExtFirmKey &extkey) {
    chainparams_vector data = Chain_info::Params().Base58Prefix(CChainParams::EXT_SECRET_KEY);
    const size_t size = data.size();
    data.resize(size + CExtPubKey::BIP32_EXTKEY_SIZE);
    extkey.Encode(data.data() + size);
    std::string ret = base58::manage::EncodeBase58Check(data);
    cleanse::OPENSSL_cleanse(data.data(), data.size());
    return ret;
}

std::string key_io::EncodeDestination(const CTxDestination &dest) {
    return boost::apply_visitor(DestinationEncoder(Chain_info::Params()), dest);
}

CTxDestination key_io::DecodeDestination(const std::string &str) {
    return DecodeDestination(str, Chain_info::Params());
}

bool key_io::IsValidDestinationString(const std::string &str, const CChainParams &params) {
    return Script_util::IsValidDestination(DecodeDestination(str, params));
}

bool key_io::IsValidDestinationString(const std::string &str) {
    return IsValidDestinationString(str, Chain_info::Params());
}
