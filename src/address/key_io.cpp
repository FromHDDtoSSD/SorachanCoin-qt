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
#include <init.h>
#include <address/hasheth.h>

int CBase58Data::CompareTo(const CBase58Data &b58) const {
    std::string vch = this->ToString();
    std::string b58vch = b58.ToString();
    if (vch < b58vch) { return -1; }
    if (vch > b58vch) { return  1; }
    return 0;
}

void CBase58Data::SetData(int nVersionIn, const void *pdata, size_t nSize) {
    nVersion = nVersionIn;
    vchData.resize(nSize);
    if (! vchData.empty()) {
        std::memcpy(&vchData[0], pdata, nSize);
    }
}

void CBase58Data::SetData(int nVersionIn, const unsigned char *pbegin, const unsigned char *pend) {
    SetData(nVersionIn, (void *)pbegin, pend - pbegin);
}

bool CBase58Data::SetString(const std::string &str) {
    return SetString(str.c_str());
}

std::string CBase58Data::ToString(bool fhidden) const {
    if(! fhidden) {
        CEthID ethid;
        if(entry::pwalletMain->GetEthID(CKeyID(uint160(vchData)), ethid))
            return hasheth::HexStr(ethid);
    }

    CScript redeemScript;
    CKeyID keyid;
    CEthID ethid;
    if(entry::pwalletMain->GetCScript(CScriptID(uint160(vchData)), redeemScript, keyid, ethid)) {
        if(redeemScript.IsPayToEthID() || redeemScript.IsLockToEthID())
            return hasheth::HexStr(ethid);
    }

    base58_vector vch((uint32_t)1, (uint8_t)nVersion);
    vch.insert(vch.end(), vchData.begin(), vchData.end());
    return base58::manage::EncodeBase58Check(vch);
}

bool CBase58Data::SetString(const char *psz) { // psz is base58 or CEthID
    base58_vector vchTemp;
    if(psz[0]=='0' && psz[1]=='x') {
        CEthID ethid = hasheth::ParseHex(std::string(psz));
        if(ethid == CEthID())
            return false;
        CScriptID scriptid;
        if(! entry::pwalletMain->GetScriptID(ethid, scriptid))
            return false;
        unsigned char prefix = args_bool::fTestNet ? key_io::SCRIPT_ADDRESS_TEST : key_io::SCRIPT_ADDRESS;
        vchTemp.push_back(prefix);
        vchTemp.insert(vchTemp.end(), BEGIN(scriptid), END(scriptid));
    } else {
        base58::manage::DecodeBase58Check(psz, vchTemp);
    }

    if (vchTemp.empty()) {
        vchData.clear();
        nVersion = 0;
        return false;
    } else {
        nVersion = vchTemp[0];
        vchData.resize(vchTemp.size() - 1);
        if (! vchData.empty()) {
            std::memcpy(&vchData[0], &vchTemp[1], vchData.size());
        }
        cleanse::OPENSSL_cleanse(&vchTemp[0], vchData.size());
        return true;
    }
}

namespace {
template <typename ENC>
class CBitcoinAddressVisitor : public boost::static_visitor<bool>
{
private:
    CBitcoinAddress_impl<ENC> *addr;

public:
    CBitcoinAddressVisitor(CBitcoinAddress_impl<ENC> *addrIn) : addr(addrIn) {}

    bool operator()(const CKeyID &id) const              { return addr->Set(id); }
    bool operator()(const CScriptID &id) const           { return addr->Set(id); }
    bool operator()(const CMalleablePubKey &mpk) const   { return addr->Set(mpk); }
    bool operator()(const CNoDestination &id) const      { (void)id; return false; }

    bool operator()(const WitnessV0KeyHash &id) const    {return false;}
    bool operator()(const WitnessV0ScriptHash &id) const {return addr->Set(id);}
    bool operator()(const WitnessUnknown &id) const      {(void)id; return false;}
};
} // namespace

template <typename ENC>
bool CBitcoinAddress_impl<ENC>::Set(const CTxDestination &dest) {
    return boost::apply_visitor(CBitcoinAddressVisitor<ENC>(this), dest);
}

template <typename ENC>
bool CBitcoinAddress_impl<ENC>::Set(const CKeyID &id) {
    ENC::SetData(args_bool::fTestNet ? key_io::PUBKEY_ADDRESS_TEST : key_io::PUBKEY_ADDRESS, &id, 20);
    return true;
}

template <typename ENC>
bool CBitcoinAddress_impl<ENC>::Set(const CScriptID &id) {
    ENC::SetData(args_bool::fTestNet ? key_io::SCRIPT_ADDRESS_TEST : key_io::SCRIPT_ADDRESS, &id, 20);
    return true;
}

template <typename ENC>
bool CBitcoinAddress_impl<ENC>::Set(const CMalleablePubKey &mpk) {
    key_vector vchPubkeyPair = mpk.Raw();
    ENC::SetData(args_bool::fTestNet ? key_io::PUBKEY_PAIR_ADDRESS_TEST : key_io::PUBKEY_PAIR_ADDRESS, &vchPubkeyPair[0], 68);
    return true;
}

template <typename ENC>
bool CBitcoinAddress_impl<ENC>::SetAddrToID(const std::string &strAddress) {
    return ENC::SetString(strAddress);
}

template <typename ENC>
bool CBitcoinAddress_impl<ENC>::SetAddrToID(const char *strAddress) {
    return ENC::SetString(strAddress);
}

template <typename ENC>
bool CBitcoinAddress_impl<ENC>::IsValid() const {
    unsigned int nExpectedSize = 20;
    bool fExpectTestNet = false;
    bool fSimple = true;

    //debugcs::instance() << "CBitcoinAddress IsValid: version: " << ENC::getVersion() << debugcs::endl();
    switch(ENC::getVersion())
    {
    case key_io::PUBKEY_PAIR_ADDRESS:
        nExpectedSize = 68; // Serialized pair of public keys
        fExpectTestNet = false;
        fSimple = false;
        break;
    case key_io::PUBKEY_ADDRESS:
        nExpectedSize = 20; // Hash of public key CHash160
        fExpectTestNet = false;
        break;
    case key_io::SCRIPT_ADDRESS:
        nExpectedSize = 20; // Hash of CScript CHash160
        fExpectTestNet = false;
        break;
    case key_io::PUBKEY_ETH_ADDRESS:
        nExpectedSize = 20; // Hash of public key CHashEth
        fExpectTestNet = false;
        break;
    case key_io::PUBKEY_PAIR_ADDRESS_TEST:
        nExpectedSize = 68;
        fExpectTestNet = true;
        fSimple = false;
        break;
    case key_io::PUBKEY_ADDRESS_TEST:
        nExpectedSize = 20;
        fExpectTestNet = true;
        break;
    case key_io::SCRIPT_ADDRESS_TEST:
        nExpectedSize = 20;
        fExpectTestNet = true;
        break;
    case key_io::PUBKEY_ETH_ADDRESS_TEST:
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

template <typename ENC>
CTxDestination CBitcoinAddress_impl<ENC>::Get() const {
    if (! IsValid()) {
        return CNoDestination();
    }

    switch (ENC::getVersion())
    {
    case key_io::PUBKEY_ADDRESS:
    case key_io::PUBKEY_ADDRESS_TEST:
        {
            uint160 id;
            std::memcpy(&id, ENC::getvchArray(), 20);
            return CKeyID(id);
        }
        break;
    case key_io::SCRIPT_ADDRESS:
    case key_io::SCRIPT_ADDRESS_TEST:
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

template <typename ENC>
bool CBitcoinAddress_impl<ENC>::GetKeyID(CKeyID &keyID) const {
    if (! IsValid()) {
        return false;
    }

    switch (ENC::getVersion())
    {
    case key_io::PUBKEY_ADDRESS:
    case key_io::PUBKEY_ADDRESS_TEST:
        {
            uint160 id;
            std::memcpy(&id, ENC::getvchArray(), 20);
            keyID = CKeyID(id);
            return true;
        }
        break;
    case key_io::PUBKEY_PAIR_ADDRESS:
    case key_io::PUBKEY_PAIR_ADDRESS_TEST:
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

template <typename ENC>
bool CBitcoinAddress_impl<ENC>::IsEth() const {
    if (! IsValid()) {
        return false;
    }

    switch (ENC::getVersion())
    {
    case key_io::PUBKEY_ETH_ADDRESS:
    case key_io::PUBKEY_ETH_ADDRESS_TEST:
        return true;
    default:
        return false;
    }
    return false;
}

template <typename ENC>
bool CBitcoinAddress_impl<ENC>::IsScript() const {
    if (! IsValid()) {
        return false;
    }

    switch (ENC::getVersion())
    {
    case key_io::SCRIPT_ADDRESS:
    case key_io::SCRIPT_ADDRESS_TEST:
        return true;
    default:
        return false;
    }
    return false;
}

template <typename ENC>
bool CBitcoinAddress_impl<ENC>::IsPubKey() const {
    if (! IsValid()) {
        return false;
    }

    switch (ENC::getVersion())
    {
    case key_io::PUBKEY_ADDRESS:
    case key_io::PUBKEY_ADDRESS_TEST:
        return true;
    default:
        return false;
    }
    return false;
}

template <typename ENC>
bool CBitcoinAddress_impl<ENC>::IsPair() const {
    if (! IsValid()) {
        return false;
    }

    switch (ENC::getVersion())
    {
    case key_io::PUBKEY_PAIR_ADDRESS:
    case key_io::PUBKEY_PAIR_ADDRESS_TEST:
        return true;
    default:
        return false;
    }
}

template class CBitcoinAddress_impl<CBase58Data>;
template class CBitcoinAddress_impl<CBech32Data>;
template class CBitcoinSecret_impl<CBase58Data>;
template class CBitcoinSecret_impl<CBech32Data>;


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

static constexpr unsigned char compressed_flag = 1;
static constexpr size_t base58_bytes_prefix_size = sizeof(unsigned char);
CFirmKey key_io::DecodeSecret(const SecureString &str) {
    CFirmKey key;
    CfCompSecret data;
    if (base58::manage::DecodeBase58Check<SecureString, CfCompSecret>(str, data)) {
        //debugcs::instance() << "DecodeSecret size: " << data.size() << debugcs::endl();
        if(data.size() == CFirmKey::PRIVATE_BYTE_VECTOR_SIZE + base58_bytes_prefix_size + 1 && data.back() == compressed_flag) {
            data.pop_back();
            key.Set(data.begin() + base58_bytes_prefix_size, data.end(), true);
        } else if (data.size() == CFirmKey::PRIVATE_BYTE_VECTOR_SIZE + base58_bytes_prefix_size) {
            key.Set(data.begin() + base58_bytes_prefix_size, data.end(), false);
        } else {
            throw std::runtime_error("CfCompSecret is invalid");
        }
    }
    return key;
}

SecureString key_io::EncodeSecret(const CFirmKey &key) {
    if(! key.IsValid())
        throw std::runtime_error("privkey is invalid");

    const unsigned char prefix = key.IsCompressed() ? key_io::PRIVKEY_COMPRESS: key_io::PRIVKEY_UNCOMPRESS;
    CfCompSecret data((uint32_t)base58_bytes_prefix_size, (uint8_t)prefix);
    data.insert(data.end(), key.begin(), key.end());
    if (key.IsCompressed())
        data.push_back(compressed_flag);

    return base58::manage::EncodeBase58Check<SecureString, CfCompSecret>(data);
}

CExtPubKey key_io::DecodeExtPubKey(const std::string &str) { // str is base58
    CExtPubKey key;
    base58_vector data;
    if (base58::manage::DecodeBase58Check<std::string, base58_vector>(str, data)) {
        if (data.size() == CExtPubKey::BIP32_EXTKEY_SIZE + base58_bytes_prefix_size) {
            // data structure is bytes_prefix(unsigned char) + CExtPubKey bytes vector
            // only require CExtPubKey bytes vector, therefore add pointer in base58_bytes_prefix_size
            key.Set(data.data() + base58_bytes_prefix_size);
        }
    }
    if(data.empty() || data.size() != CExtPubKey::BIP32_EXTKEY_SIZE)
        throw std::runtime_error("key_io::DecodeExtPubKey failure");

    cleanse::memory_cleanse(data.data(), data.size());
    return key;
}

std::string key_io::EncodeExtPubKey(const CExtPubKey &extkey, unsigned char nVersion) { // e.g. nVersion: key_io::PUBKEY_ADDRESS
    base58_vector data((uint32_t)base58_bytes_prefix_size, (uint8_t)nVersion);
    base58_vector vch = extkey.GetPubVch();
    data.insert(data.end(), vch.begin(), vch.end());
    if(data.size() != CExtPubKey::BIP32_EXTKEY_SIZE + base58_bytes_prefix_size)
        throw std::runtime_error("key_io::EncodeExtPubKey is failure");

    std::string ret = base58::manage::EncodeBase58Check<std::string, base58_vector>(data);
    cleanse::memory_cleanse(data.data(), data.size());
    return ret;
}

CExtFirmKey key_io::DecodeExtFirmKey(const SecureString &str) {
    CExtFirmKey key;
    CExtSecret data;
    if (base58::manage::DecodeBase58Check<SecureString, CExtSecret>(str, data)) {
        if (data.size() != CExtPubKey::BIP32_EXTKEY_SIZE + base58_bytes_prefix_size)
            throw std::runtime_error("key_io::DecodeExtFirmKey: size is invalid");

        bool fCompressed = true;
        if(data[0] == key_io::PRIVKEY_COMPRESS)
            fCompressed = true;
        else if (data[0] == key_io::PRIVKEY_UNCOMPRESS)
            fCompressed = false;
        else
            throw std::runtime_error("key_io::DecodeExtFirmKey: base58 prefix is invalid");

        key.Set(&data[0] + base58_bytes_prefix_size, fCompressed);
    } else {
        throw std::runtime_error("key_io::DecodeExtFirmKey: Decode base58 is failure");
    }
    return key;
}

SecureString key_io::EncodeExtFirmKey(const CExtFirmKey &extkey) {
    if(! extkey.key.IsValid()) {
        throw std::runtime_error("key_io::EncodeExtFirmKey: privkey is invalid");
    }

    CExtSecret data;
    if(extkey.key.IsCompressed()) {
        data.push_back((uint8_t)key_io::PRIVKEY_COMPRESS);
    } else {
        data.push_back((uint8_t)key_io::PRIVKEY_UNCOMPRESS);
    }

    data.resize(base58_bytes_prefix_size + CExtPubKey::BIP32_EXTKEY_SIZE);
    CPrivKey keyvch = extkey.GetPrivKeyVch();
    data.insert(data.end(), keyvch.begin(), keyvch.end());
    return base58::manage::EncodeBase58Check<SecureString, CExtSecret>(data);
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
