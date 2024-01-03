// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2023 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEY_IO_H
#define BITCOIN_KEY_IO_H

#include <util/strencodings.h>
#include <address/base58.h>
#include <address/bech32.h>
#include <address/hasheth.h>
#include <const/chainparams.h>
#include <key/privkey.h>
#include <script/interpreter.h>
#include <string>
#include <allocator/allocators.h>
#include <debugcs/debugcs.h>

namespace key_io {
    enum {
        PUBKEY_PAIR_ADDRESS = 1,
        PUBKEY_ADDRESS = 63,
        SCRIPT_ADDRESS = 20,

        PUBKEY_PAIR_ADDRESS_TEST = 6,
        PUBKEY_ADDRESS_TEST = 145,
        SCRIPT_ADDRESS_TEST = 196,

        // from implementation
        PUBKEY_DIRECT = 35,
        PUBKEY_ETH_ADDRESS = 80,
        PUBKEY_DIRECT_TEST = 15,
        PUBKEY_ETH_ADDRESS_TEST = 81,

        // WIF (wallet import format)
        PRIVKEY_UNCOMPRESS = 10,
        PRIVKEY_COMPRESS = 48
    };
} // namespace key_io

/** Base class for all data */
class IKeyData {
    IKeyData(const IKeyData &)=delete;
    IKeyData &operator=(const IKeyData &)=delete;
    IKeyData(IKeyData &&)=delete;
    IKeyData &operator=(IKeyData &&)=delete;

protected:
    // the version byte
    unsigned char nVersion;

    // the actually encoded data
    base58_vector vchData;

    virtual void SetData(int nVersionIn, const void *pdata, size_t nSize)=0;
    virtual void SetData(int nVersionIn, const unsigned char *pbegin, const unsigned char *pend)=0;
    unsigned int getVersion() const { return nVersion; }
    const base58_vector &getvchData() const { return vchData; }
    void setvchData(const unsigned char &in) { vchData.push_back(in); }
    const unsigned char *getvchArray() const { return &vchData[0]; }
    bool Set(const IKeyData &dest) {
        nVersion = dest.nVersion;
        vchData = dest.vchData;
        return true;
    }

    virtual bool SetString(const char *psz)=0; // address to vch
    virtual bool SetString(const std::string &str)=0; // address to vch
    virtual std::string ToString() const=0; // vch to address

    IKeyData() {
        nVersion = 0;
        vchData.clear();
    }
    virtual ~IKeyData() {
        // zero the memory, as it may contain sensitive data
        if (! vchData.empty()) {
            cleanse::OPENSSL_cleanse(&vchData[0], vchData.size());
        }
    }

public:
    const base58_vector &GetData() const {
        return vchData;
    }

    int CompareTo(const IKeyData &b58) const {
        if (nVersion < b58.nVersion) { return -1; }
        if (nVersion > b58.nVersion) { return  1; }
        if (vchData < b58.vchData)   { return -1; }
        if (vchData > b58.vchData)   { return  1; }
        return 0;
    }
    bool operator==(const IKeyData &b58) const { return CompareTo(b58) == 0; }
    bool operator<=(const IKeyData &b58) const { return CompareTo(b58) <= 0; }
    bool operator>=(const IKeyData &b58) const { return CompareTo(b58) >= 0; }
    bool operator< (const IKeyData &b58) const { return CompareTo(b58) <  0; }
    bool operator> (const IKeyData &b58) const { return CompareTo(b58) >  0; }
};

/** vchData: keccak256 under 160bit in hex */
class CEthData : public IKeyData {
protected:
    CEthData() {}
    virtual ~CEthData() {}

    void SetData(int nVersionIn, const void *pdata, size_t nSize) {
        nVersion = nVersionIn;
        vchData.resize(nSize);
        if (! vchData.empty()) {
            std::memcpy(&vchData[0], pdata, nSize);
        }
    }
    void SetData(int nVersionIn, const unsigned char *pbegin, const unsigned char *pend) {
        SetData(nVersionIn, (void *)pbegin, pend - pbegin);
    }

public:
    bool SetString(const std::string &str) { // str is ETH address
        if(str.empty())
            return false;
        nVersion = 0; // unused
        std::string strTemp = str;
        if(str[0] == '0' && str[1] == 'x') {
            strTemp = str.substr(2);
        }
        vchData = strenc::ParseHex(strTemp);
        return (vchData.size() == 20) ? true: false;
    }

    bool SetString(const char *psz) {
        return SetString(std::string(psz));
    }

    std::string ToString() const {
        std::string str = std::string("0x");
        str += strenc::HexStr(vchData);
        return str;
    }
};

/** vchData: CKeyID */
class CBase58Data : public IKeyData {
protected:
    CBase58Data() {}
    virtual ~CBase58Data() {}

    void SetData(int nVersionIn, const void *pdata, size_t nSize) {
        nVersion = nVersionIn;
        vchData.resize(nSize);
        if (! vchData.empty()) {
            std::memcpy(&vchData[0], pdata, nSize);
        }
    }
    void SetData(int nVersionIn, const unsigned char *pbegin, const unsigned char *pend) {
        SetData(nVersionIn, (void *)pbegin, pend - pbegin);
    }

public:
    bool SetString(const char *psz) { // psz is base58
        base58_vector vchTemp;
        base58::manage::DecodeBase58Check(psz, vchTemp);
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

    bool SetString(const std::string &str) {
        return SetString(str.c_str());
    }

    std::string ToString() const {
        base58_vector vch((uint32_t)1, (uint8_t)nVersion);
        vch.insert(vch.end(), vchData.begin(), vchData.end());
        return base58::manage::EncodeBase58Check(vch);
    }
};

/** vchData: CKeyID */
#define DEBUG_CS_BECH32(str) debugcs::instance() << "Bech32: " << (str) << debugcs::endl()
const std::string hrp_main = "sora";
const std::string hrp_test = "soratest";
class CBech32Data : public IKeyData {
protected:
    CBech32Data() {}
    virtual ~CBech32Data() {}

    void SetData(int nVersionIn, const void *pdata, size_t nSize) {
        nVersion = nVersionIn;
        vchData.resize(nSize);
        if (! vchData.empty()) {
            std::memcpy(&vchData[0], pdata, nSize);
        }
    }
    void SetData(int nVersionIn, const unsigned char *pbegin, const unsigned char *pend) {
        SetData(nVersionIn, (void *)pbegin, pend - pbegin);
    }

public:
    bool SetString(const std::string &str) { // str is bech32
        std::string hrp = args_bool::fTestNet ? hrp_test: hrp_main;
        std::pair<std::string, bech32_vector> ret = bech32::Decode(str);
        if (!ret.first.empty() && ret.first == hrp) {
           nVersion = 0; // unused
           vchData = ret.second;
           return true;
        }
        return false;
    }

    bool SetString(const char *psz) {
        return SetString(std::string(psz));
    }

    std::string ToString() const {
        std::string hrp = args_bool::fTestNet ? hrp_test: hrp_main;
        return bech32::Encode(hrp, vchData);
    }
};

/** base58-encoded or bech32-encoded Bitcoin addresses.
 * Public-key-hash-addresses have version 0 (or 111 testnet).
 * The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
 * Script-hash-addresses have version 5 (or 196 testnet).
 * The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
 * Pubkey-pair-addresses have version 1 (or 6 testnet)
 * The data vector contains a serialized copy of two compressed ECDSA secp256k1 public keys.
 */
// ENC: CBase58Data, CBech32Data, CEthData
template <typename ENC>
class CBitcoinAddress_impl final : public ENC {
public:
    CBitcoinAddress_impl &operator=(const CBitcoinAddress_impl &obj) {
        ENC::Set(static_cast<const ENC &>(obj));
        return *this;
    }

    CBitcoinAddress_impl() {}
    CBitcoinAddress_impl(const CBitcoinAddress_impl &obj) {
        ENC::Set(static_cast<const ENC &>(obj));
    }

    // insert CKeyID, CScript
    CBitcoinAddress_impl(const CTxDestination &dest) {
        Set(dest);
    }
    CBitcoinAddress_impl(const CMalleablePubKey &mpk) {
        Set(mpk);
    }

    // address to id
    CBitcoinAddress_impl(const std::string &strAddress) {
        SetAddrToID(strAddress);
    }
    CBitcoinAddress_impl(const char *pszAddress) {
        SetAddrToID(pszAddress);
    }

    bool Set(const CTxDestination &dest);
    bool Set(const CMalleablePubKey &mpk);
    bool Set(const CPubKeyVch &vch);
    bool Set(const CKeyID &id);
    bool Set(const CScriptID &id);
    bool IsValid() const;
    CTxDestination Get() const;
    bool GetKeyID(CKeyID &keyID) const;

    // script type
    bool IsDirect() const;
    bool IsEth() const;
    bool IsScript() const;
    bool IsPubKey() const;
    bool IsPair() const;

private:
    bool SetAddrToID(const std::string &strAddress);
    bool SetAddrToID(const char *strAddress);
};
using CBitcoinPubkey  = CBitcoinAddress_impl<CBase58Data>; // P2PK 'F' '7' CPubKey 65bytes
using CBitcoinAddress = CBitcoinAddress_impl<CBase58Data>; // P2PKH 'S' '2' CHash160 to CPubKey 20bytes
using CScriptAddress  = CBitcoinAddress_impl<CBase58Data>; // P2SH '9' '2' CHash160 to CScript 20bytes
using CWitnessAddress = CBitcoinAddress_impl<CBech32Data>; // P2WPKH 'sora' 'soratest' CHash160 to CPubKey 20bytes
using CWitnessScript  = CBitcoinAddress_impl<CBech32Data>; // P2WSH 'sora' 'soratest' CSHA256 to CScript 32bytes
using CEthAddress     = CBitcoinAddress_impl<CEthData>;    // DAO atomic swap custom op_code 'ETH: 0x' CHashEth to CPubKey 20bytes

/** base58-encoded or bech32-encoded secret key */
template <typename ENC>
class CBitcoinSecret_impl : public ENC
{
private:
    CBitcoinSecret_impl(const CBitcoinSecret_impl &);
    CBitcoinSecret_impl &operator=(const CBitcoinSecret_impl &);

public:
    CBitcoinSecret_impl() {}
    CBitcoinSecret_impl(const CSecret &vchSecret, bool fCompressed) {
        SetSecret(vchSecret, fCompressed);
    }

    void SetSecret(const CSecret &vchSecret, bool fCompressed) {
        assert(vchSecret.size() == 32);

        ENC::SetData(128 + (args_bool::fTestNet ? key_io::PUBKEY_ADDRESS_TEST : key_io::PUBKEY_ADDRESS), &vchSecret[0], vchSecret.size());
        if (fCompressed) {
            ENC::setvchData(1);
        }
    }

    CSecret GetSecret(bool &fCompressedOut) {
        CSecret vchSecret;
        vchSecret.resize(32);

        std::memcpy(&vchSecret[0], ENC::getvchArray(), 32);
        fCompressedOut = (ENC::getvchData().size() == 33);
        return vchSecret;
    }

    bool IsValid() const {
        bool fExpectTestNet = false;
        switch(ENC::getVersion())
        {
        case (128 + key_io::PUBKEY_ADDRESS):
            break;
        case (128 + key_io::PUBKEY_ADDRESS_TEST):
            fExpectTestNet = true;
            break;
        default:
            return false;
        }
        return fExpectTestNet == args_bool::fTestNet && (ENC::getvchData().size() == 32 || (ENC::getvchData().size() == 33 && ENC::getvchData()[32] == 1));
    }

    bool SetString(const char *pszSecret) {
        return ENC::SetString(pszSecret) && IsValid();
    }

    bool SetString(const std::string &strSecret) {
        return SetString(strSecret.c_str());
    }
};
using CEthSecret = CBitcoinSecret_impl<CEthData>;
using CBitcoinSecret = CBitcoinSecret_impl<CBase58Data>;
using CWitnessSecret = CBitcoinSecret_impl<CBech32Data>;

// BIP32 and WIF
namespace key_io {

CFirmKey DecodeSecret(const std::string &str);
SecureString EncodeSecret(const CFirmKey &key);

CExtPubKey DecodeExtPubKey(const std::string &str);
std::string EncodeExtPubKey(const CExtPubKey &extpubkey, unsigned char nVersion);

CExtFirmKey DecodeExtFirmKey(const SecureString &str);
SecureString EncodeExtFirmKey(const CExtFirmKey &extkey);

std::string EncodeDestination(const CTxDestination &dest);
CTxDestination DecodeDestination(const std::string &str);
bool IsValidDestinationString(const std::string &str);
bool IsValidDestinationString(const std::string &str, const CChainParams &params);

} // namespace key_io

#endif // BITCOIN_KEY_IO_H
