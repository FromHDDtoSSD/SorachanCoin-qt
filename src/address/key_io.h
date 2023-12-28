// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEY_IO_H
#define BITCOIN_KEY_IO_H

#include <util/strencodings.h>
#include <address/base58.h>
#include <address/bech32.h>
#include <const/chainparams.h>
#include <key/privkey.h>
#include <script/interpreter.h>
#include <string>

/** Base class for all base58-encoded or bech32-encoded data */
class IKeyData {
private:
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

class CHexAddress : public IKeyData {
protected:
    CHexAddress() {}
    virtual ~CHexAddress() {}

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
    bool SetString(const char *psz) {
        return SetString(std::string(psz));
    }

    bool SetString(const std::string &str) {
        if(str.empty())
            return false;
        vchData = strenc::ParseHex(str);
        return true;
    }

    std::string ToString() const {
        std::string str = std::string("0x");
        str += strenc::HexStr(vchData);
        return str;
    }
};

class VERHexAddress {
public:
    enum {
        PUBKEY_PAIR_ADDRESS = 1,
        PUBKEY_ADDRESS = 63,
        SCRIPT_ADDRESS = 20,
        PUBKEY_PAIR_ADDRESS_TEST = 6,
        PUBKEY_ADDRESS_TEST = 145,
        SCRIPT_ADDRESS_TEST = 196,

        PUBKEY_COMPRESSED_DIRECT = 333,
        PUBKEY_DIRECT = 353
    };
};

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
    bool SetString(const char *psz) {
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

class VERBase58 {
public:
    enum {
        PUBKEY_PAIR_ADDRESS = 1,
        PUBKEY_ADDRESS = 63,
        SCRIPT_ADDRESS = 20,
        PUBKEY_PAIR_ADDRESS_TEST = 6,
        PUBKEY_ADDRESS_TEST = 145,
        SCRIPT_ADDRESS_TEST = 196,

        PUBKEY_COMPRESSED_DIRECT = 333,
        PUBKEY_DIRECT = 353
    };
};

#define BECH32_TEST_MODE
#ifdef BECH32_TEST_MODE
# include <debugcs/debugcs.h>
# define DEBUG_CS_BECH32(str) debugcs::instance() << "Bech32: " << (str) << debugcs::endl()
#else
# define DEBUG_CS_BECH32(str)
#endif
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
    bool SetString(const char *psz) {
#ifndef BECH32_TEST_MODE
        std::pair<std::string, bech32_vector> ret = bech32::Decode(std::string(psz));
        bech32_vector &vchTemp = ret.second;
#else
        base58_vector vchTemp;
        base58::manage::DecodeBase58Check(psz, vchTemp);
#endif
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
        static const char *hrp_main = "sora";
        static const char *hrp_test = "sora_testnet";
        const char *hrp = args_bool::fTestNet ? hrp_test: hrp_main;
        bech32_vector vch((uint32_t)1, (uint8_t)nVersion);
        vch.insert(vch.end(), vchData.begin(), vchData.end());
#ifdef BECH32_TEST_MODE
        DEBUG_CS_BECH32(bech32::Encode(hrp, vch).c_str());

        base58_vector vch58((uint32_t)1, (uint8_t)nVersion);
        vch58.insert(vch58.end(), vchData.begin(), vchData.end());
        return base58::manage::EncodeBase58Check(vch58);
#else
        return bech32::Encode(hrp, vch);
#endif
    }
};

class VERBech32 {
public:
    enum {
        PUBKEY_PAIR_ADDRESS = 11,
        PUBKEY_ADDRESS = 33,
        SCRIPT_ADDRESS = 53,
        PUBKEY_PAIR_ADDRESS_TEST = 66,
        PUBKEY_ADDRESS_TEST = 233,
        SCRIPT_ADDRESS_TEST = 253,

        PUBKEY_COMPRESSED_DIRECT = 333,
        PUBKEY_DIRECT = 353
    };
};

/** base58-encoded or bech32-encoded Bitcoin addresses.
 * Public-key-hash-addresses have version 0 (or 111 testnet).
 * The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
 * Script-hash-addresses have version 5 (or 196 testnet).
 * The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
 * Pubkey-pair-addresses have version 1 (or 6 testnet)
 * The data vector contains a serialized copy of two compressed ECDSA secp256k1 public keys.
 */
template <typename ENC, typename VER>
class CBitcoinAddress_impl final : public ENC, public VER {
public:
    CBitcoinAddress_impl &operator=(const CBitcoinAddress_impl &obj) {
        ENC::Set(static_cast<const ENC &>(obj));
        return *this;
    }

    CBitcoinAddress_impl() {}
    CBitcoinAddress_impl(const CBitcoinAddress_impl &obj) {
        ENC::Set(static_cast<const ENC &>(obj));
    }
    CBitcoinAddress_impl(const CTxDestination &dest) {
        Set(dest);
    }
    CBitcoinAddress_impl(const CMalleablePubKey &mpk) {
        Set(mpk);
    }
    CBitcoinAddress_impl(const std::string &strAddress) {
        ENC::SetString(strAddress);
    }
    CBitcoinAddress_impl(const char *pszAddress) {
        ENC::SetString(pszAddress);
    }

    bool Set(const CTxDestination &dest);
    bool Set(const CPubKeyVch &vch);
    bool Set(const CKeyID &id);
    bool Set(const CScriptID &id);
    bool Set(const CMalleablePubKey &mpk);

    bool IsValid() const;
    CTxDestination Get() const;
    bool GetKeyID(CKeyID &keyID) const;
    bool IsScript() const;
    bool IsPubKey() const;
    bool IsPair() const;
};
using CBitcoinPubkey  = CBitcoinAddress_impl<CHexAddress, VERHexAddress>; // P2PK '0x'
using CBitcoinAddress = CBitcoinAddress_impl<CBase58Data, VERBase58>; // P2PKH 'S'
using CScriptAddress  = CBitcoinAddress_impl<CBase58Data, VERBase58>; // P2SH 'A'
using CWitnessAddress = CBitcoinAddress_impl<CBech32Data, VERBech32>; // P2WPKH 'sora'
using CDaoAddress     = CBitcoinAddress_impl<CHexAddress, VERHexAddress>; // atomic swap custom op_code '0x'

/** A base58-encoded secret key */
template <typename ENC, typename VER>
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

        ENC::SetData(128 + (args_bool::fTestNet ? VER::PUBKEY_ADDRESS_TEST : VER::PUBKEY_ADDRESS), &vchSecret[0], vchSecret.size());
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
        case (128 + VER::PUBKEY_ADDRESS):
            break;
        case (128 + VER::PUBKEY_ADDRESS_TEST):
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
using CBitcoinSecHex = CBitcoinSecret_impl<CHexAddress, VERHexAddress>;
using CBitcoinSecret = CBitcoinSecret_impl<CBase58Data, VERBase58>;
using CWitnessSecret = CBitcoinSecret_impl<CBech32Data, VERBech32>;

namespace key_io {

CFirmKey DecodeSecret(const std::string &str);
std::string EncodeSecret(const CFirmKey &key);

CExtPubKey DecodeExtPubKey(const std::string &str);
std::string EncodeExtPubKey(const CExtPubKey &extpubkey);

CExtFirmKey DecodeExtKey(const std::string &str);
std::string EncodeExtKey(const CExtFirmKey &extkey);

std::string EncodeDestination(const CTxDestination &dest);
CTxDestination DecodeDestination(const std::string &str);
bool IsValidDestinationString(const std::string &str);
bool IsValidDestinationString(const std::string &str, const CChainParams &params);

} // namespace key_io

#endif // BITCOIN_KEY_IO_H
