// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//

//
// Why base-58 instead of standard base-64 encoding?
// - Don't want 0OIl characters that look the same in some fonts and
//      could be used to create visually identical looking account numbers.
// - A string with non-alphanumeric characters is not as easily accepted as an account number.
// - E-mail usually won't line-break if there's no punctuation to break at.
// - Double-clicking selects the whole number as one word if it's all alphanumeric.
//
#ifndef BITCOIN_BASE58_H
#define BITCOIN_BASE58_H

#include <string>
#include <vector>
#include <openssl/crypto.h> // for OPENSSL_cleanse()
#include "bignum.h"
#include "key.h"
#include "script.h"

namespace base58
{
    const char *const pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    class manage : private no_instance
    {
    private:
        // Decode a base58-encoded string psz into byte vector vchRet
        static bool DecodeBase58(const char *psz, std::vector<unsigned char> &vchRet);

    public:
        // Encode a byte sequence as a base58-encoded string
        static std::string EncodeBase58(const unsigned char *pbegin, const unsigned char *pend);

        // Encode a byte vector as a base58-encoded string
        static std::string EncodeBase58(const std::vector<unsigned char> &vch);

        // Decode a base58-encoded string str into byte vector vchRet
        static bool DecodeBase58(const std::string &str, std::vector<unsigned char> &vchRet);

        // [4 bytes hash check] Encode a byte vector to a base58-encoded string, including checksum
        static std::string EncodeBase58Check(const std::vector<unsigned char> &vchIn);

        // [4 bytes hash check] Decode a base58-encoded string psz or str that includes a checksum, into byte vector vchRet
        static bool DecodeBase58Check(const char *psz, std::vector<unsigned char> &vchRet);
        static bool DecodeBase58Check(const std::string &str, std::vector<unsigned char> &vchRet);
    };
}

/** Base class for all base58-encoded data */
class CBase58Data
{
private:
    CBase58Data(const CBase58Data &);
    CBase58Data &operator=(const CBase58Data &);

    // the version byte
    unsigned char nVersion;

    // the actually encoded data
    std::vector<unsigned char> vchData;

protected:
    CBase58Data() {
        nVersion = 0;
        vchData.clear();
    }
    virtual ~CBase58Data() {
        // zero the memory, as it may contain sensitive data
        if (! vchData.empty()) {
            OPENSSL_cleanse(&vchData[0], vchData.size());
        }
    }

    void SetData(int nVersionIn, const void *pdata, size_t nSize) {
        nVersion = nVersionIn;
        vchData.resize(nSize);
        if (! vchData.empty()) {
            ::memcpy(&vchData[0], pdata, nSize);
        }
    }
    void SetData(int nVersionIn, const unsigned char *pbegin, const unsigned char *pend) {
        SetData(nVersionIn, (void *)pbegin, pend - pbegin);
    }

    unsigned int getVersion() const { return nVersion; }
    const std::vector<unsigned char> &getvchData() const { return vchData; }
    void setvchData(const unsigned char &in) { vchData.push_back(in); }
    const unsigned char *getvchArray() const { return &vchData[0]; }
    bool Set(const CBase58Data &dest) {
        nVersion = dest.nVersion;
        vchData = dest.vchData;
        return true;
    }

public:
    bool SetString(const char *psz) {
        std::vector<unsigned char> vchTemp;
        base58::manage::DecodeBase58Check(psz, vchTemp);
        if (vchTemp.empty()) {
            vchData.clear();
            nVersion = 0;
            return false;
        } else {
            nVersion = vchTemp[0];
            vchData.resize(vchTemp.size() - 1);
            if (! vchData.empty()) {
                ::memcpy(&vchData[0], &vchTemp[1], vchData.size());
            }
            OPENSSL_cleanse(&vchTemp[0], vchData.size());
            return true;
        }
    }
    bool SetString(const std::string &str) {
        return SetString(str.c_str());
    }

    std::string ToString() const {
        std::vector<unsigned char> vch(1, nVersion);
        vch.insert(vch.end(), vchData.begin(), vchData.end());
        return base58::manage::EncodeBase58Check(vch);
    }

    const std::vector<unsigned char> &GetData() const {
        return vchData;
    }

    int CompareTo(const CBase58Data &b58) const {
        if (nVersion < b58.nVersion) { return -1; }
        if (nVersion > b58.nVersion) { return  1; }
        if (vchData < b58.vchData)   { return -1; }
        if (vchData > b58.vchData)   { return  1; }
        return 0;
    }

    bool operator==(const CBase58Data &b58) const { return CompareTo(b58) == 0; }
    bool operator<=(const CBase58Data &b58) const { return CompareTo(b58) <= 0; }
    bool operator>=(const CBase58Data &b58) const { return CompareTo(b58) >= 0; }
    bool operator< (const CBase58Data &b58) const { return CompareTo(b58) <  0; }
    bool operator> (const CBase58Data &b58) const { return CompareTo(b58) >  0; }
};

/** base58-encoded Bitcoin addresses.
 * Public-key-hash-addresses have version 0 (or 111 testnet).
 * The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
 * Script-hash-addresses have version 5 (or 196 testnet).
 * The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
 * Pubkey-pair-addresses have version 1 (or 6 testnet)
 * The data vector contains a serialized copy of two compressed ECDSA secp256k1 public keys.
 */
class CBitcoinAddress : public CBase58Data
{
public:
    enum
    {
        PUBKEY_PAIR_ADDRESS = 1,
        PUBKEY_ADDRESS = 63,
        SCRIPT_ADDRESS = 20,
        PUBKEY_PAIR_ADDRESS_TEST = 6,
        PUBKEY_ADDRESS_TEST = 145,
        SCRIPT_ADDRESS_TEST = 196
    };

    CBitcoinAddress &operator=(const CBitcoinAddress &obj) {
        CBase58Data::Set(obj);
        return *this;
    }

    CBitcoinAddress() {}
    CBitcoinAddress(const CBitcoinAddress &obj) {
        CBase58Data::Set(obj);
    }
    CBitcoinAddress(const CTxDestination &dest) {
        Set(dest);
    }
    CBitcoinAddress(const CMalleablePubKey &mpk) {
        Set(mpk);
    }
    CBitcoinAddress(const std::string &strAddress) {
        SetString(strAddress);
    }
    CBitcoinAddress(const char *pszAddress) {
        SetString(pszAddress);
    }

    bool Set(const CKeyID &id) {
        SetData(args_bool::fTestNet ? PUBKEY_ADDRESS_TEST : PUBKEY_ADDRESS, &id, 20);
        return true;
    }
    bool Set(const CScriptID &id) {
        SetData(args_bool::fTestNet ? SCRIPT_ADDRESS_TEST : SCRIPT_ADDRESS, &id, 20);
        return true;
    }
    bool Set(const CTxDestination &dest);    // base58.cpp
    bool Set(const CMalleablePubKey &mpk) {
        std::vector<unsigned char> vchPubkeyPair = mpk.Raw();
        SetData(args_bool::fTestNet ? PUBKEY_PAIR_ADDRESS_TEST : PUBKEY_PAIR_ADDRESS, &vchPubkeyPair[0], 68);
        return true;
    }

    bool IsValid() const;
    CTxDestination Get() const;
    bool GetKeyID(CKeyID &keyID) const;
    bool IsScript() const;
    bool IsPubKey() const;
    bool IsPair() const;
};

class CBitcoinAddressVisitor : public boost::static_visitor<bool>
{
private:
    CBitcoinAddressVisitor();
    CBitcoinAddressVisitor(const CBitcoinAddressVisitor &);
    CBitcoinAddressVisitor &operator=(const CBitcoinAddressVisitor &);

    CBitcoinAddress *addr;
public:
    CBitcoinAddressVisitor(CBitcoinAddress *addrIn) : addr(addrIn) {}
    bool operator()(const CKeyID &id) const                   { return addr->Set(id); }
    bool operator()(const CScriptID &id) const                { return addr->Set(id); }
    bool operator()(const CMalleablePubKey &mpk) const        { return addr->Set(mpk); }
    bool operator()(const CNoDestination &id) const           { return false; }
};

/** A base58-encoded secret key */
class CBitcoinSecret : public CBase58Data
{
private:
    CBitcoinSecret(const CBitcoinSecret &);
    CBitcoinSecret &operator=(const CBitcoinSecret &);

public:
    CBitcoinSecret() {}
    CBitcoinSecret(const CSecret &vchSecret, bool fCompressed) {
        SetSecret(vchSecret, fCompressed);
    }

    void SetSecret(const CSecret &vchSecret, bool fCompressed) {
        assert(vchSecret.size() == 32);

        SetData(128 + (args_bool::fTestNet ? CBitcoinAddress::PUBKEY_ADDRESS_TEST : CBitcoinAddress::PUBKEY_ADDRESS), &vchSecret[0], vchSecret.size());
        if (fCompressed) {
            setvchData(1);
        }
    }
    CSecret GetSecret(bool &fCompressedOut) {
        CSecret vchSecret;
        vchSecret.resize(32);

        ::memcpy(&vchSecret[0], getvchArray(), 32);
        fCompressedOut = (getvchData().size() == 33);
        return vchSecret;
    }

    bool IsValid() const {
        bool fExpectTestNet = false;
        switch(getVersion())
        {
        case (128 + CBitcoinAddress::PUBKEY_ADDRESS):
            break;
        case (128 + CBitcoinAddress::PUBKEY_ADDRESS_TEST):
            fExpectTestNet = true;
            break;
        default:
            return false;
        }
        return fExpectTestNet == args_bool::fTestNet && (getvchData().size() == 32 || (getvchData().size() == 33 && getvchData()[32] == 1));
    }
    bool SetString(const char *pszSecret) {
        return CBase58Data::SetString(pszSecret) && IsValid();
    }
    bool SetString(const std::string &strSecret) {
        return SetString(strSecret.c_str());
    }
};

#endif
//@
