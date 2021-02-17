// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEY_H
#define BITCOIN_KEY_H

#include <stdexcept>
#include <vector>
#include <allocator/allocators.h>
#include <serialize.h>
#include <uint256.h>
#include <hash.h>
#include <bignum.h>
#include <ies.h>
#include <key/pubkey.h>
#include <openssl/ec.h> // for EC_KEY definition

class CScript;

class key_error : public std::runtime_error
{
public:
    explicit key_error(const std::string& str) : std::runtime_error(str) {}
};

/** A reference to a CScript: the Hash160 of its serialization (see script.h) */
class CScriptID : public uint160
{
public:
    CScriptID() : uint160(0) {}
    explicit CScriptID(const CScript &in);
    CScriptID(const uint160 &in) : uint160(in) {}
};

//////////////////////////////////////////////////////////////////////////////////
// secure_allocator is defined in allocators.h
//////////////////////////////////////////////////////////////////////////////////

/** 2, CPrivKey is a serialized private key, with all parameters included (279 bytes) **/
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CPrivKey;

/** 3, CSecret is a serialization of just the secret parameter (must be 32 bytes) **/
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CSecret;

/** [A(1`3)] An encapsulated OpenSSL Elliptic Curve key (private) **/
/** The private key includes the secret key as well as the public key. **/
class CKey
{
protected:
    EC_KEY *pkey;
    bool fSet;

public:
    CKey() {
        pkey = NULL;
        Reset();
    }
    CKey(const CKey &b) {
        pkey = EC_KEY_dup(b.pkey);
        if (pkey == NULL) {
            throw key_error("CKey::CKey(const CKey &) : EC_KEY_dup failed");
        }
        fSet = b.fSet;
    }
    CKey(const CSecret &b, bool fCompressed = true) {
        pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (pkey == NULL) {
            throw key_error("CKey::CKey(const CSecret &, bool) : EC_KEY_dup failed");
        }
        SetSecret(b, fCompressed);
    }
    CKey &operator=(const CKey &b) {
        if (! EC_KEY_copy(pkey, b.pkey)) {
            throw key_error("CKey::operator=(const CKey &) : EC_KEY_copy failed");
        }
        fSet = b.fSet;
        return *this;
    }
    ~CKey() {
        if (pkey != NULL) {
            EC_KEY_free(pkey);
        }
    }
    void Reset() {
        fSet = false;
        if (pkey != NULL) {
            EC_KEY_free(this->pkey);
        }
        pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (pkey == NULL) {
            throw key_error("CKey::Reset() : EC_KEY_new_by_curve_name failed");
        }
    }
    bool IsNull() const {
        return !fSet;
    }
    bool IsCompressed() const {
        return (EC_KEY_get_conv_form(pkey) == POINT_CONVERSION_COMPRESSED);
    }
    void SetCompressedPubKey(bool fCompressed = true) {
        EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
    }

    // [GET] Key information (Secret, Private, Public)
    CSecret GetSecret(bool &fCompressed) const;
    CSecret GetSecret() const {
        bool fCompressed;
        return GetSecret(fCompressed);
    }
    CPrivKey GetPrivKey() const;
    CPubKey GetPubKey() const;

    // [SET] Key create
    void MakeNewKey(bool fCompressed = true);
    bool SetPrivKey(const CPrivKey &vchPrivKey);
    bool SetSecret(const CSecret &vchSecret, bool fCompressed = true);

    bool WritePEM(BIO *streamObj, const SecureString &strPassKey) const;
    bool Sign(uint256 hash, key_vector &vchSig);

    // create a compact signature (65 bytes), which allows reconstructing the used public key
    // The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
    // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
    //                  0x1D = second key with even y, 0x1E = second key with odd y
    bool SignCompact(uint256 hash, std::vector<unsigned char> &vchSig);

    bool IsValid() const;

    // Check whether an element of a signature (r or s) is valid.
    static bool CheckSignatureElement(const unsigned char *vch, int len, bool half);

    // Decrypt data
    void DecryptData(const key_vector &encrypted, key_vector &data);
};

class CPoint
{
private:
    EC_POINT *point;
    EC_GROUP *group;
    BN_CTX *ctx;

public:
    CPoint() {
        std::string err;
        group = NULL;
        point = NULL;
        ctx   = NULL;

        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (! group) {
            err = "EC_KEY_new_by_curve_name failed.";
            goto finish;
        }

        this->point = EC_POINT_new(group);
        if (! point) {
            err = "EC_POINT_new failed.";
            goto finish;
        }

        ctx = BN_CTX_new();
        if (! ctx) {
            err = "BN_CTX_new failed.";
            goto finish;
        }

        return;

    finish:
        if (group) { EC_GROUP_free(group); }
        if (point) { EC_POINT_free(point); }
        throw std::runtime_error(std::string("CPoint::CPoint() :  - ") + err);
    }
    bool operator!=(const CPoint &a) {
        if (EC_POINT_cmp(group, point, a.point, ctx) != 0) {
            return true;
        }
        return false;
    }
    ~CPoint() {
        if (point) { EC_POINT_free(point); }
        if (group) { EC_GROUP_free(group); }
        if (ctx) { BN_CTX_free(ctx); }
    }

    // Initialize from octets stream
    bool setBytes(const std::vector<unsigned char> &vchBytes) {
        if (! EC_POINT_oct2point(group, point, &vchBytes[0], vchBytes.size(), ctx)) {
            return false;
        }
        return true;
    }

    // Initialize from pubkey
    bool setPubKey(const CPubKey &key) {
        std::vector<uint8_t> vchPubKey(key.begin(), key.end());
        return setBytes(vchPubKey);
    }

    // Serialize to octets stream
    bool getBytes(key_vector &vchBytes) {
        size_t nSize = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        vchBytes.resize(nSize);
        if (! (nSize == EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, &vchBytes[0], nSize, ctx))) {
            return false;
        }
        return true;
    }

    // ECC multiplication by specified multiplier
    bool ECMUL(const CBigNum &bnMultiplier) {
        if (! EC_POINT_mul(group, point, NULL, point, &bnMultiplier, NULL)) {
            logging::LogPrintf("CPoint::ECMUL() : EC_POINT_mul failed");
            return false;
        }
        return true;
    }

    // Calculate G*m + q
    bool ECMULGEN(const CBigNum &bnMultiplier, const CPoint &qPoint) {
        if (! EC_POINT_mul(group, point, &bnMultiplier, qPoint.point, BN_value_one(), NULL)) {
            logging::LogPrintf("CPoint::ECMULGEN() : EC_POINT_mul failed.");
            return false;
        }
        return true;
    }

    bool IsInfinity() { return EC_POINT_is_at_infinity(group, point) != 0; }
};

class CMalleablePubKey
{
private:
    CPubKey pubKeyL;
    CPubKey pubKeyH;
    friend class CMalleableKey;

    static const unsigned char CURRENT_VERSION = 1;

public:
    CMalleablePubKey() {}
    CMalleablePubKey(const CMalleablePubKey &mpk) {
        pubKeyL = mpk.pubKeyL;
        pubKeyH = mpk.pubKeyH;
    }
    CMalleablePubKey(const key_vector &vchPubKeyPair) { setvch(vchPubKeyPair); }
    CMalleablePubKey(const std::string &strMalleablePubKey) { SetString(strMalleablePubKey); }
    CMalleablePubKey(const CPubKey &pubKeyInL, const CPubKey &pubKeyInH) : pubKeyL(pubKeyInL), pubKeyH(pubKeyInH) {}

    bool IsValid() const {
        return pubKeyL.IsValid() && pubKeyH.IsValid();
    }

    bool operator==(const CMalleablePubKey &b) {
        return pubKeyL == b.pubKeyL && pubKeyH == b.pubKeyH;
    }
    bool operator!=(const CMalleablePubKey &b) { return !(*this == b); }
    CMalleablePubKey &operator=(const CMalleablePubKey &mpk) {
        pubKeyL = mpk.pubKeyL;
        pubKeyH = mpk.pubKeyH;
        return *this;
    }

    CKeyID GetID() const {
        return pubKeyL.GetID();
    }

    bool setvch(const key_vector &vchPubKeyPair) {
        CDataStream ssKey(vchPubKeyPair, SER_NETWORK, version::PROTOCOL_VERSION);
        ssKey >> *this;

        return IsValid();
    }
    key_vector Raw() const {
        CDataStream ssKey(SER_NETWORK, version::PROTOCOL_VERSION);
        ssKey << *this;

        key_vector vch(ssKey.begin(), ssKey.end());
        return vch;
    }

    CPubKey &GetL() { return pubKeyL; }
    CPubKey &GetH() { return pubKeyH; }

    std::string ToString() const;
    bool SetString(const std::string &strMalleablePubKey);
    void GetVariant(CPubKey &R, CPubKey &vchPubKeyVariant) const;

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(this->pubKeyL);
        READWRITE(this->pubKeyH);
    }
};

class CMalleableKey
{
private:
    CSecret vchSecretL;
    CSecret vchSecretH;

    friend class CMalleableKeyView;

public:
    CMalleableKey() { Reset(); }
    CMalleableKey(const CMalleableKey &b) { SetSecrets(b.vchSecretL, b.vchSecretH); }
    CMalleableKey(const CSecret &L, const CSecret &H) { SetSecrets(L, H); }
    ~CMalleableKey() {}

    std::string ToString() const;
    bool SetString(const std::string &strMalleablePubKey);
    std::vector<unsigned char> Raw() const {
        CDataStream ssKey(SER_NETWORK, version::PROTOCOL_VERSION);
        ssKey << *this;
        std::vector<unsigned char> vch(ssKey.begin(), ssKey.end());
        return vch;
    }
    CMalleableKey &operator=(const CMalleableKey &mk) {
        vchSecretL = mk.vchSecretL;
        vchSecretH = mk.vchSecretH;
        return *this;
    }

    void Reset() {
        vchSecretL.clear();
        vchSecretH.clear();
    }
    void MakeNewKeys() {
        Reset();

        CKey keyL, keyH;
        keyL.MakeNewKey();
        keyH.MakeNewKey();

        vchSecretL = keyL.GetSecret();
        vchSecretH = keyH.GetSecret();
    }
    bool IsNull() const {
        return vchSecretL.size() != 32 || vchSecretH.size() != 32;
    }
    bool IsValid() const { return !IsNull() && GetMalleablePubKey().IsValid(); }
    bool SetSecrets(const CSecret &pvchSecretL, const CSecret &pvchSecretH) {
        Reset();
        CKey keyL(pvchSecretL);
        CKey keyH(pvchSecretH);
        if (! keyL.IsValid() || ! keyH.IsValid()) {
            return false;
        } else {
            vchSecretL = pvchSecretL;
            vchSecretH = pvchSecretH;
            return true;
        }
    }

    CSecret GetSecretL() const { return vchSecretL; }
    CSecret GetSecretH() const { return vchSecretH; }

    CKeyID GetID() const {
        return GetMalleablePubKey().GetID();
    }
    CMalleablePubKey GetMalleablePubKey() const {
        CKey L(vchSecretL), H(vchSecretH);
        return CMalleablePubKey(L.GetPubKey(), H.GetPubKey());
    }

    bool CheckKeyVariant(const CPubKey &R, const CPubKey &vchPubKeyVariant) const;
    bool CheckKeyVariant(const CPubKey &R, const CPubKey &vchPubKeyVariant, CKey &privKeyVariant) const;

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(vchSecretL);
        READWRITE(vchSecretH);
    }
};

class CMalleableKeyView
{
private:
    CSecret vchSecretL;
    CPubKey vchPubKeyH;

public:
    CMalleableKeyView() {}
    CMalleableKeyView(const CMalleableKey &b) {
        if (b.vchSecretL.size() != 32) {
            throw key_error("CMalleableKeyView::CMalleableKeyView() : L size must be 32 bytes");
        }
        if (b.vchSecretH.size() != 32) {
            throw key_error("CMalleableKeyView::CMalleableKeyView() : H size must be 32 bytes");
        }
        vchSecretL = b.vchSecretL;

        CKey H(b.vchSecretH);
        vchPubKeyH = H.GetPubKey();
    }
    CMalleableKeyView(const std::string &strMalleableKey) { SetString(strMalleableKey); }

    CMalleableKeyView(const CMalleableKeyView &b) {
        vchSecretL = b.vchSecretL;
        vchPubKeyH = b.vchPubKeyH;
    }
    CMalleableKeyView &operator=(const CMalleableKey &b) {
        vchSecretL = b.vchSecretL;

        CKey H(b.vchSecretH);
        vchPubKeyH = H.GetPubKey();
        return *this;
    }
    ~CMalleableKeyView() {}

    bool IsValid() const { return vchSecretL.size() == 32 && GetMalleablePubKey().IsValid(); }

    std::string ToString() const;
    bool SetString(const std::string &strMalleablePubKey);
    std::vector<unsigned char> Raw() const {
        CDataStream ssKey(SER_NETWORK, version::PROTOCOL_VERSION);
        ssKey << *this;
        std::vector<unsigned char> vch(ssKey.begin(), ssKey.end());
        return vch;
    }
    CMalleableKeyView &operator=(const CMalleableKeyView &mkv) {
        vchSecretL = mkv.vchSecretL;
        vchPubKeyH = mkv.vchPubKeyH;
        return *this;
    }

    CKeyID GetID() const {
        return GetMalleablePubKey().GetID();
    }
    CMalleablePubKey GetMalleablePubKey() const {
        CKey keyL(vchSecretL);
        return CMalleablePubKey(keyL.GetPubKey(), vchPubKeyH);
    }
    CMalleableKey GetMalleableKey(const CSecret &vchSecretH) const {
        return CMalleableKey(vchSecretL, vchSecretH);
    }

    bool operator <(const CMalleableKeyView &kv) const { return vchPubKeyH.GetID() < kv.vchPubKeyH.GetID(); }
    bool CheckKeyVariant(const CPubKey &R, const CPubKey &vchPubKeyVariant) const;

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(vchSecretL);
        READWRITE(vchPubKeyH);
    }
};

#endif
