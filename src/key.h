// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef BITCOIN_KEY_H
#define BITCOIN_KEY_H

#include <stdexcept>
#include <vector>

#include "allocators.h"
#include "serialize.h"
#include "uint256.h"
#include "hash.h"
#include "bignum.h"
#include "ies.h"

#include <openssl/ec.h> // for EC_KEY definition

// secp160k1
// const unsigned int PRIVATE_KEY_SIZE = 192;
// const unsigned int PUBLIC_KEY_SIZE  = 41;
// const unsigned int SIGNATURE_SIZE   = 48;
//
// secp192k1
// const unsigned int PRIVATE_KEY_SIZE = 222;
// const unsigned int PUBLIC_KEY_SIZE  = 49;
// const unsigned int SIGNATURE_SIZE   = 57;
//
// secp224k1
// const unsigned int PRIVATE_KEY_SIZE = 250;
// const unsigned int PUBLIC_KEY_SIZE  = 57;
// const unsigned int SIGNATURE_SIZE   = 66;
//
// secp256k1:
// const unsigned int PRIVATE_KEY_SIZE = 279;
// const unsigned int PUBLIC_KEY_SIZE  = 65;
// const unsigned int SIGNATURE_SIZE   = 72;
//
// see www.keylength.com
// script supports up to 75 for single byte push

class key_error : public std::runtime_error
{
public:
    explicit key_error(const std::string& str) : std::runtime_error(str) {}
};

/** A reference to a CKey: the Hash160 of its serialized public key */
class CKeyID : public uint160
{
public:
    CKeyID() : uint160(0) {}
    CKeyID(const uint160 &in) : uint160(in) {}
};

/** A reference to a CScript: the Hash160 of its serialization (see script.h) */
class CScriptID : public uint160
{
public:
    CScriptID() : uint160(0) {}
    CScriptID(const uint160 &in) : uint160(in) {}
};

//
// 1, An encapsulated OpenSSL Elliptic Curve key (public)
// 32Bytes or 32Bytes + 32Bytes PublicKey
// The signature is 1 byte at the beginning. so 33Bytes or 65 Bytes.
// CoinAddress to use when sending coins is converted from CPubKey(65 Bytes) to CBitcoinAddress.
//
class CPubKey
{
private:
    /**
     * Just store the serialized data.
     * Its length can very cheaply be computed from the first byte.
     */
    unsigned char vbytes[65];

    //! Compute the length of a pubkey with a given first byte.
    unsigned int static GetLen(unsigned char chHeader) {
        if (chHeader == 2 || chHeader == 3) {
            return 33;
        }
        if (chHeader == 4 || chHeader == 6 || chHeader == 7) {
            return 65;
        }
        return 0;
    }

    void Invalidate() {        // Set this key data to be invalid
        vbytes[0] = 0xFF;
    }

public:
    // Construct an invalid public key.
    CPubKey() {
        Invalidate();
    }
    CPubKey(const CPubKey &key) {
        *this = key;
    }

    CPubKey &operator=(const CPubKey &key) {
        ::memcpy(vbytes, key.vbytes, sizeof(vbytes));
        return *this;
    }
    bool operator==(const CPubKey &key) const {
        return ((vbytes[0] == key.vbytes[0]) && (::memcmp(vbytes, key.vbytes, size()) == 0));
    }
    bool operator!=(const CPubKey &key) const {
        return !(*this == key);
    }
    bool operator<(const CPubKey &key) const {
        return ((vbytes[0] < key.vbytes[0]) || ((vbytes[0] == key.vbytes[0]) && (::memcmp(vbytes, key.vbytes, size()) < 0)));
    }

    template <typename T>
    CPubKey(const T pbegin, const T pend) {
        Set(pbegin, pend);
    }

    CPubKey(const std::vector<unsigned char> &vch) {
        Set(vch.begin(), vch.end());
    }

    // Initialize a public key using begin/end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend) {
        int len = (pend == pbegin) ? 0 : CPubKey::GetLen(pbegin[0]);
        if (len && len == (pend - pbegin)) {
            ::memcpy(vbytes, (unsigned char *)&pbegin[0], len);
        } else {
            Invalidate();
        }
    }

    void Set(const std::vector<unsigned char> &vch) {
        Set(vch.begin(), vch.end());
    }

    // Read-only vector-like interface to the data.
    unsigned int size() const { return CPubKey::GetLen(vbytes[0]); }
    const unsigned char *begin() const { return vbytes; }
    const unsigned char *end() const { return vbytes + size(); }
    const unsigned char &operator[](unsigned int pos) const { return vbytes[pos]; }

    //! Implement serialization, as if this was a byte vector.
    unsigned int GetSerializeSize(int nType, int nVersion) const {
        return size() + 1;
    }
    template <typename Stream>
    void Serialize(Stream &s, int nType, int nVersion) const {
        unsigned int len = size();
        compact_size::manage::WriteCompactSize(s, len);
        s.write((char *)vbytes, len);
    }
    template <typename Stream>
    void Unserialize(Stream &s, int nType, int nVersion) {
        unsigned int len = compact_size::manage::ReadCompactSize(s);
        if (len <= 65) {
            s.read((char *)vbytes, len);
        } else {
            // invalid pubkey, skip available data
            char dummy;
            while (len--)
            {
                s.read(&dummy, 1);
            }
            Invalidate();
        }
    }

    CKeyID GetID() const {
        return CKeyID(hash_basis::Hash160(vbytes, vbytes + size()));
    }

    uint256 GetHash() const {
        return hash_basis::Hash(vbytes, vbytes + size());
    }

    //!! Check syntactic correctness. This is consensus critical as CheckSig() calls it!
    bool IsValid() const {
        return size() > 0;
    }

    //! fully validate whether this is a valid public key (more expensive than IsValid())
    bool IsFullyValid() const {
        const unsigned char *pbegin = &vbytes[0];
        EC_KEY *pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (o2i_ECPublicKey(&pkey, &pbegin, size())) {
            EC_KEY_free(pkey);
            return true;
        }
        return false;
    }

    //! Check whether this is a compressed public key.
    bool IsCompressed() const {
        return size() == 33;
    }

    // Verify (Check only)
    bool Verify(const uint256 &hash, const std::vector<unsigned char> &vchSig) const;
    static bool VerifyCompact(uint256 hash, const std::vector<unsigned char> &vchSig);    // [static] CPubKey SetCompactSignature check only.

    bool SetCompactSignature(uint256 hash, const std::vector<unsigned char> &vchSig);

    // Reserialize to DER
    static bool ReserealizeSignature(std::vector<unsigned char> &vchSig);

    // Encrypt data
    void EncryptData(const std::vector<unsigned char> &data, std::vector<unsigned char> &encrypted) const;
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
    bool Sign(uint256 hash, std::vector<unsigned char> &vchSig);

    // create a compact signature (65 bytes), which allows reconstructing the used public key
    // The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
    // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
    //                  0x1D = second key with even y, 0x1E = second key with odd y
    bool SignCompact(uint256 hash, std::vector<unsigned char> &vchSig);

    bool IsValid() const;

    // Check whether an element of a signature (r or s) is valid.
    static bool CheckSignatureElement(const unsigned char *vch, int len, bool half);

    // Decrypt data
    void DecryptData(const std::vector<unsigned char>& encrypted, std::vector<unsigned char> &data);
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
    bool getBytes(std::vector<unsigned char> &vchBytes) {
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
            printf("CPoint::ECMUL() : EC_POINT_mul failed");
            return false;
        }
        return true;
    }

    // Calculate G*m + q
    bool ECMULGEN(const CBigNum &bnMultiplier, const CPoint &qPoint) {
        if (! EC_POINT_mul(group, point, &bnMultiplier, qPoint.point, BN_value_one(), NULL)) {
            printf("CPoint::ECMULGEN() : EC_POINT_mul failed.");
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
    CMalleablePubKey(const std::vector<unsigned char> &vchPubKeyPair) { setvch(vchPubKeyPair); }
    CMalleablePubKey(const std::string &strMalleablePubKey) { SetString(strMalleablePubKey); }
    CMalleablePubKey(const CPubKey &pubKeyInL, const CPubKey &pubKeyInH) : pubKeyL(pubKeyInL), pubKeyH(pubKeyInH) {}

    IMPLEMENT_SERIALIZE(
        READWRITE(this->pubKeyL);
        READWRITE(this->pubKeyH);
    )

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

    bool setvch(const std::vector<unsigned char> &vchPubKeyPair) {
        CDataStream ssKey(vchPubKeyPair, SER_NETWORK, version::PROTOCOL_VERSION);
        ssKey >> *this;

        return IsValid();
    }
    std::vector<unsigned char> Raw() const {
        CDataStream ssKey(SER_NETWORK, version::PROTOCOL_VERSION);
        ssKey << *this;

        std::vector<unsigned char> vch(ssKey.begin(), ssKey.end());
        return vch;
    }

    CPubKey &GetL() { return pubKeyL; }
    CPubKey &GetH() { return pubKeyH; }

    std::string ToString() const;
    bool SetString(const std::string &strMalleablePubKey);
    void GetVariant(CPubKey &R, CPubKey &vchPubKeyVariant) const;
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

    IMPLEMENT_SERIALIZE(
        READWRITE(vchSecretL);
        READWRITE(vchSecretH);
    )

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
};

class CMalleableKeyView
{
private:
    CSecret vchSecretL;
    CPubKey vchPubKeyH;

public:
    CMalleableKeyView() {};
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

    IMPLEMENT_SERIALIZE(
        READWRITE(vchSecretL);
        READWRITE(vchPubKeyH);
    )

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
};

#endif
//@
