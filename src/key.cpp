// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <map>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <key.h>
#include <key/pubkey.h>
#include <address/base58.h>
#include <script/script.h>

CScriptID::CScriptID(const CScript &in) : uint160(hash_basis::Hash160(in.begin(), in.end())) {}

// Generate a private key from just the secret parameter
int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    EC_POINT *pub_key = NULL;

    if (! eckey) { return 0; }

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if ((ctx = BN_CTX_new()) == NULL) {
        goto err;
    }

    pub_key = EC_POINT_new(group);
    if (pub_key == NULL) {
        goto err;
    }

    if (! EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx)) {
        goto err;
    }

    EC_KEY_set_private_key(eckey,priv_key);
    EC_KEY_set_public_key(eckey,pub_key);

    ok = 1;

err:

    if (pub_key) {
        EC_POINT_free(pub_key);
    }
    if (ctx != NULL) {
        BN_CTX_free(ctx);
    }

    return(ok);
}

int CompareBigEndian(const unsigned char *c1, size_t c1len, const unsigned char *c2, size_t c2len) {
    while (c1len > c2len) {
        if (*c1) {
            return 1;
        }
        c1++;
        c1len--;
    }
    while (c2len > c1len) {
        if (*c2) {
            return -1;
        }
        c2++;
        c2len--;
    }
    while (c1len > 0) {
        if (*c1 > *c2) {
            return 1;
        }
        if (*c2 > *c1) {
            return -1;
        }
        c1++;
        c2++;
        c1len--;
    }
    return 0;
}

// Order of secp256k1's generator minus 1.
const unsigned char vchMaxModOrder[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40
};

// Half of the order of secp256k1's generator minus 1.
const unsigned char vchMaxModHalfOrder[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,
    0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
};

const unsigned char *vchZero = NULL;

bool CKey::CheckSignatureElement(const unsigned char *vch, int len, bool half) {
    return CompareBigEndian(vch, len, vchZero, 0) > 0 &&
           CompareBigEndian(vch, len, half ? vchMaxModHalfOrder : vchMaxModOrder, 32) <= 0;
}

void CKey::MakeNewKey(bool fCompressed)
{
    if (! EC_KEY_generate_key(pkey)) {
        throw key_error("CKey::MakeNewKey() : EC_KEY_generate_key failed");
    }
    SetCompressedPubKey(fCompressed);
    fSet = true;
}

bool CKey::SetPrivKey(const CPrivKey &vchPrivKey)
{
    const unsigned char* pbegin = &vchPrivKey[0];
    if (d2i_ECPrivateKey(&pkey, &pbegin, vchPrivKey.size())) {
        // In testing, d2i_ECPrivateKey can return true
        // but fill in pkey with a key that fails
        // EC_KEY_check_key, so:
        if (EC_KEY_check_key(pkey)) {
            fSet = true;
            return true;
        }
    }

    // If vchPrivKey data is bad d2i_ECPrivateKey() can
    // leave pkey in a state where calling EC_KEY_free()
    // crashes. To avoid that, set pkey to NULL and
    // leak the memory (a leak is better than a crash)
    pkey = NULL;
    Reset();
    return false;
}

bool CKey::SetSecret(const CSecret &vchSecret, bool fCompressed)
{
    EC_KEY_free(pkey);

    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (pkey == NULL) {
        throw key_error("CKey::SetSecret() : EC_KEY_new_by_curve_name failed");
    }

    if (vchSecret.size() != 32) {
        throw key_error("CKey::SetSecret() : secret must be 32 bytes");
    }

    BIGNUM *bn = BN_bin2bn(&vchSecret[0], 32, BN_new());
    if (bn == NULL) {
        throw key_error("CKey::SetSecret() : BN_bin2bn failed");
    }
    if (! EC_KEY_regenerate_key(pkey, bn)) {
        BN_clear_free(bn);
        throw key_error("CKey::SetSecret() : EC_KEY_regenerate_key failed");
    }

    BN_clear_free(bn);
    fSet = true;
    SetCompressedPubKey(fCompressed);
    return true;
}

CSecret CKey::GetSecret(bool &fCompressed) const
{
    CSecret vchRet;
    vchRet.resize(32);
    const BIGNUM *bn = EC_KEY_get0_private_key(pkey);
    if (bn == NULL) {
        throw key_error("CKey::GetSecret(bool &fCompressed) : EC_KEY_get0_private_key failed");
    }

    int nBytes = BN_num_bytes(bn);
    int n = BN_bn2bin(bn, &vchRet[32 - nBytes]);
    if (n != nBytes) {
        throw key_error("CKey::GetSecret(bool &fCompressed): BN_bn2bin failed");
    }

    fCompressed = IsCompressed();
    return vchRet;
}

bool CKey::WritePEM(BIO *streamObj, const SecureString &strPassKey) const // dumppem 4KJLA99FyqMMhjjDe7KnRXK4sjtv9cCtNS /tmp/test.pem 123
{
    EVP_PKEY *evpKey = EVP_PKEY_new();
    if (! EVP_PKEY_assign_EC_KEY(evpKey, pkey)) {
        return logging::error("CKey::WritePEM() : Error initializing EVP_PKEY instance.");
    }
    if(! PEM_write_bio_PKCS8PrivateKey(streamObj, evpKey, EVP_aes_256_cbc(), (char *)&strPassKey[0], strPassKey.size(), NULL, NULL)) {
        return logging::error("CKey::WritePEM() : Error writing private key data to stream object");
    }

    return true;
}

CPrivKey CKey::GetPrivKey() const
{
    int nSize = i2d_ECPrivateKey(pkey, NULL);
    if (! nSize) {
        throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey failed");
    }

    CPrivKey vchPrivKey(nSize, 0);
    unsigned char *pbegin = &vchPrivKey[0];
    if (i2d_ECPrivateKey(pkey, &pbegin) != nSize) {
        throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey returned unexpected size");
    }
    return vchPrivKey;
}

CPubKey CKey::GetPubKey() const
{
    int nSize = i2o_ECPublicKey(pkey, nullptr);
    if (! nSize) {
        throw key_error("CKey::GetPubKey() : i2o_ECPublicKey failed");
    }
    if(IsCompressed()) {
        if(nSize != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE) {
            throw key_error("CKey::GetPubKey() : i2o_ECPublicKey returned unexpected size");
        }
    } else {
        if(nSize != CPubKey::PUBLIC_KEY_SIZE) {
            throw key_error("CKey::GetPubKey() : i2o_ECPublicKey returned unexpected size");
        }
    }

    key_vector vchPubKey((uint32_t)nSize, (uint8_t)0);
    unsigned char *pbegin = &vchPubKey[0];
    if (i2o_ECPublicKey(pkey, &pbegin) != nSize) {
        throw key_error("CKey::GetPubKey() : i2o_ECPublicKey returned unexpected size");
    }

    return CPubKey(vchPubKey);
}

bool CKey::Sign(uint256 hash, key_vector &vchSig)
{
    vchSig.clear();
    ECDSA_SIG *sig = ECDSA_do_sign((unsigned char *)&hash, sizeof(hash), pkey);
    if (sig == NULL) {
        return false;
    }

    const EC_GROUP *group = EC_KEY_get0_group(pkey);

    CBigNum order, halforder;
    EC_GROUP_get_order(group, &order, NULL);
    BN_rshift1(&halforder, &order);
    // enforce low S values, by negating the value (modulo the order) if above order/2.
    if (BN_cmp(sig->s, &halforder) > 0) {
        BN_sub(sig->s, &order, sig->s);
    }
    unsigned int nSize = ECDSA_size(pkey);
    vchSig.resize(nSize); // Make sure it is big enough

    unsigned char *pos = &vchSig[0];
    nSize = i2d_ECDSA_SIG(sig, &pos);
    ECDSA_SIG_free(sig);
    vchSig.resize(nSize); // Shrink to fit actual size

    // Testing our new signature
    if (ECDSA_verify(0, (unsigned char *)&hash, sizeof(hash), &vchSig[0], vchSig.size(), pkey) != 1) {
        vchSig.clear();
        return false;
    }
    return true;
}

// create a compact signature (65 bytes), which allows reconstructing the used public key
// The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
// The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
//                  0x1D = second key with even y, 0x1E = second key with odd y
bool CKey::SignCompact(uint256 hash, key_vector &vchSig)
{
    bool fOk = false;
    ECDSA_SIG *sig = ECDSA_do_sign((unsigned char *)&hash, sizeof(hash), pkey);
    if (sig == NULL) {
        return false;
    }

    const EC_GROUP *group = EC_KEY_get0_group(pkey);
    CBigNum order, halforder;
    EC_GROUP_get_order(group, &order, NULL);
    BN_rshift1(&halforder, &order);
    // enforce low S values, by negating the value (modulo the order) if above order/2.
    if (BN_cmp(sig->s, &halforder) > 0) {
        BN_sub(sig->s, &order, sig->s);
    }

    vchSig.clear();
    vchSig.resize(65, 0);
    int nBitsR = BN_num_bits(sig->r);
    int nBitsS = BN_num_bits(sig->s);

    bool fCompressedPubKey = IsCompressed();
    if (nBitsR <= 256 && nBitsS <= 256) {
        int8_t nRecId = -1;
        for (int8_t i=0; i < 4; i++)
        {
            CKey keyRec;
            keyRec.fSet = true;
            keyRec.SetCompressedPubKey(fCompressedPubKey);
            if (CPubKey::ECDSA_SIG_recover_key_GFp(keyRec.pkey, sig, (unsigned char *)&hash, sizeof(hash), i, 1) == 1) {
                if (keyRec.GetPubKey() == GetPubKey()) {
                    nRecId = i;
                    break;
                }
            }
        }
        if (nRecId == -1) {
            ECDSA_SIG_free(sig);
            throw key_error("CKey::SignCompact() : unable to construct recoverable key");
        }

        vchSig[0] = nRecId + 27 + (fCompressedPubKey ? 4 : 0);
        BN_bn2bin(sig->r, &vchSig[33 - (nBitsR + 7) / 8]);
        BN_bn2bin(sig->s, &vchSig[65 - (nBitsS + 7) / 8]);
        fOk = true;
    }

    ECDSA_SIG_free(sig);
    return fOk;
}

bool CKey::IsValid() const
{
    if (! fSet) {
        return false;
    }
    if (! EC_KEY_check_key(pkey)) {
        return false;
    }

    bool fCompr;
    CSecret secret = GetSecret(fCompr);

    CKey key2;
    key2.SetSecret(secret, fCompr);

    return GetPubKey() == key2.GetPubKey();
}

//
// CMalleablePubKey
//
std::string CMalleablePubKey::ToString() const {
    CDataStream ssKey(SER_NETWORK, version::PROTOCOL_VERSION);
    ssKey << *this;

    key_vector vch(ssKey.begin(), ssKey.end());
    return base58::manage::EncodeBase58Check(vch);
}
bool CMalleablePubKey::SetString(const std::string &strMalleablePubKey) {
    key_vector vchTemp;
    if (! base58::manage::DecodeBase58Check(strMalleablePubKey, vchTemp)) {
        throw key_error("CMalleablePubKey::SetString() : Provided key data seems corrupted.");
    }
    if (vchTemp.size() != 68) {
        return false;
    }

    CDataStream ssKey(vchTemp, SER_NETWORK, version::PROTOCOL_VERSION);
    ssKey >> *this;

    return IsValid();
}

void CMalleablePubKey::GetVariant(CPubKey &R, CPubKey &vchPubKeyVariant) const
{
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (eckey == NULL) {
        throw key_error("CMalleablePubKey::GetVariant() : EC_KEY_new_by_curve_name failed");
    }

    // Use standard key generation function to get r and R values.
    //
    // r will be presented by private key;
    // R is ECDSA public key which calculated as G*r
    if (! EC_KEY_generate_key(eckey)) {
        throw key_error("CMalleablePubKey::GetVariant() : EC_KEY_generate_key failed");
    }

    EC_KEY_set_conv_form(eckey, POINT_CONVERSION_COMPRESSED);

    int nSize = i2o_ECPublicKey(eckey, NULL);
    if (! nSize) {
        throw key_error("CMalleablePubKey::GetVariant() : i2o_ECPublicKey failed");
    }

    key_vector vchPubKey((uint32_t)nSize, (uint8_t)0);
    unsigned char *pbegin_R = &vchPubKey[0];

    if (i2o_ECPublicKey(eckey, &pbegin_R) != nSize) {
        throw key_error("CMalleablePubKey::GetVariant() : i2o_ECPublicKey returned unexpected size");
    }

    // R = G*r
    R = CPubKey(vchPubKey);

    // OpenSSL BIGNUM representation of r value
    CBigNum bnr = *(CBigNum *)EC_KEY_get0_private_key(eckey);
    EC_KEY_free(eckey);

    CPoint point;
    if (! point.setPubKey(pubKeyL)) {
        throw key_error("CMalleablePubKey::GetVariant() : Unable to decode L value");
    }

    // Calculate L*r
    point.ECMUL(bnr);

    key_vector vchLr;
    if (! point.getBytes(vchLr)) {
        throw key_error("CMalleablePubKey::GetVariant() : Unable to convert Lr value");
    }

    // Calculate Hash(L*r) and then get a BIGNUM representation of hash value.
    CBigNum bnHash;
    bnHash.setuint160(hash_basis::Hash160(vchLr));

    CPoint pointH;
    pointH.setPubKey(pubKeyH);

    CPoint P;
    // Calculate P = Hash(L*r)*G + H
    P.ECMULGEN(bnHash, pointH);

    if (P.IsInfinity()) {
        throw key_error("CMalleablePubKey::GetVariant() : P is infinity");
    }

    key_vector vchResult;
    if(! P.getBytes(vchResult)) {
        throw key_error("CMalleablePubKey::GetVariant() : vchResult failed");
    }

    vchPubKeyVariant = CPubKey(vchResult);
}

//
// CMalleableKey
//
// Check ownership
bool CMalleableKey::CheckKeyVariant(const CPubKey &R, const CPubKey &vchPubKeyVariant) const
{
    if (IsNull()) {
        throw key_error("CMalleableKey::CheckKeyVariant() : Attempting to run on NULL key object.");
    }

    if (! R.IsValid()) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : R is invalid");
        return false;
    }

    if (! vchPubKeyVariant.IsValid()) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : public key variant is invalid");
        return false;
    }

    CPoint point_R;
    if (! point_R.setPubKey(R)) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : Unable to decode R value");
        return false;
    }

    CKey H(vchSecretH);
    CPubKey vchPubKeyH = H.GetPubKey();

    CPoint point_H;
    if (! point_H.setPubKey(vchPubKeyH)) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : Unable to decode H value");
        return false;
    }

    CPoint point_P;
    if (! point_P.setPubKey(vchPubKeyVariant)) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : Unable to decode P value");
        return false;
    }

    // Infinity points are senseless
    if (point_P.IsInfinity()) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : P is infinity");
        return false;
    }

    CBigNum bnl;
    bnl.setBytes(std::vector<unsigned char>(vchSecretL.begin(), vchSecretL.end()));

    point_R.ECMUL(bnl);

    key_vector vchRl;
    if (! point_R.getBytes(vchRl)) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : Unable to convert Rl value");
        return false;
    }

    // Calculate Hash(R*l)
    CBigNum bnHash;
    bnHash.setuint160(hash_basis::Hash160(vchRl));

    CPoint point_Ps;
    // Calculate Ps = Hash(L*r)*G + H
    point_Ps.ECMULGEN(bnHash, point_H);

    // Infinity points are senseless
    if (point_Ps.IsInfinity()) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : Ps is infinity");
        return false;
    }

    // Check ownership
    if (point_Ps != point_P) {
        return false;
    }

    return true;
}

// Check ownership and restore private key
bool CMalleableKey::CheckKeyVariant(const CPubKey &R, const CPubKey &vchPubKeyVariant, CFirmKey &privKeyVariant) const
{
    if (IsNull()) {
        throw key_error("CMalleableKey::CheckKeyVariant() : Attempting to run on NULL key object.");
    }

    if (! R.IsValid()) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : R is invalid");
        return false;
    }

    if (! vchPubKeyVariant.IsValid()) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : public key variant is invalid");
        return false;
    }

    CPoint point_R;
    if (! point_R.setPubKey(R)) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : Unable to decode R value");
        return false;
    }

    CKey H(vchSecretH);
    CPubKey vchPubKeyH = H.GetPubKey();

    CPoint point_H;
    if (! point_H.setPubKey(vchPubKeyH)) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : Unable to decode H value");
        return false;
    }

    CPoint point_P;
    if (! point_P.setPubKey(vchPubKeyVariant)) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : Unable to decode P value");
        return false;
    }

    // Infinity points are senseless
    if (point_P.IsInfinity()) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : P is infinity");
        return false;
    }

    CBigNum bnl;
    bnl.setBytes(std::vector<unsigned char>(vchSecretL.begin(), vchSecretL.end()));

    point_R.ECMUL(bnl);

    key_vector vchRl;
    if (! point_R.getBytes(vchRl)) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : Unable to convert Rl value");
        return false;
    }

    // Calculate Hash(R*l)
    CBigNum bnHash;
    bnHash.setuint160(hash_basis::Hash160(vchRl));

    CPoint point_Ps;
    // Calculate Ps = Hash(L*r)*G + H
    point_Ps.ECMULGEN(bnHash, point_H);

    // Infinity points are senseless
    if (point_Ps.IsInfinity()) {
        logging::LogPrintf("CMalleableKey::CheckKeyVariant() : Ps is infinity");
        return false;
    }

    // Check ownership
    if (point_Ps != point_P) {
        return false;
    }

    // OpenSSL BIGNUM representation of the second private key from (l, h) pair
    CBigNum bnh;
    bnh.setBytes(std::vector<unsigned char>(vchSecretH.begin(), vchSecretH.end()));

    // Calculate p = Hash(R*l) + h
    CBigNum bnp = bnHash + bnh;

    std::vector<unsigned char> vchp = bnp.getBytes();
    privKeyVariant.SetSecret(CSecret(vchp.begin(), vchp.end()));

    return true;
}

std::string CMalleableKey::ToString() const
{
    CDataStream ssKey(SER_NETWORK, version::PROTOCOL_VERSION);
    ssKey << *this;
    key_vector vch(ssKey.begin(), ssKey.end());

    return base58::manage::EncodeBase58Check(vch);
}

bool CMalleableKey::SetString(const std::string &strMutableKey)
{
    key_vector vchTemp;
    if (! base58::manage::DecodeBase58Check(strMutableKey, vchTemp)) {
        throw key_error("CMalleableKey::SetString() : Provided key data seems corrupted.");
    }
    if (vchTemp.size() != 66) {
        return false;
    }

    CDataStream ssKey(vchTemp, SER_NETWORK, version::PROTOCOL_VERSION);
    ssKey >> *this;

    return IsValid();
}

//
// CMalleableKeyView
//
// Check ownership
bool CMalleableKeyView::CheckKeyVariant(const CPubKey &R, const CPubKey &vchPubKeyVariant) const
{
    if (! IsValid()) {
        throw key_error("CMalleableKeyView::CheckKeyVariant() : Attempting to run on invalid view object.");
    }

    if (! R.IsValid()) {
        logging::LogPrintf("CMalleableKeyView::CheckKeyVariant() : R is invalid");
        return false;
    }

    if (! vchPubKeyVariant.IsValid()) {
        logging::LogPrintf("CMalleableKeyView::CheckKeyVariant() : public key variant is invalid");
        return false;
    }

    CPoint point_R;
    if (! point_R.setPubKey(R)) {
        logging::LogPrintf("CMalleableKeyView::CheckKeyVariant() : Unable to decode R value");
        return false;
    }

    CPoint point_H;
    if (! point_H.setPubKey(vchPubKeyH)) {
        logging::LogPrintf("CMalleableKeyView::CheckKeyVariant() : Unable to decode H value");
        return false;
    }

    CPoint point_P;
    if (! point_P.setPubKey(vchPubKeyVariant)) {
        logging::LogPrintf("CMalleableKeyView::CheckKeyVariant() : Unable to decode P value");
        return false;
    }

    // Infinity points are senseless
    if (point_P.IsInfinity()) {
        logging::LogPrintf("CMalleableKeyView::CheckKeyVariant() : P is infinity");
        return false;
    }

    CBigNum bnl;
    bnl.setBytes(std::vector<unsigned char>(vchSecretL.begin(), vchSecretL.end()));

    point_R.ECMUL(bnl);

    key_vector vchRl;
    if (! point_R.getBytes(vchRl)) {
        logging::LogPrintf("CMalleableKeyView::CheckKeyVariant() : Unable to convert Rl value");
        return false;
    }

    // Calculate Hash(R*l)
    CBigNum bnHash;
    bnHash.setuint160(hash_basis::Hash160(vchRl));

    CPoint point_Ps;
    // Calculate Ps = Hash(L*r)*G + H
    point_Ps.ECMULGEN(bnHash, point_H);

    // Infinity points are senseless
    if (point_Ps.IsInfinity()) {
        logging::LogPrintf("CMalleableKeyView::CheckKeyVariant() : Ps is infinity");
        return false;
    }

    // Check ownership
    if (point_Ps != point_P) {
        return false;
    }

    return true;
}

std::string CMalleableKeyView::ToString() const
{
    CDataStream ssKey(SER_NETWORK, version::PROTOCOL_VERSION);
    ssKey << *this;
    key_vector vch(ssKey.begin(), ssKey.end());

    return base58::manage::EncodeBase58Check(vch);
}

bool CMalleableKeyView::SetString(const std::string &strMutableKey)
{
    key_vector vchTemp;
    if (! base58::manage::DecodeBase58Check(strMutableKey, vchTemp)) {
        throw key_error("CMalleableKeyView::SetString() : Provided key data seems corrupted.");
    }
    if (vchTemp.size() != 67) {
        return false;
    }

    CDataStream ssKey(vchTemp, SER_NETWORK, version::PROTOCOL_VERSION);
    ssKey >> *this;

    return IsValid();
}

//// Asymmetric encryption

/*
void CPubKey::EncryptData(const key_vector &data, key_vector &encrypted) const
{
    char error[1024] = "Unknown error";

    const unsigned char *pbegin = &vbytes[0];
    EC_KEY *pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (! o2i_ECPublicKey(&pkey, &pbegin, size())) {
        throw key_error("Unable to parse EC key");
    }

    ies_ctx_t *ctx = cryptogram::create_context(pkey);
    if (! EC_KEY_get0_public_key(ctx->user_key)) {
        throw key_error("Given EC key is not public key");
    }

    cryptogram_t *cryptogram = cryptogram::ecies_encrypt(ctx, (unsigned char *)&data[0], data.size(), error);
    if (cryptogram == NULL) {
        delete ctx;
        ctx = NULL;
        throw key_error(std::string("Error in encryption: %s") + error);
    }

    encrypted.resize(cryptogram::cryptogram_data_sum_length(cryptogram));
    unsigned char *key_data = cryptogram::cryptogram_key_data(cryptogram);
    std::memcpy(&encrypted[0], key_data, encrypted.size());
    cryptogram::cryptogram_free(cryptogram);
    delete ctx;
}
*/

void CKey::DecryptData(const key_vector &encrypted, key_vector &data)
{
    char error[1024] = "Unknown error";

    ies_ctx_t *ctx = cryptogram::create_context(pkey);
    if (! EC_KEY_get0_private_key(ctx->user_key)) {
        throw key_error("Given EC key is not private key");
    }

    size_t key_length = ctx->stored_key_length;
    size_t mac_length = EVP_MD_size(ctx->md);
    cryptogram_t *cryptogram = cryptogram::cryptogram_alloc(key_length, mac_length, encrypted.size() - key_length - mac_length);
    if(cryptogram == NULL) {
        throw key_error("Cryptogram is not alloc memory");
    }

    std::memcpy(cryptogram::cryptogram_key_data(cryptogram), &encrypted[0], encrypted.size());

    size_t length = 0;
    unsigned char *decrypted = cryptogram::ecies_decrypt(ctx, cryptogram, &length, error);
    cryptogram::cryptogram_free(cryptogram);
    delete ctx;

    if (decrypted == NULL) {
        throw key_error(std::string("Error in decryption: %s") + error);
    }

    data.resize(length);
    std::memcpy(&data[0], decrypted, length);
    free(decrypted);    // ecies_decrypt malloc
}
