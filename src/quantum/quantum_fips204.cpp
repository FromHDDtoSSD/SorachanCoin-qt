// Copyright (c) 2026 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <quantum/quantum_fips204.h>
#include <random/random.h>
#include <quantum/mldsa_fips204/sign_fips204.h>

void CqPubKey_fips204::Init(const uint8_t *pk) {
    this->pubvch.resize(CRYPTO_PUBLICKEYBYTES);
    memcpy(&this->pubvch.front(), pk, CRYPTO_PUBLICKEYBYTES);
    _valid = true;
}

bool CqPubKey_fips204::Verify(const qkey_vector &data, const qkey_vector &vchSig) const {
    if(!_valid)
        return false;

    const uint8_t context[] = "";
    return crypto_sign_verify(vchSig.data(), vchSig.size(), data.data(), data.size(), context, 0, pubvch.data()) == 0;
}

bool CqPubKey_fips204::Verify(const uint256 &data, const qkey_vector &vchSig) const {
    if(!_valid)
        return false;

    assert(sizeof(uint256)==32);
    const uint8_t context[] = "";
    return crypto_sign_verify(vchSig.data(), vchSig.size(), data.begin(), sizeof(uint256), context, 0, pubvch.data()) == 0;
}

bool CqPubKey_fips204::VerifyQai(const uint256 &data, const qkey_vector &vchSig) const {
    if(!_valid)
        return false;

    assert(sizeof(uint256)==32);
    const uint8_t context[] = "";
    return crypto_sign_verify(vchSig.data(), vchSig.size(), data.begin(), sizeof(uint256), context, 0, pubvch.data()) == 0;
}

bool CqPubKey_fips204::IsValid() const {
    return _valid;
}

bool CqPubKey_fips204::IsFullyValid_BIP66() const {
    return _valid;
}

bool CqPubKey_fips204::RecoverCompact(const qkey_vector &vchSig) {
    this->pubvch = vchSig;
    _valid = true;
    return true;
}

bool CqPubKey_fips204::RecoverCompact(const CqKeyID &pubkeyid) {
    return RecoverCompact(strenc::ParseHex(pubkeyid));
}

uint256 CqPubKey_fips204::GetHash() const {
    qkey_vector qvch = GetVch();
    uint256 hash;
    CHash256().Write((const unsigned char *)qvch.data(), qvch.size()).Finalize(hash.begin());
    return hash;
}

qkey_vector CqPubKey_fips204::GetVch() const {
    return this->pubvch;
}

CqKeyID CqPubKey_fips204::GetID() const {
    return CqKeyID(strenc::HexStr(GetVch()));
}

qkey_vector CqPubKey_fips204::GetQaiHash() const {
    qkey_vector qvch = GetVch();

    //debugcs::instance() << "MLDSA - FIPS 204 pubkey size: " << qvch.size() << " bytes" << debugcs::endl();

    uint160 hash;
    CHash160().Write((const unsigned char *)qvch.data(), qvch.size()).Finalize(hash.begin());

    //uint256 hash256;
    //uint160 hash160;
    //CSHA256().Write((const unsigned char *)qvch.data(), qvch.size()).Finalize(hash256.begin());
    //CRIPEMD160().Write((const unsigned char *)hash256.begin(), hash256.size()).Finalize(hash160.begin());
    //assert(hash == hash160);

    qkey_vector qhash;
    qhash.resize(33); // size is CPubKey::COMPRESSED_PUBLIC_KEY_SIZE
    ::memset(&qhash.front(), 0x00, 33);
    qhash[0] = 0x02;
    ::memcpy(&qhash.front() + 1, hash.begin(), sizeof(uint160));
    return qhash;
}

bool CqPubKey_fips204::CmpQaiHash(const qkey_vector &hashvch) const {
    return (GetQaiHash() == hashvch);
}

bool CqPubKey_fips204::IsQaiHash(const qkey_vector &hashvch) {
    return CqPubKey::IsQaiHash(hashvch);
}

qkey_vector CqPubKey_fips204::GetRandHash() {
    static const unsigned char QaiVersion = (unsigned char)0x04;
    qkey_vector buf;
    buf.resize(33); // size is CPubKey::COMPRESSED_PUBLIC_KEY_SIZE
    ::memset(&buf.front(), 0xFF, 33);
    buf[0] = 0x02;
    buf[1] = QaiVersion;
    if(!map_arg::GetBoolArg(std::string("-restorehdwallet"))) {
        random::GetStrongRandBytes(&buf[2], 20);
    }
    return buf;
}

bool CqPubKey_fips204::IsRandHash(const qkey_vector &randvch) {
    return CqPubKey::IsRandHash(randvch);
}

CqKey_fips204::CqKey_fips204(const CqSecretKey &seed) : _valid(false) {
    privKey.resize(CRYPTO_SECRETKEYBYTES);
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    if (crypto_sign_seed_keypair(pk, &privKey.front(), seed.data()) != 0) {
        _valid = false;
        return;
    }

    pubKey.Init(pk);
    _valid = true;
}

bool CqKey_fips204::IsValid() const {
    return _valid;
}

bool CqKey_fips204::Sign(const qkey_vector &data, qkey_vector &vchSig) const {
    if(!_valid)
        return false;

    vchSig.resize(CRYPTO_BYTES);
    const uint8_t context[] = "";
    size_t sig_len = 0;
    bool ret = crypto_sign_signature(&vchSig.front(), &sig_len, data.data(), data.size(), context, 0, this->privKey.data()) == 0;
    assert(sig_len == CRYPTO_BYTES);
    return ret;
}

bool CqKey_fips204::Sign(const uint256 &hash, qkey_vector &vchSig) const {
    if(!_valid)
        return false;

    vchSig.resize(CRYPTO_BYTES);
    const uint8_t context[] = "";
    size_t sig_len = 0;
    bool ret = crypto_sign_signature(&vchSig.front(), &sig_len, hash.begin(), sizeof(uint256), context, 0, this->privKey.data()) == 0;
    assert(sig_len == CRYPTO_BYTES);
    return ret;
}

bool CqKey_fips204::SignQai(const uint256 &hash, qkey_vector &vchSig) const {
    return Sign(hash, vchSig);
}

bool CqKey_fips204::VerifyPubKey(const CqPubKey_fips204 &pubkey) const {
    if(!_valid)
        return false;
    if(!pubkey.IsValid())
        return false;

    unsigned char rnd[8];
    std::string str = "SorachanCoin key verification\n";
    random::GetRandBytes(rnd, sizeof(rnd));
    uint256 hash;
    CHash256().Write((unsigned char *)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash.begin());
    qkey_vector vchSig;
    bool ret1 = Sign(hash, vchSig);
    bool ret2 = pubkey.Verify(hash, vchSig);
    cleanse::OPENSSL_cleanse(rnd, sizeof(rnd));
    cleanse::OPENSSL_cleanse(&hash, sizeof(uint256));
    cleanse::OPENSSL_cleanse(vchSig.data(), vchSig.size() * sizeof(unsigned char));
    return ret1 && ret2;
}
