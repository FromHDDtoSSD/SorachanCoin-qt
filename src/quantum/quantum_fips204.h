// Copyright (c) 2026 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORA_QUANTUM_FIPS204_H
#define SORA_QUANTUM_FIPS204_H

#include <quantum/quantum.h>

typedef std::vector<unsigned char, secure_allocator<unsigned char> > CqPrivKey;

class CqPubKey_fips204 {
public:
    CqPubKey_fips204() : _valid(false) {}

    void Init(const uint8_t *pk);

    CqPubKey_fips204 &operator=(const CqPubKey_fips204 &obj) {
        this->pubvch = obj.pubvch;
        _valid = true;
        return *this;
    }

    bool operator==(const CqPubKey_fips204 &obj) const {
        if(! _valid)
            return false;

        return this->pubvch == obj.pubvch;
    }

    bool operator!=(const CqPubKey_fips204 &obj) const {
        return !(operator ==(obj));
    }

    bool Verify(const qkey_vector &data, const qkey_vector &vchSig) const;
    bool Verify(const uint256 &data, const qkey_vector &vchSig) const;
    bool VerifyQai(const uint256 &data, const qkey_vector &vchSig) const;

    bool IsValid() const;
    bool IsFullyValid_BIP66() const;
    bool RecoverCompact(const qkey_vector &vchSig);
    bool RecoverCompact(const CqKeyID &pubkeyid);

    uint256 GetHash() const;
    qkey_vector GetVch() const;
    CqKeyID GetID() const;
    qkey_vector GetQaiHash() const;
    bool CmpQaiHash(const qkey_vector &hashvch) const;

    static bool IsQaiHash(const qkey_vector &hashvch);
    static qkey_vector GetRandHash();
    static bool IsRandHash(const qkey_vector &randvch);

private:
    qkey_vector pubvch;
    bool _valid;
};

class CqKey_fips204 {
    CqKey_fips204() = delete;

public:
    CqKey_fips204(const CqSecretKey &seed);

    CqPubKey_fips204 GetPubKey() const {
        return this->pubKey;
    }

    bool IsValid() const;

    bool Sign(const qkey_vector &data, qkey_vector &vchSig) const;
    bool Sign(const uint256 &hash, qkey_vector &vchSig) const;
    bool SignQai(const uint256 &hash, qkey_vector &vchSig) const;

    bool VerifyPubKey(const CqPubKey_fips204 &pubkey) const;

    CqKey_fips204(const CqKey_fips204 &obj) {
        assert(obj._valid);
        this->privKey = obj.privKey;
        this->pubKey = obj.pubKey;
        this->_valid = true;
    }

    CqKey_fips204(CqKey_fips204 &&obj) {
        assert(obj._valid);
        this->privKey = std::move(obj.privKey);
        this->pubKey = std::move(obj.pubKey);
        this->_valid = true;
    }

    CqKey_fips204 &operator=(const CqKey_fips204 &obj) {
        assert(obj._valid);
        this->privKey = obj.privKey;
        this->pubKey = obj.pubKey;
        return *this;
    }

    bool operator==(const CqKey_fips204 &obj) const {
        //assert(_valid && obj._valid);
        if(! _valid)
            return false;

        return this->privKey == obj.privKey;
    }

    bool operator!=(const CqKey_fips204 &obj) const {
        //assert(_valid && obj._valid);
        return !(operator ==(obj));
    }

    ~CqKey_fips204() {}

private:
    CqPrivKey privKey;
    CqPubKey_fips204 pubKey;
    bool _valid;
};

#endif
