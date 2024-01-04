// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <keystore.h>
#include <script/script.h>
#include <address/base58.h>
#include <wallet.h> // CWallet::fWalletUnlockMintOnly

static void keydebug(const CKey &key) {
    //using namespace ScriptOpcodes;
    // debug ok: WIF
    /*
    try {
        CFirmKey fikey;
        fikey.SetSecret(key.GetSecret(), key.IsCompressed());
        SecureString enc_priv_key = key_io::EncodeSecret(fikey);
        debugcs::instance() << "WIF CFirmKey encoded: " << enc_priv_key.size() << " : " << enc_priv_key.print() << debugcs::endl();

        CFirmKey fikey2 = key_io::DecodeSecret(enc_priv_key);
        assert(fikey == fikey2);
        assert(fikey.GetPubKey().IsCompressed() == fikey2.GetPubKey().IsCompressed());
        assert(fikey.GetPubKey() == fikey2.GetPubKey());

        CFirmKey fikey3;
        fikey3.SetSecret(key.GetSecret(), false);
        SecureString enc_priv_key2 = key_io::EncodeSecret(fikey3);
        debugcs::instance() << "WIF CFirmKey encoded: " << enc_priv_key2.size() << " : " << enc_priv_key2.print() << debugcs::endl();

        CFirmKey fikey4 = key_io::DecodeSecret(enc_priv_key2);
        assert(fikey3 == fikey4);
        assert(fikey3.GetPubKey().IsCompressed() == fikey4.GetPubKey().IsCompressed());
        assert(fikey3.GetPubKey() == fikey4.GetPubKey());
    } catch (const std::runtime_error &e) {
        debugcs::instance() << "Error" << debugcs::endl();
    }
    */

    // ETH style(ecrecover) consensus in signCompact and recoverCompact

    /* debug ok: CFirmKey(for Eth) RecoverCompact checked
    CSecret secret = key.GetSecret();
    CFirmKey fikey;
    fikey.Set(secret.begin(), secret.end(), true);
    key_vector vec = fikey.GetPubKey().GetPubVch();
    CPubKey pubkey(vec);
    assert(fikey.GetPubKey().GetID()==pubkey.GetID());

    uint256 target;
    std::string info = "happy new year!";
    latest_crypto::CSHA256().Write((const unsigned char *)info.c_str(), info.size()).Finalize((unsigned char *)&target);
    key_vector sig1, sig2;
    fikey.SignCompact(target, sig1);
    CPubKey pub1;
    assert(pub1.RecoverCompact(target, sig1));
    assert(pub1.GetID()==fikey.GetPubKey().GetID());
    CKey sokey = key;
    sokey.SignCompact(target, sig2);
    CPubKey pub2;
    assert(pub2.RecoverCompact(target, sig2));
    assert(pub2.GetID()==sokey.GetPubKey().GetID());
    */

    //CPubKey pubkey1 = key.GetPubKey();

    // debug ok: Compress checked
    //pubkey1.Decompress();
    //pubkey1.Compress();
    //CPubKey pubkey2 = key.GetPubKey();
    //assert(pubkey1.GetID()==pubkey2.GetID());

    /* debug ok: CFirmKey(for Eth) checked
    CKeyID d1 = pubkey1.GetID();
    debugcs::instance() << "Add mapKeys CKeyID1: " << strenc::HexStr(key_vector(d1.begin(), d1.end())) << debugcs::endl();

    CFirmKey fikey;
    CKey sokey = key;
    CSecret secret = sokey.GetSecret();
    fikey.Set(secret.begin(), secret.end(), true);

    CPubKey pub1 = fikey.GetPubKey();
    CPubKey pub2 = sokey.GetPubKey();
    pub1.Compress();
    pub2.Compress();
    CKeyID d2 = pub1.GetID();
    assert(pub1==pub2);
    debugcs::instance() << "Add mapKeys CKeyID2: " << strenc::HexStr(key_vector(d2.begin(), d2.end())) << debugcs::endl();

    CSecret s1 = fikey.GetSecret();
    CSecret s2 = sokey.GetSecret();
    assert(s1==s2);

    CPrivKey pr1 = fikey.GetPrivKey();
    CPrivKey pr2 = sokey.GetPrivKey();
    assert(pr1==pr2);

    uint256 target;
    std::string info = "happy new year!";
    latest_crypto::CSHA256().Write((const unsigned char *)info.c_str(), info.size()).Finalize((unsigned char *)&target);
    key_vector sig1, sig2;
    fikey.Sign(target, sig1);
    sokey.Sign(target, sig2);
    debugcs::instance() << sig1.size() << " : " << sig2.size() << debugcs::endl();
    debugcs::instance() << "sig1: " << strenc::HexStr(key_vector(sig1.begin(), sig1.end())) << debugcs::endl();
    debugcs::instance() << "sig2: " << strenc::HexStr(key_vector(sig2.begin(), sig2.end())) << debugcs::endl();
    //sig1[16] = '8';
    bool fpub1sig1 = pub1.Verify_BIP66(target, sig1);
    bool fpub1sig2 = pub1.Verify_BIP66(target, sig2);
    debugcs::instance() << (fpub1sig1 ? "ok": "failure") << (fpub1sig2 ? "ok": "failure") << debugcs::endl();
    assert(fpub1sig1 && fpub1sig2);
    bool fpub2sig1 = pub2.Verify(target, sig1);
    bool fpub2sig2 = pub2.Verify(target, sig2);
    debugcs::instance() << (fpub2sig1 ? "ok": "failure") << (fpub2sig2 ? "ok": "failure") << debugcs::endl();
    assert(fpub2sig1 && fpub2sig2);
    */
}

bool CBasicKeyStore::AddKey(const CKey &key)
{
    keydebug(key);

    bool fCompressed = false;
    CSecret secret = key.GetSecret(fCompressed);

    {
        LOCK(cs_KeyStore);
        mapKeys[key.GetPubKey().GetID()] = std::make_pair(secret, fCompressed);
    }
    return true;
}

bool CBasicKeyStore::AddMalleableKey(const CMalleableKeyView &keyView, const CSecret &vchSecretH)
{
    {
        LOCK(cs_KeyStore);
        mapMalleableKeys[CMalleableKeyView(keyView)] = vchSecretH;
    }
    return true;
}

bool CBasicKeyStore::AddCScript(const CScript &redeemScript)
{
    if (redeemScript.size() > Script_const::MAX_SCRIPT_ELEMENT_SIZE) {
        return logging::error("CBasicKeyStore::AddCScript() : redeemScripts > %i bytes are invalid", Script_const::MAX_SCRIPT_ELEMENT_SIZE);
    }

    {
        LOCK(cs_KeyStore);
        mapScripts[redeemScript.GetID()] = redeemScript;
    }
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID &hash) const
{
    bool result;
    {
        LOCK(cs_KeyStore);
        result = (mapScripts.count(hash) > 0);
    }
    return result;
}

bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript &redeemScriptOut) const
{
    {
        LOCK(cs_KeyStore);
        ScriptMap::const_iterator mi = mapScripts.find(hash);
        if (mi != mapScripts.end()) {
            redeemScriptOut = (*mi).second;
            return true;
        }
    }
    return false;
}

bool CBasicKeyStore::AddWatchOnly(const CScript &dest)
{
    {
        LOCK(cs_KeyStore);
        CTxDestination address;
        if (Script_util::ExtractDestination(dest, address)) {
            CKeyID keyID;
            CBitcoinAddress(address).GetKeyID(keyID);
            if (HaveKey(keyID)) {
                return false;
            }
        }

        setWatchOnly.insert(dest);
    }
    return true;
}

bool CBasicKeyStore::RemoveWatchOnly(const CScript &dest)
{
    {
        LOCK(cs_KeyStore);
        setWatchOnly.erase(dest);
    }
    return true;
}

bool CBasicKeyStore::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool CBasicKeyStore::HaveWatchOnly() const
{
    LOCK(cs_KeyStore);
    return (!setWatchOnly.empty());
}

bool CCryptoKeyStore::SetCrypted()
{
    {
        LOCK(cs_KeyStore);
        if (fUseCrypto) {
            return true;
        }

        if (! mapKeys.empty()) {
            return false;
        }
        fUseCrypto = true;
    }
    return true;
}

bool CCryptoKeyStore::Lock()
{
    if (! SetCrypted()) {
        return false;
    }

    {
        LOCK(cs_KeyStore);
        vMasterKey.clear();
        CWallet::fWalletUnlockMintOnly = false;
    }

    NotifyStatusChanged(this);
    return true;
}

bool CCryptoKeyStore::Unlock(const CKeyingMaterial &vMasterKeyIn)
{
    {
        LOCK(cs_KeyStore);
        if (! SetCrypted()) {
            return false;
        }

        for (CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin(); mi != mapCryptedKeys.end(); ++mi)
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CSecret vchSecret;
            if(! crypter::DecryptSecret(vMasterKeyIn, vchCryptedSecret, vchPubKey.GetHash(), vchSecret)) {
                return false;
            }
            if (vchSecret.size() != 32) {
                return false;
            }

            CKey key;
            key.SetSecret(vchSecret);
            key.SetCompressedPubKey(vchPubKey.IsCompressed());
            if (key.GetPubKey() == vchPubKey) {
                break;
            }

            return false;
        }

        vMasterKey = vMasterKeyIn;
    }
    NotifyStatusChanged(this);
    return true;
}

bool CCryptoKeyStore::AddKey(const CKey &key)
{
    {
        LOCK(cs_KeyStore);

        CScript script;
        script.SetDestination(key.GetPubKey().GetID());

        if (HaveWatchOnly(script)) {
            return false;
        }

        if (! IsCrypted()) {
            return CBasicKeyStore::AddKey(key);
        }

        if (IsLocked()) {    // this lock is CCryptoKeyStore
            return false;
        }

        std::vector<unsigned char> vchCryptedSecret;
        CPubKey vchPubKey = key.GetPubKey();
        bool fCompressed;
        if (! crypter::EncryptSecret(vMasterKey, key.GetSecret(fCompressed), vchPubKey.GetHash(), vchCryptedSecret)) {
            return false;
        }
        if (! AddCryptedKey(key.GetPubKey(), vchCryptedSecret)) {
            return false;
        }
    }
    return true;
}

bool CCryptoKeyStore::AddMalleableKey(const CMalleableKeyView &keyView, const CSecret &vchSecretH)
{
    {
        LOCK(cs_KeyStore);
        if (! SetCrypted()) {
            return CBasicKeyStore::AddMalleableKey(keyView, vchSecretH);
        }
        if (IsLocked()) {
            return false;
        }

        CKey keyH;
        keyH.SetSecret(vchSecretH, true);

        std::vector<unsigned char> vchCryptedSecretH;
        if (! crypter::EncryptSecret(vMasterKey, vchSecretH, keyH.GetPubKey().GetHash(), vchCryptedSecretH)) {
            return false;
        }
        if (! AddCryptedMalleableKey(keyView, vchCryptedSecretH)) {
            return false;
        }
    }
    return true;
}

bool CCryptoKeyStore::AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    {
        LOCK(cs_KeyStore);
        if (! SetCrypted()) {
            return false;
        }

        mapCryptedKeys[vchPubKey.GetID()] = std::make_pair(vchPubKey, vchCryptedSecret);
    }
    return true;
}

bool CCryptoKeyStore::AddCryptedMalleableKey(const CMalleableKeyView &keyView, const std::vector<unsigned char> &vchCryptedSecretH)
{
    {
        LOCK(cs_KeyStore);
        if (! SetCrypted()) {
            return false;
        }

        mapCryptedMalleableKeys[CMalleableKeyView(keyView)] = vchCryptedSecretH;
    }
    return true;
}

bool CCryptoKeyStore::CreatePrivKey(const CPubKey &pubKeyVariant, const CPubKey &R, CKey &privKey) const
{
    {
        LOCK(cs_KeyStore);
        if (! IsCrypted()) {
            return CBasicKeyStore::CreatePrivKey(pubKeyVariant, R, privKey);
        }

        for (CryptedMalleableKeyMap::const_iterator mi = mapCryptedMalleableKeys.begin(); mi != mapCryptedMalleableKeys.end(); mi++)
        {
            if (mi->first.CheckKeyVariant(R, pubKeyVariant)) {
                const CPubKey H = mi->first.GetMalleablePubKey().GetH();

                CSecret vchSecretH;
                if (! crypter::DecryptSecret(vMasterKey, mi->second, H.GetHash(), vchSecretH)) {
                    return false;
                }
                if (vchSecretH.size() != 32) {
                    return false;
                }

                CMalleableKey mKey = mi->first.GetMalleableKey(vchSecretH);
                return mKey.CheckKeyVariant(R, pubKeyVariant, privKey);
            }
        }

    }
    return true;
}

bool CCryptoKeyStore::GetMalleableKey(const CMalleableKeyView &keyView, CMalleableKey &mKey) const
{
    {
        LOCK(cs_KeyStore);
        if (! IsCrypted()) {
            return CBasicKeyStore::GetMalleableKey(keyView, mKey);
        }

        CryptedMalleableKeyMap::const_iterator mi = mapCryptedMalleableKeys.find(keyView);
        if (mi != mapCryptedMalleableKeys.end()) {
            const CPubKey H = keyView.GetMalleablePubKey().GetH();

            CSecret vchSecretH;
            if (! crypter::DecryptSecret(vMasterKey, mi->second, H.GetHash(), vchSecretH)) {
                return false;
            }
            if (vchSecretH.size() != 32) {
                return false;
            }
            mKey = mi->first.GetMalleableKey(vchSecretH);

            return true;
        }
    }
    return false;
}

bool CCryptoKeyStore::GetKey(const CKeyID &address, CKey &keyOut) const
{
    //debugcs::instance() << "called keystore GetKey size: " << mapKeys.size() << " : " << mapCryptedKeys.size() << debugcs::endl();
    //for(const auto &d: mapKeys) {
    //    debugcs::instance() << "mapKeys CKeyID: " << strenc::HexStr(key_vector(d.first.begin(), d.first.end())) << debugcs::endl();
    //}

    {
        LOCK(cs_KeyStore);
        if (! IsCrypted()) {
            return CBasicKeyStore::GetKey(address, keyOut);
        }

        CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
        if (mi != mapCryptedKeys.end()) {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CSecret vchSecret;
            if (! crypter::DecryptSecret(vMasterKey, vchCryptedSecret, vchPubKey.GetHash(), vchSecret)) {
                return false;
            }
            if (vchSecret.size() != 32) {
                return false;
            }

            keyOut.SetSecret(vchSecret);
            keyOut.SetCompressedPubKey(vchPubKey.IsCompressed());
            return true;
        }
    }
    return false;
}

bool CCryptoKeyStore::GetKey(const CKeyID &address, CFirmKey &keyOut) const
{
    LOCK(cs_KeyStore);
    if (! IsCrypted()) {
        return CBasicKeyStore::GetKey(address, keyOut);
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end()) {
        const CPubKey &vchPubKey = (*mi).second.first;
        const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
        CSecret vchSecret;
        if (! crypter::DecryptSecret(vMasterKey, vchCryptedSecret, vchPubKey.GetHash(), vchSecret)) {
            return false;
        }
        if (vchSecret.size() != CFirmKey::PRIVATE_BYTE_VECTOR_SIZE) {
            return false;
        }

        keyOut.SetSecret(vchSecret);
        keyOut.SetCompressedPubKey(vchPubKey.IsCompressed());
        return true;
    }

    return false;
}

bool CBasicKeyStore::GetEthAddr(const CKeyID &id, std::string &address) const {
    LOCK(cs_KeyStore);

    KeyMap::const_iterator mi = mapKeys.find(id);
    if(mi != mapKeys.end()) {
        CFirmKey key;
        key.SetSecret((*mi).second.first, (*mi).second.second);
        key_vector vch = key.GetPubKey().GetPubVch();
        uint160 hash;
        latest_crypto::CHashEth().Write((const unsigned char *)vch.data(), vch.size()).Finalize((unsigned char *)&hash);
        address = strenc::HexStr(key_vector(BEGIN(hash), END(hash)));
        return true;
    }

    return false;
}

bool CCryptoKeyStore::GetEthAddr(const CKeyID &id, std::string &address) const {
    LOCK(cs_KeyStore);
    if(! IsCrypted()) {
        return CBasicKeyStore::GetEthAddr(id, address);
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(id);
    if(mi != mapCryptedKeys.end()) {
        const CPubKey &pubkey = (*mi).second.first;
        const std::vector<unsigned char> &vchCrypted = (*mi).second.second;
        CSecret secret;
        if(! crypter::DecryptSecret(vMasterKey, vchCrypted, pubkey.GetHash(), secret))
            return false;
        if(secret.size() != CFirmKey::PRIVATE_BYTE_VECTOR_SIZE)
            return false;

        CFirmKey key;
        key.SetSecret(secret, pubkey.IsCompressed());
        key_vector vch = key.GetPubKey().GetPubVch();
        uint160 hash;
        latest_crypto::CHashEth().Write((const unsigned char *)vch.data(), vch.size()).Finalize((unsigned char *)&hash);
        address = strenc::HexStr(key_vector(BEGIN(hash), END(hash)));
        return true;
    }

    return false;
}

bool CCryptoKeyStore::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    {
        LOCK(cs_KeyStore);
        if (! IsCrypted()) {
            return CKeyStore::GetPubKey(address, vchPubKeyOut);
        }

        CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
        if (mi != mapCryptedKeys.end()) {
            vchPubKeyOut = (*mi).second.first;
            return true;
        }
    }
    return false;
}

bool CCryptoKeyStore::EncryptKeys(CKeyingMaterial &vMasterKeyIn)
{
    {
        LOCK(cs_KeyStore);
        if (!mapCryptedKeys.empty() || IsCrypted()) {
            return false;
        }

        fUseCrypto = true;
        for(KeyMap::value_type &mKey: mapKeys)
        {
            CKey key;
            if (! key.SetSecret(mKey.second.first, mKey.second.second)) {
                return false;
            }

            const CPubKey vchPubKey = key.GetPubKey();
            std::vector<unsigned char> vchCryptedSecret;
            bool fCompressed;
            if (! crypter::EncryptSecret(vMasterKeyIn, key.GetSecret(fCompressed), vchPubKey.GetHash(), vchCryptedSecret)) {
                return false;
            }
            if (! AddCryptedKey(vchPubKey, vchCryptedSecret)) {
                return false;
            }
        }
        mapKeys.clear();

        for(MalleableKeyMap::value_type &mKey: mapMalleableKeys)
        {
            const CPubKey vchPubKeyH = mKey.first.GetMalleablePubKey().GetH();
            std::vector<unsigned char> vchCryptedSecretH;
            if (! crypter::EncryptSecret(vMasterKeyIn, mKey.second, vchPubKeyH.GetHash(), vchCryptedSecretH)) {
                return false;
            }
            if (! AddCryptedMalleableKey(mKey.first, vchCryptedSecretH)) {
                return false;
            }
        }
        mapMalleableKeys.clear();
    }
    return true;
}

bool CCryptoKeyStore::DecryptKeys(const CKeyingMaterial &vMasterKeyIn)
{
    {
        LOCK(cs_KeyStore);
        if (! IsCrypted()) {
            return false;
        }

        for (CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin(); mi != mapCryptedKeys.end(); ++mi)
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CSecret vchSecret;
            if(! crypter::DecryptSecret(vMasterKeyIn, vchCryptedSecret, vchPubKey.GetHash(), vchSecret)) {
                return false;
            }
            if (vchSecret.size() != 32) {
                return false;
            }

            CKey key;
            key.SetSecret(vchSecret);
            key.SetCompressedPubKey(vchPubKey.IsCompressed());
            if (! CBasicKeyStore::AddKey(key)) {
                return false;
            }
        }
        mapCryptedKeys.clear();

        for(CryptedMalleableKeyMap::const_iterator mi2 = mapCryptedMalleableKeys.begin(); mi2 != mapCryptedMalleableKeys.end(); ++mi2)
        {
            const CPubKey vchPubKeyH = mi2->first.GetMalleablePubKey().GetH();

            CSecret vchSecretH;
            if(! crypter::DecryptSecret(vMasterKeyIn, mi2->second, vchPubKeyH.GetHash(), vchSecretH)) {
                return false;
            }
            if (vchSecretH.size() != 32) {
                return false;
            }

            if (! CBasicKeyStore::AddMalleableKey(mi2->first, vchSecretH)) {
                return false;
            }
        }
        mapCryptedMalleableKeys.clear();
    }

    return true;
}
