// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEYSTORE_H
#define BITCOIN_KEYSTORE_H

#include <crypter.h>
#include <sync/lsync.h>
#include <key/privkey.h>
#include <boost/signals2/signal.hpp>
#include <boost/variant.hpp>
class CScript;

// Note: inheritance CWallet
// A(CKeyStore) -> B -> C -> D(CWallet)

// A, virtual base class for key stores
class CKeyStore
{
    CKeyStore(const CKeyStore &)=delete;
    CKeyStore &operator=(const CKeyStore &)=delete;

protected:
    mutable CCriticalSection cs_KeyStore;

public:
    CKeyStore() {}
    virtual ~CKeyStore() {}

    // Add a key to the store.
    virtual bool AddKey(const CKey& key) =0;

    // Add a malleable key to store.
    virtual bool AddMalleableKey(const CMalleableKeyView &keyView, const CSecret &vchSecretH) =0;
    virtual bool GetMalleableKey(const CMalleableKeyView &keyView, CMalleableKey &mKey) const =0;

    // Check whether a key corresponding to a given address is present in the store.
    virtual bool HaveKey(const CKeyID &address) const =0;
    virtual bool GetKey(const CKeyID &address, CKey &keyOut) const =0;
    virtual bool GetKey(const CKeyID &address, CFirmKey &keyOut) const =0;
    virtual void GetKeys(std::set<CKeyID> &setAddress) const =0;
    virtual bool GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const {
        CKey key;
        if (! GetKey(address, key)) {
            return false;
        }
        vchPubKeyOut = key.GetPubKey();
        return true;
    }

    // Support for Eth Address
    virtual bool GetEthAddr(const CKeyID &id, std::string &address) const =0;

    // Support for BIP 0013 : see https://en.bitcoin.it/wiki/BIP_0013
    virtual bool AddCScript(const CScript &redeemScript) =0;
    virtual bool HaveCScript(const CScriptID &hash) const =0;
    virtual bool GetCScript(const CScriptID &hash, CScript &redeemScriptOut) const =0;

    // Support for Watch-only addresses
    virtual bool AddWatchOnly(const CScript &dest) =0;
    virtual bool RemoveWatchOnly(const CScript &dest) =0;
    virtual bool HaveWatchOnly(const CScript &dest) const =0;
    virtual bool HaveWatchOnly() const =0;
    virtual bool GetSecret(const CKeyID &address, CSecret &vchSecret, bool &fCompressed) const {
        CKey key;
        if (! GetKey(address, key)) {
            return false;
        }
        vchSecret = key.GetSecret(fCompressed);
        return true;
    }

    virtual bool CheckOwnership(const CPubKey &pubKeyVariant, const CPubKey &R) const =0;
    virtual bool CheckOwnership(const CPubKey &pubKeyVariant, const CPubKey &R, CMalleableKeyView &view) const =0;
    virtual bool CreatePrivKey(const CPubKey &pubKeyVariant, const CPubKey &R, CKey &privKey) const =0;
    virtual void ListMalleableViews(std::list<CMalleableKeyView> &malleableViewList) const =0;
};

//
// Basic Type
//
typedef std::map<CKeyID, std::pair<CSecret, bool> > KeyMap;
typedef std::map<CScriptID, std::pair<CKeyID, CEthID> > EthMap;
typedef std::map<CScriptID, CScript > ScriptMap;
typedef std::set<CScript> WatchOnlySet;
typedef std::map<CMalleableKeyView, CSecret> MalleableKeyMap;

//
// B, Basic key store, that keeps keys in an address -> secret map
//
class CBasicKeyStore : public CKeyStore
{
protected:
    KeyMap mapKeys;
    EthMap mapEths;
    MalleableKeyMap mapMalleableKeys;

    ScriptMap mapScripts;
    WatchOnlySet setWatchOnly;

    static CEthID GetEthAddr(const CPubKey &pubkey);

public:
    bool AddKey(const CKey &key);
    bool AddMalleableKey(const CMalleableKeyView &keyView, const CSecret &vchSecretH);
    bool GetMalleableKey(const CMalleableKeyView &keyView, CMalleableKey &mKey) const {
        {
            LOCK(cs_KeyStore);
            MalleableKeyMap::const_iterator mi = mapMalleableKeys.find(keyView);
            if (mi != mapMalleableKeys.end()) {
                mKey = mi->first.GetMalleableKey(mi->second);
                return true;
            }
        }
        return false;
    }

    bool HaveKey(const CKeyID &address) const {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapKeys.count(address) > 0);
        }
        return result;
    }

    bool HaveEth(const CEthID &address) const {
        {
            LOCK(cs_KeyStore);
            for(const auto &d: mapEths) {
                if(d.second.second == address)
                    return true;
            }
        }
        return false;
    }

    void GetKeys(std::set<CKeyID> &setAddress) const {
        setAddress.clear();
        {
            LOCK(cs_KeyStore);
            for (KeyMap::const_iterator mi = mapKeys.begin(); mi != mapKeys.end(); ++mi)
            {
                setAddress.insert((*mi).first);
            }
        }
    }

    bool GetKey(const CKeyID &address, CKey &keyOut) const {
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.find(address);
            if (mi != mapKeys.end()) {
                keyOut.SetSecret((*mi).second.first, (*mi).second.second);
                return true;
            }
        }
        return false;
    }

    bool GetKey(const CKeyID &address, CFirmKey &keyOut) const {
        LOCK(cs_KeyStore);
        KeyMap::const_iterator mi = mapKeys.find(address);
        if (mi != mapKeys.end()) {
            keyOut.SetSecret((*mi).second.first, (*mi).second.second);
            return true;
        }
        return false;
    }

    bool GetKeyID(const CEthID &address, CKeyID &keyid) const {
        LOCK(cs_KeyStore);
        for(const auto &d: mapEths) {
            if(address == d.second.second) {
                keyid = d.second.first;
                return true;
            }
        }
        return false;
    }

    bool GetScriptID(const CEthID &address, CScriptID &scriptid) const {
        LOCK(cs_KeyStore);
        for(const auto &d: mapEths) {
            if(address == d.second.second) {
                scriptid = d.first;
                return true;
            }
        }
        return false;
    }

    bool GetEthID(const CKeyID &id, CEthID &ethaddr) const {
        LOCK(cs_KeyStore);
        for(const auto &d: mapEths) {
            if(id == d.second.first) {
                ethaddr = d.second.second;
                return true;
            }
        }
        return false;
    }

    virtual bool GetEthAddr(const CKeyID &id, std::string &address) const;

    virtual bool AddCScript(const CScript &redeemScript);
    virtual bool AddCScript(const CScript &redeemScript, const CPubKey &pubkey);
    virtual bool HaveCScript(const CScriptID &hash) const;
    virtual bool GetCScript(const CScriptID &hash, CScript &redeemScriptOut) const;
    virtual bool GetCScript(const CScriptID &hash, CScript &redeemScriptOut, CKeyID &keyid, CEthID &ethid) const;

    virtual bool AddWatchOnly(const CScript &dest);
    virtual bool RemoveWatchOnly(const CScript &dest);
    virtual bool HaveWatchOnly(const CScript &dest) const;
    virtual bool HaveWatchOnly() const;

    bool CheckOwnership(const CPubKey &pubKeyVariant, const CPubKey &R) const {
        {
            LOCK(cs_KeyStore);
            for (MalleableKeyMap::const_iterator mi = mapMalleableKeys.begin(); mi != mapMalleableKeys.end(); mi++)
            {
                if (mi->first.CheckKeyVariant(R, pubKeyVariant)) {
                    return true;
                }
            }
        }
        return false;
    }

    bool CheckOwnership(const CPubKey &pubKeyVariant, const CPubKey &R, CMalleableKeyView &view) const {
        {
            LOCK(cs_KeyStore);
            for (MalleableKeyMap::const_iterator mi = mapMalleableKeys.begin(); mi != mapMalleableKeys.end(); mi++)
            {
                if (mi->first.CheckKeyVariant(R, pubKeyVariant)) {
                    view = mi->first;
                    return true;
                }
            }
        }
        return false;
    }

    bool CreatePrivKey(const CPubKey &pubKeyVariant, const CPubKey &R, CKey &privKey) const {
        {
            LOCK(cs_KeyStore);
            for (MalleableKeyMap::const_iterator mi = mapMalleableKeys.begin(); mi != mapMalleableKeys.end(); mi++)
            {
                if (mi->first.CheckKeyVariant(R, pubKeyVariant)) {
                    CMalleableKey mKey = mi->first.GetMalleableKey(mi->second);
                    return mKey.CheckKeyVariant(R, pubKeyVariant, privKey);
                }
            }
        }
        return false;
    }

    void ListMalleableViews(std::list<CMalleableKeyView> &malleableViewList) const {
        malleableViewList.clear();
        {
            LOCK(cs_KeyStore);
            for (MalleableKeyMap::const_iterator mi = mapMalleableKeys.begin(); mi != mapMalleableKeys.end(); mi++)
            {
                malleableViewList.push_back(CMalleableKeyView(mi->first));
            }
        }
    }

    bool GetMalleableView(const CMalleablePubKey &mpk, CMalleableKeyView &view) {
        const CKeyID &mpkID = mpk.GetID();
        {
            LOCK(cs_KeyStore);
            for (MalleableKeyMap::const_iterator mi = mapMalleableKeys.begin(); mi != mapMalleableKeys.end(); mi++)
            {
                if (mi->first.GetID() == mpkID) {
                    view = CMalleableKeyView(mi->first);
                    return true;
                }
            }
        }

        return false;
    }
};

//
// Crypto Type
//
typedef std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char> > > CryptedKeyMap;
typedef std::map<CMalleableKeyView, std::vector<unsigned char> > CryptedMalleableKeyMap;

//
// C, Keystore which keeps the private keys encrypted.
// It derives from the basic key store, which is used if no encryption is active.
//
class CCryptoKeyStore : public CBasicKeyStore
{
    CCryptoKeyStore(const CCryptoKeyStore &)=delete;
    CCryptoKeyStore &operator=(const CCryptoKeyStore &)=delete;

private:
    CryptedKeyMap mapCryptedKeys;
    CryptedMalleableKeyMap mapCryptedMalleableKeys;
    CKeyingMaterial vMasterKey;

    // CCryptoKeyStore::SetCrypted() is confirmed the fUseCrypto flag only:
    // if fUseCrypto is true, CBasicKeyStore::mapKeys must be empty
    // if fUseCrypto is false, CCryptoKeyStore::vMasterKey must be empty
    bool fUseCrypto;

protected:
    bool SetCrypted();

    //
    // will encrypt previously unencrypted keys
    //
    bool EncryptKeys(CKeyingMaterial &vMasterKeyIn);
    bool DecryptKeys(const CKeyingMaterial &vMasterKeyIn);

    bool Unlock(const CKeyingMaterial &vMasterKeyIn);

public:
    CCryptoKeyStore() : fUseCrypto(false) {}

    bool IsCrypted() const {
        return fUseCrypto;
    }

    bool IsLocked() const {
        if (! IsCrypted()) {
            return false;
        }

        bool result;
        {
            LOCK(cs_KeyStore);
            result = vMasterKey.empty();
        }
        return result;
    }

    bool Lock();

    virtual bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    virtual bool AddCryptedMalleableKey(const CMalleableKeyView& keyView, const std::vector<unsigned char> &vchCryptedSecretH);

    bool AddKey(const CKey& key);
    bool AddMalleableKey(const CMalleableKeyView& keyView, const CSecret &vchSecretH);
    bool HaveKey(const CKeyID &address) const {
        {
            LOCK(cs_KeyStore);
            if (! IsCrypted()) {
                return CBasicKeyStore::HaveKey(address);
            }
            return mapCryptedKeys.count(address) > 0;
        }
    }
    bool GetKey(const CKeyID &address, CKey &keyOut) const;
    bool GetKey(const CKeyID &address, CFirmKey &keyOut) const;
    bool GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const;
    void GetKeys(std::set<CKeyID> &setAddress) const {
        if (! IsCrypted()) {
            CBasicKeyStore::GetKeys(setAddress);
            return;
        }

        setAddress.clear();
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        while (mi != mapCryptedKeys.end())
        {
            setAddress.insert((*mi).first);
            mi++;
        }
    }

    bool GetMalleableKey(const CMalleableKeyView &keyView, CMalleableKey &mKey) const;

    bool CheckOwnership(const CPubKey &pubKeyVariant, const CPubKey &R) const {
        {
            LOCK(cs_KeyStore);
            if (! IsCrypted()) {
                return CBasicKeyStore::CheckOwnership(pubKeyVariant, R);
            }
            for (CryptedMalleableKeyMap::const_iterator mi = mapCryptedMalleableKeys.begin(); mi != mapCryptedMalleableKeys.end(); mi++)
            {
                if (mi->first.CheckKeyVariant(R, pubKeyVariant)) {
                    return true;
                }
            }
        }
        return false;
    }

    bool CheckOwnership(const CPubKey &pubKeyVariant, const CPubKey &R, CMalleableKeyView &view) const {
        {
            LOCK(cs_KeyStore);
            if (! IsCrypted()) {
                return CBasicKeyStore::CheckOwnership(pubKeyVariant, R, view);
            }
            for (CryptedMalleableKeyMap::const_iterator mi = mapCryptedMalleableKeys.begin(); mi != mapCryptedMalleableKeys.end(); mi++)
            {
                if (mi->first.CheckKeyVariant(R, pubKeyVariant)) {
                    view = mi->first;
                    return true;
                }
            }
        }
        return false;
    }

    bool CheckOwnership(const CMalleablePubKey &mpk) {
        CMalleableKeyView view;
        return GetMalleableView(mpk, view);
    }

    bool CreatePrivKey(const CPubKey &pubKeyVariant, const CPubKey &R, CKey &privKey) const;

    void ListMalleableViews(std::list<CMalleableKeyView> &malleableViewList) const {
        malleableViewList.clear();
        {
            LOCK(cs_KeyStore);
            if (! IsCrypted()) {
                return CBasicKeyStore::ListMalleableViews(malleableViewList);
            }
            for (CryptedMalleableKeyMap::const_iterator mi = mapCryptedMalleableKeys.begin(); mi != mapCryptedMalleableKeys.end(); mi++)
            {
                malleableViewList.push_back(CMalleableKeyView(mi->first));
            }
        }
    }

    bool GetMalleableView(const CMalleablePubKey &mpk, CMalleableKeyView &view) {
        const CKeyID &mpkID = mpk.GetID();
        {
            LOCK(cs_KeyStore);
            if (! IsCrypted()) {
                return CBasicKeyStore::GetMalleableView(mpk, view);
            }
            for (CryptedMalleableKeyMap::const_iterator mi = mapCryptedMalleableKeys.begin(); mi != mapCryptedMalleableKeys.end(); mi++)
            {
                if (mi->first.GetID() == mpkID) {
                    view = CMalleableKeyView(mi->first);
                    return true;
                }
            }
        }
        return false;
    }

    bool GetEthAddr(const CKeyID &id, std::string &address) const;

    //
    // Wallet status (encrypted, locked) changed.
    // Note: Called without locks held.
    //
    boost::signals2::signal<void (CCryptoKeyStore *wallet)> NotifyStatusChanged;
};

// A virtual base class for key stores
/*
class CKeyStore : public SigningProvider
{
public:
    //! Add a key to the store.
    virtual bool AddKeyPubKey(const CKey &key, const CPubKey &pubkey) =0;

    //! Check whether a key corresponding to a given address is present in the store.
    virtual bool HaveKey(const CKeyID &address) const =0;
    virtual std::set<CKeyID> GetKeys() const =0;

    //! Support for BIP 0013 : see https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
    virtual bool AddCScript(const CScript& redeemScript) =0;
    virtual bool HaveCScript(const CScriptID &hash) const =0;
    virtual std::set<CScriptID> GetCScripts() const =0;

    //! Support for Watch-only addresses
    virtual bool AddWatchOnly(const CScript &dest) =0;
    virtual bool RemoveWatchOnly(const CScript &dest) =0;
    virtual bool HaveWatchOnly(const CScript &dest) const =0;
    virtual bool HaveWatchOnly() const =0;
};

// Basic key store, that keeps keys in an address->secret map
class CBasicKeyStore : public CKeyStore
{
protected:
    mutable CCriticalSection cs_KeyStore;

    using KeyMap = std::map<CKeyID, CKey>;
    using WatchKeyMap = std::map<CKeyID, CPubKey>;
    using ScriptMap = std::map<CScriptID, CScript>;
    using WatchOnlySet = std::set<CScript>;

    KeyMap mapKeys GUARDED_BY(cs_KeyStore);
    WatchKeyMap mapWatchKeys GUARDED_BY(cs_KeyStore);
    ScriptMap mapScripts GUARDED_BY(cs_KeyStore);
    WatchOnlySet setWatchOnly GUARDED_BY(cs_KeyStore);

    void ImplicitlyLearnRelatedKeyScripts(const CPubKey& pubkey) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);

public:
    bool AddKeyPubKey(const CKey& key, const CPubKey &pubkey) override;
    bool AddKey(const CKey &key) { return AddKeyPubKey(key, key.GetPubKey()); }
    bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const override;
    bool HaveKey(const CKeyID &address) const override;
    std::set<CKeyID> GetKeys() const override;
    bool GetKey(const CKeyID &address, CKey &keyOut) const override;
    bool AddCScript(const CScript& redeemScript) override;
    bool HaveCScript(const CScriptID &hash) const override;
    std::set<CScriptID> GetCScripts() const override;
    bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const override;

    bool AddWatchOnly(const CScript &dest) override;
    bool RemoveWatchOnly(const CScript &dest) override;
    bool HaveWatchOnly(const CScript &dest) const override;
    bool HaveWatchOnly() const override;
};

// Return the CKeyID of the key involved in a script (if there is a unique one).
CKeyID GetKeyForDestination(const CKeyStore& store, const CTxDestination& dest);

// Checks if a CKey is in the given CKeyStore compressed or otherwise
bool HaveKey(const CKeyStore& store, const CKey& key);
*/

#endif
