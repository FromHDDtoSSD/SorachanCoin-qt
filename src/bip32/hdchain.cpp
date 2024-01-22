// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <db.h>
#include <wallet.h>
#include <walletdb.h>
#include <key/privkey.h>
#include <random/random.h>
#include <init.h>
#include <bip32/hdchain.h>
//#include <crypto/hmac_sha512.h>

namespace SeedCrypto {
    static const unsigned char civ[] = {'S','o','r','a','c','h','a','n','C','o','i','n','S','e','e','d'}; // AES_BLOCKSIZE: 16 bytes
    constexpr int keysaltsize = 32;

    void CreateKeyToHash(const CSeedSecret &keydata, CSeedSecret &outkeysalt, unsigned char keyhash[latest_crypto::AES256_KEYSIZE]) {
        seed::RandAddSeedPerfmon();
        outkeysalt.resize(keysaltsize);
        latest_crypto::random::GetStrongRandBytes(&outkeysalt.front(), keysaltsize);
        latest_crypto::CHMAC_SHA256(outkeysalt.data(), outkeysalt.size()).Write(keydata.data(), keydata.size()).Finalize(keyhash);
    }

    void GetKeyToHash(const CSeedSecret &keydata, const CSeedSecret &keysalt, unsigned char keyhash[latest_crypto::AES256_KEYSIZE]) {
        latest_crypto::CHMAC_SHA256(keysalt.data(), keysalt.size()).Write(keydata.data(), keydata.size()).Finalize(keyhash);
    }

    CSeedSecret DataAddSignature(const CSeedSecret &org) {
        CSeedSecret ret;
        ret.resize(org.size() + 16);
        ::memcpy(&ret.front(), org.data(), org.size());
        ::memcpy(&ret.front() + org.size(), civ, 16);
        return ret;
    }

    bool IsValidData(const CSeedSecret &data, CSeedSecret &out) {
        if(data.size()<=16)
            return false;
        int pos = data.size() - 16;
        if(::memcmp(data.data() + pos, civ, 16) != 0)
            return false;

        out.resize(data.size() - 16);
        ::memcpy(&out.front(), data.data(), data.size() - 16);
        return true;
    }

    bool IsValidDataPermitBlank(const CSeedSecret &data, CSeedSecret &out) {
        if(data.size()<16)
            return false;
        int pos = data.size() - 16;
        if(::memcmp(data.data() + pos, civ, 16) != 0)
            return false;
        if(pos == 0) {
            out.clear();
            return true;
        }

        out.resize(data.size() - 16);
        ::memcpy(&out.front(), data.data(), data.size() - 16);
        return true;
    }

    bool Encrypto(const unsigned char key[latest_crypto::AES256_KEYSIZE], const unsigned char *data, size_t size, unsigned char *out, size_t *outsize) {
        std::vector<unsigned char> iv;
        iv.resize(latest_crypto::AES_BLOCKSIZE);
        ::memcpy(&iv.front(), civ, latest_crypto::AES_BLOCKSIZE);
        latest_crypto::AES256CBCEncrypt context(key, iv.data(), true);
        *outsize = context.Encrypt(data, size, out);
        return *outsize != 0;
    }

    bool Decrypto(const unsigned char key[latest_crypto::AES256_KEYSIZE], const unsigned char *data, size_t size, unsigned char *out, size_t *outsize) {
        std::vector<unsigned char> iv;
        iv.resize(latest_crypto::AES_BLOCKSIZE);
        ::memcpy(&iv.front(), civ, latest_crypto::AES_BLOCKSIZE);
        latest_crypto::AES256CBCDecrypt context(key, iv.data(), true);
        *outsize = context.Decrypt(data, size, out);
        return *outsize != 0;
    }
}

hd_wallet::~hd_wallet() {
    delete pkeyseed;
}

bool hd_wallet::InValidKeyseed() {
    if(! pkeyseed)
        return true;

    delete pkeyseed; // operation secure allocator
    pkeyseed = new (std::nothrow) CExtKey;
    if(! pkeyseed)
        return false;

    unsigned char zero[CExtPubKey::BIP32_EXTKEY_SIZE] = {0};
    pkeyseed->Decode(zero);

    fcryptoseed = true; // locked
    return true;
}

bool hd_wallet::get_nextkey(CExtKey &nextkey, const CExtKey &extkeyseed) {
    //CPrivKey vchprivkey;
    //vchprivkey.resize(CExtPubKey::BIP32_EXTKEY_SIZE);
    //extkeyseed.Encode(&vchprivkey.front());
    //CExtKey key;
    //key.Decode(vchprivkey.data());

    __printf("_child_numof: %d\n", _child_offset);
    if(! extkeyseed.Derive(nextkey, _child_offset++))
        return false;
    if(! nextkey.privkey_.IsValid())
        return false;
    if(! nextkey.privkey_.GetPubKey().IsFullyValid_BIP66())
        return false;

    //__printf("nextkey fingerprint:%c %c %c %c\n", nextkey.vchFingerprint_[0], nextkey.vchFingerprint_[1], nextkey.vchFingerprint_[2], nextkey.vchFingerprint_[3]);
    //__printf("nextkey chaincode:%s\n", nextkey.chaincode_.GetHex().c_str());
    __printf("nextkey child:%d depth:%d\n", nextkey.nChild_, nextkey.nDepth_);
    __printf("nextkey pubkey id :%s\n", nextkey.privkey_.GetPubKey().GetID().GetHex().c_str());
    return true;
}

//
// must be call create_seed: when balance 0 and Decrypted
//
bool hd_wallet::create_seed(const CSeedSecret &seed, CSeedSecret &outvchextkey, std::vector<CPubKey> &outpubkeys) {
    constexpr int generate_keys_unit = hdkeys_child_regenerate;

    CExtKey keyseed;
    if(seed.size()==0)
        return false;
    if(! keyseed.SetSeed(seed.data(), seed.size()))
        return false;

    CPubKey pubkeyseed = keyseed.privkey_.GetPubKey();
    if(! pubkeyseed.IsFullyValid_BIP66())
        return false;

    CExtKey nextkey[generate_keys_unit];
    for(int i=0; i<generate_keys_unit; ++i) {
        if(! hd_wallet::get_nextkey(nextkey[i], keyseed))
            return false;
    }

    //CWalletDB walletdb(std::string(""), std::string(""), CSqliteDBEnv::getname_wallet());
    CWalletDB walletdb(entry::pwalletMain->strWalletFile, entry::pwalletMain->strWalletLevelDB, entry::pwalletMain->strWalletSqlFile);
    LOCK(entry::pwalletMain->cs_wallet);

    CSeedSecret cryptosalt;
    cryptosalt.resize(SeedCrypto::keysaltsize); // when no crypto, no necessary.
    cleanse::OPENSSL_cleanse(&cryptosalt.front(), SeedCrypto::keysaltsize);

    CPrivKey vchextkey;
    vchextkey.resize(CExtPubKey::BIP32_EXTKEY_SIZE);
    if(! keyseed.Encode(&vchextkey.front()))
        return false;
    if(! walletdb.WriteHDSeed(pubkeyseed, vchextkey, _child_offset, cryptosalt, 0))
        return false;

    outvchextkey = vchextkey;

    // Erase random-wallet keys
    // remaining random wallet keys
    /* SORA L1 - Blockchain is no supported these erase because using random-wallet too
    {
        //LOCK(entry::pwalletMain->cs_wallet);
        std::vector<CPubKey> vpubkeys;
        IDB::DbIterator ite = walletdb.GetIteCursor();
        if(ite.is_error())
            return false;
        for(;;) {
            CDataStream ssKey, ssValue;
            int ret = IDB::ReadAtCursor(ite, ssKey, ssValue);
            if(ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
                return false;
            std::string strType;
            ssKey >> strType;
            if(strType == "key") {
                CPubKey pubkey;
                ssKey >> pubkey;
                vpubkeys.emplace_back(pubkey);
            }
        }
        __printf("EraseKey: random-wallet keys num: %d\n", (int)vpubkeys.size());
        for(const auto &pubkey: vpubkeys) {
            __printf("EraseKey: random-wallet keys id: %s\n", pubkey.GetID().GetHex().c_str());
            if(! walletdb.EraseKey(pubkey))
                return false;
        }
        if(! entry::pwalletMain->EraseBasicKey())
            return false;
    }
    */

    //
    // Registerd hd-wallet keys
    //
    {
        //LOCK(entry::pwalletMain->cs_wallet);
        std::vector<CPubKey> &pubkeys = outpubkeys;
        pubkeys.clear();
        for(int i=0; i<generate_keys_unit; ++i) {
            pubkeys.emplace_back(nextkey[i].privkey_.GetPubKey());
        }
        if(! walletdb.WriteReservedHDPubkeys(pubkeys))
            return false;
        if(! walletdb.WriteUsedHDKey(0))
            return false;
        //outpubkeys = pubkeys;
    }

    // register hd wallet keys
    //int64_t nCreationTime = bitsystem::GetTime();
    for(int i=0; i<generate_keys_unit; ++i) {
        if(! nextkey[i].privkey_.IsValid())
            return false;

        CPubKey pubkey = nextkey[i].privkey_.GetPubKey();
        if(! pubkey.IsFullyValid_BIP66())
            return false;
        //if(! walletdb.WriteKey(pubkey, nextkey[i].privkey_.GetPrivKey(), CKeyMetadata(nCreationTime + i)))
        //  return false;
        if(! entry::pwalletMain->AddKey(nextkey[i].privkey_))
            return false;
    }
    return true;
}

// if handle qkey, must use try and catch (exception)
CqSecretKey hd_wallet::GetSecretKey() {
    if(! enable)
        throw std::runtime_error("invalid HD Wallet.");
    if(entry::pwalletMain->IsLocked())
        throw std::runtime_error("locked HD Wallet.");

    assert(sizeof(uint512)==64);
    constexpr size_t qkeysize = 16 * 1024;
    CqSecretKey qsecretkey;
    qsecretkey.resize(qkeysize);

    std::string salt = "SorachanCoin quantum resistance salt\n";
    for(int i=0; i < qkeysize; i+=sizeof(uint512)) {
        salt += std::to_string(i);
        uint512 hash;
        latest_crypto::CHMAC_SHA512((const unsigned char *)salt.data(), salt.size()).Write(hd_wallet::get().pkeyseed->privkey_.begin(), hd_wallet::get().pkeyseed->privkey_.size()).Finalize(hash.begin());
        ::memcpy(&qsecretkey.front() + i, hash.begin(), sizeof(uint512));
        cleanse::OPENSSL_cleanse(hash.begin(), sizeof(uint512));
    }

    return qsecretkey;
}

CqKeyID hd_wallet::GetKeyID() { // get a compact pubkey keyid (1024 bytes)
    return GetPubKey().GetID();
}

CqPubKey hd_wallet::GetPubKey() {
    if(! enable)
        throw std::runtime_error("invalid HD Wallet.");
    if(entry::pwalletMain->IsLocked())
        throw std::runtime_error("locked HD Wallet.");

    CqSecretKey qsecretkey = hd_wallet::GetSecretKey();
    CqKey qkey(qsecretkey);
    if(! qkey.IsValid())
        throw std::runtime_error("invalid CqSecretKey.");

    CqPubKey pubkey = qkey.GetPubKey();
    if(! pubkey.IsFullyValid_BIP66())
        throw std::runtime_error("invalid CqPubKey.");

    return pubkey;
}


namespace hd_wallet_debug {
    int _debug_depth = 0;
    bool hd_enabled = false;
    static CPrivKey *_debug_data = nullptr;

    void create_seed(std::string seed) {
        CExtKey key;
        _debug_data = new CPrivKey;
        bool ret = key.SetSeed((const unsigned char *)seed.c_str(), seed.size());
        __printf("seed master ret : %d\n", ret);
        __printf("seed master : %s\n", key.privkey_.GetPubKey().GetID().GetHex().c_str());
        _debug_data->resize(CExtPubKey::BIP32_EXTKEY_SIZE);
        key.Encode(&_debug_data->front());
        hd_enabled = true;
    }

    void get_key() {
        CExtKey key1, key2;
        bool ret1 = key1.Decode(_debug_data->data());
        bool ret2 = key1.Derive(key2, _debug_depth);
        __printf("seed %d ret1:%d ret2:%d\n", _debug_depth, ret1, ret2);
        __printf("seed fingerprint:%c %c %c %c\n", key2.vchFingerprint_[0], key2.vchFingerprint_[1], key2.vchFingerprint_[2], key2.vchFingerprint_[3]);
        __printf("seed chaincode:%s\n", key2.chaincode_.GetHex().c_str());
        __printf("seed child:%d depth:%d\n", key2.nChild_, key2.nDepth_);
        __printf("seed %d : %s\n", _debug_depth, key2.privkey_.GetPubKey().GetID().GetHex().c_str());
        ++_debug_depth;
        bool ret3 = key2.Encode(&_debug_data->front());
        __printf("seed ret3:%d\n", ret3);
    }
}
