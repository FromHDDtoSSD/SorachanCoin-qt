// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <keystore.h>
#include <script/script.h>
#include <address/base58.h>
#include <wallet.h> // CWallet::fWalletUnlockMintOnly

namespace firmkeydebug {

static bool sign1(const CFirmKey &fikey, const uint256 &hash, int nHashType, CScript &scriptSigRet) {
    key_vector vchSig;
    if(! fikey.Sign(hash, vchSig))
        return false;

    vchSig.push_back((unsigned char)nHashType);
    scriptSigRet << vchSig;
    return true;
}

static bool signC(const CFirmKey &fikey, const uint256 &hash, int nHashType, CScript &scriptSigRet) {
    key_vector vchSig;
    if(! fikey.SignCompact(hash, vchSig))
        return false;

    vchSig.push_back((unsigned char)nHashType);
    scriptSigRet << vchSig;
    return true;
}

static uint256 SignatureHash(const CScript &scriptCodeIn, const CTransaction &txTo, unsigned int nIn, int nHashType) {
    if (nIn >= txTo.get_vin().size())
        return uint256(1);

    CScript scriptCode(scriptCodeIn);
    CTransaction txTmp(txTo);
    scriptCode.FindAndDelete(CScript(ScriptOpcodes::OP_CODESEPARATOR));
    for (auto &d: txTmp.set_vin()) {
        d.set_scriptSig(CScript());
    }
    txTmp.set_vin(nIn).set_scriptSig(scriptCode);

    if ((nHashType & 0x1f) == Script_param::SIGHASH_NONE) {
        txTmp.set_vout().clear();
        for (unsigned int i = 0; i < txTmp.get_vin().size(); ++i) {
            if (i != nIn)
                txTmp.set_vin(i).set_nSequence(0);
        }
    } else if ((nHashType & 0x1f) == Script_param::SIGHASH_SINGLE) {
        unsigned int nOut = nIn;
        if (nOut >= txTmp.get_vout().size())
            return false;

        txTmp.set_vout().resize(nOut+1);
        for (unsigned int i = 0; i < nOut; ++i)
            txTmp.set_vout(i).SetNull();

        for (unsigned int i = 0; i < txTmp.get_vin().size(); ++i) {
            if (i != nIn)
                txTmp.set_vin(i).set_nSequence(0);
        }
    }

    if (nHashType & Script_param::SIGHASH_ANYONECANPAY) {
        txTmp.set_vin(0) = txTmp.get_vin(nIn);
        txTmp.set_vin().resize(1);
    }

    CDataStream ss(SER_GETHASH, 0);
    ss.reserve(10000);
    ss << txTmp << nHashType;
    uint256 hash;
    latest_crypto::CHash256().Write((const unsigned char *)&ss[0], ss.size()).Finalize((unsigned char *)&hash);
    return hash;
}

static bool ecrecover(const uint256 &hash, const key_vector &sig, CPubKey &pubkeyRet, bool fCompress = true) {
    if(! pubkeyRet.RecoverCompact(hash, sig))
        return false;
    if(! pubkeyRet.IsFullyValid_BIP66())
        return false;

    // SignCompact and RecoverCompact generate compressed public key in any case,
    // then, if require decompress public key, must call decompress method.
    if(fCompress)
        (pubkeyRet.IsCompressed()==false) ? pubkeyRet.Compress(): 0;
    else
        pubkeyRet.IsCompressed() ? pubkeyRet.Decompress(): 0;

    return true;
}

static CSecret DecodeEthStylePrivKey(const SecureString &address) {
    if(! (address.size()==64 || address.size()==66))
        throw std::runtime_error("address is invalid.");

    const char *begin = (address[0]=='0' && address[1]=='x') ? address.data() + 2: address.data();
    return strenc::ParseHex<CSecret>(begin);
}

template <typename T=CKey>
static void debug1(const T &key) {
    //using namespace ScriptOpcodes;

    /* keccak256 sha3: ok
    {
        uint256 hashke;
        keccak256_lib::Keccak kecc;
        kecc.Init();
        kecc.Update((const unsigned char *)"hello", 5);
        kecc.Finalize((unsigned char *)&hashke);
        debugcs::instance() << strenc::HexStr(key_vector(hashke.begin(), hashke.begin() + 32)) << debugcs::endl();
    }

    {
        uint256 hashke;
        latest_crypto::CKECCAK256().Write((const unsigned char *)"hello", 5).Finalize((unsigned char *)&hashke);
        debugcs::instance() << strenc::HexStr(key_vector(hashke.begin(), hashke.begin() + 32)) << debugcs::endl();
    }
    */

    /* Eth style adress: ok
     * pubkey: 0xae72a48c1a36bd18af168541c53037965d26e4a8
    {
        char tmp[128];
        strcpy(tmp, "7777777777777777777777777777777777777777777777777777777777777777");
        SecureString secretkey;
        secretkey.operator=((char *)&tmp[0]);
        CSecret secret = DecodeEthStylePrivKey(secretkey);
        debugcs::instance() << strenc::HexStr(key_vector(secret.begin(), secret.end())) << debugcs::endl();
        CFirmKey fikey;
        fikey.Set(secret.begin(), secret.end(), true);
        CPubKey pubkey = fikey.GetPubKey();
        debugcs::instance() << "pubkey CKeyID: " << strenc::HexStr(pubkey.GetID()) << debugcs::endl();
        key_vector vchPubKey = pubkey.GetPubEth();
        uint160 hash;
        latest_crypto::CHashEth().Write((const unsigned char *)vchPubKey.data(), vchPubKey.size()).Finalize((unsigned char *)&hash);
        debugcs::instance() << "Eth Style public key: 0x" << strenc::HexStr(key_vector(hash.begin(), hash.end())) << debugcs::endl();
    }
    */

    /* checking privhash and custom script(for DAO): OK
    {
        CFirmKey fikey;
        CSecret secret = key.GetSecret();
        fikey.Set(secret.begin(), secret.end(), key.IsCompressed());
        fikey.SetCompressedPubKey(true);

        uint256 privhash;
        CSecret target = fikey.GetSecret();
        latest_crypto::CHash256().Write((const unsigned char *)target.data(), target.size()).Finalize((unsigned char *)&privhash);

        CTxIn txin;
        txin.set_prevout().SetNull();
        CTxOut txout;
        CScript scriptPubKey = CScript() << OP_DUP << OP_HASH160 << fikey.GetPubKey().GetID() << OP_EQUALVERIFY << OP_CHECKSIGVERIFY << privhash << OP_EQUAL;
        txout.set_scriptPubKey() = scriptPubKey;
        txout.set_nValue(1000000);

        CTransaction tx;
        tx.set_vin().emplace_back(txin);
        tx.set_vout().emplace_back(txout);
        uint256 txhash = SignatureHash(scriptPubKey, tx, 0, Script_param::SIGHASH_ALL);
        CScript scriptSig;
        assert(sign1(fikey, txhash, Script_param::SIGHASH_ALL, scriptSig)==true);
        CScript scriptDao = CScript() << privhash;
        scriptDao += scriptSig;
        scriptDao << fikey.GetPubKey();
        tx.set_vin(0).set_scriptSig() = scriptDao;
        assert(Script_util::VerifyScript(scriptDao, scriptPubKey, tx, 0, Script_param::STRICT_FLAGS, Script_param::SIGHASH_ALL)==true);
    }
    */

    // checking txconbase CFirmKey: ok
    /*
    {
        CFirmKey fikey;
        CSecret secret = key.GetSecret();
        fikey.Set(secret.begin(), secret.end(), key.IsCompressed());
        fikey.SetCompressedPubKey(true);

        CTransaction txCoinBase;
        txCoinBase.set_vin().resize(1);
        txCoinBase.set_vin(0).set_prevout().SetNull();
        txCoinBase.set_vout().resize(1);
        txCoinBase.set_vout(0).set_scriptPubKey().SetDestination(fikey.GetPubKey().GetID());
        txCoinBase.set_vout(0).set_nValue(1000000);

        CScript scriptPubKey = CScript() << OP_DUP << OP_HASH160 << fikey.GetPubKey().GetID() << OP_EQUALVERIFY << OP_CHECKSIG;
        debugcs::instance() << scriptPubKey.ToString() << debugcs::endl();
        assert(scriptPubKey == txCoinBase.get_vout(0).get_scriptPubKey());
        uint256 txhash = SignatureHash(scriptPubKey, txCoinBase, 0, Script_param::SIGHASH_ALL);

        CScript scriptSig;
        assert(sign1(fikey, txhash, Script_param::SIGHASH_ALL, scriptSig) == true);
        scriptSig << fikey.GetPubKey();
        txCoinBase.set_vin(0).set_scriptSig() = scriptSig;
        assert(Script_util::VerifyScript(scriptSig, scriptPubKey, txCoinBase, 0, Script_param::STRICT_FLAGS, Script_param::SIGHASH_ALL)==true);
    }
    */

    /* checking custom opecode CFirmKey: ok
    {
        CFirmKey fikey;
        CSecret secret = key.GetSecret();
        fikey.Set(secret.begin(), secret.end(), key.IsCompressed());
        fikey.SetCompressedPubKey(true);

        CTxIn txin;
        txin.set_prevout().SetNull();
        CTxOut txout;
        CScript scriptPubKey = CScript() << OP_HASH160 << fikey.GetPubKey().GetID() << OP_EQUALVERIFY << OP_CHECKSIG;
        txout.set_scriptPubKey() = scriptPubKey;
        txout.set_nValue(1000000);

        CTransaction tx;
        tx.set_vin().emplace_back(txin);
        tx.set_vout().emplace_back(txout);
        uint256 txhash = SignatureHash(scriptPubKey, tx, 0, Script_param::SIGHASH_ALL);
        CScript scriptSig;
        assert(sign1(fikey, txhash, Script_param::SIGHASH_ALL, scriptSig)==true);
        scriptSig << fikey.GetPubKey() << fikey.GetPubKey();
        tx.set_vin(0).set_scriptSig() = scriptSig;
        assert(Script_util::VerifyScript(scriptSig, scriptPubKey, tx, 0, Script_param::STRICT_FLAGS, Script_param::SIGHASH_ALL)==true);
    }
    */

    /*
    {
        CFirmKey fikey;
        CSecret secret = key.GetSecret();
        fikey.Set(secret.begin(), secret.end(), key.IsCompressed());
        fikey.SetCompressedPubKey(true);

        CTxIn txin;
        txin.set_prevout().SetNull();
        CTxOut txout;
        CScript redeemScript = CScript() << OP_1 << fikey.GetPubKey() << OP_1 << OP_CHECKMULTISIG;
        CScript scriptPubKey = CScript() << redeemScript.GetID() << OP_EQUAL;

        //assert(Script_util::VerifyScript(scriptSig, scriptPubKey, tx, 0, Script_param::STRICT_FLAGS, Script_param::SIGHASH_ALL)==true);
    }
    */

    /* CFirmKey multisig: P2PK and OP_IF ok
    {
        CFirmKey fikey;
        CSecret secret = key.GetSecret();
        fikey.Set(secret.begin(), secret.end(), key.IsCompressed());
        fikey.SetCompressedPubKey(true);

        CFirmKey fikey2;
        fikey2.MakeNewKey(true);

        CTxIn txin;
        txin.set_prevout().SetNull();
        CTxOut txout;
        CScript scriptPubKey = CScript() << fikey.GetPubKey() << OP_CHECKSIG << OP_IF << fikey2.GetPubKey() << OP_CHECKSIG << OP_ELSE << OP_FALSE << OP_ENDIF;
        txout.set_scriptPubKey() = scriptPubKey;
        txout.set_nValue(1000000);

        CTransaction tx;
        tx.set_vin().emplace_back(txin);
        tx.set_vout().emplace_back(txout);
        uint256 txhash = SignatureHash(scriptPubKey, tx, 0, Script_param::SIGHASH_ALL);
        CScript multiSig;
        assert(sign1(fikey2, txhash, Script_param::SIGHASH_ALL, multiSig)==true);
        assert(sign1(fikey, txhash, Script_param::SIGHASH_ALL, multiSig)==true);
        tx.set_vin(0).set_scriptSig() = multiSig;
        assert(Script_util::VerifyScript(multiSig, scriptPubKey, tx, 0, Script_param::STRICT_FLAGS, Script_param::SIGHASH_ALL)==true);
    }
    */

    /* CFirmKey multisig: P2PKH ok
    {
        CFirmKey fikey;
        CSecret secret = key.GetSecret();
        fikey.Set(secret.begin(), secret.end(), key.IsCompressed());
        fikey.SetCompressedPubKey(true);

        CFirmKey fikey2;
        fikey2.MakeNewKey(true);

        CTxIn txin;
        txin.set_prevout().SetNull();
        CTxOut txout;
        CScript scriptPubKey = CScript() << OP_DUP << OP_HASH160 << fikey.GetPubKey().GetID() << OP_EQUALVERIFY << OP_CHECKSIGVERIFY << OP_DUP << OP_HASH160 << fikey2.GetPubKey().GetID() << OP_EQUALVERIFY << OP_CHECKSIG;
        txout.set_scriptPubKey() = scriptPubKey;
        txout.set_nValue(1000000);

        CTransaction tx;
        tx.set_vin().emplace_back(txin);
        tx.set_vout().emplace_back(txout);
        uint256 txhash = SignatureHash(scriptPubKey, tx, 0, Script_param::SIGHASH_ALL);
        CScript multiSig1;
        assert(sign1(fikey, txhash, Script_param::SIGHASH_ALL, multiSig1)==true);
        multiSig1 << fikey.GetPubKey();
        CScript multiSig2;
        assert(sign1(fikey2, txhash, Script_param::SIGHASH_ALL, multiSig2)==true);
        multiSig2 << fikey2.GetPubKey();
        multiSig2 += multiSig1;
        tx.set_vin(0).set_scriptSig() = multiSig2;
        assert(Script_util::VerifyScript(multiSig2, scriptPubKey, tx, 0, Script_param::STRICT_FLAGS, Script_param::SIGHASH_ALL)==true);
    }
    */

    // ETH style(ecrecover) consensus in SignCompact and RecoverCompact
    /* debug ok
    CFirmKey fikey;
    CSecret secret = key.GetSecret();
    fikey.Set(secret.begin(), secret.end(), key.IsCompressed());
    fikey.SetCompressedPubKey(true);
    debugcs::instance() << "pubkey compressed: " << strenc::HexStr(fikey.GetPubKey().GetPubVch()) << debugcs::endl();
    fikey.SetCompressedPubKey(false);
    debugcs::instance() << "pubkey decompress: " << strenc::HexStr(fikey.GetPubKey().GetPubVch()) << debugcs::endl();

    CTxIn txin;
    CTxOut txout;
    CScript scriptPubKey = CScript() << OP_DUP << OP_HASH160 << fikey.GetPubKey().GetID() << OP_EQUALVERIFY << OP_CHECKSIG;

    CTransaction tx;
    tx.set_vin().emplace_back(txin);
    tx.set_vout().emplace_back(txout);

    uint256 txhash = SignatureHash(scriptPubKey, tx, 0, Script_param::SIGHASH_ALL);
    debugcs::instance() << "sign target hash: " << txhash.ToString() << debugcs::endl();

    fikey.SetCompressedPubKey(true);
    key_vector sig;
    fikey.SignCompact(txhash, sig);
    CPubKey pubkey;
    assert(ecrecover(txhash, sig, pubkey, fikey.IsCompressed())==true);
    assert(pubkey.IsCompressed() == fikey.GetPubKey().IsCompressed());
    assert(pubkey == fikey.GetPubKey());

    fikey.SetCompressedPubKey(false);
    key_vector sig2;
    fikey.SignCompact(txhash, sig2);
    CPubKey pubkey2;
    assert(ecrecover(txhash, sig2, pubkey2, fikey.IsCompressed())==true);
    assert(pubkey2.IsCompressed() == fikey.GetPubKey().IsCompressed());
    assert(pubkey2 == fikey.GetPubKey());

    assert(pubkey != pubkey2);
    key_vector sig3;
    fikey.Sign(txhash, sig3);
    CPubKey pubkey3;
    assert(ecrecover(txhash, sig3, pubkey3, fikey.IsCompressed())==false);

    CPubKey pubkey4;
    assert(ecrecover(txhash, sig, pubkey4, true)==true);
    assert(ecrecover(txhash, sig, pubkey4, false)==true);
    */

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

} // namespace keydebug

bool CBasicKeyStore::EraseBasicKey() {
    LOCK(cs_KeyStore);
    mapKeys.clear();
    return true;
}

bool CBasicKeyStore::AddKey(const CKey &key)
{
    firmkeydebug::debug1(key);

    bool fCompressed = false;
    CSecret secret = key.GetSecret(fCompressed);

    {
        LOCK(cs_KeyStore);
        mapKeys[key.GetPubKey().GetID()] = std::make_pair(secret, fCompressed);
    }
    return true;
}

bool CBasicKeyStore::AddKey(const CFirmKey &key)
{
    firmkeydebug::debug1(key);

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

bool CBasicKeyStore::AddCScript(const CScript &redeemScript, const CPubKey &pubkey)
{
    if (redeemScript.size() > Script_const::MAX_SCRIPT_ELEMENT_SIZE) {
        return logging::error("CBasicKeyStore::AddCScript() : redeemScripts > %i bytes are invalid", Script_const::MAX_SCRIPT_ELEMENT_SIZE);
    }

    {
        LOCK(cs_KeyStore);
        CKeyID keyid = pubkey.GetID();
        CEthID ethid = GetEthAddr(pubkey);
        mapScripts[redeemScript.GetID()] = redeemScript;
        mapEths[redeemScript.GetID()] = std::make_pair(keyid, ethid);
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

bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript &redeemScriptOut, CKeyID &keyid, CEthID &ethid) const
{
    LOCK(cs_KeyStore);
    bool f1=false, f2=false;
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end()) {
        redeemScriptOut = (*mi).second;
        f1 = true;
    }

    EthMap::const_iterator mi2 = mapEths.find(hash);
    if (mi2 != mapEths.end()) {
        keyid = (*mi2).second.first;
        ethid = (*mi2).second.second;
        f2 = true;
    }

    return f1 && f2;
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

    if(hd_wallet::get().enable) {
        if(! LockHDSeed())
            return false;
    }

    NotifyStatusChanged(this);
    return true;
}

bool CCryptoKeyStore::LockHDSeed() {
    return hd_wallet::get().InValidKeyseed();
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

bool CCryptoKeyStore::AddKey(const CFirmKey &key)
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

CEthID CBasicKeyStore::GetEthAddr(const CPubKey &pubkey) {
    key_vector vchPubKey = pubkey.GetPubEth();
    uint160 hash;
    latest_crypto::CHashEth().Write((const unsigned char *)vchPubKey.data(), vchPubKey.size()).Finalize((unsigned char *)&hash);
    return CEthID(hash);
}

bool CBasicKeyStore::GetEthAddr(const CKeyID &id, std::string &address) const {
    LOCK(cs_KeyStore);

    KeyMap::const_iterator mi = mapKeys.find(id);
    if(mi != mapKeys.end()) {
        CFirmKey key;
        key.SetSecret((*mi).second.first, (*mi).second.second);
        address = hasheth::EncodeHashEth(key.GetPubKey());
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
        address = hasheth::EncodeHashEth(key.GetPubKey());
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
