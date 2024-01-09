// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
#include <script/standard.h>
#include <crypto/sha256.h>
#include <key/pubkey.h>
#include <script/script.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <prevector/prevector.h>
#include <hash.h>

#ifdef CSCRIPT_PREVECTOR_ENABLE
using valtype = prevector<PREVECTOR_N, unsigned char>;
using statype = prevector<PREVECTOR_N, prevector<PREVECTOR_N, unsigned char> >;
#else
using valtype = std::vector<unsigned char>;
using statype = std::vector<std::vector<unsigned char> >;
#endif

bool Script_param::fAcceptDatacarrier = Script_param::DEFAULT_ACCEPT_DATACARRIER;
unsigned Script_param::nMaxDatacarrierBytes = Script_param::MAX_OP_RETURN_RELAY;

WitnessV0ScriptHash::WitnessV0ScriptHash(const CScript &in) {
    latest_crypto::CSHA256().Write(in.data(), in.size()).Finalize(begin());
}

namespace {
bool MatchPayToPubkey(const CScript &script, valtype &pubkey) {
    using namespace ScriptOpcodes;
    if (script.size() == CPubKey::PUBLIC_KEY_SIZE + 2 && script[0] == CPubKey::PUBLIC_KEY_SIZE && script.back() == OP_CHECKSIG) {
        pubkey = valtype(script.begin() + 1, script.begin() + CPubKey::PUBLIC_KEY_SIZE + 1);
        return CPubKey::ValidSize(pubkey);
    }
    if (script.size() == CPubKey::COMPRESSED_PUBLIC_KEY_SIZE + 2 && script[0] == CPubKey::COMPRESSED_PUBLIC_KEY_SIZE && script.back() == OP_CHECKSIG) {
        pubkey = valtype(script.begin() + 1, script.begin() + CPubKey::COMPRESSED_PUBLIC_KEY_SIZE + 1);
        return CPubKey::ValidSize(pubkey);
    }
    return false;
}

bool MatchPayToPubkeyHash(const CScript &script, valtype &pubkeyhash) {
    using namespace ScriptOpcodes;
    if (script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 && script[2] == 20 && script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG) {
        pubkeyhash = valtype(script.begin () + 3, script.begin() + 23);
        return true;
    }
    return false;
}

/** Test for "small positive integer" script opcodes - OP_1 through OP_16. */
constexpr bool IsSmallInteger(ScriptOpcodes::opcodetype opcode) {
    using namespace ScriptOpcodes;
    return opcode >= OP_1 && opcode <= OP_16;
}

bool MatchMultisig(const CScript &script, unsigned int &required, statype &pubkeys) {
    using namespace ScriptOpcodes;
    opcodetype opcode;
    valtype data;
    CScript::const_iterator it = script.begin();
    if (script.size() < 1 || script.back() != OP_CHECKMULTISIG) return false;

    if (!script.GetOp(it, opcode, data) || !IsSmallInteger(opcode)) return false;
    required = CScript::DecodeOP_N(opcode);
    while (script.GetOp(it, opcode, data) && CPubKey::ValidSize(data)) {
        //pubkeys.emplace_back(std::move(data));
        pubkeys.push_back(data);
    }
    if (! IsSmallInteger(opcode)) return false;
    unsigned int keys = CScript::DecodeOP_N(opcode);
    if (pubkeys.size() != keys || keys < required) return false;
    return (it + 1 == script.end());
}
} // namespace

TxnOutputType::txnouttype Script_util::Solver(const CScript &scriptPubKey, statype &vSolutionsRet) {
    using namespace ScriptOpcodes;
    using namespace TxnOutputType;
    vSolutionsRet.clear();

    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    if (scriptPubKey.IsPayToScriptHash()) {
        valtype hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        vSolutionsRet.push_back(hashBytes);
        return TX_SCRIPTHASH;
    }

    int witnessversion;
    valtype witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_KEYHASH_SIZE) {
            vSolutionsRet.push_back(witnessprogram);
            return TX_WITNESS_V0_KEYHASH;
        }
        if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
            vSolutionsRet.push_back(witnessprogram);
            return TX_WITNESS_V0_SCRIPTHASH;
        }
        if (witnessversion != 0) {
            vSolutionsRet.push_back(valtype{(unsigned char)witnessversion});
            vSolutionsRet.push_back(std::move(witnessprogram));
            return TX_WITNESS_UNKNOWN;
        }
        return TX_NONSTANDARD;
    }

    // Provably prunable, data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the
    // script.
    if (scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_RETURN && scriptPubKey.IsPushOnly(scriptPubKey.begin()+1)) {
        return TX_NULL_DATA;
    }

    valtype data;
    if (MatchPayToPubkey(scriptPubKey, data)) {
        vSolutionsRet.push_back(std::move(data));
        return TX_PUBKEY;
    }

    if (MatchPayToPubkeyHash(scriptPubKey, data)) {
        vSolutionsRet.push_back(std::move(data));
        return TX_PUBKEYHASH;
    }

    unsigned int required;
    statype keys;
    if (MatchMultisig(scriptPubKey, required, keys)) {
        valtype header; header.push_back(static_cast<unsigned char>(required));
        vSolutionsRet.push_back(header); // safe as required is in range 1..16
        vSolutionsRet.insert(vSolutionsRet.end(), keys.begin(), keys.end());
        valtype term; term.push_back(static_cast<unsigned char>(keys.size()));
        vSolutionsRet.push_back(term); // safe as size is in range 1..16
        return TX_MULTISIG;
    }

    vSolutionsRet.clear();
    return TX_NONSTANDARD;
}

bool Script_util::ExtractDestination(const CScript &scriptPubKey, CTxDestination &addressRet) {
    using namespace TxnOutputType;

    statype vSolutions;
    txnouttype whichType = Solver(scriptPubKey, vSolutions);
    if (whichType == TX_PUBKEY) {
        CPubKey pubKey(vSolutions[0]);
        if (! pubKey.IsValid())
            return false;
        addressRet = pubKey.GetID();
        return true;
    } else if (whichType == TX_PUBKEYHASH) {
        addressRet = CKeyID(uint160(vSolutions[0]));
        return true;
    } else if (whichType == TX_SCRIPTHASH) {
        addressRet = CScriptID(uint160(vSolutions[0]));
        return true;
    } else if (whichType == TX_WITNESS_V0_KEYHASH) {
        WitnessV0KeyHash hash;
        std::copy(vSolutions[0].begin(), vSolutions[0].end(), hash.begin());
        addressRet = hash;
        return true;
    } else if (whichType == TX_WITNESS_V0_SCRIPTHASH) {
        WitnessV0ScriptHash hash;
        std::copy(vSolutions[0].begin(), vSolutions[0].end(), hash.begin());
        addressRet = hash;
        return true;
    } else if (whichType == TX_WITNESS_UNKNOWN) {
        WitnessUnknown unk;
        unk.version = vSolutions[0][0];
        std::copy(vSolutions[1].begin(), vSolutions[1].end(), unk.program);
        unk.length = vSolutions[1].size();
        addressRet = unk;
        return true;
    }
    // Multisig txns have more than one address...
    return false;
}

bool Script_util::ExtractDestinations(const CScript &scriptPubKey, TxnOutputType::txnouttype &typeRet, std::vector<CTxDestination> &addressRet, int &nRequiredRet) {
    using namespace TxnOutputType;

    addressRet.clear();
    statype vSolutions;
    typeRet = Solver(scriptPubKey, vSolutions);
    if (typeRet == TX_NONSTANDARD) {
        return false;
    } else if (typeRet == TX_NULL_DATA) {
        // This is data, not addresses
        return false;
    }

    if (typeRet == TX_MULTISIG) {
        nRequiredRet = vSolutions.front()[0];
        for (unsigned int i = 1; i < vSolutions.size()-1; ++i) {
            CPubKey pubKey(vSolutions[i]);
            if (! pubKey.IsValid())
                continue;
            CTxDestination address = pubKey.GetID();
            addressRet.push_back(address);
        }
        if (addressRet.empty())
            return false;
    } else {
        nRequiredRet = 1;
        if (typeRet == TxnOutputType::TX_PUBKEY_DROP)
            return true;

        CTxDestination address;
        if (! ExtractDestination(scriptPubKey, address))
           return false;
        addressRet.push_back(address);
    }

    return true;
}

namespace {
class CScriptVisitor : public boost::static_visitor<bool>
{
private:
    CScript *script;
public:
    explicit CScriptVisitor(CScript *scriptin) { script = scriptin; }

    bool operator()(const CNoDestination &dest) const {
        (void)dest;
        script->clear();
        return false;
    }

    bool operator()(const CKeyID &keyID) const {
        using namespace ScriptOpcodes;
        script->clear();
        *script << OP_DUP << OP_HASH160 << CScript::ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
        return true;
    }

    bool operator()(const CScriptID &scriptID) const {
        using namespace ScriptOpcodes;
        script->clear();
        *script << OP_HASH160 << CScript::ToByteVector(scriptID) << OP_EQUAL;
        return true;
    }

    bool operator()(const WitnessV0KeyHash &id) const {
        using namespace ScriptOpcodes;
        script->clear();
        *script << OP_0 << CScript::ToByteVector(id);
        return true;
    }

    bool operator()(const WitnessV0ScriptHash &id) const {
        using namespace ScriptOpcodes;
        script->clear();
        *script << OP_0 << CScript::ToByteVector(id);
        return true;
    }

    bool operator()(const WitnessUnknown &id) const {
        script->clear();
        *script << CScript::EncodeOP_N(id.version) << valtype(id.program, id.program + id.length);
        return true;
    }
};
} // namespace

CScript Script_util::GetScriptForDestination(const CTxDestination &dest) {
    CScript script;
    boost::apply_visitor(CScriptVisitor(&script), dest);
    return script;
}

CScript Script_util::GetScriptForRawPubKey(const CPubKey &pubKey) {
    return CScript() << valtype(pubKey.begin(), pubKey.end()) << ScriptOpcodes::OP_CHECKSIG;
}

CScript Script_util::GetScriptForMultisig(int nRequired, const std::vector<CPubKey> &keys) { // multi pubkey
    CScript script;
    script << CScript::EncodeOP_N(nRequired);
    for (const CPubKey &key: keys)
        script << CScript::ToByteVector(key);
    script << CScript::EncodeOP_N(keys.size()) << ScriptOpcodes::OP_CHECKMULTISIG;
    return script;
}

CScript Script_util::GetScriptForWitness(const CScript &redeemscript) {
    using namespace TxnOutputType;
    statype vSolutions;
    txnouttype typ = Solver(redeemscript, vSolutions);
    if (typ == TX_PUBKEY) {
        return GetScriptForDestination(WitnessV0KeyHash(hash_basis::Hash160(vSolutions[0].begin(), vSolutions[0].end())));
    } else if (typ == TX_PUBKEYHASH) {
        return GetScriptForDestination(WitnessV0KeyHash(vSolutions[0]));
    }
    return GetScriptForDestination(WitnessV0ScriptHash(redeemscript));
}

bool Script_util::IsValidDestination(const CTxDestination &dest) {
    return dest.which() != 0;
}
