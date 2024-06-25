// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/script.h>
#include <script/interpreter.h>
#include <crypto/common.h>
#include <keystore.h>
#include <bignum.h>
#include <key.h>
#include <main.h>
#include <sync/lsync.h>
#include <util.h>
#include <address/key_io.h>
#include <hash.h>
#include <bip32/hdchain.h>
#include <init.h>

namespace {
const Script_util::valtype vchFalse((uint32_t)0);
const Script_util::valtype vchZero((uint32_t)0);
const Script_util::valtype vchTrue((uint32_t)1, (uint8_t)1);
const CScriptNum bnZero(0);
const CScriptNum bnOne(1);
const CScriptNum bnFalse(0);
const CScriptNum bnTrue(1);
} // namespace

const char *TxnOutputType::GetTxnOutputType(TxnOutputType::txnouttype t) {
    switch (t)
    {
    case TX_NONSTANDARD: return "nonstandard";
    case TX_PUBKEY: return "pubkey";
    case TX_PUBKEY_DROP: return "pubkeydrop";
    case TX_PUBKEYHASH: return "pubkeyhash";
    case TX_SCRIPTHASH: return "scripthash";
    case TX_MULTISIG: return "multisig";
    case TX_NULL_DATA: return "nulldata";
    case TX_WITNESS_V0_KEYHASH: return "witness_v0_keyhash";
    case TX_WITNESS_V0_SCRIPTHASH: return "witness_v0_scripthash";
    case TX_WITNESS_UNKNOWN: return "witness_unknown";
    }
    return nullptr;
}

const char *ScriptOpcodes::GetOpName(ScriptOpcodes::opcodetype opcode) {
    using namespace ScriptOpcodes;
    switch (opcode)
    {
    // push value
    case OP_0                      : return "0";
    case OP_PUSHDATA1              : return "OP_PUSHDATA1";
    case OP_PUSHDATA2              : return "OP_PUSHDATA2";
    case OP_PUSHDATA4              : return "OP_PUSHDATA4";
    case OP_1NEGATE                : return "-1";
    case OP_RESERVED               : return "OP_RESERVED";
    case OP_1                      : return "1";
    case OP_2                      : return "2";
    case OP_3                      : return "3";
    case OP_4                      : return "4";
    case OP_5                      : return "5";
    case OP_6                      : return "6";
    case OP_7                      : return "7";
    case OP_8                      : return "8";
    case OP_9                      : return "9";
    case OP_10                     : return "10";
    case OP_11                     : return "11";
    case OP_12                     : return "12";
    case OP_13                     : return "13";
    case OP_14                     : return "14";
    case OP_15                     : return "15";
    case OP_16                     : return "16";

    // control
    case OP_NOP                    : return "OP_NOP";
    case OP_VER                    : return "OP_VER";
    case OP_IF                     : return "OP_IF";
    case OP_NOTIF                  : return "OP_NOTIF";
    case OP_VERIF                  : return "OP_VERIF";
    case OP_VERNOTIF               : return "OP_VERNOTIF";
    case OP_ELSE                   : return "OP_ELSE";
    case OP_ENDIF                  : return "OP_ENDIF";
    case OP_VERIFY                 : return "OP_VERIFY";
    case OP_RETURN                 : return "OP_RETURN";

    // stack ops
    case OP_TOALTSTACK             : return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
    case OP_2DROP                  : return "OP_2DROP";
    case OP_2DUP                   : return "OP_2DUP";
    case OP_3DUP                   : return "OP_3DUP";
    case OP_2OVER                  : return "OP_2OVER";
    case OP_2ROT                   : return "OP_2ROT";
    case OP_2SWAP                  : return "OP_2SWAP";
    case OP_IFDUP                  : return "OP_IFDUP";
    case OP_DEPTH                  : return "OP_DEPTH";
    case OP_DROP                   : return "OP_DROP";
    case OP_DUP                    : return "OP_DUP";
    case OP_NIP                    : return "OP_NIP";
    case OP_OVER                   : return "OP_OVER";
    case OP_PICK                   : return "OP_PICK";
    case OP_ROLL                   : return "OP_ROLL";
    case OP_ROT                    : return "OP_ROT";
    case OP_SWAP                   : return "OP_SWAP";
    case OP_TUCK                   : return "OP_TUCK";

    // splice ops
    case OP_CAT                    : return "OP_CAT";
    case OP_SUBSTR                 : return "OP_SUBSTR";
    case OP_LEFT                   : return "OP_LEFT";
    case OP_RIGHT                  : return "OP_RIGHT";
    case OP_SIZE                   : return "OP_SIZE";

    // bit logic
    case OP_INVERT                 : return "OP_INVERT";
    case OP_AND                    : return "OP_AND";
    case OP_OR                     : return "OP_OR";
    case OP_XOR                    : return "OP_XOR";
    case OP_EQUAL                  : return "OP_EQUAL";
    case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
    case OP_RESERVED1              : return "OP_RESERVED1";
    case OP_RESERVED2              : return "OP_RESERVED2";

    // numeric
    case OP_1ADD                   : return "OP_1ADD";
    case OP_1SUB                   : return "OP_1SUB";
    case OP_2MUL                   : return "OP_2MUL";
    case OP_2DIV                   : return "OP_2DIV";
    case OP_NEGATE                 : return "OP_NEGATE";
    case OP_ABS                    : return "OP_ABS";
    case OP_NOT                    : return "OP_NOT";
    case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
    case OP_ADD                    : return "OP_ADD";
    case OP_SUB                    : return "OP_SUB";
    case OP_MUL                    : return "OP_MUL";
    case OP_DIV                    : return "OP_DIV";
    case OP_MOD                    : return "OP_MOD";
    case OP_LSHIFT                 : return "OP_LSHIFT";
    case OP_RSHIFT                 : return "OP_RSHIFT";
    case OP_BOOLAND                : return "OP_BOOLAND";
    case OP_BOOLOR                 : return "OP_BOOLOR";
    case OP_NUMEQUAL               : return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               : return "OP_LESSTHAN";
    case OP_GREATERTHAN            : return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    : return "OP_MIN";
    case OP_MAX                    : return "OP_MAX";
    case OP_WITHIN                 : return "OP_WITHIN";

    // crypto
    case OP_RIPEMD160              : return "OP_RIPEMD160";
    case OP_SHA1                   : return "OP_SHA1";
    case OP_SHA256                 : return "OP_SHA256";
    case OP_HASH160                : return "OP_HASH160";
    case OP_HASH256                : return "OP_HASH256";
    case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
    case OP_CHECKSIG               : return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";

    // expanson
    case OP_NOP1                   : return "OP_NOP1";
    case OP_CHECKLOCKTIMEVERIFY    : return "OP_CHECKLOCKTIMEVERIFY";
    case OP_CHECKSEQUENCEVERIFY    : return "OP_CHECKSEQUENCEVERIFY";
    case OP_CHECKQAISIGVERIFY      : return "OP_CHECKQAISIGVERIFY";
    case OP_NOP5                   : return "OP_NOP5";
    case OP_NOP6                   : return "OP_NOP6";
    case OP_NOP7                   : return "OP_NOP7";
    case OP_NOP8                   : return "OP_NOP8";
    case OP_NOP9                   : return "OP_NOP9";
    case OP_NOP10                  : return "OP_NOP10";

    // zerocoin, dao
    case OP_ZEROCOINMINT           : return "OP_ZEROCOINMINT";
    case OP_ZEROCOINSPEND          : return "OP_ZEROCOINSPEND";
    case OP_HASHETH                : return "OP_HASHETH";

    // template matching params
    case OP_PUBKEYHASH             : return "OP_PUBKEYHASH";
    case OP_PUBKEY                 : return "OP_PUBKEY";
    case OP_SMALLDATA              : return "OP_SMALLDATA";

    case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";
    default                        : return "OP_UNKNOWN";
    }
}

unsigned int CScript::GetSigOpCount(bool fAccurate) const {
    using namespace ScriptOpcodes;
    unsigned int n = 0;
    const_iterator pc = begin();
    opcodetype lastOpcode = OP_INVALIDOPCODE;
    while (pc < end()) {
        opcodetype opcode;
        if (! GetOp(pc, opcode))
            break;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY) {
            ++n;
        } else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY) {
            if (fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16) {
                n += DecodeOP_N(lastOpcode);
            } else {
                n += Script_const::MAX_PUBKEYS_PER_MULTISIG;
            }
        }
        lastOpcode = opcode;
    }
    return n;
}

unsigned int CScript::GetSigOpCount(const CScript &scriptSig) const {
    if (! IsPayToScriptHash())
        return GetSigOpCount(true);

    // This is a pay-to-script-hash scriptPubKey;
    // get the last item that the scriptSig
    // pushes onto the stack:
    const_iterator pc = scriptSig.begin();
    script_vector data;
    while (pc < scriptSig.end()) {
        ScriptOpcodes::opcodetype opcode;
        if (! scriptSig.GetOp(pc, opcode, data))
            return 0;
        if (opcode > ScriptOpcodes::OP_16)
            return 0;
    }

    // ... and return its opcount:
    CScript subscript(data.begin(), data.end());
    return subscript.GetSigOpCount(true);
}

bool CScript::IsPayToScriptHash() const {
    // Extra-fast test for pay-to-script-hash CScripts
    return (size()  == 23 &&
            at(0)   == ScriptOpcodes::OP_HASH160 &&
            at(1)   == 0x14 &&
            at(22)  == ScriptOpcodes::OP_EQUAL);
}

bool CScript::IsPayToEthID() const {
    return (size() == 37 &&
            at(0)  == ScriptOpcodes::OP_1 &&
            at(1)  == 0x21 &&
            at(36) == ScriptOpcodes::OP_CHECKMULTISIG);
}

bool CScript::IsLockToEthID() const {
    return (size() == 71 &&
            at(0)  == ScriptOpcodes::OP_2 &&
            at(1)  == 0x21 &&
            at(70) == ScriptOpcodes::OP_CHECKMULTISIG);
}

bool CScript::IsPayToQAIResistance() const {
    bool fret = (size()  == 105 &&
                 at(0)   == ScriptOpcodes::OP_1 &&
                 at(1)   == 0x21 &&
                 at(103) == ScriptOpcodes::OP_3 &&
                 at(104) == ScriptOpcodes::OP_CHECKMULTISIG);
    if(!fret)
        return false;

    if(at(35) != 0x21)
        return false;
    qkey_vector vch1(&at(36), &at(69)); // [36] - [68]
    if(at(69) != 0x21)
        return false;
    qkey_vector vch2(&at(70), &at(103)); // [70] - [102]

    return (CqPubKey::IsQaiHash(vch1) && CqPubKey::IsRandHash(vch2));
}

/*
bool CScript::IsPayToQAIResistance() const {
    bool fret = (size() == 71 &&
                 at(0)  == ScriptOpcodes::OP_1 &&
                 at(1)  == 0x21 &&
                 at(69) == ScriptOpcodes::OP_2 &&
                 at(70) == ScriptOpcodes::OP_CHECKMULTISIG);
    if(!fret)
        return false;

    qkey_vector qvchhash(&at(36), &at(69));
    return CqPubKey::IsQaiHash(qvchhash);
}
*/

bool CScript::IsPushOnly(const_iterator pc) const {
    while (pc < end()) {
        ScriptOpcodes::opcodetype opcode;
        if (! GetOp(pc, opcode)) {
            return false;
        }
        if (opcode > ScriptOpcodes::OP_16) {
            return false;
        }
    }
    return true;
}

bool CScript::IsPushOnly() const {
    return IsPushOnly(begin());
}

bool CScript::HasCanonicalPushes() const {
    using namespace ScriptOpcodes;
    const_iterator pc = begin();
    while (pc < end()) {
        opcodetype opcode;
        script_vector data;
        if (! GetOp(pc, opcode, data)) {
            return false;
        }
        if (opcode > OP_16) {
            continue;
        }

        if (opcode < OP_PUSHDATA1 && opcode > OP_0 && (data.size() == 1 && data[0] <= 16)) {
            // Could have used an OP_n code, rather than a 1-byte push.
            return false;
        }
        if (opcode == OP_PUSHDATA1 && data.size() < OP_PUSHDATA1) {
            // Could have used a normal n-byte push, rather than OP_PUSHDATA1.
            return false;
        }
        if (opcode == OP_PUSHDATA2 && data.size() <= 0xFF) {
            // Could have used an OP_PUSHDATA1.
            return false;
        }
        if (opcode == OP_PUSHDATA4 && data.size() <= 0xFFFF) {
            // Could have used an OP_PUSHDATA2.
            return false;
        }
    }
    return true;
}

bool CScript::IsPayToWitnessScriptHash() const {
    // Extra-fast test for pay-to-witness-script-hash CScripts:
    return (size() == 34 &&
            at(0)  == ScriptOpcodes::OP_0 &&
            at(1)  == 0x20);
}

// A witness program is any valid CScript that consists of a 1-byte push opcode
// followed by a data push between 2 and 40 bytes.
bool CScript::IsWitnessProgram(int &version, script_vector &program) const {
    using namespace ScriptOpcodes;
    if (size() < 4 || size() > 42) {
        return false;
    }
    if (at(0) != OP_0 && (at(0) < OP_1 || at(0) > OP_16)) {
        return false;
    }
    if ((size_t)(at(1) + 2) == size()) {
        version = DecodeOP_N((opcodetype)at(0));
        program = script_vector(begin() + 2, end());
        return true;
    }
    return false;
}

bool CScript::HasValidOps() const {
    using namespace ScriptOpcodes;
    CScript::const_iterator it = begin();
    while (it < end()) {
        opcodetype opcode;
        script_vector item;
        if (!GetOp(it, opcode, item) || opcode > MAX_OPCODE || item.size() > Script_const::MAX_SCRIPT_ELEMENT_SIZE) {
            return false;
        }
    }
    return true;
}

//
// GetScript Operation
//
bool CScript::GetOp(iterator &pc, ScriptOpcodes::opcodetype &opcodeRet, script_vector &vchRet) {
     const_iterator pc2 = pc;
     bool fRet = GetScriptOp(pc2, end(), opcodeRet, &vchRet);
     pc = begin() + (pc2 - begin());
     return fRet;
}

bool CScript::GetOp(iterator &pc, ScriptOpcodes::opcodetype &opcodeRet) {
     const_iterator pc2 = pc;
     bool fRet = GetScriptOp(pc2, end(), opcodeRet, nullptr);
     pc = begin() + (pc2 - begin());
     return fRet;
}

bool CScript::GetOp(const_iterator &pc, ScriptOpcodes::opcodetype &opcodeRet, script_vector &vchRet) const {
    return GetScriptOp(pc, end(), opcodeRet, &vchRet);
}

bool CScript::GetOp(const_iterator &pc, ScriptOpcodes::opcodetype &opcodeRet) const {
    return GetScriptOp(pc, end(), opcodeRet, nullptr);
}

bool CScript::GetScriptOp(const_iterator &pc, const_iterator end, ScriptOpcodes::opcodetype &opcodeRet, script_vector *pvchRet) {
    using namespace ScriptOpcodes;
    opcodeRet = OP_INVALIDOPCODE;
    if (pvchRet)
        pvchRet->clear();
    if (pc >= end)
        return false;

    // Read instruction
    if (end - pc < 1)
        return false;
    unsigned int opcode = *pc++;

    // Immediate operand
    if (opcode <= OP_PUSHDATA4) {
        unsigned int nSize = 0;
        if (opcode < OP_PUSHDATA1)
            nSize = opcode;
        else if (opcode == OP_PUSHDATA1) {
            if (end - pc < 1)
                return false;
            nSize = *pc++;
        }
        else if (opcode == OP_PUSHDATA2) {
            if (end - pc < 2)
                return false;
            nSize = latest_crypto::ReadLE16(&pc[0]);
            pc += 2;
        }
        else if (opcode == OP_PUSHDATA4) {
            if (end - pc < 4)
                return false;
            nSize = latest_crypto::ReadLE32(&pc[0]);
            pc += 4;
        }
        if (end - pc < 0 || (unsigned int)(end - pc) < nSize)
            return false;
        if (pvchRet)
            pvchRet->assign(pc, pc + nSize);
        pc += nSize;
    }

    opcodeRet = static_cast<opcodetype>(opcode);
    return true;
}

std::string CScript::ToString(bool fShort/*=false*/) const {
    std::string str;
    ScriptOpcodes::opcodetype opcode;
    script_vector vch;
    const_iterator pc = begin();
    while (pc < end()) {
        if (! str.empty()) {
            str += " ";
        }
        if (! GetOp(pc, opcode, vch)) {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= ScriptOpcodes::OP_PUSHDATA4) {
            str += fShort? ValueString(vch).substr(0, 10) : ValueString(vch);
        } else {
            str += ScriptOpcodes::GetOpName(opcode);
        }
    }
    return str;
}

bool Script_util::CastToBool(const valtype &vch) {
    for (unsigned int i = 0; i < vch.size(); ++i) {
        if (vch[i] != 0) {
            // Can be negative zero
            if (i == vch.size()-1 && vch[i] == 0x80) {
                return false;
            }
            return true;
        }
    }
    return false;
}

// Script is a stack machine (like Forth) that evaluates a predicate
// returning a bool indicating valid or not.  There are no loops.
#define stacktop(i) (stack.at(stack.size()+(i)))
#define altstacktop(i) (altstack.at(altstack.size()+(i)))
void Script_util::popstack(statype &stack) {
    if (stack.empty()) {
        throw std::runtime_error("popstack() : stack empty");
    }
    stack.pop_back();
}

bool Script_util::IsCanonicalPubKey(const valtype &vchPubKey, unsigned int flags) {
    if (!(flags & Script_param::SCRIPT_VERIFY_STRICTENC)) {
        return true;
    }

    if (vchPubKey.size() < 33) {
        return logging::error("Non-canonical public key: too short");
    }
    if (vchPubKey[0] == 0x04) {
        if (vchPubKey.size() != 65) {
            return logging::error("Non-canonical public key: invalid length for uncompressed key");
        }
    } else if (vchPubKey[0] == 0x02 || vchPubKey[0] == 0x03) {
        if (vchPubKey.size() != 33) {
            return logging::error("Non-canonical public key: invalid length for compressed key");
        }
    } else {
        return logging::error("Non-canonical public key: compressed nor uncompressed");
    }
    return true;
}

bool Script_util::IsDERSignature(const valtype &vchSig, bool fWithHashType/*= false*/, bool fCheckLow/*= false*/) {
    // See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
    // A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
    // Where R and S are not negative (their first byte has its highest bit not set), and not
    // excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
    // in which case a single 0 byte is necessary and even required).
    if (vchSig.size() < 9) {
        return logging::error("Non-canonical signature: too short");
    }
    if (vchSig.size() > 73) {
        return logging::error("Non-canonical signature: too long");
    }
    if (vchSig[0] != 0x30) {
        return logging::error("Non-canonical signature: wrong type");
    }
    if (vchSig[1] != vchSig.size() - (fWithHashType ? 3 : 2)) {
        return logging::error("Non-canonical signature: wrong length marker");
    }
    if (fWithHashType) {
        unsigned char nHashType = vchSig[vchSig.size() - 1] & (~(Script_param::SIGHASH_ANYONECANPAY));
        if (nHashType < Script_param::SIGHASH_ALL || nHashType > Script_param::SIGHASH_SINGLE) {
            return logging::error("Non-canonical signature: unknown hashtype byte");
        }
    }

    unsigned int nLenR = vchSig[3];
    if (5 + nLenR >= vchSig.size()) {
        return logging::error("Non-canonical signature: S length misplaced");
    }

    unsigned int nLenS = vchSig[5+nLenR];
    if ((nLenR + nLenS + (fWithHashType ? 7 : 6)) != vchSig.size()) {
        return logging::error("Non-canonical signature: R+S length mismatch");
    }

    const unsigned char *R = &vchSig[4];
    if (R[-2] != 0x02) {
        return logging::error("Non-canonical signature: R value type mismatch");
    }
    if (nLenR == 0) {
        return logging::error("Non-canonical signature: R length is zero");
    }
    if (R[0] & 0x80) {
        return logging::error("Non-canonical signature: R value negative");
    }
    if (nLenR > 1 && (R[0] == 0x00) && !(R[1] & 0x80)) {
        return logging::error("Non-canonical signature: R value excessively padded");
    }

    const unsigned char *S = &vchSig[6+nLenR];
    if (S[-2] != 0x02) {
        return logging::error("Non-canonical signature: S value type mismatch");
    }
    if (nLenS == 0) {
        return logging::error("Non-canonical signature: S length is zero");
    }
    if (S[0] & 0x80) {
        return logging::error("Non-canonical signature: S value negative");
    }
    if (nLenS > 1 && (S[0] == 0x00) && !(S[1] & 0x80)) {
        return logging::error("Non-canonical signature: S value excessively padded");
    }

    if (fCheckLow) {
        unsigned int nLenR = vchSig[3];
        unsigned int nLenS = vchSig[5 + nLenR];
        const unsigned char *S = &vchSig[6 + nLenR];

        // If the S value is above the order of the curve divided by two, its
        // complement modulo the order could have been used instead, which is
        // one byte shorter when encoded correctly.
        if (! CKey::CheckSignatureElement(S, nLenS, true)) {
            return logging::error("Non-canonical signature: S value is unnecessarily high");
        }
    }

    return true;
}

bool Script_util::IsCanonicalSignature(const valtype &vchSig, unsigned int flags) {
    if (!(flags & Script_param::SCRIPT_VERIFY_STRICTENC)) {
        return true;
    }
    return Script_util::IsDERSignature(vchSig, true, (flags & Script_param::SCRIPT_VERIFY_LOW_S) != 0);
}

bool Script_util::CheckMinimalPush(const valtype &data, ScriptOpcodes::opcodetype opcode) {
    using namespace ScriptOpcodes;
    // Excludes OP_1NEGATE, OP_1-16 since they are by definition minimal
    assert(0 <= opcode && opcode <= OP_PUSHDATA4);
    if (data.size() == 0) {
        // Should have used OP_0.
        return opcode == OP_0;
    } else if (data.size() == 1 && data[0] >= 1 && data[0] <= 16) {
        // Should have used OP_1 .. OP_16.
        return false;
    } else if (data.size() == 1 && data[0] == 0x81) {
        // Should have used OP_1NEGATE.
        return false;
    } else if (data.size() <= 75) {
        // Must have used a direct push (opcode indicating number of bytes pushed + those bytes).
        return opcode == data.size();
    } else if (data.size() <= 255) {
        // Must have used OP_PUSHDATA.
        return opcode == OP_PUSHDATA1;
    } else if (data.size() <= 65535) {
        // Must have used OP_PUSHDATA2.
        return opcode == OP_PUSHDATA2;
    }
    return true;
}

bool Script_util::EvalScript(statype &stack, const CScript &script, const CTransaction &txTo, unsigned int nIn, unsigned int flags, int nHashType) {
    using namespace ScriptOpcodes;
    auto CheckLockTime = [](const int64_t &nLockTime, const CTransaction &txTo, unsigned int nIn) {
        // There are two kinds of nLockTime: lock-by-blockheight
        // and lock-by-blocktime, distinguished by whether
        // nLockTime < block_param::LOCKTIME_THRESHOLD.
        // We want to compare apples to apples, so fail the script
        // unless the type of nLockTime being tested is the same as
        // the nLockTime in the transaction.
        if (!(
            (txTo.get_nLockTime() <  block_params::LOCKTIME_THRESHOLD && nLockTime < block_params::LOCKTIME_THRESHOLD) ||
            (txTo.get_nLockTime() >= block_params::LOCKTIME_THRESHOLD && nLockTime >= block_params::LOCKTIME_THRESHOLD)
            )) {
            //printf("EvalScript_CheckLockTime Failure A.\n");
            return false;
        }

        // Now that we know we're comparing apples-to-apples, the
        // comparison is a simple numeric one.
        if (nLockTime > (int64_t)txTo.get_nLockTime()) {
            //printf("EvalScript_CheckLockTime Failure B.\n");
            return false;
        }

        // Finally the nLockTime feature can be disabled and thus
        // CHECKLOCKTIMEVERIFY bypassed if every txin has been
        // finalized by setting nSequence to maxint. The
        // transaction would be allowed into the blockchain, making
        // the opcode ineffective.
        // Testing if this vin is not final is sufficient to
        // prevent this condition. Alternatively we could test all
        // inputs, but testing just this input minimizes the data
        // required to prove correct CHECKLOCKTIMEVERIFY execution.
        if (CTxIn::SEQUENCE_FINAL == txTo.get_vin(nIn).get_nSequence()) {
            //printf("EvalScript_CheckLockTime Failure C.\n");
            return false;
        }

        return true;
    };

    auto CheckSequence = [](const int64_t &nSequence, const CTransaction &txTo, unsigned int nIn) {
        // Relative lock times are supported by comparing the passed
        // in operand to the sequence number of the input.
        const int64_t txToSequence = (int64_t)txTo.get_vin(nIn).get_nSequence();

        // Sequence numbers with their most significant bit set are not
        // consensus constrained. Testing that the transaction's sequence
        // number do not have this bit set prevents using this property
        // to get around a CHECKSEQUENCEVERIFY check.
        if (txToSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            //printf("EvalScript_Sequence Failure A.\n");
            return false;
        }

        // Mask off any bits that do not have consensus-enforced meaning
        // before doing the integer comparisons
        const uint32_t nLockTimeMask = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
        const int64_t txToSequenceMasked = txToSequence & nLockTimeMask;
        const int64_t nSequenceMasked = nSequence & nLockTimeMask;

        // There are two kinds of nSequence: lock-by-blockheight
        // and lock-by-blocktime, distinguished by whether
        // nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
        // We want to compare apples to apples, so fail the script
        // unless the type of nSequenceMasked being tested is the same as
        // the nSequenceMasked in the transaction.
        if (!(
            (txToSequenceMasked <  CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked <  CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
            (txToSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)
            )) {
            //debugcs::instance() << "EvalScript_Sequence Failure B." << debugcs::endl();
            return false;
        }

        // Now that we know we're comparing apples-to-apples, the
        // comparison is a simple numeric one.
        if (nSequenceMasked > txToSequenceMasked) {
            //debugcs::instance() << "EvalScript_Sequence Failure C." << debugcs::endl();
            return false;
        }

        return true;
    };

    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    ScriptOpcodes::opcodetype opcode;
    valtype vchPushValue;
    std::vector<bool> vfExec;
    statype altstack;
    if (script.size() > Script_const::MAX_SCRIPT_SIZE) {
        //debugcs::instance() << "EvalScript Failure A." << debugcs::endl();
        return false;
    }

    bool fRequireMinimal = (flags & Script_param::SCRIPT_VERIFY_MINIMALDATA) != 0;

    int nOpCount = 0;
    try {
        while (pc < pend)
        {
            bool fExec = !count(vfExec.begin(), vfExec.end(), false);

            //
            // Read instruction
            //
            if (! script.GetOp(pc, opcode, vchPushValue)) {
                //debugcs::instance() << "EvalScript GetOp Failure." << debugcs::endl();
                return false;
            }
            if (vchPushValue.size() > Script_const::MAX_SCRIPT_ELEMENT_SIZE) {
                //debugcs::instance() << "EvalScript Failure B." << debugcs::endl();
                return false;
            }
            if (opcode > OP_16 && ++nOpCount > Script_const::MAX_OPS_PER_SCRIPT) {
                //debugcs::instance() << "EvalScript Failure C." << debugcs::endl();
                return false;
            }

            if (opcode == OP_CAT ||
                opcode == OP_SUBSTR ||
                opcode == OP_LEFT ||
                opcode == OP_RIGHT ||
                opcode == OP_INVERT ||
                opcode == OP_AND ||
                opcode == OP_OR ||
                opcode == OP_XOR ||
                opcode == OP_2MUL ||
                opcode == OP_2DIV ||
                opcode == OP_MUL ||
                opcode == OP_DIV ||
                opcode == OP_MOD ||
                opcode == OP_LSHIFT ||
                opcode == OP_RSHIFT) {
                //debugcs::instance() << "EvalScript Failure, disabled opecodes is used." << debugcs::endl();
                return false; // Disabled opcodes.
            }

            if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4) {
                if (fRequireMinimal && !CheckMinimalPush(vchPushValue, opcode)) {
                    return false;
                }
                stack.push_back(vchPushValue);
            } else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF)) {
                switch (opcode)
                {
                    //
                    // Push value
                    //
                    case OP_1NEGATE:
                    case OP_1:
                    case OP_2:
                    case OP_3:
                    case OP_4:
                    case OP_5:
                    case OP_6:
                    case OP_7:
                    case OP_8:
                    case OP_9:
                    case OP_10:
                    case OP_11:
                    case OP_12:
                    case OP_13:
                    case OP_14:
                    case OP_15:
                    case OP_16:
                    {
                        // ( -- value)
                        //CBigNum bn((int)opcode - (int)(OP_1 - 1));
                        CScriptNum bn((int)opcode - (int)(OP_1 - 1));
                        stack.push_back(bn.getvch());
                    }
                    break;

                    //
                    // Control
                    //
                    case OP_NOP:
                    break;

                    case OP_CHECKLOCKTIMEVERIFY:
                    {
                        if (!(flags & Script_param::SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
                            // not enabled; treat as a NOP2
                            break;
                        }

                        if (stack.size() < 1)
                            return false;

                        // Note that elsewhere numeric opcodes are limited to
                        // operands in the range -2**31+1 to 2**31-1, however it is
                        // legal for opcodes to produce results exceeding that
                        // range. This limitation is implemented by CScriptNum's
                        // default 4-byte limit.
                        //
                        // If we kept to that limit we'd have a year 2038 problem,
                        // even though the nLockTime field in transactions
                        // themselves is uint32 which only becomes meaningless
                        // after the year 2106.
                        //
                        // Thus as a special case we tell CScriptNum to accept up
                        // to 5-byte bignums, which are good until 2**39-1, well
                        // beyond the 2**32-1 limit of the nLockTime field itself.
                        const CScriptNum nLockTime(stacktop(-1), fRequireMinimal, 5);

                        // In the rare event that the argument may be < 0 due to
                        // some arithmetic being done first, you can always use
                        // 0 MAX CHECKLOCKTIMEVERIFY.
                        if (nLockTime < 0)
                            return false;

                        // Actually compare the specified lock time with the transaction.
                        if (! CheckLockTime(nLockTime.getint64(), txTo, nIn))
                            return false;

                        break;
                    }

                    case OP_CHECKSEQUENCEVERIFY:
                    {
                        if (!(flags & Script_param::SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
                            // not enabled; treat as a NOP3
                            break;
                        }

                        if (stack.size() < 1)
                            return false;

                        // nSequence, like nLockTime, is a 32-bit unsigned integer
                        // field. See the comment in CHECKLOCKTIMEVERIFY regarding
                        // 5-byte numeric operands.
                        const CScriptNum nSequence(stacktop(-1), fRequireMinimal, 5);

                        // In the rare event that the argument may be < 0 due to
                        // some arithmetic being done first, you can always use
                        // 0 MAX CHECKSEQUENCEVERIFY.
                        if (nSequence < 0)
                            return false;

                        // To provide for future soft-fork extensibility, if the
                        // operand has the disabled lock-time flag set,
                        // CHECKSEQUENCEVERIFY behaves as a NOP.
                        if ((nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
                            break;

                        // Compare the specified sequence number with the input.
                        if (! CheckSequence(nSequence.getint64(), txTo, nIn))
                            return false;

                        break;
                    }

                    case OP_CHECKQAISIGVERIFY:
                    {
                        // (bool -- QAI Signature)
                        if(stack.size() != 20)
                            return false;

                        valtype pubkey = stacktop(-1);
                        valtype ecdsasig = stacktop(-2);
                        valtype qpubvch;
                        for(int i=3; i <= 4; ++i) {
                            qpubvch.insert(qpubvch.end(), stack.at(stack.size() - i).begin(), stack.at(stack.size() - i).end());
                        }
                        valtype qaisig;
                        for(int i=5; i <= 20; ++i) {
                            qaisig.insert(qaisig.end(), stack.at(stack.size() - i).begin(), stack.at(stack.size() - i).end());
                        }

                        // size check
                        if(qpubvch.size() != 1024)
                            return false;
                        if(qaisig.size() != 8193)
                            return false;

                        // ecdsa hash
                        CScript buildScriptsig;
                        buildScriptsig << ecdsasig;
                        buildScriptsig << pubkey;
                        uint256 hash;
                        latest_crypto::CHash256().Write(buildScriptsig.data(), buildScriptsig.size()).Finalize(hash.begin());

                        // QAI signature verify
                        CqPubKey qpubkey;
                        if(!qpubkey.RecoverCompact(strenc::HexStr(qpubvch)))
                            return false;
                        if(!qpubkey.IsFullyValid_BIP66())
                            return false;
                        if(qaisig.back() != Script_param::SIGHASH_ALL)
                            return false;
                        qaisig.pop_back();
                        if(!qpubkey.Verify(hash, qaisig))
                            return false;
                    }
                    break;

                    case OP_NOP1: case OP_NOP5:
                    case OP_NOP6: case OP_NOP7: case OP_NOP8: case OP_NOP9: case OP_NOP10:
                    {
                        if (flags & Script_param::SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                            return false;
                    }
                    break;

                    case OP_IF:
                    case OP_NOTIF:
                    {
                        // <expression> if [statements] [else [statements]] endif
                        bool fValue = false;
                        if (fExec) {
                            if (stack.size() < 1) {
                                //debugcs::instance() << "EvalScript Failure D." << debugcs::endl();
                                return false;
                            }
                            valtype &vch = stacktop(-1);
                            fValue = CastToBool(vch);
                            if (opcode == OP_NOTIF) {
                                fValue = !fValue;
                            }
                            popstack(stack);
                        }
                        vfExec.push_back(fValue);
                    }
                    break;

                    case OP_ELSE:
                    {
                        if (vfExec.empty()) {
                            //debugcs::instance() << "EvalScript Failure E." << debugcs::endl();
                            return false;
                        }
                        vfExec.back() = !vfExec.back();
                    }
                    break;

                    case OP_ENDIF:
                    {
                        if (vfExec.empty()) {
                            //debugcs::instance() << "EvalScript Failure F." << debugcs::endl();
                            return false;
                        }
                        vfExec.pop_back();
                    }
                    break;

                    case OP_VERIFY:
                    {
                        // (true -- ) or
                        // (false -- false) and return
                        if (stack.size() < 1) {
                            //debugcs::instance() << "EvalScript Failure G." << debugcs::endl();
                            return false;
                        }

                        bool fValue = CastToBool(stacktop(-1));
                        if (fValue) {
                            popstack(stack);
                        } else {
                            //debugcs::instance() << "EvalScript Failure H." << debugcs::endl();
                            return false;
                        }
                    }
                    break;

                    case OP_RETURN:
                    {
                        //debugcs::instance() << "EvalScript OP_RET." << debugcs::endl();
                        return false;
                    }
                    break;

                    //
                    // Stack ops
                    //
                    case OP_TOALTSTACK:
                    {
                        if (stack.size() < 1) {
                            //debugcs::instance() << "EvalScript Failure O." << debugcs::endl();
                            return false;
                        }
                        altstack.push_back(stacktop(-1));
                        popstack(stack);
                    }
                    break;

                    case OP_FROMALTSTACK:
                    {
                        if (altstack.size() < 1) {
                            //debugcs::instance() << "EvalScript Failure P." << debugcs::endl();
                            return false;
                        }
                        stack.push_back(altstacktop(-1));
                        popstack(altstack);
                    }
                    break;

                    case OP_2DROP:
                    {
                        // (x1 x2 -- )
                        if (stack.size() < 2) {
                            //debugcs::instance() << "EvalScript Failure Q." << debugcs::endl();
                            return false;
                        }
                        popstack(stack);
                        popstack(stack);
                    }
                    break;

                    case OP_2DUP:
                    {
                        // (x1 x2 -- x1 x2 x1 x2)
                        if (stack.size() < 2) {
                            //debugcs::instance() << "EvalScript Failure R." << debugcs::endl();
                            return false;
                        }
                        valtype vch1 = stacktop(-2);
                        valtype vch2 = stacktop(-1);
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                    }
                    break;

                    case OP_3DUP:
                    {
                        // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                        if (stack.size() < 3) {
                            //debugcs::instance() << "EvalScript Failure S." << debugcs::endl();
                            return false;
                        }
                        valtype vch1 = stacktop(-3);
                        valtype vch2 = stacktop(-2);
                        valtype vch3 = stacktop(-1);
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                        stack.push_back(vch3);
                    }
                    break;

                    case OP_2OVER:
                    {
                        // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                        if (stack.size() < 4) {
                            //debugcs::instance() << "EvalScript Failure T." << debugcs::endl();
                            return false;
                        }
                        valtype vch1 = stacktop(-4);
                        valtype vch2 = stacktop(-3);
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                    }
                    break;

                    case OP_2ROT:
                    {
                        // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                        if (stack.size() < 6) {
                            //debugcs::instance() << "EvalScript Failure U." << debugcs::endl();
                            return false;
                        }
                        valtype vch1 = stacktop(-6);
                        valtype vch2 = stacktop(-5);
                        stack.erase(stack.end()-6, stack.end()-4);
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                    }
                    break;

                    case OP_2SWAP:
                    {
                        // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                        if (stack.size() < 4) {
                            //debugcs::instance() << "EvalScript Failure V." << debugcs::endl();
                            return false;
                        }
                        std::swap(stacktop(-4), stacktop(-2));
                        std::swap(stacktop(-3), stacktop(-1));
                    }
                    break;

                    case OP_IFDUP:
                    {
                        // (x - 0 | x x)
                        if (stack.size() < 1) {
                            //debugcs::instance() << "EvalScript Failure W." << debugcs::endl();
                            return false;
                        }
                        valtype vch = stacktop(-1);
                        if (CastToBool(vch)) {
                            stack.push_back(vch);
                        }
                    }
                    break;

                    case OP_DEPTH:
                    {
                        // -- stacksize
                        //CBigNum bn((uint16_t) stack.size());
                        CScriptNum bn((uint16_t)stack.size());
                        stack.push_back(bn.getvch());
                    }
                    break;

                    case OP_DROP:
                    {
                        // (x -- )
                        if (stack.size() < 1) {
                            //debugcs::instance() << "EvalScript Failure X." << debugcs::endl();
                            return false;
                        }
                        popstack(stack);
                    }
                    break;

                    case OP_DUP:
                    {
                        // (x -- x x)
                        if (stack.size() < 1) {
                            //debugcs::instance() << "EvalScript Failure Y." << debugcs::endl();
                            return false;
                        }
                        valtype vch = stacktop(-1);
                        stack.push_back(vch);
                    }
                    break;

                    case OP_NIP:
                    {
                        // (x1 x2 -- x2)
                        if (stack.size() < 2) {
                            //debugcs::instance() << "EvalScript Failure Z." << debugcs::endl();
                            return false;
                        }
                        stack.erase(stack.end() - 2);
                    }
                    break;

                    case OP_OVER:
                    {
                        // (x1 x2 -- x1 x2 x1)
                        if (stack.size() < 2) {
                            //debugcs::instance() << "EvalScript Failure AA." << debugcs::endl();
                            return false;
                        }
                        valtype vch = stacktop(-2);
                        stack.push_back(vch);
                    }
                    break;

                    case OP_PICK:
                    case OP_ROLL:
                    {
                        // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                        // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                        if (stack.size() < 2) {
                            //debugcs::instance() << "EvalScript Failure AB." << debugcs::endl();
                            return false;
                        }

                        //int n = CastToBigNum(stacktop(-1)).getint32();
                        int n = CScriptNum(stacktop(-1), fRequireMinimal).getint();
                        popstack(stack);
                        if (n < 0 || n >= (int)stack.size()) {
                            //debugcs::instance() << "EvalScript Failure AC." << debugcs::endl();
                            return false;
                        }

                        valtype vch = stacktop(-n-1);
                        if (opcode == OP_ROLL) {
                            stack.erase(stack.end()-n-1);
                        }
                        stack.push_back(vch);
                    }
                    break;

                    case OP_ROT:
                    {
                        // (x1 x2 x3 -- x2 x3 x1)
                        //  x2 x1 x3  after first swap
                        //  x2 x3 x1  after second swap
                        if (stack.size() < 3) {
                            //debugcs::instance() << "EvalScript Failure AD." << debugcs::endl();
                            return false;
                        }
                        std::swap(stacktop(-3), stacktop(-2));
                        std::swap(stacktop(-2), stacktop(-1));
                    }
                    break;

                    case OP_SWAP:
                    {
                        // (x1 x2 -- x2 x1)
                        if (stack.size() < 2) {
                            //debugcs::instance() << "EvalScript Failure AE." << debugcs::endl();
                            return false;
                        }
                        std::swap(stacktop(-2), stacktop(-1));
                    }
                    break;

                    case OP_TUCK:
                    {
                        // (x1 x2 -- x2 x1 x2)
                        if (stack.size() < 2) {
                            //debugcs::instance() << "EvalScript Failure AF." << debugcs::endl();
                            return false;
                        }
                        valtype vch = stacktop(-1);
                        stack.insert(stack.end()-2, vch);
                    }
                    break;


                    case OP_SIZE:
                    {
                        // (in -- in size)
                        if (stack.size() < 1) {
                            //debugcs::instance() << "EvalScript Failure AG." << debugcs::endl();
                            return false;
                        }
                        //CBigNum bn((uint16_t) stacktop(-1).size());
                        CScriptNum bn((uint16_t)stacktop(-1).size());
                        stack.push_back(bn.getvch());
                    }
                    break;


                    //
                    // Bitwise logic
                    //
                    case OP_EQUAL:
                    case OP_EQUALVERIFY:
                    //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
                    {
                        // (x1 x2 - bool)
                        if (stack.size() < 2) {
                            //debugcs::instance() << "EvalScript Failure AH." << debugcs::endl();
                            return false;
                        }
                        valtype &vch1 = stacktop(-2);
                        valtype &vch2 = stacktop(-1);
                        bool fEqual = (vch1 == vch2);
                        //
                        // OP_NOTEQUAL is disabled because it would be too easy to say
                        // something like n != 1 and have some wiseguy pass in 1 with extra
                        // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                        //if (opcode == OP_NOTEQUAL)
                        //    fEqual = !fEqual;
                        //
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(fEqual ? vchTrue : vchFalse);
                        if (opcode == OP_EQUALVERIFY) {
                            if (fEqual) {
                                popstack(stack);
                            } else {
                                //debugcs::instance() << "EvalScript Failure AI." << debugcs::endl();
                                return false;
                            }
                        }
                    }
                    break;

                    //
                    // Numeric
                    //
                    case OP_1ADD:
                    case OP_1SUB:
                    case OP_NEGATE:
                    case OP_ABS:
                    case OP_NOT:
                    case OP_0NOTEQUAL:
                    {
                        // (in -- out)
                        if (stack.size() < 1) {
                            //debugcs::instance() << "EvalScript Failure AJ." << debugcs::endl();
                            return false;
                        }

                        //CScrNum bn = CastToBigNum(stacktop(-1));
                        CScriptNum bn(stacktop(-1), fRequireMinimal);
                        switch (opcode)
                        {
                        case OP_1ADD:       bn += bnOne; break;
                        case OP_1SUB:       bn -= bnOne; break;
                        case OP_NEGATE:     bn = -bn; break;
                        case OP_ABS:        if (bn < bnZero) bn = -bn; break;
                        case OP_NOT:        bn = (bn == bnZero); break;
                        case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
                        default:            assert(!"invalid opcode"); break;
                        }
                        popstack(stack);
                        stack.push_back(bn.getvch());
                    }
                    break;

                    case OP_ADD:
                    case OP_SUB:
                    case OP_BOOLAND:
                    case OP_BOOLOR:
                    case OP_NUMEQUAL:
                    case OP_NUMEQUALVERIFY:
                    case OP_NUMNOTEQUAL:
                    case OP_LESSTHAN:
                    case OP_GREATERTHAN:
                    case OP_LESSTHANOREQUAL:
                    case OP_GREATERTHANOREQUAL:
                    case OP_MIN:
                    case OP_MAX:
                    {
                        // (x1 x2 -- out)
                        if (stack.size() < 2) {
                            debugcs::instance() << "EvalScript Failure AK." << debugcs::endl();
                            return false;
                        }

                        //CScrNum bn1 = CastToBigNum(stacktop(-2));
                        //CScrNum bn2 = CastToBigNum(stacktop(-1));
                        //CScrNum bn;
                        CScriptNum bn1(stacktop(-2), fRequireMinimal);
                        CScriptNum bn2(stacktop(-1), fRequireMinimal);
                        CScriptNum bn(0);
                        switch (opcode)
                        {
                        case OP_ADD:
                            bn = bn1 + bn2;
                            break;

                        case OP_SUB:
                            bn = bn1 - bn2;
                            break;

                        case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
                        case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
                        case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
                        case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
                        case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
                        case OP_LESSTHAN:            bn = (bn1 < bn2); break;
                        case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
                        case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
                        case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
                        case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
                        case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
                        default:                     assert(!"invalid opcode"); break;
                        }
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(bn.getvch());

                        if (opcode == OP_NUMEQUALVERIFY) {
                            if (CastToBool(stacktop(-1))) {
                                popstack(stack);
                            } else {
                                //debugcs::instance() << "EvalScript Failure AL." << debugcs::endl();
                                return false;
                            }
                        }
                    }
                    break;

                    case OP_WITHIN:
                    {
                        // (x min max -- out)
                        if (stack.size() < 3) {
                            //debugcs::instance() << "EvalScript Failure AM." << debugcs::endl();
                            return false;
                        }

                        CScriptNum bn1(stacktop(-3), fRequireMinimal);
                        CScriptNum bn2(stacktop(-2), fRequireMinimal);
                        CScriptNum bn3(stacktop(-1), fRequireMinimal);
                        bool fValue = (bn2 <= bn1 && bn1 < bn3);
                        popstack(stack);
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(fValue ? vchTrue : vchFalse);
                    }
                    break;

                    //
                    // Crypto
                    //
                    case OP_RIPEMD160:
                    case OP_SHA1:
                    case OP_SHA256:
                    case OP_HASH160:
                    case OP_HASH256:
                    case OP_HASHETH:
                    {
                        // (in -- hash)
                        if (stack.size() < 1) {
                            //debugcs::instance() << "EvalScript Failure AN." << debugcs::endl();
                            return false;
                        }

                        valtype &vch = stacktop(-1);
                        valtype vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160 || opcode == OP_HASHETH) ? 20 : 32);
                        if (opcode == OP_RIPEMD160) {
                            RIPEMD160(&vch[0], vch.size(), &vchHash[0]);
                        } else if (opcode == OP_SHA1) {
                            SHA1(&vch[0], vch.size(), &vchHash[0]);
                        } else if (opcode == OP_SHA256) {
                            SHA256(&vch[0], vch.size(), &vchHash[0]);
                        } else if (opcode == OP_HASH160) {
                            uint160 hash160 = hash_basis::Hash160(vch);
                            std::memcpy(&vchHash[0], &hash160, sizeof(hash160));
                        } else if (opcode == OP_HASHETH) {
                            uint160 hash160;
                            latest_crypto::CHashEth().Write(&vch[0], vch.size()).Finalize((unsigned char *)&hash160);
                            std::memcpy(&vchHash[0], &hash160, sizeof(hash160));
                        } else if (opcode == OP_HASH256) {
                            uint256 hash = hash_basis::Hash(vch.begin(), vch.end());
                            std::memcpy(&vchHash[0], &hash, sizeof(hash));
                        }
                        popstack(stack);
                        stack.push_back(vchHash);
                    }
                    break;

                    case OP_CODESEPARATOR:
                    {
                        // Hash starts after the code separator
                        pbegincodehash = pc;
                    }
                    break;

                    case OP_CHECKSIG:
                    case OP_CHECKSIGVERIFY:
                    {
                        // (sig pubkey -- bool)
                        if (stack.size() < 2) {
                            //debugcs::instance() << "EvalScript Failure AO." << debugcs::endl();
                            return false;
                        }

                        valtype &vchSig    = stacktop(-2);
                        valtype &vchPubKey = stacktop(-1);

                        //////
                        ////// debug print
                        //////
                        //util::PrintHex(vchSig.begin(), vchSig.end(), "sig: %s\n");
                        //util::PrintHex(vchPubKey.begin(), vchPubKey.end(), "pubkey: %s\n");

                        // Subset of script starting at the most recent codeseparator
                        CScript scriptCode(pbegincodehash, pend);

                        // Drop the signature, since there's no way for a signature to sign itself
                        scriptCode.FindAndDelete(CScript(vchSig));

                        bool fSuccess = IsCanonicalSignature(vchSig, flags) && IsCanonicalPubKey(vchPubKey, flags) && CheckSig(vchSig, vchPubKey, scriptCode, txTo, nIn, nHashType, flags);

                        popstack(stack);
                        popstack(stack);
                        stack.push_back(fSuccess ? vchTrue : vchFalse);
                        if (opcode == OP_CHECKSIGVERIFY) {
                            if (fSuccess) {
                                popstack(stack);
                            } else {
                                //debugcs::instance() << "EvalScript Failure AP." << debugcs::endl();
                                return false;
                            }
                        }
                    }
                    break;

                    case OP_CHECKMULTISIG:
                    case OP_CHECKMULTISIGVERIFY:
                    {
                        // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                        // SORA L1 Quantum and AI Resistance transaction Verify
                        // (bool -- QAI Signature)
                        // Must search all the stack, because the stack can change size by user
                        bool fQaimode = false;
                        int32_t qaiVersion = 0;
                        for(const auto &vs: stack) {
                            if(CqPubKey::IsQaiHash(vs)) {
                                fQaimode = true;
                                break;
                            }
                        }

                        if(args_bool::fTestNet) { // skip verify (blockHeight)
                            if(block_info::nBestHeight < 227400)
                                fQaimode = false;
                        } else {
                            // do nothing
                        }

                        if(fQaimode) {
                            if(stack.size() < 10)
                                return false;

                            debugcs::instance() << "QAI_CHECKMULTISIG stack size: " << stack.size() << debugcs::endl();

                            // QAI version
                            const valtype &qairand = stacktop(-2);
                            const unsigned char CurrentQaiVersion = qairand[1]; // version flag [1]
                            if(CurrentQaiVersion == (unsigned char)0x01) {
                                const valtype &qaihashvch = stacktop(-3);
                                if(!CqPubKey::IsQaiHash(qaihashvch))
                                    return false;

                                // QAI publickey recover
                                const valtype &qpubvch = stacktop(-8);
                                CqPubKey qpubkey;
                                if(!qpubkey.RecoverCompact(qpubvch))
                                    return false;
                                if(!qpubkey.IsFullyValid_BIP66())
                                    return false;

                                // scriptPubKey QAI hash compare
                                if(!qpubkey.CmpQaiHash(qaihashvch))
                                    return false;

                                // load signature, ecdsahash QAI
                                valtype qaisig = stacktop(-10);
                                const valtype &ecdsahash = stacktop(-9);
                                if(qaisig.size() != 129) // signature + hashType
                                    return false;
                                if(ecdsahash.size() != sizeof(uint256))
                                    return false;

                                // signature QAI target hash
                                const valtype &ecdsaPubkey = stacktop(-4);
                                const valtype &ecdsaSig = stacktop(-6);
                                const int32_t nHashType = (int32_t)qaisig.back();
                                const int32_t nCurrentQaiVersion = (int32_t)CurrentQaiVersion;
                                CScript qaistream;
                                qaistream.reserve(256);
                                qaistream << ecdsaSig;
                                qaistream << ecdsaPubkey;
                                qaistream << qaihashvch;
                                qaistream << qairand;
                                qaistream << ecdsahash;
                                qaistream << nCurrentQaiVersion;
                                qaistream << nHashType;
                                CHashWriter qaihash(SER_GETHASH, 0);
                                qaihash << qaistream;

                                // signature QAI verify
                                qaisig.erase(qaisig.begin() + 128, qaisig.end());
                                if(!qpubkey.VerifyQai(qaihash.GetHash(), qaisig))
                                    return false;

                                qaiVersion = nCurrentQaiVersion;
                                debugcs::instance() << "QAI_CHECKMULTISIG Verify OK" << debugcs::endl();
                            } else {
                                // CurrentQaiVersion 0x02, 0x03 ... 0xFF
                            }
                        } // fQaimode

                        /*
                        if(fQaimode) {
                            if(stack.size() != 25)
                                return false;

                            // QAI version
                            const valtype &qairand = stacktop(-2);
                            const unsigned char CurrentQaiVersion = qairand[0];
                            if(CurrentQaiVersion == (unsigned char)0x01) {
                                const valtype &qaihashvch = stacktop(-3);
                                if(CqPubKey::IsQaiHash(qaihashvch)) {
                                    valtype qpubvch;
                                    qpubvch.reserve(1024);
                                    for(int i=8; i <= 9; ++i) {
                                        qpubvch.insert(qpubvch.end(), stack.at(stack.size() - i).begin(), stack.at(stack.size() - i).end());
                                    }
                                    if(qpubvch.size() != 1024)
                                        return false;

                                    // QAI publickey recover
                                    CqPubKey qpubkey;
                                    if(!qpubkey.RecoverCompact(qpubvch))
                                        return false;
                                    if(!qpubkey.IsFullyValid_BIP66())
                                        return false;

                                    // scriptPubKey QAI hash compare
                                    if(!qpubkey.CmpQaiHash(qaihashvch))
                                        return false;

                                    // load signature QAI
                                    valtype qaisig;
                                    qaisig.reserve(8192 + 32 + 1);
                                    for(int i=10; i <= 25; ++i) {
                                        qaisig.insert(qaisig.end(), stack.at(stack.size() - i).begin(), stack.at(stack.size() - i).end());
                                    }
                                    if(qaisig.size() != (8192 + 32 + 1))
                                        return false;

                                    // signature QAI target hash
                                    //const valtype &qairand = stacktop(-2);
                                    const valtype &ecdsaPubkey = stacktop(-4);
                                    const valtype &ecdsaSig = stacktop(-6);
                                    const uint256 ecdsahash;
                                    ::memcpy((void *)ecdsahash.begin(), &qaisig[8192], sizeof(uint256));
                                    const int nHashType = qaisig.back();
                                    const int nCurrentQaiVersion = (int)CurrentQaiVersion;
                                    CScript qaiScriptsig;
                                    qaiScriptsig.reserve(256);
                                    qaiScriptsig << ScriptOpcodes::OP_0;
                                    qaiScriptsig << ecdsaSig;
                                    qaiScriptsig << ecdsaPubkey;
                                    qaiScriptsig << qaihashvch;
                                    qaiScriptsig << qairand;
                                    qaiScriptsig << ecdsahash;
                                    qaiScriptsig << nCurrentQaiVersion;
                                    qaiScriptsig << nHashType;
                                    uint256 hash;
                                    latest_crypto::CHash256().Write(qaiScriptsig.data(), qaiScriptsig.size()).Finalize(hash.begin());

                                    // signature QAI verify
                                    qaisig.erase(qaisig.begin() + 8192, qaisig.end());
                                    if(!qpubkey.Verify(hash, qaisig))
                                        return false;

                                } else {
                                    return false;
                                }
                            } else {
                                // CurrentQaiVersion 0x02, 0x03 ... 0xFF
                            }
                        } // fQaimode
                        */

                        int i = 1;
                        if ((int)stack.size() < i) {
                            //debugcs::instance() << "EvalScript Failure AQ." << debugcs::endl();
                            return false;
                        }

                        //int nKeysCount = CastToBigNum(stacktop(-i)).getint32();
                        int nKeysCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                        if (nKeysCount < 0 || nKeysCount > 20) {
                            //debugcs::instance() << "EvalScript Failure AR." << debugcs::endl();
                            return false;
                        }

                        nOpCount += nKeysCount;
                        if (nOpCount > Script_const::MAX_OPS_PER_SCRIPT) {
                            //debugcs::instance() << "EvalScript Failure AS." << debugcs::endl();
                            return false;
                        }

                        int ikey = ++i;
                        i += nKeysCount;
                        if ((int)stack.size() < i) {
                            //debugcs::instance() << "EvalScript Failure AT." << debugcs::endl();
                            return false;
                        }

                        //int nSigsCount = CastToBigNum(stacktop(-i)).getint32();
                        int nSigsCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                        if (nSigsCount < 0 || nSigsCount > nKeysCount) {
                            //debugcs::instance() << "EvalScript Failure AU." << debugcs::endl();
                            return false;
                        }

                        int isig = ++i;
                        i += nSigsCount;
                        if ((int)stack.size() < i) {
                            //debugcs::instance() << "EvalScript Failure AV." << debugcs::endl();
                            return false;
                        }

                        // Subset of script starting at the most recent codeseparator
                        CScript scriptCode(pbegincodehash, pend);

                        // Drop the signatures, since there's no way for a signature to sign itself
                        for (int k = 0; k < nSigsCount; ++k)
                        {
                            valtype &vchSig = stacktop(-isig-k);
                            scriptCode.FindAndDelete(CScript(vchSig));
                        }

                        bool fSuccess = true;
                        while (fSuccess && nSigsCount > 0)
                        {
                            valtype &vchSig    = stacktop(-isig);
                            valtype &vchPubKey = stacktop(-ikey);

                            // Check signature
                            bool fOk = IsCanonicalSignature(vchSig, flags) && IsCanonicalPubKey(vchPubKey, flags) && CheckSig(vchSig, vchPubKey, scriptCode, txTo, nIn, nHashType, flags);

                            if (fOk) {
                                isig++;
                                nSigsCount--;
                            }
                            ikey++;
                            nKeysCount--;

                            //
                            // If there are more signatures left than keys left,
                            // then too many signatures have failed
                            //
                            if (nSigsCount > nKeysCount) {
                                fSuccess = false;
                            }
                        }

                        while (i-- > 1)
                        {
                            popstack(stack);
                        }

                        // A bug causes CHECKMULTISIG to consume one extra argument
                        // whose contents were not checked in any way.
                        //
                        // Unfortunately this is a potential source of mutability,
                        // so optionally verify it is exactly equal to zero prior
                        // to removing it from the stack.
                        if (stack.size() < 1) {
                            //debugcs::instance() << "EvalScript Failure AW." << debugcs::endl();
                            return false;
                        }
                        if ((flags & Script_param::SCRIPT_VERIFY_NULLDUMMY) && stacktop(-1).size()) {
                            return logging::error("CHECKMULTISIG dummy argument not null");
                        }
                        popstack(stack);

                        // removing QAI from the stack
                        if(fQaimode) {
                            if(qaiVersion == 0) {
                                return false;
                            } else if(qaiVersion == 1) {
                                for(int i=0; i < 3; ++i) {
                                    popstack(stack);
                                }
                                if(opcode == OP_CHECKMULTISIG) { // if OP_CHECKMULTISIG, stack size should be zero after popstack
                                    debugcs::instance() << "QAI removing OP_CHECKMULTISIG stack size: " << std::to_string(stack.size()) << debugcs::endl();
                                    if(stack.size() > 0) {
                                        return false;
                                    }
                                }
                            }
                        }

                        stack.push_back(fSuccess ? vchTrue : vchFalse);

                        if(fSuccess) {
                            debugcs::instance() << "BASE OP_CHECKMULTISIG Verify OK" << debugcs::endl();
                        }

                        if (opcode == OP_CHECKMULTISIGVERIFY) {
                            if (fSuccess) {
                                popstack(stack);
                            } else {
                                //debugcs::instance() << "EvalScript Failure AX." << debugcs::endl();
                                return false;
                            }
                        }
                    }
                    break;

                    default:
                        //debugcs::instance() << "EvalScript Failure OP_CODE no hit. opcode: " << opcode << debugcs::endl();
                        return false;
                }

            } // else if, close

            // Size limits
            if (stack.size() + altstack.size() > Script_const::MAX_STACK_SIZE) {
                //debugcs::instance() << "EvalScript Failure AY." << debugcs::endl();
                return false;
            }
        }
    } catch (...) {
        //debugcs::instance() << "EvalScript Failure AZ." << debugcs::endl();
        return false;
    }

    if (! vfExec.empty()) {
        //debugcs::instance() << "EvalScript Failure BA." << debugcs::endl();
        return false;
    }

    return true;
}

namespace {

/**
 * Wrapper that serializes like CTransaction, but with the modifications
 *  required for the signature hash done in-place
 */
template <class T>
class CTransactionSignatureSerializer
{
private:
    const T& txTo;             //!< reference to the spending transaction (the one being serialized)
    const CScript& scriptCode; //!< output script being consumed
    const unsigned int nIn;    //!< input index of txTo being signed
    const bool fAnyoneCanPay;  //!< whether the hashtype has the SIGHASH_ANYONECANPAY flag set
    const bool fHashSingle;    //!< whether the hashtype is SIGHASH_SINGLE
    const bool fHashNone;      //!< whether the hashtype is SIGHASH_NONE

public:
    CTransactionSignatureSerializer(const T& txToIn, const CScript& scriptCodeIn, unsigned int nInIn, int nHashTypeIn) :
        txTo(txToIn), scriptCode(scriptCodeIn), nIn(nInIn),
        fAnyoneCanPay(!!(nHashTypeIn & Script_param::SIGHASH_ANYONECANPAY)),
        fHashSingle((nHashTypeIn & 0x1f) == Script_param::SIGHASH_SINGLE),
        fHashNone((nHashTypeIn & 0x1f) == Script_param::SIGHASH_NONE) {}

    /** Serialize the passed scriptCode, skipping OP_CODESEPARATORs */
    template<typename S>
    void SerializeScriptCode(S &s) const {
        CScript::const_iterator it = scriptCode.begin();
        CScript::const_iterator itBegin = it;
        ScriptOpcodes::opcodetype opcode;
        unsigned int nCodeSeparators = 0;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == ScriptOpcodes::OP_CODESEPARATOR)
                nCodeSeparators++;
        }
        compact_size::manage::WriteCompactSize(s, scriptCode.size() - nCodeSeparators);
        it = itBegin;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == ScriptOpcodes::OP_CODESEPARATOR) {
                s.write((char*)&itBegin[0], it-itBegin-1);
                itBegin = it;
            }
        }
        if (itBegin != scriptCode.end())
            s.write((char*)&itBegin[0], it-itBegin);
    }

    /** Serialize an input of txTo */
    template<typename S>
    void SerializeInput(S &s, unsigned int nInput) const {
        // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
        if (fAnyoneCanPay)
            nInput = nIn;
        // Serialize the prevout
        ::Serialize(s, txTo.get_vin(nInput).get_prevout());
        // Serialize the script
        if (nInput != nIn)
            // Blank out other inputs' signatures
            ::Serialize(s, CScript());
        else
            SerializeScriptCode(s);
        // Serialize the nSequence
        if (nInput != nIn && (fHashSingle || fHashNone))
            // let the others update at will
            ::Serialize(s, (int)0);
        else
            ::Serialize(s, txTo.get_vin(nInput).get_nSequence());
    }

    /** Serialize an output of txTo */
    template<typename S>
    void SerializeOutput(S &s, unsigned int nOutput) const {
        if (fHashSingle && nOutput != nIn)
            // Do not lock-in the txout payee at other indices as txin
            ::Serialize(s, CTxOut());
        else
            ::Serialize(s, txTo.get_vout(nOutput));
    }

    /** Serialize txTo */
    template<typename S>
    void Serialize(S &s) const {
        // Serialize nVersion
        ::Serialize(s, txTo.get_nVersion());
        // Serialize nTime
        ::Serialize(s, txTo.get_nTime());
        // Serialize vin
        unsigned int nInputs = fAnyoneCanPay ? 1 : txTo.get_vin().size();
        compact_size::manage::WriteCompactSize(s, nInputs);
        for (unsigned int nInput = 0; nInput < nInputs; nInput++)
             SerializeInput(s, nInput);
        // Serialize vout
        unsigned int nOutputs = fHashNone ? 0 : (fHashSingle ? nIn+1 : txTo.get_vout().size());
        compact_size::manage::WriteCompactSize(s, nOutputs);
        for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++)
             SerializeOutput(s, nOutput);
        // Serialize nLockTime
        ::Serialize(s, txTo.get_nLockTime());
    }
};

}

namespace {

class CTransactionBaseSignatureHash
{
    CTransactionBaseSignatureHash() = delete;
public:
    explicit CTransactionBaseSignatureHash(const CTransaction &tx) {
        nVersion = tx.get_nVersion();
        nTime = tx.get_nTime();
        vin = tx.get_vin();
        vout = tx.get_vout();
        nLockTime = tx.get_nLockTime();
    }
    ~CTransactionBaseSignatureHash() {}

    uint32_t get_nTime() const {return nTime;}
    int get_nVersion() const {return nVersion;}
    const std::vector<CTxIn> &get_vin() const {return vin;}
    const CTxIn &get_vin(int index) const {return vin[index];}
    const std::vector<CTxOut> &get_vout() const {return vout;}
    const CTxOut &get_vout(int index) const {return vout[index];}
    uint32_t get_nLockTime() const {return nLockTime;}

    void set_nTime(uint32_t _InTime) {nTime = _InTime;}
    uint32_t &set_nTime() {return nTime;}
    int &set_nVersion() {return nVersion;}
    std::vector<CTxIn> &set_vin() {return vin;}
    CTxIn &set_vin(int index) {return vin[index];}
    std::vector<CTxOut> &set_vout() {return vout;}
    CTxOut &set_vout(int index) {return vout[index];}
    uint32_t &set_nLockTime() {return nLockTime;}

    template <typename Stream>
    inline void Serialize(Stream &s) const {
        NCONST_PTR(this)->SerializationOp(s, CSerActionSerialize());
    }
    template <typename Stream>
    inline void Unserialize(Stream &s) {
        this->SerializationOp(s, CSerActionUnserialize());
    }
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(this->nTime);
        READWRITE(this->vin);
        READWRITE(this->vout);
        READWRITE(this->nLockTime);
    }

private:
    int nVersion;
    uint32_t nTime;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime;
};

uint256 DebugSignatureHash(CScript scriptCode, const CTransaction &txTo, unsigned int nIn, int nHashType) {
    if (nIn >= txTo.get_vin().size()) {
        printf("ERROR: SignatureHash() : nIn=%d out of range\n", nIn);
        return 1;
    }
    CTransactionBaseSignatureHash txTmp(txTo);

    // In case concatenating two scripts ends up with two codeseparators,
    // or an extra one at the end, this prevents all those possible incompatibilities.
    scriptCode.FindAndDelete(CScript(ScriptOpcodes::OP_CODESEPARATOR));

    // Blank out other inputs' signatures
    for (unsigned int i = 0; i < txTmp.get_vin().size(); ++i) {
        txTmp.set_vin(i).set_scriptSig(CScript());
    }
    txTmp.set_vin(nIn).set_scriptSig(scriptCode);

    // Blank out some of the outputs
    if ((nHashType & 0x1f) == Script_param::SIGHASH_NONE) {
        // Wildcard payee
        txTmp.set_vout().clear();

        // Let the others update at will
        for (unsigned int i = 0; i < txTmp.get_vin().size(); ++i) {
            if (i != nIn) {
                txTmp.set_vin(i).set_nSequence(0);
            }
        }
    } else if ((nHashType & 0x1f) == Script_param::SIGHASH_SINGLE) {
        //
        // Only lock-in the txout payee at same index as txin
        //
        unsigned int nOut = nIn;
        if (nOut >= txTmp.get_vout().size()) {
            printf("ERROR: SignatureHash() : nOut=%d out of range\n", nOut);
            return 1;
        }

        txTmp.set_vout().resize(nOut+1);
        for (unsigned int i = 0; i < nOut; ++i) {
            txTmp.set_vout(i).SetNull();
        }

        // Let the others update at will
        for (unsigned int i = 0; i < txTmp.get_vin().size(); ++i) {
            if (i != nIn) {
                txTmp.set_vin(i).set_nSequence(0);
            }
        }
    }

    // Blank out other inputs completely, not recommended for open transactions
    if (nHashType & Script_param::SIGHASH_ANYONECANPAY) {
        txTmp.set_vin(0) = txTmp.get_vin(nIn);
        txTmp.set_vin().resize(1);
    }

    // Serialize and hash
    CDataStream ss(SER_GETHASH, 0);
    ss.reserve(10000);
    ss << txTmp << nHashType;
    return hash_basis::Hash(ss.begin(), ss.end());
}

}

// Ctransaction Base(P2PK, P2PKH, P2SH) SignatureHash
uint256 Script_util::SignatureHash(const CScript &scriptCode, const CTransaction &txTo, unsigned int nIn, int nHashType) {
    // Wrapper to serialize only the necessary parts of the transaction being signed
    CTransactionSignatureSerializer<CTransaction> txTmp(txTo, scriptCode, nIn, nHashType);

    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTmp << nHashType;
    return ss.GetHash();

    //uint256 hash = ss.GetHash();
    //assert(hash == DebugSignatureHash(scriptCode, txTo, nIn, nHashType));
    //debugcs::instance() << "Ctransaction Base SignatureHash OK" << debugcs::endl();
    //return hash;
}

// Valid signature cache, to avoid doing expensive ECDSA signature checking
// twice for every transaction (once when accepted into memory pool, and
// again when accepted into the block chain)
// Singleton Class
class CSignatureCache {
private:
    CSignatureCache() {}
    CSignatureCache(const CSignatureCache &)=delete;
    CSignatureCache(CSignatureCache &&)=delete;
    CSignatureCache &operator=(const CSignatureCache &)=delete;
    CSignatureCache &operator=(CSignatureCache &&)=delete;

    // sigdata_type is (signature hash, signature, public key):
    using sigdata_type = std::tuple<uint256, script_vector, CPubKey>;

    std::set<sigdata_type> setValid;
    boost::shared_mutex cs_sigcache; // std, After C++17
public:
    static CSignatureCache signatureCache;
    bool Get(const uint256 &hash, const script_vector &vchSig, const CPubKey &pubKey) {
        boost::shared_lock<boost::shared_mutex> lock(cs_sigcache);

        sigdata_type k(hash, vchSig, pubKey);
        std::set<sigdata_type>::iterator mi = setValid.find(k);
        if (mi != setValid.end()) {
            return true;
        }
        return false;
    }

    void Set(const uint256 &hash, const script_vector &vchSig, const CPubKey &pubKey) {
        // DoS prevention: limit cache size to less than 10MB
        // (~200 bytes per cache entry times 50,000 entries)
        // Since there are a maximum of 20,000 signature operations per block
        // 50,000 is a reasonable default.
        int64_t nMaxCacheSize = map_arg::GetArg("-maxsigcachesize", 50000);
        if (nMaxCacheSize <= 0) {
            return;
        }

        boost::shared_lock<boost::shared_mutex> lock(cs_sigcache);

        while (static_cast<int64_t>(setValid.size()) > nMaxCacheSize) {
            // Evict a random entry. Random because that helps
            // foil would-be DoS attackers who might try to pre-generate
            // and re-use a set of valid signatures just-slightly-greater
            // than our cache size.
            uint256 randomHash = bitsystem::GetRandHash();
            script_vector unused;
            CPubKey unusedpubkey;
            std::set<sigdata_type>::iterator it = setValid.lower_bound(sigdata_type(randomHash, unused, unusedpubkey));
            if (it == setValid.end()) {
                it = setValid.begin();
            }
            setValid.erase(*it);
        }

        sigdata_type k(hash, vchSig, pubKey);
        setValid.insert(k);
    }
};
CSignatureCache CSignatureCache::signatureCache;

bool Script_util::CheckSig(const script_vector &vchSig, const script_vector &vchPubKey, const uint256 &hash) {
    CPubKey pubkey(vchPubKey);
    if(! pubkey.IsFullyValid_BIP66())
        return false;
    return pubkey.Verify_BIP66(hash, vchSig);
}

bool Script_util::CheckSig(script_vector vchSig, const script_vector &vchPubKey, const CScript &scriptCode, const CTransaction &txTo, unsigned int nIn, int nHashType, int flags) {
    //
    // static CSignatureCache signatureCache;
    //
    CPubKey pubkey(vchPubKey);
    if (! pubkey.IsValid()) {
        return false;
    }

    // Hash type is one byte tacked on to the end of the signature
    if (vchSig.empty()) {
        return false;
    }
    if (nHashType == 0) {
        nHashType = vchSig.back();
    } else if (nHashType != vchSig.back()) {
        return false;
    }
    vchSig.pop_back();

    uint256 sighash = SignatureHash(scriptCode, txTo, nIn, nHashType);

    if (CSignatureCache::signatureCache.Get(sighash, vchSig, pubkey)) {
        return true;
    }
    if (! pubkey.Verify(sighash, vchSig)) {
        return false;
    }
    if (!(flags & Script_param::SCRIPT_VERIFY_NOCACHE)) {
        CSignatureCache::signatureCache.Set(sighash, vchSig, pubkey);
    }

    return true;
}

// Return public keys or hashes from scriptPubKey, for 'standard' transaction types.
bool Script_util::Solver(const CScript &scriptPubKey, TxnOutputType::txnouttype &typeRet, statype &vSolutionsRet) {
    auto CastToBigNum = [](const valtype &vch) {
        static constexpr size_t nMaxNumSize = 4;
        if (vch.size() > nMaxNumSize) {
            throw std::runtime_error("EvalScript CastToBigNum : overflow");
        }
        // Get rid of extra leading zeros
        return CBigNum(CBigNum(vch).getvch());
    };

    // Templates
    static std::map<TxnOutputType::txnouttype, CScript> mTemplates;

    if (mTemplates.empty()) {
        // Standard tx, sender provides pubkey, receiver adds signature
        mTemplates.insert(std::make_pair(TxnOutputType::TX_PUBKEY, CScript() << ScriptOpcodes::OP_PUBKEY << ScriptOpcodes::OP_CHECKSIG));

        // Malleable pubkey tx hack, sender provides generated pubkey combined with R parameter. The R parameter is dropped before checking a signature.
        mTemplates.insert(std::make_pair(TxnOutputType::TX_PUBKEY_DROP, CScript() << ScriptOpcodes::OP_PUBKEY << ScriptOpcodes::OP_PUBKEY << ScriptOpcodes::OP_DROP << ScriptOpcodes::OP_CHECKSIG));

        // Bitcoin address tx, sender provides hash of pubkey, receiver provides signature and pubkey
        mTemplates.insert(std::make_pair(TxnOutputType::TX_PUBKEYHASH, CScript() << ScriptOpcodes::OP_DUP << ScriptOpcodes::OP_HASH160 << ScriptOpcodes::OP_PUBKEYHASH << ScriptOpcodes::OP_EQUALVERIFY << ScriptOpcodes::OP_CHECKSIG));

        // Sender provides N pubkeys, receivers provides M signatures
        mTemplates.insert(std::make_pair(TxnOutputType::TX_MULTISIG, CScript() << ScriptOpcodes::OP_SMALLINTEGER << ScriptOpcodes::OP_PUBKEYS << ScriptOpcodes::OP_SMALLINTEGER << ScriptOpcodes::OP_CHECKMULTISIG));

        // Empty, provably prunable, data-carrying output
        mTemplates.insert(std::make_pair(TxnOutputType::TX_NULL_DATA, CScript() << ScriptOpcodes::OP_RETURN << ScriptOpcodes::OP_SMALLDATA));
    }

    vSolutionsRet.clear();

    //
    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    //
    if (scriptPubKey.IsPayToScriptHash()) {
        typeRet = TxnOutputType::TX_SCRIPTHASH;
        valtype hashBytes(scriptPubKey.begin() + 2, scriptPubKey.begin() + 22);
        vSolutionsRet.push_back(hashBytes);
        return true;
    }

    //
    // Provably prunable, data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the script.
    //
    if (scriptPubKey.size() >= 1 && scriptPubKey[0] == ScriptOpcodes::OP_RETURN && scriptPubKey.IsPushOnly(scriptPubKey.begin() + 1)) {
        typeRet = TxnOutputType::TX_NULL_DATA;
        return true;
    }

    // Scan templates
    const CScript &script1 = scriptPubKey;
    for(const std::pair<TxnOutputType::txnouttype, CScript> &tplate: mTemplates) {
        const CScript &script2 = tplate.second;
        vSolutionsRet.clear();

        ScriptOpcodes::opcodetype opcode1, opcode2;
        valtype vch1, vch2;

        // Compare
        CScript::const_iterator pc1 = script1.begin();
        CScript::const_iterator pc2 = script2.begin();
        for (;;) {
            if (pc1 == script1.end() && pc2 == script2.end()) {
                // Found a match
                typeRet = tplate.first;
                if (typeRet == TxnOutputType::TX_MULTISIG) {
                    // Additional checks for TX_MULTISIG:
                    unsigned char m = vSolutionsRet.front()[0];
                    unsigned char n = vSolutionsRet.back()[0];
                    if (m < 1 || n < 1 || m > n || vSolutionsRet.size() - 2 != n) {
                        return false;
                    }
                }
                return true;
            }
            if (! script1.GetOp(pc1, opcode1, vch1)) {
                break;
            }
            if (! script2.GetOp(pc2, opcode2, vch2)) {
                break;
            }

            // Template matching opcodes:
            if (opcode2 == ScriptOpcodes::OP_PUBKEYS) {
                while (vch1.size() >= 33 && vch1.size() <= 120)
                {
                    vSolutionsRet.push_back(vch1);
                    if (! script1.GetOp(pc1, opcode1, vch1)) {
                        break;
                    }
                }
                if (! script2.GetOp(pc2, opcode2, vch2)) {
                    break;
                }
                // Normal situation is to fall through
                // to other if/else statements
            }

            if (opcode2 == ScriptOpcodes::OP_PUBKEY) {
                if (vch1.size() < 33 || vch1.size() > 120)
                    break;
                if(vch1[0] == CPubKey::PUBLIC_KEY_SIZE) {
                    valtype pubkey = valtype(vch1.begin() + 1, vch1.begin() + CPubKey::PUBLIC_KEY_SIZE + 1);
                    if(! CPubKey::ValidSize(pubkey))
                        break;
                }
                if(vch1[0] == CPubKey::COMPRESSED_PUBLIC_KEY_SIZE) {
                    valtype pubkey = valtype(vch1.begin() + 1, vch1.begin() + CPubKey::COMPRESSED_PUBLIC_KEY_SIZE + 1);
                    if(! CPubKey::ValidSize(pubkey))
                        break;
                }
                vSolutionsRet.push_back(vch1);
            } else if (opcode2 == ScriptOpcodes::OP_PUBKEYHASH) {
                if (vch1.size() != sizeof(uint160)) {
                    break;
                }
                vSolutionsRet.push_back(vch1);
            } else if (opcode2 == ScriptOpcodes::OP_SMALLINTEGER) {
                //
                // Single-byte small integer pushed onto vSolutions
                //
                if (opcode1 == ScriptOpcodes::OP_0 || (opcode1 >= ScriptOpcodes::OP_1 && opcode1 <= ScriptOpcodes::OP_16)) {
                    char n = (char)CScript::DecodeOP_N(opcode1);
                    vSolutionsRet.push_back(valtype(1, n));
                } else {
                    break;
                }
            } else if (opcode2 == ScriptOpcodes::OP_INTEGER) {
                //
                // Up to four-byte integer pushed onto vSolutions
                //
                try {
                    CBigNum bnVal = CastToBigNum(vch1);
                    if (bnVal <= 16) {
                        break; // It's better to use ScriptOpcodes::OP_0 ... ScriptOpcodes::OP_16 for small integers.
                    }
                    vSolutionsRet.push_back(vch1);
                } catch(...) {
                    break;
                }
            } else if (opcode2 == ScriptOpcodes::OP_SMALLDATA) {
                //
                // small pushdata, <= 1024 bytes
                //
                if (vch1.size() > 1024) {
                    break;
                }
            } else if (opcode1 != opcode2 || vch1 != vch2) {
                //
                // Others must match exactly
                //
                break;
            }
        }
    }

    vSolutionsRet.clear();
    typeRet = TxnOutputType::TX_NONSTANDARD;
    return false;
}

bool Script_util::Sign1(const CKeyID &address, const CKeyStore &keystore, const uint256 &hash, int nHashType, CScript &scriptSigRet) {
    CFirmKey key;
    if (! keystore.GetKey(address, key)) {
        return false;
    }

    valtype vchSig;
    if (! key.Sign(hash, vchSig)) {
        return false;
    }

    vchSig.push_back((unsigned char)nHashType);
    scriptSigRet << vchSig;

    return true;
}

/*
bool Script_util::SignQAI(const CqKey &qkey, const CScript &scriptSig, const uint256 &ecdsahash, int nHashType, CScript &scriptSigRet) {
    uint256 hash;
    latest_crypto::CHash256().Write(scriptSig.data(), scriptSig.size()).Finalize(hash.begin());
    key_vector vchSig;
    vchSig.reserve(8192 + 32 + 1);
    qkey.Sign(hash, vchSig);
    assert(vchSig.size() == 8192);
    vchSig.resize(8192 + sizeof(uint256));
    ::memcpy(&vchSig[8192], ecdsahash.begin(), sizeof(uint256));
    vchSig.push_back((unsigned char)nHashType);
    assert(vchSig.size() == (8192 + 32 + 1));

    std::vector<key_vector> vchtmp;
    size_t offset = 0;
    for(int i=0; i < (8192/Script_const::MAX_SCRIPT_ELEMENT_SIZE); ++i) {
        key_vector vchChunk(&vchSig[offset], &vchSig[offset + Script_const::MAX_SCRIPT_ELEMENT_SIZE]);
        vchtmp.emplace_back(vchChunk);
        offset += Script_const::MAX_SCRIPT_ELEMENT_SIZE;
    }
    key_vector vchChunkLast(&vchSig[offset], &vchSig.back() + 1);
    vchtmp.emplace_back(vchChunkLast);

    for(int i = vchtmp.size() - 1; 0 <= i; --i) {
        scriptSigRet << vchtmp[i];
    }
    return true;
}
*/

bool Script_util::SignQAI(const CqKey &qkey, const uint256 &qaihash, const uint256 &ecdsahash, int nHashType, CScript &scriptSigRet) {
    if(!hd_wallet::get().enable)
        return false;

    key_vector vchSig;
    qkey.SignQai(qaihash, vchSig);
    vchSig.push_back((unsigned char)nHashType);
    if(vchSig.size() != 129)
        return false;

    scriptSigRet << vchSig;
    scriptSigRet << ecdsahash;
    return true;
}

bool Script_util::SignR(const CPubKey &pubKey, const CPubKey &R, const CKeyStore &keystore, const uint256 &hash, int nHashType, CScript &scriptSigRet) {
    CFirmKey key;
    if (! keystore.CreatePrivKey(pubKey, R, key)) {
        return false;
    }

    valtype vchSig;
    if (! key.Sign(hash, vchSig)) {
        return false;
    }

    vchSig.push_back((unsigned char)nHashType);
    scriptSigRet << vchSig;

    return true;
}

bool Script_util::SignN(const statype &multisigdata, const CKeyStore &keystore, const uint256 &hash, int nHashType, CScript &scriptSigRet) {
    int nSigned = 0;
    int nRequired = multisigdata.front()[0];
    for (unsigned int i = 1; i < multisigdata.size() - 1 && nSigned < nRequired; ++i)
    {
        const valtype &pubkey = multisigdata[i];
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (Sign1(keyID, keystore, hash, nHashType, scriptSigRet)) {
            ++nSigned;
        }
    }
    return nSigned == nRequired;
}

bool Script_util::SignSchnorr(const CKeyID &keyid, const uint256 &hash, XOnlyPubKeys &xonly_pubkeys, CScript &schnorrSig) {
    if(!hd_wallet::get().enable)
        return false;
    if(entry::pwalletMain->IsLocked())
        return false;

    XOnlyAggWalletInfo xonly_agg_wallet;
    if(!xonly_agg_wallet.LoadFromWalletInfo())
        return false;

    XOnlyKeys xonly_keys;
    if(!xonly_agg_wallet.GetXOnlyKeys(keyid, xonly_pubkeys, xonly_keys))
        return false;

    std::vector<unsigned char> sigbytes;
    if(!xonly_keys.SignSchnorr(hash, sigbytes))
        return false;

    schnorrSig << sigbytes;
    return true;
}

/*
static bool VerifySignatureQAI(const CScript &scriptSigQAI, const CScript &ScriptSigECDSA) {
    CScript scriptCheck;
    {
        CScript::const_iterator pc = scriptSigQAI.begin();
        std::vector<script_vector> vchtmp;
        while(pc != scriptSigQAI.end()) {
            ScriptOpcodes::opcodetype code;
            script_vector vch;
            if(!scriptSigQAI.GetOp(pc, code, vch))
                return false;
            vchtmp.emplace_back(vch);
        }
        for(int i = vchtmp.size() - 1; 0 <= i; --i) {
            scriptCheck << vchtmp[i];
        }
    }

    CqPubKey qpubkey;
    CScript::const_iterator pc = scriptCheck.begin();
    int count = 0;
    script_vector vchqpubkey;
    script_vector qsig;
    while(pc != scriptCheck.end()) {
        ScriptOpcodes::opcodetype code;
        script_vector vch;
        if(!scriptCheck.GetOp(pc, code, vch))
            return false;
        if(count <= 1) {
            vchqpubkey.insert(vchqpubkey.end(), vch.begin(), vch.end());
            if(count == 1) {
                if(!qpubkey.RecoverCompact(vchqpubkey))
                    return false;
                if(!qpubkey.IsFullyValid_BIP66())
                    return false;
            }
        } else {
            qsig.insert(qsig.end(), vch.begin(), vch.end());
        }
        ++count;
    }

    uint256 hash;
    latest_crypto::CHash256().Write(ScriptSigECDSA.data(), ScriptSigECDSA.size()).Finalize(hash.begin());
    if(qsig.size() != (8192 + 32 + 1))
        return false;
    //if(qsig.back() != Script_param::SIGHASH_ALL)
    //    return false;

    qsig.erase(qsig.begin() + 8192, qsig.end());
    return qpubkey.Verify(hash, qsig);
}
*/

static bool VerifySignatureQAI(const CScript &scriptSigQAI, const CScript &ScriptSigECDSA) {
    CqPubKey qpubkey;
    CScript::const_iterator pc = scriptSigQAI.begin();
    script_vector ecdsahash;
    script_vector qsig;
    unsigned char hashType;
    int counter = 0;
    while(pc != scriptSigQAI.end()) {
        ScriptOpcodes::opcodetype code;
        script_vector vch;
        if(!scriptSigQAI.GetOp(pc, code, vch))
            return false;
        if(counter == 2) {
            if(!qpubkey.RecoverCompact(vch))
                return false;
            if(!qpubkey.IsFullyValid_BIP66())
                return false;
            if(qpubkey.GetVch() != vch)
                return false;
            debugcs::instance() << "QAI verify pubkey ok" << debugcs::endl();
        } else if (counter == 1) {
            ecdsahash = vch;
            if(ecdsahash.size() != sizeof(uint256))
                return false;
            debugcs::instance() << "QAI verify ecdsahash ok" << debugcs::endl();
        } else if (counter == 0) {
            qsig = vch;
            if(qsig.size() != 129)
                return false;
            hashType = (unsigned char)qsig.back();
            debugcs::instance() << "QAI verify signature ok" << debugcs::endl();
        } else {
            return false;
        }

        ++counter;
    }

    CHashWriter hash(SER_GETHASH, 0);
    hash << ScriptSigECDSA;
    if((int)hashType != Script_param::SIGHASH_ALL)
        return false;
    debugcs::instance() << "QAI verify hashtype ok" << debugcs::endl();

    qsig.erase(qsig.begin() + 128, qsig.end());
    return qpubkey.VerifyQai(hash.GetHash(), qsig);
}

// Sign scriptPubKey with private keys stored in keystore, given transaction hash and hash type.
// Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
// unless whichTypeRet is TX_SCRIPTHASH, in which case scriptSigRet is the redemption script.
// Returns false if scriptPubKey could not be completely satisfied.
bool Script_util::Solver(const CKeyStore &keystore, const CScript &scriptPubKey, const uint256 &hash, int nHashType, CScript &scriptSigRet, TxnOutputType::txnouttype &whichTypeRet) {
    using namespace TxnOutputType;

    scriptSigRet.clear();
    statype vSolutions;
    if (! Script_util::Solver(scriptPubKey, whichTypeRet, vSolutions)) {
        return false;
    }

    CKeyID keyID;
    switch (whichTypeRet)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        return false;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        return Sign1(keyID, keystore, hash, nHashType, scriptSigRet);
    case TX_PUBKEY_DROP:
        {
            CPubKey key = CPubKey(vSolutions[0]);
            CPubKey R = CPubKey(vSolutions[1]);
            return SignR(key, R, keystore, hash, nHashType, scriptSigRet);
        }
    case TX_PUBKEYHASH:
        {
            keyID = CKeyID(uint160(vSolutions[0]));
            if (! Sign1(keyID, keystore, hash, nHashType, scriptSigRet))
                return false;

            CPubKey vch;
            keystore.GetPubKey(keyID, vch);
            scriptSigRet << vch;
            return true;
        }
    case TX_SCRIPTHASH:
        //debugcs::instance() << "Solver CScriptID: " << uint160(vSolutions[0]).GetHex() << debugcs::endl();
        return keystore.GetCScript(uint160(vSolutions[0]), scriptSigRet);
    case TX_MULTISIG:
        {
            bool fQaiTransaction = false;
            qkey_vector qaihash;
            qkey_vector ecdsapub;
            qkey_vector qairand;
            for(const auto &vch: vSolutions) {
                if(vch.size() == 33) {
                    // OP_1 << ECDSA pubkey << QaiHash << QaiRand << OP_3 << OP_CHECKMULTISIG
                    if(CqPubKey::IsQaiHash(vch)) {
                        fQaiTransaction = true;
                        qaihash = vch;
                    } else if (CqPubKey::IsRandHash(vch)) {
                        qairand = vch;
                    } else {
                        // ECDSA UTXO public key (include QAI Sign)
                        ecdsapub = vch;
                    }
                }
            }

            if(fQaiTransaction && qaihash.size() == 33 && ecdsapub.size() == 33 && qairand.size() == 33 && qairand[1] == 0x01 && hd_wallet::get().enable) {
                //! [Version 1] OP_CHECKMULTISIG for QAI Transaction
                CScript ecdsaScriptSig;
                if(!SignN(vSolutions, keystore, hash, nHashType, ecdsaScriptSig))
                    return false;

                const int32_t nCurrentQaiVersion = (int32_t)qairand[1];
                const int32_t nHashType32 = (int32_t)nHashType;
                CScript qaiVerifySig;
                qaiVerifySig.reserve(256);
                qaiVerifySig += ecdsaScriptSig;
                qaiVerifySig << ecdsapub;
                qaiVerifySig << qaihash;
                qaiVerifySig << qairand;
                qaiVerifySig << hash;
                qaiVerifySig << nCurrentQaiVersion;
                qaiVerifySig << nHashType32;

                CqKey qkey(hd_wallet::get().GetSecretKey());
                if(!qkey.IsValid())
                    return false;

                CHashWriter qaihash(SER_GETHASH, 0);
                qaihash << qaiVerifySig;
                CScript qaiSig;
                if(!SignQAI(qkey, qaihash.GetHash(), hash, nHashType, qaiSig))
                    return false;

                CqPubKey qpubkey = hd_wallet::get().GetPubKeyQai();
                if(!qpubkey.IsFullyValid_BIP66())
                    return false;
                qaiSig << qpubkey;

                // QAI signature verify check
                if(!VerifySignatureQAI(qaiSig, qaiVerifySig))
                    return false;

                debugcs::instance() << "QAI creation OK" << debugcs::endl();

                scriptSigRet += qaiSig;
                scriptSigRet << ScriptOpcodes::OP_0; // workaround CHECKMULTISIG bug
                scriptSigRet += ecdsaScriptSig;
            } else if (fQaiTransaction && qaihash.size() == 33 && ecdsapub.size() == 33 && qairand.size() == 33 && qairand[1] == 0x02 && hd_wallet::get().enable) {
                //! [Version 2] OP_CHECKMULTISIG for QAI and Schnorr Transaction
                CScript ecdsaScriptSig;
                if(!SignN(vSolutions, keystore, hash, nHashType, ecdsaScriptSig))
                    return false;

                const int32_t nCurrentQaiVersion = (int32_t)qairand[1];
                const int32_t nHashType32 = (int32_t)nHashType;
                CScript qaiVerifySig;
                qaiVerifySig.reserve(256);
                qaiVerifySig += ecdsaScriptSig;
                qaiVerifySig << ecdsapub;
                qaiVerifySig << qaihash;
                qaiVerifySig << qairand;
                qaiVerifySig << hash;
                qaiVerifySig << nCurrentQaiVersion;
                qaiVerifySig << nHashType32;

                CqKey qkey(hd_wallet::get().GetSecretKey());
                if(!qkey.IsValid())
                    return false;

                CHashWriter qaihash(SER_GETHASH, 0);
                qaihash << qaiVerifySig;
                CScript qaiSig;
                const uint256 msg_qhash = qaihash.GetHash();
                if(!SignQAI(qkey, msg_qhash, hash, nHashType, qaiSig))
                    return false;

                CqPubKey qpubkey = hd_wallet::get().GetPubKeyQai();
                if(!qpubkey.IsFullyValid_BIP66())
                    return false;
                qaiSig << qpubkey;

                // QAI signature verify check
                if(!VerifySignatureQAI(qaiSig, qaiVerifySig))
                    return false;

                // Schnorr signature
                CKeyID keyid = XOnlyPubKey::GetFromQairand(qairand);
                CScript schnorrSig;
                XOnlyPubKeys xonly_pubkeys;
                if(!SignSchnorr(keyid, msg_qhash, xonly_pubkeys, schnorrSig))
                    return false;
                schnorrSig << xonly_pubkeys.GetXOnlyPubKey().GetPubVch();

                debugcs::instance() << "QAI and Schnorr creation OK" << debugcs::endl();

                scriptSigRet += qaiSig;
                scriptSigRet += schnorrSig;
                scriptSigRet << ScriptOpcodes::OP_0; // workaround CHECKMULTISIG bug
                scriptSigRet += ecdsaScriptSig;
            } else {
                //! OP_CHECKMULTISIG for P2SH BASE
                scriptSigRet << ScriptOpcodes::OP_0; // workaround CHECKMULTISIG bug
                if(!SignN(vSolutions, keystore, hash, nHashType, scriptSigRet))
                    return false;
            }

            return true;
        }
    default:
        return false;

    /*
    case TX_PUBKEYHASH:
        {
            CScript buildScriptSig;
            keyID = CKeyID(uint160(vSolutions[0]));
            if (! Sign1(keyID, keystore, hash, nHashType, buildScriptSig))
                return false;

            CPubKey vch;
            keystore.GetPubKey(keyID, vch);
            buildScriptSig << vch;

            if(hd_wallet::get().enable) {
                CqKey qkey(hd_wallet::get().GetSecretKey());
                if(!qkey.IsValid())
                    return false;
                if(!SignQAI(qkey, buildScriptSig, nHashType, scriptSigRet))
                    return false;

                CqKeyID qvch = hd_wallet::get().GetKeyID();
                scriptSigRet << qvch;

                // QAI signature verify check
                if(!VerifySignatureQAI(scriptSigRet, buildScriptSig))
                    return false;
            }

            scriptSigRet += buildScriptSig;

            // QAI checking OP_CODE
            scriptSigRet << ScriptOpcodes::OP_CHECKQAISIGVERIFY;

            return true;
        }
    case TX_SCRIPTHASH:
        //debugcs::instance() << "Solver CScriptID: " << uint160(vSolutions[0]).GetHex() << debugcs::endl();
        return keystore.GetCScript(uint160(vSolutions[0]), scriptSigRet);
    case TX_MULTISIG:
        scriptSigRet << ScriptOpcodes::OP_0; // workaround CHECKMULTISIG bug
        return (SignN(vSolutions, keystore, hash, nHashType, scriptSigRet));
    default:
        assert(!"Witness is not supported.");
        return false;
    */
    }
    return false;
}

int Script_util::ScriptSigArgsExpected(TxnOutputType::txnouttype t, const statype &vSolutions) {
    using namespace TxnOutputType;
    switch (t)
    {
    case TX_NONSTANDARD:
        return -1;
    case TX_NULL_DATA:
        return 1;
    case TX_PUBKEY:
    case TX_PUBKEY_DROP:
        return 1;
    case TX_PUBKEYHASH:
        return 2;
    case TX_MULTISIG:
        if (vSolutions.size() < 1 || vSolutions[0].size() < 1) {
            return -1;
        }

        {
            int addstack = 0;
            for(const auto &vch: vSolutions) {
                if(CqPubKey::IsRandHash(vch)) {
                    if(vch[1] == 0x00)
                        return -1;
                    else if (vch[1] == 0x01) {
                        addstack = 3;
                        break;
                    } else if (vch[1] == 0x02) {
                        addstack = 5;
                        break;
                    } else
                        return -1;
                }
            }

            debugcs::instance() << "ScriptSigArgExpected TX_MULTISIG: " << std::to_string((vSolutions[0][0] + 1) + addstack) << debugcs::endl();
            return ((vSolutions[0][0] + 1) + addstack);
        }
        return -1;
    case TX_SCRIPTHASH:
        return 1; // doesn't include args needed by the script
    default:
        return -1;
    }
    return -1;
}

bool Script_util::IsStandard(const CScript &scriptPubKey, TxnOutputType::txnouttype &whichType) {
    statype vSolutions;
    if (! Script_util::Solver(scriptPubKey, whichType, vSolutions)) {
        return false;
    }

    if (whichType == TxnOutputType::TX_MULTISIG) {
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];

        //
        // Support up to x-of-3 multisig txns as standard
        //
        if (n < 1 || n > 3) {
            return false;
        }
        if (m < 1 || m > n) {
            return false;
        }
    }

    return whichType != TxnOutputType::TX_NONSTANDARD;
}

/*
unsigned int Script_util::HaveKeys(const std::vector<valtype> &pubkeys, const CKeyStore &keystore) {
    unsigned int nResult = 0;
    for(const valtype &pubkey: pubkeys) {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (keystore.HaveKey(keyID)) {
            ++nResult;
        } else if(hd_wallet::get().enable && (!entry::pwalletMain->IsLocked())) {
            unsigned char qhash[CPubKey::COMPRESSED_PUBLIC_KEY_SIZE];
            ::memset(qhash, 0x00, sizeof(qhash));
            ::memcpy(qhash, hd_wallet::get().GetPubKey().GetHash().begin(), sizeof(uint256));
            if(pubkey == valtype(BEGIN(qhash), END(qhash)))
                ++nResult;
        }
    }
    return nResult;
}

unsigned int Script_util::HaveKeys(const std::vector<valtype> &pubkeys, const CKeyStore &keystore) {
    unsigned int nResult = 0;
    for(const valtype &pubkey: pubkeys) {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (keystore.HaveKey(keyID)) {
            ++nResult;
        } else if(hd_wallet::get().enable) {
            try {
                if(hd_wallet::get().GetPubKey().CmpQaiHash(pubkey))
                    ++nResult;
            } catch (const std::exception &) {}
        }
    }
    return nResult;
}
*/

unsigned int Script_util::HaveKeys(const std::vector<valtype> &pubkeys, const CKeyStore &keystore) {
    unsigned int nResult = 0;
    for(const valtype &pubkey: pubkeys) {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (keystore.HaveKey(keyID)) {
            ++nResult;
        } else if(hd_wallet::get().enable) {
            try {
                if(hd_wallet::get().GetPubKeyQai().CmpQaiHash(pubkey))
                    ++nResult;
                else if(CqPubKey::IsRandHash(pubkey))
                    ++nResult;
            } catch (const std::exception &) {}
        }
    }
    return nResult;
}

isminetype Script_util::IsMine(const CKeyStore &keystore, const CBitcoinAddress &dest) {
    CScript script;
    script.SetAddress(dest);
    return IsMine(keystore, script);
}

isminetype Script_util::IsMine(const CKeyStore &keystore, const CScript &scriptPubKey) {
    using namespace TxnOutputType;
    statype vSolutions;
    TxnOutputType::txnouttype whichType;
    if (! Script_util::Solver(scriptPubKey, whichType, vSolutions)) {
        if (keystore.HaveWatchOnly(scriptPubKey)) {
            return MINE_WATCH_ONLY;
        }
        return MINE_NO;
    }

    CKeyID keyID;
    switch (whichType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        break;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if (keystore.HaveKey(keyID)) {
            return MINE_SPENDABLE;
        }
        break;
    case TX_PUBKEY_DROP:
        {
            CPubKey key = CPubKey(vSolutions[0]);
            CPubKey R = CPubKey(vSolutions[1]);
            if (keystore.CheckOwnership(key, R)) {
                return MINE_SPENDABLE;
            }
        }
        break;
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (keystore.HaveKey(keyID)) {
            return MINE_SPENDABLE;
        }
        break;
    case TX_SCRIPTHASH:
        {
            CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
            //debugcs::instance() << "IsMine CScriptID 1: " << scriptID.GetHex() << debugcs::endl();
            CScript subscript;
            if (keystore.GetCScript(scriptID, subscript)) {
                //debugcs::instance() << "IsMine CScriptID 2: " << scriptID.GetHex() << debugcs::endl();
                isminetype ret = IsMine(keystore, subscript);
                if (ret == MINE_SPENDABLE) {
                    return ret;
                }
            }
        }
        break;
    case TX_MULTISIG:
        {
            //
            // Only consider transactions "mine" if we own ALL the
            // keys involved. multi-signature transactions that are
            // partially owned (somebody else has a key that can spend
            // them) enable spend-out-from-under-you attacks, especially
            // in shared-wallet situations.
            //
            std::vector<valtype> keys(vSolutions.begin() + 1, vSolutions.begin() + vSolutions.size() - 1);
            if (HaveKeys(keys, keystore) == keys.size()) {
                return MINE_SPENDABLE;
            }
        }
        break;
    }

    if (keystore.HaveWatchOnly(scriptPubKey)) {
        return MINE_WATCH_ONLY;
    }

    return MINE_NO;
}

/*
bool Script_util::ExtractDestination(const CScript &scriptPubKey, CTxDestination &addressRet) {
    statype vSolutions;
    TxnOutputType::txnouttype whichType;
    if (! Script_util::Solver(scriptPubKey, whichType, vSolutions)) {
        return false;
    }

    if (whichType == TxnOutputType::TX_PUBKEY) {
        addressRet = CPubKey(vSolutions[0]).GetID();
        return true;
    } else if (whichType == TxnOutputType::TX_PUBKEYHASH) {
        addressRet = CKeyID(uint160(vSolutions[0]));
        return true;
    } else if (whichType == TxnOutputType::TX_SCRIPTHASH) {
        addressRet = CScriptID(uint160(vSolutions[0]));
        return true;
    }

    // Multisig txns have more than one address...
    return false;
}
*/

bool Script_util::ExtractAddress(const CKeyStore &keystore, const CScript &scriptPubKey, CBitcoinAddress &addressRet) {
    statype vSolutions;
    TxnOutputType::txnouttype whichType;
    if (! Script_util::Solver(scriptPubKey, whichType, vSolutions)) {
        return false;
    }

    if (whichType == TxnOutputType::TX_PUBKEY) {
        addressRet = CBitcoinAddress(CPubKey(vSolutions[0]).GetID());
        return true;
    }
    if (whichType == TxnOutputType::TX_PUBKEY_DROP) {
        // Pay-to-Pubkey-R
        CMalleableKeyView view;
        if (! keystore.CheckOwnership(CPubKey(vSolutions[0]), CPubKey(vSolutions[1]), view)) {
            return false;
        }

        addressRet = CBitcoinAddress(view.GetMalleablePubKey());
        return true;
    } else if (whichType == TxnOutputType::TX_PUBKEYHASH) {
        addressRet = CBitcoinAddress(CKeyID(uint160(vSolutions[0])));
        return true;
    } else if (whichType == TxnOutputType::TX_SCRIPTHASH) {
        addressRet = CBitcoinAddress(CScriptID(uint160(vSolutions[0])));
        return true;
    }

    // Multisig txns have more than one address...
    return false;
}

namespace {
class CAffectedKeysVisitor : public boost::static_visitor<void>
{
private:
    CAffectedKeysVisitor()=delete;
    CAffectedKeysVisitor(const CAffectedKeysVisitor &)=delete;
    CAffectedKeysVisitor(CAffectedKeysVisitor &&)=delete;
    CAffectedKeysVisitor &operator=(const CAffectedKeysVisitor &)=delete;
    CAffectedKeysVisitor &operator=(CAffectedKeysVisitor &&)=delete;
    const CKeyStore &keystore;
    std::vector<CKeyID> &vKeys;
public:
    explicit CAffectedKeysVisitor(const CKeyStore &keystoreIn, std::vector<CKeyID> &vKeysIn) : keystore(keystoreIn), vKeys(vKeysIn) {}

    void Process(const CScript &script) {
        TxnOutputType::txnouttype type;
        std::vector<CTxDestination> vDest;
        int nRequired;
        if (Script_util::ExtractDestinations(script, type, vDest, nRequired)) {
            for(const CTxDestination &dest: vDest) {
                boost::apply_visitor(*this, dest);
            }
        }
    }

    void operator()(const CKeyID &keyId) {
        if (keystore.HaveKey(keyId)) {
            vKeys.push_back(keyId);
        }
    }

    void operator()(const CScriptID &scriptId) {
        //debugcs::instance() << "CAffectedKeysVisitor CScriptID: " << scriptId.GetHex() << debugcs::endl();
        CScript script;
        if (keystore.GetCScript(scriptId, script)) {
            Process(script);
        }
    }

    void operator()(const CNoDestination &none) {}

    void operator()(const WitnessV0KeyHash &id) const {}

    void operator()(const WitnessV0ScriptHash &id) const {}

    void operator()(const WitnessUnknown &id) const {}
};
} // namespace

void Script_util::ExtractAffectedKeys(const CKeyStore &keystore, const CScript &scriptPubKey, std::vector<CKeyID> &vKeys) {
    CAffectedKeysVisitor(keystore, vKeys).Process(scriptPubKey);
}

/*
bool Script_util::ExtractDestinations(const CScript &scriptPubKey, TxnOutputType::txnouttype &typeRet, std::vector<CTxDestination> &addressRet, int &nRequiredRet) {
    addressRet.clear();

    typeRet = TxnOutputType::TX_NONSTANDARD;
    statype vSolutions;
    if (! Script_util::Solver(scriptPubKey, typeRet, vSolutions)) {
        return false;
    }
    if (typeRet == TxnOutputType::TX_NULL_DATA) {
        nRequiredRet = 0;
        return true;
    }

    if (typeRet == TxnOutputType::TX_MULTISIG) {
        nRequiredRet = vSolutions.front()[0];
        for (unsigned int i = 1; i < vSolutions.size()-1; ++i)
        {
            CTxDestination address = CPubKey(vSolutions[i]).GetID();
            addressRet.push_back(address);
        }
    } else {
        nRequiredRet = 1;
        if (typeRet == TxnOutputType::TX_PUBKEY_DROP) {
            return true;
        }

        CTxDestination address;
        if (! Script_util::ExtractDestination(scriptPubKey, address)) {
           return false;
        }
        addressRet.push_back(address);
    }

    return true;
}
*/

bool Script_util::VerifyScript(const CScript &scriptSig, const CScript &scriptPubKey, const CTransaction &txTo, unsigned int nIn, unsigned int flags, int nHashType) {
    statype stack, stackCopy;
    if (! Script_util::EvalScript(stack, scriptSig, txTo, nIn, flags, nHashType)) {
        return false;
    }
    if (flags & Script_param::SCRIPT_VERIFY_P2SH) {
        stackCopy = stack;
    }
    if (! Script_util::EvalScript(stack, scriptPubKey, txTo, nIn, flags, nHashType)) {
        return false;
    }
    if (stack.empty()) {
        return false;
    }

    if (CastToBool(stack.back()) == false) {
        return false;
    }

    // Additional validation for spend-to-script-hash transactions:
    if ((flags & Script_param::SCRIPT_VERIFY_P2SH) && scriptPubKey.IsPayToScriptHash()) {
        if (! scriptSig.IsPushOnly()) {    // scriptSig must be literals-only
            return false;                  // or validation fails
        }

        // stackCopy cannot be empty here, because if it was the
        // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        // an empty stack and the EvalScript above would return false.
        assert(!stackCopy.empty());

        const valtype &pubKeySerialized = stackCopy.back();
        CScript pubKey2(pubKeySerialized.begin(), pubKeySerialized.end());
        popstack(stackCopy);

        if (! Script_util::EvalScript(stackCopy, pubKey2, txTo, nIn, flags, nHashType)) {
            return false;
        }
        if (stackCopy.empty()) {
            return false;
        }
        return CastToBool(stackCopy.back());
    }
    return true;
}

bool Script_util::SignSignature(const CKeyStore &keystore, const CScript &fromPubKey, CTransaction &txTo, unsigned int nIn, int nHashType/* =Script_param::SIGHASH_ALL */) {
    assert(nIn < txTo.get_vin().size());
    CTxIn &txin = txTo.set_vin(nIn);

    // Leave out the signature from the hash, since a signature can't sign itself.
    // The checksig op will also drop the signatures from its hash.
    uint256 hash = SignatureHash(fromPubKey, txTo, nIn, nHashType);

    TxnOutputType::txnouttype whichType;
    if (! Script_util::Solver(keystore, fromPubKey, hash, nHashType, txin.set_scriptSig(), whichType)) {
        return false;
    }

    if (whichType == TxnOutputType::TX_SCRIPTHASH) {
        //
        // Solver returns the subscript that need to be evaluated;
        // the final scriptSig is the signatures from that
        // and then the serialized subscript:
        //
        CScript subscript = txin.get_scriptSig();

        // Recompute txn hash using subscript in place of scriptPubKey:
        uint256 hash2 = SignatureHash(subscript, txTo, nIn, nHashType);

        TxnOutputType::txnouttype subType;
        bool fSolved = Script_util::Solver(keystore, subscript, hash2, nHashType, txin.set_scriptSig(), subType) && subType != TxnOutputType::TX_SCRIPTHASH;

        //
        // Append serialized subscript whether or not it is completely signed:
        //
        //txin.scriptSig << static_cast<valtype>(subscript);
        txin << static_cast<valtype>(subscript);
        if (! fSolved) {
            return false;
        }
    }

    // Test solution
    return VerifyScript(txin.get_scriptSig(), fromPubKey, txTo, nIn, Script_param::STRICT_FLAGS, 0);
}

bool Script_util::SignSignature(const CKeyStore &keystore, const CTransaction &txFrom, CTransaction &txTo, unsigned int nIn, int nHashType) {
    assert(nIn < txTo.get_vin().size());

    CTxIn &txin = txTo.set_vin(nIn);
    assert(txin.get_prevout().get_n() < txFrom.get_vout().size());
    assert(txin.get_prevout().get_hash() == txFrom.GetHash());
    const CTxOut &txout = txFrom.get_vout(txin.get_prevout().get_n());

    return SignSignature(keystore, txout.get_scriptPubKey(), txTo, nIn, nHashType);
}

CScript Script_util::CombineSignatures(const CScript &scriptPubKey, const CTransaction &txTo, unsigned int nIn, const TxnOutputType::txnouttype txType, const statype &vSolutions, statype &sigs1, statype &sigs2) {
    using namespace TxnOutputType;

    auto PushAll = [](const statype &values) {
        CScript result;
        for(const valtype &v: values) {
            result << v;
        }
        return result;
    };

    auto CombineMultisig = [](const CScript &scriptPubKey, const CTransaction &txTo, unsigned int nIn, const statype &vSolutions, statype &sigs1, statype &sigs2) {
        //
        // Combine all the signatures we've got
        //
        std::set<valtype> allsigs;
        for(const valtype &v: sigs1) {
            if (! v.empty()) {
                allsigs.insert(v);
            }
        }
        for(const valtype &v: sigs2) {
            if (! v.empty()) {
                allsigs.insert(v);
            }
        }

        //
        // Build a map of pubkey -> signature by matching sigs to pubkeys
        //
        assert(vSolutions.size() > 1);
        unsigned int nSigsRequired = vSolutions.front()[0];
        unsigned int nPubKeys = (unsigned int)(vSolutions.size() - 2);
        std::map<valtype, valtype> sigs;
        for(const valtype &sig: allsigs) {
            for (unsigned int i = 0; i < nPubKeys; ++i) {
                const valtype &pubkey = vSolutions[i+1];
                if (sigs.count(pubkey)) {
                    continue;    // Already got a sig for this pubkey
                }
                if (Script_util::CheckSig(sig, pubkey, scriptPubKey, txTo, nIn, 0, 0)) {
                    sigs[pubkey] = sig;
                    break;
                }
            }
        }

        //
        // Now build a merged CScript
        //
        unsigned int nSigsHave = 0;
        CScript result; result << ScriptOpcodes::OP_0; // pop-one-too-many workaround
        for (unsigned int i = 0; i < nPubKeys && nSigsHave < nSigsRequired; ++i) {
            if (sigs.count(vSolutions[i+1])) {
                result << sigs[vSolutions[i+1]];
                ++nSigsHave;
            }
        }

        //
        // Fill any missing with ScriptOpcodes::OP_0
        //
        for (unsigned int i = nSigsHave; i < nSigsRequired; ++i) {
            result << ScriptOpcodes::OP_0;
        }

        return result;
    };

    switch (txType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        //
        // Don't know anything about this, assume bigger one is correct:
        //
        if (sigs1.size() >= sigs2.size()) {
            return PushAll(sigs1);
        }
        return PushAll(sigs2);
    case TX_PUBKEY:
    case TX_PUBKEY_DROP:
    case TX_PUBKEYHASH:
        //
        // Signatures are bigger than placeholders or empty scripts:
        //
        if (sigs1.empty() || sigs1[0].empty()) {
            return PushAll(sigs2);
        }
        return PushAll(sigs1);
    case TX_SCRIPTHASH:
        if (sigs1.empty() || sigs1.back().empty()) {
            return PushAll(sigs2);
        } else if (sigs2.empty() || sigs2.back().empty()) {
            return PushAll(sigs1);
        } else {
            //
            // Recur to combine:
            //
            valtype spk = sigs1.back();
            CScript pubKey2(spk.begin(), spk.end());

            TxnOutputType::txnouttype txType2;
            statype vSolutions2;
            Script_util::Solver(pubKey2, txType2, vSolutions2);
            sigs1.pop_back();
            sigs2.pop_back();
            CScript result = Script_util::CombineSignatures(pubKey2, txTo, nIn, txType2, vSolutions2, sigs1, sigs2);
            result << spk;
            return result;
        }
    case TX_MULTISIG:
        return CombineMultisig(scriptPubKey, txTo, nIn, vSolutions, sigs1, sigs2);
    }

    return CScript();
}

CScript Script_util::CombineSignatures(const CScript &scriptPubKey, const CTransaction &txTo, unsigned int nIn, const CScript &scriptSig1, const CScript &scriptSig2) {
    TxnOutputType::txnouttype txType;
    statype vSolutions;
    Script_util::Solver(scriptPubKey, txType, vSolutions);

    statype stack1;
    Script_util::EvalScript(stack1, scriptSig1, CTransaction(), 0, Script_param::SCRIPT_VERIFY_STRICTENC, 0);
    statype stack2;
    Script_util::EvalScript(stack2, scriptSig2, CTransaction(), 0, Script_param::SCRIPT_VERIFY_STRICTENC, 0);

    return Script_util::CombineSignatures(scriptPubKey, txTo, nIn, txType, vSolutions, stack1, stack2);
}

namespace {
class CScriptVisitor : public boost::static_visitor<bool>
{
private:
    CScriptVisitor()=delete;
    CScriptVisitor(const CScriptVisitor &)=delete;
    CScriptVisitor(CScriptVisitor &&)=delete;
    CScriptVisitor &operator=(const CScriptVisitor &)=delete;
    CScriptVisitor &operator=(CScriptVisitor &&)=delete;
    CScript *script;
public:
    explicit CScriptVisitor(CScript *scriptin) {
        script = scriptin;
    }

    bool operator()(const CNoDestination &dest) const {
        script->clear();
        return false;
    }

    bool operator()(const CKeyID &keyID) const {
        using namespace ScriptOpcodes;
        script->clear();
        *script << OP_DUP << OP_HASH160 << keyID << OP_EQUALVERIFY << OP_CHECKSIG;
        return true;
    }

    bool operator()(const CScriptID &scriptID) const {
        using namespace ScriptOpcodes;
        script->clear();
        *script << OP_HASH160 << scriptID << OP_EQUAL;
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
        *script << CScript::EncodeOP_N(id.version) << Script_util::valtype(id.program, id.program + id.length);
        return true;
    }
};
} // namespace

void CScript::SetDestination(const CTxDestination &dest) {
    boost::apply_visitor(CScriptVisitor(this), dest);
}

void CScript::SetAddress(const CBitcoinAddress &dest) {
    this->clear();
    if (dest.IsEth()) {
        *this << ScriptOpcodes::OP_DUP << ScriptOpcodes::OP_HASHETH << dest.GetData() << ScriptOpcodes::OP_EQUALVERIFY << ScriptOpcodes::OP_CHECKSIG;
    } else if (dest.IsScript()) {
        *this << ScriptOpcodes::OP_HASH160 << dest.GetData() << ScriptOpcodes::OP_EQUAL;
    } else if (dest.IsPubKey()) {
        *this << ScriptOpcodes::OP_DUP << ScriptOpcodes::OP_HASH160 << dest.GetData() << ScriptOpcodes::OP_EQUALVERIFY << ScriptOpcodes::OP_CHECKSIG;
    } else if (dest.IsPair()) {
        //
        // Pubkey pair address, going to generate
        // new one-time public key.
        //
        CMalleablePubKey mpk;
        if (! mpk.setvch(dest.GetData())) {
            return;
        }
        CPubKey R, pubKeyVariant;
        mpk.GetVariant(R, pubKeyVariant);
        *this << pubKeyVariant << R << ScriptOpcodes::OP_DROP << ScriptOpcodes::OP_CHECKSIG;
    }
}

void CScript::SetMultisig(int nRequired, const std::vector<CPubKey> &keys) {
    clear();
    *this << EncodeOP_N(nRequired);
    for(const CPubKey &key: keys) {
        *this << key;
    }

    *this << EncodeOP_N((int)(keys.size())) << ScriptOpcodes::OP_CHECKMULTISIG;
}
