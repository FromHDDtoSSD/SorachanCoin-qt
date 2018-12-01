// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef H_BITCOIN_SCRIPT
#define H_BITCOIN_SCRIPT

#include <string>
#include <vector>

#include <boost/foreach.hpp>

#include "keystore.h"
#include "bignum.h"
#include "base58.h"

class CTransaction;
class CBitcoinAddress;

namespace Script_param
{
    const unsigned int MAX_SCRIPT_ELEMENT_SIZE = 520; // bytes

    //
    // Strict verification:
    //

    // Script verification flags
    enum
    {
        SCRIPT_VERIFY_NONE      = 0,
        SCRIPT_VERIFY_P2SH      = (1U << 0),            // evaluate P2SH (BIP16) subscripts
        SCRIPT_VERIFY_STRICTENC = (1U << 1),            // enforce strict conformance to DER and SEC2 for signatures and pubkeys
        SCRIPT_VERIFY_LOW_S     = (1U << 2),            // enforce low S values in signatures (depends on STRICTENC)
        SCRIPT_VERIFY_NOCACHE   = (1U << 3),            // do not store results in signature cache (but do query it)
        SCRIPT_VERIFY_NULLDUMMY = (1U << 4),            // verify dummy stack item consumed by CHECKMULTISIG is of zero-length
        SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),
        SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10)
    };

    // * force DER encoding;
    // * force low S;
    // * ensure that CHECKMULTISIG dummy argument is null.
    const unsigned int STRICT_FORMAT_FLAGS = SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_NULLDUMMY;

    // Mandatory script verification flags that all new blocks must comply with for
    // them to be valid. (but old blocks may not comply with) Currently just P2SH,
    // but in the future other flags may be added, such as a soft-fork to enforce
    // strict DER encoding.
    //
    // Failing one of these tests may trigger a DoS ban - see ConnectInputs() for details.
    const unsigned int MANDATORY_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH;

    // Standard script verification flags that standard transactions will comply
    // with. However scripts violating these flags may still be present in valid blocks and we must accept those blocks.
    const unsigned int STRICT_FLAGS = MANDATORY_SCRIPT_VERIFY_FLAGS | STRICT_FORMAT_FLAGS;

    //
    // Signature hash types/flags
    //
    enum
    {
        SIGHASH_ALL = 1,
        SIGHASH_NONE = 2,
        SIGHASH_SINGLE = 3,
        SIGHASH_ANYONECANPAY = 0x80
    };
}

//
// IsMine() return codes
//
enum isminetype
{
    MINE_NO = 0,
    MINE_WATCH_ONLY = 1,
    MINE_SPENDABLE = 2,
    MINE_ALL = MINE_WATCH_ONLY | MINE_SPENDABLE
};
typedef uint8_t isminefilter;

//
// TxnOutputType
//
namespace TxnOutputType
{
    enum txnouttype
    {
        TX_NONSTANDARD,

        // 'standard' transaction types:
        TX_PUBKEY,
        TX_PUBKEY_DROP,
        TX_PUBKEYHASH,
        TX_SCRIPTHASH,
        TX_MULTISIG,
        TX_NULL_DATA
    };
    const char *GetTxnOutputType(TxnOutputType::txnouttype t);
}

//
// Script opcodes
//
namespace ScriptOpcodes
{
    enum opcodetype
    {
        // push value
        OP_0 = 0x00,
        OP_FALSE = OP_0,
        OP_PUSHDATA1 = 0x4c,
        OP_PUSHDATA2 = 0x4d,
        OP_PUSHDATA4 = 0x4e,
        OP_1NEGATE = 0x4f,
        OP_RESERVED = 0x50,
        OP_1 = 0x51,
        OP_TRUE=OP_1,
        OP_2 = 0x52,
        OP_3 = 0x53,
        OP_4 = 0x54,
        OP_5 = 0x55,
        OP_6 = 0x56,
        OP_7 = 0x57,
        OP_8 = 0x58,
        OP_9 = 0x59,
        OP_10 = 0x5a,
        OP_11 = 0x5b,
        OP_12 = 0x5c,
        OP_13 = 0x5d,
        OP_14 = 0x5e,
        OP_15 = 0x5f,
        OP_16 = 0x60,

        // control
        OP_NOP = 0x61,
        OP_VER = 0x62,
        OP_IF = 0x63,
        OP_NOTIF = 0x64,
        OP_VERIF = 0x65,
        OP_VERNOTIF = 0x66,
        OP_ELSE = 0x67,
        OP_ENDIF = 0x68,
        OP_VERIFY = 0x69,
        OP_RETURN = 0x6a,
        OP_CHECKLOCKTIMEVERIFY = 0xb1,
        OP_CHECKSEQUENCEVERIFY = 0xb2,

        // stack ops
        OP_TOALTSTACK = 0x6b,
        OP_FROMALTSTACK = 0x6c,
        OP_2DROP = 0x6d,
        OP_2DUP = 0x6e,
        OP_3DUP = 0x6f,
        OP_2OVER = 0x70,
        OP_2ROT = 0x71,
        OP_2SWAP = 0x72,
        OP_IFDUP = 0x73,
        OP_DEPTH = 0x74,
        OP_DROP = 0x75,
        OP_DUP = 0x76,
        OP_NIP = 0x77,
        OP_OVER = 0x78,
        OP_PICK = 0x79,
        OP_ROLL = 0x7a,
        OP_ROT = 0x7b,
        OP_SWAP = 0x7c,
        OP_TUCK = 0x7d,

        // splice ops
        OP_CAT = 0x7e,
        OP_SUBSTR = 0x7f,
        OP_LEFT = 0x80,
        OP_RIGHT = 0x81,
        OP_SIZE = 0x82,

        // bit logic
        OP_INVERT = 0x83,
        OP_AND = 0x84,
        OP_OR = 0x85,
        OP_XOR = 0x86,
        OP_EQUAL = 0x87,
        OP_EQUALVERIFY = 0x88,
        OP_RESERVED1 = 0x89,
        OP_RESERVED2 = 0x8a,

        // numeric
        OP_1ADD = 0x8b,
        OP_1SUB = 0x8c,
        OP_2MUL = 0x8d,
        OP_2DIV = 0x8e,
        OP_NEGATE = 0x8f,
        OP_ABS = 0x90,
        OP_NOT = 0x91,
        OP_0NOTEQUAL = 0x92,

        OP_ADD = 0x93,
        OP_SUB = 0x94,
        OP_MUL = 0x95,
        OP_DIV = 0x96,
        OP_MOD = 0x97,
        OP_LSHIFT = 0x98,
        OP_RSHIFT = 0x99,

        OP_BOOLAND = 0x9a,
        OP_BOOLOR = 0x9b,
        OP_NUMEQUAL = 0x9c,
        OP_NUMEQUALVERIFY = 0x9d,
        OP_NUMNOTEQUAL = 0x9e,
        OP_LESSTHAN = 0x9f,
        OP_GREATERTHAN = 0xa0,
        OP_LESSTHANOREQUAL = 0xa1,
        OP_GREATERTHANOREQUAL = 0xa2,
        OP_MIN = 0xa3,
        OP_MAX = 0xa4,

        OP_WITHIN = 0xa5,

        // crypto
        OP_RIPEMD160 = 0xa6,
        OP_SHA1 = 0xa7,
        OP_SHA256 = 0xa8,
        OP_HASH160 = 0xa9,
        OP_HASH256 = 0xaa,
        OP_CODESEPARATOR = 0xab,
        OP_CHECKSIG = 0xac,
        OP_CHECKSIGVERIFY = 0xad,
        OP_CHECKMULTISIG = 0xae,
        OP_CHECKMULTISIGVERIFY = 0xaf,

        // expansion
        OP_NOP1 = 0xb0,
        OP_NOP4 = 0xb3,
        OP_NOP5 = 0xb4,
        OP_NOP6 = 0xb5,
        OP_NOP7 = 0xb6,
        OP_NOP8 = 0xb7,
        OP_NOP9 = 0xb8,
        OP_NOP10 = 0xb9,

        // template matching params
        OP_SMALLDATA = 0xf9,
        OP_SMALLINTEGER = 0xfa,
        OP_PUBKEYS = 0xfb,
        OP_INTEGER = 0xfc,
        OP_PUBKEYHASH = 0xfd,
        OP_PUBKEY = 0xfe,

        OP_INVALIDOPCODE = 0xff
    };
    const char *GetOpName(ScriptOpcodes::opcodetype opcode);
}

//
// Serialized script, used inside transaction inputs and outputs
//
class CScript : public std::vector<uint8_t>
{
private:
    static std::string ValueString(const std::vector<unsigned char> &vch) {
        if (vch.size() <= 4) {
            return strprintf("%d", CBigNum(vch).getint32());
        } else {
            return util::HexStr(vch);
        }
    }

    static std::string StackString(const std::vector<std::vector<unsigned char> > &vStack) {
        std::string str;
        BOOST_FOREACH(const std::vector<unsigned char> &vch, vStack)
        {
            if (! str.empty()) {
                str += " ";
            }
            str += ValueString(vch);
        }
        return str;
    }

protected:
    CScript &push_int64(int64_t n) {
        if (n == -1 || (n >= 1 && n <= 16)) {
            push_back((uint8_t)n + (ScriptOpcodes::OP_1 - 1));
        } else {
            CBigNum bn(n);
            *this << bn.getvch();
        }
        return *this;
    }

    CScript &push_uint64(uint64_t n) {
        if (n >= 1 && n <= 16) {
            push_back((uint8_t)n + (ScriptOpcodes::OP_1 - 1));
        } else {
            CBigNum bn(n);
            *this << bn.getvch();
        }
        return *this;
    }

public:
    CScript() {}
    CScript(const CScript &b) : std::vector<uint8_t>(b.begin(), b.end()) {}
    CScript(const_iterator pbegin, const_iterator pend) : std::vector<uint8_t>(pbegin, pend) {}
#ifndef _MSC_VER
    CScript(const uint8_t *pbegin, const uint8_t* pend) : std::vector<uint8_t>(pbegin, pend) {}
#endif

    CScript &operator+=(const CScript &b) {
        insert(end(), b.begin(), b.end());
        return *this;
    }

    explicit CScript(int8_t  b) { operator<<(b); }
    explicit CScript(int16_t b) { operator<<(b); }
    explicit CScript(int32_t b) { operator<<(b); }
    explicit CScript(int64_t b) { operator<<(b); }

    explicit CScript(uint8_t  b) { operator<<(b); }
    explicit CScript(uint16_t b) { operator<<(b); }
    explicit CScript(uint32_t b) { operator<<(b); }
    explicit CScript(uint64_t b) { operator<<(b); }

    explicit CScript(ScriptOpcodes::opcodetype b) { operator<<(b); }
    explicit CScript(const uint256 &b) { operator<<(b); }
    explicit CScript(const CBigNum &b) { operator<<(b); }
    explicit CScript(const std::vector<uint8_t> &b) { operator<<(b); }

    CScript &operator<<(int8_t  b) { return push_int64(b); }
    CScript &operator<<(int16_t b) { return push_int64(b); }
    CScript &operator<<(int32_t b) { return push_int64(b); }
    CScript &operator<<(int64_t b) { return push_int64(b); }

    CScript &operator<<(uint8_t  b) { return push_uint64(b); }
    CScript &operator<<(uint16_t b) { return push_uint64(b); }
    CScript &operator<<(uint32_t b) { return push_uint64(b); }
    CScript &operator<<(uint64_t b) { return push_uint64(b); }

    CScript &operator<<(ScriptOpcodes::opcodetype opcode) {
        if (opcode < 0 || opcode > 0xff) {
            throw std::runtime_error("CScript::operator<<() : invalid opcode");
        }
        insert(end(), (uint8_t)opcode);
        return *this;
    }

    CScript &operator<<(const uint160 &b) {
        insert(end(), sizeof(b));
        insert(end(), (uint8_t*)&b, (uint8_t*)&b + sizeof(b));
        return *this;
    }

    CScript &operator<<(const uint256& b) {
        insert(end(), sizeof(b));
        insert(end(), (uint8_t*)&b, (uint8_t*)&b + sizeof(b));
        return *this;
    }

    CScript &operator<<(const CPubKey &key) {
        std::vector<uint8_t> vchKey(key.begin(), key.end());
        return (*this) << vchKey;
    }

    CScript &operator<<(const CBigNum &b) {
        (*this) << b.getvch();
        return *this;
    }

    CScript &operator<<(const std::vector<uint8_t> &b) {
        if (b.size() < ScriptOpcodes::OP_PUSHDATA1) {
            insert(end(), (uint8_t)b.size());
        } else if (b.size() <= 0xff) {
            insert(end(), ScriptOpcodes::OP_PUSHDATA1);
            insert(end(), (uint8_t)b.size());
        } else if (b.size() <= 0xffff) {
            insert(end(), ScriptOpcodes::OP_PUSHDATA2);
            uint16_t nSize = (uint16_t) b.size();
            insert(end(), (uint8_t *)&nSize, (uint8_t *)&nSize + sizeof(nSize));
        } else {
            insert(end(), ScriptOpcodes::OP_PUSHDATA4);
            uint32_t nSize = (uint32_t) b.size();
            insert(end(), (uint8_t *)&nSize, (uint8_t *)&nSize + sizeof(nSize));
        }
        insert(end(), b.begin(), b.end());
        return *this;
    }

    friend CScript operator+(const CScript &a, const CScript &b) {
        CScript ret = a;
        ret += b;
        return ret;
    }

    CScript &operator<<(const CScript &b) {
        //
        // I'm not sure if this should push the script or concatenate scripts.
        // If there's ever a use for pushing a script onto a script, delete this member fn
        // 
        // CScript a, b;
        // NG: a << b
        // OK: a += b
        //
        assert(!"Warning: Pushing a CScript onto a CScript with << is probably not intended, use + to concatenate!");
        return *this;
    }

    bool GetOp(iterator& pc, ScriptOpcodes::opcodetype &opcodeRet, std::vector<uint8_t> &vchRet) {
         //
         // Wrapper so it can be called with either iterator or const_iterator
         //
         const_iterator pc2 = pc;
         bool fRet = GetOp2(pc2, opcodeRet, &vchRet);
         pc = begin() + (pc2 - begin());
         return fRet;
    }

    bool GetOp(iterator &pc, ScriptOpcodes::opcodetype &opcodeRet) {
         const_iterator pc2 = pc;
         bool fRet = GetOp2(pc2, opcodeRet, NULL);
         pc = begin() + (pc2 - begin());
         return fRet;
    }

    bool GetOp(const_iterator &pc, ScriptOpcodes::opcodetype &opcodeRet, std::vector<uint8_t> &vchRet) const {
        return GetOp2(pc, opcodeRet, &vchRet);
    }

    bool GetOp(const_iterator &pc, ScriptOpcodes::opcodetype &opcodeRet) const {
        return GetOp2(pc, opcodeRet, NULL);
    }

    bool GetOp2(const_iterator &pc, ScriptOpcodes::opcodetype &opcodeRet, std::vector<uint8_t> *pvchRet) const {
        opcodeRet = ScriptOpcodes::OP_INVALIDOPCODE;
        if (pvchRet) {
            pvchRet->clear();
        }
        if (pc >= end()) {
            return false;
        }

        // Read instruction
        if (end() - pc < 1) {
            return false;
        }
        uint32_t opcode = *pc++;

        // Immediate operand
        if (opcode <= ScriptOpcodes::OP_PUSHDATA4) {
            uint32_t nSize = ScriptOpcodes::OP_0;
            if (opcode < ScriptOpcodes::OP_PUSHDATA1) {
                nSize = opcode;
            } else if (opcode == ScriptOpcodes::OP_PUSHDATA1) {
                if (end() - pc < 1) {
                    return false;
                }
                nSize = *pc++;
            } else if (opcode == ScriptOpcodes::OP_PUSHDATA2) {
                if (end() - pc < 2) {
                    return false;
                }
                ::memcpy(&nSize, &pc[0], 2);
                pc += 2;
            } else if (opcode == ScriptOpcodes::OP_PUSHDATA4) {
                if (end() - pc < 4) {
                    return false;
                }
                ::memcpy(&nSize, &pc[0], 4);
                pc += 4;
            }
            if (end() - pc < 0 || (uint32_t)(end() - pc) < nSize) {
                return false;
            }
            if (pvchRet) {
                pvchRet->assign(pc, pc + nSize);
            }
            pc += nSize;
        }

        opcodeRet = (ScriptOpcodes::opcodetype)opcode;
        return true;
    }

    //
    // Encode/decode small integers
    //
    static int DecodeOP_N(ScriptOpcodes::opcodetype opcode) {
        if (opcode == ScriptOpcodes::OP_0) {
            return 0;
        }
        assert(opcode >= ScriptOpcodes::OP_1 && opcode <= ScriptOpcodes::OP_16);
        return (opcode - (ScriptOpcodes::OP_1 - 1));
    }

    static ScriptOpcodes::opcodetype EncodeOP_N(int n) {
        assert(n >= 0 && n <= 16);
        if (n == 0) {
            return ScriptOpcodes::OP_0;
        }
        return (ScriptOpcodes::opcodetype)(ScriptOpcodes::OP_1 + n - 1);
    }

    int FindAndDelete(const CScript &b) {
        int nFound = 0;
        if (b.empty()) {
            return nFound;
        }

        iterator pc = begin();
        ScriptOpcodes::opcodetype opcode;
        do
        {
            while (end() - pc >= (long)b.size() && ::memcmp(&pc[0], &b[0], b.size()) == 0)
            {
                erase(pc, pc + b.size());
                ++nFound;
            }
        } while (GetOp(pc, opcode));
        return nFound;
    }

    int Find(ScriptOpcodes::opcodetype op) const {
        int nFound = 0;
        ScriptOpcodes::opcodetype opcode;
        for (const_iterator pc = begin(); pc != end() && GetOp(pc, opcode);)
        {
            if (opcode == op) {
                ++nFound;
            }
        }
        return nFound;
    }

    //
    // Pre-version-0.6, Bitcoin always counted CHECKMULTISIGs
    // as 20 sigops. With pay-to-script-hash, that changed:
    // CHECKMULTISIGs serialized in scriptSigs are
    // counted more accurately, assuming they are of the form
    //  ... OP_N CHECKMULTISIG ...
    //
    unsigned int GetSigOpCount(bool fAccurate) const;

    //
    // Accurately count sigOps, including sigOps in
    // pay-to-script-hash transactions:
    //
    unsigned int GetSigOpCount(const CScript &scriptSig) const;

    bool IsPayToScriptHash() const;
    bool IsPushOnly(const_iterator pc) const {
        while (pc < end())
        {
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

    //
    // Called by CTransaction::IsStandard and P2SH VerifyScript (which makes it consensus-critical).
    //
    bool IsPushOnly() const {
        return IsPushOnly(begin());
    }

    //
    // Called by CTransaction::IsStandard.
    //
    bool HasCanonicalPushes() const;

    void SetDestination(const CTxDestination &address);
    void SetAddress(const CBitcoinAddress &dest);
    void SetMultisig(int nRequired, const std::vector<CPubKey> &keys);

    void PrintHex() const {
        printf("CScript(%s)\n", util::HexStr(begin(), end(), true).c_str());
    }

    std::string ToString(bool fShort=false) const {
        std::string str;
        ScriptOpcodes::opcodetype opcode;
        std::vector<uint8_t> vch;
        const_iterator pc = begin();
        while (pc < end())
        {
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

    void script_print() const {        // rename: print => script_print
        printf("%s\n", ToString().c_str());
    }

    CScriptID GetID() const {
        return CScriptID(hash_basis::Hash160(*this));
    }
};

//
// Script_util
//
class Script_util : private no_instance
{
public:
    typedef std::vector<uint8_t> valtype;

private:
    // Setting nSequence to this value for every input in a transaction disables nLockTime.
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    // Threshold for inverted nSequence: below this value it is interpreted as a relative lock-time, otherwise ignored.
    // static const uint32_t SEQUENCE_THRESHOLD = 0x80000000;

    // If this flag set, CTxIn::nSequence is NOT interpreted as a relative lock-time.
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = 0x80000000;

    // If CTxIn::nSequence encodes a relative lock-time and this flag is set, the relative lock-time has units of 512 seconds,
    // otherwise it specifies blocks with a granularity of 1.
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = 0x00400000;

    // If CTxIn::nSequence encodes a relative lock-time, this mask is applied to extract that lock-time from the sequence field.
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    static const valtype vchFalse;
    static const valtype vchZero;
    static const valtype vchTrue;
    static const CBigNum bnZero;
    static const CBigNum bnOne;
    static const CBigNum bnFalse;
    static const CBigNum bnTrue;

    static CBigNum CastToBigNum(const valtype &vch);
    static bool CastToBool(const valtype &vch);

    static void popstack(std::vector<valtype> &stack);

    static uint256 SignatureHash(CScript scriptCode, const CTransaction &txTo, unsigned int nIn, int nHashType);
    static bool CheckSig(std::vector<unsigned char> vchSig, const std::vector<unsigned char> &vchPubKey, const CScript &scriptCode, const CTransaction &txTo, unsigned int nIn, int nHashType, int flags);
    static unsigned int HaveKeys(const std::vector<valtype> &pubkeys, const CKeyStore &keystore);

    static bool IsCanonicalSignature(const valtype &vchSig, unsigned int flags);
    static bool IsCanonicalPubKey(const std::vector<unsigned char> &vchPubKey, unsigned int flags);
    static bool Solver(const CKeyStore &keystore, const CScript &scriptPubKey, const uint256& hash, int nHashType, CScript &scriptSigRet, TxnOutputType::txnouttype &whichTypeRet);

    static bool Sign1(const CKeyID &address, const CKeyStore &keystore, const uint256 &hash, int nHashType, CScript &scriptSigRet);
    static bool SignR(const CPubKey &pubKey, const CPubKey &R, const CKeyStore &keystore, const uint256 &hash, int nHashType, CScript &scriptSigRet);
    static bool SignN(const std::vector<valtype> &multisigdata, const CKeyStore &keystore, const uint256 &hash, int nHashType, CScript &scriptSigRet);

    static CScript CombineSignatures(const CScript &scriptPubKey, const CTransaction &txTo, unsigned int nIn, const TxnOutputType::txnouttype txType, const std::vector<valtype> &vSolutions, std::vector<valtype> &sigs1, std::vector<valtype> &sigs2);

public:
    static bool IsDERSignature(const valtype &vchSig, bool fWithHashType=false, bool fCheckLow=false);
    static bool EvalScript(std::vector<std::vector<unsigned char> > &stack, const CScript &script, const CTransaction &txTo, unsigned int nIn, unsigned int flags, int nHashType);
    static bool Solver(const CScript &scriptPubKey, TxnOutputType::txnouttype &typeRet, std::vector<std::vector<unsigned char> > &vSolutionsRet);
    static int ScriptSigArgsExpected(TxnOutputType::txnouttype t, const std::vector<std::vector<unsigned char> > &vSolutions);
    static bool IsStandard(const CScript &scriptPubKey, TxnOutputType::txnouttype &whichType);

    static isminetype IsMine(const CKeyStore &keystore, const CBitcoinAddress &dest);
    static isminetype IsMine(const CKeyStore &keystore, const CScript &scriptPubKey);
    static void ExtractAffectedKeys(const CKeyStore &keystore, const CScript &scriptPubKey, std::vector<CKeyID> &vKeys);
    
    static bool ExtractDestination(const CScript &scriptPubKey, CTxDestination &addressRet);
    static bool ExtractDestinations(const CScript &scriptPubKey, TxnOutputType::txnouttype &typeRet, std::vector<CTxDestination> &addressRet, int &nRequiredRet);
    static bool ExtractAddress(const CKeyStore &keystore, const CScript &scriptPubKey, CBitcoinAddress &addressRet);

    static bool SignSignature(const CKeyStore &keystore, const CScript &fromPubKey, CTransaction &txTo, unsigned int nIn, int nHashType=Script_param::SIGHASH_ALL);
    static bool SignSignature(const CKeyStore &keystore, const CTransaction &txFrom, CTransaction &txTo, unsigned int nIn, int nHashType=Script_param::SIGHASH_ALL);
    static bool VerifyScript(const CScript &scriptSig, const CScript &scriptPubKey, const CTransaction &txTo, unsigned int nIn, unsigned int flags, int nHashType);

    //
    // Given two sets of signatures for scriptPubKey, possibly with OP_0 placeholders,
    // combine them intelligently and return the result.
    //
    static CScript CombineSignatures(const CScript &scriptPubKey, const CTransaction &txTo, unsigned int nIn, const CScript &scriptSig1, const CScript &scriptSig2);
};

// isminetype IsMine(const CKeyStore& keystore, const CTxDestination& dest);    // unused: CTxDestination -> CBitcoinAddress (A CTxDestination is the internal data type encoded in a CBitcoinAddress)

#endif
//@
