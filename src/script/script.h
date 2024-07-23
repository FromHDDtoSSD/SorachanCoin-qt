// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef H_BITCOIN_SCRIPT
#define H_BITCOIN_SCRIPT

#include <string>
#include <vector>
#include <prevector/prevector.h>
#include <script/scriptnum.h>
#include <script/standard.h>

#include <keystore.h>
#include <bignum.h>
#include <address/base58.h>

template <typename ENC> class CBitcoinAddress_impl;
class CBase58Data;
using CBitcoinAddress = CBitcoinAddress_impl<CBase58Data>;

namespace Script_const {
    // Maximum number of bytes pushable to the stack
    static constexpr unsigned int MAX_SCRIPT_ELEMENT_SIZE = 520;

    // Maximum number of non-push operations per script
    static constexpr int MAX_OPS_PER_SCRIPT = 201;

    // Maximum number of public keys per multisig
    static constexpr int MAX_PUBKEYS_PER_MULTISIG = 20;

    // Maximum script length in bytes
    static constexpr int MAX_SCRIPT_SIZE = 10000;

    // Maximum number of values on script interpreter stack
    static constexpr int MAX_STACK_SIZE = 1000;

    // Threshold for nLockTime: below this value it is interpreted as block number,
    // otherwise as UNIX timestamp.
    static constexpr unsigned int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC

    // Maximum nLockTime. Since a lock time indicates the last invalid timestamp, a
    // transaction with this lock time will never be valid unless lock time
    // checking is disabled (by setting all input sequence numbers to
    // SEQUENCE_FINAL).
    static constexpr uint32_t LOCKTIME_MAX = 0xFFFFFFFFU;
}

namespace Script_param
{
    // constexpr unsigned int MAX_SCRIPT_ELEMENT_SIZE = 520; // bytes

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
        SCRIPT_VERIFY_MINIMALDATA = (1U << 6),          // Require minimal encodings for all push operations, Evaluating any other push causes the script to fail (BIP62 rule 3)
        SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1U << 7), // Discourage use of NOPs reserved for upgrades (NOP1-10)
        SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),
        SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10)
    };

    // * force DER encoding;
    // * force low S;
    // * ensure that CHECKMULTISIG dummy argument is null.
    constexpr unsigned int STRICT_FORMAT_FLAGS = SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_NULLDUMMY;

    // Mandatory script verification flags that all new blocks must comply with for
    // them to be valid. (but old blocks may not comply with) Currently just P2SH,
    // but in the future other flags may be added, such as a soft-fork to enforce
    // strict DER encoding.
    //
    // Failing one of these tests may trigger a DoS ban - see ConnectInputs() for details.
    constexpr unsigned int MANDATORY_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH;

    // Standard script verification flags that standard transactions will comply
    // with. However scripts violating these flags may still be present in valid blocks and we must accept those blocks.
    constexpr unsigned int STRICT_FLAGS = MANDATORY_SCRIPT_VERIFY_FLAGS | STRICT_FORMAT_FLAGS;

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
using isminefilter = uint8_t;

//
// TxnOutputType
//
namespace TxnOutputType
{
    enum txnouttype
    {
        TX_NONSTANDARD,
        // 'standard' transaction types:
        TX_PUBKEY, // P2PK
        TX_PUBKEYVCH, // P2PKB (DAO: Pay to PublicKey Bridge)
        TX_PUBKEY_DROP,
        TX_PUBKEYHASH, // P2PKH
        TX_SCRIPTHASH, // P2SH
        TX_MULTISIG,
        TX_NULL_DATA, //!< unspendable OP_RETURN script that carries data
        TX_WITNESS_V0_SCRIPTHASH, // P2WSH
        TX_WITNESS_V0_KEYHASH, // P2WPKH
        TX_WITNESS_UNKNOWN, //!< Only for Witness versions not already defined above
    };
    /** Get the name of a txnouttype as a C string, or nullptr if unknown. */
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
        //OP_CHECKLOCKTIMEVERIFY = 0xb1,
        //OP_CHECKSEQUENCEVERIFY = 0xb2,

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
        OP_CHECKLOCKTIMEVERIFY = 0xb1,
        OP_NOP2 = OP_CHECKLOCKTIMEVERIFY,
        OP_CHECKSEQUENCEVERIFY = 0xb2,
        OP_NOP3 = OP_CHECKSEQUENCEVERIFY,
        OP_CHECKQAISIGVERIFY = 0xb3,
        OP_NOP4 = OP_CHECKQAISIGVERIFY,
        OP_NOP5 = 0xb4,
        OP_NOP6 = 0xb5,
        OP_NOP7 = 0xb6,
        OP_NOP8 = 0xb7,
        OP_NOP9 = 0xb8,
        OP_NOP10 = 0xb9,

        // zerocoin, dao
        OP_ZEROCOINMINT = 0xc1,
        OP_ZEROCOINSPEND = 0xc2,
        OP_HASHETH = 0xc3,

        // template matching params
        OP_SMALLDATA = 0xf9,
        OP_SMALLINTEGER = 0xfa,
        OP_PUBKEYS = 0xfb,
        OP_INTEGER = 0xfc,
        OP_PUBKEYHASH = 0xfd,
        OP_PUBKEY = 0xfe,

        OP_INVALIDOPCODE = 0xff
    };

    // Maximum value that an opcode can be
    static constexpr unsigned int MAX_OPCODE = OP_PUBKEY;

    const char *GetOpName(ScriptOpcodes::opcodetype opcode);
}

//
// Serialized script, used inside transaction inputs and outputs
//
#ifdef CSCRIPT_PREVECTOR_ENABLE
using script_vector = prevector<PREVECTOR_N, uint8_t>;
using stack_vector = prevector<PREVECTOR_N, prevector<PREVECTOR_N, uint8_t> >;
#else
using script_vector = std::vector<uint8_t>;
using stack_vector = std::vector<std::vector<uint8_t> >;
#endif
class CScript final : public script_vector
{
public:
    template <typename T>
    static script_vector ToByteVector(const T &in) {
        return script_vector(in.begin(), in.end());
    }

private:
    static std::string ValueString(const script_vector &vch) {
        if (vch.size() <= 4)
            return tfm::format("%d", CBigNum(vch).getint32());
        else
            return util::HexStr(vch);
    }

    static std::string StackString(const stack_vector &vStack) {
        std::string str;
        for(const script_vector &vch: vStack) {
            if (! str.empty())
                str += " ";
            str += ValueString(vch);
        }
        return str;
    }

protected:
    CScript &push_int64(int64_t n) { // OP_1NEGATE, OP_1 - OP_16 or OP_PUSHDATA1 - OP_PUSHDATA4
        if (n == -1 || (n >= 1 && n <= 16)) {
            push_back((uint8_t)n + (ScriptOpcodes::OP_1 - 1));
        } else if (n == 0) {
            push_back(ScriptOpcodes::OP_0);
        } else {
            *this << CScriptNum::serialize(n);
        }
        return *this;
    }

    CScript &push_uint64(uint64_t n) { // [used: miner.cpp] OP_1 - OP_16 or OP_PUSHDATA1 - OP_PUSHDATA4
        if (n >= 1 && n <= 16) {
            push_back((uint8_t)n + (ScriptOpcodes::OP_1 - 1));
        } else if (n == 0) {
            push_back(ScriptOpcodes::OP_0);
        } else {
            *this << CScriptNum::serialize(n);
        }
        return *this;
    }

public:
    CScript() {}
    CScript(const CScript &b) : script_vector(b.begin(), b.end()) {}
    CScript(script_vector::const_iterator pbegin, script_vector::const_iterator pend) : script_vector(pbegin, pend) {}
#ifndef _MSC_VER
    CScript(const uint8_t *pbegin, const uint8_t *pend) : script_vector(pbegin, pend) {}
#endif

    CScript &operator+=(const CScript &b) {
        insert(end(), b.begin(), b.end());
        return *this;
    }

    friend CScript operator+(const CScript &a, const CScript &b) {
        CScript ret = a;
        ret += b;
        return ret;
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITEAS(script_vector, *this);
    }

    operator std::vector<unsigned char>() const { // convert from prevector to std::vector<unsigned char>
        std::vector<unsigned char> obj(this->begin(), this->end());
        return obj;
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
    explicit CScript(const script_vector &b) { operator<<(b); }

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
        insert(end(), (uint8_t *)&b, (uint8_t *)&b + sizeof(b));
        return *this;
    }

    CScript &operator<<(const uint256 &b) {
        insert(end(), sizeof(b));
        insert(end(), (uint8_t *)&b, (uint8_t *)&b + sizeof(b));
        return *this;
    }

    CScript &operator<<(const uint65536 &b) {
        script_vector vch(BEGIN(b), END(b));
        return (*this) << vch;
    }

    CScript &operator<<(const CPubKey &pubkey) {
        script_vector vchpubKey(pubkey.begin(), pubkey.end());
        return (*this) << vchpubKey;
    }

    /* unused
    CScript &operator<<(const CqKeyID &qpubid) {
        script_vector vchqpubKey = strenc::ParseHex(qpubid);
        assert(vchqpubKey.size() == CqPubKey::QAI_PUBLIC_KEY_SIZE || vchqpubKey.size() == CqPubKey::COMPRESSED_PUBLIC_KEY_SIZE);

        if(vchqpubKey.size() == CqPubKey::QAI_PUBLIC_KEY_SIZE) {
            (*this) << vchqpubKey;
        } else {
            script_vector vchChunk(&vchqpubKey[0], &vchqpubKey[Script_const::MAX_SCRIPT_ELEMENT_SIZE]);
            script_vector vchChunk2(&vchqpubKey[Script_const::MAX_SCRIPT_ELEMENT_SIZE], &vchqpubKey.back() + 1);
            (*this) << vchChunk2;
            (*this) << vchChunk;
        }
        return *this;
    }
    */

    CScript &operator<<(const CqPubKey &qpubkey) {
        script_vector vchqpubKey = qpubkey.GetVch();
        assert(vchqpubKey.size() == CqPubKey::QAI_PUBLIC_KEY_SIZE || vchqpubKey.size() == CqPubKey::COMPRESSED_PUBLIC_KEY_SIZE);

        if(vchqpubKey.size() == CqPubKey::QAI_PUBLIC_KEY_SIZE) {
            (*this) << vchqpubKey;
        } else {
            script_vector vchChunk(&vchqpubKey[0], &vchqpubKey[Script_const::MAX_SCRIPT_ELEMENT_SIZE]);
            script_vector vchChunk2(&vchqpubKey[Script_const::MAX_SCRIPT_ELEMENT_SIZE], &vchqpubKey.back() + 1);
            (*this) << vchChunk2;
            (*this) << vchChunk;
        }
        return *this;
    }

    CScript &operator<<(const CBigNum &b) {
        return (*this) << b.getvch();
    }

    CScript &operator<<(const CScriptNum &b) {
        return (*this) << b.getvch();
    }

    CScript &operator<<(const script_vector &b) {
        if (b.size() < ScriptOpcodes::OP_PUSHDATA1) { // secp256k1 pubkey size: below 75 byte.
            insert(end(), (uint8_t)b.size());
        } else if (b.size() <= 0xff) {
            insert(end(), ScriptOpcodes::OP_PUSHDATA1);
            insert(end(), (uint8_t)b.size());
        } else if (b.size() <= 0xffff) {
            insert(end(), ScriptOpcodes::OP_PUSHDATA2);
            uint16_t nSize = (uint16_t)b.size();
            insert(end(), (uint8_t *)&nSize, (uint8_t *)&nSize + sizeof(nSize));
        } else {
            insert(end(), ScriptOpcodes::OP_PUSHDATA4);
            uint32_t nSize = (uint32_t)b.size();
            insert(end(), (uint8_t *)&nSize, (uint8_t *)&nSize + sizeof(nSize));
        }
        insert(end(), b.begin(), b.end());
        return *this;
    }

    // I'm not sure if this should push the script or concatenate scripts.
    // If there's ever a use for pushing a script onto a script, delete this member fn
    // CScript a, b;
    // NG: a << b
    // OK: a += b
    CScript &operator<<(const CScript &b)=delete;

    //
    // Wrapper so it can be called with either iterator or const_iterator
    //
    bool GetOp(iterator &pc, ScriptOpcodes::opcodetype &opcodeRet, script_vector &vchRet);
    bool GetOp(iterator &pc, ScriptOpcodes::opcodetype &opcodeRet);
    bool GetOp(const_iterator &pc, ScriptOpcodes::opcodetype &opcodeRet, script_vector &vchRet) const;
    bool GetOp(const_iterator &pc, ScriptOpcodes::opcodetype &opcodeRet) const;
    static bool GetScriptOp(const_iterator &pc, script_vector::const_iterator end, ScriptOpcodes::opcodetype &opcodeRet, script_vector *pvchRet);

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
    bool IsPushOnly(const_iterator pc) const;

    //
    // P2PKH Transaction
    //
    bool IsPayToPublicKeyHash() const;

    //
    // If 1-1 multisig, in PayToEthID tarnsactions:
    //
    bool IsPayToEthID() const;

    //
    // If EthID Locked Transaction
    //
    bool IsLockToEthID() const;

    //
    // If SORA L1 Quantum and AI Resistance transaction
    //
    bool IsPayToQAIResistance() const;

    //
    // witness transactions:
    //
    bool IsPayToWitnessScriptHash() const;
    bool IsWitnessProgram(int &version, script_vector &program) const;

    bool HasValidOps() const;

    //
    // Called by CTransaction::IsStandard and P2SH VerifyScript (which makes it consensus-critical).
    //
    bool IsPushOnly() const;

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

    std::string ToString(bool fShort=false) const;
    void script_print() const { // rename: print => script_print
        printf("%s\n", ToString().c_str());
    }

    CScriptID GetID() const {
        return CScriptID(hash_basis::Hash160(*this));
    }

    /**
    * Returns whether the script is guaranteed to fail at execution,
    * regardless of the initial stack. This allows outputs to be pruned
    * instantly when entering the UTXO set.
    */
    bool IsUnspendable() const {
        return (size() > 0 && *begin() == ScriptOpcodes::OP_RETURN);
    }

    bool IsZerocoinMint() const {
        //fast test for Zerocoin Mint CScripts
        return (this->size() > 0 &&
            this->at(0) == ScriptOpcodes::OP_ZEROCOINMINT);
    }

    bool IsZerocoinSpend() const {
        return (this->size() > 0 &&
            this->at(0) == ScriptOpcodes::OP_ZEROCOINSPEND);
    }

};

#endif
