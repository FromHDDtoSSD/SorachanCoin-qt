// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_INTERPRETER_H
#define BITCOIN_SCRIPT_INTERPRETER_H

#include <script/scriptnum.h>
#include <script/script_error.h>
#include <block/transaction.h>
#include <const/amount.h>
#include <prevector/prevector.h>
#include <script/standard.h>

#include <vector>
#include <stdint.h>
#include <string>

class CPubKey;
class CScript;
class uint256;

class Script_util : private no_instance {
public:
#ifdef CSCRIPT_PREVECTOR_ENABLE
    using valtype = prevector<PREVECTOR_N, uint8_t>;
    using statype = prevector<PREVECTOR_N, prevector<PREVECTOR_N, uint8_t> >;
#else
    using valtype = std::vector<uint8_t>;
    using statype = std::vector<std::vector<uint8_t> >;
#endif
private:

    static uint256 SignatureHash(CScript scriptCode, const CTransaction &txTo, unsigned int nIn, int nHashType);
    static bool CheckSig(const script_vector &vchSig, const script_vector &vchPubKey, const uint256 &hash);
    static bool CheckSig(script_vector vchSig, const script_vector &vchPubKey, const CScript &scriptCode, const CTransaction &txTo, unsigned int nIn, int nHashType, int flags);
    static unsigned int HaveKeys(const std::vector<valtype> &pubkeys, const CKeyStore &keystore);

    static bool IsCanonicalSignature(const valtype &vchSig, unsigned int flags);
    static bool IsCanonicalPubKey(const valtype &vchPubKey, unsigned int flags);
    static bool Solver(const CKeyStore &keystore, const CScript &scriptPubKey, const uint256& hash, int nHashType, CScript &scriptSigRet, TxnOutputType::txnouttype &whichTypeRet);

    static bool Sign1(const CKeyID &address, const CKeyStore &keystore, const uint256 &hash, int nHashType, CScript &scriptSigRet);
    static bool SignR(const CPubKey &pubKey, const CPubKey &R, const CKeyStore &keystore, const uint256 &hash, int nHashType, CScript &scriptSigRet);
    static bool SignN(const statype &multisigdata, const CKeyStore &keystore, const uint256 &hash, int nHashType, CScript &scriptSigRet);

    static CScript CombineSignatures(const CScript &scriptPubKey, const CTransaction &txTo, unsigned int nIn, const TxnOutputType::txnouttype txType, const statype &vSolutions, statype &sigs1, statype &sigs2);

public:
    static bool IsDERSignature(const valtype &vchSig, bool fWithHashType=false, bool fCheckLow=false);
    static bool EvalScript(statype &stack, const CScript &script, const CTransaction &txTo, unsigned int nIn, unsigned int flags, int nHashType);
    static bool Solver(const CScript &scriptPubKey, TxnOutputType::txnouttype &typeRet, statype &vSolutionsRet);
    static int ScriptSigArgsExpected(TxnOutputType::txnouttype t, const statype &vSolutions);
    static bool IsStandard(const CScript &scriptPubKey, TxnOutputType::txnouttype &whichType);

    static isminetype IsMine(const CKeyStore &keystore, const CBitcoinAddress &dest);
    static isminetype IsMine(const CKeyStore &keystore, const CScript &scriptPubKey);
    static void ExtractAffectedKeys(const CKeyStore &keystore, const CScript &scriptPubKey, std::vector<CKeyID> &vKeys);

    static bool ExtractAddress(const CKeyStore &keystore, const CScript &scriptPubKey, CBitcoinAddress &addressRet);

    static bool SignSignature(const CKeyStore &keystore, const CScript &fromPubKey, CTransaction &txTo, unsigned int nIn, int nHashType=Script_param::SIGHASH_ALL);
    static bool SignSignature(const CKeyStore &keystore, const CTransaction &txFrom, CTransaction &txTo, unsigned int nIn, int nHashType=Script_param::SIGHASH_ALL);
    static bool VerifyScript(const CScript &scriptSig, const CScript &scriptPubKey, const CTransaction &txTo, unsigned int nIn, unsigned int flags, int nHashType);

    // Given two sets of signatures for scriptPubKey, possibly with OP_0 placeholders,
    // combine them intelligently and return the result.
    static CScript CombineSignatures(const CScript &scriptPubKey, const CTransaction &txTo, unsigned int nIn, const CScript &scriptSig1, const CScript &scriptSig2);

public:
    enum class SigVersion {
        BASE = 0,
        WITNESS_V0 = 1,
    };

    class BaseSignatureChecker {
    public:
        virtual bool CheckSig(const valtype &scriptSig, const valtype &vchPubKey, const CScript &scriptCode, SigVersion sigversion) const = 0;
        virtual bool CheckLockTime(const CScriptNum &nLockTime) const = 0;
        virtual bool CheckSequence(const CScriptNum &nSequence) const = 0;
        virtual ~BaseSignatureChecker() {}
    };

private:
    /** Signature hash types/flags */
    enum
    {
        SIGHASH_ALL = 1,
        SIGHASH_NONE = 2,
        SIGHASH_SINGLE = 3,
        SIGHASH_ANYONECANPAY = 0x80,
    };

    /** Script verification flags.
     *
     *  All flags are intended to be soft forks: the set of acceptable scripts under
     *  flags (A | B) is a subset of the acceptable scripts under flag (A).
     */
    enum
    {
        SCRIPT_VERIFY_NONE      = 0,

        // Evaluate P2SH subscripts (BIP16).
        SCRIPT_VERIFY_P2SH      = (1U << 0),

        // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
        // Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
        // (not used or intended as a consensus rule).
        SCRIPT_VERIFY_STRICTENC = (1U << 1),

        // Passing a non-strict-DER signature to a checksig operation causes script failure (BIP62 rule 1)
        SCRIPT_VERIFY_DERSIG    = (1U << 2),

        // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
        // (BIP62 rule 5).
        SCRIPT_VERIFY_LOW_S     = (1U << 3),

        // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (BIP62 rule 7).
        SCRIPT_VERIFY_NULLDUMMY = (1U << 4),

        // Using a non-push operator in the scriptSig causes script failure (BIP62 rule 2).
        SCRIPT_VERIFY_SIGPUSHONLY = (1U << 5),

        // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
        // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
        // any other push causes the script to fail (BIP62 rule 3).
        // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
        SCRIPT_VERIFY_MINIMALDATA = (1U << 6),

        // Discourage use of NOPs reserved for upgrades (NOP1-10)
        //
        // Provided so that nodes can avoid accepting or mining transactions
        // containing executed NOP's whose meaning may change after a soft-fork,
        // thus rendering the script invalid; with this flag set executing
        // discouraged NOPs fails the script. This verification flag will never be
        // a mandatory flag applied to scripts in a block. NOPs that are not
        // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
        // NOPs that have associated forks to give them new meaning (CLTV, CSV)
        // are not subject to this rule.
        SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS  = (1U << 7),

        // Require that only a single stack element remains after evaluation. This changes the success criterion from
        // "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
        // "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
        // (BIP62 rule 6)
        // Note: CLEANSTACK should never be used without P2SH or WITNESS.
        SCRIPT_VERIFY_CLEANSTACK = (1U << 8),

        // Verify CHECKLOCKTIMEVERIFY
        //
        // See BIP65 for details.
        SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),

        // support CHECKSEQUENCEVERIFY opcode
        //
        // See BIP112 for details
        SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10),

        // Support segregated witness
        //
        SCRIPT_VERIFY_WITNESS = (1U << 11),

        // Making v1-v16 witness program non-standard
        //
        SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = (1U << 12),

        // Segwit script only: Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
        //
        SCRIPT_VERIFY_MINIMALIF = (1U << 13),

        // Signature(s) must be empty vector if a CHECK(MULTI)SIG operation failed
        //
        SCRIPT_VERIFY_NULLFAIL = (1U << 14),

        // Public keys in segregated witness scripts must be compressed
        //
        SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = (1U << 15),

        // Making OP_CODESEPARATOR and FindAndDelete fail any non-segwit scripts
        //
        SCRIPT_VERIFY_CONST_SCRIPTCODE = (1U << 16),
    };

private:
    static bool set_success(ScriptError *ret);
    static bool set_error(ScriptError *ret, const ScriptError serror);
    static bool CastToBool(const valtype &vch);

    static void popstack(statype &stack);
    static bool IsCompressedOrUncompressedPubKey(const valtype &vchPubKey);
    static bool IsCompressedPubKey(const valtype &vchPubKey);

    static bool IsValidSignatureEncoding(const valtype &sig);
    static bool IsLowDERSignature(const valtype &vchSig, ScriptError *serror);
    static bool IsDefinedHashtypeSignature(const valtype &vchSig);

    static bool CheckPubKeyEncoding(const valtype &vchPubKey, unsigned int flags, const SigVersion &sigversion, ScriptError *serror);
    static bool CheckMinimalPush(const valtype &data, ScriptOpcodes::opcodetype opcode);

    template <class T>
    static uint256 GetPrevoutHash(const T &txTo);
    template <class T>
    static uint256 GetSequenceHash(const T &txTo);
    template <class T>
    static uint256 GetOutputsHash(const T &txTo);

    // witness program
    static bool VerifyWitnessProgram(const CScriptWitness &witness, int witversion, const valtype &program, unsigned int flags, const BaseSignatureChecker &checker, ScriptError *serror);
    static size_t WitnessSigOps(int witversion, const valtype &witprogram, const CScriptWitness &witness);
public:
    static bool CheckSignatureEncoding(const valtype &vchSig, unsigned int flags, ScriptError *serror);
    static int FindAndDelete(CScript &script, const CScript &b);
    static bool EvalScript(statype &stack, const CScript &script, unsigned int flags, const BaseSignatureChecker &checker, SigVersion sigversion, ScriptError *error = nullptr);

    struct PrecomputedTransactionData {
        PrecomputedTransactionData()=delete;
        PrecomputedTransactionData(const PrecomputedTransactionData &)=delete;
        PrecomputedTransactionData(PrecomputedTransactionData &&)=delete;
        PrecomputedTransactionData &operator=(const PrecomputedTransactionData &)=delete;
        PrecomputedTransactionData &operator=(PrecomputedTransactionData &&)=delete;
        uint256 hashPrevouts, hashSequence, hashOutputs;
        bool ready = false;
        template <class T>
        explicit PrecomputedTransactionData(const T &tx);
    };

    template <class T>
    static uint256 SignatureHash(const CScript &scriptCode, const T &txTo, unsigned int nIn, int nHashType, const CAmount &amount, SigVersion sigversion, const PrecomputedTransactionData *cache = nullptr);

    /** Signature hash sizes */
    static constexpr size_t WITNESS_V0_SCRIPTHASH_SIZE = 32;
    static constexpr size_t WITNESS_V0_KEYHASH_SIZE = 20;

    template <class T>
    class GenericTransactionSignatureChecker : public BaseSignatureChecker
    {
    private:
        const T *txTo;
        unsigned int nIn;
        const CAmount amount;
        const PrecomputedTransactionData* txdata;
    protected:
        virtual bool VerifySignature(const valtype& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const;
    public:
        GenericTransactionSignatureChecker(const T *txToIn, unsigned int nInIn, const CAmount &amountIn) : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(nullptr) {}
        GenericTransactionSignatureChecker(const T *txToIn, unsigned int nInIn, const CAmount &amountIn, const PrecomputedTransactionData& txdataIn) : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(&txdataIn) {}
        bool CheckSig(const valtype &scriptSig, const valtype &vchPubKey, const CScript &scriptCode, SigVersion sigversion) const override;
        bool CheckLockTime(const CScriptNum &nLockTime) const override;
        bool CheckSequence(const CScriptNum &nSequence) const override;
    };

    using TransactionSignatureChecker = GenericTransactionSignatureChecker<CTransaction>;
    using MutableTransactionSignatureChecker = GenericTransactionSignatureChecker<CMutableTransaction>;
    static bool VerifyScript(const CScript &scriptSig, const CScript &scriptPubKey, const CScriptWitness *witness, unsigned int flags, const BaseSignatureChecker &checker, ScriptError *serror = nullptr);
    static size_t CountWitnessSigOps(const CScript &scriptSig, const CScript &scriptPubKey, const CScriptWitness *witness, unsigned int flags);

    /**
     * Parse a scriptPubKey and identify script type for standard scripts. If
     * successful, returns script type and parsed pubkeys or hashes, depending on
     * the type. For example, for a P2SH script, vSolutionsRet will contain the
     * script hash, for P2PKH it will contain the key hash, etc.
     *
     * @param[in]   scriptPubKey   Script to parse
     * @param[out]  vSolutionsRet  Vector of parsed pubkeys and hashes
     * @return                     The script type. TX_NONSTANDARD represents a failed solve.
     */
    static TxnOutputType::txnouttype Solver(const CScript &scriptPubKey, statype &vSolutionsRet);

    /**
     * Parse a standard scriptPubKey for the destination address. Assigns result to
     * the addressRet parameter and returns true if successful. For multisig
     * scripts, instead use ExtractDestinations. Currently only works for P2PK,
     * P2PKH, P2SH, P2WPKH, and P2WSH scripts.
     */
    static bool ExtractDestination(const CScript &scriptPubKey, CTxDestination &addressRet);

    /**
     * Parse a standard scriptPubKey with one or more destination addresses. For
     * multisig scripts, this populates the addressRet vector with the pubkey IDs
     * and nRequiredRet with the n required to spend. For other destinations,
     * addressRet is populated with a single value and nRequiredRet is set to 1.
     * Returns true if successful. Currently does not extract address from
     * pay-to-witness scripts.
     *
     * Note: this function confuses destinations (a subset of CScripts that are
     * encodable as an address) with key identifiers (of keys involved in a
     * CScript), and its use should be phased out.
     */
    static bool ExtractDestinations(const CScript &scriptPubKey, TxnOutputType::txnouttype &typeRet, std::vector<CTxDestination> &addressRet, int &nRequiredRet);

    /**
     * Generate a Bitcoin scriptPubKey for the given CTxDestination. Returns a P2PKH
     * script for a CKeyID destination, a P2SH script for a CScriptID, and an empty
     * script for CNoDestination.
     */
    static CScript GetScriptForDestination(const CTxDestination &dest);

    /** Generate a P2PK script for the given pubkey. */
    static CScript GetScriptForRawPubKey(const CPubKey &pubkey);

    /** Generate a multisig script. */
    static CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey> &keys);

    /**
     * Generate a pay-to-witness script for the given redeem script. If the redeem
     * script is P2PK or P2PKH, this returns a P2WPKH script, otherwise it returns a
     * P2WSH script.
     *
     * TODO: replace calls to GetScriptForWitness with GetScriptForDestination using
     * the various witness-specific CTxDestination subtypes.
     */
    static CScript GetScriptForWitness(const CScript &redeemscript);

    /** Check whether a CTxDestination is a CNoDestination. */
    static bool IsValidDestination(const CTxDestination &dest);
};

#endif // BITCOIN_SCRIPT_INTERPRETER_H
