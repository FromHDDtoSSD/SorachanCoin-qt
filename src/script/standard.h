// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_STANDARD_H
#define BITCOIN_SCRIPT_STANDARD_H

#include <stdint.h>
#include <uint256.h>
#include <boost/variant.hpp>
class CKeyID;
class CScriptID;
class CScript;

/*
 * Mandatory script verification flags that all new blocks must comply with for
 * them to be valid. (but old blocks may not comply with) Currently just P2SH,
 * but in the future other flags may be added, such as a soft-fork to enforce
 * strict DER encoding.
 *
 * Failing one of these tests may trigger a DoS ban - see CheckInputs() for
 * details.
 */
struct CNoDestination {
    friend bool operator==(const CNoDestination &a, const CNoDestination &b) { return true; }
    friend bool operator<(const CNoDestination &a, const CNoDestination &b) { return true; }
};

struct WitnessV0ScriptHash : public uint256 {
    WitnessV0ScriptHash() : uint256(0) {}
    explicit WitnessV0ScriptHash(const uint256 &hash) : uint256(hash) {}
    explicit WitnessV0ScriptHash(const CScript &in);
    using uint256::uint256;
};

struct WitnessV0KeyHash : public uint160 {
    WitnessV0KeyHash() : uint160(0) {}
    explicit WitnessV0KeyHash(const uint160 &hash) : uint160(hash) {}
    using uint160::uint160;
};

struct WitnessUnknown { //! CTxDestination subtype to encode any future Witness version
    unsigned int version;
    unsigned int length;
    unsigned char program[40];

    friend bool operator==(const WitnessUnknown &w1, const WitnessUnknown &w2) {
        if (w1.version != w2.version) return false;
        if (w1.length != w2.length) return false;
        return std::equal(w1.program, w1.program + w1.length, w2.program);
    }

    friend bool operator<(const WitnessUnknown &w1, const WitnessUnknown &w2) {
        if (w1.version < w2.version) return true;
        if (w1.version > w2.version) return false;
        if (w1.length < w2.length) return true;
        if (w1.length > w2.length) return false;
        return std::lexicographical_compare(w1.program, w1.program + w1.length, w2.program, w2.program + w2.length);
    }
};

/*
 * A txout script template with a specific destination.
 *  * It is either:
 *  * CNoDestination: no destination set
 *  * CPubKeyVch: TX_PUBKEY destination (P2PK)
 *  * CKeyID: TX_PUBKEYHASH destination (P2PKH)
 *  * CScriptID: TX_SCRIPTHASH destination (P2SH)
 *  * WitnessV0ScriptHash: TX_WITNESS_V0_SCRIPTHASH destination (P2WSH)
 *  * WitnessV0KeyHash: TX_WITNESS_V0_KEYHASH destination (P2WPKH)
 *  * WitnessUnknown: TX_WITNESS_UNKNOWN destination (P2W???)
 *  A CTxDestination is the internal data type encoded in a bitcoin address
  */
using CTxDestination = boost::variant<
                       CNoDestination,
                       CKeyID,
                       CScriptID,
                       WitnessV0ScriptHash,
                       WitnessV0KeyHash,
                       WitnessUnknown>;

namespace Script_param {
    static constexpr bool DEFAULT_ACCEPT_DATACARRIER = true;

    /**
     * Default setting for nMaxDatacarrierBytes. 80 bytes of data, +1 for OP_RETURN,
     * +2 for the pushdata opcodes.
     */
    static constexpr unsigned int MAX_OP_RETURN_RELAY = 83;

    /**
     * A data carrying output is an unspendable output containing data. The script
     * type is designated as TX_NULL_DATA.
     */
    extern bool fAcceptDatacarrier;

    /** Maximum size of TX_NULL_DATA scripts that this node considers standard. */
    extern unsigned nMaxDatacarrierBytes;
}

#endif // BITCOIN_SCRIPT_STANDARD_H
