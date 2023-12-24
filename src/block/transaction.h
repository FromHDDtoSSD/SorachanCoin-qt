// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TRANSACTION_H
#define BITCOIN_TRANSACTION_H

#include <algorithm>
#include <limits>
#include <list>
#include <map>

#include <const/block_params.h>
#include <block/block_info.h>
#include <file_operate/file_open.h>
#include <serialize.h>
#include <timestamps.h>
#include <bignum.h>
#include <sync/lsync.h>
#include <script/script.h>
#include <scrypt.h>
#include <checkqueue.h>
#include <prevector/prevector.h>
#include <block/witness.h>
#include <const/amount.h>
#include <debug/debug.h>

class CWallet;
class CTxDB;
class CScriptCheck;
class COutPoint;
class CTransaction;

static constexpr int SERIALIZE_TRANSACTION_NO_WITNESS = 0x40000000;

namespace block_transaction
{
    constexpr unsigned int DONOT_ACCEPT_BLOCKS_ADMIT_HOURS = 96;
    constexpr unsigned int DONOT_ACCEPT_BLOCKS_ADMIT_HOURS_TESTNET = 75040;

    constexpr unsigned int MAX_ORPHAN_SERIALIZESIZE = 5000; // send-big-orphans memory exhaustion attack. 10,000 orphans, each of which is at most 5,000 bytes big is at most 500 megabytes of orphans

    namespace testnet {
        const int nCoinbaseMaturity = 6;
    }
    namespace mainnet {
        const int nCoinbaseMaturity = 15;
    }
    extern int nCoinbaseMaturity;// = mainnet::nCoinbaseMaturity;

    template <typename T>
    class manage_impl : private no_instance
    {
    private:
        static CBlockIndex *pblockindexFBBHLast;
    public:
        static void setnull_pblockindexFBBHLast() { pblockindexFBBHLast = nullptr; } // New Block
        static bool GetTransaction(const T &hash, CTransaction &tx, T &hashBlock);
        static CBlockIndex *FindBlockByHeight(int nHeight);
        static bool MoneyRange(int64_t nValue) {
            return (nValue >= 0 && nValue <= block_params::MAX_MONEY);
        }
    };
    using manage = manage_impl<uint256>;
}

namespace tx_util {
    static inline std::string EncodeHexTx(const CTransaction &tx) {
        CDataStream ssTx;
        ssTx << tx;
        return util::HexStr(ssTx.begin(), ssTx.end());
    }
}

// An inpoint - a combination of a transaction and an index n into its vin
class CInPoint
{
    //CInPoint(const CInPoint &)=delete;
    //CInPoint(CInPoint &&)=delete;
    //CInPoint &operator=(const CInPoint &)=delete;
    //CInPoint &operator=(CInPoint &&)=delete;
private:
    CTransaction *ptx;
    uint32_t n;
public:
    const CTransaction *get_ptx() const {return ptx;}
    CTransaction *get_ptx() {return ptx;}
    uint32_t get_n() const {return n;}

    CInPoint() {
        SetNull();
    }
    CInPoint(CTransaction *ptxIn, unsigned int nIn) {
        ptx = ptxIn;
        n = nIn;
    }

    void SetNull() {
        ptx = nullptr;
        n = std::numeric_limits<uint32_t>::max();
    }
    bool IsNull() const {
        return (ptx == nullptr && n == std::numeric_limits<uint32_t>::max());
    }
};

// An outpoint - a combination of a transaction hash and an index n into its vout
class COutPoint
{
    //COutPoint(const COutPoint &)=delete;
    //COutPoint(COutPoint &)=delete;
    //COutPoint &operator=(const COutPoint &)=delete;
    //COutPoint &operator=(COutPoint &&)=delete;
private:
    uint256 hash;
    uint32_t n;
public:
    uint32_t get_n() const {return n;}
    const uint256 &get_hash() const {return hash;}

    COutPoint() {
        SetNull();
    }
    COutPoint(uint256 hashIn, unsigned int nIn) {
        hash = hashIn;
        n = nIn;
    }
    void SetNull() {
        hash = 0;
        n = std::numeric_limits<uint32_t>::max();
    }
    bool IsNull() const {
        return (hash == 0 && n == std::numeric_limits<uint32_t>::max());
    }

    friend bool operator<(const COutPoint &a, const COutPoint &b) {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }
    friend bool operator==(const COutPoint &a, const COutPoint &b) {
        return (a.hash == b.hash && a.n == b.n);
    }
    friend bool operator!=(const COutPoint &a, const COutPoint &b) {
        return !(a == b);
    }

    std::string ToString() const;
    void print() const {
        logging::LogPrintf("%s\n", ToString().c_str());
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(FLATDATA(*this));
    }
};

// Position on disk for a particular transaction
class CDiskTxPos
{
    //CDiskTxPos(const CDiskTxPos &)=delete;
    //CDiskTxPos(CDiskTxPos &)=delete;
    //CDiskTxPos &operator=(const CDiskTxPos &)=delete;
    //CDiskTxPos &operator=(CDiskTxPos &&)=delete;
private:
    uint32_t nFile;
    uint32_t nBlockPos;
    uint32_t nTxPos;
public:
    uint32_t get_nFile() const {return nFile;}
    uint32_t get_nBlockPos() const {return nBlockPos;}
    uint32_t get_nTxPos() const {return nTxPos;}

    CDiskTxPos() {
        SetNull();
    }
    CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn, unsigned int nTxPosIn) {
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nTxPos = nTxPosIn;
    }

    void SetNull() {
        nFile = std::numeric_limits<uint32_t>::max();
        nBlockPos = 0;
        nTxPos = 0;
    }
    bool IsNull() const {
        return (nFile == std::numeric_limits<uint32_t>::max());
    }

    friend bool operator==(const CDiskTxPos &a, const CDiskTxPos &b) {
        return (a.nFile     == b.nFile &&
                a.nBlockPos == b.nBlockPos &&
                a.nTxPos    == b.nTxPos);
    }
    friend bool operator!=(const CDiskTxPos &a, const CDiskTxPos &b) {
        return !(a == b);
    }

    std::string ToString() const;
    void print() const {
        logging::LogPrintf("%s", ToString().c_str());
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(FLATDATA(*this));
    }
};

// A txdb record that contains the disk location of a transaction and the locations of transactions that spend its outputs.
// vSpent is really only used as a flag, but having the location is very helpful for debugging.
class CTxIndex
{
    //CTxIndex(const CTxIndex &)=delete;
    //CTxIndex(CTxIndex &)=delete;
    //CTxIndex &operator=(const CTxIndex &)=delete;
    //CTxIndex &operator=(CTxIndex &)=delete;
private:
    CDiskTxPos pos;
    std::vector<CDiskTxPos> vSpent;
public:
    const CDiskTxPos &get_pos() const {return pos;}
    const std::vector<CDiskTxPos> &get_vSpent() const {return vSpent;}
    const CDiskTxPos &get_vSpent(int index) const {return vSpent[index];}

    std::vector<CDiskTxPos> &set_vSpent() {return vSpent;}
    CDiskTxPos &set_vSpent(int index) {return vSpent[index];}

    CTxIndex() {
        SetNull();
    }

    CTxIndex(const CDiskTxPos &posIn, unsigned int nOutputs) {
        pos = posIn;
        vSpent.resize(nOutputs);
    }

    void SetNull() {
        pos.SetNull();
        vSpent.clear();
    }

    bool IsNull() const {
        return pos.IsNull();
    }

    friend bool operator==(const CTxIndex &a, const CTxIndex &b) {
        return (a.pos    == b.pos &&
                a.vSpent == b.vSpent);
    }
    friend bool operator!=(const CTxIndex &a, const CTxIndex &b) {
        return !(a == b);
    }

    int GetDepthInMainChain() const;

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        int nVersion = 0;
        READWRITE(nVersion); // new core takes over old core in the nVersion (unused).

        READWRITE(this->pos);
        READWRITE(this->vSpent);
    }
};

// CTransaction IN
// An input of a transaction.  It contains the location of the previous
// transaction's output that it claims and a signature that matches the output's public key.
class CTxIn
{
    //CTxIn(const CTxIn &)=delete;
    //CTxIn(CTxIn &)=delete;
    //CTxIn &operator=(const CTxIn &)=delete;
    //CTxIn &operator=(CTxIn &&)=delete;
public:
    /* Setting nSequence to this value for every input in a transaction
     * disables nLockTime. */
    static constexpr uint32_t SEQUENCE_FINAL = 0xffffffff;

    /* Below flags apply in the context of BIP 68*/
    /* If this flag set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time. */
    static constexpr uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1U << 31);

    /* If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    static constexpr uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /* If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    static constexpr uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /* In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static constexpr int SEQUENCE_LOCKTIME_GRANULARITY = 9;

private:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;
    CScriptWitness scriptWitness; //!< Only serialized through CTransaction

public:
    const COutPoint &get_prevout() const {return prevout;}
    const CScript &get_scriptSig() const {return scriptSig;}
    uint32_t get_nSequence() const {return nSequence;}
    const CScriptWitness &get_scriptWitness() const {return scriptWitness;}

    COutPoint &set_prevout() {return prevout;}
    CScript &set_scriptSig() {return scriptSig;}
    void set_nSequence(uint32_t _seq) {nSequence = _seq;}
    void set_scriptSig(const CScript &_sig) {scriptSig = _sig;}
    CScriptWitness &set_scriptWitness() {return scriptWitness;}

    // script <valtype>
    template <typename valtype>
    CTxIn &operator<<(const valtype &_obj) {
        scriptSig << _obj;
        return *this;
    }

    CTxIn() {
        //nSequence = std::numeric_limits<unsigned int>::max();
        nSequence = SEQUENCE_FINAL;
    }
    //explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=std::numeric_limits<unsigned int>::max()) {
    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=SEQUENCE_FINAL) {
        prevout = prevoutIn;
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }
    //CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=std::numeric_limits<unsigned int>::max()) {
    CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=SEQUENCE_FINAL) {
        prevout = COutPoint(hashPrevTx, nOut);
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    bool IsFinal() const {
        //return (nSequence == std::numeric_limits<unsigned int>::max());
        return (nSequence == SEQUENCE_FINAL);
    }

    friend bool operator==(const CTxIn &a, const CTxIn &b) {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }
    friend bool operator!=(const CTxIn &a, const CTxIn &b) {
        return !(a == b);
    }

    std::string ToStringShort() const;
    std::string ToString() const;
    void print() const {
        logging::LogPrintf("%s\n", ToString().c_str());
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(this->prevout);
        READWRITE(this->scriptSig);
        READWRITE(this->nSequence);
    }
};

// CTransaction OUT
// An output of a transaction. It contains the public key that the next input must be able to sign with to claim it.
class CTxOut
{
    //CTxOut(const CTxOut &)=delete;
    //CTxOut(CTxOut &&)=delete;
    //CTxOut &operator=(const CTxOut &)=delete;
    //CTxOut &operator=(CTxOut &&)=delete;
private:
    int64_t nValue; // amount
    CScript scriptPubKey;

public:
    int64_t get_nValue() const {return nValue;}
    const CScript &get_scriptPubKey() const {return scriptPubKey;}

    void set_nValue(int64_t _InValue) {assert(_InValue >= 0); nValue = _InValue;}
    void add_nValue(int64_t _InValue) {assert(! IsNull()); nValue += _InValue;}
    void sub_nValue(int64_t _InValue) {nValue -= _InValue; assert(nValue >= 0);}
    CScript &set_scriptPubKey() {return scriptPubKey;}

    CTxOut() {
        SetNull();
    }
    CTxOut(int64_t nValueIn, CScript scriptPubKeyIn) {
        nValue = nValueIn;
        scriptPubKey = scriptPubKeyIn;
    }

    void SetNull() {
        nValue = -1;
        scriptPubKey.clear();
    }
    bool IsNull() const {
        return (this->nValue == -1);
    }
    void SetEmpty() {
        nValue = 0;
        scriptPubKey.clear();
    }
    bool IsEmpty() const {
        return (nValue == 0 && scriptPubKey.empty());
    }
    uint256 GetHash() const {
        return hash_basis::SerializeHash(*this);
    }

    bool IsZerocoinMint() const {
        return !scriptPubKey.empty() && scriptPubKey.IsZerocoinMint();
    }

    friend bool operator==(const CTxOut &a, const CTxOut &b) {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }
    friend bool operator!=(const CTxOut &a, const CTxOut &b) {
        return !(a == b);
    }

    std::string ToStringShort() const;
    std::string ToString() const;
    void print() const {
        logging::LogPrintf("%s\n", ToString().c_str());
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(this->nValue);
        READWRITE(this->scriptPubKey);
    }
};

struct CMutableTransaction;

/**
 * Basic transaction serialization format:
 * - int32_t nVersion
 * - if (CURRENT_VERSION == 1)
 *   - uint32_t nTime
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 *
 * Extended transaction serialization format:
 * - int32_t nVersion
 * - if (CURRENT_VERSION == 1)
 *   - uint32_t nTime
 * - unsigned char dummy = 0x00
 * - unsigned char flags (!= 0)
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - if (flags & 1):
 *   - CTxWitness wit;
 * - uint32_t nLockTime
 */
template<typename Stream, typename TxType>
inline void UnserializeTransaction(TxType &tx, Stream &s) {
    s >> tx.set_nVersion();
    const bool fAllowWitness = (tx.get_nVersion() >= 2) && (!(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS));

    if(tx.get_nVersion() == 1)
        s >> tx.set_nTime();
    unsigned char flags = 0;
    tx.set_vin().clear();
    tx.set_vout().clear();
    /* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
    s >> tx.set_vin();
    if (tx.get_vin().size() == 0 && fAllowWitness) {
        /* We read a dummy or an empty vin. */
        s >> flags;
        if (flags != 0) {
            s >> tx.set_vin();
            s >> tx.set_vout();
        }
    } else {
        /* We read a non-empty vin. Assume a normal vout follows. */
        s >> tx.set_vout();
    }
    if ((flags & 1) && fAllowWitness) {
        /* The witness flag is present, and we support witnesses. */
        flags ^= 1;
        for (size_t i = 0; i < tx.get_vin().size(); i++) {
            s >> tx.set_vin(i).set_scriptWitness().stack; // todo: std::vector<std::vector<unsigned char> >
        }
        if (! tx.HasWitness()) {
            /* It's illegal to encode witnesses when all witness stacks are empty. */
            throw std::ios_base::failure("Superfluous witness record");
        }
    }
    if (flags) {
        /* Unknown flag in the serialization */
        throw std::ios_base::failure("Unknown transaction optional data");
    }
    s >> tx.set_nLockTime();
}

template<typename Stream, typename TxType>
inline void SerializeTransaction(const TxType &tx, Stream &s) {
    const bool fAllowWitness = (tx.get_nVersion() >= 2) && (!(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS));

    s << tx.get_nVersion();
    if(tx.get_nVersion() == 1)
        s << tx.get_nTime();
    unsigned char flags = 0;
    // Consistency check
    if (fAllowWitness) {
        /* Check whether witnesses need to be serialized. */
        if (tx.HasWitness()) {
            flags |= 1;
        }
    }
    if (flags) {
        /* Use extended format in case witnesses are to be serialized. */
        std::vector<CTxIn> vinDummy;
        s << vinDummy;
        s << flags;
    }
    s << tx.get_vin();
    s << tx.get_vout();
    if (flags & 1) {
        for (size_t i = 0; i < tx.get_vin().size(); i++) {
            s << tx.get_vin(i).get_scriptWitness().stack;
        }
    }
    s << tx.get_nLockTime();
}

// The basic transaction that is broadcasted on the network and contained in blocks.
// transaction can contain multiple inputs and outputs.
using MapPrevTx = std::map<uint256, std::pair<CTxIndex, CTransaction> >;
class CTransaction
{
    friend class CMutableTransaction;
    //CTransaction(const CTransaction &)=delete;
    //CTransaction(CTransaction &&)=delete;
    //CTransaction &operator=(const CTransaction &)=delete;
    //CTransaction &operator=(CTransaction &&)=delete;
public:
    enum GetMinFee_mode {
        GMF_BLOCK,
        GMF_RELAY,
        GMF_SEND
    };
protected: // CMerkleTx => CWalletTx
    const CTxOut &GetOutputFor(const CTxIn &input, const MapPrevTx &inputs) const;
private:
    // Default transaction version.
    static constexpr int CURRENT_VERSION = 1;

    // Changing the default transaction version requires a two step process: first
    // adapting relay policy by bumping MAX_STANDARD_VERSION, and then later date
    // bumping the default CURRENT_VERSION at which point both CURRENT_VERSION and
    // MAX_STANDARD_VERSION will be equal.
    static constexpr int32_t MAX_STANDARD_VERSION = 2;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    int nVersion;
    uint32_t nTime;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime;
private:
    /** CURRENT_VERSION == 1: hash */
    mutable uint256 hash_v1;
    /** Memory only. */
    //const uint256 hash;
    //const uint256 m_witness_hash;
    uint256 hash;
    uint256 m_witness_hash;

    uint256 ComputeHash() const;
    uint256 ComputeWitnessHash() const;
public:
    // Denial-of-service detection:
    mutable int nDoS;
    bool DoS(int nDoSIn, bool fIn) const {
        nDoS += nDoSIn;
        return fIn;
    }

    uint32_t get_nTime() const {return nTime;}
    int get_nVersion() const {return nVersion;}
    const std::vector<CTxIn> &get_vin() const {return vin;}
    const CTxIn &get_vin(int index) const {return vin[index];}
    const std::vector<CTxOut> &get_vout() const {return vout;}
    const CTxOut &get_vout(int index) const {return vout[index];}
    uint32_t get_nLockTime() const {return nLockTime;}

    void set_nTime(uint32_t _InTime) {nTime = _InTime;}
    uint32_t &set_nTime() {return nTime;}
    int &set_nVersion() {
        return nVersion;
    }
    std::vector<CTxIn> &set_vin() {return vin;}
    CTxIn &set_vin(int index) {return vin[index];}
    std::vector<CTxOut> &set_vout() {return vout;}
    CTxOut &set_vout(int index) {return vout[index];}
    uint32_t &set_nLockTime() {return nLockTime;}

    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction() : hash{}, m_witness_hash{} {
        SetNull();
    }

    virtual ~CTransaction() {}

    void SetNull() {
        nVersion = CTransaction::CURRENT_VERSION;
        nTime = (uint32_t)bitsystem::GetAdjustedTime();
        vin.clear();
        vout.clear();
        hash_v1 = uint256(0);
        nLockTime = 0;
        nDoS = 0;  // Denial-of-service prevention
    }
    bool IsNull() const {
        return (vin.empty() && vout.empty());
    }
    //uint256 GetHash() const {
    //    return hash_basis::SerializeHash(*this);
    //}

    // Compute priority, given priority of inputs and (optionally) tx size
    double ComputePriority(double dPriorityInputs, unsigned int nTxSize=0) const;

    // Compute modified tx size for priority calculation (optionally given tx size)
    unsigned int CalculateModifiedSize(unsigned int nTxSize=0) const;

    bool IsFinal(int nBlockHeight = 0, int64_t nBlockTime = 0) const {
        // Time based nLockTime implemented in 0.1.6
        if (nLockTime == 0) return true;
        if (nBlockHeight == 0)
            nBlockHeight = block_info::nBestHeight;
        if (nBlockTime == 0)
            nBlockTime = bitsystem::GetAdjustedTime();
        if ((int64_t)nLockTime < ((int64_t)nLockTime < block_params::LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
            return true;
        for(const CTxIn &txin: this->vin) {
            if (! txin.IsFinal()) return false;
        }
        return true;
    }
    bool IsNewerThan(const CTransaction &old) const {
        if (vin.size() != old.vin.size()) return false;
        for (unsigned int i = 0; i < vin.size(); ++i) {
            if (vin[i].get_prevout() != old.vin[i].get_prevout()) return false;
        }

        bool fNewer = false;
        unsigned int nLowest = std::numeric_limits<unsigned int>::max();
        for (unsigned int i = 0; i < vin.size(); ++i) {
            if (vin[i].get_nSequence() != old.vin[i].get_nSequence()) {
                if (vin[i].get_nSequence() <= nLowest) {
                    fNewer = false;
                    nLowest = vin[i].get_nSequence();
                }
                if (old.vin[i].get_nSequence() < nLowest) {
                    fNewer = true;
                    nLowest = old.vin[i].get_nSequence();
                }
            }
        }
        return fNewer;
    }

    bool IsCoinBase() const {
        return (vin.size() == 1 && vin[0].get_prevout().IsNull() && vout.size() >= 1);
    }
    bool IsCoinStake() const { // ppcoin: the coin stake transaction is marked with the first output empty
        return (vin.size() > 0 && (!vin[0].get_prevout().IsNull()) && vout.size() >= 2 && vout[0].IsEmpty());
    }

    bool IsCoinBench() const {
        return (vin.size() > 1 && (!vin[0].get_prevout().IsNull()) && (!vin[1].get_prevout().IsNull()) && vout.size() >= 3 && vout[0].IsEmpty() && vout[1].IsEmpty());
    }
    bool IsCoinMasternode() const {
        return (vin.size() > 2 && (!vin[0].get_prevout().IsNull()) && (!vin[1].get_prevout().IsNull()) && (!vin[2].get_prevout().IsNull()) && vout.size() >= 4 && vout[0].IsEmpty() && vout[1].IsEmpty() && vout[2].IsEmpty());
    }

    bool IsZerocoinSpend() const {
        return (vin.size() > 0 && vin[0].get_prevout().IsNull() && vin[0].get_scriptSig()[0] == ScriptOpcodes::OP_ZEROCOINSPEND);
    }
    bool IsZerocoinMint() const {
        for(const CTxOut &txout : vout) {
            if (txout.get_scriptPubKey().IsZerocoinMint())
                return true;
        }
        return false;
    }
    bool ContainsZerocoins() const {
        return IsZerocoinSpend() || IsZerocoinMint();
    }
    CAmount GetZerocoinMinted() const;
    CAmount GetZerocoinSpent() const;
    int GetZerocoinMintCount() const;

    // Check for standard transaction types
    // @return True if all outputs (scriptPubKeys) use only standard transaction forms
    bool IsStandard(std::string &strReason) const;
    bool IsStandard() const;

    // [1] Check for standard transaction types
    //    @param[in] mapInputs Map of previous transactions that have outputs we're spending
    //    @return True if all inputs (scriptSigs) use only standard transaction forms
    //    @see CTransaction::FetchInputs
    bool AreInputsStandard(const MapPrevTx &mapInputs) const;

    // [2] Count ECDSA signature operations the old-fashioned (pre-0.6) way
    //    @return number of sigops this transaction's outputs will produce when spent
    //    @see CTransaction::FetchInputs
    unsigned int GetLegacySigOpCount() const;

    // [3] Count ECDSA signature operations in pay-to-script-hash inputs.
    //    @param[in] mapInputs    Map of previous transactions that have outputs we're spending
    //    @return maximum number of sigops required to validate this transaction's inputs
    //    @see CTransaction::FetchInputs
    unsigned int GetP2SHSigOpCount(const MapPrevTx &mapInputs) const;

    // [A] Amount of bitcoins spent by this transaction.
    //    @return sum of all outputs (note: does not include fees)
    int64_t GetValueOut() const;

    // [B] Amount of bitcoins coming in to this transaction
    //    Note that lightweight clients may not know anything besides the hash of previous transactions,
    //    so may not be able to calculate this.
    //    @param[in] mapInputs    Map of previous transactions that have outputs we're spending
    //    @return    Sum of value of all inputs (scriptSigs)
    //    @see CTransaction::FetchInputs
    int64_t GetValueIn(const MapPrevTx &mapInputs) const;

    // [C] Fee of this transaction
    static bool AllowFree(double dPriority);
    int64_t GetMinFee(unsigned int nBlockSize=1, bool fAllowFree=false, enum GetMinFee_mode mode=GMF_BLOCK, unsigned int nBytes = 0) const;

    friend bool operator==(const CTransaction &a, const CTransaction &b) {
        return (a.nVersion  == b.nVersion &&
                a.nTime     == b.nTime &&
                a.vin       == b.vin &&
                a.vout      == b.vout &&
                a.nLockTime == b.nLockTime);
    }
    friend bool operator!=(const CTransaction &a, const CTransaction &b) {
        return !(a == b);
    }

    std::string ToStringShort() const;
    std::string ToString() const;
    void print() const {
        logging::LogPrintf("%s", ToString().c_str());
    }

#ifdef VSTREAM_INMEMORY_MODE
    bool ReadFromDisk(CDiskTxPos pos);
    bool ReadFromVStream(CDiskTxPos pos, vstream **pfileRet);
#else
    bool ReadFromDisk(CDiskTxPos pos, FILE **pfileRet=nullptr);
#endif
    bool ReadFromDisk(CTxDB &txdb, COutPoint prevout, CTxIndex &txindexRet);
    bool ReadFromDisk(CTxDB &txdb, COutPoint prevout);
    bool ReadFromDisk(COutPoint prevout);
    bool DisconnectInputs(CTxDB &txdb);

    /** Fetch from memory and/or disk. inputsRet keys are transaction hashes.
     @param[in] txdb    Transaction database
     @param[in] mapTestPool    List of pending changes to the transaction index database
     @param[in] fBlock    True if being called to add a new best-block to the chain
     @param[in] fMiner    True if being called by miner::CreateNewBlock
     @param[out] inputsRet    Pointers to this transaction's inputs
     @param[out] fInvalid    returns true if transaction is invalid
     @return    Returns true if all inputs are in txdb or mapTestPool
     */
    bool FetchInputs(CTxDB &txdb, const std::map<uint256, CTxIndex> &mapTestPool, bool fBlock, bool fMiner, MapPrevTx &inputsRet, bool &fInvalid);

    /** Sanity check previous transactions, then, if all checks succeed,
        mark them as spent by this transaction.
        @param[in] inputs    Previous transactions (from FetchInputs)
        @param[out] mapTestPool    Keeps track of inputs that need to be updated on disk
        @param[in] posThisTx    Position of this transaction on disk
        @param[in] pindexBlock
        @param[in] fBlock    true if called from ConnectBlock
        @param[in] fMiner    true if called from miner::CreateNewBlock
        @param[in] fScriptChecks    enable scripts validation?
        @param[in] flags    Script_param::STRICT_FLAGS script validation flags
        @param[in] pvChecks    NULL If pvChecks is not NULL, script checks are pushed onto it instead of being performed inline.
        @return Returns true if all checks succeed
     */
    bool ConnectInputs(CTxDB &txdb, MapPrevTx inputs, std::map<uint256, CTxIndex> &mapTestPool, const CDiskTxPos &posThisTx, const CBlockIndex *pindexBlock, bool fBlock, bool fMiner, bool fScriptChecks=true, unsigned int flags=Script_param::STRICT_FLAGS, std::vector<CScriptCheck> *pvChecks = nullptr);

    bool ClientConnectInputs();
    bool CheckTransaction() const;
    bool AcceptToMemoryPool(CTxDB &txdb, bool fCheckInputs=true, bool *pfMissingInputs=nullptr);
    bool GetCoinAge(CTxDB &txdb, uint64_t &nCoinAge) const;  // ppcoin: get transaction coin age

    // witness(Segwit) programs
    /** Convert a CMutableTransaction into a CTransaction. */
    explicit CTransaction(const CMutableTransaction &tx);
    CTransaction(CMutableTransaction &&tx);

    /** This deserializing constructor is provided instead of an Unserialize method.
     *  Unserialize is not possible, since it would require overwriting const fields. */
    template <typename Stream>
    CTransaction(deserialize_type, Stream &s) : CTransaction(CMutableTransaction(deserialize, s)) {}

    const uint256 &GetHash() const {
        if(CTransaction::CURRENT_VERSION == 1) {
            hash_v1 = hash_basis::SerializeHash(*this);
            return hash_v1;
        } else if (CTransaction::CURRENT_VERSION == 2) {
            return hash;
        } else {
            assert(!"Error: CTransaction::CURRENT_VERSION is no setting.");
            hash_v1 = hash_basis::SerializeHash(*this);
            return hash_v1;
        }
    }
    const uint256 &GetWitnessHash() const { return m_witness_hash; }

    bool HasWitness() const {
        for (size_t i = 0; i < vin.size(); i++) {
            if (! vin[i].get_scriptWitness().IsNull()) {
                return true;
            }
        }
        return false;
    }

    // CURRENT_VERSION==1 serialize methods
    size_t GetSerializeSize() const {
        if(this->nVersion == 1) {
            size_t size = 0;
            size += ::GetSerializeSize(this->nVersion);
            size += ::GetSerializeSize(this->nTime);
            size += ::GetSerializeSize(this->vin);
            size += ::GetSerializeSize(this->vout);
            size += ::GetSerializeSize(this->nLockTime);
            return size;
        } else {
            assert(!"Only using CTransaction::GetSerializeSize is (nVersion == 1)");
            throw std::runtime_error("Only using CTransaction::GetSerializeSize is (nVersion == 1)");

            size_t size = 0;
            size += ::GetSerializeSize(this->nVersion);
            size += ::GetSerializeSize(this->vin);
            size += ::GetSerializeSize(this->vout);
            size += ::GetSerializeSize(this->nLockTime);
            return size;
        }
    }

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
        if(this->nVersion == 1 || this->nVersion == 2) {
            if(this->nVersion == 2) {
                debugcs::instance() << "CTransaction nVersion: " << this->nVersion << debugcs::endl();
            }
            READWRITE(this->nVersion);
            READWRITE(this->nTime);
            READWRITE(this->vin);
            READWRITE(this->vout);
            READWRITE(this->nLockTime);
        } else {
            debugcs::instance() << "CTransaction nVersion: " << this->nVersion << debugcs::endl();
            assert(!"Only using CTransaction::Unserialize is (2 < nVersion)");
            READWRITE(this->nVersion);
            READWRITE(this->vin);
            READWRITE(this->vout);
            READWRITE(this->nLockTime);
        }
    }
};

// Transaction Memory Pool
// Singleton Class
class CTxMemPool
{
    CTxMemPool(const CTxMemPool &)=delete;
    CTxMemPool(CTxMemPool &&)=delete;
    CTxMemPool &operator=(const CTxMemPool &)=delete;
    CTxMemPool &operator=(CTxMemPool &&)=delete;
private:
    CTxMemPool() {
        nTransactionsUpdated = 0;
    }
    mutable CCriticalSection cs;
    mutable std::map<uint256, CTransaction> mapTx; // mutable: operator []
    std::map<COutPoint, CInPoint> mapNextTx;
    unsigned int nTransactionsUpdated;
public:
    static CTxMemPool mempool;
    CCriticalSection &get_cs() const {return cs;}
    const std::map<uint256, CTransaction> &get_mapTx() const {return mapTx;}
    const CTransaction &get_mapTx(uint256 hash) const {return mapTx[hash];}

    std::map<uint256, CTransaction> &set_mapTx() {return mapTx;}

    bool accept(CTxDB &txdb, CTransaction &tx, bool fCheckInputs, bool *pfMissingInputs);
    bool addUnchecked(const uint256 &hash, CTransaction &tx);
    bool remove(CTransaction &tx);
    void clear();
    void queryHashes(std::vector<uint256> &vtxid);
    bool IsFromMe(CTransaction &tx);
    void EraseFromWallets(uint256 hash);
    size_t size() const {
        LOCK(cs);
        return mapTx.size();
    }
    bool exists(uint256 hash) const {
        return (mapTx.count(hash) != 0);
    }
    CTransaction &lookup(uint256 hash) {
        return mapTx[hash];
    }

    unsigned int GetTransactionsUpdated() const {
        LOCK(cs);
        return nTransactionsUpdated;
    }
    void AddTransactionsUpdated(unsigned int n) {
        LOCK(cs);
        nTransactionsUpdated += n;
    }
};

// Closure representing one script verification
// Note that this stores references to the spending transaction
class CScriptCheck
{
    //CScriptCheck(const CScriptCheck &)=delete;
    //CScriptCheck(CScriptCheck &)=delete;
    //CScriptCheck &operator=(const CScriptCheck &)=delete;
    //CScriptCheck &operator=(CScriptCheck &&)=delete;
public:
    CScriptCheck() {}
    CScriptCheck(const CTransaction &txFromIn, const CTransaction &txToIn, unsigned int nInIn, unsigned int nFlagsIn, int nHashTypeIn) :
    scriptPubKey(txFromIn.get_vout(txToIn.get_vin(nInIn).get_prevout().get_n()).get_scriptPubKey()), ptxTo(&txToIn), nIn(nInIn), nFlags(nFlagsIn), nHashType(nHashTypeIn) {}

    bool operator()() const;
    void swap(CScriptCheck &check) { // swap from this to check
        scriptPubKey.swap(check.scriptPubKey);
        std::swap(ptxTo, check.ptxTo);
        std::swap(nIn, check.nIn);
        std::swap(nFlags, check.nFlags);
        std::swap(nHashType, check.nHashType);
    }

private:
    CScript scriptPubKey;
    const CTransaction *ptxTo;
    unsigned int nIn;
    unsigned int nFlags;
    int nHashType;
};

/** A mutable version of CTransaction. */
struct CMutableTransaction {
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    int32_t nVersion;
    uint32_t nLockTime;

    CMutableTransaction();
    explicit CMutableTransaction(const CTransaction &tx);

    template <typename Stream>
    inline void Serialize(Stream &s) const {
        ::SerializeTransaction(*this, s);
    }

    template <typename Stream>
    inline void Unserialize(Stream &s) {
        ::UnserializeTransaction(*this, s);
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream &s) {
        this->Unserialize(s);
    }

    // Compute the hash of this CMutableTransaction. This is computed on the
    // fly, as opposed to GetHash() in CTransaction, which uses a cached result.
    uint256 GetHash() const;

    bool HasWitness() const {
        for (size_t i = 0; i < vin.size(); i++) {
            if (! vin[i].get_scriptWitness().IsNull()) {
                return true;
            }
        }
        return false;
    }

    // same CTransaction methods
    int32_t get_nVersion() const {return nVersion;}
    uint32_t get_nTime() const {
        assert(!"CMutableTransaction no member nTime.");
        return 0;
    }
    const std::vector<CTxIn> &get_vin() const {return vin;}
    const std::vector<CTxOut> &get_vout() const {return vout;}
    const CTxIn &get_vin(size_t index) const {return vin[index];}
    uint32_t get_nLockTime() const {return nLockTime;}
};

#endif // BITCOIN_TRANSACTION_H
