// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TRANSACTION_H
#define BITCOIN_TRANSACTION_H

#include <algorithm>
#include <limits>
#include <list>
#include <map>

#include <const/block_param.h>
#include <block/block_info.h>
#include <file_operate/file_open.h>
#include <serialize.h>
#include <timestamps.h>
#include <bignum.h>
#include <sync/sync.h>
#include <script.h>
#include <scrypt.h>
#include <checkqueue.h>
#include <prevector/prevector.h>
#include <debug/debug.h>

class CWallet;
class CTxDB;
class CScriptCheck;
template <typename T> class COutPoint_impl;
using COutPoint = COutPoint_impl<uint256>;

namespace block_transaction
{
    const unsigned int DONOT_ACCEPT_BLOCKS_ADMIT_HOURS = 36;
    const unsigned int DONOT_ACCEPT_BLOCKS_ADMIT_HOURS_TESTNET = 168;

    const unsigned int MAX_ORPHAN_SERIALIZESIZE = 5000; // send-big-orphans memory exhaustion attack. 10,000 orphans, each of which is at most 5,000 bytes big is at most 500 megabytes of orphans

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
        static bool GetTransaction(const T &hash, CTransaction_impl<T> &tx, T &hashBlock);
        static CBlockIndex *FindBlockByHeight(int nHeight);
        static bool MoneyRange(int64_t nValue) noexcept {
            return (nValue >= 0 && nValue <= block_param::MAX_MONEY);
        }
    };
    using manage = manage_impl<uint256>;
}

// An inpoint - a combination of a transaction and an index n into its vin
template <typename T>
class CInPoint_impl
{
private:
    CInPoint_impl(const CInPoint_impl &)=delete;
    // CInPoint_impl &operator=(const CInPoint_impl &)=delete;
    // CInPoint_impl &operator=(const CInPoint_impl &&)=delete;
public:
    CTransaction_impl<T> *ptx;
    uint32_t n;

    CInPoint_impl() {
        SetNull();
    }
    CInPoint_impl(CTransaction_impl<T> *ptxIn, unsigned int nIn) {
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
using CInPoint = CInPoint_impl<uint256>;

// An outpoint - a combination of a transaction hash and an index n into its vout
template <typename T>
class COutPoint_impl
{
//private:
    // COutPoint_impl(const COutPoint_impl &)=delete;
    // COutPoint_impl &operator=(const COutPoint_impl &)=delete;
    // COutPoint_impl &operator=(const COutPoint_impl &&)=delete;
public:
    T hash;
    uint32_t n;

    COutPoint_impl() {
        SetNull();
    }
    COutPoint_impl(T hashIn, unsigned int nIn) {
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

    friend bool operator<(const COutPoint_impl &a, const COutPoint_impl &b) {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }
    friend bool operator==(const COutPoint_impl &a, const COutPoint_impl &b) {
        return (a.hash == b.hash && a.n == b.n);
    }
    friend bool operator!=(const COutPoint_impl &a, const COutPoint_impl &b) {
        return !(a == b);
    }

    std::string ToString() const;
    void print() const {
        printf("%s\n", ToString().c_str());
    }

    IMPLEMENT_SERIALIZE(
        READWRITE(FLATDATA(*this));
    )
};
using COutPoint = COutPoint_impl<uint256>;

// Position on disk for a particular transaction
class CDiskTxPos
{
//private:
    // CDiskTxPos(const CDiskTxPos &)=delete;
    // CDiskTxPos &operator=(const CDiskTxPos &)=delete;
    // CDiskTxPos &operator=(const CDiskTxPos &&)=delete;
public:
    uint32_t nFile;
    uint32_t nBlockPos;
    uint32_t nTxPos;

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
        printf("%s", ToString().c_str());
    }

    IMPLEMENT_SERIALIZE(
        READWRITE(FLATDATA(*this));
    )
};

// A txdb record that contains the disk location of a transaction and the locations of transactions that spend its outputs.
// vSpent is really only used as a flag, but having the location is very helpful for debugging.
class CTxIndex
{
//private:
    // CTxIndex(const CTxIndex &)=delete;
    // CTxIndex &operator=(const CTxIndex &)=delete;
    // CTxIndex &operator=(const CTxIndex &)=delete;
public:
    CDiskTxPos pos;
    std::vector<CDiskTxPos> vSpent;

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

    bool IsNull() {
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

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH)) {
            READWRITE(nVersion);
        }
        READWRITE(this->pos);
        READWRITE(this->vSpent);
    )
};

// Transaction Memory Pool
// Singleton Class
template <typename T>
class CTxMemPool_impl
{
private:
    CTxMemPool_impl() {}
    CTxMemPool_impl(const CTxMemPool_impl &)=delete;
    CTxMemPool_impl &operator=(const CTxMemPool_impl &)=delete;
    CTxMemPool_impl &operator=(const CTxMemPool_impl &&)=delete;
public:
    static CTxMemPool_impl mempool;
    mutable CCriticalSection cs;
    std::map<T, CTransaction_impl<T> > mapTx;
    std::map<COutPoint_impl<T>, CInPoint_impl<T> > mapNextTx;

    bool accept(CTxDB &txdb, CTransaction_impl<T> &tx, bool fCheckInputs, bool *pfMissingInputs);
    bool addUnchecked(const T &hash, CTransaction_impl<T> &tx);
    bool remove(CTransaction_impl<T> &tx);
    void clear();
    void queryHashes(std::vector<T> &vtxid);
    bool IsFromMe(CTransaction_impl<T> &tx);
    void EraseFromWallets(T hash);
    size_t size() {
        LOCK(cs);
        return mapTx.size();
    }
    bool exists(T hash) {
        return (mapTx.count(hash) != 0);
    }
    CTransaction &lookup(T hash) {
        return mapTx[hash];
    }
};
using CTxMemPool = CTxMemPool_impl<uint256>;

// CTransaction IN
// An input of a transaction.  It contains the location of the previous
// transaction's output that it claims and a signature that matches the output's public key.
template <typename T>
class CTxIn_impl
{
//private:
    // CTxIn_impl(const CTxIn_impl &)=delete;
    // CTxIn_impl &operator=(const CTxIn_impl &)=delete;
    // CTxIn_impl &operator=(const CTxIn_impl &&)=delete;
public:
    COutPoint_impl<T> prevout;
    CScript scriptSig;
    uint32_t nSequence;

    CTxIn_impl() {
        nSequence = std::numeric_limits<unsigned int>::max();
    }
    explicit CTxIn_impl(COutPoint_impl<T> prevoutIn, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=std::numeric_limits<unsigned int>::max()) {
        prevout = prevoutIn;
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }
    CTxIn_impl(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=std::numeric_limits<unsigned int>::max()) {
        prevout = COutPoint_impl<T>(hashPrevTx, nOut);
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    bool IsFinal() const {
        return (nSequence == std::numeric_limits<unsigned int>::max());
    }

    friend bool operator==(const CTxIn_impl &a, const CTxIn_impl &b) {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }
    friend bool operator!=(const CTxIn_impl &a, const CTxIn_impl &b) {
        return !(a == b);
    }

    std::string ToStringShort() const;
    std::string ToString() const;
    void print() const {
        printf("%s\n", ToString().c_str());
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->prevout);
        READWRITE(this->scriptSig);
        READWRITE(this->nSequence);
    )
};
using CTxIn = CTxIn_impl<uint256>;

// CTransaction OUT
// An output of a transaction. It contains the public key that the next input must be able to sign with to claim it.
template <typename T>
class CTxOut_impl
{
//private:
    // CTxOut_impl(const CTxOut_impl &)=delete;
    // CTxOut_impl &operator=(const CTxOut_impl &)=delete;
    // CTxOut_impl &operator=(const CTxOut_impl &&)=delete;
public:
    int64_t nValue;
    CScript scriptPubKey;

    CTxOut_impl() {
        SetNull();
    }
    CTxOut_impl(int64_t nValueIn, CScript scriptPubKeyIn) {
        nValue = nValueIn;
        scriptPubKey = scriptPubKeyIn;
    }

    void SetNull() {
        nValue = -1;
        scriptPubKey.clear();
    }
    bool IsNull() {
        return (this->nValue == -1);
    }
    void SetEmpty() {
        nValue = 0;
        scriptPubKey.clear();
    }
    bool IsEmpty() const {
        return (nValue == 0 && scriptPubKey.empty());
    }
    T GetHash() const {
        return hash_basis::SerializeHash(*this);
    }

    friend bool operator==(const CTxOut_impl &a, const CTxOut_impl &b) {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }
    friend bool operator!=(const CTxOut_impl &a, const CTxOut_impl &b) {
        return !(a == b);
    }

    std::string ToStringShort() const;
    std::string ToString() const;
    void print() const {
        printf("%s\n", ToString().c_str());
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nValue);
        READWRITE(this->scriptPubKey);
    )
};
using CTxOut = CTxOut_impl<uint256>;

// The basic transaction that is broadcasted on the network and contained in blocks.
// transaction can contain multiple inputs and outputs.
template <typename T> class CTransaction_impl;
using CTransaction = CTransaction_impl<uint256>;
using MapPrevTx = std::map<uint256, std::pair<CTxIndex, CTransaction> >;
template <typename T>
class CTransaction_impl
{
//private:
    // CTransaction_impl(const CTransaction_impl &)=delete;
    // CTransaction_impl &operator=(const CTransaction_impl &)=delete;
    // CTransaction_impl &operator=(const CTransaction_impl &&)=delete;
protected:
    const CTxOut_impl<T> &GetOutputFor(const CTxIn_impl<T> &input, const MapPrevTx &inputs) const;
public:
    enum GetMinFee_mode {
        GMF_BLOCK,
        GMF_RELAY,
        GMF_SEND
    };
public:
    static const int CURRENT_VERSION = 1;
    int nVersion;
    uint32_t nTime;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime;

    // Denial-of-service detection:
    mutable int nDoS;
    bool DoS(int nDoSIn, bool fIn) const {
        nDoS += nDoSIn;
        return fIn;
    }

    CTransaction_impl() {
        SetNull();
    }
    virtual ~CTransaction_impl() {}

    void SetNull() {
        nVersion = CTransaction::CURRENT_VERSION;
        nTime = (uint32_t)bitsystem::GetAdjustedTime();
        vin.clear();
        vout.clear();
        nLockTime = 0;
        nDoS = 0;  // Denial-of-service prevention
    }
    bool IsNull() const {
        return (vin.empty() && vout.empty());
    }
    T GetHash() const {
        return hash_basis::SerializeHash(*this);
    }

    bool IsFinal(int nBlockHeight = 0, int64_t nBlockTime = 0) const {
        // Time based nLockTime implemented in 0.1.6
        if (nLockTime == 0) return true;
        if (nBlockHeight == 0)
            nBlockHeight = block_info::nBestHeight;
        if (nBlockTime == 0)
            nBlockTime = bitsystem::GetAdjustedTime();
        if ((int64_t)nLockTime < ((int64_t)nLockTime < block_param::LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
            return true;
        for(const CTxIn_impl<T> &txin: this->vin) {
            if (! txin.IsFinal()) return false;
        }
        return true;
    }
    bool IsNewerThan(const CTransaction &old) const {
        if (vin.size() != old.vin.size()) return false;
        for (unsigned int i = 0; i < vin.size(); ++i) {
            if (vin[i].prevout != old.vin[i].prevout) return false;
        }

        bool fNewer = false;
        unsigned int nLowest = std::numeric_limits<unsigned int>::max();
        for (unsigned int i = 0; i < vin.size(); ++i) {
            if (vin[i].nSequence != old.vin[i].nSequence) {
                if (vin[i].nSequence <= nLowest) {
                    fNewer = false;
                    nLowest = vin[i].nSequence;
                }
                if (old.vin[i].nSequence < nLowest) {
                    fNewer = true;
                    nLowest = old.vin[i].nSequence;
                }
            }
        }
        return fNewer;
    }

    bool IsCoinBase() const {
        return (vin.size() == 1 && vin[0].prevout.IsNull() && vout.size() >= 1);
    }
    bool IsCoinStake() const { // ppcoin: the coin stake transaction is marked with the first output empty
        return (vin.size() > 0 && (!vin[0].prevout.IsNull()) && vout.size() >= 2 && vout[0].IsEmpty());
    }

    // Check for standard transaction types
    // @return True if all outputs (scriptPubKeys) use only standard transaction forms
    bool IsStandard(std::string &strReason) const;
    bool IsStandard() const;

    // [1] Check for standard transaction types
    //    @param[in] mapInputs Map of previous transactions that have outputs we're spending
    //    @return True if all inputs (scriptSigs) use only standard transaction forms
    //    @see CTransaction_impl<T>::FetchInputs
    bool AreInputsStandard(const MapPrevTx &mapInputs) const;

    // [2] Count ECDSA signature operations the old-fashioned (pre-0.6) way
    //    @return number of sigops this transaction's outputs will produce when spent
    //    @see CTransaction_impl<T>::FetchInputs
    unsigned int GetLegacySigOpCount() const;

    // [3] Count ECDSA signature operations in pay-to-script-hash inputs.
    //    @param[in] mapInputs    Map of previous transactions that have outputs we're spending
    //    @return maximum number of sigops required to validate this transaction's inputs
    //    @see CTransaction_impl<T>::FetchInputs
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

    friend bool operator==(const CTransaction_impl<T> &a, const CTransaction_impl<T> &b) {
        return (a.nVersion  == b.nVersion &&
                a.nTime     == b.nTime &&
                a.vin       == b.vin &&
                a.vout      == b.vout &&
                a.nLockTime == b.nLockTime);
    }
    friend bool operator!=(const CTransaction_impl<T> &a, const CTransaction_impl<T> &b) {
        return !(a == b);
    }

    std::string ToStringShort() const;
    std::string ToString() const;
    void print() const {
        printf("%s", ToString().c_str());
    }

    bool ReadFromDisk(CDiskTxPos pos, FILE **pfileRet=nullptr);
    bool ReadFromDisk(CTxDB &txdb, COutPoint_impl<T> prevout, CTxIndex &txindexRet);
    bool ReadFromDisk(CTxDB &txdb, COutPoint_impl<T> prevout);
    bool ReadFromDisk(COutPoint_impl<T> prevout);
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
    bool FetchInputs(CTxDB &txdb, const std::map<T, CTxIndex> &mapTestPool, bool fBlock, bool fMiner, MapPrevTx &inputsRet, bool &fInvalid);

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
    bool ConnectInputs(CTxDB &txdb, MapPrevTx inputs, std::map<T, CTxIndex> &mapTestPool, const CDiskTxPos &posThisTx, const CBlockIndex *pindexBlock, bool fBlock, bool fMiner, bool fScriptChecks=true, unsigned int flags=Script_param::STRICT_FLAGS, std::vector<CScriptCheck> *pvChecks = nullptr);

    bool ClientConnectInputs();
    bool CheckTransaction() const;
    bool AcceptToMemoryPool(CTxDB &txdb, bool fCheckInputs=true, bool *pfMissingInputs=nullptr);
    bool GetCoinAge(CTxDB &txdb, uint64_t &nCoinAge) const;  // ppcoin: get transaction coin age

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(this->nTime);
        READWRITE(this->vin);
        READWRITE(this->vout);
        READWRITE(this->nLockTime);
    )
};

// Closure representing one script verification
// Note that this stores references to the spending transaction
class CScriptCheck
{
private:
    // CScriptCheck(const CScriptCheck &)=delete;
    // CScriptCheck &operator=(const CScriptCheck &)=delete;
    // CScriptCheck &operator=(const CScriptCheck &&)=delete;

    CScript scriptPubKey;
    const CTransaction *ptxTo;
    unsigned int nIn;
    unsigned int nFlags;
    int nHashType;

public:
    CScriptCheck() {}
    CScriptCheck(const CTransaction& txFromIn, const CTransaction& txToIn, unsigned int nInIn, unsigned int nFlagsIn, int nHashTypeIn) :
    scriptPubKey(txFromIn.vout[txToIn.vin[nInIn].prevout.n].scriptPubKey), ptxTo(&txToIn), nIn(nInIn), nFlags(nFlagsIn), nHashType(nHashTypeIn) {}

    bool operator()() const;
    void swap(CScriptCheck &check) {
        scriptPubKey.swap(check.scriptPubKey);
        std::swap(ptxTo, check.ptxTo);
        std::swap(nIn, check.nIn);
        std::swap(nFlags, check.nFlags);
        std::swap(nHashType, check.nHashType);
    }
};

#endif // BITCOIN_TRANSACTION_H