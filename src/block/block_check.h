// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Copyright (c) 2018-2021 The Sora neko developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_CHECK_H
#define BITCOIN_BLOCK_CHECK_H

#include <util.h>
#include <block/transaction.h>
#include <block/block_keyhasher.h>
#include <unordered_map>

/** Compact serializer for scripts.
 *
 *  It detects common cases and encodes them much more efficiently.
 *  3 special cases are defined:
 *  * Pay to pubkey hash (encoded as 21 bytes)
 *  * Pay to script hash (encoded as 21 bytes)
 *  * Pay to pubkey starting with 0x02, 0x03 or 0x04 (encoded as 33 bytes)
 *
 *  Other scripts up to 121 bytes require 1 byte + script length. Above
 *  that, scripts up to 16505 bytes require 2 bytes + script length.
 */
class CScriptCompressor
{
private:
    /**
     * make this static for now (there are only 6 special scripts defined)
     * this can potentially be extended together with a new nVersion for
     * transactions, in which case this value becomes dependent on nVersion
     * and nHeight of the enclosing transaction.
     */
    static constexpr unsigned int nSpecialScripts = 6;

    CScript &script;

protected:
    /**
     * These check for scripts for which a special case with a shorter encoding is defined.
     * They are implemented separately from the CScript test, as these test for exact byte
     * sequence correspondences, and are more strict. For example, IsToPubKey also verifies
     * whether the public key is valid (as invalid ones cannot be represented in compressed
     * form).
     */
    bool IsToKeyID(CKeyID &hash) const;
    bool IsToScriptID(CScriptID &hash) const;
    bool IsToPubKey(CPubKey &pubkey) const;

    bool Compress(std::vector<unsigned char> &out) const;
    unsigned int GetSpecialSize(unsigned int nSize) const;
    bool Decompress(unsigned int nSize, const std::vector<unsigned char> &out);

public:
    CScriptCompressor(CScript &scriptIn) : script(scriptIn) {}

    unsigned int GetSerializeSize(int nType, int nVersion) const {
        std::vector<unsigned char> compr;
        if (Compress(compr))
            return compr.size();
        unsigned int nSize = script.size() + nSpecialScripts;
        return script.size() + VARUINT(nSize).GetSerializeSize(nType, nVersion);
    }

    template <typename Stream>
    void Serialize(Stream &s, int nType=0, int nVersion=0) const {
        std::vector<unsigned char> compr;
        if (Compress(compr)) {
            //s << CFlatData(compr);
            s << FLATDATA(compr);
            return;
        }
        unsigned int nSize = script.size() + nSpecialScripts;
        s << VARUINT(nSize);
        //s << CFlatData(script);
        s << FLATDATA(script);
    }

    template <typename Stream>
    void Unserialize(Stream &s, int nType=0, int nVersion=0) {
        unsigned int nSize = 0;
        s >> VARUINT(nSize);
        if (nSize < nSpecialScripts) {
            std::vector<unsigned char> vch(GetSpecialSize(nSize), 0x00);
            s >> REF(CFlatData(vch));
            Decompress(nSize, vch);
            return;
        }
        nSize -= nSpecialScripts;
        script.resize(nSize);
        s >> REF(CFlatData(script));
    }
};

/** wrapper for CTxOut that provides a more compact serialization */
class CCompressAmount {
protected:
    static uint64_t CompressAmount(uint64_t nAmount);
    static uint64_t DecompressAmount(uint64_t nAmount);
};

template <typename T>
class CTxOutCompressor_impl : protected CCompressAmount
{
private:
    CTxOut_impl<T> &txout;

public:
    CTxOutCompressor_impl(CTxOut_impl<T> &txoutIn) : txout(txoutIn) {}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action, int nType=0, int nVersion=0) {
        if (! ser_action.ForRead()) {
            uint64_t nVal = CompressAmount(txout.get_nValue());
            READWRITE(VARUINT(nVal));
        } else {
            uint64_t nVal = 0;
            READWRITE(VARUINT(nVal));
            txout.set_nValue(DecompressAmount(nVal));
        }
        CScriptCompressor cscript(REF(txout.get_scriptPubKey()));
        READWRITE(cscript);
    }
};
using CTxOutCompressor = CTxOutCompressor_impl<uint256>;

/** Undo information for a CTxIn
 *
 *  Contains the prevout's CTxOut being spent, and if this was the
 *  last output of the affected transaction, its metadata as well
 *  (coinbase or not, height, transaction version)
 */
template <typename T>
class CTxInUndo_impl
{
public:
    CTxOut_impl<T> txout;   // the txout data before being spent
    bool fCoinBase; // if the outpoint was the last unspent: whether it belonged to a coinbase
    bool fCoinStake;
    bool fCoinPoBench;
    bool fCoinMasternode;
    unsigned int nHeight; // if the outpoint was the last unspent: its height
    int nVersion;         // if the outpoint was the last unspent: its version

    CTxInUndo_impl() : txout(), fCoinBase(false), fCoinStake(false), nHeight(0), nVersion(0) {}
    CTxInUndo_impl(const CTxOut_impl<T> &txoutIn, bool fCoinBaseIn = false, bool fCoinStakeIn = false, bool fCoinPoBenchIn = false, bool fCoinMasternodeIn = false, unsigned int nHeightIn = 0, int nVersionIn = 0) : txout(txoutIn), fCoinBase(fCoinBaseIn), fCoinStake(fCoinStakeIn), fCoinPoBench(fCoinPoBenchIn), fCoinMasternode(fCoinMasternodeIn), nHeight(nHeightIn), nVersion(nVersionIn) {}

    unsigned int GetSerializeSize(int, int) const {
        return ::GetSerializeSize(VARUINT(nHeight * 4 + (fCoinBase ? 2 : 0) + (fCoinStake ? 1 : 0) + (fCoinPoBench ? 16 : 0) + (fCoinMasternode ? 32 : 0))) +
               (nHeight > 0 ? ::GetSerializeSize(VARINT(this->nVersion)) : 0) +
               ::GetSerializeSize(CTxOutCompressor(REF(txout)));
    }

    template <typename Stream>
    void Serialize(Stream &s, int, int) const {
        ::Serialize(s, VARINT(nHeight * 4 + (fCoinBase ? 2 : 0) + (fCoinStake ? 1 : 0)));
        if (nHeight > 0)
            ::Serialize(s, VARINT(this->nVersion));
        ::Serialize(s, CTxOutCompressor(REF(txout)));
    }

    template <typename Stream>
    void Unserialize(Stream &s, int, int) {
        unsigned int nCode = 0;
        ::Unserialize(s, VARUINT(nCode));
        nHeight = nCode >> 2;
        fCoinBase = nCode & 2;
        fCoinStake = nCode & 1;
        fCoinPoBench = nCode & 16;
        fCoinMasternode = nCode & 32;
        if (nHeight > 0)
            ::Unserialize(s, VARINT(this->nVersion));
        ::Unserialize(s, REF(CTxOutCompressor(REF(txout))));
    }
};

/** Undo information for a CTransaction */
template <typename T>
class CTxUndo_impl
{
public:
    // undo information for all txins
    std::vector<CTxInUndo_impl<T>> vprevout;

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action, int, int) {
        READWRITE(vprevout);
    }
};
using CTxUndo = CTxUndo_impl<uint256>;

/**

    ****Note - for MERGE we added fCoinStake to the 2nd bit. Keep in mind when reading the following and adjust as needed.
 * Pruned version of CTransaction: only retains metadata and unspent transaction outputs
 *
 * Serialized format:
 * - VARINT(nVersion)
 * - VARINT(nCode)
 * - unspentness bitvector, for vout[2] and further; least significant byte first
 * - the non-spent CTxOuts (via CTxOutCompressor)
 * - VARINT(nHeight)
 *
 * The nCode value consists of:
 * - bit 1: IsCoinBase()
 * - bit 2: vout[0] is not spent
 * - bit 4: vout[1] is not spent
 * - The higher bits encode N, the number of non-zero bytes in the following bitvector.
 *   - In case both bit 2 and bit 4 are unset, they encode N-1, as there must be at
 *     least one non-spent output).
 *
 * Example: 0104835800816115944e077fe7c803cfa57f29b36bf87c1d358bb85e
 *          <><><--------------------------------------------><---->
 *          |  \                  |                             /
 *    version   code             vout[1]                  height
 *
 *    - version = 1
 *    - code = 4 (vout[1] is not spent, and 0 non-zero bytes of bitvector follow)
 *    - unspentness bitvector: as 0 non-zero bytes follow, it has length 0
 *    - vout[1]: 835800816115944e077fe7c803cfa57f29b36bf87c1d35
 *               * 8358: compact amount representation for 60000000000 (600 BTC)
 *               * 00: special txout type pay-to-pubkey-hash
 *               * 816115944e077fe7c803cfa57f29b36bf87c1d35: address uint160
 *    - height = 203998
 *
 *
 * Example: 0109044086ef97d5790061b01caab50f1b8e9c50a5057eb43c2d9563a4eebbd123008c988f1a4a4de2161e0f50aac7f17e7f9555caa486af3b
 *          <><><--><--------------------------------------------------><----------------------------------------------><---->
 *         /  \   \                     |                                                           |                     /
 *  version  code  unspentness       vout[4]                                                     vout[16]           height
 *
 *  - version = 1
 *  - code = 9 (coinbase, neither vout[0] or vout[1] are unspent, 2 (1, +1 because both bit 2 and bit 4 are unset) non-zero bitvector bytes follow)
 *  - unspentness bitvector: bits 2 (0x04) and 14 (0x4000) are set, so vout[2+2] and vout[14+2] are unspent
 *  - vout[4]: 86ef97d5790061b01caab50f1b8e9c50a5057eb43c2d9563a4ee
 *             * 86ef97d579: compact amount representation for 234925952 (2.35 BTC)
 *             * 00: special txout type pay-to-pubkey-hash
 *             * 61b01caab50f1b8e9c50a5057eb43c2d9563a4ee: address uint160
 *  - vout[16]: bbd123008c988f1a4a4de2161e0f50aac7f17e7f9555caa4
 *              * bbd123: compact amount representation for 110397 (0.001 BTC)
 *              * 00: special txout type pay-to-pubkey-hash
 *              * 8c988f1a4a4de2161e0f50aac7f17e7f9555caa4: address uint160
 *  - height = 120891
 */

template <typename T>
class CCoins_impl
{
public:
    void FromTx(const CTransaction_impl<T> &tx, int nHeightIn);

    //! construct a CCoins from a CTransaction, at a given height
    CCoins_impl(const CTransaction_impl<T> &tx, int nHeightIn) {
        FromTx(tx, nHeightIn);
    }

    void Clear();

    //! empty constructor
    CCoins_impl() : fCoinBase(false), fCoinStake(false), fCoinPoBench(false), fCoinMasternode(false), vout(0), nHeight(0), nVersion(0) {}

    //! remove spent outputs at the end of vout
    void Cleanup();

    //! when OP_RETURN, txout.setNull()
    void ClearUnspendable();

    void swap(CCoins_impl &to) {
        std::swap(to.fCoinBase, fCoinBase);
        std::swap(to.fCoinStake, fCoinStake);
        std::swap(to.fCoinPoBench, fCoinPoBench);
        std::swap(to.fCoinMasternode, fCoinMasternode);
        to.vout.swap(vout);
        std::swap(to.nHeight, nHeight);
        std::swap(to.nVersion, nVersion);
    }

    //! equality test
    friend bool operator==(const CCoins_impl &a, const CCoins_impl &b) {
        // Empty CCoins objects are always equal.
        if (a.IsPruned() && b.IsPruned())
            return true;
        return a.fCoinBase == b.fCoinBase &&
               a.fCoinStake == b.fCoinStake &&
               a.fCoinPoBench == b.fCoinPoBench &&
               a.fCoinMasternode == b.fCoinMasternode &&
               a.nHeight == b.nHeight &&
               a.nVersion == b.nVersion &&
               a.vout == b.vout;
    }
    friend bool operator!=(const CCoins_impl &a, const CCoins_impl &b) {
        return !(a == b);
    }

    void CalcMaskSize(unsigned int &nBytes, unsigned int &nNonzeroBytes) const;

    bool IsCoinBase() const noexcept {
        return fCoinBase;
    }

    bool IsCoinStake() const noexcept {
        return fCoinStake;
    }

    bool IsCoinPoBench() const noexcept {
        return fCoinPoBench;
    }

    bool IsCoinMasternode() const noexcept {
        return fCoinMasternode;
    }

    unsigned int GetSerializeSize(int nType=0, int nVersion=0) {
        unsigned int nSize = 0;
        unsigned int nMaskSize = 0, nMaskCode = 0;
        CalcMaskSize(nMaskSize, nMaskCode);
        bool fFirst = vout.size() > 0 && !vout[0].IsNull();
        bool fSecond = vout.size() > 1 && !vout[1].IsNull();
        assert(fFirst || fSecond || nMaskCode);
        unsigned int nCode = 8 * (nMaskCode - (fFirst || fSecond ? 0 : 1)) + (fCoinBase ? 1 : 0) + (fCoinStake ? 2 : 0) + (fFirst ? 4 : 0) + (fSecond ? 8 : 0) + (fCoinPoBench ? 16 : 0) + (fCoinMasternode ? 32 : 0);
        // version
        nSize += ::GetSerializeSize(VARINT(this->nVersion));
        // size of header code
        nSize += ::GetSerializeSize(VARUINT(nCode));
        // spentness bitmask
        nSize += nMaskSize;
        // txouts themself
        for (unsigned int i = 0; i < vout.size(); i++) {
            if (! vout[i].IsNull())
                nSize += ::GetSerializeSize(CTxOutCompressor(REF(vout[i])));
        }
        // height
        nSize += ::GetSerializeSize(VARINT(nHeight));
        return nSize;
    }

    template <typename Stream>
    void Serialize(Stream &s, int nType=0, int nVersion=0) {
        unsigned int nMaskSize = 0, nMaskCode = 0;
        CalcMaskSize(nMaskSize, nMaskCode);
        bool fFirst = vout.size() > 0 && !vout[0].IsNull();
        bool fSecond = vout.size() > 1 && !vout[1].IsNull();
        assert(fFirst || fSecond || nMaskCode);
        unsigned int nCode = 16 * (nMaskCode - (fFirst || fSecond ? 0 : 1)) + (fCoinBase ? 1 : 0) + (fCoinStake ? 2 : 0) + (fFirst ? 4 : 0) + (fSecond ? 8 : 0) + (fCoinPoBench ? 16 : 0) + (fCoinMasternode ? 32 : 0);
        // version
        ::Serialize(s, VARINT(this->nVersion));
        // header code
        ::Serialize(s, VARUINT(nCode));
        // spentness bitmask
        for (unsigned int b = 0; b < nMaskSize; b++) {
            unsigned char chAvail = 0;
            for (unsigned int i = 0; i < 8 && 2 + b * 8 + i < vout.size(); i++) {
                if (!vout[2 + b * 8 + i].IsNull())
                    chAvail |= (1 << i);
            }
            ::Serialize(s, chAvail);
        }
        // txouts themself
        for (unsigned int i = 0; i < vout.size(); i++) {
            if (! vout[i].IsNull())
                ::Serialize(s, CTxOutCompressor(REF(vout[i])));
        }
        // coinbase height
        ::Serialize(s, VARINT(nHeight));
    }

    template <typename Stream>
    void Unserialize(Stream &s, int nType=0, int nVersion=0)
    {
        unsigned int nCode = 0;
        // version
        ::Unserialize(s, VARINT(this->nVersion));
        // header code
        ::Unserialize(s, VARUINT(nCode));
        fCoinBase = nCode & 1;         //0001 - means coinbase
        fCoinStake = (nCode & 2) != 0; //0010 coinstake
        fCoinPoBench = (nCode & 16) != 0; // 10000 coinpospace
        fCoinMasternode = (nCode & 32) != 0; // 100000 coinmasternode
        std::vector<bool> vAvail(2, false);
        vAvail[0] = (nCode & 4) != 0; // 0100
        vAvail[1] = (nCode & 8) != 0; // 1000
        unsigned int nMaskCode = (nCode / 16) + ((nCode & 12) != 0 ? 0 : 1);
        // spentness bitmask
        while (nMaskCode > 0) {
            unsigned char chAvail = 0;
            ::Unserialize(s, chAvail);
            for (unsigned int p = 0; p < 8; p++) {
                bool f = (chAvail & (1 << p)) != 0;
                vAvail.push_back(f);
            }
            if (chAvail != 0)
                nMaskCode--;
        }
        // txouts themself
        vout.assign(vAvail.size(), CTxOut_impl<T>());
        for (unsigned int i = 0; i < vAvail.size(); i++) {
            if (vAvail[i])
                ::Unserialize(s, REF(CTxOutCompressor_impl<T>(vout[i])));
        }
        // coinbase height
        ::Unserialize(s, VARINT(nHeight));
        Cleanup();
    }

    //! mark an outpoint spent, and construct undo information
    bool Spend(const COutPoint_impl<T> &out, CTxInUndo_impl<T> &undo);

    //! mark a vout spent
    bool Spend(int nPos);

    //! check whether a particular output is still available
    bool IsAvailable(unsigned int nPos) const;

    //! check whether the entire CCoins is spent
    //! note that only !IsPruned() CCoins can be serialized
    bool IsPruned() const;

public:
    //! whether transaction is a coinbase
    bool fCoinBase;
    bool fCoinStake;
    bool fCoinPoBench;
    bool fCoinMasternode;

    //! unspent transaction outputs; spent outputs are .IsNull(); spent outputs at the end of the array are dropped
    std::vector<CTxOut_impl<T>> vout;

    //! at which height this transaction was included in the active block chain
    int nHeight;

    //! version of the CTransaction; accesses to this value should probably check for nHeight as well,
    //! as new tx version will probably only be introduced at certain heights
    int nVersion;
};
using CCoins = CCoins_impl<uint256>;

template <typename T>
struct CCoinsCacheEntry_impl {
    CCoins_impl<T> coins; // The actual cached data.
    unsigned char flags;

    enum Flags {
        DIRTY = (1 << 0), // This cache entry is potentially different from the version in the parent view.
        FRESH = (1 << 1), // The parent view does not have this entry (or it is pruned).
    };

    CCoinsCacheEntry_impl() : coins(), flags(0) {}
};
using CCoinsCacheEntry = CCoinsCacheEntry_impl<uint256>;

using CCoinsMap = std::unordered_map<uint256b, CCoinsCacheEntry, CCoinsKeyHasher>;

struct CCoinsStats {
    int nHeight;
    uint256 hashBlock;
    uint64_t nTransactions;
    uint64_t nTransactionOutputs;
    uint64_t nSerializedSize;
    uint256 hashSerialized;
    CAmount nTotalAmount;

    CCoinsStats() : nHeight(0), hashBlock(0), nTransactions(0), nTransactionOutputs(0), nSerializedSize(0), hashSerialized(0), nTotalAmount(0) {}
};

/** Abstract view on the open txout dataset. */
template <typename T>
class CCoinsView_impl
{
public:
    //! Retrieve the CCoins (unspent transaction outputs) for a given txid
    virtual bool GetCoins(const uint256 &txid, CCoins_impl<T> &coins) const = 0;

    //! Just check whether we have data for a given txid.
    //! This may (but cannot always) return true for fully spent transactions
    virtual bool HaveCoins(const uint256 &txid) const = 0;

    //! Retrieve the block hash whose state this CCoinsView currently represents
    virtual uint256 GetBestBlock() const = 0;

    //! Do a bulk modification (multiple CCoins changes + BestBlock change).
    //! The passed mapCoins can be modified.
    virtual bool BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) = 0;

    //! Calculate statistics about the unspent transaction output set
    virtual bool GetStats(CCoinsStats &stats) const = 0;

    //! As we use CCoinsViews polymorphically, have a virtual destructor
    virtual ~CCoinsView_impl() {}
};

/** CCoinsView backed by another CCoinsView */
template <typename T>
class CCoinsViewBacked_impl : public CCoinsView_impl<T>
{
protected:
    CCoinsView_impl<T> *base;

public:
    CCoinsViewBacked_impl(CCoinsView_impl<T> *viewIn);
    bool GetCoins(const uint256 &txid, CCoins_impl<T> &coins) const;
    bool HaveCoins(const uint256 &txid) const;
    uint256 GetBestBlock() const;
    void SetBackend(CCoinsView_impl<T> &viewIn);
    bool BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock);
    bool GetStats(CCoinsStats &stats) const;
};

/** Flags for nSequence and nLockTime locks */
enum {
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

/** Used as the flags parameter to sequence and nLocktime checks in non-consensus code. */
static constexpr unsigned int STANDARD_LOCKTIME_VERIFY_FLAGS = LOCKTIME_VERIFY_SEQUENCE |
                                                               LOCKTIME_MEDIAN_TIME_PAST;

/**
 * A reference to a mutable cache entry. Encapsulating it allows us to run
 *  cleanup code after the modification is finished, and keeping track of
 *  concurrent modifications.
 */
template <typename T>
class CCoinsViewCache_impl;
template <typename T>
class CCoinsModifier_impl
{
private:
    CCoinsViewCache_impl<T> &cache;
    CCoinsMap::iterator it;
    CCoinsModifier_impl(CCoinsViewCache_impl<T> &cache_, CCoinsMap::iterator it_);

public:
    CCoins_impl<T> *operator->() { return &it->second.coins; }
    CCoins_impl<T> &operator*() { return it->second.coins; }
    ~CCoinsModifier_impl();
    friend class CCoinsViewCache_impl<T>;
};
using CCoinsModifier = CCoinsModifier_impl<uint256>;

/** CCoinsView that adds a memory cache for transactions to another CCoinsView */
template <typename T>
class CCoinsViewCache_impl : public CCoinsViewBacked_impl<T>
{
protected:
    /* Whether this cache has an active modifier. */
    bool hasModifier;

    /**
     * Make mutable so that we can "fill the cache" even from Get-methods
     * declared as "const".
     */
    mutable uint256 hashBlock;
    mutable CCoinsMap cacheCoins;

public:
    CCoinsViewCache_impl(CCoinsView_impl<T> *baseIn);
    ~CCoinsViewCache_impl();

    // Standard CCoinsView methods
    bool GetCoins(const uint256 &txid, CCoins_impl<T> &coins) const;
    bool HaveCoins(const uint256 &txid) const;
    uint256 GetBestBlock() const;
    void SetBestBlock(const uint256 &hashBlock);
    bool BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock);

    /**
     * Return a pointer to CCoins in the cache, or NULL if not found. This is
     * more efficient than GetCoins. Modifications to other cache entries are
     * allowed while accessing the returned pointer.
     */
    const CCoins_impl<T> *AccessCoins(const uint256 &txid) const;

    /**
     * Return a modifiable reference to a CCoins. If no entry with the given
     * txid exists, a new one is created. Simultaneous modifications are not
     * allowed.
     */
    CCoinsModifier_impl<T> ModifyCoins(const uint256 &txid);

    /**
     * Push the modifications applied to this cache to its base.
     * Failure to call this method before destruction will cause the changes to be forgotten.
     * If false is returned, the state of this cache (and its backing view) will be undefined.
     */
    bool Flush();

    //! Calculate the size of the cache (in number of transactions)
    unsigned int GetCacheSize() const;

    /**
     * Amount of merge coming in to a transaction
     * Note that lightweight clients may not know anything besides the hash of previous transactions,
     * so may not be able to calculate this.
     *
     * @param[in] tx	transaction for which we are checking input total
     * @return	Sum of value of all inputs (scriptSigs)
     */
    CAmount GetValueIn(const CTransaction_impl<T> &tx) const;

    //! Check whether all prevouts of the transaction are present in the UTXO set represented by this view
    bool HaveInputs(const CTransaction_impl<T> &tx) const;

    //! Return priority of tx at height nHeight
    double GetPriority(const CTransaction_impl<T> &tx, int nHeight) const;

    const CTxOut_impl<T> &GetOutputFor(const CTxIn_impl<T> &input) const;

    friend class CCoinsModifier_impl<T>;

private:
    CCoinsMap::iterator FetchCoins(const uint256 &txid);
    CCoinsMap::const_iterator FetchCoins(const uint256 &txid) const;
};
using CCoinsViewCache = CCoinsViewCache_impl<uint256>;


namespace block_check
{
    namespace testnet
    {
        const unsigned int nStakeMinAge = 2 * util::nOneHour;       // test net min age is 2 hours
        const unsigned int nModifierInterval = 3 * 60;              // test modifier interval is 3 minutes
        const unsigned int nStakeTargetSpacing = 1 * 60;            // test block spacing is 1 minutes
        const unsigned int nPowTargetSpacing = 60;
    }
    namespace mainnet
    {
        const unsigned int nStakeMinAge = 8 * util::nOneHour;
        const unsigned int nModifierInterval = 10 * 60;             // main modifier 10 minutes
        const unsigned int nStakeTargetSpacing = 6 * 60;
        const unsigned int nPowTargetSpacing = 3 * 60;
    }

    extern unsigned int nStakeMinAge;// = mainnet::nStakeMinAge;
    const unsigned int nStakeMaxAge = 90 * util::nOneDay;

    extern unsigned int nStakeTargetSpacing;// = mainnet::nStakeTargetSpacing;
    extern unsigned int nPowTargetSpacing; // = mainnet::nPowTargetSpacing;
    extern unsigned int nModifierInterval;// = mainnet::nModifierInterval;
    const int64_t nTargetTimespan = 7 * util::nOneDay;

    template <typename T>
    class manage : private no_instance
    {
    public:
        static void InvalidChainFound(CBlockIndex *pindexNew);
        static bool VerifySignature(const CTransaction &txFrom, const CTransaction &txTo, unsigned int nIn, unsigned int flags, int nHashType);
        static bool Reorganize(CTxDB_impl<T> &txdb, CBlockIndex *pindexNew);

        static int64_t PastDrift(int64_t nTime) {    // up to 2 hours from the past
            return nTime - 2 * util::nOneHour;
        }
        static int64_t FutureDrift(int64_t nTime) {  // up to 2 hours from the future
            return nTime + 2 * util::nOneHour;
        }
    };

    class thread : private no_instance
    {
    public:
        static CCheckQueue<CScriptCheck> scriptcheckqueue;
        static void ThreadScriptCheck(void *);
        static void ThreadScriptCheckQuit();
    };
}

#endif
