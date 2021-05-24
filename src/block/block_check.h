// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_CHECK_H
#define BITCOIN_BLOCK_CHECK_H

#include <stdint.h>
#include <util.h>
#include <block/transaction.h>

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

class CCoins
{
public:
    //! whether transaction is a coinbase
    bool fCoinBase;
    bool fCoinStake;
    bool fCoinPoSpace;
    bool fCoinMasternode;

    //! unspent transaction outputs; spent outputs are .IsNull(); spent outputs at the end of the array are dropped
    std::vector<CTxOut> vout;

    //! at which height this transaction was included in the active block chain
    int nHeight;

    //! version of the CTransaction; accesses to this value should probably check for nHeight as well,
    //! as new tx version will probably only be introduced at certain heights
    int nVersion;

    //void FromTx(const CTransaction &tx, int nHeightIn)
    //{
    //    fCoinBase = tx.IsCoinBase();
    //    fCoinStake = tx.IsCoinStake();
    //    vout = tx.vout;
    //    nHeight = nHeightIn;
    //    nVersion = tx.nVersion;
    //    ClearUnspendable();
    //}

    //! construct a CCoins from a CTransaction, at a given height
    //CCoins(const CTransaction &tx, int nHeightIn)
    //{
    //    FromTx(tx, nHeightIn);
    //}

    void Clear()
    {
        fCoinBase = false;
        fCoinStake = false;
        std::vector<CTxOut>().swap(vout);
        nHeight = 0;
        nVersion = 0;
    }

    //! empty constructor
    CCoins() : fCoinBase(false), fCoinStake(false), vout(0), nHeight(0), nVersion(0) {}

    //!remove spent outputs at the end of vout
    void Cleanup()
    {
        while (vout.size() > 0 && vout.back().IsNull())
            vout.pop_back();
        if (vout.empty())
            std::vector<CTxOut>().swap(vout);
    }

    //void ClearUnspendable()
    //{
    //    for (CTxOut& txout: vout) {
    //        if (txout.scriptPubKey.IsUnspendable())
    //            txout.SetNull();
    //    }
    //    Cleanup();
    //}

    void swap(CCoins &to)
    {
        std::swap(to.fCoinBase, fCoinBase);
        std::swap(to.fCoinStake, fCoinStake);
        to.vout.swap(vout);
        std::swap(to.nHeight, nHeight);
        std::swap(to.nVersion, nVersion);
    }

    //! equality test
    //friend bool operator==(const CCoins &a, const CCoins &b)
    //{
        // Empty CCoins objects are always equal.
    //    if (a.IsPruned() && b.IsPruned())
    //        return true;
    //    return a.fCoinBase == b.fCoinBase &&
    //           a.fCoinStake == b.fCoinStake &&
    //           a.nHeight == b.nHeight &&
    //           a.nVersion == b.nVersion &&
    //           a.vout == b.vout;
    //}
    //friend bool operator!=(const CCoins &a, const CCoins &b)
    //{
    //    return !(a == b);
    //}

    void CalcMaskSize(unsigned int &nBytes, unsigned int &nNonzeroBytes) const;

    bool IsCoinBase() const
    {
        return fCoinBase;
    }

    bool IsCoinStake() const
    {
        return fCoinStake;
    }

    unsigned int GetSerializeSize(int nType=0, int nVersion=0)
    {
        unsigned int nSize = 0;
        unsigned int nMaskSize = 0, nMaskCode = 0;
        CalcMaskSize(nMaskSize, nMaskCode);
        bool fFirst = vout.size() > 0 && !vout[0].IsNull();
        bool fSecond = vout.size() > 1 && !vout[1].IsNull();
        assert(fFirst || fSecond || nMaskCode);
        unsigned int nCode = 8 * (nMaskCode - (fFirst || fSecond ? 0 : 1)) + (fCoinBase ? 1 : 0) + (fCoinStake ? 2 : 0) + (fFirst ? 4 : 0) + (fSecond ? 8 : 0);
        // version
        nSize += ::GetSerializeSize(VARINT(this->nVersion));
        // size of header code
        nSize += ::GetSerializeSize(VARUINT(nCode));
        // spentness bitmask
        nSize += nMaskSize;
        // txouts themself
        //for (unsigned int i = 0; i < vout.size(); i++) {
        //    if (!vout[i].IsNull())
        //        nSize += ::GetSerializeSize(CTxOutCompressor(REF(vout[i])));
        //}
        // height
        nSize += ::GetSerializeSize(VARINT(nHeight));
        return nSize;
    }

    template <typename Stream>
    void Serialize(Stream &s, int nType=0, int nVersion=0)
    {
        unsigned int nMaskSize = 0, nMaskCode = 0;
        CalcMaskSize(nMaskSize, nMaskCode);
        bool fFirst = vout.size() > 0 && !vout[0].IsNull();
        bool fSecond = vout.size() > 1 && !vout[1].IsNull();
        assert(fFirst || fSecond || nMaskCode);
        unsigned int nCode = 16 * (nMaskCode - (fFirst || fSecond ? 0 : 1)) + (fCoinBase ? 1 : 0) + (fCoinStake ? 2 : 0) + (fFirst ? 4 : 0) + (fSecond ? 8 : 0);
        // version
        ::Serialize(s, VARINT(this->nVersion));
        // header code
        ::Serialize(s, VARUINT(nCode));
        // spentness bitmask
        for (unsigned int b = 0; b < nMaskSize; b++) {
            unsigned char chAvail = 0;
            //for (unsigned int i = 0; i < 8 && 2 + b * 8 + i < vout.size(); i++) {
            //    if (!vout[2 + b * 8 + i].IsNull())
            //        chAvail |= (1 << i);
            //}
            ::Serialize(s, chAvail);
        }
        // txouts themself
        //for (unsigned int i = 0; i < vout.size(); i++) {
        //    if (!vout[i].IsNull())
        //        ::Serialize(s, CTxOutCompressor(REF(vout[i])));
        //}
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
        vout.assign(vAvail.size(), CTxOut());
        //for (unsigned int i = 0; i < vAvail.size(); i++) {
        //    if (vAvail[i])
        //        ::Unserialize(s, REF(CTxOutCompressor(vout[i])));
        //}
        // coinbase height
        ::Unserialize(s, VARINT(nHeight));
        Cleanup();
    }

    //! mark an outpoint spent, and construct undo information
    //bool Spend(const COutPoint &out, CTxInUndo &undo);

    //! mark a vout spent
    bool Spend(int nPos);

    //! check whether a particular output is still available
    //bool IsAvailable(unsigned int nPos) const
    //{
    //    return (nPos < vout.size() && !vout[nPos].IsNull() && !vout[nPos].scriptPubKey.IsZerocoinMint());
    //}

    //! check whether the entire CCoins is spent
    //! note that only !IsPruned() CCoins can be serialized
    //bool IsPruned() const
    //{
    //    for (const CTxOut &out: vout) {
    //        if (! out.IsNull())
    //            return false;
    //    }
    //    return true;
    //}
};


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
        static void InvalidChainFound(CBlockIndex_impl<T> *pindexNew);
        static bool VerifySignature(const CTransaction &txFrom, const CTransaction &txTo, unsigned int nIn, unsigned int flags, int nHashType);
        static bool Reorganize(CTxDB_impl<T> &txdb, CBlockIndex_impl<T> *pindexNew);

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
