// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <block/transaction.h>
#include <block/block_process.h>
#include <miner/diff.h>
#include <block/block_check.h>
#include <checkpoints.h>
#include <txdb.h>
#include <wallet.h>

template <typename T> CTxMemPool_impl<T> CTxMemPool_impl<T>::mempool;
template <typename T> CBlockIndex *block_transaction::manage_impl<T>::pblockindexFBBHLast = nullptr;
int block_transaction::nCoinbaseMaturity = block_transaction::mainnet::nCoinbaseMaturity;

/*
** collect transaction print
*/
template <typename T>
std::string CTransaction_impl<T>::ToStringShort() const {
    std::string str;
    str += strprintf("%s %s", GetHash().ToString().c_str(), IsCoinBase()? "base" : (IsCoinStake()? "stake" : "user"));
    return str;
}

template <typename T>
std::string CTransaction_impl<T>::ToString() const {
    std::string str;
    str += IsCoinBase() ? "Coinbase" : (IsCoinStake() ? "Coinstake" : "CTransaction");
    str += strprintf("(hash=%s, nTime=%d, ver=%d, vin.size=%" PRIszu ", vout.size=%" PRIszu ", nLockTime=%d)\n",
        GetHash().ToString().substr(0,10).c_str(),
        nTime,
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (unsigned int i = 0; i < vin.size(); ++i)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); ++i)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

template <typename T>
std::string COutPoint_impl<T>::ToString() const noexcept {
    return strprintf("COutPoint_impl<T>(%s, %u)", hash.ToString().substr(0,10).c_str(), n);
}

std::string CDiskTxPos::ToString() const noexcept {
    if (IsNull())
        return "null";
    else
        return strprintf("(nFile=%u, nBlockPos=%u, nTxPos=%u)", nFile, nBlockPos, nTxPos);
}

template <typename T>
std::string CTxIn_impl<T>::ToStringShort() const {
    return strprintf(" %s %d", prevout.get_hash().ToString().c_str(), prevout.get_n());
}

template <typename T>
std::string CTxIn_impl<T>::ToString() const {
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", util::HexStr(scriptSig).c_str());
    else
        str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0,24).c_str());
    if (nSequence != std::numeric_limits<unsigned int>::max())
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

template <typename T>
std::string CTxOut_impl<T>::ToStringShort() const {
    return strprintf(" out %s %s", bitstr::FormatMoney(nValue).c_str(), scriptPubKey.ToString(true).c_str());
}

template <typename T>
std::string CTxOut_impl<T>::ToString() const {
    if (IsEmpty()) return "CTxOut(empty)";
    if (scriptPubKey.size() < 6) return "CTxOut(error)";
    return strprintf("CTxOut(nValue=%s, scriptPubKey=%s)", bitstr::FormatMoney(nValue).c_str(), scriptPubKey.ToString().c_str());
}

// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
template <typename T>
bool block_transaction::manage_impl<T>::GetTransaction(const T &hash, CTransaction_impl<T> &tx, T &hashBlock)
{
    {
        LOCK(block_process::cs_main);
        {
            LOCK(CTxMemPool_impl<T>::mempool.get_cs());
            if (CTxMemPool_impl<T>::mempool.exists(hash)) {
                tx = CTxMemPool_impl<T>::mempool.lookup(hash);
                return true;
            }
        }

        CTxDB txdb("r");
        CTxIndex txindex;
        if (tx.ReadFromDisk(txdb, COutPoint(hash, 0), txindex)) {
            CBlock block;
            if (block.ReadFromDisk(txindex.get_pos().get_nFile(), txindex.get_pos().get_nBlockPos(), false))
                hashBlock = block.GetHash();
            return true;
        }
    }
    return false;
}

template <typename T>
CBlockIndex *block_transaction::manage_impl<T>::FindBlockByHeight(int nHeight)
{
    CBlockIndex *pblockindex;
    if (nHeight < block_info::nBestHeight / 2)
        pblockindex = block_info::pindexGenesisBlock;
    else
        pblockindex = block_info::pindexBest;

    if (pblockindexFBBHLast && abs(nHeight - pblockindex->get_nHeight()) > abs(nHeight - pblockindexFBBHLast->get_nHeight()))
        pblockindex = pblockindexFBBHLast;
    while (pblockindex->get_nHeight() > nHeight)
        pblockindex = pblockindex->set_pprev();
    while (pblockindex->get_nHeight() < nHeight)
        pblockindex = pblockindex->set_pnext();
    pblockindexFBBHLast = pblockindex;
    return pblockindex;
}

template <typename T>
bool CTxMemPool_impl<T>::accept(CTxDB &txdb, CTransaction_impl<T> &tx, bool fCheckInputs, bool *pfMissingInputs)
{
    if (pfMissingInputs)
        *pfMissingInputs = false;

    // Time (prevent mempool memory exhaustion attack)
    if (tx.get_nTime() > block_check::manage::FutureDrift(bitsystem::GetAdjustedTime()))
        return tx.DoS(10, print::error("CTxMemPool::accept() : transaction timestamp is too far in the future"));
    if (! tx.CheckTransaction())
        return print::error("CTxMemPool::accept() : CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return tx.DoS(100, print::error("CTxMemPool::accept() : coinbase as individual tx"));

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return tx.DoS(100, print::error("CTxMemPool::accept() : coinstake as individual tx"));

    // To help v0.1.5 clients who would see it as a negative number
    if ((int64_t)tx.get_nLockTime() > std::numeric_limits<int>::max())
        return print::error("CTxMemPool::accept() : not accepting nLockTime beyond 2038 yet");

    // Rather not work on nonstandard transactions (unless -testnet)
    std::string strNonStd;
    if (!args_bool::fTestNet && !tx.IsStandard(strNonStd))
        return print::error("CTxMemPool::accept() : nonstandard transaction (%s)", strNonStd.c_str());

    // Do we already have it?
    T hash = tx.GetHash();
    {
        LOCK(cs);
        if (mapTx.count(hash)) return false;
    }
    if (fCheckInputs) {
        if (txdb.ContainsTx(hash)) return false;
    }

    // Check for conflicts with in-memory transactions
    // replacing with a newer version, ptxOld insert mapNextTx[outpoint].
    CTransaction_impl<T> *ptxOld = nullptr;
    for (unsigned int i = 0; i < tx.get_vin().size(); ++i) {
        COutPoint_impl<T> outpoint = tx.get_vin(i).get_prevout();
        if (mapNextTx.count(outpoint)) {
            // Disable replacement feature for now
            return false;
            //////////////////////////////////////

            // Allow replacing with a newer version of the same transaction.
            if (i != 0) return false;
            ptxOld = mapNextTx[outpoint].get_ptx();
            if (ptxOld->IsFinal())
                return false;
            if (! tx.IsNewerThan(*ptxOld))
                return false;
            for (unsigned int i = 0; i < tx.get_vin().size(); ++i) {
                COutPoint_impl<T> outpoint = tx.get_vin(i).get_prevout();
                if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].get_ptx() != ptxOld)
                    return false;
            }
            break;
        }
    }
    if (fCheckInputs) {
        MapPrevTx mapInputs;
        std::map<T, CTxIndex> mapUnused;
        bool fInvalid = false;
        if (! tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid)) {
            if (fInvalid)
                return print::error("CTxMemPool::accept() : FetchInputs found invalid tx %s", hash.ToString().substr(0,10).c_str());
            if (pfMissingInputs)
                *pfMissingInputs = true;
            return false;
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (!tx.AreInputsStandard(mapInputs) && !args_bool::fTestNet)
            return print::error("CTxMemPool::accept() : nonstandard transaction input");

        // Note: if you modify this code to accept non-standard transactions, then
        // you should add code here to check that the transaction does a
        // reasonable number of ECDSA signature verifications.
        int64_t nFees = tx.GetValueIn(mapInputs) - tx.GetValueOut();
        unsigned int nSize = ::GetSerializeSize(tx);

        // Don't accept it if it can't get into a block
        int64_t txMinFee = tx.GetMinFee(1000, true, CTransaction_impl<T>::GMF_RELAY, nSize);
        if (nFees < txMinFee)
            return print::error("CTxMemPool::accept() : not enough fees %s, %" PRId64 " < %" PRId64, hash.ToString().c_str(), nFees, txMinFee);

        // Continuously rate-limit free transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (nFees < block_params::MIN_RELAY_TX_FEE) {
            static CCriticalSection __cs;
            static double dFreeCount;
            static int64_t nLastTime;
            int64_t nNow = bitsystem::GetTime();
            {
                LOCK(__cs);

                // Use an exponentially decaying ~10-minute window:
                dFreeCount *= pow(1.0 - 1.0 / 600.0, (double)(nNow - nLastTime));
                nLastTime = nNow;

                // -limitfreerelay unit is thousand-bytes-per-minute
                // At default rate it would take over a month to fill 1GB
                if (dFreeCount > map_arg::GetArg("-limitfreerelay", 15) * 10 * 1000 && !IsFromMe(tx))
                    return print::error("CTxMemPool::accept() : free transaction rejected by rate limiter");
                if (args_bool::fDebug)
                    logging::LogPrintf("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
                dFreeCount += nSize;
            }
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (! tx.ConnectInputs(txdb, mapInputs, mapUnused, CDiskTxPos(1,1,1), block_info::pindexBest, false, false, true, Script_param::STRICT_FLAGS))
            return print::error("CTxMemPool::accept() : ConnectInputs failed %s", hash.ToString().substr(0,10).c_str());
    }

    // Store transaction in memory
    {
        LOCK(cs);
        if (ptxOld) {
            logging::LogPrintf("CTxMemPool::accept() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
            remove(*ptxOld);
        }
        addUnchecked(hash, tx);
    }

    // are we sure this is ok when loading transactions or restoring block txes
    // If updated, erase old tx from wallet
    if (ptxOld)
        EraseFromWallets(ptxOld->GetHash());

    logging::LogPrintf("CTxMemPool::accept() : accepted %s (poolsz %" PRIszu ")\n", hash.ToString().substr(0,10).c_str(), mapTx.size());
    return true;
}

template <typename T>
bool CTxMemPool_impl<T>::addUnchecked(const T &hash, CTransaction_impl<T> &tx)
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call CTxMemPool::accept to properly check the transaction first.
    {
        mapTx[hash] = tx;
        for (unsigned int i = 0; i < tx.get_vin().size(); ++i)
            mapNextTx[tx.get_vin(i).get_prevout()] = CInPoint(&mapTx[hash], i);
        block_info::nTransactionsUpdated++;
    }
    return true;
}

template <typename T>
bool CTxMemPool_impl<T>::remove(CTransaction_impl<T> &tx)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        T hash = tx.GetHash();
        if (mapTx.count(hash)) {
            for(const CTxIn &txin: tx.get_vin())
                mapNextTx.erase(txin.get_prevout());
            mapTx.erase(hash);
            block_info::nTransactionsUpdated++;
        }
    }
    return true;
}

template <typename T>
void CTxMemPool_impl<T>::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapNextTx.clear();
    ++block_info::nTransactionsUpdated;
}

template <typename T>
void CTxMemPool_impl<T>::queryHashes(std::vector<T> &vtxid)
{
    vtxid.clear();
    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (typename std::map<T, CTransaction_impl<T> >::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}

// check whether the passed transaction is from us
template <typename T>
bool CTxMemPool_impl<T>::IsFromMe(CTransaction_impl<T> &tx)
{
    for(CWallet *pwallet: block_info::setpwalletRegistered) {
        if (pwallet->IsFromMe(tx)) return true;
    }
    return false;
}

// erases transaction with the given hash from all wallets
template <typename T>
void CTxMemPool_impl<T>::EraseFromWallets(T hash)
{
    for(CWallet *pwallet: block_info::setpwalletRegistered)
        pwallet->EraseFromWallet(hash);
}

template <typename T>
bool CTransaction_impl<T>::IsStandard(std::string &strReason) const
{
    if (nVersion > CTransaction_impl<T>::CURRENT_VERSION) {
        strReason = "version";
        return false;
    }

    unsigned int nDataOut = 0;
    TxnOutputType::txnouttype whichType;
    for(const CTxIn_impl<T> &txin: vin) {
        // Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed
        // keys. (remember the 520 byte limit on redeemScript size) That works
        // out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)=1624
        // bytes of scriptSig, which we round off to 1650 bytes for some minor
        // future-proofing. That's also enough to spend a 20-of-20
        // CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not considered standard)
        if (txin.get_scriptSig().size() > 1650) {
            strReason = "scriptsig-size";
            return false;
        }
        if (! txin.get_scriptSig().IsPushOnly()) {
            strReason = "scriptsig-not-pushonly";
            return false;
        }
        if (! txin.get_scriptSig().HasCanonicalPushes()) {
            strReason = "txin-scriptsig-not-canonicalpushes";
            return false;
        }
    }

    for(const CTxOut_impl<T> &txout: vout) {
        if (! Script_util::IsStandard(txout.get_scriptPubKey(), whichType)) {
            strReason = "scriptpubkey";
            return false;
        }
        if (whichType == TxnOutputType::TX_NULL_DATA)
            ++nDataOut;
        else {
            if (txout.get_nValue() == 0) {
                strReason = "txout-value=0";
                return false;
            }
            if (! txout.get_scriptPubKey().HasCanonicalPushes()) {
                strReason = "txout-scriptsig-not-canonicalpushes";
                return false;
            }
        }
    }

    // only one OP_RETURN txout is permitted
    if (nDataOut > 1) {
        strReason = "multi-op-return";
        return false;
    }

    return true;
}

template <typename T>
bool CTransaction_impl<T>::IsStandard() const {
    std::string strReason;
    return IsStandard(strReason);
}

// Check transaction inputs, and make sure any
// pay-to-script-hash transactions are evaluating IsStandard scripts
//
// Why bother? To avoid denial-of-service attacks; an attacker
// can submit a standard HASH... OP_EQUAL transaction,
// which will get accepted into blocks. The redemption
// script can be anything; an attacker could use a very
// expensive-to-check-upon-redemption script like:
//   DUP CHECKSIG DROP ... repeated 100 times... OP_1
template <typename T>
bool CTransaction_impl<T>::AreInputsStandard(const MapPrevTx &mapInputs) const
{
    if (IsCoinBase())
        return true; // Coinbases don't use vin normally
    for (unsigned int i = 0; i < vin.size(); ++i) {
        const CTxOut_impl<T> &prev = GetOutputFor(vin[i], mapInputs);
        Script_util::statype vSolutions;
        TxnOutputType::txnouttype whichType;

        // get the scriptPubKey corresponding to this input:
        const CScript &prevScript = prev.get_scriptPubKey();
        if (! Script_util::Solver(prevScript, whichType, vSolutions))
            return false;
        int nArgsExpected = Script_util::ScriptSigArgsExpected(whichType, vSolutions);
        if (nArgsExpected < 0)
            return false;

        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig the
        // IsStandard() call returns false
        Script_util::statype stack;
        if (! Script_util::EvalScript(stack, vin[i].get_scriptSig(), *this, i, false, 0))
            return false;
        if (whichType == TxnOutputType::TX_SCRIPTHASH) {
            if (stack.empty()) return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            Script_util::statype vSolutions2;
            TxnOutputType::txnouttype whichType2;
            if (! Script_util::Solver(subscript, whichType2, vSolutions2)) return false;
            if (whichType2 == TxnOutputType::TX_SCRIPTHASH) return false;
            int tmpExpected = Script_util::ScriptSigArgsExpected(whichType2, vSolutions2);
            if (tmpExpected < 0) return false;
            nArgsExpected += tmpExpected;
        }
        if (stack.size() != (unsigned int)nArgsExpected)
            return false;
    }

    return true;
}

template <typename T>
unsigned int CTransaction_impl<T>::GetLegacySigOpCount() const
{
    unsigned int nSigOps = 0;
    if (! IsCoinBase()) {
        // Coinbase scriptsigs are never executed, so there is no sense in calculation of sigops.
        for(const CTxIn_impl<T> &txin: this->vin)
            nSigOps += txin.get_scriptSig().GetSigOpCount(false);
    }
    for(const CTxOut_impl<T> &txout: this->vout)
        nSigOps += txout.get_scriptPubKey().GetSigOpCount(false);

    return nSigOps;
}

template <typename T>
unsigned int CTransaction_impl<T>::GetP2SHSigOpCount(const MapPrevTx &inputs) const
{
    if (IsCoinBase()) return 0;
    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < vin.size(); ++i) {
        const CTxOut_impl<T> &prevout = GetOutputFor(vin[i], inputs);
        if (prevout.get_scriptPubKey().IsPayToScriptHash())
            nSigOps += prevout.get_scriptPubKey().GetSigOpCount(vin[i].get_scriptSig());
    }
    return nSigOps;
}

template <typename T>
int64_t CTransaction_impl<T>::GetValueOut() const {
    int64_t nValueOut = 0;
    for(const CTxOut_impl<T> &txout: vout) {
        nValueOut += txout.get_nValue();
        if (!block_transaction::manage::MoneyRange(txout.get_nValue()) || !block_transaction::manage::MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction_impl<T>::GetValueOut() : value out of range");
    }
    return nValueOut;
}

template <typename T>
int64_t CTransaction_impl<T>::GetValueIn(const MapPrevTx &inputs) const
{
    if (IsCoinBase()) return 0;
    int64_t nResult = 0;
    for (unsigned int i = 0; i < vin.size(); ++i)
        nResult += GetOutputFor(vin[i], inputs).get_nValue();
    return nResult;
}

template <typename T>
bool CTransaction_impl<T>::AllowFree(double dPriority) { // Large (in bytes) low-priority (new, small-coin) transactions need a fee.
    return dPriority > util::COIN * 960 / 250;
}

template <typename T>
int64_t CTransaction_impl<T>::GetMinFee(unsigned int nBlockSize/*=1*/, bool fAllowFree/*=false*/, enum GetMinFee_mode mode/*=GMF_BLOCK*/, unsigned int nBytes/*=0*/) const
{
    int64_t nMinTxFee = block_params::MIN_TX_FEE, nMinRelayTxFee = block_params::MIN_RELAY_TX_FEE;
    if(IsCoinStake()) {
        // Enforce 0.01 as minimum fee for coinstake
        nMinTxFee = util::CENT;
        nMinRelayTxFee = util::CENT;
    }

    // Base fee is either nMinTxFee or nMinRelayTxFee
    int64_t nBaseFee = (mode == GMF_RELAY) ? nMinRelayTxFee : nMinTxFee;

    unsigned int nNewBlockSize = nBlockSize + nBytes;
    int64_t nMinFee = (1 + (int64_t)nBytes / 1000) * nBaseFee;
    if (fAllowFree) {
        if (nBlockSize == 1) {
            // Transactions under 1K are free
            if (nBytes < 1000)
                nMinFee = 0;
        } else {
            // Free transaction area
            if (nNewBlockSize < 27000)
                nMinFee = 0;
        }
    }

    // [prevent SPAM] To limit dust spam,
    // require additional block_params::MIN_TX_FEE/block_params::MIN_RELAY_TX_FEE for
    // each non empty output which is less than 0.01
    // It's safe to ignore empty outputs here, because these inputs are allowed only for coinbase and coinstake transactions.
    for(const CTxOut_impl<T> &txout: vout) {
        if (txout.get_nValue() < util::CENT && !txout.IsEmpty())
            nMinFee += nBaseFee;
    }

    // Raise the price as the block approaches full
    if (nBlockSize != 1 && nNewBlockSize >= block_params::MAX_BLOCK_SIZE_GEN / 2) {
        if (nNewBlockSize >= block_params::MAX_BLOCK_SIZE_GEN) return block_params::MAX_MONEY;
        nMinFee *= block_params::MAX_BLOCK_SIZE_GEN / (block_params::MAX_BLOCK_SIZE_GEN - nNewBlockSize);
    }
    if (! block_transaction::manage::MoneyRange(nMinFee))
        nMinFee = block_params::MAX_MONEY;

    return nMinFee;
}

template <typename T>
bool CTransaction_impl<T>::ReadFromDisk(CDiskTxPos pos, FILE **pfileRet/*=nullptr*/) {
    CAutoFile filein = CAutoFile(file_open::OpenBlockFile(pos.get_nFile(), 0, pfileRet ? "rb+" : "rb"), SER_DISK, version::CLIENT_VERSION);
    if (! filein) return print::error("CTransaction_impl<T>::ReadFromDisk() : file_open::OpenBlockFile failed");

    // Read transaction
    if (fseek(filein, pos.get_nTxPos(), SEEK_SET) != 0) return print::error("CTransaction_impl<T>::ReadFromDisk() : fseek failed");
    try {
        filein >> *this;
    } catch (const std::exception &) {
        return print::error("%s() : deserialize or I/O error", BOOST_CURRENT_FUNCTION);
    }

    // Return file pointer
    if (pfileRet) {
        if (::fseek(filein, pos.get_nTxPos(), SEEK_SET) != 0) return print::error("CTransaction_impl<T>::ReadFromDisk() : second fseek failed");
        *pfileRet = filein.release();
    }
    return true;
}

template <typename T>
bool CTransaction_impl<T>::ReadFromDisk(CTxDB &txdb, COutPoint_impl<T> prevout, CTxIndex &txindexRet)
{
    SetNull();
    if (! txdb.ReadTxIndex(prevout.get_hash(), txindexRet)) return false;
    if (! ReadFromDisk(txindexRet.get_pos())) return false;
    if (prevout.get_n() >= vout.size()) {
        SetNull();
        return false;
    }
    return true;
}

template <typename T>
bool CTransaction_impl<T>::ReadFromDisk(CTxDB &txdb, COutPoint_impl<T> prevout)
{
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}

template <typename T>
bool CTransaction_impl<T>::ReadFromDisk(COutPoint_impl<T> prevout)
{
    CTxDB txdb("r");
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}

template <typename T>
bool CTransaction_impl<T>::DisconnectInputs(CTxDB &txdb)
{
    // Relinquish previous transactions' spent pointers
    if (! IsCoinBase()) {
        for(const CTxIn_impl<T> &txin: this->vin) {
            COutPoint prevout = txin.get_prevout();

            // Get prev txindex from disk
            CTxIndex txindex;
            if (! txdb.ReadTxIndex(prevout.get_hash(), txindex))
                return print::error("DisconnectInputs() : ReadTxIndex failed");
            if (prevout.get_n() >= txindex.get_vSpent().size())
                return print::error("DisconnectInputs() : prevout.n out of range");

            // Mark outpoint as not spent
            txindex.set_vSpent(prevout.get_n()).SetNull();

            // Write back
            if (! txdb.UpdateTxIndex(prevout.get_hash(), txindex))
                return print::error("DisconnectInputs() : UpdateTxIndex failed");
        }
    }

    // Remove transaction from index
    // This can fail if a duplicate of this transaction was in a chain that got
    // reorganized away.
    // This is only possible if this transaction was completely spent, so erasing it would be a no-op anyway.
    txdb.EraseTxIndex(*this);

    return true;
}

template <typename T>
bool CTransaction_impl<T>::FetchInputs(CTxDB &txdb, const std::map<T, CTxIndex> &mapTestPool, bool fBlock, bool fMiner, MapPrevTx &inputsRet, bool &fInvalid)
{
    // FetchInputs can return false either because we just haven't seen some inputs
    // (in which case the transaction should be stored as an orphan)
    // or because the transaction is malformed (in which case the transaction should
    // be dropped).  If tx is definitely invalid, fInvalid will be set to true.
    fInvalid = false;
    if (IsCoinBase())
        return true; // Coinbase transactions have no inputs to fetch.

    for (unsigned int i = 0; i < vin.size(); ++i) {
        COutPoint_impl<T> prevout = vin[i].get_prevout();
        if (inputsRet.count(prevout.get_hash()))
            continue; // Got it already

        // Read txindex
        CTxIndex &txindex = inputsRet[prevout.get_hash()].first;
        bool fFound = true;
        if ((fBlock || fMiner) && mapTestPool.count(prevout.get_hash())) {
            // Get txindex from current proposed changes
            txindex = mapTestPool.find(prevout.get_hash())->second;
        } else {
            // Read txindex from txdb
            fFound = txdb.ReadTxIndex(prevout.get_hash(), txindex);
        }
        if (!fFound && (fBlock || fMiner))
            return fMiner ? false : print::error("FetchInputs() : %s prev tx %s index entry not found", GetHash().ToString().substr(0,10).c_str(),  prevout.get_hash().ToString().substr(0,10).c_str());

        // Read txPrev
        CTransaction_impl<T> &txPrev = inputsRet[prevout.get_hash()].second;
        if (!fFound || txindex.get_pos() == CDiskTxPos(1,1,1)) {
            // Get prev tx from single transactions in memory
            {
                LOCK(CTxMemPool_impl<T>::mempool.get_cs());
                if (! CTxMemPool_impl<T>::mempool.exists(prevout.get_hash()))
                    return print::error("FetchInputs() : %s CTxMemPool::mempool Tx prev not found %s", GetHash().ToString().substr(0,10).c_str(),  prevout.get_hash().ToString().substr(0,10).c_str());
                txPrev = CTxMemPool_impl<T>::mempool.lookup(prevout.get_hash());
            }
            if (! fFound)
                txindex.set_vSpent().resize(txPrev.vout.size());
        } else {
            // Get prev tx from disk
            if (! txPrev.ReadFromDisk(txindex.get_pos()))
                return print::error("FetchInputs() : %s ReadFromDisk prev tx %s failed", GetHash().ToString().substr(0,10).c_str(),  prevout.get_hash().ToString().substr(0,10).c_str());
        }
    }

    // Make sure all prevout.n indexes are valid:
    for (unsigned int i = 0; i < vin.size(); ++i) {
        const COutPoint_impl<T> prevout = vin[i].get_prevout();
        assert(inputsRet.count(prevout.get_hash()) != 0);
        const CTxIndex &txindex = inputsRet[prevout.get_hash()].first;
        const CTransaction_impl<T> &txPrev = inputsRet[prevout.get_hash()].second;
        if (prevout.get_n() >= txPrev.vout.size() || prevout.get_n() >= txindex.get_vSpent().size()) {
            // Revisit this if/when transaction replacement is implemented and allows
            // adding inputs:
            fInvalid = true;
            return DoS(100, print::error("FetchInputs() : %s prevout.n out of range %d %" PRIszu " %" PRIszu " prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.get_n(), txPrev.vout.size(), txindex.get_vSpent().size(), prevout.get_hash().ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));
        }
    }

    return true;
}

template <typename T>
bool CTransaction_impl<T>::ConnectInputs(CTxDB &txdb, MapPrevTx inputs, std::map<T, CTxIndex> &mapTestPool, const CDiskTxPos &posThisTx, const CBlockIndex *pindexBlock, bool fBlock, bool fMiner, bool fScriptChecks/*=true*/, unsigned int flags/*=Script_param::STRICT_FLAGS*/, std::vector<CScriptCheck> *pvChecks/*=NULL*/)
{
    // Take over previous transactions' spent pointers
    // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
    // fMiner is true when called from the internal bitcoin miner
    // ... both are false when called from CTransaction_impl<T>::AcceptToMemoryPool
    if (! IsCoinBase()) {
        int64_t nValueIn = 0;
        int64_t nFees = 0;
        for (unsigned int i = 0; i < vin.size(); ++i) {
            COutPoint_impl<T> prevout = vin[i].get_prevout();
            assert(inputs.count(prevout.get_hash()) > 0);
            CTxIndex &txindex = inputs[prevout.get_hash()].first;
            CTransaction_impl<T> &txPrev = inputs[prevout.get_hash()].second;
            if (prevout.get_n() >= txPrev.vout.size() || prevout.get_n() >= txindex.get_vSpent().size())
                return DoS(100, print::error("ConnectInputs() : %s prevout.n out of range %d %" PRIszu " %" PRIszu " prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.get_n(), txPrev.vout.size(), txindex.get_vSpent().size(), prevout.get_hash().ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));

            // If prev is coinbase or coinstake, check that it's matured
            if (txPrev.IsCoinBase() || txPrev.IsCoinStake()) {
                for (const CBlockIndex *pindex = pindexBlock; pindex && pindexBlock->get_nHeight() - pindex->get_nHeight() < block_transaction::nCoinbaseMaturity; pindex = pindex->get_pprev()) {
                    if (pindex->get_nBlockPos() == txindex.get_pos().get_nBlockPos() && pindex->get_nFile() == txindex.get_pos().get_nFile())
                        return print::error("ConnectInputs() : tried to spend %s at depth %d", txPrev.IsCoinBase() ? "coinbase" : "coinstake", pindexBlock->get_nHeight() - pindex->get_nHeight());
                }
            }

            // ppcoin: check transaction timestamp
            if (txPrev.nTime > nTime)
                return DoS(100, print::error("ConnectInputs() : transaction timestamp earlier than input transaction"));

            // Check for negative or overflow input values
            nValueIn += txPrev.vout[prevout.get_n()].get_nValue();
            if (!block_transaction::manage::MoneyRange(txPrev.vout[prevout.get_n()].get_nValue()) || !block_transaction::manage::MoneyRange(nValueIn))
                return DoS(100, print::error("ConnectInputs() : txin values out of range"));
        }
        if (pvChecks)
            pvChecks->reserve(vin.size());

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.
        for (unsigned int i = 0; i < vin.size(); ++i) {
            COutPoint_impl<T> prevout = vin[i].get_prevout();
            assert(inputs.count(prevout.get_hash()) > 0);
            CTxIndex &txindex = inputs[prevout.get_hash()].first;
            CTransaction_impl<T> &txPrev = inputs[prevout.get_hash()].second;

            // Check for conflicts (double-spend)
            // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
            // for an attacker to attempt to split the network.
            if (! txindex.get_vSpent(prevout.get_n()).IsNull())
                return fMiner ? false : print::error("ConnectInputs() : %s prev tx already used at %s", GetHash().ToString().substr(0,10).c_str(), txindex.get_vSpent(prevout.get_n()).ToString().c_str());

            // Skip ECDSA signature verification when connecting blocks (fBlock=true)
            // before the last blockchain checkpoint. This is safe because block merkle hashes are
            // still computed and checked, and any change will be caught at the next checkpoint.
            if (fScriptChecks) {
                // Verify signature
                CScriptCheck check(txPrev, *this, i, flags, 0);
                if (pvChecks) {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                } else if (! check()) {
                    if (flags & Script_param::STRICT_FLAGS) {
                        // Don't trigger DoS code in case of Script_param::STRICT_FLAGS caused failure.
                        CScriptCheck check(txPrev, *this, i, flags & ~Script_param::STRICT_FLAGS, 0);
                        if (check())
                            return print::error("ConnectInputs() : %s strict block_check::manage::VerifySignature failed", GetHash().ToString().substr(0,10).c_str());
                    }
                    return DoS(100,print::error("ConnectInputs() : %s block_check::manage::VerifySignature failed", GetHash().ToString().substr(0,10).c_str()));
                }
            }

            // Mark outpoints as spent
            txindex.set_vSpent(prevout.get_n()) = posThisTx;

            // Write back
            if (fBlock || fMiner)
                mapTestPool[prevout.get_hash()] = txindex;
        }
        if (IsCoinStake()) {
            if (nTime >  Checkpoints::manage::GetLastCheckpointTime()) {
                unsigned int nTxSize = GetSerializeSize();

                // coin stake tx earns reward instead of paying fee
                uint64_t nCoinAge;
                if (! GetCoinAge(txdb, nCoinAge))
                    return print::error("ConnectInputs() : %s unable to get %s age for coinstake", GetHash().ToString().substr(0,10).c_str(), strCoinName);

                int64_t nReward = GetValueOut() - nValueIn;
                int64_t nCalculatedReward = diff::reward::GetProofOfStakeReward(nCoinAge, pindexBlock->get_nBits(), nTime) - GetMinFee(1, false, GMF_BLOCK, nTxSize) + util::CENT;
                if (nReward > nCalculatedReward)
                    return DoS(100, print::error("ConnectInputs() : coinstake pays too much(actual=%" PRId64 " vs calculated=%" PRId64 ")", nReward, nCalculatedReward));
            }
        } else {
            if (nValueIn < GetValueOut())
                return DoS(100, print::error("ConnectInputs() : %s value in < value out", GetHash().ToString().substr(0,10).c_str()));

            // Tally transaction fees
            int64_t nTxFee = nValueIn - GetValueOut();
            if (nTxFee < 0)
                return DoS(100, print::error("ConnectInputs() : %s nTxFee < 0", GetHash().ToString().substr(0,10).c_str()));

            nFees += nTxFee;
            if (! block_transaction::manage::MoneyRange(nFees))
                return DoS(100, print::error("ConnectInputs() : nFees out of range"));
        }
    }

    return true;
}

template <typename T>
bool CTransaction_impl<T>::ClientConnectInputs()
{
    if (IsCoinBase()) return false;

    // Take over previous transactions' spent pointers
    {
        LOCK(CTxMemPool_impl<T>::mempool.get_cs());
        int64_t nValueIn = 0;
        for (unsigned int i = 0; i < vin.size(); ++i) {
            // Get prev tx from single transactions in memory
            COutPoint_impl<T> prevout = vin[i].get_prevout();
            if (! CTxMemPool_impl<T>::mempool.exists(prevout.get_hash()))
                return false;
            CTransaction_impl<T> &txPrev = CTxMemPool_impl<T>::mempool.lookup(prevout.get_hash());
            if (prevout.get_n() >= txPrev.vout.size())
                return false;

            // Verify signature
            if (! block_check::manage::VerifySignature(txPrev, *this, i, Script_param::SCRIPT_VERIFY_NOCACHE | Script_param::SCRIPT_VERIFY_P2SH, 0))
                return print::error("ClientConnectInputs() : block_check::manage::VerifySignature failed");

            // this is redundant with the CTxMemPool::mempool.mapNextTx stuff,
            // not sure which I want to get rid of
            // this has to go away now that posNext is gone
            // Check for conflicts
            // if (!txPrev.vout[prevout.n].posNext.IsNull())
            //     return print::error("ConnectInputs() : prev tx already used");
            //
            // Flag outpoints as used
            // txPrev.vout[prevout.n].posNext = posThisTx;

            nValueIn += txPrev.vout[prevout.get_n()].get_nValue();
            if (!block_transaction::manage::MoneyRange(txPrev.vout[prevout.get_n()].get_nValue()) || !block_transaction::manage::MoneyRange(nValueIn))
                return print::error("ClientConnectInputs() : txin values out of range");
        }
        if (GetValueOut() > nValueIn)
            return false;
    }

    return true;
}

template <typename T>
bool CTransaction_impl<T>::CheckTransaction() const
{
    // Basic checks that don't depend on any context
    if (vin.empty())
        return DoS(10, print::error("CTransaction_impl<T>::CheckTransaction() : vin empty"));
    if (vout.empty())
        return DoS(10, print::error("CTransaction_impl<T>::CheckTransaction() : vout empty"));

    // Size limits
    if (::GetSerializeSize(*this) > block_params::MAX_BLOCK_SIZE)
        return DoS(100, print::error("CTransaction_impl<T>::CheckTransaction() : size limits failed"));

    // Check for negative or overflow output values
    int64_t nValueOut = 0;
    for (unsigned int i = 0; i < vout.size(); ++i) {
        const CTxOut_impl<T> &txout = vout[i];
        if (txout.IsEmpty() && !IsCoinBase() && !IsCoinStake())
            return DoS(100, print::error("CTransaction_impl<T>::CheckTransaction() : txout empty for user transaction"));
        if (txout.get_nValue() < 0)
            return DoS(100, print::error("CTransaction_impl<T>::CheckTransaction() : txout.nValue is negative"));
        if (txout.get_nValue() > block_params::MAX_MONEY)
            return DoS(100, print::error("CTransaction_impl<T>::CheckTransaction() : txout.nValue too high"));
        nValueOut += txout.get_nValue();
        if (! block_transaction::manage::MoneyRange(nValueOut))
            return DoS(100, print::error("CTransaction_impl<T>::CheckTransaction() : txout total out of range"));
    }

    // Check for duplicate inputs
    std::set<COutPoint_impl<T> > vInOutPoints;
    for(const CTxIn_impl<T> &txin: this->vin) {
        if (vInOutPoints.count(txin.get_prevout()))
            return false;
        vInOutPoints.insert(txin.get_prevout());
    }
    if (IsCoinBase()) {
        if (vin[0].get_scriptSig().size() < 2 || vin[0].get_scriptSig().size() > 100)
            return DoS(100, print::error("CTransaction_impl<T>::CheckTransaction() : coinbase script size is invalid"));
    } else {
        for(const CTxIn_impl<T> &txin: this->vin) {
            if (txin.get_prevout().IsNull())
                return DoS(10, print::error("CTransaction_impl<T>::CheckTransaction() : prevout is null"));
        }
    }

    return true;
}

template <typename T>
bool CTransaction_impl<T>::AcceptToMemoryPool(CTxDB &txdb, bool fCheckInputs/*=true*/, bool *pfMissingInputs/*=NULL*/)
{
    return CTxMemPool_impl<T>::mempool.accept(txdb, *this, fCheckInputs, pfMissingInputs);
}

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
template <typename T>
bool CTransaction_impl<T>::GetCoinAge(CTxDB &txdb, uint64_t &nCoinAge) const
{
    CBigNum bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;
    if (IsCoinBase()) return true;
    for(const CTxIn_impl<T> &txin: this->vin) {
        // First try finding the previous transaction in database
        CTransaction_impl<T> txPrev;
        CTxIndex txindex;
        if (! txPrev.ReadFromDisk(txdb, txin.get_prevout(), txindex))
            continue;  // previous transaction not in main chain
        if (nTime < txPrev.nTime)
            return false;  // Transaction timestamp violation

        // Read block header
        CBlock_impl<T> block;
        if (! block.ReadFromDisk(txindex.get_pos().get_nFile(), txindex.get_pos().get_nBlockPos(), false))
            return false; // unable to read block of previous transaction
        if (block.GetBlockTime() + block_check::nStakeMinAge > nTime)
            continue; // only count coins meeting min age requirement

        int64_t nValueIn = txPrev.vout[txin.get_prevout().get_n()].get_nValue();
        bnCentSecond += CBigNum(nValueIn) * (nTime-txPrev.nTime) / util::CENT;
        if (args_bool::fDebug && map_arg::GetBoolArg("-printcoinage"))
            logging::LogPrintf("coin age nValueIn=%" PRId64 " nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString().c_str());
    }

    CBigNum bnCoinDay = bnCentSecond * util::CENT / util::COIN / util::nOneDay;
    if (args_bool::fDebug && map_arg::GetBoolArg("-printcoinage"))
        logging::LogPrintf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());

    nCoinAge = bnCoinDay.getuint64();
    return true;
}

template <typename T>
const CTxOut_impl<T> &CTransaction_impl<T>::GetOutputFor(const CTxIn_impl<T> &input, const MapPrevTx &inputs) const
{
    MapPrevTx::const_iterator mi = inputs.find(input.get_prevout().get_hash());
    if (mi == inputs.end())
        throw std::runtime_error("CTransaction_impl<T>::GetOutputFor() : prevout.hash not found");

    const CTransaction_impl<T> &txPrev = (mi->second).second;
    if (input.get_prevout().get_n() >= txPrev.vout.size())
        throw std::runtime_error("CTransaction_impl<T>::GetOutputFor() : prevout.n out of range");

    return txPrev.vout[input.get_prevout().get_n()];
}

bool CScriptCheck::operator()() const
{
    const CScript &scriptSig = ptxTo->get_vin(nIn).get_scriptSig();
    if (! Script_util::VerifyScript(scriptSig, scriptPubKey, *ptxTo, nIn, nFlags, nHashType))
        return print::error("CScriptCheck() functor : %s block_check::manage::VerifySignature failed", ptxTo->GetHash().ToString().substr(0,10).c_str());
    return true;
}

// witness(Segwit) programs
template <typename T>
T CTransaction_impl<T>::ComputeHash() const
{
    return hash_basis::SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

template <typename T>
T CTransaction_impl<T>::ComputeWitnessHash() const
{
    if (! HasWitness())
        return hash;
    return hash_basis::SerializeHash(*this, SER_GETHASH, 0);
}

/* For backward compatibility, the hash is initialized to 0.
 * TODO: remove the need for this default constructor entirely. */
//template <typename T>
//CTransaction_impl<T>::CTransaction_impl() : vin(), vout(), nVersion(CTransaction_impl<T>::CURRENT_VERSION), nLockTime(0), hash{}, m_witness_hash{} {}
template <typename T>
CTransaction_impl<T>::CTransaction_impl(const CMutableTransaction_impl<T> &tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
template <typename T>
CTransaction_impl<T>::CTransaction_impl(CMutableTransaction_impl<T> &&tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), nVersion(tx.nVersion), nLockTime(tx.nLockTime), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

template <typename T>
CMutableTransaction_impl<T>::CMutableTransaction_impl() : nVersion(CTransaction_impl<T>::CURRENT_VERSION), nLockTime(0) {}
template <typename T>
CMutableTransaction_impl<T>::CMutableTransaction_impl(const CTransaction_impl<T> &tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime) {}

template <typename T>
T CMutableTransaction_impl<T>::GetHash() const
{
    return hash_basis::SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

template class CTransaction_impl<uint256>;
template class CTxMemPool_impl<uint256>;
template class COutPoint_impl<uint256>;
template class CTxIn_impl<uint256>;
template class CTxOut_impl<uint256>;
template class block_transaction::manage_impl<uint256>;
