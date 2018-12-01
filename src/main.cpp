// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "alert.h"
#include "checkpoints.h"
#include "db.h"
#include "txdb.h"
#include "init.h"
#include "ui_interface.h"
#include "checkqueue.h"
#include "kernel.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include "main.h"

std::multimap<uint256, CBlock *> block_process::manage::mapOrphanBlocksByPrev;
std::set<std::pair<COutPoint, unsigned int> > block_process::manage::setStakeSeenOrphan;
std::map<uint256, CTransaction> block_process::manage::mapOrphanTransactions;
std::map<uint256, std::set<uint256> > block_process::manage::mapOrphanTransactionsByPrev;
CCriticalSection wallet_process::manage::cs_setpwalletRegistered;
CTxMemPool CTxMemPool::mempool;
CBlockIndex *block_transaction::manage::pblockindexFBBHLast = NULL;
CCheckQueue<CScriptCheck> block_check::thread::scriptcheckqueue(128);
CMedianFilter<int> block_process::manage::cPeerBlockCounts(5, 0);
int64_t block_process::manage::nPingInterval = 30 * 60;
const uint64_t file_open::nMinDiskSpace = 52428800;
CBigNum diff::bnProofOfWorkLimit = diff::mainnet::bnProofOfWorkLimit;
CCriticalSection block_process::cs_main;
std::map<uint256, CBlock *> block_process::mapOrphanBlocks;
std::map<uint256, uint256> block_process::mapProofOfStake;
unsigned int block_check::nStakeMinAge = block_check::mainnet::nStakeMinAge;
unsigned int block_check::nStakeTargetSpacing = block_check::mainnet::nStakeTargetSpacing;
unsigned int block_check::nPowTargetSpacing = block_check::mainnet::nPowTargetSpacing;
unsigned int block_check::nModifierInterval = block_check::mainnet::nModifierInterval;
int block_transaction::nCoinbaseMaturity = block_transaction::mainnet::nCoinbaseMaturity;
CScript block_info::COINBASE_FLAGS;
std::map<uint256, CBlockIndex *> block_info::mapBlockIndex;
std::set<std::pair<COutPoint, unsigned int> > block_info::setStakeSeen;
CBlockIndex *block_info::pindexGenesisBlock = NULL;
int64_t block_info::nTimeBestReceived = 0;
std::set<CWallet *> block_info::setpwalletRegistered;
uint64_t block_info::nLastBlockTx = 0;
uint64_t block_info::nLastBlockSize = 0;
uint32_t block_info::nLastCoinStakeSearchInterval = 0;
int block_info::nBestHeight = -1;
uint256 block_info::nBestChainTrust = 0;
uint256 block_info::nBestInvalidTrust = 0;
uint256 block_info::hashBestChain = 0;
CBlockIndex *block_info::pindexBest = NULL;
unsigned int block_info::nTransactionsUpdated = 0;
int64_t block_info::nTransactionFee = block_param::MIN_TX_FEE;
int64_t block_info::nMinimumInputValue = block_param::MIN_TXOUT_AMOUNT;
int block_info::nScriptCheckThreads = 0;

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// main.cpp dispatching functions
//
///////////////////////////////////////////////////////////////////////////////////////////////////

//
// These functions dispatch to one or all registered wallets
//
void wallet_process::manage::RegisterWallet(CWallet *pwalletIn)
{
    {
        LOCK(wallet_process::manage::cs_setpwalletRegistered);
        block_info::setpwalletRegistered.insert(pwalletIn);
    }
}

void wallet_process::manage::UnregisterWallet(CWallet *pwalletIn)
{
    {
        LOCK(wallet_process::manage::cs_setpwalletRegistered);
        block_info::setpwalletRegistered.erase(pwalletIn);
    }
}

// check whether the passed transaction is from us
bool CTxMemPool::IsFromMe(CTransaction &tx)
{
    BOOST_FOREACH(CWallet *pwallet, block_info::setpwalletRegistered)
    {
        if (pwallet->IsFromMe(tx)) {
            return true;
        }
    }
    return false;
}

// erases transaction with the given hash from all wallets
void CTxMemPool::EraseFromWallets(uint256 hash)
{
    BOOST_FOREACH(CWallet *pwallet, block_info::setpwalletRegistered)
    {
        pwallet->EraseFromWallet(hash);
    }
}

// make sure all wallets know about the given transaction, in the given block
void wallet_process::manage::SyncWithWallets(const CTransaction &tx, const CBlock *pblock /*= NULL*/, bool fUpdate/*= false*/, bool fConnect/*= true*/)
{
    if (! fConnect) {
        // wallets need to refund inputs when disconnecting coinstake
        if (tx.IsCoinStake()) {
            BOOST_FOREACH(CWallet *pwallet, block_info::setpwalletRegistered)
            {
                if (pwallet->IsFromMe(tx)) {
                    pwallet->DisableTransaction(tx);
                }
            }
        }
        return;
    }

    BOOST_FOREACH(CWallet *pwallet, block_info::setpwalletRegistered)
    {
        pwallet->AddToWalletIfInvolvingMe(tx, pblock, fUpdate);
    }
}

//
// notify wallets about a new best chain
//
void block_notify::SetBestChain(const CBlockLocator &loc)
{
    BOOST_FOREACH(CWallet *pwallet, block_info::setpwalletRegistered)
    {
        pwallet->SetBestChain(loc);
    }
}

//
// notify wallets about an updated transaction
//
void block_notify::UpdatedTransaction(const uint256 &hashTx)
{
    BOOST_FOREACH(CWallet *pwallet, block_info::setpwalletRegistered)
    {
        pwallet->UpdatedTransaction(hashTx);
    }
}

//
// dump all wallets
//
void block_notify::PrintWallets(const CBlock &block)
{
    BOOST_FOREACH(CWallet *pwallet, block_info::setpwalletRegistered)
    {
        pwallet->PrintWallet(block);
    }
}

// notify wallets about an incoming inventory (for request counts)
void block_process::manage::Inventory(const uint256 &hash)
{
    BOOST_FOREACH(CWallet *pwallet, block_info::setpwalletRegistered)
    {
        pwallet->Inventory(hash);
    }
}

// ask wallets to resend their transactions
void block_process::manage::ResendWalletTransactions(bool fForceResend /*= false*/)
{
    BOOST_FOREACH(CWallet *pwallet, block_info::setpwalletRegistered)
    {
        pwallet->ResendWalletTransactions(fForceResend);
    }
}

//
// mapOrphanTransactions
//
bool block_process::manage::AddOrphanTx(const CTransaction &tx)
{
    uint256 hash = tx.GetHash();
    if (block_process::manage::mapOrphanTransactions.count(hash)) {
        return false;
    }

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is at most 500 megabytes of orphans

    size_t nSize = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);
    if (nSize > block_transaction::MAX_ORPHAN_SERIALIZESIZE) {
        printf("ignoring large orphan tx (size: %" PRIszu ", hash: %s)\n", nSize, hash.ToString().substr(0,10).c_str());
        return false;
    }

    block_process::manage::mapOrphanTransactions[hash] = tx;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        block_process::manage::mapOrphanTransactionsByPrev[txin.prevout.hash].insert(hash);
    }

    printf("stored orphan tx %s (mapsz %" PRIszu ")\n", hash.ToString().substr(0,10).c_str(), mapOrphanTransactions.size());
    return true;
}

void block_process::manage::EraseOrphanTx(uint256 hash)
{
    if (! block_process::manage::mapOrphanTransactions.count(hash)) {
        return;
    }

    const CTransaction &tx = block_process::manage::mapOrphanTransactions[hash];
    BOOST_FOREACH(const CTxIn &txin, tx.vin)
    {
        block_process::manage::mapOrphanTransactionsByPrev[txin.prevout.hash].erase(hash);
        if (block_process::manage::mapOrphanTransactionsByPrev[txin.prevout.hash].empty()) {
            block_process::manage::mapOrphanTransactionsByPrev.erase(txin.prevout.hash);
        }
    }
    block_process::manage::mapOrphanTransactions.erase(hash);
}

unsigned int block_process::manage::LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;
    while (block_process::manage::mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = bitsystem::GetRandHash();
        std::map<uint256, CTransaction>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end()) {
            it = mapOrphanTransactions.begin();
        }
        block_process::manage::EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}

//
// CTransaction and CTxIndex
//
bool CTransaction::ReadFromDisk(CTxDB &txdb, COutPoint prevout, CTxIndex &txindexRet)
{
    SetNull();
    if (! txdb.ReadTxIndex(prevout.hash, txindexRet)) {
        return false;
    }
    if (! ReadFromDisk(txindexRet.pos)) {
        return false;
    }
    if (prevout.n >= vout.size()) {
        SetNull();
        return false;
    }
    return true;
}

bool CTransaction::ReadFromDisk(CTxDB &txdb, COutPoint prevout)
{
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}

bool CTransaction::ReadFromDisk(COutPoint prevout)
{
    CTxDB txdb("r");
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}

bool CTransaction::IsStandard(std::string &strReason) const
{
    if (nVersion > CTransaction::CURRENT_VERSION) {
        strReason = "version";
        return false;
    }

    unsigned int nDataOut = 0;
    TxnOutputType::txnouttype whichType;
    BOOST_FOREACH(const CTxIn &txin, vin)
    {
        //
        // Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed
        // keys. (remember the 520 byte limit on redeemScript size) That works
        // out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)=1624
        // bytes of scriptSig, which we round off to 1650 bytes for some minor
        // future-proofing. That's also enough to spend a 20-of-20
        // CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not considered standard)
        //
        if (txin.scriptSig.size() > 1650) {
            strReason = "scriptsig-size";
            return false;
        }
        if (! txin.scriptSig.IsPushOnly()) {
            strReason = "scriptsig-not-pushonly";
            return false;
        }
        if (! txin.scriptSig.HasCanonicalPushes()) {
            strReason = "txin-scriptsig-not-canonicalpushes";
            return false;
        }
    }

    BOOST_FOREACH(const CTxOut &txout, vout)
    {
        // if (!::IsStandard(txout.scriptPubKey, whichType)) {
        if (! Script_util::IsStandard(txout.scriptPubKey, whichType)) {
            strReason = "scriptpubkey";
            return false;
        }
        if (whichType == TxnOutputType::TX_NULL_DATA) {
            nDataOut++;
        } else {
            if (txout.nValue == 0) {
                strReason = "txout-value=0";
                return false;
            }
            if (! txout.scriptPubKey.HasCanonicalPushes()) {
                strReason = "txout-scriptsig-not-canonicalpushes";
                return false;
            }
        }
    }

    //
    // only one OP_RETURN txout is permitted
    //
    if (nDataOut > 1) {
        strReason = "multi-op-return";
        return false;
    }

    return true;
}

//
// Check transaction inputs, and make sure any
// pay-to-script-hash transactions are evaluating IsStandard scripts
//
// Why bother? To avoid denial-of-service attacks; an attacker
// can submit a standard HASH... OP_EQUAL transaction,
// which will get accepted into blocks. The redemption
// script can be anything; an attacker could use a very
// expensive-to-check-upon-redemption script like:
//   DUP CHECKSIG DROP ... repeated 100 times... OP_1
//
bool CTransaction::AreInputsStandard(const MapPrevTx &mapInputs) const
{
    if (IsCoinBase()) {
        return true; // Coinbases don't use vin normally
    }

    for (unsigned int i = 0; i < vin.size(); ++i)
    {
        const CTxOut &prev = GetOutputFor(vin[i], mapInputs);

        std::vector<std::vector<unsigned char> > vSolutions;
        TxnOutputType::txnouttype whichType;

        //
        // get the scriptPubKey corresponding to this input:
        //
        const CScript &prevScript = prev.scriptPubKey;
        if (! Script_util::Solver(prevScript, whichType, vSolutions)) {
            return false;
        }

        int nArgsExpected = Script_util::ScriptSigArgsExpected(whichType, vSolutions);
        if (nArgsExpected < 0) {
            return false;
        }

        //
        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig the
        // IsStandard() call returns false
        //
        std::vector<std::vector<unsigned char> > stack;
        if (! Script_util::EvalScript(stack, vin[i].scriptSig, *this, i, false, 0)) {
            return false;
        }

        if (whichType == TxnOutputType::TX_SCRIPTHASH) {
            if (stack.empty()) {
                return false;
            }

            CScript subscript(stack.back().begin(), stack.back().end());
            std::vector<std::vector<unsigned char> > vSolutions2;
            TxnOutputType::txnouttype whichType2;
            if (! Script_util::Solver(subscript, whichType2, vSolutions2)) {
                return false;
            }
            if (whichType2 == TxnOutputType::TX_SCRIPTHASH) {
                return false;
            }

            int tmpExpected = Script_util::ScriptSigArgsExpected(whichType2, vSolutions2);
            if (tmpExpected < 0) {
                return false;
            }
            nArgsExpected += tmpExpected;
        }

        if (stack.size() != (unsigned int)nArgsExpected) {
            return false;
        }
    }

    return true;
}

unsigned int CTransaction::GetLegacySigOpCount() const
{
    unsigned int nSigOps = 0;
    if (! IsCoinBase()) {
        //
        // Coinbase scriptsigs are never executed, so there is no sense in calculation of sigops.
        //
        BOOST_FOREACH(const CTxIn &txin, this->vin)
        {
            nSigOps += txin.scriptSig.GetSigOpCount(false);
        }
    }

    BOOST_FOREACH(const CTxOut &txout, this->vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

int CMerkleTx::SetMerkleBranch(const CBlock *pblock/*=NULL*/)
{
    if (args_bool::fClient) {
        if (hashBlock == 0) {
            return 0;
        }
    } else {
        CBlock blockTmp;

        if (pblock == NULL) {
            //
            // Load the block this tx is in
            //
            CTxIndex txindex;
            if (! CTxDB("r").ReadTxIndex(GetHash(), txindex)) {
                return 0;
            }
            if (! blockTmp.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos)) {
                return 0;
            }
            pblock = &blockTmp;
        }

        //
        // Update the tx's hashBlock
        //
        hashBlock = pblock->GetHash();

        //
        // Locate the transaction
        //
        for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
        {
            if (pblock->vtx[nIndex] == *(CTransaction*)this) {
                break;
            }
        }
        if (nIndex == (int)pblock->vtx.size()) {
            vMerkleBranch.clear();
            nIndex = -1;
            printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
    }

    //
    // Is the tx in a block that's in the main chain
    //
    std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hashBlock);
    if (mi == block_info::mapBlockIndex.end()) {
        return 0;
    }

    const CBlockIndex *pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain()) {
        return 0;
    }

    return block_info::pindexBest->nHeight - pindex->nHeight + 1;
}

bool CTransaction::CheckTransaction() const
{
    //
    // Basic checks that don't depend on any context
    //
    if (vin.empty()) {
        return DoS(10, print::error("CTransaction::CheckTransaction() : vin empty"));
    }
    if (vout.empty()) {
        return DoS(10, print::error("CTransaction::CheckTransaction() : vout empty"));
    }

    //
    // Size limits
    //
    if (::GetSerializeSize(*this, SER_NETWORK, version::PROTOCOL_VERSION) > block_param::MAX_BLOCK_SIZE) {
        return DoS(100, print::error("CTransaction::CheckTransaction() : size limits failed"));
    }

    //
    // Check for negative or overflow output values
    //
    int64_t nValueOut = 0;
    for (unsigned int i = 0; i < vout.size(); ++i)
    {
        const CTxOut &txout = vout[i];
        if (txout.IsEmpty() && !IsCoinBase() && !IsCoinStake()) {
            return DoS(100, print::error("CTransaction::CheckTransaction() : txout empty for user transaction"));
        }

        if (txout.nValue < 0) {
            return DoS(100, print::error("CTransaction::CheckTransaction() : txout.nValue is negative"));
        }
        if (txout.nValue > block_param::MAX_MONEY) {
            return DoS(100, print::error("CTransaction::CheckTransaction() : txout.nValue too high"));
        }

        nValueOut += txout.nValue;
        if (! block_transaction::manage::MoneyRange(nValueOut)) {
            return DoS(100, print::error("CTransaction::CheckTransaction() : txout total out of range"));
        }
    }

    //
    // Check for duplicate inputs
    //
    std::set<COutPoint> vInOutPoints;
    BOOST_FOREACH(const CTxIn &txin, this->vin)
    {
        if (vInOutPoints.count(txin.prevout)) {
            return false;
        }
        vInOutPoints.insert(txin.prevout);
    }

    if (IsCoinBase()) {
        if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100) {
            return DoS(100, print::error("CTransaction::CheckTransaction() : coinbase script size is invalid"));
        }
    } else {
        BOOST_FOREACH(const CTxIn &txin, this->vin)
        {
            if (txin.prevout.IsNull()) {
                return DoS(10, print::error("CTransaction::CheckTransaction() : prevout is null"));
            }
        }
    }

    return true;
}

int64_t CTransaction::GetMinFee(unsigned int nBlockSize/*=1*/, bool fAllowFree/*=false*/, enum GetMinFee_mode mode/*=GMF_BLOCK*/, unsigned int nBytes/*=0*/) const
{
    int64_t nMinTxFee = block_param::MIN_TX_FEE, nMinRelayTxFee = block_param::MIN_RELAY_TX_FEE;

    if(IsCoinStake()) {
        //
        // Enforce 0.01 as minimum fee for coinstake
        //
        nMinTxFee = util::CENT;
        nMinRelayTxFee = util::CENT;
    }

    // Base fee is either nMinTxFee or nMinRelayTxFee
    int64_t nBaseFee = (mode == GMF_RELAY) ? nMinRelayTxFee : nMinTxFee;

    unsigned int nNewBlockSize = nBlockSize + nBytes;
    int64_t nMinFee = (1 + (int64_t)nBytes / 1000) * nBaseFee;

    if (fAllowFree) {
        if (nBlockSize == 1) {
            //
            // Transactions under 1K are free
            //
            if (nBytes < 1000) {
                nMinFee = 0;
            }
        } else {
            //
            // Free transaction area
            //
            if (nNewBlockSize < 27000) {
                nMinFee = 0;
            }
        }
    }

    //
    // To limit dust spam, require additional block_param::MIN_TX_FEE/block_param::MIN_RELAY_TX_FEE for
    //    each non empty output which is less than 0.01
    //
    // It's safe to ignore empty outputs here, because these inputs are allowed only for coinbase and coinstake transactions.
    //
    BOOST_FOREACH(const CTxOut &txout, vout)
    {
        if (txout.nValue < util::CENT && !txout.IsEmpty()) {
            nMinFee += nBaseFee;
        }
    }

    //
    // Raise the price as the block approaches full
    //
    if (nBlockSize != 1 && nNewBlockSize >= block_param::MAX_BLOCK_SIZE_GEN / 2) {
        if (nNewBlockSize >= block_param::MAX_BLOCK_SIZE_GEN) {
            return block_param::MAX_MONEY;
        }
        
        nMinFee *= block_param::MAX_BLOCK_SIZE_GEN / (block_param::MAX_BLOCK_SIZE_GEN - nNewBlockSize);
    }

    if (! block_transaction::manage::MoneyRange(nMinFee)) {
        nMinFee = block_param::MAX_MONEY;
    }

    return nMinFee;
}

bool CTxMemPool::accept(CTxDB &txdb, CTransaction &tx, bool fCheckInputs, bool *pfMissingInputs)
{
    if (pfMissingInputs) {
        *pfMissingInputs = false;
    }

    // Time (prevent mempool memory exhaustion attack)
    if (tx.nTime > block_check::manage::FutureDrift(bitsystem::GetAdjustedTime())) {
        return tx.DoS(10, print::error("CTxMemPool::accept() : transaction timestamp is too far in the future"));
    }

    if (! tx.CheckTransaction()) {
        return print::error("CTxMemPool::accept() : CheckTransaction failed");
    }

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase()) {
        return tx.DoS(100, print::error("CTxMemPool::accept() : coinbase as individual tx"));
    }

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake()) {
        return tx.DoS(100, print::error("CTxMemPool::accept() : coinstake as individual tx"));
    }

    // To help v0.1.5 clients who would see it as a negative number
    if ((int64_t)tx.nLockTime > std::numeric_limits<int>::max()) {
        return print::error("CTxMemPool::accept() : not accepting nLockTime beyond 2038 yet");
    }

    // Rather not work on nonstandard transactions (unless -testnet)
    std::string strNonStd;
    if (!args_bool::fTestNet && !tx.IsStandard(strNonStd)) {
        return print::error("CTxMemPool::accept() : nonstandard transaction (%s)", strNonStd.c_str());
    }

    // Do we already have it?
    uint256 hash = tx.GetHash();
    {
        LOCK(cs);
        if (mapTx.count(hash)) {
            return false;
        }
    }
    if (fCheckInputs) {
        if (txdb.ContainsTx(hash)) {
            return false;
        }
    }

    //
    // Check for conflicts with in-memory transactions
    // replacing with a newer version, ptxOld insert mapNextTx[outpoint].
    //
    CTransaction *ptxOld = NULL;
    for (unsigned int i = 0; i < tx.vin.size(); ++i)
    {
        COutPoint outpoint = tx.vin[i].prevout;
        if (mapNextTx.count(outpoint)) {
            //
            // Disable replacement feature for now
            //
            return false;
            //////////////////////////////////////

            //
            // Allow replacing with a newer version of the same transaction.
            //
            if (i != 0) {
                return false;
            }

            ptxOld = mapNextTx[outpoint].ptx;
            if (ptxOld->IsFinal()) {
                return false;
            }
            if (! tx.IsNewerThan(*ptxOld)) {
                return false;
            }
            for (unsigned int i = 0; i < tx.vin.size(); ++i)
            {
                COutPoint outpoint = tx.vin[i].prevout;
                if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].ptx != ptxOld) {
                    return false;
                }
            }
            break;
        }
    }

    if (fCheckInputs) {
        MapPrevTx mapInputs;
        std::map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        if (! tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid)) {
            if (fInvalid) {
                return print::error("CTxMemPool::accept() : FetchInputs found invalid tx %s", hash.ToString().substr(0,10).c_str());
            }
            if (pfMissingInputs) {
                *pfMissingInputs = true;
            }
            return false;
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (!tx.AreInputsStandard(mapInputs) && !args_bool::fTestNet) {
            return print::error("CTxMemPool::accept() : nonstandard transaction input");
        }

        //
        // Note: if you modify this code to accept non-standard transactions, then
        // you should add code here to check that the transaction does a
        // reasonable number of ECDSA signature verifications.
        //
        int64_t nFees = tx.GetValueIn(mapInputs) - tx.GetValueOut();
        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, version::PROTOCOL_VERSION);

        // Don't accept it if it can't get into a block
        int64_t txMinFee = tx.GetMinFee(1000, true, CTransaction::GMF_RELAY, nSize);
        if (nFees < txMinFee) {
            return print::error("CTxMemPool::accept() : not enough fees %s, %" PRId64 " < %" PRId64, hash.ToString().c_str(), nFees, txMinFee);
        }

        // Continuously rate-limit free transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (nFees < block_param::MIN_RELAY_TX_FEE) {

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
                if (dFreeCount > map_arg::GetArg("-limitfreerelay", 15) * 10 * 1000 && !IsFromMe(tx)) {
                    return print::error("CTxMemPool::accept() : free transaction rejected by rate limiter");
                }
                if (args_bool::fDebug) {
                    printf("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
                }
                dFreeCount += nSize;
            }
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (! tx.ConnectInputs(txdb, mapInputs, mapUnused, CDiskTxPos(1,1,1), block_info::pindexBest, false, false, true, Script_param::STRICT_FLAGS)) {
            return print::error("CTxMemPool::accept() : ConnectInputs failed %s", hash.ToString().substr(0,10).c_str());
        }
    }

    //
    // Store transaction in memory
    //
    {
        LOCK(cs);
        if (ptxOld) {
            printf("CTxMemPool::accept() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
            remove(*ptxOld);
        }
        addUnchecked(hash, tx);
    }

    //
    // are we sure this is ok when loading transactions or restoring block txes
    // If updated, erase old tx from wallet
    //
    if (ptxOld) {
        EraseFromWallets(ptxOld->GetHash());
    }

    printf("CTxMemPool::accept() : accepted %s (poolsz %" PRIszu ")\n", hash.ToString().substr(0,10).c_str(), mapTx.size());
    return true;
}

bool CTransaction::AcceptToMemoryPool(CTxDB &txdb, bool fCheckInputs/*=true*/, bool *pfMissingInputs/*=NULL*/)
{
    return CTxMemPool::mempool.accept(txdb, *this, fCheckInputs, pfMissingInputs);
}

bool CTxMemPool::addUnchecked(const uint256 &hash, CTransaction &tx)
{
    //
    // Add to memory pool without checking anything.  Don't call this directly,
    // call CTxMemPool::accept to properly check the transaction first.
    //
    {
        mapTx[hash] = tx;
        for (unsigned int i = 0; i < tx.vin.size(); ++i)
        {
            mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTx[hash], i);
        }
        block_info::nTransactionsUpdated++;
    }
    return true;
}

bool CTxMemPool::remove(CTransaction &tx)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        uint256 hash = tx.GetHash();
        if (mapTx.count(hash)) {
            BOOST_FOREACH(const CTxIn &txin, tx.vin)
            {
                mapNextTx.erase(txin.prevout);
            }
            
            mapTx.erase(hash);
            block_info::nTransactionsUpdated++;
        }
    }
    return true;
}

void CTxMemPool::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapNextTx.clear();
    ++block_info::nTransactionsUpdated;
}

void CTxMemPool::queryHashes(std::vector<uint256> &vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (std::map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
    {
        vtxid.push_back((*mi).first);
    }
}

int CMerkleTx::GetDepthInMainChain(CBlockIndex *&pindexRet) const
{
    if (hashBlock == 0 || nIndex == -1) {
        return 0;
    }

    //
    // Find the block it claims to be in
    //
    std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hashBlock);
    if (mi == block_info::mapBlockIndex.end()) {
        return 0;
    }

    CBlockIndex *pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain()) {
        return 0;
    }

    //
    // Make sure the merkle branch connects to this block
    //
    if (! fMerkleVerified) {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot) {
            return 0;
        }
        fMerkleVerified = true;
    }

    pindexRet = pindex;
    return block_info::pindexBest->nHeight - pindex->nHeight + 1;
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!(IsCoinBase() || IsCoinStake())) {
        return 0;
    }

    return std::max(0, (block_transaction::nCoinbaseMaturity + 0) - GetDepthInMainChain());
}

bool CMerkleTx::AcceptToMemoryPool(CTxDB &txdb, bool fCheckInputs/*=true*/)
{
    if (args_bool::fClient) {
        if (!IsInMainChain() && !ClientConnectInputs()) {
            return false;
        }
        return CTransaction::AcceptToMemoryPool(txdb, false);
    } else {
        return CTransaction::AcceptToMemoryPool(txdb, fCheckInputs);
    }
}

bool CMerkleTx::AcceptToMemoryPool()
{
    CTxDB txdb("r");
    return AcceptToMemoryPool(txdb);
}

bool CWalletTx::AcceptWalletTransaction(CTxDB &txdb, bool fCheckInputs)
{
    {
        LOCK(CTxMemPool::mempool.cs);

        //
        // Add previous supporting transactions first
        //
        BOOST_FOREACH(CMerkleTx &tx, this->vtxPrev)
        {
            if (!(tx.IsCoinBase() || tx.IsCoinStake())) {
                uint256 hash = tx.GetHash();
                if (!CTxMemPool::mempool.exists(hash) && !txdb.ContainsTx(hash)) {
                    tx.AcceptToMemoryPool(txdb, fCheckInputs);
                }
            }
        }
        return AcceptToMemoryPool(txdb, fCheckInputs);
    }
    return false;
}

bool CWalletTx::AcceptWalletTransaction()
{
    CTxDB txdb("r");
    return AcceptWalletTransaction(txdb);
}

int CTxIndex::GetDepthInMainChain() const
{
    // Read block header
    CBlock block;
    if (! block.ReadFromDisk(pos.nFile, pos.nBlockPos, false)) {
        return 0;
    }

    // Find the block in the index
    std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(block.GetHash());
    if (mi == block_info::mapBlockIndex.end()) {
        return 0;
    }

    CBlockIndex *pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain()) {
        return 0;
    }

    return 1 + block_info::nBestHeight - pindex->nHeight;
}

//
// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
//
bool block_transaction::manage::GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock)
{
    {
        LOCK(block_process::cs_main);
        {
            LOCK(CTxMemPool::mempool.cs);
            if (CTxMemPool::mempool.exists(hash)) {
                tx = CTxMemPool::mempool.lookup(hash);
                return true;
            }
        }

        CTxDB txdb("r");
        CTxIndex txindex;
        if (tx.ReadFromDisk(txdb, COutPoint(hash, 0), txindex)) {
            CBlock block;
            if (block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false)) {
                hashBlock = block.GetHash();
            }
            return true;
        }
    }
    return false;
}

//
// CBlock and CBlockIndex
//
CBlockIndex *block_transaction::manage::FindBlockByHeight(int nHeight)
{
    CBlockIndex *pblockindex;
    if (nHeight < block_info::nBestHeight / 2) {
        pblockindex = block_info::pindexGenesisBlock;
    } else {
        pblockindex = block_info::pindexBest;
    }

    if (pblockindexFBBHLast && abs(nHeight - pblockindex->nHeight) > abs(nHeight - pblockindexFBBHLast->nHeight)) {
        pblockindex = pblockindexFBBHLast;
    }
    while (pblockindex->nHeight > nHeight)
    {
        pblockindex = pblockindex->pprev;
    }
    while (pblockindex->nHeight < nHeight)
    {
        pblockindex = pblockindex->pnext;
    }

    pblockindexFBBHLast = pblockindex;
    return pblockindex;
}

bool CBlock::ReadFromDisk(const CBlockIndex *pindex, bool fReadTransactions/*=true*/)
{
    if (! fReadTransactions) {
        *this = pindex->GetBlockHeader();
        return true;
    }
    if (! ReadFromDisk(pindex->nFile, pindex->nBlockPos, fReadTransactions)) {
        return false;
    }
    if (GetHash() != pindex->GetBlockHash()) {
        return print::error("CBlock::ReadFromDisk() : GetHash() doesn't match index");
    }
    return true;
}

//
// ppcoin: find block wanted by given orphan block
//
uint256 block_process::manage::GetOrphanRoot(const CBlock *pblock)
{
    // Work back to the first block in the orphan chain
    while (block_process::mapOrphanBlocks.count(pblock->hashPrevBlock))
    {
        pblock = block_process::mapOrphanBlocks[pblock->hashPrevBlock];
    }
    return pblock->GetHash();
}

uint256 block_process::manage::WantedByOrphan(const CBlock *pblockOrphan)
{
    // Work back to the first block in the orphan chain
    while (block_process::mapOrphanBlocks.count(pblockOrphan->hashPrevBlock))
    {
        pblockOrphan = block_process::mapOrphanBlocks[pblockOrphan->hashPrevBlock];
    }
    return pblockOrphan->hashPrevBlock;
}

//
// miner's coin base reward based on nBits
//
int64_t diff::reward::GetProofOfWorkReward(unsigned int nBits, int64_t nFees /*= 0*/)
{
    int64_t nSubsidy = block_param::MAX_MINT_PROOF_OF_WORK;

    if (block_info::nBestHeight == 0) {
        nSubsidy = block_param::COIN_PREMINE;
    } else {
        for(std::list<std::pair<int, int64_t> >::const_iterator it = blockreward::POW_REWARD_BLOCK.begin(); it != blockreward::POW_REWARD_BLOCK.end(); ++it)
        {
            std::pair<int, int64_t> data1 = *it;
            nSubsidy = data1.second;

            std::list<std::pair<int, int64_t> >::const_iterator next = it; ++next;
            if(next == blockreward::POW_REWARD_BLOCK.end()) {
                break;
            }

            std::pair<int, int64_t> data2 = *next;
            if(data1.first <= block_info::nBestHeight && block_info::nBestHeight < data2.first) {
                break;
            }
        }
    }
    //printf("diff::reward::GetProofOfWork nSubsidy_%" PRId64 "\n", nSubsidy);

    if (args_bool::fDebug && map_arg::GetBoolArg("-printcreation")) {
        printf("diff::reward::GetProofOfWorkReward() : create=%s nSubsidy=%" PRId64 "\n", bitstr::FormatMoney(nSubsidy).c_str(), nSubsidy);
    }
    return nSubsidy + nFees;
}

//
// miner's coin stake reward based on nBits and coin age spent (coin-days)
//
int64_t diff::reward::GetProofOfStakeReward(int64_t nCoinAge, unsigned int nBits, int64_t nTime, bool bCoinYearOnly /*= false*/)
{
    int64_t nReward = block_param::COIN_YEAR_REWARD;
    int64_t bTime = bitsystem::GetTime();
    for(std::list<std::pair<unsigned int, int64_t> >::const_iterator it = blockreward::POS_REWARD_BLOCK.begin(); it != blockreward::POS_REWARD_BLOCK.end(); ++it)
    {
        std::pair<unsigned int, int64_t> data1 = *it;
        nReward = data1.second;

        std::list<std::pair<unsigned int, int64_t> >::const_iterator next = it; ++next;
        if(next == blockreward::POS_REWARD_BLOCK.end()) {
            break;
        }

        std::pair<unsigned int, int64_t> data2 = *next;
        if(data1.first <= bTime && bTime < data2.first) {
            break;
        }
    }
    //printf("diff::reward::GetProofOfStakeReward nReward_%" PRId64 "\n", nReward);

    int64_t nSubsidy = nCoinAge * nReward * 33 / (365 * 33 + 8);

    if (args_bool::fDebug && map_arg::GetBoolArg("-printcreation")) {
        printf("diff::reward::GetProofOfStakeReward(): create=%s nCoinAge=%" PRId64 "\n", bitstr::FormatMoney(nSubsidy).c_str(), nCoinAge);
    }
    return nSubsidy;
}

//
// get proof of work blocks max spacing according to hard-coded conditions
//
int64_t diff::spacing::GetTargetSpacingWorkMax(int nHeight, unsigned int nTime)
{
    if(nTime < timestamps::TARGETS_SWITCH_WORK) {
        return 3 * block_check::nPowTargetSpacing;
    }

    if(args_bool::fTestNet) {
        return 1 * block_check::nPowTargetSpacing;
    } else {
        return 2 * block_check::nPowTargetSpacing;
    }
}

//
// maximum nBits value could possible be required nTime after
//
unsigned int diff::amount::ComputeMaxBits(CBigNum bnTargetLimit, unsigned int nBase, int64_t nTime)
{
    CBigNum bnResult;
    bnResult.SetCompact(nBase);
    bnResult *= 2;
    while (nTime > 0 && bnResult < bnTargetLimit)
    {
        bnResult *= 2;        // Maximum 200% adjustment per day...
        nTime -= util::nOneDay;
    }
    if (bnResult > bnTargetLimit) {
        bnResult = bnTargetLimit;
    }
    return bnResult.GetCompact();
}

//
// select stake target limit according to hard-coded conditions
//
CBigNum diff::amount::GetProofOfStakeLimit(int nHeight, unsigned int nTime)
{
    if(args_bool::fTestNet) {
        return diff::bnProofOfStakeLimit;
    } else {
        if(nTime > timestamps::TARGETS_SWITCH_WORK) {
            return diff::bnProofOfStakeLimit;
        }
        return diff::bnProofOfWorkLimit;                     // return bnProofOfWorkLimit(PoW_Limit) of none matched
    }
}

//
// minimum amount of work that could possibly be required nTime after
// minimum proof-of-work required was nBase
//
unsigned int diff::amount::ComputeMinWork(unsigned int nBase, int64_t nTime)
{
    return diff::amount::ComputeMaxBits(diff::bnProofOfWorkLimit, nBase, nTime);
}

//
// minimum amount of stake that could possibly be required nTime after
// minimum proof-of-stake required was nBase
//
unsigned int diff::amount::ComputeMinStake(unsigned int nBase, int64_t nTime, unsigned int nBlockTime)
{
    return diff::amount::ComputeMaxBits(diff::amount::GetProofOfStakeLimit(0, nBlockTime), nBase, nTime);
}

//
// ppcoin: find last block index up to pindex
//
const CBlockIndex *diff::spacing::GetLastBlockIndex(const CBlockIndex *pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
    {
        pindex = pindex->pprev;
    }
    return pindex;
}

unsigned int diff::spacing::GetNextTargetRequired(const CBlockIndex *pindexLast, bool fProofOfStake)
{
    CBigNum bnTargetLimit = fProofOfStake ? diff::bnProofOfStakeLimit : diff::bnProofOfWorkLimit;
    if (pindexLast == NULL) {
        return bnTargetLimit.GetCompact();        // genesis block
    }

    const CBlockIndex *pindexPrev = diff::spacing::GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == NULL) {
        return bnTargetLimit.GetCompact();        // first block
    }

    const CBlockIndex *pindexPrevPrev = diff::spacing::GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == NULL) {
        return bnTargetLimit.GetCompact();        // second block
    }

    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    CBigNum bnNew;
    bnNew.SetCompact(pindexPrev->nBits);

    int64_t nTargetSpacing = fProofOfStake ? block_check::nStakeTargetSpacing :
                                            std::min( diff::spacing::GetTargetSpacingWorkMax(pindexLast->nHeight, pindexLast->nTime), (int64_t)block_check::nStakeTargetSpacing * (1 + pindexLast->nHeight - pindexPrev->nHeight) );

    int64_t nInterval = block_check::nTargetTimespan / nTargetSpacing;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);

    if (bnNew > bnTargetLimit) {
        bnNew = bnTargetLimit;
    }
    return bnNew.GetCompact();
}

bool diff::check::CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    // Check range
    if (bnTarget <= 0 || bnTarget > diff::bnProofOfWorkLimit) {
        return print::error("diff::check::CheckProofOfWork() : nBits below minimum work");
    }

    // Check proof of work matches claimed amount
    if (hash > bnTarget.getuint256()) {
        return print::error("diff::check::CheckProofOfWork() : hash doesn't match nBits");
    }

    return true;
}

//
// Return maximum amount of blocks that other nodes claim to have
//
int block_process::manage::GetNumBlocksOfPeers()
{
    return std::max(cPeerBlockCounts.median(), Checkpoints::manage::GetTotalBlocksEstimate());
}

bool block_process::manage::IsInitialBlockDownload()
{
    if (block_info::pindexBest == NULL || block_info::nBestHeight < Checkpoints::manage::GetTotalBlocksEstimate()) {
        return true;
    }

    static int64_t nLastUpdate = 0;
    static CBlockIndex *pindexLastBest = NULL;

    int64_t nCurrentTime = bitsystem::GetTime();
    if (block_info::pindexBest != pindexLastBest) {
        pindexLastBest = block_info::pindexBest;
        nLastUpdate = nCurrentTime;
    }
    return (nCurrentTime - nLastUpdate < 10 && block_info::pindexBest->GetBlockTime() < nCurrentTime - util::nOneDay);
}

void block_check::manage::InvalidChainFound(CBlockIndex *pindexNew)
{
    if (pindexNew->nChainTrust > block_info::nBestInvalidTrust) {
        block_info::nBestInvalidTrust = pindexNew->nChainTrust;
        CTxDB().WriteBestInvalidTrust(CBigNum(block_info::nBestInvalidTrust));
        CClientUIInterface::uiInterface.NotifyBlocksChanged();
    }

    uint256 nBestInvalidBlockTrust = pindexNew->nChainTrust - pindexNew->pprev->nChainTrust;
    uint256 nBestBlockTrust = block_info::pindexBest->nHeight != 0 ? (block_info::pindexBest->nChainTrust - block_info::pindexBest->pprev->nChainTrust) : block_info::pindexBest->nChainTrust;

    printf("block_check::manage::InvalidChainFound: invalid block=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
            pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight,
            CBigNum(pindexNew->nChainTrust).ToString().c_str(), nBestInvalidBlockTrust.Get64(),
            util::DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()).c_str());
    printf("block_check::manage::InvalidChainFound:  current best=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
            block_info::hashBestChain.ToString().substr(0,20).c_str(), block_info::nBestHeight,
            CBigNum(block_info::pindexBest->nChainTrust).ToString().c_str(),
            nBestBlockTrust.Get64(),
            util::DateTimeStrFormat("%x %H:%M:%S", block_info::pindexBest->GetBlockTime()).c_str());
}

void CBlock::UpdateTime(const CBlockIndex *pindexPrev)
{
    nTime = std::max(GetBlockTime(), bitsystem::GetAdjustedTime());
}

bool CTransaction::DisconnectInputs(CTxDB &txdb)
{
    //
    // Relinquish previous transactions' spent pointers
    //
    if (! IsCoinBase()) {
        BOOST_FOREACH(const CTxIn &txin, this->vin)
        {
            COutPoint prevout = txin.prevout;

            //
            // Get prev txindex from disk
            //
            CTxIndex txindex;
            if (! txdb.ReadTxIndex(prevout.hash, txindex)) {
                return print::error("DisconnectInputs() : ReadTxIndex failed");
            }

            if (prevout.n >= txindex.vSpent.size()) {
                return print::error("DisconnectInputs() : prevout.n out of range");
            }

            // Mark outpoint as not spent
            txindex.vSpent[prevout.n].SetNull();

            // Write back
            if (! txdb.UpdateTxIndex(prevout.hash, txindex)) {
                return print::error("DisconnectInputs() : UpdateTxIndex failed");
            }
        }
    }

    //
    // Remove transaction from index
    // This can fail if a duplicate of this transaction was in a chain that got
    // reorganized away. This is only possible if this transaction was completely spent, so erasing it would be a no-op anyway.
    //
    txdb.EraseTxIndex(*this);

    return true;
}


bool CTransaction::FetchInputs(CTxDB &txdb, const std::map<uint256, CTxIndex> &mapTestPool, bool fBlock, bool fMiner, MapPrevTx &inputsRet, bool &fInvalid)
{
    //
    // FetchInputs can return false either because we just haven't seen some inputs
    // (in which case the transaction should be stored as an orphan)
    // or because the transaction is malformed (in which case the transaction should
    // be dropped).  If tx is definitely invalid, fInvalid will be set to true.
    //
    fInvalid = false;

    if (IsCoinBase()) {
        return true; // Coinbase transactions have no inputs to fetch.
    }

    for (unsigned int i = 0; i < vin.size(); ++i)
    {
        COutPoint prevout = vin[i].prevout;
        if (inputsRet.count(prevout.hash)) {
            continue; // Got it already
        }

        //
        // Read txindex
        //
        CTxIndex &txindex = inputsRet[prevout.hash].first;
        bool fFound = true;
        if ((fBlock || fMiner) && mapTestPool.count(prevout.hash)) {
            //
            // Get txindex from current proposed changes
            //
            txindex = mapTestPool.find(prevout.hash)->second;
        } else {
            //
            // Read txindex from txdb
            //
            fFound = txdb.ReadTxIndex(prevout.hash, txindex);
        }
        if (!fFound && (fBlock || fMiner)) {
            return fMiner ? false : print::error("FetchInputs() : %s prev tx %s index entry not found", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
        }

        //
        // Read txPrev
        //
        CTransaction &txPrev = inputsRet[prevout.hash].second;
        if (!fFound || txindex.pos == CDiskTxPos(1,1,1)) {
            //
            // Get prev tx from single transactions in memory
            //
            {
                LOCK(CTxMemPool::mempool.cs);
                if (! CTxMemPool::mempool.exists(prevout.hash)) {
                    return print::error("FetchInputs() : %s CTxMemPool::mempool Tx prev not found %s", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
                }
                txPrev = CTxMemPool::mempool.lookup(prevout.hash);
            }
            if (! fFound) {
                txindex.vSpent.resize(txPrev.vout.size());
            }
        } else {
            //
            // Get prev tx from disk
            //
            if (! txPrev.ReadFromDisk(txindex.pos)) {
                return print::error("FetchInputs() : %s ReadFromDisk prev tx %s failed", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
            }
        }
    }

    // Make sure all prevout.n indexes are valid:
    for (unsigned int i = 0; i < vin.size(); ++i)
    {
        const COutPoint prevout = vin[i].prevout;
        assert(inputsRet.count(prevout.hash) != 0);

        const CTxIndex &txindex = inputsRet[prevout.hash].first;
        const CTransaction &txPrev = inputsRet[prevout.hash].second;
        if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size()) {
            //
            // Revisit this if/when transaction replacement is implemented and allows
            // adding inputs:
            //
            fInvalid = true;
            return DoS(100, print::error("FetchInputs() : %s prevout.n out of range %d %" PRIszu " %" PRIszu " prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));
        }
    }

    return true;
}

const CTxOut &CTransaction::GetOutputFor(const CTxIn &input, const MapPrevTx &inputs) const
{
    MapPrevTx::const_iterator mi = inputs.find(input.prevout.hash);
    if (mi == inputs.end()) {
        throw std::runtime_error("CTransaction::GetOutputFor() : prevout.hash not found");
    }

    const CTransaction &txPrev = (mi->second).second;
    if (input.prevout.n >= txPrev.vout.size()) {
        throw std::runtime_error("CTransaction::GetOutputFor() : prevout.n out of range");
    }

    return txPrev.vout[input.prevout.n];
}

int64_t CTransaction::GetValueIn(const MapPrevTx &inputs) const
{
    if (IsCoinBase()) {
        return 0;
    }

    int64_t nResult = 0;
    for (unsigned int i = 0; i < vin.size(); ++i)
    {
        nResult += GetOutputFor(vin[i], inputs).nValue;
    }
    return nResult;

}

unsigned int CTransaction::GetP2SHSigOpCount(const MapPrevTx &inputs) const
{
    if (IsCoinBase()) {
        return 0;
    }

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < vin.size(); ++i)
    {
        const CTxOut &prevout = GetOutputFor(vin[i], inputs);
        if (prevout.scriptPubKey.IsPayToScriptHash()) {
            nSigOps += prevout.scriptPubKey.GetSigOpCount(vin[i].scriptSig);
        }
    }
    return nSigOps;
}

bool CScriptCheck::operator()() const
{
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    if (! Script_util::VerifyScript(scriptSig, scriptPubKey, *ptxTo, nIn, nFlags, nHashType)) {
        return print::error("CScriptCheck() functor : %s block_check::manage::VerifySignature failed", ptxTo->GetHash().ToString().substr(0,10).c_str());
    }
    return true;
}

bool block_check::manage::VerifySignature(const CTransaction &txFrom, const CTransaction &txTo, unsigned int nIn, unsigned int flags, int nHashType)
{
    return CScriptCheck(txFrom, txTo, nIn, flags, nHashType)();    // Call by functor
}

bool CTransaction::ConnectInputs(CTxDB &txdb, MapPrevTx inputs, std::map<uint256, CTxIndex> &mapTestPool, const CDiskTxPos &posThisTx, const CBlockIndex *pindexBlock, bool fBlock, bool fMiner, bool fScriptChecks/*=true*/, unsigned int flags/*=Script_param::STRICT_FLAGS*/, std::vector<CScriptCheck> *pvChecks/*=NULL*/)
{
    //
    // Take over previous transactions' spent pointers
    // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
    // fMiner is true when called from the internal bitcoin miner
    // ... both are false when called from CTransaction::AcceptToMemoryPool
    //

    if (! IsCoinBase()) {
        int64_t nValueIn = 0;
        int64_t nFees = 0;
        for (unsigned int i = 0; i < vin.size(); ++i)
        {
            COutPoint prevout = vin[i].prevout;

            assert(inputs.count(prevout.hash) > 0);
            CTxIndex &txindex = inputs[prevout.hash].first;
            CTransaction &txPrev = inputs[prevout.hash].second;

            if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size()) {
                return DoS(100, print::error("ConnectInputs() : %s prevout.n out of range %d %" PRIszu " %" PRIszu " prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));
            }

            //
            // If prev is coinbase or coinstake, check that it's matured
            //
            if (txPrev.IsCoinBase() || txPrev.IsCoinStake()) {
                for (const CBlockIndex *pindex = pindexBlock; pindex && pindexBlock->nHeight - pindex->nHeight < block_transaction::nCoinbaseMaturity; pindex = pindex->pprev)
                {
                    if (pindex->nBlockPos == txindex.pos.nBlockPos && pindex->nFile == txindex.pos.nFile) {
                        return print::error("ConnectInputs() : tried to spend %s at depth %d", txPrev.IsCoinBase() ? "coinbase" : "coinstake", pindexBlock->nHeight - pindex->nHeight);
                    }
                }
            }

            // ppcoin: check transaction timestamp
            if (txPrev.nTime > nTime) {
                return DoS(100, print::error("ConnectInputs() : transaction timestamp earlier than input transaction"));
            }

            // Check for negative or overflow input values
            nValueIn += txPrev.vout[prevout.n].nValue;
            if (!block_transaction::manage::MoneyRange(txPrev.vout[prevout.n].nValue) || !block_transaction::manage::MoneyRange(nValueIn)) {
                return DoS(100, print::error("ConnectInputs() : txin values out of range"));
            }
        }

        if (pvChecks) {
            pvChecks->reserve(vin.size());
        }

        //
        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.
        //
        for (unsigned int i = 0; i < vin.size(); ++i)
        {
            COutPoint prevout = vin[i].prevout;
            assert(inputs.count(prevout.hash) > 0);

            CTxIndex &txindex = inputs[prevout.hash].first;
            CTransaction &txPrev = inputs[prevout.hash].second;

            //
            // Check for conflicts (double-spend)
            // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
            // for an attacker to attempt to split the network.
            //
            if (! txindex.vSpent[prevout.n].IsNull()) {
                return fMiner ? false : print::error("ConnectInputs() : %s prev tx already used at %s", GetHash().ToString().substr(0,10).c_str(), txindex.vSpent[prevout.n].ToString().c_str());
            }

            //
            // Skip ECDSA signature verification when connecting blocks (fBlock=true)
            // before the last blockchain checkpoint. This is safe because block merkle hashes are
            // still computed and checked, and any change will be caught at the next checkpoint.
            //
            if (fScriptChecks) {
                //
                // Verify signature
                //
                CScriptCheck check(txPrev, *this, i, flags, 0);
                if (pvChecks) {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                } else if (! check()) {
                    if (flags & Script_param::STRICT_FLAGS) {
                        //
                        // Don't trigger DoS code in case of Script_param::STRICT_FLAGS caused failure.
                        //
                        CScriptCheck check(txPrev, *this, i, flags & ~Script_param::STRICT_FLAGS, 0);
                        if (check()) {
                            return print::error("ConnectInputs() : %s strict block_check::manage::VerifySignature failed", GetHash().ToString().substr(0,10).c_str());
                        }
                    }
                    return DoS(100,print::error("ConnectInputs() : %s block_check::manage::VerifySignature failed", GetHash().ToString().substr(0,10).c_str()));
                }
            }

            //
            // Mark outpoints as spent
            //
            txindex.vSpent[prevout.n] = posThisTx;

            //
            // Write back
            //
            if (fBlock || fMiner) {
                mapTestPool[prevout.hash] = txindex;
            }
        }

        if (IsCoinStake()) {
            if (nTime >  Checkpoints::manage::GetLastCheckpointTime()) {
                unsigned int nTxSize = GetSerializeSize(SER_NETWORK, version::PROTOCOL_VERSION);

                //
                // coin stake tx earns reward instead of paying fee
                //
                uint64_t nCoinAge;
                if (! GetCoinAge(txdb, nCoinAge)) {
                    return print::error("ConnectInputs() : %s unable to get %s age for coinstake", GetHash().ToString().substr(0,10).c_str(), coin_param::strCoinName.c_str());
                }

                int64_t nReward = GetValueOut() - nValueIn;
                int64_t nCalculatedReward = diff::reward::GetProofOfStakeReward(nCoinAge, pindexBlock->nBits, nTime) - GetMinFee(1, false, GMF_BLOCK, nTxSize) + util::CENT;

                if (nReward > nCalculatedReward) {
                    return DoS(100, print::error("ConnectInputs() : coinstake pays too much(actual=%" PRId64 " vs calculated=%" PRId64 ")", nReward, nCalculatedReward));
                }
            }
        } else {
            if (nValueIn < GetValueOut()) {
                return DoS(100, print::error("ConnectInputs() : %s value in < value out", GetHash().ToString().substr(0,10).c_str()));
            }

            //
            // Tally transaction fees
            //
            int64_t nTxFee = nValueIn - GetValueOut();
            if (nTxFee < 0) {
                return DoS(100, print::error("ConnectInputs() : %s nTxFee < 0", GetHash().ToString().substr(0,10).c_str()));
            }

            nFees += nTxFee;
            if (! block_transaction::manage::MoneyRange(nFees)) {
                return DoS(100, print::error("ConnectInputs() : nFees out of range"));
            }
        }
    }

    return true;
}

bool CTransaction::ClientConnectInputs()
{
    if (IsCoinBase()) {
        return false;
    }

    //
    // Take over previous transactions' spent pointers
    //
    {
        LOCK(CTxMemPool::mempool.cs);
        int64_t nValueIn = 0;
        for (unsigned int i = 0; i < vin.size(); ++i)
        {
            //
            // Get prev tx from single transactions in memory
            //
            COutPoint prevout = vin[i].prevout;
            if (! CTxMemPool::mempool.exists(prevout.hash)) {
                return false;
            }
            CTransaction &txPrev = CTxMemPool::mempool.lookup(prevout.hash);

            if (prevout.n >= txPrev.vout.size()) {
                return false;
            }

            //
            // Verify signature
            //
            if (! block_check::manage::VerifySignature(txPrev, *this, i, Script_param::SCRIPT_VERIFY_NOCACHE | Script_param::SCRIPT_VERIFY_P2SH, 0)) {
                return print::error("ClientConnectInputs() : block_check::manage::VerifySignature failed");
            }

            //
            ///// this is redundant with the CTxMemPool::mempool.mapNextTx stuff,
            ///// not sure which I want to get rid of
            ///// this has to go away now that posNext is gone
            // // Check for conflicts
            // if (!txPrev.vout[prevout.n].posNext.IsNull())
            //     return print::error("ConnectInputs() : prev tx already used");
            //
            // // Flag outpoints as used
            // txPrev.vout[prevout.n].posNext = posThisTx;
            //

            nValueIn += txPrev.vout[prevout.n].nValue;

            if (!block_transaction::manage::MoneyRange(txPrev.vout[prevout.n].nValue) || !block_transaction::manage::MoneyRange(nValueIn)) {
                return print::error("ClientConnectInputs() : txin values out of range");
            }
        }
        if (GetValueOut() > nValueIn) {
            return false;
        }
    }

    return true;
}

bool CBlock::DisconnectBlock(CTxDB &txdb, CBlockIndex *pindex)
{
    // Disconnect in reverse order
    for (int i = vtx.size() - 1; i >= 0; i--)
    {
        if (! vtx[i].DisconnectInputs(txdb)) {
            return false;
        }
    }

    //
    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    //
    if (pindex->pprev) {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = 0;
        if (! txdb.WriteBlockIndex(blockindexPrev)) {
            return print::error("DisconnectBlock() : WriteBlockIndex failed");
        }
    }

    //
    // ppcoin: clean up wallet after disconnecting coinstake
    //
    BOOST_FOREACH(CTransaction &tx, this->vtx)
    {
        wallet_process::manage::SyncWithWallets(tx, this, false, false);
    }

    return true;
}

void block_check::thread::ThreadScriptCheck(void *)
{
    net_node::vnThreadsRunning[THREAD_SCRIPTCHECK]++;
    bitthread::manage::RenameThread((coin_param::strCoinName + "-scriptch").c_str());
    scriptcheckqueue.Thread();
    net_node::vnThreadsRunning[THREAD_SCRIPTCHECK]--;
}

void block_check::thread::ThreadScriptCheckQuit()
{
    scriptcheckqueue.Quit();
}

bool CBlock::ConnectBlock(CTxDB &txdb, CBlockIndex *pindex, bool fJustCheck/*=false*/)
{
    // Check it again in case a previous version let a bad block in, but skip BlockSig checking
    if (! CheckBlock(!fJustCheck, !fJustCheck, false)) {
        return false;
    }

    //
    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    //
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied all blocks whose timestamp was after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes in their initial block download.
    //
    bool fEnforceBIP30 = true; // Always active in coin
    bool fScriptChecks = pindex->nHeight >= Checkpoints::manage::GetTotalBlocksEstimate();

    //// issue here: it doesn't know the version
    unsigned int nTxPos;
    if (fJustCheck) {
        //
        // FetchInputs treats CDiskTxPos(1,1,1) as a special "refer to memorypool" indicator
        // Since we're just checking the block and not actually connecting it, it might not (and probably shouldn't) be on the disk to get the transaction from
        //
        nTxPos = 1;
    } else {
        nTxPos = pindex->nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK, version::CLIENT_VERSION) - (2 * compact_size::manage::GetSizeOfCompactSize(0)) + compact_size::manage::GetSizeOfCompactSize(vtx.size());
    }

    std::map<uint256, CTxIndex> mapQueuedChanges;
    CCheckQueueControl<CScriptCheck> control(fScriptChecks && block_info::nScriptCheckThreads ? &block_check::thread::scriptcheckqueue : NULL);

    int64_t nFees = 0;
    int64_t nValueIn = 0;
    int64_t nValueOut = 0;
    unsigned int nSigOps = 0;
    BOOST_FOREACH(CTransaction &tx, this->vtx)
    {
        uint256 hashTx = tx.GetHash();

        if (fEnforceBIP30) {
            CTxIndex txindexOld;
            if (txdb.ReadTxIndex(hashTx, txindexOld)) {
                BOOST_FOREACH(CDiskTxPos &pos, txindexOld.vSpent)
                {
                    if (pos.IsNull()) {
                        return false;
                    }
                }
            }
        }

        nSigOps += tx.GetLegacySigOpCount();
        if (nSigOps > block_param::MAX_BLOCK_SIGOPS) {
            return DoS(100, print::error("ConnectBlock() : too many sigops"));
        }

        CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
        if (! fJustCheck) {
            nTxPos += ::GetSerializeSize(tx, SER_DISK, version::CLIENT_VERSION);
        }

        MapPrevTx mapInputs;
        if (tx.IsCoinBase()) {
            nValueOut += tx.GetValueOut();
        } else {
            bool fInvalid;
            if (! tx.FetchInputs(txdb, mapQueuedChanges, true, false, mapInputs, fInvalid)) {
                return false;
            }

            // Add in sigops done by pay-to-script-hash inputs;
            // this is to prevent a "rogue miner" from creating
            // an incredibly-expensive-to-validate block.
            nSigOps += tx.GetP2SHSigOpCount(mapInputs);
            if (nSigOps > block_param::MAX_BLOCK_SIGOPS) {
                return DoS(100, print::error("ConnectBlock() : too many sigops"));
            }

            int64_t nTxValueIn = tx.GetValueIn(mapInputs);
            int64_t nTxValueOut = tx.GetValueOut();
            nValueIn += nTxValueIn;
            nValueOut += nTxValueOut;
            if (! tx.IsCoinStake()) {
                nFees += nTxValueIn - nTxValueOut;
            }

            unsigned int nFlags = Script_param::SCRIPT_VERIFY_NOCACHE | Script_param::SCRIPT_VERIFY_P2SH;

            if (tx.nTime >= timestamps::CHECKLOCKTIMEVERIFY_SWITCH_TIME) {
                nFlags |= Script_param::SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
                // OP_CHECKSEQUENCEVERIFY is senseless without BIP68, so we're going disable it for now.
                // nFlags |= Script_param::SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
            }

            std::vector<CScriptCheck> vChecks;
            if (! tx.ConnectInputs(txdb, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false, fScriptChecks, nFlags, block_info::nScriptCheckThreads ? &vChecks : NULL)) {
                return false;
            }
            control.Add(vChecks);
        }

        mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());
    }

    if (! control.Wait()) {
        return DoS(100, false);
    }

    if (IsProofOfWork()) {
        int64_t nBlockReward = diff::reward::GetProofOfWorkReward(nBits, nFees);

        // Check coinbase reward
        if (vtx[0].GetValueOut() > nBlockReward) {
            return print::error("CheckBlock() : coinbase reward exceeded (actual=%" PRId64 " vs calculated=%" PRId64 ")", vtx[0].GetValueOut(), nBlockReward);
        }
    }

    // track money supply and mint amount info
    pindex->nMint = nValueOut - nValueIn + nFees;
    pindex->nMoneySupply = (pindex->pprev? pindex->pprev->nMoneySupply : 0) + nValueOut - nValueIn;
    if (! txdb.WriteBlockIndex(CDiskBlockIndex(pindex))) {
        return print::error("Connect() : WriteBlockIndex for pindex failed");
    }

    // fees are not collected by proof-of-stake miners
    // fees are destroyed to compensate the entire network
    if (args_bool::fDebug && IsProofOfStake() && map_arg::GetBoolArg("-printcreation")) {
        printf("ConnectBlock() : destroy=%s nFees=%" PRId64 "\n", bitstr::FormatMoney(nFees).c_str(), nFees);
    }

    if (fJustCheck) {
        return true;
    }

    // Write queued txindex changes
    for (std::map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
    {
        if (! txdb.UpdateTxIndex((*mi).first, (*mi).second)) {
            return print::error("ConnectBlock() : UpdateTxIndex failed");
        }
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev) {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = pindex->GetBlockHash();
        if (! txdb.WriteBlockIndex(blockindexPrev)) {
            return print::error("ConnectBlock() : WriteBlockIndex failed");
        }
    }

    // Watch for transactions paying to me
    BOOST_FOREACH(CTransaction &tx, this->vtx)
    {
        wallet_process::manage::SyncWithWallets(tx, this, true);
    }

    return true;
}

bool block_check::manage::Reorganize(CTxDB &txdb, CBlockIndex *pindexNew)
{
    printf("REORGANIZE\n");

    // Find the fork
    CBlockIndex *pfork = block_info::pindexBest;
    CBlockIndex *plonger = pindexNew;
    while (pfork != plonger)
    {
        while (plonger->nHeight > pfork->nHeight)
        {
            if ((plonger = plonger->pprev) == NULL) {
                return print::error("block_check::manage::Reorganize() : plonger->pprev is null");
            }
        }
        if (pfork == plonger) {
            break;
        }
        if ((pfork = pfork->pprev) == NULL) {
            return print::error("block_check::manage::Reorganize() : pfork->pprev is null");
        }
    }

    // List of what to disconnect
    std::vector<CBlockIndex *> vDisconnect;
    for (CBlockIndex *pindex = block_info::pindexBest; pindex != pfork; pindex = pindex->pprev)
    {
        vDisconnect.push_back(pindex);
    }

    // List of what to connect
    std::vector<CBlockIndex *> vConnect;
    for (CBlockIndex *pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
    {
        vConnect.push_back(pindex);
    }
    reverse(vConnect.begin(), vConnect.end());

    printf("REORGANIZE: Disconnect %" PRIszu " blocks; %s..%s\n", vDisconnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), block_info::pindexBest->GetBlockHash().ToString().substr(0,20).c_str());
    printf("REORGANIZE: Connect %" PRIszu " blocks; %s..%s\n", vConnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->GetBlockHash().ToString().substr(0,20).c_str());

    // Disconnect shorter branch
    std::vector<CTransaction> vResurrect;
    BOOST_FOREACH(CBlockIndex *pindex, vDisconnect)
    {
        CBlock block;
        if (! block.ReadFromDisk(pindex)) {
            return print::error("block_check::manage::Reorganize() : ReadFromDisk for disconnect failed");
        }
        if (! block.DisconnectBlock(txdb, pindex)) {
            return print::error("block_check::manage::Reorganize() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());
        }

        // Queue memory transactions to resurrect
        BOOST_FOREACH(const CTransaction &tx, block.vtx)
        {
            if (!(tx.IsCoinBase() || tx.IsCoinStake())) {
                vResurrect.push_back(tx);
            }
        }
    }

    // Connect longer branch
    std::vector<CTransaction> vDelete;
    for (unsigned int i = 0; i < vConnect.size(); ++i)
    {
        CBlockIndex *pindex = vConnect[i];
        CBlock block;
        if (! block.ReadFromDisk(pindex)) {
            return print::error("block_check::manage::Reorganize() : ReadFromDisk for connect failed");
        }
        if (! block.ConnectBlock(txdb, pindex)) {
            // Invalid block
            return print::error("block_check::manage::Reorganize() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());
        }

        // Queue memory transactions to delete
        BOOST_FOREACH(const CTransaction &tx, block.vtx)
        {
            vDelete.push_back(tx);
        }
    }
    if (! txdb.WriteHashBestChain(pindexNew->GetBlockHash())) {
        return print::error("block_check::manage::Reorganize() : WriteHashBestChain failed");
    }

    // Make sure it's successfully written to disk before changing memory structure
    if (! txdb.TxnCommit()) {
        return print::error("block_check::manage::Reorganize() : TxnCommit failed");
    }

    // Disconnect shorter branch
    BOOST_FOREACH(CBlockIndex *pindex, vDisconnect)
    {
        if (pindex->pprev) {
            pindex->pprev->pnext = NULL;
        }
    }

    // Connect longer branch
    BOOST_FOREACH(CBlockIndex *pindex, vConnect)
    {
        if (pindex->pprev) {
            pindex->pprev->pnext = pindex;
        }
    }

    // Resurrect memory transactions that were in the disconnected branch
    BOOST_FOREACH(CTransaction &tx, vResurrect)
    {
        tx.AcceptToMemoryPool(txdb, false);
    }

    // Delete redundant memory transactions that are in the connected branch
    BOOST_FOREACH(CTransaction &tx, vDelete)
    {
        CTxMemPool::mempool.remove(tx);
    }

    printf("REORGANIZE: done\n");

    return true;
}

//
// Called from inside SetBestChain: attaches a block to the new best chain being built
//
bool CBlock::SetBestChainInner(CTxDB &txdb, CBlockIndex *pindexNew)
{
    uint256 hash = GetHash();

    // Adding to current best branch
    if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash)) {
        txdb.TxnAbort();
        block_check::manage::InvalidChainFound(pindexNew);
        return false;
    }
    if (! txdb.TxnCommit()) {
        return print::error("SetBestChain() : TxnCommit failed");
    }

    // Add to current best branch
    pindexNew->pprev->pnext = pindexNew;

    // Delete redundant memory transactions
    BOOST_FOREACH(CTransaction &tx, this->vtx)
    {
        CTxMemPool::mempool.remove(tx);
    }

    return true;
}

bool CBlock::SetBestChain(CTxDB &txdb, CBlockIndex *pindexNew)
{
    uint256 hash = GetHash();

    if (! txdb.TxnBegin()) {
        return print::error("SetBestChain() : TxnBegin failed");
    }

    if (block_info::pindexGenesisBlock == NULL && hash == (!args_bool::fTestNet ? block_param::hashGenesisBlock : block_param::hashGenesisBlockTestNet)) {
        txdb.WriteHashBestChain(hash);
        if (! txdb.TxnCommit()) {
            return print::error("SetBestChain() : TxnCommit failed");
        }
        block_info::pindexGenesisBlock = pindexNew;
    } else if (hashPrevBlock == block_info::hashBestChain) {
        if (! SetBestChainInner(txdb, pindexNew)) {
            return print::error("SetBestChain() : SetBestChainInner failed");
        }
    } else {
        // the first block in the new chain that will cause it to become the new best chain
        CBlockIndex *pindexIntermediate = pindexNew;

        // list of blocks that need to be connected afterwards
        std::vector<CBlockIndex *> vpindexSecondary;

        // block_check::manage::Reorganize is costly in terms of db load, as it works in a single db transaction.
        // Try to limit how much needs to be done inside
        while (pindexIntermediate->pprev && pindexIntermediate->pprev->nChainTrust > block_info::pindexBest->nChainTrust)
        {
            vpindexSecondary.push_back(pindexIntermediate);
            pindexIntermediate = pindexIntermediate->pprev;
        }

        if (! vpindexSecondary.empty()) {
            printf("Postponing %" PRIszu " reconnects\n", vpindexSecondary.size());
        }

        // Switch to new best branch
        if (! block_check::manage::Reorganize(txdb, pindexIntermediate)) {
            txdb.TxnAbort();
            block_check::manage::InvalidChainFound(pindexNew);
            return print::error("SetBestChain() : block_check::manage::Reorganize failed");
        }

        // Connect further blocks
        for (std::vector<CBlockIndex *>::reverse_iterator rit = vpindexSecondary.rbegin(); rit != vpindexSecondary.rend(); ++rit)
        {
            CBlock block;
            if (! block.ReadFromDisk(*rit)) {
                printf("SetBestChain() : ReadFromDisk failed\n");
                break;
            }
            if (! txdb.TxnBegin()) {
                printf("SetBestChain() : TxnBegin 2 failed\n");
                break;
            }

            //
            // errors now are not fatal, we still did a reorganisation to a new chain in a valid way
            //
            if (! block.SetBestChainInner(txdb, *rit)) {
                break;
            }
        }
    }

    //
    // Update best block in wallet (so we can detect restored wallets)
    //
    bool fIsInitialDownload = block_process::manage::IsInitialBlockDownload();
    if (! fIsInitialDownload) {
        const CBlockLocator locator(pindexNew);
        block_notify::SetBestChain(locator);
    }

    //
    // New best block
    //
    block_info::hashBestChain = hash;
    block_info::pindexBest = pindexNew;
    block_transaction::manage::setnull_pblockindexFBBHLast(); // pblockindexFBBHLast = NULL;
    block_info::nBestHeight = block_info::pindexBest->nHeight;
    block_info::nBestChainTrust = pindexNew->nChainTrust;
    block_info::nTimeBestReceived = bitsystem::GetTime();
    block_info::nTransactionsUpdated++;

    uint256 nBestBlockTrust = block_info::pindexBest->nHeight != 0 ? (block_info::pindexBest->nChainTrust - block_info::pindexBest->pprev->nChainTrust) : block_info::pindexBest->nChainTrust;

    printf("SetBestChain: new best=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
        block_info::hashBestChain.ToString().substr(0,20).c_str(), block_info::nBestHeight,
        CBigNum(block_info::nBestChainTrust).ToString().c_str(),
        nBestBlockTrust.Get64(),
        util::DateTimeStrFormat("%x %H:%M:%S", block_info::pindexBest->GetBlockTime()).c_str());

    // Check the version of the last 100 blocks to see if we need to upgrade:
    if (! fIsInitialDownload) {
        int nUpgraded = 0;
        const CBlockIndex *pindex = block_info::pindexBest;
        for (int i = 0; i < 100 && pindex != NULL; i++)
        {
            if (pindex->nVersion > CBlock::CURRENT_VERSION) {
                ++nUpgraded;
            }
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0) {
            printf("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, CBlock::CURRENT_VERSION);
        }
        if (nUpgraded > 100 / 2) {
            //
            // excep::strMiscWarning is read by block_alert::manage::GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            //
            excep::set_strMiscWarning( _("Warning: This version is obsolete, upgrade required!") );
        }
    }

    std::string strCmd = map_arg::GetArg("-blocknotify", "");

    if (!fIsInitialDownload && !strCmd.empty()) {
        boost::replace_all(strCmd, "%s", block_info::hashBestChain.GetHex());
        boost::thread t(cmd::runCommand, strCmd); // thread runs free
    }

    return true;
}

//
// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are 
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
//
bool CTransaction::GetCoinAge(CTxDB &txdb, uint64_t &nCoinAge) const
{
    CBigNum bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (IsCoinBase()) {
        return true;
    }

    BOOST_FOREACH(const CTxIn &txin, this->vin)
    {
        //
        // First try finding the previous transaction in database
        //
        CTransaction txPrev;
        CTxIndex txindex;
        if (! txPrev.ReadFromDisk(txdb, txin.prevout, txindex)) {
            continue;  // previous transaction not in main chain
        }
        if (nTime < txPrev.nTime) {
            return false;  // Transaction timestamp violation
        }

        //
        // Read block header
        //
        CBlock block;
        if (! block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false)) {
            return false; // unable to read block of previous transaction
        }
        if (block.GetBlockTime() + block_check::nStakeMinAge > nTime) {
            continue; // only count coins meeting min age requirement
        }

        int64_t nValueIn = txPrev.vout[txin.prevout.n].nValue;
        bnCentSecond += CBigNum(nValueIn) * (nTime-txPrev.nTime) / util::CENT;

        if (args_bool::fDebug && map_arg::GetBoolArg("-printcoinage")) {
            printf("coin age nValueIn=%" PRId64 " nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString().c_str());
        }
    }

    CBigNum bnCoinDay = bnCentSecond * util::CENT / util::COIN / util::nOneDay;
    if (args_bool::fDebug && map_arg::GetBoolArg("-printcoinage")) {
        printf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
    }

    nCoinAge = bnCoinDay.getuint64();
    return true;
}

// ppcoin: total coin age spent in block, in the unit of coin-days.
bool CBlock::GetCoinAge(uint64_t &nCoinAge) const
{
    nCoinAge = 0;

    CTxDB txdb("r");
    BOOST_FOREACH(const CTransaction &tx, this->vtx)
    {
        uint64_t nTxCoinAge;
        if (tx.GetCoinAge(txdb, nTxCoinAge)) {
            nCoinAge += nTxCoinAge;
        } else {
            return false;
        }
    }

    if (nCoinAge == 0) {    // block coin age minimum 1 coin-day
        nCoinAge = 1;
    }
    if (args_bool::fDebug && map_arg::GetBoolArg("-printcoinage")) {
        printf("block %s age total nCoinDays=%" PRId64 "\n", coin_param::strCoinName.c_str(), nCoinAge);
    }

    return true;
}

bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (block_info::mapBlockIndex.count(hash)) {
        return print::error("AddToBlockIndex() : %s already exists", hash.ToString().substr(0,20).c_str());
    }

    // Construct new block index object
    CBlockIndex *pindexNew = new(std::nothrow) CBlockIndex(nFile, nBlockPos, *this);
    if (! pindexNew) {
        return print::error("AddToBlockIndex() : new CBlockIndex failed");
    }

    pindexNew->phashBlock = &hash;
    std::map<uint256, CBlockIndex *>::iterator miPrev = block_info::mapBlockIndex.find(hashPrevBlock);
    if (miPrev != block_info::mapBlockIndex.end()) {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }

    // ppcoin: compute chain trust score
    pindexNew->nChainTrust = (pindexNew->pprev ? pindexNew->pprev->nChainTrust : 0) + pindexNew->GetBlockTrust();

    // ppcoin: compute stake entropy bit for stake modifier
    if (! pindexNew->SetStakeEntropyBit(GetStakeEntropyBit(pindexNew->nHeight))) {
        return print::error("AddToBlockIndex() : SetStakeEntropyBit() failed");
    }

    // ppcoin: record proof-of-stake hash value
    if (pindexNew->IsProofOfStake()) {
        if (! block_process::mapProofOfStake.count(hash)) {
            return print::error("AddToBlockIndex() : hashProofOfStake not found in map");
        }

        pindexNew->hashProofOfStake = block_process::mapProofOfStake[hash];
    }

    // ppcoin: compute stake modifier
    uint64_t nStakeModifier = 0;
    bool fGeneratedStakeModifier = false;
    if (! bitkernel::ComputeNextStakeModifier(pindexNew, nStakeModifier, fGeneratedStakeModifier)) {
        return print::error("AddToBlockIndex() : bitkernel::ComputeNextStakeModifier() failed");
    }

    pindexNew->SetStakeModifier(nStakeModifier, fGeneratedStakeModifier);
    pindexNew->nStakeModifierChecksum = bitkernel::GetStakeModifierChecksum(pindexNew);
    if (! bitkernel::CheckStakeModifierCheckpoints(pindexNew->nHeight, pindexNew->nStakeModifierChecksum)) {
        return print::error("AddToBlockIndex() : Rejected by stake modifier checkpoint height=%d, modifier=0x%016" PRIx64, pindexNew->nHeight, nStakeModifier);
    }

    // Add to block_info::mapBlockIndex
    std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    if (pindexNew->IsProofOfStake()) {
        block_info::setStakeSeen.insert(std::make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));
    }
    pindexNew->phashBlock = &((*mi).first);

    // Write to disk block index
    CTxDB txdb;
    if (! txdb.TxnBegin()) {
        return false;
    }
    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
    if (! txdb.TxnCommit()) {
        return false;
    }

    LOCK(block_process::cs_main);

    // New best
    if (pindexNew->nChainTrust > block_info::nBestChainTrust) {
        if (! SetBestChain(txdb, pindexNew)) {
            return false;
        }
    }

    if (pindexNew == block_info::pindexBest) {
        //
        // Notify UI to display prev block's coinbase if it was ours
        //
        static uint256 hashPrevBestCoinBase;

        block_notify::UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = vtx[0].GetHash();
    }

    static int8_t counter = 0;
    if( (++counter & 0x0F) == 0 || !block_process::manage::IsInitialBlockDownload()) { // repaint every 16 blocks if not in initial block download
        CClientUIInterface::uiInterface.NotifyBlocksChanged();
    }
    
    return true;
}

bool CBlock::CheckBlock(bool fCheckPOW/*=true*/, bool fCheckMerkleRoot/*=true*/, bool fCheckSig/*=true*/) const
{
    //
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.
    //
    std::set<uint256> uniqueTx; // tx hashes
    unsigned int nSigOps = 0; // total sigops

    // Size limits
    if (vtx.empty() || vtx.size() > block_param::MAX_BLOCK_SIZE || ::GetSerializeSize(*this, SER_NETWORK, version::PROTOCOL_VERSION) > block_param::MAX_BLOCK_SIZE) {
        return DoS(100, print::error("CheckBlock() : size limits failed"));
    }

    bool fProofOfStake = IsProofOfStake();

    // First transaction must be coinbase, the rest must not be
    if (! vtx[0].IsCoinBase()) {
        return DoS(100, print::error("CheckBlock() : first tx is not coinbase"));
    }

    if (! vtx[0].CheckTransaction()) {
        return DoS(vtx[0].nDoS, print::error("CheckBlock() : CheckTransaction failed on coinbase"));
    }

    uniqueTx.insert(vtx[0].GetHash());
    nSigOps += vtx[0].GetLegacySigOpCount();

    if (fProofOfStake) {
        //
        // Proof-of-STake related checkings. Note that we know here that 1st transactions is coinstake. We don't need 
        // check the type of 1st transaction because it's performed earlier by IsProofOfStake()
        //
        // nNonce must be zero for proof-of-stake blocks
        //
        if (nNonce != 0) {
            return DoS(100, print::error("CheckBlock() : non-zero nonce in proof-of-stake block"));
        }

        // Coinbase output should be empty if proof-of-stake block
        if (vtx[0].vout.size() != 1 || !vtx[0].vout[0].IsEmpty()) {
            return DoS(100, print::error("CheckBlock() : coinbase output not empty for proof-of-stake block"));
        }

        // Check coinstake timestamp
        if (GetBlockTime() != (int64_t)vtx[1].nTime) {
            return DoS(50, print::error("CheckBlock() : coinstake timestamp violation nTimeBlock=%" PRId64 " nTimeTx=%u", GetBlockTime(), vtx[1].nTime));
        }

        // ppcoin: check proof-of-stake block signature
        if (fCheckSig && !CheckBlockSignature()) {
            return DoS(100, print::error("CheckBlock() : bad proof-of-stake block signature"));
        }

        if (! vtx[1].CheckTransaction()) {
            return DoS(vtx[1].nDoS, print::error("CheckBlock() : CheckTransaction failed on coinstake"));
        }

        uniqueTx.insert(vtx[1].GetHash());
        nSigOps += vtx[1].GetLegacySigOpCount();
    } else {
        //
        // Check proof of work matches claimed amount
        //
        if (fCheckPOW && !diff::check::CheckProofOfWork(GetHash(), nBits)) {
            return DoS(50, print::error("CheckBlock() : proof of work failed"));
        }

        //
        // Check timestamp
        //
        if (GetBlockTime() > block_check::manage::FutureDrift(bitsystem::GetAdjustedTime())) {
            return print::error("CheckBlock() : block timestamp too far in the future");
        }

        //
        // Check coinbase timestamp
        //
        if (GetBlockTime() < block_check::manage::PastDrift((int64_t)vtx[0].nTime)) {
            return DoS(50, print::error("CheckBlock() : coinbase timestamp is too late"));
        }
    }

    //
    // Iterate all transactions starting from second for proof-of-stake block or first for proof-of-work block
    //
    for (unsigned int i = fProofOfStake ? 2 : 1; i < vtx.size(); ++i)
    {
        const CTransaction &tx = vtx[i];

        // Reject coinbase transactions at non-zero index
        if (tx.IsCoinBase()) {
            return DoS(100, print::error("CheckBlock() : coinbase at wrong index"));
        }

        // Reject coinstake transactions at index != 1
        if (tx.IsCoinStake()) {
            return DoS(100, print::error("CheckBlock() : coinstake at wrong index"));
        }

        // Check transaction timestamp
        if (GetBlockTime() < (int64_t)tx.nTime) {
            return DoS(50, print::error("CheckBlock() : block timestamp earlier than transaction timestamp"));
        }

        // Check transaction consistency
        if (! tx.CheckTransaction()) {
            return DoS(tx.nDoS, print::error("CheckBlock() : CheckTransaction failed"));
        }

        // Add transaction hash into list of unique transaction IDs
        uniqueTx.insert(tx.GetHash());

        // Calculate sigops count
        nSigOps += tx.GetLegacySigOpCount();
    }

    // Check for duplicate txids. This is caught by ConnectInputs(),
    // but catching it earlier avoids a potential DoS attack:
    if (uniqueTx.size() != vtx.size()) {
        return DoS(100, print::error("CheckBlock() : duplicate transaction"));
    }

    // Reject block if validation would consume too much resources.
    if (nSigOps > block_param::MAX_BLOCK_SIGOPS) {
        return DoS(100, print::error("CheckBlock() : out-of-bounds SigOpCount"));
    }

    // Check merkle root
    if (fCheckMerkleRoot && hashMerkleRoot != BuildMerkleTree()) {
        return DoS(100, print::error("CheckBlock() : hashMerkleRoot mismatch"));
    }

    return true;
}

bool CBlock::AcceptBlock()
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (block_info::mapBlockIndex.count(hash)) {
        return print::error("CBlock::AcceptBlock() : block already in block_info::mapBlockIndex");
    }

    // Get prev block index
    std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hashPrevBlock);
    if (mi == block_info::mapBlockIndex.end()) {
        return DoS(10, print::error("CBlock::AcceptBlock() : prev block not found"));
    }

    CBlockIndex *pindexPrev = (*mi).second;
    int nHeight = pindexPrev->nHeight + 1;

    // Check proof-of-work or proof-of-stake
    if (nBits != diff::spacing::GetNextTargetRequired(pindexPrev, IsProofOfStake())) {
        return DoS(100, print::error("CBlock::AcceptBlock() : incorrect %s", IsProofOfWork() ? "proof-of-work" : "proof-of-stake"));
    }

    int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();
    int nMaxOffset = (args_bool::fTestNet || pindexPrev->nTime < timestamps::BLOCKS_ADMIT_HOURS_SWITCH_TIME) ?
        block_transaction::DONOT_ACCEPT_BLOCKS_ADMIT_HOURS_TESTNET * util::nOneHour: 
        block_transaction::DONOT_ACCEPT_BLOCKS_ADMIT_HOURS * util::nOneHour;

    // Check timestamp against prev
    if (GetBlockTime() <= nMedianTimePast || block_check::manage::FutureDrift(GetBlockTime()) < pindexPrev->GetBlockTime()) {
        return print::error("CBlock::AcceptBlock() : block's timestamp is too early");
    }

    // Don't accept blocks with future timestamps
    if (pindexPrev->nHeight > 1 && nMedianTimePast + nMaxOffset < GetBlockTime()) {
        return print::error(("CBlock::AcceptBlock() : block's timestamp is too far in the future ___ nMedianTimePast：" + std::to_string(nMedianTimePast) + " nMaxOffset：" + std::to_string(nMaxOffset) + " GetBlockTime()：" + std::to_string(GetBlockTime()) + " nHeight：" + std::to_string(pindexPrev->nHeight)).c_str());
    }

    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction &tx, vtx)
    {
        if (! tx.IsFinal(nHeight, GetBlockTime())) {
            return DoS(10, print::error("CBlock::AcceptBlock() : contains a non-final transaction"));
        }
    }

    // Check that the block chain matches the known block chain up to a checkpoint
    if (! Checkpoints::manage::CheckHardened(nHeight, hash)) {
        return DoS(100, print::error("CBlock::AcceptBlock() : rejected by hardened checkpoint lock-in at %d", nHeight));
    }

    bool cpSatisfies = Checkpoints::manage::CheckSync(hash, pindexPrev);

    // Check that the block satisfies synchronized checkpoint
    if (entry::CheckpointsMode == Checkpoints::STRICT && !cpSatisfies) {
        return print::error("CBlock::AcceptBlock() : rejected by synchronized checkpoint");
    }
    if (entry::CheckpointsMode == Checkpoints::ADVISORY && !cpSatisfies) {
        excep::set_strMiscWarning( _("WARNING: syncronized checkpoint violation detected, but skipped!") );
    }

    // Enforce rule that the coinbase starts with serialized block height
    CScript expect = CScript() << nHeight;
    if (vtx[0].vin[0].scriptSig.size() < expect.size() || !std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin())) {
        return DoS(100, print::error("CBlock::AcceptBlock() : block height mismatch in coinbase"));
    }

    // Write block to history file
    if (! file_open::CheckDiskSpace(::GetSerializeSize(*this, SER_DISK, version::CLIENT_VERSION))) {
        return print::error("CBlock::AcceptBlock() : out of disk space");
    }

    unsigned int nFile = std::numeric_limits<unsigned int>::max();
    unsigned int nBlockPos = 0;
    if (! WriteToDisk(nFile, nBlockPos)) {
        return print::error("CBlock::AcceptBlock() : WriteToDisk failed");
    }
    if (! AddToBlockIndex(nFile, nBlockPos)) {
        return print::error("CBlock::AcceptBlock() : AddToBlockIndex failed");
    }

    // Relay inventory, but don't relay old inventory during initial block download
    int nBlockEstimate = Checkpoints::manage::GetTotalBlocksEstimate();
    if (block_info::hashBestChain == hash) {
        LOCK(net_node::cs_vNodes);
        BOOST_FOREACH(CNode *pnode, net_node::vNodes)
        {
            if (block_info::nBestHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate)) {
                pnode->PushInventory(CInv(_CINV_MSG_TYPE::MSG_BLOCK, hash));
            }
        }
    }

    // ppcoin: check pending sync-checkpoint
    Checkpoints::manage::AcceptPendingSyncCheckpoint();
    return true;
}

uint256 CBlockIndex::GetBlockTrust() const
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    if (bnTarget <= 0) {
        return 0;
    }

    // Return 1 for the first 12 blocks
    if (pprev == NULL || pprev->nHeight < 12) {
        return 1;
    }

    const CBlockIndex *currentIndex = pprev;
    if(IsProofOfStake()) {
        CBigNum bnNewTrust = (CBigNum(1) << 256) / (bnTarget + 1);

        //
        // Return 1/3 of score if parent block is not the PoW block
        //
        if (! pprev->IsProofOfWork()) {
            return (bnNewTrust / 3).getuint256();
        }

        int nPoWCount = 0;

        //
        // Check last 12 blocks type
        //
        while (pprev->nHeight - currentIndex->nHeight < 12)
        {
            if (currentIndex->IsProofOfWork()) {
                nPoWCount++;
            }
            currentIndex = currentIndex->pprev;
        }

        //
        // Return 1/3 of score if less than 3 PoW blocks found
        //
        if (nPoWCount < 3) {
            printf("GetBlockTrust(Return 1/3 of score)：nPoWCount %d\n", nPoWCount);
            return (bnNewTrust / 3).getuint256();
        }

        return bnNewTrust.getuint256();
    } else {
        //
        // Calculate work amount for block
        //
        CBigNum bnPoWTrust = CBigNum(diff::nPoWBase) / (bnTarget+1);

        //
        // Set nPowTrust to 1 if PoW difficulty is too low
        //
        if (bnPoWTrust < 1) {
            bnPoWTrust = 1;
        }

        CBigNum bnLastBlockTrust = CBigNum(pprev->nChainTrust - pprev->pprev->nChainTrust);

        //
        // Return nPoWTrust + 2/3 of previous block score if two parent blocks are not PoS blocks
        //
        if (!(pprev->IsProofOfStake() && pprev->pprev->IsProofOfStake())) {
            return (bnPoWTrust + 2 * bnLastBlockTrust / 3).getuint256();
        }

        int nPoSCount = 0;

        //
        // Check last 12 blocks type
        //
        while (pprev->nHeight - currentIndex->nHeight < 12)
        {
            if (currentIndex->IsProofOfStake()) {
                nPoSCount++;
            }
            currentIndex = currentIndex->pprev;
        }

        //
        // Return nPoWTrust + 2/3 of previous block score if less than 7 PoS blocks found
        //
        if (nPoSCount < 7) {
            printf("GetBlockTrust(nPoWTrust + 2/3 of previous block)：nPosCount %d\n", nPoSCount);
            return (bnPoWTrust + 2 * bnLastBlockTrust / 3).getuint256();
        }

        bnTarget.SetCompact(pprev->nBits);
        if (bnTarget <= 0) {
            return 0;
        }

        CBigNum bnNewTrust = (CBigNum(1) << 256) / (bnTarget + 1);

        //
        // Return nPoWTrust + full trust score for previous block nBits
        //
        return (bnPoWTrust + bnNewTrust).getuint256();
    }
}

bool CBlockIndex::IsSuperMajority(int minVersion, const CBlockIndex *pstart, unsigned int nRequired, unsigned int nToCheck)
{
    unsigned int nFound = 0;
    for (unsigned int i = 0; i < nToCheck && nFound < nRequired && pstart != NULL; ++i)
    {
        if (pstart->nVersion >= minVersion) {
            ++nFound;
        }
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}

bool block_process::manage::ReserealizeBlockSignature(CBlock *pblock)
{
    if (pblock->IsProofOfWork()) {
        pblock->vchBlockSig.clear();
        return true;
    }
    return CPubKey::ReserealizeSignature(pblock->vchBlockSig);
}

bool block_process::manage::IsCanonicalBlockSignature(CBlock *pblock)
{
    if (pblock->IsProofOfWork()) {
        return pblock->vchBlockSig.empty();
    }
    return Script_util::IsDERSignature(pblock->vchBlockSig);
}

bool block_process::manage::ProcessBlock(CNode *pfrom, CBlock *pblock)
{
    uint256 hash = pblock->GetHash();

    // Check for duplicate
    if (block_info::mapBlockIndex.count(hash)) {
        return print::error("block_process::manage::ProcessBlock() : already have block %d %s", block_info::mapBlockIndex[hash]->nHeight, hash.ToString().substr(0,20).c_str());
    }
    if (block_process::mapOrphanBlocks.count(hash)) {
        return print::error("block_process::manage::ProcessBlock() : already have block (orphan) %s", hash.ToString().substr(0,20).c_str());
    }

    // Check that block isn't listed as unconditionally banned.
    if (! Checkpoints::manage::CheckBanned(hash)) {
        if (pfrom) {
            pfrom->Misbehaving(100);
        }
        return print::error("block_process::manage::ProcessBlock() : block %s is rejected by hard-coded banlist", hash.GetHex().substr(0,20).c_str());
    }

    // Check proof-of-stake
    // Limited duplicity on stake: prevents block flood attack
    // Duplicate stake allowed only when there is orphan child block
    if (pblock->IsProofOfStake() && block_info::setStakeSeen.count(pblock->GetProofOfStake()) && !block_process::manage::mapOrphanBlocksByPrev.count(hash) && !Checkpoints::manage::WantedByPendingSyncCheckpoint(hash)) {
        return print::error("block_process::manage::ProcessBlock() : duplicate proof-of-stake (%s, %d) for block %s", pblock->GetProofOfStake().first.ToString().c_str(), pblock->GetProofOfStake().second, hash.ToString().c_str());
    }

    // Strip the garbage from newly received blocks, if we found some
    if (! block_process::manage::IsCanonicalBlockSignature(pblock)) {
        if (! block_process::manage::ReserealizeBlockSignature(pblock)) {
            printf("WARNING: ProcessBlock() : ReserealizeBlockSignature FAILED\n");
        }
    }

    // Preliminary checks
    if (! pblock->CheckBlock(true, true, (pblock->nTime > Checkpoints::manage::GetLastCheckpointTime()))) {
        return print::error("block_process::manage::ProcessBlock() : CheckBlock FAILED");
    }

    // ppcoin: verify hash target and signature of coinstake tx
    if (pblock->IsProofOfStake()) {
        uint256 hashProofOfStake = 0, targetProofOfStake = 0;
        if (! bitkernel::CheckProofOfStake(pblock->vtx[1], pblock->nBits, hashProofOfStake, targetProofOfStake)) {
            printf("WARNING: block_process::manage::ProcessBlock(): check proof-of-stake failed for block %s\n", hash.ToString().c_str());
            return false; // do not error here as we expect this during initial block download
        }
        if (! block_process::mapProofOfStake.count(hash)) { // add to mapProofOfStake
            block_process::mapProofOfStake.insert(std::make_pair(hash, hashProofOfStake));
        }
    }

    CBlockIndex *pcheckpoint = Checkpoints::manage::GetLastSyncCheckpoint();
    if (pcheckpoint && pblock->hashPrevBlock != block_info::hashBestChain && !Checkpoints::manage::WantedByPendingSyncCheckpoint(hash)) {
        // Extra checks to prevent "fill up memory by spamming with bogus blocks"
        int64_t deltaTime = pblock->GetBlockTime() - pcheckpoint->nTime;
        CBigNum bnNewBlock;
        bnNewBlock.SetCompact(pblock->nBits);
        CBigNum bnRequired;

        if (pblock->IsProofOfStake()) {
            bnRequired.SetCompact(diff::amount::ComputeMinStake(diff::spacing::GetLastBlockIndex(pcheckpoint, true)->nBits, deltaTime, pblock->nTime));
        } else {
            bnRequired.SetCompact(diff::amount::ComputeMinWork(diff::spacing::GetLastBlockIndex(pcheckpoint, false)->nBits, deltaTime));
        }

        if (bnNewBlock > bnRequired) {
            if (pfrom) {
                pfrom->Misbehaving(100);
            }
            return print::error("block_process::manage::ProcessBlock() : block with too little %s", pblock->IsProofOfStake()? "proof-of-stake" : "proof-of-work");
        }
    }

    // ppcoin: ask for pending sync-checkpoint if any
    if (! block_process::manage::IsInitialBlockDownload()) {
        Checkpoints::manage::AskForPendingSyncCheckpoint(pfrom);
    }

    // If don't already have its previous block, shunt it off to holding area until we get it
    if (! block_info::mapBlockIndex.count(pblock->hashPrevBlock)) {
        printf("block_process::manage::ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.ToString().substr(0,20).c_str());

        // ppcoin: check proof-of-stake
        if (pblock->IsProofOfStake()) {
            // Limited duplicity on stake: prevents block flood attack
            // Duplicate stake allowed only when there is orphan child block
            if (block_process::manage::setStakeSeenOrphan.count(pblock->GetProofOfStake()) && !block_process::manage::mapOrphanBlocksByPrev.count(hash) && !Checkpoints::manage::WantedByPendingSyncCheckpoint(hash)) {
                return print::error("block_process::manage::ProcessBlock() : duplicate proof-of-stake (%s, %d) for orphan block %s", pblock->GetProofOfStake().first.ToString().c_str(), pblock->GetProofOfStake().second, hash.ToString().c_str());
            } else {
                block_process::manage::setStakeSeenOrphan.insert(pblock->GetProofOfStake());
            }
        }

        CBlock *pblock2 = NULL;
        try {
            pblock2 = new CBlock(*pblock);
        } catch (const std::bad_alloc &e) {
            return print::error("block_process::manage::ProcessBlock() : bad alloc for orphan block %s", e.what());
        }

        block_process::mapOrphanBlocks.insert(std::make_pair(hash, pblock2));
        block_process::manage::mapOrphanBlocksByPrev.insert(std::make_pair(pblock2->hashPrevBlock, pblock2));

        // Ask this guy to fill in what we're missing
        if (pfrom) {
            pfrom->PushGetBlocks(block_info::pindexBest, block_process::manage::GetOrphanRoot(pblock2));

            // ppcoin: getblocks may not obtain the ancestor block rejected
            // earlier by duplicate-stake check so we ask for it again directly
            if (! block_process::manage::IsInitialBlockDownload()) {
                pfrom->AskFor(CInv(_CINV_MSG_TYPE::MSG_BLOCK, block_process::manage::WantedByOrphan(pblock2)));
            }
        }
        return true;
    }

    // Store to disk
    if (! pblock->AcceptBlock()) {
        return print::error("block_process::manage::ProcessBlock() : AcceptBlock FAILED");
    }

    // Recursively process any orphan blocks that depended on this one
    std::vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (unsigned int i = 0; i < vWorkQueue.size(); ++i)
    {
        uint256 hashPrev = vWorkQueue[i];
        for (std::multimap<uint256, CBlock *>::iterator mi = block_process::manage::mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != block_process::manage::mapOrphanBlocksByPrev.upper_bound(hashPrev);
             ++mi)
        {
            CBlock *pblockOrphan = (*mi).second;
            if (pblockOrphan->AcceptBlock()) {
                vWorkQueue.push_back(pblockOrphan->GetHash());
            }

            block_process::mapOrphanBlocks.erase(pblockOrphan->GetHash());
            block_process::manage::setStakeSeenOrphan.erase(pblockOrphan->GetProofOfStake());
            delete pblockOrphan;    // manage::mapOrphanBlocksByPrev.insert(std::make_pair(first, second) ...
        }
        block_process::manage::mapOrphanBlocksByPrev.erase(hashPrev);
    }

    printf("block_process::manage::ProcessBlock: ACCEPTED\n");

    // ppcoin: if responsible for sync-checkpoint send it
    if (pfrom && !CSyncCheckpoint::strMasterPrivKey.empty()) {
        Checkpoints::manage::AutoSendSyncCheckpoint();
    }

    return true;
}

// ppcoin: check block signature
bool CBlock::CheckBlockSignature() const
{
    if (vchBlockSig.empty()) {
        return false;
    }

    TxnOutputType::txnouttype whichType;
    std::vector<Script_util::valtype> vSolutions;
    if (! Script_util::Solver(vtx[1].vout[1].scriptPubKey, whichType, vSolutions)) {
        return false;
    }

    if (whichType == TxnOutputType::TX_PUBKEY) {
        Script_util::valtype &vchPubKey = vSolutions[0];
        CPubKey key(vchPubKey);
        if (! key.IsValid()) {
            return false;
        }
        return key.Verify(GetHash(), vchBlockSig);
    }

    return false;
}

bool file_open::CheckDiskSpace(uint64_t nAdditionalBytes/*=0*/)
{
    uint64_t nFreeBytesAvailable = boost::filesystem::space(iofs::GetDataDir()).available;

    //
    // Check for nMinDiskSpace bytes
    //
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes) {
        args_bool::fShutdown = true;
        std::string strMessage = _("Warning: Disk space is low!");
        excep::set_strMiscWarning( strMessage );
        printf("*** %s\n", strMessage.c_str());
        CClientUIInterface::uiInterface.ThreadSafeMessageBox(strMessage, coin_param::strCoinName.c_str(), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        entry::StartShutdown();
        return false;
    }
    return true;
}

FILE *file_open::OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char *pszMode/*="rb"*/)
{
    auto BlockFilePath = [](unsigned int nFile) {
        std::string strBlockFn = strprintf("blk%04u.dat", nFile);
        return iofs::GetDataDir() / strBlockFn;
    };

    if ((nFile < 1) || (nFile == std::numeric_limits<uint32_t>::max())) {
        return NULL;
    }

    FILE *file = ::fopen(BlockFilePath(nFile).string().c_str(), pszMode);
    if (! file) {
        return NULL;
    }
    if (nBlockPos != 0 && !::strchr(pszMode, 'a') && !::strchr(pszMode, 'w')) {
        if (::fseek(file, nBlockPos, SEEK_SET) != 0) {
            ::fclose(file);
            return NULL;
        }
    }

    return file;
}

FILE *file_open::AppendBlockFile(unsigned int &nFileRet)
{
    static unsigned int nCurrentBlockFile = 1;

    nFileRet = 0;
    for ( ; ; )
    {
        FILE *file = file_open::OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (! file) {
            return NULL;
        }
        if (::fseek(file, 0, SEEK_END) != 0) {
            return NULL;
        }

        //
        // FAT32 file size max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        //
        if (ftell(file) < (long)(0x7F000000 - compact_size::MAX_SIZE)) {
            nFileRet = nCurrentBlockFile;
            return file;
        }

        ::fclose(file);
        nCurrentBlockFile++;
    }
}

void block_load::UnloadBlockIndex()
{
    block_info::mapBlockIndex.clear();
    block_info::setStakeSeen.clear();
    block_info::pindexGenesisBlock = NULL;
    block_info::nBestHeight = 0;
    block_info::nBestChainTrust = 0;
    block_info::nBestInvalidTrust = 0;
    block_info::hashBestChain = 0;
    block_info::pindexBest = NULL;

}

bool block_load::LoadBlockIndex(bool fAllowNew/*=true*/)    // Call by init.cpp
{
    if (args_bool::fTestNet) {
        block_info::gpchMessageStart[0] = 0xcd;
        block_info::gpchMessageStart[1] = 0xf2;
        block_info::gpchMessageStart[2] = 0xc0;
        block_info::gpchMessageStart[3] = 0xef;

        diff::bnProofOfWorkLimit = diff::testnet::bnProofOfWorkLimit;
        block_check::nStakeMinAge = block_check::testnet::nStakeMinAge;
        block_check::nModifierInterval = block_check::testnet::nModifierInterval;
        block_transaction::nCoinbaseMaturity = block_transaction::testnet::nCoinbaseMaturity;
        block_check::nStakeTargetSpacing = block_check::testnet::nStakeTargetSpacing;
        block_check::nPowTargetSpacing = block_check::testnet::nPowTargetSpacing;
    }

    //
    // Load block index
    //
    CTxDB txdb("cr+");
    if (! txdb.LoadBlockIndex()) {
        return false;
    }

    //
    // Init with genesis block
    //
    if (block_info::mapBlockIndex.empty()) {
        if (! fAllowNew) {
            return false;
        }

        //
        // Genesis block
        //
        const char *pszTimestamp = block_param::pszTimestamp;

        CTransaction txNew;
        txNew.nTime = !args_bool::fTestNet ? block_param::nGenesisTimeMainnet: block_param::nGenesisTimeTestnet;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 0 << CBigNum(42) << std::vector<unsigned char>((const unsigned char *)pszTimestamp, (const unsigned char *)pszTimestamp + ::strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();

        CBlock block;
        block.vtx.push_back(txNew);
        block.hashPrevBlock = 0;
        block.hashMerkleRoot = block.BuildMerkleTree();
        block.nVersion = 1;
        block.nTime    = !args_bool::fTestNet ? block_param::nGenesisTimeMainnet: block_param::nGenesisTimeTestnet;
        block.nBits    = diff::bnProofOfWorkLimit.GetCompact();
        block.nNonce   = !args_bool::fTestNet ? block_param::nGenesisNonceMainnet : block_param::nGenesisNonceTestnet;

        if (true && (block.GetHash() != block_param::hashGenesisBlock)) {
            //
            // This will figure out a valid hash and Nonce if you're creating a different genesis block
            //
            uint256 hashTarget = CBigNum().SetCompact(block.nBits).getuint256();
            while (block.GetHash() > hashTarget)
            {
                ++block.nNonce;
                if (block.nNonce == 0) {
                    printf("NONCE WRAPPED, incrementing time");
                    ++block.nTime;
                }
            }
        }

        //
        // Genesis check
        //
        block.print();        
        printf("block.GetHash() == %s\n", block.GetHash().ToString().c_str());
        printf("block.hashMerkleRoot == %s\n", block.hashMerkleRoot.ToString().c_str());
        printf("block.nTime = %u \n", block.nTime);
        printf("block.nNonce = %u \n", block.nNonce);

        assert(block.hashMerkleRoot == block_param::hashMerkleRoot);
        assert(block.GetHash() == (!args_bool::fTestNet ? block_param::hashGenesisBlock : block_param::hashGenesisBlockTestNet));
        assert(block.CheckBlock());

        //
        // Start new block file
        //
        unsigned int nFile;
        unsigned int nBlockPos;
        if (! block.WriteToDisk(nFile, nBlockPos)) {
            return print::error("LoadBlockIndex() : writing genesis block to disk failed");
        }
        if (! block.AddToBlockIndex(nFile, nBlockPos)) {
            return print::error("LoadBlockIndex() : genesis block not accepted");
        }

        // initialize synchronized checkpoint
        if (! Checkpoints::manage::WriteSyncCheckpoint((!args_bool::fTestNet ? block_param::hashGenesisBlock : block_param::hashGenesisBlockTestNet))) {
            return print::error("LoadBlockIndex() : failed to init sync checkpoint");
        }

        // upgrade time set to zero if txdb initialized
        {
            if (! txdb.WriteModifierUpgradeTime(0)) {
                return print::error("LoadBlockIndex() : failed to init upgrade info");
            }
            printf(" Upgrade Info: ModifierUpgradeTime txdb initialization\n");
        }

    }

    {
        CTxDB txdb("r+");

        //
        // if checkpoint master key changed must reset sync-checkpoint
        //
        std::string strPubKey = "";
        if (!txdb.ReadCheckpointPubKey(strPubKey) || strPubKey != CSyncCheckpoint::strMasterPubKey) {
            //
            // write checkpoint master key to db
            //
            txdb.TxnBegin();
            if (! txdb.WriteCheckpointPubKey(CSyncCheckpoint::strMasterPubKey)) {
                return print::error("LoadBlockIndex() : failed to write new checkpoint master key to db");
            }
            if (! txdb.TxnCommit()) {
                return print::error("LoadBlockIndex() : failed to commit new checkpoint master key to db");
            }
            if ((!args_bool::fTestNet) && !Checkpoints::manage::ResetSyncCheckpoint()) {
                return print::error("LoadBlockIndex() : failed to reset sync-checkpoint");
            }
        }

        //
        // upgrade time set to zero if blocktreedb initialized
        //
        if (txdb.ReadModifierUpgradeTime(bitkernel::nModifierUpgradeTime)) {
            if (bitkernel::nModifierUpgradeTime) {
                printf(" Upgrade Info: blocktreedb upgrade detected at timestamp %d\n", bitkernel::nModifierUpgradeTime);
            } else {
                printf(" Upgrade Info: no blocktreedb upgrade detected.\n");
            }
        } else {
            bitkernel::nModifierUpgradeTime = bitsystem::GetTime();
            printf(" Upgrade Info: upgrading blocktreedb at timestamp %u\n", bitkernel::nModifierUpgradeTime);
            if (! txdb.WriteModifierUpgradeTime(bitkernel::nModifierUpgradeTime)) {
                return print::error("LoadBlockIndex() : failed to write upgrade info");
            }
        }

#ifndef USE_LEVELDB
        txdb.Close();
#endif
    }

    return true;
}

void CBlock::PrintBlockTree()
{
    //
    // pre-compute tree structure
    //
    std::map<CBlockIndex *, std::vector<CBlockIndex *> > mapNext;
    for (std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.begin(); mi != block_info::mapBlockIndex.end(); ++mi)
    {
        CBlockIndex *pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);

        // test
        // while (rand() % 3 == 0)
        // {
        //        mapNext[pindex->pprev].push_back(pindex);
        // }
    }

    std::vector<std::pair<int, CBlockIndex *> > vStack;
    vStack.push_back(std::make_pair(0, block_info::pindexGenesisBlock));

    int nPrevCol = 0;
    while (! vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex *pindex = vStack.back().second;
        vStack.pop_back();

        //
        // print split or gap
        //
        if (nCol > nPrevCol) {
            for (int i = 0; i < nCol-1; ++i)
            {
                printf("| ");
            }
            printf("|\\\n");
        } else if (nCol < nPrevCol) {
            for (int i = 0; i < nCol; ++i)
            {
                printf("| ");
            }
            printf("|\n");
        }
        nPrevCol = nCol;

        //
        // print columns
        //
        for (int i = 0; i < nCol; ++i)
        {
            printf("| ");
        }

        //
        // print item
        //
        CBlock block;
        block.ReadFromDisk(pindex);
        printf("%d (%u,%u) %s  %08x  %s  mint %7s  tx %" PRIszu "\n",
            pindex->nHeight,
            pindex->nFile,
            pindex->nBlockPos,
            block.GetHash().ToString().c_str(),
            block.nBits,
            util::DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()).c_str(),
            bitstr::FormatMoney(pindex->nMint).c_str(),
            block.vtx.size());

        block_notify::PrintWallets(block);

        //
        // put the main time-chain first
        //
        std::vector<CBlockIndex *> &vNext = mapNext[pindex];
        for (unsigned int i = 0; i < vNext.size(); ++i)
        {
            if (vNext[i]->pnext) {
                std::swap(vNext[0], vNext[i]);
                break;
            }
        }

        //
        // iterate children
        //
        for (unsigned int i = 0; i < vNext.size(); ++i)
        {
            vStack.push_back(std::make_pair(nCol+i, vNext[i]));
        }
    }
}

bool block_load::LoadExternalBlockFile(FILE *fileIn)
{
    int64_t nStart = util::GetTimeMillis();

    int nLoaded = 0;
    {
        LOCK(block_process::cs_main);
        try {
            CAutoFile blkdat(fileIn, SER_DISK, version::CLIENT_VERSION);
            unsigned int nPos = 0;
            while (nPos != std::numeric_limits<uint32_t>::max() && blkdat.good() && !args_bool::fRequestShutdown)
            {
                unsigned char pchData[65536];
                do
                {
                    ::fseek(blkdat, nPos, SEEK_SET);
                    size_t nRead = ::fread(pchData, 1, sizeof(pchData), blkdat);
                    if (nRead <= 8) {
                        nPos = std::numeric_limits<uint32_t>::max();
                        break;
                    }

                    void *nFind = ::memchr(pchData, block_info::gpchMessageStart[0], nRead + 1 - sizeof(block_info::gpchMessageStart));
                    if (nFind) {
                        if (::memcmp(nFind, block_info::gpchMessageStart, sizeof(block_info::gpchMessageStart)) == 0 ) {
                            nPos += ((unsigned char *)nFind - pchData) + sizeof(block_info::gpchMessageStart);
                            break;
                        }
                        nPos += ((unsigned char *)nFind - pchData) + 1;
                    } else {
                        nPos += sizeof(pchData) - sizeof(block_info::gpchMessageStart) + 1;
                    }
                } while(! args_bool::fRequestShutdown);

                if (nPos == std::numeric_limits<uint32_t>::max()) {
                    break;
                }

                ::fseek(blkdat, nPos, SEEK_SET);
                unsigned int nSize;
                blkdat >> nSize;
                if (nSize > 0 && nSize <= block_param::MAX_BLOCK_SIZE) {
                    CBlock block;
                    blkdat >> block;
                    if (block_process::manage::ProcessBlock(NULL, &block)) {
                        nLoaded++;
                        nPos += 4 + nSize;
                    }
                }
            }
        } catch (const std::exception &) {
            printf("%s() : Deserialize or I/O error caught during load\n", BOOST_CURRENT_FUNCTION);
        }
    }

    printf("Loaded %i blocks from external file in %" PRId64 "ms\n", nLoaded, util::GetTimeMillis() - nStart);
    return nLoaded > 0;
}

//
// CAlert
//
std::string block_alert::manage::GetWarnings(std::string strFor)
{
    int nPriority = 0;
    std::string strStatusBar;
    std::string strRPC;
    if (map_arg::GetBoolArg("-testsafemode")) {
        strRPC = "test";
    }

    // Misc warnings like out of disk space and clock is wrong
    if (! excep::get_strMiscWarning().empty()) {
        nPriority = 1000;
        strStatusBar = excep::get_strMiscWarning();
    }

    // if detected unmet upgrade requirement enter safe mode
    // Note: Modifier upgrade requires blockchain redownload if past protocol switch
    if (bitkernel::IsFixedModifierInterval(bitkernel::nModifierUpgradeTime + util::nOneDay)) {    // 1 day margin
        nPriority = 5000;
        strStatusBar = strRPC = "WARNING: Blockchain redownload required approaching or past v.1.0.0 upgrade deadline.";
    }

    // if detected invalid checkpoint enter safe mode
    if (Checkpoints::manage::getHashInvalidCheckpoint() != 0) {
        nPriority = 3000;
        strStatusBar = strRPC = _("WARNING: Invalid checkpoint found! Displayed transactions may not be correct! You may need to upgrade, or notify developers.");
    }

    // Alerts
    {
        LOCK(CUnsignedAlert::cs_mapAlerts);
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)&item, CAlert::mapAlerts)
        {
            const CAlert &alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority) {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;
                if (nPriority > 1000) {
                    strRPC = strStatusBar;
                }
            }
        }
    }

    if (strFor == "statusbar") {
        return strStatusBar;
    } else if (strFor == "rpc") {
        return strRPC;
    }

    assert(!"block_alert::manage::GetWarnings() : invalid parameter");
    return "error";
}

//
// Messages
//
bool block_process::manage::AlreadyHave(CTxDB &txdb, const CInv &inv)
{
    switch (inv.get_type())
    {
    case _CINV_MSG_TYPE::MSG_TX:
        {
            bool txInMap = false;
            {
                LOCK(CTxMemPool::mempool.cs);
                txInMap = (CTxMemPool::mempool.exists(inv.get_hash()));
            }
            return  txInMap ||
                    mapOrphanTransactions.count(inv.get_hash()) ||
                    txdb.ContainsTx(inv.get_hash());
        }
        break;
    case _CINV_MSG_TYPE::MSG_BLOCK:
        return  block_info::mapBlockIndex.count(inv.get_hash()) ||
                block_process::mapOrphanBlocks.count(inv.get_hash());
        break;
    }

    // Don't know what it is, just say we already got one
    return true;
}

//
// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
//
// unsigned char gpchMessageStart[4] = { 0xe4, 0xe8, 0xe9, 0xe5 };

bool block_process::manage::ProcessMessage(CNode *pfrom, std::string strCommand, CDataStream &vRecv)
{
    static std::map<CService, CPubKey> mapReuseKey;

    seed::RandAddSeedPerfmon();
    if (args_bool::fDebug) {
        printf("received: %s (%" PRIszu " bytes)\n", strCommand.c_str(), vRecv.size());
    }
    if (map_arg::GetMapArgsCount("-dropmessagestest") && bitsystem::GetRand(atoi(map_arg::GetMapArgsString("-dropmessagestest"))) == 0) {
        printf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

    if (strCommand == "version") {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0) {
            pfrom->Misbehaving(1);
            return false;
        }

        int64_t nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64_t nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion < version::MIN_PROTO_VERSION) {
            // Since February 20, 2012, the protocol is initiated at version 209,
            // and earlier versions are no longer supported
            printf("partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return false;
        }

        if (pfrom->nVersion == 10300) {
            pfrom->nVersion = 300;
        }
        if (! vRecv.empty()) {
            vRecv >> addrFrom >> nNonce;
        }
        if (! vRecv.empty()) {
            vRecv >> pfrom->strSubVer;
        }
        if (! vRecv.empty()) {
            vRecv >> pfrom->nStartingHeight;
        }
        if (pfrom->fInbound && addrMe.IsRoutable()) {
            pfrom->addrLocal = addrMe;
            ext_ip::SeenLocal(addrMe);
        }

        // Disconnect if we connected to ourself
        if (nNonce == bitsocket::nLocalHostNonce && nNonce > 1) {
            printf("connected to self at %s, disconnecting\n", pfrom->addr.ToString().c_str());
            pfrom->fDisconnect = true;
            return true;
        }

        if (pfrom->nVersion < 60010) {
            printf("partner %s using a buggy client %d, disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return true;
        }

        // record my external IP reported by peer
        if (addrFrom.IsRoutable() && addrMe.IsRoutable()) {
            bitsocket::addrSeenByPeer = addrMe;
        }

        // Be shy and don't send version until we hear
        if (pfrom->fInbound) {
            pfrom->PushVersion();
        }

        pfrom->fClient = !(pfrom->nServices & protocol::NODE_NETWORK);

        bitsystem::AddTimeData(pfrom->addr, nTime);

        // Change version
        pfrom->PushMessage("verack");
        pfrom->vSend.SetVersion(std::min(pfrom->nVersion, version::PROTOCOL_VERSION));

        if (! pfrom->fInbound) {
            // Advertise our address
            if (!args_bool::fNoListen && !block_process::manage::IsInitialBlockDownload()) {
                CAddress addr = ext_ip::GetLocalAddress(&pfrom->addr);
                if (addr.IsRoutable()) {
                    pfrom->PushAddress(addr);
                }
            }

            // Get recent addresses
            if (pfrom->fOneShot || pfrom->nVersion >= version::CADDR_TIME_VERSION || net_node::addrman.size() < 1000) {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
            net_node::addrman.Good(pfrom->addr);
        } else {
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom) {
                net_node::addrman.Add(addrFrom, addrFrom);
                net_node::addrman.Good(addrFrom);
            }
        }

        // Ask the first connected node for block updates
        static int nAskedForBlocks = 0;
        if (!pfrom->fClient && 
            !pfrom->fOneShot &&
            (pfrom->nStartingHeight > (block_info::nBestHeight - 144)) &&
            (pfrom->nVersion < version::NOBLKS_VERSION_START || pfrom->nVersion >= version::NOBLKS_VERSION_END) &&
            (nAskedForBlocks < 1 || net_node::vNodes.size() <= 1)) {
            ++nAskedForBlocks;
            pfrom->PushGetBlocks(block_info::pindexBest, uint256(0));
        }

        // Relay alerts
        {
            LOCK(CUnsignedAlert::cs_mapAlerts);
            BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, CAlert::mapAlerts)
            {
                item.second.RelayTo(pfrom);
            }
        }

        // Relay sync-checkpoint
        {
            LOCK(Checkpoints::cs_hashSyncCheckpoint);
            if (! Checkpoints::checkpointMessage.IsNull()) {
                Checkpoints::checkpointMessage.RelayTo(pfrom);
            }
        }

        pfrom->fSuccessfullyConnected = true;

        printf("receive version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", pfrom->nVersion, pfrom->nStartingHeight, addrMe.ToString().c_str(), addrFrom.ToString().c_str(), pfrom->addr.ToString().c_str());

        cPeerBlockCounts.input(pfrom->nStartingHeight);

        // ppcoin: ask for pending sync-checkpoint if any
        if (! block_process::manage::IsInitialBlockDownload()) {
            Checkpoints::manage::AskForPendingSyncCheckpoint(pfrom);
        }
    } else if (pfrom->nVersion == 0) {
        // Must have a version message before anything else
        pfrom->Misbehaving(1);
        return false;
    } else if (strCommand == "verack") {
        pfrom->vRecv.SetVersion(std::min(pfrom->nVersion, version::PROTOCOL_VERSION));
    } else if (strCommand == "addr") {
        std::vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < version::CADDR_TIME_VERSION && net_node::addrman.size() > 1000) {
            return true;
        }
        if (vAddr.size() > 1000) {
            pfrom->Misbehaving(20);
            return print::error("message addr size() = %" PRIszu "", vAddr.size());
        }

        // Store the new addresses
        std::vector<CAddress> vAddrOk;
        int64_t nNow = bitsystem::GetAdjustedTime();
        int64_t nSince = nNow - 10 * 60;
        BOOST_FOREACH(CAddress& addr, vAddr)
        {
            if (args_bool::fShutdown) {
                return true;
            }
            if (addr.get_nTime() <= 100000000 || addr.get_nTime() > nNow + 10 * 60) {
                addr.set_nTime( nNow - 5 * util::nOneDay );
            }

            pfrom->AddAddressKnown(addr);
            bool fReachable = ext_ip::IsReachable(addr);
            if (addr.get_nTime() > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable()) {
                // Relay to a limited number of other nodes
                {
                    LOCK(net_node::cs_vNodes);

                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats

                    static uint256 hashSalt;
                    if (hashSalt == 0) {
                        hashSalt = bitsystem::GetRandHash();
                    }
                    uint64_t hashAddr = addr.GetHash();
                    uint256 hashRand = hashSalt ^ (hashAddr<<32) ^ ((bitsystem::GetTime() + hashAddr) / util::nOneDay);
                    hashRand = hash_basis::Hash(BEGIN(hashRand), END(hashRand));
                    std::multimap<uint256, CNode *> mapMix;
                    BOOST_FOREACH(CNode* pnode, net_node::vNodes)
                    {
                        if (pnode->nVersion < version::CADDR_TIME_VERSION) {
                            continue;
                        }
                        unsigned int nPointer;
                        memcpy(&nPointer, &pnode, sizeof(nPointer));
                        uint256 hashKey = hashRand ^ nPointer;
                        hashKey = hash_basis::Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(std::make_pair(hashKey, pnode));
                    }

                    int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
                    for (std::multimap<uint256, CNode *>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                    {
                        ((*mi).second)->PushAddress(addr);
                    }
                }
            }
            // Do not store addresses outside our network
            if (fReachable) {
                vAddrOk.push_back(addr);
            }
        }

        net_node::addrman.Add(vAddrOk, pfrom->addr, 2 * util::nOneHour);
        if (vAddr.size() < 1000) {
            pfrom->fGetAddr = false;
        }
        if (pfrom->fOneShot) {
            pfrom->fDisconnect = true;
        }
    } else if (strCommand == "inv") {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > block_param::MAX_INV_SZ) {
            pfrom->Misbehaving(20);
            return print::error("message inv size() = %" PRIszu "", vInv.size());
        }

        // find last block in inv vector
        size_t nLastBlock = std::numeric_limits<size_t>::max();
        for (size_t nInv = 0; nInv < vInv.size(); nInv++)
        {
            if (vInv[vInv.size() - 1 - nInv].get_type() == _CINV_MSG_TYPE::MSG_BLOCK) {
                nLastBlock = vInv.size() - 1 - nInv;
                break;
            }
        }

        CTxDB txdb("r");
        for (size_t nInv = 0; nInv < vInv.size(); nInv++)
        {
            const CInv &inv = vInv[nInv];

            if (args_bool::fShutdown) {
                return true;
            }
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = block_process::manage::AlreadyHave(txdb, inv);
            if (args_bool::fDebug) {
                printf("  got inventory: %s  %s\n", inv.ToString().c_str(), fAlreadyHave ? "have" : "new");
            }

            if (! fAlreadyHave) {
                pfrom->AskFor(inv);
            } else if (inv.get_type() == _CINV_MSG_TYPE::MSG_BLOCK && block_process::mapOrphanBlocks.count(inv.get_hash())) {
                pfrom->PushGetBlocks(block_info::pindexBest, block_process::manage::GetOrphanRoot(block_process::mapOrphanBlocks[inv.get_hash()]));
            } else if (nInv == nLastBlock) {
                // In case we are on a very long side-chain, it is possible that we already have
                // the last block in an inv bundle sent in response to getblocks. Try to detect
                // this situation and push another getblocks to continue.
                pfrom->PushGetBlocks(block_info::mapBlockIndex[inv.get_hash()], uint256(0));
                if (args_bool::fDebug) {
                    printf("force request: %s\n", inv.ToString().c_str());
                }
            }

            // Track requests for our stuff
            block_process::manage::Inventory(inv.get_hash());
        }
    } else if (strCommand == "getdata") {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > block_param::MAX_INV_SZ) {
            pfrom->Misbehaving(20);
            return print::error("message getdata size() = %" PRIszu "", vInv.size());
        }
        if (args_bool::fDebugNet || (vInv.size() != 1)) {
            printf("received getdata (%" PRIszu " invsz)\n", vInv.size());
        }

        BOOST_FOREACH(const CInv &inv, vInv)
        {
            if (args_bool::fShutdown) {
                return true;
            }
            if (args_bool::fDebugNet || (vInv.size() == 1)) {
                printf("received getdata for: %s\n", inv.ToString().c_str());
            }

            if (inv.get_type() == _CINV_MSG_TYPE::MSG_BLOCK) {
                // Send block from disk
                std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(inv.get_hash());
                if (mi != block_info::mapBlockIndex.end()) {
                    CBlock block;
                    block.ReadFromDisk((*mi).second);
                    pfrom->PushMessage("block", block);

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.get_hash() == pfrom->hashContinue) {
                        // ppcoin: send latest proof-of-work block to allow the
                        // download node to accept as orphan (proof-of-stake 
                        // block might be rejected by stake connection check)

                        std::vector<CInv> vInv;
                        vInv.push_back(CInv(_CINV_MSG_TYPE::MSG_BLOCK, diff::spacing::GetLastBlockIndex(block_info::pindexBest, false)->GetBlockHash()));
                        pfrom->PushMessage("inv", vInv);
                        pfrom->hashContinue = 0;
                    }
                }
            } else if (inv.IsKnownType()) {
                // Send stream from relay memory
                bool pushed = false;
                {
                    LOCK(net_node::cs_mapRelay);
                    std::map<CInv, CDataStream>::iterator mi = net_node::mapRelay.find(inv);
                    if (mi != net_node::mapRelay.end()) {
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        pushed = true;
                    }
                }
                if (!pushed && inv.get_type() == _CINV_MSG_TYPE::MSG_TX) {
                    LOCK(CTxMemPool::mempool.cs);
                    if (CTxMemPool::mempool.exists(inv.get_hash())) {
                        CTransaction tx = CTxMemPool::mempool.lookup(inv.get_hash());
                        CDataStream ss(SER_NETWORK, version::PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << tx;
                        pfrom->PushMessage("tx", ss);
                    }
                }
            }

            // Track requests for our stuff
            block_process::manage::Inventory(inv.get_hash());
        }
    } else if (strCommand == "getblocks") {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        // Find the last block the caller has in the main chain
        CBlockIndex *pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex) {
            pindex = pindex->pnext;
        }

        int nLimit = 500;
        printf("getblocks %d to %s limit %d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,20).c_str(), nLimit);
        for (; pindex; pindex = pindex->pnext)
        {
            if (pindex->GetBlockHash() == hashStop) {
                printf("  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,20).c_str());
                // ppcoin: tell downloading node about the latest block if it's
                // without risk being rejected due to stake connection check
                if (hashStop != block_info::hashBestChain && pindex->GetBlockTime() + block_check::nStakeMinAge > block_info::pindexBest->GetBlockTime()) {
                    pfrom->PushInventory(CInv(_CINV_MSG_TYPE::MSG_BLOCK, block_info::hashBestChain));
                }
                break;
            }

            pfrom->PushInventory(CInv(_CINV_MSG_TYPE::MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0) {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                printf("  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,20).c_str());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    } else if (strCommand == "checkpoint") {
        CSyncCheckpoint checkpoint;
        vRecv >> checkpoint;

        if (checkpoint.ProcessSyncCheckpoint(pfrom)) {
            // Relay
            pfrom->hashCheckpointKnown = checkpoint.hashCheckpoint;
            LOCK(net_node::cs_vNodes);
            BOOST_FOREACH(CNode* pnode, net_node::vNodes)
            {
                checkpoint.RelayTo(pnode);
            }
        }
    } else if (strCommand == "getheaders") {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        CBlockIndex *pindex = NULL;
        if (locator.IsNull()) {
            // If locator is null, return the hashStop block
            std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hashStop);
            if (mi == block_info::mapBlockIndex.end()) {
                return true;
            }
            pindex = (*mi).second;
        } else {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();
            if (pindex) {
                pindex = pindex->pnext;
            }
        }

        std::vector<CBlock> vHeaders;
        int nLimit = 2000;
        printf("getheaders %d to %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,20).c_str());
        for (; pindex; pindex = pindex->pnext)
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop) {
                break;
            }
        }
        pfrom->PushMessage("headers", vHeaders);
    } else if (strCommand == "tx") {
        std::vector<uint256> vWorkQueue;
        std::vector<uint256> vEraseQueue;
        CDataStream vMsg(vRecv);
        CTxDB txdb("r");
        CTransaction tx;
        vRecv >> tx;

        CInv inv(_CINV_MSG_TYPE::MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        bool fMissingInputs = false;
        if (tx.AcceptToMemoryPool(txdb, true, &fMissingInputs)) {
            wallet_process::manage::SyncWithWallets(tx, NULL, true);
            bitrelay::RelayTransaction(tx, inv.get_hash());
            net_node::mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.get_hash());
            vEraseQueue.push_back(inv.get_hash());

            // Recursively process any orphan transactions that depended on this one
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hashPrev = vWorkQueue[i];
                for (std::set<uint256>::iterator mi = mapOrphanTransactionsByPrev[hashPrev].begin();
                     mi != mapOrphanTransactionsByPrev[hashPrev].end();
                     ++mi)
                {
                    const uint256& orphanTxHash = *mi;
                    CTransaction& orphanTx = mapOrphanTransactions[orphanTxHash];
                    bool fMissingInputs2 = false;

                    if (orphanTx.AcceptToMemoryPool(txdb, true, &fMissingInputs2)) {
                        printf("   accepted orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                        wallet_process::manage::SyncWithWallets(tx, NULL, true);
                        bitrelay::RelayTransaction(orphanTx, orphanTxHash);
                        net_node::mapAlreadyAskedFor.erase(CInv(_CINV_MSG_TYPE::MSG_TX, orphanTxHash));
                        vWorkQueue.push_back(orphanTxHash);
                        vEraseQueue.push_back(orphanTxHash);
                    } else if (!fMissingInputs2) {
                        // invalid orphan
                        vEraseQueue.push_back(orphanTxHash);
                        printf("   removed invalid orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                    }
                }
            }

            BOOST_FOREACH(uint256 hash, vEraseQueue)
            {
                block_process::manage::EraseOrphanTx(hash);
            }
        } else if (fMissingInputs) {

            if(! block_process::manage::AddOrphanTx(tx)) {
                printf("mapOrphan overflow\n");
                return false;    // add
            }

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            unsigned int nEvicted = block_process::manage::LimitOrphanTxSize(block_param::MAX_ORPHAN_TRANSACTIONS);
            if (nEvicted > 0) {
                printf("mapOrphan overflow, removed %u tx\n", nEvicted);
            }
        }
        if (tx.nDoS) {
            pfrom->Misbehaving(tx.nDoS);
        }
    } else if (strCommand == "block") {
        CBlock block;
        vRecv >> block;
        uint256 hashBlock = block.GetHash();

        printf("received block %s\n", hashBlock.ToString().substr(0,20).c_str());
        // block.print();

        CInv inv(_CINV_MSG_TYPE::MSG_BLOCK, hashBlock);
        pfrom->AddInventoryKnown(inv);

        if (block_process::manage::ProcessBlock(pfrom, &block)) {
            net_node::mapAlreadyAskedFor.erase(inv);
        }
        if (block.nDoS) {
            pfrom->Misbehaving(block.nDoS);
        }
    } else if ((strCommand == "getaddr") && (pfrom->fInbound)) {
        // This asymmetric behavior for inbound and outbound connections was introduced
        // to prevent a fingerprinting attack: an attacker can send specific fake addresses
        // to users' AddrMan and later request them by sending getaddr messages. 
        // Making users (which are behind NAT and can only make outgoing connections) ignore 
        // getaddr message mitigates the attack.

        // Don't return addresses older than nCutOff timestamp
        int64_t nCutOff = bitsystem::GetTime() - (args_uint::nNodeLifespan * util::nOneDay);
        pfrom->vAddrToSend.clear();
        std::vector<CAddress> vAddr = net_node::addrman.GetAddr();
        BOOST_FOREACH(const CAddress &addr, vAddr)
        {
            if(addr.get_nTime() > nCutOff) {
                pfrom->PushAddress(addr);
            }
        }
    } else if (strCommand == "mempool") {
        std::vector<uint256> vtxid;
        CTxMemPool::mempool.queryHashes(vtxid);
        std::vector<CInv> vInv;
        for (unsigned int i = 0; i < vtxid.size(); ++i)
        {
            CInv inv(_CINV_MSG_TYPE::MSG_TX, vtxid[i]);
            vInv.push_back(inv);
            if (i == (block_param::MAX_INV_SZ - 1)) {
                break;
            }
        }
        if (vInv.size() > 0) {
            pfrom->PushMessage("inv", vInv);
        }
    } else if (strCommand == "checkorder") {
        uint256 hashReply;
        vRecv >> hashReply;
        if (! map_arg::GetBoolArg("-allowreceivebyip")) {
            pfrom->PushMessage("reply", hashReply, 2, std::string(""));
            return true;
        }

        CWalletTx order;
        vRecv >> order;
        /// we have a chance to check the order here

        // Keep giving the same key to the same ip until they use it
        if (! mapReuseKey.count(pfrom->addr)) {
            entry::pwalletMain->GetKeyFromPool(mapReuseKey[pfrom->addr], true);
        }

        // Send back approval of order and pubkey to use
        CScript scriptPubKey;
        scriptPubKey << mapReuseKey[pfrom->addr] << ScriptOpcodes::OP_CHECKSIG;
        pfrom->PushMessage("reply", hashReply, 0, scriptPubKey);
    } else if (strCommand == "reply") {
        uint256 hashReply;
        vRecv >> hashReply;

        CRequestTracker tracker;
        {
            LOCK(pfrom->cs_mapRequests);
            std::map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
            if (mi != pfrom->mapRequests.end()) {
                tracker = (*mi).second;
                pfrom->mapRequests.erase(mi);
            }
        }
        if (! tracker.IsNull()) {
            tracker.fn(tracker.param1, vRecv);
        }
    } else if (strCommand == "ping") {
        uint64_t nonce = 0;
        vRecv >> nonce;
        // Echo the message back with the nonce. This allows for two useful features:
        //
        // 1) A remote node can quickly check if the connection is operational
        // 2) Remote nodes can measure the latency of the network thread. If this node
        //    is overloaded it won't respond to pings quickly and the remote node can
        //    avoid sending us more work, like chain download requests.
        //
        // The nonce stops the remote getting confused between different pings: without
        // it, if the remote node sends a ping once per second and this node takes 5
        // seconds to respond to each, the 5th ping the remote sends would appear to
        // return very quickly.
        pfrom->PushMessage("pong", nonce);
    } else if (strCommand == "alert") {
        CAlert alert;
        vRecv >> alert;

        uint256 alertHash = alert.GetHash();
        if (pfrom->setKnown.count(alertHash) == 0) {
            if (alert.ProcessAlert()) {
                // Relay
                pfrom->setKnown.insert(alertHash);
                {
                    LOCK(net_node::cs_vNodes);
                    BOOST_FOREACH(CNode *pnode, net_node::vNodes)
                    {
                        alert.RelayTo(pnode);
                    }
                }
            } else {
                // Small DoS penalty so peers that send us lots of
                // duplicate/expired/invalid-signature/whatever alerts
                // eventually get banned.
                // This isn't a Misbehaving(100) (immediate ban) because the
                // peer might be an older or different implementation with
                // a different signature key, etc.
                pfrom->Misbehaving(10);
            }
        }
    } else {
        // Ignore unknown commands for extensibility
    }

    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode) {
        if (strCommand == "version" || strCommand == "addr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping") {
            net_node::AddressCurrentlyConnected(pfrom->addr);
        }
    }

    return true;
}

bool block_process::manage::ProcessMessages(CNode *pfrom)
{
    CDataStream& vRecv = pfrom->vRecv;
    if (vRecv.empty()) {
        return true;
    }

    // if (args_bool::fDebug) {
    //        printf("ProcessMessages(%u bytes)\n", vRecv.size());
    // }

    ////////////////////////////////////////////////////////////
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    ////////////////////////////////////////////////////////////

    for ( ; ; )
    {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->vSend.size() >= net_node::SendBufferSize()) {
            break;
        }

        // Scan for message start
        CDataStream::iterator pstart = search(vRecv.begin(), vRecv.end(), BEGIN(block_info::gpchMessageStart), END(block_info::gpchMessageStart));
        int nHeaderSize = vRecv.GetSerializeSize(CMessageHeader());
        if (vRecv.end() - pstart < nHeaderSize) {
            if ((int)vRecv.size() > nHeaderSize) {
                printf("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n");
                vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
            }
            break;
        }
        if (pstart - vRecv.begin() > 0) {
            printf("\n\nPROCESSMESSAGE SKIPPED %" PRIpdd " BYTES\n\n", pstart - vRecv.begin());
        }
        vRecv.erase(vRecv.begin(), pstart);

        // Read header
        std::vector<char> vHeaderSave(vRecv.begin(), vRecv.begin() + nHeaderSize);
        CMessageHeader hdr;
        vRecv >> hdr;
        if (! hdr.IsValid()) {
            printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        std::string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.GetMessageSize();
        if (nMessageSize > compact_size::MAX_SIZE) {
            printf("block_process::manage::ProcessMessages(%s, %u bytes) : nMessageSize > compact_size::MAX_SIZE\n", strCommand.c_str(), nMessageSize);
            continue;
        }
        if (nMessageSize > vRecv.size()) {
            // Rewind and wait for rest of message
            vRecv.insert(vRecv.begin(), vHeaderSave.begin(), vHeaderSave.end());
            break;
        }

        // Checksum
        uint256 hash = hash_basis::Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
        unsigned int nChecksum = 0;
        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        if (nChecksum != hdr.GetChecksum()) {
            printf("block_process::manage::ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n", strCommand.c_str(), nMessageSize, nChecksum, hdr.GetChecksum());
            continue;
        }

        // Copy message to its own buffer
        CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType, vRecv.nVersion);
        vRecv.ignore(nMessageSize);

        // Process message
        bool fRet = false;
        try {
            {
                LOCK(block_process::cs_main);
                fRet = block_process::manage::ProcessMessage(pfrom, strCommand, vMsg);
            }
            if (args_bool::fShutdown) {
                return true;
            }
        } catch (std::ios_base::failure &e) {
            if (::strstr(e.what(), "end of data")) {
                // Allow exceptions from under-length message on vRecv
                printf("block_process::manage::ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
            } else if (strstr(e.what(), "size too large")) {
                // Allow exceptions from over-long size
                printf("block_process::manage::ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
            } else {
                excep::PrintExceptionContinue(&e, "block_process::manage::ProcessMessages()");
            }
        } catch (std::exception &e) {
            excep::PrintExceptionContinue(&e, "block_process::manage::ProcessMessages()");
        } catch (...) {
            excep::PrintExceptionContinue(NULL, "block_process::manage::ProcessMessages()");
        }
        if (! fRet) {
            printf("block_process::manage::ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(), nMessageSize);
        }
    }

    vRecv.Compact();
    return true;
}

bool block_process::manage::SendMessages(CNode *pto)
{
    TRY_LOCK(block_process::cs_main, lockMain);
    if (lockMain) {
        // Current time in microseconds
        int64_t nNow = util::GetTimeMicros();

        // Don't send anything until we get their version message
        if (pto->nVersion == 0) {
            return true;
        }

        // Keep-alive ping. We send a nonce of zero because we don't use it anywhere
        // right now.
        if (pto->nLastSend && bitsystem::GetTime() - pto->nLastSend > block_process::manage::nPingInterval && pto->vSend.empty()) {
            uint64_t nonce = 0;
            pto->PushMessage("ping", nonce);
        }

        // Start block sync
        if (pto->fStartSync) {
            pto->fStartSync = false;
            pto->PushGetBlocks(block_info::pindexBest, uint256(0));
        }

        // Resend wallet transactions that haven't gotten in a block yet
        block_process::manage::ResendWalletTransactions();

        // Address refresh broadcast
        if (! block_process::manage::IsInitialBlockDownload() && pto->nNextLocalAddrSend < nNow) {
            ext_ip::AdvertiseLocal(pto);
            pto->nNextLocalAddrSend = future_time::PoissonNextSend(nNow, util::nOneDay);
        }

        // Message: addr
        if (pto->nNextAddrSend < nNow) {
            pto->nNextAddrSend = future_time::PoissonNextSend(nNow, 30);
            std::vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend)
            {
                if (pto->setAddrKnown.insert(addr).second) {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000) {
                        pto->PushMessage("addr", vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (! vAddr.empty()) {
                pto->PushMessage("addr", vAddr);
            }
        }

        // Message: inventory
        std::vector<CInv> vInv;
        std::vector<CInv> vInvWait;
        {
            bool fSendTrickle = false;
            if (pto->nNextInvSend < nNow) {
                fSendTrickle = true;
                pto->nNextInvSend = future_time::PoissonNextSend(nNow, 5);
            }

            LOCK(pto->cs_inventory);
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend)
            {
                if (pto->setInventoryKnown.count(inv)) {
                    continue;
                }

                // trickle out tx inv to protect privacy
                if (inv.get_type() == _CINV_MSG_TYPE::MSG_TX && !fSendTrickle) {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;
                    if (hashSalt == 0) {
                        hashSalt = bitsystem::GetRandHash();
                    }

                    uint256 hashRand = inv.get_hash() ^ hashSalt;
                    hashRand = hash_basis::Hash(BEGIN(hashRand), END(hashRand));
                    bool fTrickleWait = ((hashRand & 3) != 0);

                    if (fTrickleWait) {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second) {
                    vInv.push_back(inv);
                    if (vInv.size() >= 1000) {
                        pto->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (! vInv.empty()) {
            pto->PushMessage("inv", vInv);
        }

        // Message: getdata
        std::vector<CInv> vGetData;
        CTxDB txdb("r");
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (! block_process::manage::AlreadyHave(txdb, inv)) {
                if (args_bool::fDebugNet) {
                    printf("sending getdata: %s\n", inv.ToString().c_str());
                }

                vGetData.push_back(inv);
                if (vGetData.size() >= 1000) {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
                net_node::mapAlreadyAskedFor[inv] = nNow;
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (! vGetData.empty()) {
            pto->PushMessage("getdata", vGetData);
        }
    }
    return true;
}

//
// main cleanup
// Singleton Class
//
class CMainCleanup
{
private:
    static CMainCleanup instance_of_cmaincleanup;

    CMainCleanup() {}
    ~CMainCleanup() {
        //
        // Thread stop
        //

        //
        // block headers
        //
        std::map<uint256, CBlockIndex *>::iterator it1 = block_info::mapBlockIndex.begin();
        for (; it1 != block_info::mapBlockIndex.end(); it1++)
        {
            delete (*it1).second;
        }
        block_info::mapBlockIndex.clear();

        //
        // orphan blocks
        //
        std::map<uint256, CBlock *>::iterator it2 = block_process::mapOrphanBlocks.begin();
        for (; it2 != block_process::mapOrphanBlocks.end(); it2++)
        {
            delete (*it2).second;
        }
        block_process::mapOrphanBlocks.clear();

        // orphan transactions
        // development ...
    }
};
CMainCleanup CMainCleanup::instance_of_cmaincleanup;
