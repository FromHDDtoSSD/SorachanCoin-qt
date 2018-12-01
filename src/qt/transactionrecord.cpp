
#include "transactionrecord.h"

#include "init.h"
#include "wallet.h"
#include "base58.h"

std::map<const TransactionRecord *, int> TransactionRecord::mapConfirmations;

/*
 * Return positive answer if transaction should be shown in list.
 */
bool TransactionRecord::showTransaction(const CWalletTx &wtx)
{
    if (wtx.IsCoinBase()) {
        //
        // Ensures we show generated coins / mined transactions at depth 1
        //
        if (! wtx.IsInMainChain()) {
            return false;
        }
    }
    return true;
}

/*
 * Decompose CWallet transaction to model transaction records.
 */
QList<TransactionRecord> TransactionRecord::decomposeTransaction(const CWallet *wallet, const CWalletTx &wtx)
{
    QList<TransactionRecord> parts;
    int64_t nTime = wtx.GetTxTime();
    int64_t nCredit = wtx.GetCredit(MINE_ALL);
    int64_t nDebit = wtx.GetDebit(MINE_ALL);
    int64_t nNet = nCredit - nDebit;
    uint256 hash = wtx.GetHash(), hashPrev = 0;
    std::map<std::string, std::string> mapValue = wtx.mapValue;
    
    bool fCoinBase = wtx.IsCoinBase(),
         fCoinStake = wtx.IsCoinStake();

    if (nNet > 0 || fCoinBase || fCoinStake) {
        //
        // Credit
        //
        BOOST_FOREACH(const CTxOut &txout, wtx.vout)
        {
            if(wallet->IsMine(txout)) {
                TransactionRecord sub(hash, nTime);
                sub.idx = parts.size(); // sequence number
                sub.credit = txout.nValue;

                CBitcoinAddress addressRet;
                if (Script_util::ExtractAddress(*entry::pwalletMain, txout.scriptPubKey, addressRet)) {
                    sub.type = TransactionRecord::RecvWithAddress;
                    sub.address = addressRet.ToString();
                } else {
                    //
                    // Received by IP connection (deprecated features), or a multisignature or other non-simple transaction
                    //
                    sub.type = TransactionRecord::RecvFromOther;
                    sub.address = mapValue["from"];
                }

                if (fCoinBase || fCoinStake) {
                    //
                    // Generated
                    //
                    sub.type = TransactionRecord::Generated;
                    if (fCoinStake) {
                        //
                        // proof-of-stake
                        //
                        if (hashPrev == hash) {
                            continue; // last coinstake output
                        }
                        sub.credit = nNet > 0 ? nNet : wtx.GetValueOut() - nDebit;
                        hashPrev = hash;
                    }
                }

                parts.append(sub);
            }
        }
    } else {
        bool fAllFromMe = true;
        BOOST_FOREACH(const CTxIn &txin, wtx.vin)
        {
            fAllFromMe = fAllFromMe && wallet->IsMine(txin);
        }

        bool fAllToMe = true;
        BOOST_FOREACH(const CTxOut &txout, wtx.vout)
        {
            fAllToMe = fAllToMe && wallet->IsMine(txout);
        }

        if (fAllFromMe && fAllToMe) {
            //
            // Payment to self
            //
            int64_t nChange = wtx.GetChange();

            parts.append(TransactionRecord(hash, nTime, TransactionRecord::SendToSelf, "", -(nDebit - nChange), nCredit - nChange));
        } else if (fAllFromMe) {
            //
            // Debit
            //
            int64_t nTxFee = nDebit - wtx.GetValueOut();

            for (unsigned int nOut = 0; nOut < wtx.vout.size(); ++nOut)
            {
                const CTxOut &txout = wtx.vout[nOut];
                TransactionRecord sub(hash, nTime);
                sub.idx = parts.size();

                if(wallet->IsMine(txout)) {
                    //
                    // Ignore parts sent to self, as this is usually the change
                    // from a transaction sent back to our own address.
                    //
                    continue;
                }

                CTxDestination address;
                if (Script_util::ExtractDestination(txout.scriptPubKey, address)) {
                    //
                    // Sent to Bitcoin Address
                    //
                    sub.type = TransactionRecord::SendToAddress;
                    sub.address = CBitcoinAddress(address).ToString();
                } else {
                    //
                    // Sent to IP, or other non-address transaction like OP_EVAL
                    //
                    sub.type = TransactionRecord::SendToOther;
                    sub.address = mapValue["to"];
                }

                int64_t nValue = txout.nValue;
                /* Add fee to first output */
                if (nTxFee > 0) {
                    nValue += nTxFee;
                    nTxFee = 0;
                }
                sub.debit = -nValue;

                parts.append(sub);
            }
        } else {
            //
            // Mixed debit transaction, can't break down payees
            //
            parts.append(TransactionRecord(hash, nTime, TransactionRecord::Other, "", nNet, 0));
        }
    }

    return parts;
}

// Determine transaction status
void TransactionRecord::updateStatus(const CWalletTx &wtx)
{
    //
    // Find the block the tx is in
    //
    CBlockIndex *pindex = NULL;
    std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(wtx.hashBlock);
    if (mi != block_info::mapBlockIndex.end()) {
        pindex = (*mi).second;
    }

    //
    // debug
    // TransactionID -> wtx.GetHash()
    //
    //int64_t nCredit = wtx.GetCredit(MINE_ALL);
    //int64_t nDebit = wtx.GetDebit(MINE_ALL);
    //int64_t nMine = nCredit - nDebit;
    //printf("TransactionRecord::updateStatus %s _ %I64d %d %d\n", wtx.GetHash().ToString().c_str(), nMine, wtx.IsCoinBase(), wtx.IsCoinStake());

    //
    // Find confirmations
    //
    int NumConfirmations = (wtx.IsCoinBase() || wtx.IsCoinStake()) ? block_transaction::nCoinbaseMaturity: TransactionRecord::defConfirmations;
    //if(pindex && pindex->IsProofOfStake()) {
    //    NumConfirmations = block_transaction::nCoinbaseMaturity;
    //}
    TransactionRecord::mapConfirmations.insert(std::make_pair(this, NumConfirmations));

    //
    // Sort order, unrecorded transactions sort to the top
    //
    status.sortKey = strprintf("%010d-%01d-%010u-%03d",
        (pindex ? pindex->nHeight : std::numeric_limits<int>::max()),
        (wtx.IsCoinBase() ? 1 : 0),
        wtx.nTimeReceived,
        idx);
    status.confirmed = wtx.IsTrusted();
    status.depth = wtx.GetDepthInMainChain();
    status.cur_num_blocks = block_info::nBestHeight;

    if (! wtx.IsFinal()) {
        if (wtx.nLockTime < block_param::LOCKTIME_THRESHOLD) {
            status.status = TransactionStatus::OpenUntilBlock;
            status.open_for = block_info::nBestHeight - wtx.nLockTime;
        } else {
            status.status = TransactionStatus::OpenUntilDate;
            status.open_for = wtx.nLockTime;
        }
    } else {
        if (bitsystem::GetAdjustedTime() - wtx.nTimeReceived > 2 * 60 && wtx.GetRequestCount() == 0) {
            status.status = TransactionStatus::Offline;
        } else if (status.depth < NumConfirmations) {
            status.status = TransactionStatus::Unconfirmed;
        } else {
            status.status = TransactionStatus::HaveConfirmations;
        }
    }

    //
    // For generated transactions, determine maturity
    //
    if(type == TransactionRecord::Generated) {
        if (wtx.GetBlocksToMaturity() > 0) {
            status.maturity = TransactionStatus::Immature;

            if (wtx.IsInMainChain()) {
                status.matures_in = wtx.GetBlocksToMaturity();

                // Check if the block was requested by anyone
                if (bitsystem::GetAdjustedTime() - wtx.nTimeReceived > 2 * 60 && wtx.GetRequestCount() == 0) {
                    status.maturity = TransactionStatus::MaturesWarning;
                }
            } else {
                status.maturity = TransactionStatus::NotAccepted;
            }
        } else {
            status.maturity = TransactionStatus::Mature;
        }
    }
}

bool TransactionRecord::statusUpdateNeeded()
{
    return status.cur_num_blocks != block_info::nBestHeight;
}

std::string TransactionRecord::getTxID()
{
    return hash.ToString() + strprintf("-%03d", idx);
}
