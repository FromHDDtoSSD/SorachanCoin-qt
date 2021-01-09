// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TRANSACTIONRECORD_H
#define TRANSACTIONRECORD_H

#include <uint256.h>
#include <map>
#include <QList>

class CWallet;
class CWalletTx;

/** UI model for transaction status. The transaction status is the part of a transaction that will change over time.
 */
class TransactionStatus
{
private:
    //TransactionStatus(const TransactionStatus &)=delete;
    //TransactionStatus &operator =(const TransactionStatus &)=delete;
    //TransactionStatus(TransactionStatus &&)=delete;
    //TransactionStatus &operator =(TransactionStatus &&)=delete;
public:
    TransactionStatus():
            confirmed(false), sortKey(""), maturity(Mature),
            matures_in(0), status(Offline), depth(0), open_for(0), cur_num_blocks(-1)
    {
    }

    enum Maturity
    {
        Immature,
        Mature,
        MaturesWarning, /**< Transaction will likely not mature because no nodes have confirmed */
        NotAccepted
    };

    enum Status {
        OpenUntilDate,
        OpenUntilBlock,
        Offline,
        Unconfirmed,
        HaveConfirmations
    };

    bool confirmed;
    std::string sortKey;

    /** @name Generated (mined) transactions
       @{*/
    Maturity maturity;
    int matures_in;
    /**@}*/

    /** @name Reported status
       @{*/
    Status status;
    int64_t depth;
    int64_t open_for; /**< Timestamp if status==OpenUntilDate, otherwise number of blocks */
    /**@}*/

    /** Current number of blocks (to know whether cached status is still valid) */
    int cur_num_blocks;
};

/** UI model for a transaction. A core transaction can be represented by multiple UI transactions if it has
    multiple outputs.
 */
class TransactionRecord
{
private:
    //TransactionRecord(const TransactionRecord &)=delete;
    //TransactionRecord &operator =(const TransactionRecord &)=delete;
    //TransactionRecord(TransactionRecord &&)=delete;
    //TransactionRecord &operator =(TransactionRecord &&)=delete;
public:
    enum Type
    {
        Other,
        Generated,
        SendToAddress,
        SendToOther,
        RecvWithAddress,
        RecvFromOther,
        SendToSelf
    };

    /** Number of confirmation needed for transaction */
    static constexpr int defConfirmations = 6;
    static std::map<const TransactionRecord *, int> mapConfirmations;

    TransactionRecord():
            hash(), time(0), type(Other), address(""), debit(0), credit(0), idx(0)
    {
    }

    TransactionRecord(uint256 hash, int64_t time):
            hash(hash), time(time), type(Other), address(""), debit(0),
            credit(0), idx(0)
    {
    }

    TransactionRecord(uint256 hash, int64_t time,
                Type type, const std::string &address,
                int64_t debit, int64_t credit):
            hash(hash), time(time), type(type), address(address), debit(debit), credit(credit),
            idx(0)
    {
    }

    /** Decompose CWallet transaction to model transaction records.
     */
    static bool showTransaction(const CWalletTx &wtx);
    static QList<TransactionRecord> decomposeTransaction(const CWallet *wallet, const CWalletTx &wtx);

    /** @name Immutable transaction attributes
      @{*/
    uint256 hash;
    int64_t time;
    Type type;
    std::string address;
    int64_t debit;
    int64_t credit;
    /**@}*/

    /** Subtransaction index, for sort key */
    int idx;

    /** Status: can change with block chain update */
    TransactionStatus status;

    /** Return the unique identifier for this transaction (part) */
    std::string getTxID();

    /** Update status from core wallet tx.
     */
    void updateStatus(const CWalletTx &wtx);

    /** Return whether a status update is needed.
     */
    bool statusUpdateNeeded();
};

#endif // TRANSACTIONRECORD_H
