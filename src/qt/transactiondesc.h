// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TRANSACTIONDESC_H
#define TRANSACTIONDESC_H

#include <QString>
#include <QObject>
#include <string>

class CWallet;
class CWalletTx;

/** Provide a human-readable extended HTML description of a transaction.
 */
class TransactionDesc: public QObject
{
    Q_OBJECT
private:
    TransactionDesc(const TransactionDesc &)=delete;
    TransactionDesc &operator=(const TransactionDesc &)=delete;
    TransactionDesc(TransactionDesc &&)=delete;
    TransactionDesc &operator=(TransactionDesc &&)=delete;
public:
    static QString toHTML(CWallet *wallet, CWalletTx &wtx);
private:
    TransactionDesc() {}

    static QString FormatTxStatus(const CWalletTx& wtx);
};

#endif // TRANSACTIONDESC_H
