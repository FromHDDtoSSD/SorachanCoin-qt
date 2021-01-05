// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINADDRESSVALIDATOR_H
#define BITCOINADDRESSVALIDATOR_H

#include <QRegExpValidator>

/** Base48 entry widget validator.
   Corrects near-miss characters and refuses characters that are no part of base48.
 */
class BitcoinAddressValidator : public QValidator
{
    Q_OBJECT
private:
    BitcoinAddressValidator(const BitcoinAddressValidator &)=delete;
    BitcoinAddressValidator &operator=(const BitcoinAddressValidator &)=delete;
    BitcoinAddressValidator(BitcoinAddressValidator &&)=delete;
    BitcoinAddressValidator &operator=(BitcoinAddressValidator &&)=delete;
public:
    static constexpr int MaxAddressLength = 99;
    explicit BitcoinAddressValidator(QObject *parent = 0);
    State validate(QString &input, int &pos) const;
signals:

public slots:

};

#endif // BITCOINADDRESSVALIDATOR_H
