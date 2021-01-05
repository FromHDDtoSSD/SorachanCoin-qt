// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINUNITS_H
#define BITCOINUNITS_H

#include <QString>
#include <QAbstractListModel>
#include <stdint.h>

/** Bitcoin unit definitions. Encapsulates parsing and formatting
   and serves as list model for drop-down selection boxes.
*/
class BitcoinUnits: public QAbstractListModel
{
private:
    BitcoinUnits(const BitcoinUnits &)=delete;
    BitcoinUnits &operator=(const BitcoinUnits &)=delete;
    BitcoinUnits(BitcoinUnits &&)=delete;
    BitcoinUnits &operator=(BitcoinUnits &&)=delete;
public:
    explicit BitcoinUnits(QObject *parent);

    /** Bitcoin units.
      @note Source: https://en.bitcoin.it/wiki/Units . Please add only sensible ones
     */
    enum Unit {
        BTC,
        mBTC,
        uBTC,
        undef_BTC
    };

    //! @name Static API
    //! Unit conversion and formatting
    //! Get list of units, for drop-down box
    static QList<Unit> availableUnits();
    //! Is unit ID valid?
    static bool valid(Unit unit);
    //! Short name
    static QString name(Unit unit);
    //! Longer description
    static QString description(Unit unit);
    //! Number of Satoshis (1e-8) per unit
    static qint64 factor(Unit unit);
    //! Number of amount digits (to represent max number of coins)
    static int amountDigits(Unit unit);
    //! Number of decimals left
    static int decimals(Unit unit);
    //! Format as string
    static QString format(Unit unit, qint64 amount, bool plussign=false, uint8_t nNumberOfZeros=2);
    //! Format as string (with unit)
    static QString formatWithUnit(Unit unit, qint64 amount, bool plussign=false, uint8_t nNumberOfZeros=2);
    //! Parse string to coin amount
    static bool parse(Unit unit, const QString &value, qint64 *val_out);
    //! Gets title for amount column including current display unit if optionsModel reference available */
    static QString getAmountColumnTitle(Unit unit);

    //! @name AbstractListModel implementation
    //! List model for unit drop-down selection box.
    enum RoleIndex {
        /** Unit identifier */
        UnitRole = Qt::UserRole
    };
    int rowCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
private:
    QList<BitcoinUnits::Unit> unitlist;
};
using BitcoinUnit = BitcoinUnits::Unit;

#endif // BITCOINUNITS_H
