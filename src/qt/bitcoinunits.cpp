// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bitcoinunits.h>
#include <QStringList>
#include <allocator/qtsecure.h>

BitcoinUnits::BitcoinUnits(QObject *parent):
        QAbstractListModel(parent),
        unitlist(availableUnits())
{
}

QList<BitcoinUnits::Unit> BitcoinUnits::availableUnits() {
    QList<BitcoinUnits::Unit> unitlist;
    unitlist.append(BTC);
    unitlist.append(mBTC);
    unitlist.append(uBTC);
    return unitlist;
}

bool BitcoinUnits::valid(Unit unit) {
    switch(unit)
    {
    case BTC:
    case mBTC:
    case uBTC:
        return true;
    default:
        return false;
    }
}

QString BitcoinUnits::name(Unit unit) {
    switch(unit)
    {
    case BTC: return QString("SORA");
    case mBTC: return QString("mSORA");
    case uBTC: return QString::fromUtf8("μSORA");
    default:
        throw qt_error("invalid BitcoinUnits::name", nullptr);
        return QString("???");
    }
}

QString BitcoinUnits::description(Unit unit) {
    switch(unit)
    {
    case BTC: return QString(QObject::tr("SorachanCoins"));
    case mBTC: return QString(QObject::tr("Milli-SorachanCoins (1 / 1,000)"));
    case uBTC: return QString(QObject::tr("Micro-SorachanCoins (1 / 1,000,000)"));
    default:
        throw qt_error("invalid BitcoinUnits::description", nullptr);
        return QString("???");
    }
}

qint64 BitcoinUnits::factor(Unit unit) {
    switch(unit)
    {
    case BTC:  return 1000000;
    case mBTC: return 1000;
    case uBTC: return 1;
    default:
        throw qt_error("invalid BitcoinUnits::factor", nullptr);
        return 1000000;
    }
}

int BitcoinUnits::amountDigits(Unit unit) {
    switch(unit)
    {
    //case BTC: return 8; // 21,000,000 (# digits, without commas)
    //case mBTC: return 11; // 21,000,000,000
    //case uBTC: return 14; // 21,000,000,000,000
    case BTC: return 7; // 8,000,000 (# digits, without commas)
    case mBTC: return 10; // 8,000,000,000
    case uBTC: return 13; // 8,000,000,000,000
    default:
        throw qt_error("invalid BitcoinUnits::amountDigits", nullptr);
        return 0;
    }
}

int BitcoinUnits::decimals(Unit unit) {
    switch(unit)
    {
    case BTC: return 6;
    case mBTC: return 3;
    case uBTC: return 0;
    default:
        throw qt_error("invalid BitcoinUnits::decimals", nullptr);
        return 0;
    }
}

QString BitcoinUnits::format(Unit unit, qint64 n, bool fPlus, uint8_t nNumberOfZeros) {
    // Note: not using straight sprintf here because we do NOT want
    // localized number formatting.
    if(! valid(unit)) {
        return QString(); // Refuse to format invalid unit
    }

    qint64 coin = factor(unit);
    int num_decimals = decimals(unit);
    qint64 n_abs = (n > 0 ? n : -n);
    qint64 quotient = n_abs / coin;
    qint64 remainder = n_abs % coin;
    QString quotient_str = QString::number(quotient);
    QString remainder_str = QString::number(remainder).rightJustified(num_decimals, '0');

    // Right-trim excess zeros after the decimal point
    int nTrim = 0;
    for (int i = remainder_str.size()-1; i>=nNumberOfZeros && (remainder_str.at(i) == '0'); --i)
        ++nTrim;

    remainder_str.chop(nTrim);

    if (n < 0) {
        quotient_str.insert(0, '-');
    } else if (fPlus && n > 0) {
        quotient_str.insert(0, '+');
    }
    return quotient_str + QString(".") + remainder_str;
}

QString BitcoinUnits::formatWithUnit(Unit unit, qint64 amount, bool plussign, uint8_t nNumberOfZeros) {
    return format(unit, amount, plussign, nNumberOfZeros) + QString(" ") + name(unit);
}

bool BitcoinUnits::parse(Unit unit, const QString &value, qint64 *val_out) {
    if(!valid(unit) || value.isEmpty()) {
        return false; // Refuse to parse invalid unit or empty string
    }

    int num_decimals = decimals(unit);
    QStringList parts = value.split(".");

    if(parts.size() > 2) {
        return false; // More than one dot
    }

    QString whole = parts[0];
    QString decimals;

    if(parts.size() > 1) {
        decimals = parts[1];
    }
    if(decimals.size() > num_decimals) {
        return false; // Exceeds max precision
    }

    bool ok = false;
    QString str = whole + decimals.leftJustified(num_decimals, '0');

    if(str.size() > 18) {
        return false; // Longer numbers will exceed 63 bits
    }

    qint64 retvalue = str.toLongLong(&ok);
    if(val_out) {
        *val_out = retvalue;
    }
    return ok;
}

int BitcoinUnits::rowCount(const QModelIndex &parent) const {
    Q_UNUSED(parent);
    return unitlist.size();
}

QVariant BitcoinUnits::data(const QModelIndex &index, int role) const {
    int row = index.row();
    if(row >= 0 && row < unitlist.size()) {
        Unit unit = unitlist.at(row);
        switch(role)
        {
        case Qt::EditRole:
        case Qt::DisplayRole:
            return QVariant(name(unit));
        case Qt::ToolTipRole:
            return QVariant(description(unit));
        case UnitRole:
            return QVariant(static_cast<int>(unit));
        }
    }
    return QVariant();
}

QString BitcoinUnits::getAmountColumnTitle(Unit unit) {
    QString amountTitle = QObject::tr("Amount");
    if (BitcoinUnits::valid(unit)) {
        amountTitle += " ("+BitcoinUnits::name(unit) + ")";
    }
    return amountTitle;
}
