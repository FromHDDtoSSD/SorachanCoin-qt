// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINFIELD_H
#define BITCOINFIELD_H

#include <qt/bitcoinunits.h>
#include <QWidget>

QT_BEGIN_NAMESPACE
class QDoubleSpinBox;
class QValueComboBox;
QT_END_NAMESPACE

/** Widget for entering bitcoin amounts.
  */
class BitcoinAmountField: public QWidget
{
    Q_OBJECT
    Q_PROPERTY(qint64 value READ value WRITE setValue NOTIFY textChanged USER true)
private:
    BitcoinAmountField(const BitcoinAmountField &)=delete;
    BitcoinAmountField &operator=(const BitcoinAmountField &)=delete;
    BitcoinAmountField(BitcoinAmountField &&)=delete;
    BitcoinAmountField &operator=(BitcoinAmountField &&)=delete;
public:
    explicit BitcoinAmountField(QWidget *parent = nullptr);
    qint64 value(bool *valid = nullptr) const;
    void setValue(qint64 value);

    /** Mark current value as invalid in UI. */
    void setValid(bool valid);
    /** Perform input validation, mark field as invalid if entered value is not valid. */
    bool validate();

    /** Change unit used to display amount. */
    void setDisplayUnit(BitcoinUnits::Unit unit);

    /** Make field empty and ready for new input. */
    void clear();

    /** Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907),
        in these cases we have to set it up manually.
    */
    QWidget *setupTabChain(QWidget *prev);

signals:
    void textChanged();

protected:
    /** Intercept focus-in event and ',' key presses */
    bool eventFilter(QObject *object, QEvent *event);

private:
    QDoubleSpinBox *amount;
    QValueComboBox *unit;
    BitcoinUnits::Unit currentUnit;

    void setText(const QString &text);
    QString text() const;

private slots:
    void unitChanged(int idx);
};

#endif // BITCOINFIELD_H
