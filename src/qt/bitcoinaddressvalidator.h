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
    BitcoinAddressValidator(const BitcoinAddressValidator &); // {}
    BitcoinAddressValidator &operator=(const BitcoinAddressValidator &); // {}
public:
    explicit BitcoinAddressValidator(QObject *parent = 0);

    State validate(QString &input, int &pos) const;

    static const int MaxAddressLength = 99;
signals:

public slots:

};

#endif // BITCOINADDRESSVALIDATOR_H
//@
