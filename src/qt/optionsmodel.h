// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OPTIONSMODEL_H
#define OPTIONSMODEL_H

#include <qt/bitcoinunits.h>
#include <QAbstractListModel>

/** Interface from Qt to configuration data structure for Bitcoin client.
   To Qt, the options are presented as a list with the different options
   laid out vertically.
   This can be changed to a tree once the settings become sufficiently
   complex.
 */
class OptionsModel : public QAbstractListModel
{
    Q_OBJECT
private:
    OptionsModel(const OptionsModel &)=delete;
    OptionsModel &operator=(const OptionsModel &)=delete;
    OptionsModel(OptionsModel &&)=delete;
    OptionsModel &operator=(OptionsModel &&)=delete;
public:
    explicit OptionsModel(QObject *parent = nullptr);

    enum OptionID {
        StartAtStartup,    // bool
        MinimizeToTray,    // bool
        MinimizeOnClose,   // bool
        ProxyUse,          // bool
        ProxyIP,           // QString
        ProxyPort,         // int
        ProxySocksVersion, // int
        TorUse,            // bool
        TorIP,             // QString
        TorPort,           // int
        TorOnly,           // bool
        TorName,           // QString
        Fee,               // qint64
        DisplayUnit,       // BitcoinUnits::Unit
        DisplayAddresses,  // bool
        ThirdPartyTxUrls,  // QString
        DetachDatabases,   // bool
        Language,          // QString
        CoinControlFeatures, // bool
        ExternalSeeder,    // QString
        Bip66Use,          // entry::b66mode
        FullSecureString,  // bool
        ConnectBalanceUse, // bool
        PredictionSMARTUse, // bool
        PredictionBenchUse, // bool
        OptionIDRowCount,
    };

    void Init();

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole);

    /* Explicit getters */
    qint64 getTransactionFee();
    bool getMinimizeToTray();
    bool getMinimizeOnClose();
    BitcoinUnits::Unit getDisplayUnit();
    bool getDisplayAddresses();
    bool getCoinControlFeatures();
    QString getThirdPartyTxUrls() { return strThirdPartyTxUrls; }
    QString getLanguage() { return language; }

private:
    BitcoinUnits::Unit nDisplayUnit;
    bool bDisplayAddresses;
    bool fMinimizeToTray;
    bool fMinimizeOnClose;
    bool fCoinControlFeatures;
    QString language;
    QString strThirdPartyTxUrls;

signals:
    void displayUnitChanged(int unit);
    void transactionFeeChanged(qint64);
    void coinControlFeaturesChanged(bool);
};

#endif // OPTIONSMODEL_H
