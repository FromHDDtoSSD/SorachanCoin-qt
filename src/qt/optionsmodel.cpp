#include "optionsmodel.h"
#include "bitcoinunits.h"
#include <QSettings>

#include "init.h"
#include "walletdb.h"
#include "guiutil.h"

OptionsModel::OptionsModel(QObject *parent) :
    QAbstractListModel(parent)
{
    Init();
}

bool static ApplyProxySettings()
{
    QSettings settings;
    CService addrProxy(settings.value("addrProxy", "127.0.0.1:9050").toString().toStdString());
    int nSocksVersion(settings.value("nSocksVersion", 5).toInt());
    if (! settings.value("fUseProxy", false).toBool()) {
        addrProxy = CService();
        nSocksVersion = 0;
        return false;
    }
    if (nSocksVersion && !addrProxy.IsValid()) {
        return false;
    }

    if (! ext_ip::IsLimited(netbase::NET_IPV4)) {
        netbase::manage::SetProxy(netbase::NET_IPV4, addrProxy, nSocksVersion);
    }
    if (nSocksVersion > 4) {
#ifdef USE_IPV6
        if (! ext_ip::IsLimited(netbase::NET_IPV6)) {
            netbase::manage::SetProxy(netbase::NET_IPV6, addrProxy, nSocksVersion);
        }
#endif
    }

    netbase::manage::SetNameProxy(addrProxy, nSocksVersion);

    return true;
}

bool static ApplyTorSettings()
{
    QSettings settings;
    CService addrTor(settings.value("addrTor", "127.0.0.1:6350").toString().toStdString());
    if (! settings.value("fUseTor", false).toBool()) {
        addrTor = CService();
        return false;
    }
    if (! addrTor.IsValid()) {
        return false;
    }

    netbase::manage::SetProxy(netbase::NET_TOR, addrTor, 5);
    ext_ip::SetReachable(netbase::NET_TOR);

    return true;
}

void OptionsModel::Init()
{
    QSettings settings;

    // These are Qt-only settings:
    nDisplayUnit = settings.value("nDisplayUnit", BitcoinUnits::BTC).toInt();
    bDisplayAddresses = settings.value("bDisplayAddresses", false).toBool();
    if (! settings.contains("strThirdPartyTxUrls")) {
        if(args_bool::fTestNet) {
            settings.setValue("strThirdPartyTxUrls", "");
        } else {
            settings.setValue("strThirdPartyTxUrls", "https://www.junkhdd.com:7350");
        }
    }
    strThirdPartyTxUrls = settings.value("strThirdPartyTxUrls", "https://www.junkhdd.com:7350").toString();
    fMinimizeToTray = settings.value("fMinimizeToTray", false).toBool();
    fMinimizeOnClose = settings.value("fMinimizeOnClose", false).toBool();
    fCoinControlFeatures = settings.value("fCoinControlFeatures", false).toBool();
    block_info::nTransactionFee = settings.value("nTransactionFee").toLongLong();
    language = settings.value("language", "").toString();

    // These are shared with core Bitcoin; we want
    // command-line options to override the GUI settings:
    if ( !(settings.value("fTorOnly").toBool() && settings.contains("addrTor")) ) {
        if (settings.contains("addrProxy") && settings.value("fUseProxy").toBool()) {
            map_arg::SoftSetArg("-proxy", settings.value("addrProxy").toString().toStdString());
        }
        if (settings.contains("nSocksVersion") && settings.value("fUseProxy").toBool()) {
            map_arg::SoftSetArg("-socks", settings.value("nSocksVersion").toString().toStdString());
        }
    }

    if (settings.contains("addrTor") && settings.value("fUseTor").toBool()) {
        map_arg::SoftSetArg("-tor", settings.value("addrTor").toString().toStdString());
        if (settings.value("fTorOnly").toBool()) {
            map_arg::SoftSetArg("-onlynet", "tor");
        }

        if (settings.value("TorName").toString().length() == 22) {
            std::string strTorName = settings.value("TorName").toString().toStdString();

            CService addrTorName(strTorName, net_basis::GetListenPort());
            if (addrTorName.IsValid()) {
                map_arg::SoftSetArg("-torname", strTorName);
            }
        }
    }

    if (!args_bool::fTestNet && settings.contains("externalSeeder") && settings.value("externalSeeder").toString() != "") {
        map_arg::SoftSetArg("-peercollector", settings.value("externalSeeder").toString().toStdString());
    }

    if (settings.contains("detachDB")) {
        map_arg::SoftSetBoolArg("-detachdb", settings.value("detachDB").toBool());
    }
    if (! language.isEmpty()) {
        map_arg::SoftSetArg("-lang", language.toStdString());
    }
}

int OptionsModel::rowCount(const QModelIndex &parent) const
{
    return OptionIDRowCount;
}

QVariant OptionsModel::data(const QModelIndex &index, int role) const
{
    if(role == Qt::EditRole) {
        QSettings settings;
        switch(index.row())
        {
        case StartAtStartup:
            return QVariant(GUIUtil::GetStartOnSystemStartup());
        case MinimizeToTray:
            return QVariant(fMinimizeToTray);
        case MinimizeOnClose:
            return QVariant(fMinimizeOnClose);
        case ProxyUse:
            return settings.value("fUseProxy", false);
        case ProxyIP: {
            netbase::proxyType proxy;
            if (netbase::manage::GetProxy(netbase::NET_IPV4, proxy)) {
                return QVariant(QString::fromStdString(proxy.first.ToStringIP()));
            } else {
                return QVariant(QString::fromStdString("127.0.0.1"));
            }
        }
        case ProxyPort: {
            netbase::proxyType proxy;
            if (netbase::manage::GetProxy(netbase::NET_IPV4, proxy)) {
                return QVariant(proxy.first.GetPort());
            } else {
                return QVariant(entry::nSocksDefault);
            }
        }
        case ProxySocksVersion:
            return settings.value("nSocksVersion", 5);
        case TorUse:
            return settings.value("fUseTor", false);
        case TorIP: {
            netbase::proxyType proxy;
            if (netbase::manage::GetProxy(netbase::NET_TOR, proxy)) {
                return QVariant(QString::fromStdString(proxy.first.ToStringIP()));
            } else {
                return QVariant(QString::fromStdString("127.0.0.1"));
            }
        }
        case TorPort: {
            netbase::proxyType proxy;
            if (netbase::manage::GetProxy(netbase::NET_TOR, proxy)) {
                return QVariant(proxy.first.GetPort());
            } else {
                return QVariant(entry::nSocksDefault);
            }
        }
        case TorOnly:
            return settings.value("fTorOnly", false);
        case TorName:
            return settings.value("TorName", "");
        case ExternalSeeder:
            return settings.value("externalSeeder", "");
        case Fee:
            return QVariant(static_cast<qlonglong>(block_info::nTransactionFee));
        case DisplayUnit:
            return QVariant(nDisplayUnit);
        case DisplayAddresses:
            return QVariant(bDisplayAddresses);
        case ThirdPartyTxUrls:
            return QVariant(strThirdPartyTxUrls);
        case DetachDatabases:
            return QVariant(CDBEnv::bitdb.GetDetach());
        case Language:
            return settings.value("language", "");
        case CoinControlFeatures:
            return QVariant(fCoinControlFeatures);
        default:
            return QVariant();
        }
    }
    return QVariant();
}

bool OptionsModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    bool successful = true; /* set to false on parse error */
    if(role == Qt::EditRole) {
        QSettings settings;
        switch(index.row())
        {
        case StartAtStartup:
            successful = GUIUtil::SetStartOnSystemStartup(value.toBool());
            break;
        case MinimizeToTray:
            fMinimizeToTray = value.toBool();
            settings.setValue("fMinimizeToTray", fMinimizeToTray);
            break;
        case MinimizeOnClose:
            fMinimizeOnClose = value.toBool();
            settings.setValue("fMinimizeOnClose", fMinimizeOnClose);
            break;
        case ProxyUse:
            settings.setValue("fUseProxy", value.toBool());
            ApplyProxySettings();
            break;
        case ProxyIP: {
            netbase::proxyType proxy;
            proxy.first = CService("127.0.0.1", entry::nSocksDefault);
            netbase::manage::GetProxy(netbase::NET_IPV4, proxy);

            CNetAddr addr(value.toString().toStdString());
            proxy.first.SetIP(addr);
            settings.setValue("addrProxy", proxy.first.ToStringIPPort().c_str());
            successful = ApplyProxySettings();
        }
        break;
        case ProxyPort: {
            netbase::proxyType proxy;
            proxy.first = CService("127.0.0.1", entry::nSocksDefault);
            netbase::manage::GetProxy(netbase::NET_IPV4, proxy);

            proxy.first.SetPort(value.toInt());
            settings.setValue("addrProxy", proxy.first.ToStringIPPort().c_str());
            successful = ApplyProxySettings();
        }
        break;
        case ProxySocksVersion: {
            netbase::proxyType proxy;
            proxy.second = 5;
            netbase::manage::GetProxy(netbase::NET_IPV4, proxy);

            proxy.second = value.toInt();
            settings.setValue("nSocksVersion", proxy.second);
            successful = ApplyProxySettings();
        }
        break;
        case TorUse: {
            settings.setValue("fUseTor", value.toBool());
            ApplyTorSettings();
        }
        break;
        case TorIP: {
            netbase::proxyType proxy;
            proxy.first = CService("127.0.0.1", entry::nSocksDefault);
            netbase::manage::GetProxy(netbase::NET_TOR, proxy);

            CNetAddr addr(value.toString().toStdString());
            proxy.first.SetIP(addr);
            settings.setValue("addrTor", proxy.first.ToStringIPPort().c_str());
            successful = ApplyTorSettings();
        }
        break;
        case TorPort: {
            netbase::proxyType proxy;
            proxy.first = CService("127.0.0.1", entry::nSocksDefault);
            netbase::manage::GetProxy(netbase::NET_TOR, proxy);

            proxy.first.SetPort((uint16_t)value.toUInt());
            settings.setValue("addrTor", proxy.first.ToStringIPPort().c_str());
            successful = ApplyTorSettings();
        }
        break;
        case TorOnly: {
            settings.setValue("fTorOnly", value.toBool());
            ApplyTorSettings();
        }
        case TorName: {
            settings.setValue("TorName", value.toString());
        }
        break;
        case ExternalSeeder:
            settings.setValue("externalSeeder", value.toString());
        break;
        case Fee:
            block_info::nTransactionFee = value.toLongLong();
            settings.setValue("block_info::nTransactionFee", static_cast<qlonglong>(block_info::nTransactionFee));
            emit transactionFeeChanged(block_info::nTransactionFee);
            break;
        case DisplayUnit:
            nDisplayUnit = value.toInt();
            settings.setValue("nDisplayUnit", nDisplayUnit);
            emit displayUnitChanged(nDisplayUnit);
            break;
        case DisplayAddresses:
            bDisplayAddresses = value.toBool();
            settings.setValue("bDisplayAddresses", bDisplayAddresses);
            break;
        case DetachDatabases: {
            bool fDetachDB = value.toBool();
            CDBEnv::bitdb.SetDetach(fDetachDB);
            settings.setValue("detachDB", fDetachDB);
            }
            break;
        case ThirdPartyTxUrls:
            if (strThirdPartyTxUrls != value.toString()) {
                strThirdPartyTxUrls = value.toString();
                settings.setValue("strThirdPartyTxUrls", strThirdPartyTxUrls);
            }
            break;
        case Language:
            settings.setValue("language", value);
            break;
        case CoinControlFeatures: {
            fCoinControlFeatures = value.toBool();
            settings.setValue("fCoinControlFeatures", fCoinControlFeatures);
            emit coinControlFeaturesChanged(fCoinControlFeatures);
            }
            break;
        default:
            break;
        }
    }
    emit dataChanged(index, index);

    return successful;
}

qint64 OptionsModel::getTransactionFee()
{
    return block_info::nTransactionFee;
}

bool OptionsModel::getCoinControlFeatures()
{
    return fCoinControlFeatures;
}

bool OptionsModel::getMinimizeToTray()
{
    return fMinimizeToTray;
}

bool OptionsModel::getMinimizeOnClose()
{
    return fMinimizeOnClose;
}

int OptionsModel::getDisplayUnit()
{
    return nDisplayUnit;
}

bool OptionsModel::getDisplayAddresses()
{
    return bDisplayAddresses;
}
