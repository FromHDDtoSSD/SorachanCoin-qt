#include "clientmodel.h"
#include "guiconstants.h"
#include "optionsmodel.h"
#include "addresstablemodel.h"
#include "transactiontablemodel.h"

#include "alert.h"
#include "main.h"
#include "ui_interface.h"

#include "bitcoinrpc.h"

#include <QDateTime>
#include <QTimer>

static const int64_t nClientStartupTime = bitsystem::GetTime();

ClientModel::ClientModel(OptionsModel *optionsModel, QObject *parent) :
    QObject(parent), optionsModel(optionsModel),
    cachedNumBlocks(0), cachedNumBlocksOfPeers(0), pollTimer(0)
{
    try {
        numBlocksAtStartup = -1;

        pollTimer = new QTimer(this);
        pollTimer->setInterval(MODEL_UPDATE_DELAY);
        pollTimer->start();
        connect(pollTimer, SIGNAL(timeout()), this, SLOT(updateTimer()));

        subscribeToCoreSignals();
    } catch (const std::bad_alloc &) {
        throw std::runtime_error("ClientModel Failed to allocate memory.");
    }
}

ClientModel::~ClientModel()
{
    unsubscribeFromCoreSignals();
}

double ClientModel::getPoSKernelPS()
{
    return CRPCTable::CRPCTable_GUI::GetPoSKernelPS();
}

double ClientModel::getDifficulty(bool fProofofStake)
{
    if (fProofofStake) {
        return CRPCTable::CRPCTable_GUI::GetDifficulty(diff::spacing::GetLastBlockIndex(block_info::pindexBest, true));
    } else {
        return CRPCTable::CRPCTable_GUI::GetDifficulty(diff::spacing::GetLastBlockIndex(block_info::pindexBest, false));
    }
}

int ClientModel::getNumConnections(uint8_t flags) const
{
    LOCK(net_node::cs_vNodes);
    if (flags == CONNECTIONS_ALL) {    // Shortcut if we want total
        return (int)(net_node::vNodes.size());
    }

    int nNum = 0;
    BOOST_FOREACH(CNode* pnode, net_node::vNodes)
    {
        if (flags & (pnode->fInbound ? CONNECTIONS_IN : CONNECTIONS_OUT)) {
            nNum++;
        }
    }

    return nNum;
}

int ClientModel::getNumBlocks() const
{
    return block_info::nBestHeight;
}

int ClientModel::getNumBlocksAtStartup()
{
    if (numBlocksAtStartup == -1) {
        numBlocksAtStartup = getNumBlocks();
    }

    return numBlocksAtStartup;
}

quint64 ClientModel::getTotalBytesRecv() const
{
    return CNode::GetTotalBytesRecv();
}

quint64 ClientModel::getTotalBytesSent() const
{
    return CNode::GetTotalBytesSent();
}

QDateTime ClientModel::getLastBlockDate() const
{
    if (block_info::pindexBest) {
        return QDateTime::fromTime_t(block_info::pindexBest->GetBlockTime());
    } else {
        return QDateTime::fromTime_t(1360105017); // Genesis block's time
    }
}

void ClientModel::updateTimer()
{
    // Some quantities (such as number of blocks) change so fast that we don't want to be notified for each change.
    // Periodically check and update with a timer.
    int newNumBlocks = getNumBlocks();
    int newNumBlocksOfPeers = getNumBlocksOfPeers();

    if(cachedNumBlocks != newNumBlocks || cachedNumBlocksOfPeers != newNumBlocksOfPeers) {
        cachedNumBlocks = newNumBlocks;
        cachedNumBlocksOfPeers = newNumBlocksOfPeers;

        emit numBlocksChanged(newNumBlocks, newNumBlocksOfPeers);
    }

    emit bytesChanged(getTotalBytesRecv(), getTotalBytesSent());
}

void ClientModel::updateNumConnections(int numConnections)
{
    emit numConnectionsChanged(numConnections);
}

void ClientModel::updateAlert(const QString &hash, int status)
{
    // Show error message notification for new alert
    if(status == CT_NEW) {
        uint256 hash_256;
        hash_256.SetHex(hash.toStdString());
        CAlert alert = CAlert::getAlertByHash(hash_256);
        if(! alert.IsNull()) {
            emit error(tr("Network Alert"), QString::fromStdString(alert.strStatusBar), false);
        }
    }

    // Emit a numBlocksChanged when the status message changes,
    // so that the view recomputes and updates the status bar.
    emit numBlocksChanged(getNumBlocks(), getNumBlocksOfPeers());
}

bool ClientModel::isTestNet() const
{
    return args_bool::fTestNet;
}

bool ClientModel::inInitialBlockDownload() const
{
    return block_process::manage::IsInitialBlockDownload();
}

int ClientModel::getNumBlocksOfPeers() const
{
    return block_process::manage::GetNumBlocksOfPeers();
}

QString ClientModel::getStatusBarWarnings() const
{
    return QString::fromStdString(block_alert::manage::GetWarnings("statusbar"));
}

OptionsModel *ClientModel::getOptionsModel()
{
    return optionsModel;
}

QString ClientModel::formatFullVersion() const
{
    return QString::fromStdString(format_version::FormatFullVersion());
}

QString ClientModel::formatBuildDate() const
{
    return QString::fromStdString(version::CLIENT_DATE);
}

QString ClientModel::clientName() const
{
    return QString::fromStdString(version::CLIENT_NAME);
}

QString ClientModel::formatClientStartupTime() const
{
    return QDateTime::fromTime_t(nClientStartupTime).toString();
}

// Handlers for core signals
static void NotifyBlocksChanged(ClientModel *clientmodel)
{
    // This notification is too frequent. Don't trigger a signal.
    // Don't remove it, though, as it might be useful later.
}

static void NotifyNumConnectionsChanged(ClientModel *clientmodel, int newNumConnections)
{
    // Too noisy: print::OutputDebugStringF("NotifyNumConnectionsChanged %i\n", newNumConnections);
    QMetaObject::invokeMethod(clientmodel, "updateNumConnections", Qt::QueuedConnection,
                              Q_ARG(int, newNumConnections));
}

static void NotifyAlertChanged(ClientModel *clientmodel, const uint256 &hash, ChangeType status)
{
    print::OutputDebugStringF("NotifyAlertChanged %s status=%i\n", hash.GetHex().c_str(), status);
    QMetaObject::invokeMethod(clientmodel, "updateAlert", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(hash.GetHex())),
                              Q_ARG(int, status));
}

void ClientModel::subscribeToCoreSignals()
{
    // Connect signals to client
    CClientUIInterface::uiInterface.NotifyBlocksChanged.connect(boost::bind(NotifyBlocksChanged, this));
    CClientUIInterface::uiInterface.NotifyNumConnectionsChanged.connect(boost::bind(NotifyNumConnectionsChanged, this, _1));
    CClientUIInterface::uiInterface.NotifyAlertChanged.connect(boost::bind(NotifyAlertChanged, this, _1, _2));
}

void ClientModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from client
    CClientUIInterface::uiInterface.NotifyBlocksChanged.disconnect(boost::bind(NotifyBlocksChanged, this));
    CClientUIInterface::uiInterface.NotifyNumConnectionsChanged.disconnect(boost::bind(NotifyNumConnectionsChanged, this, _1));
    CClientUIInterface::uiInterface.NotifyAlertChanged.disconnect(boost::bind(NotifyAlertChanged, this, _1, _2));
}
