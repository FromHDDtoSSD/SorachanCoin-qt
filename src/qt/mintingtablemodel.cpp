// Copyright (c) 2012-2013 The PPCoin developers
// Copyright (c) 2013-2015 The Novacoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/mintingtablemodel.h>
#include <qt/mintingfilterproxy.h>
#include <qt/transactiontablemodel.h>
#include <qt/guiutil.h>
#include <kernelrecord.h>
#include <qt/guiconstants.h>
#include <qt/transactiondesc.h>
#include <qt/walletmodel.h>
#include <qt/optionsmodel.h>
#include <qt/addresstablemodel.h>
#include <qt/bitcoinunits.h>
#include <util.h>
#include <kernel.h>
#include <wallet.h>
#include <rpc/bitcoinrpc.h>
#include <QLocale>
#include <QList>
#include <QColor>
#include <QTimer>
#include <QIcon>
#include <QDateTime>
#include <QtAlgorithms>
#include <miner/diff.h>
#include <allocator/qtsecure.h>

namespace {
static int column_alignments[] = {
    Qt::AlignLeft|Qt::AlignVCenter,
    Qt::AlignLeft|Qt::AlignVCenter,
    Qt::AlignLeft|Qt::AlignVCenter,
    Qt::AlignLeft|Qt::AlignVCenter,
    Qt::AlignLeft|Qt::AlignVCenter,
    Qt::AlignLeft|Qt::AlignVCenter,
    Qt::AlignLeft|Qt::AlignVCenter
};

struct TxLessThan
{
    bool operator()(const KernelRecord &a, const KernelRecord &b) const
    {
        return a.hash < b.hash;
    }
    bool operator()(const KernelRecord &a, const uint256 &b) const
    {
        return a.hash < b;
    }
    bool operator()(const uint256 &a, const KernelRecord &b) const
    {
        return a < b.hash;
    }
};
} // namespace

class MintingTablePriv
{
private:
    MintingTablePriv(const MintingTablePriv &)=delete;
    MintingTablePriv &operator=(const MintingTablePriv &)=delete;
    MintingTablePriv(MintingTablePriv &&)=delete;
    MintingTablePriv &operator=(MintingTablePriv &&)=delete;
public:
    MintingTablePriv(CWallet *wallet, MintingTableModel *parent):
        wallet(wallet),
        parent(parent)
    {
    }
    CWallet *wallet;
    MintingTableModel *parent;

    QList<KernelRecord> cachedWallet;

    void refreshWallet()
    {
#ifdef WALLET_UPDATE_DEBUG
        qDebug() << "refreshWallet";
#endif
        cachedWallet.clear();
        {
            LOCK(wallet->cs_wallet);
            for(std::map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it)
            {
                std::vector<KernelRecord> txList = KernelRecord::decomposeOutput(wallet, it->second);
                for(KernelRecord& kr: txList)
                {
                    if(! kr.spent) {
                        cachedWallet.append(kr);
                    }
                }
            }
        }
    }

    /* Update our model of the wallet incrementally, to synchronize our model of the wallet
       with that of the core.

       Call with list of hashes of transactions that were added, removed or changed.
     */
    void updateWallet(const QList<uint256> &updated)
    {
        // Walk through updated transactions, update model as needed.
#ifdef WALLET_UPDATE_DEBUG
        qDebug() << "updateWallet";
#endif
        // Sort update list, and iterate through it in reverse, so that model updates
        //  can be emitted from end to beginning (so that earlier updates will not influence
        // the indices of latter ones).
        QList<uint256> updated_sorted = updated;
        qSort(updated_sorted);

        {
            LOCK(wallet->cs_wallet);
            for(int update_idx = updated_sorted.size()-1; update_idx >= 0; --update_idx)
            {
                const uint256 &hash = updated_sorted.at(update_idx);
                // Find transaction in wallet
                std::map<uint256, CWalletTx>::iterator mi = wallet->mapWallet.find(hash);
                bool inWallet = mi != wallet->mapWallet.end();
                // Find bounds of this transaction in model
                QList<KernelRecord>::iterator lower = qLowerBound(
                    cachedWallet.begin(), cachedWallet.end(), hash, TxLessThan());
                QList<KernelRecord>::iterator upper = qUpperBound(
                    cachedWallet.begin(), cachedWallet.end(), hash, TxLessThan());
                int lowerIndex = (lower - cachedWallet.begin());
                int upperIndex = (upper - cachedWallet.begin());

                // Determine if transaction is in model already
                bool inModel = false;
                if(lower != upper) {
                    inModel = true;
                }

#ifdef WALLET_UPDATE_DEBUG
                qDebug() << "  " << QString::fromStdString(hash.ToString()) << inWallet << " " << inModel
                        << lowerIndex << "-" << upperIndex;
#endif

                if(inWallet && !inModel) {
                    // Added -- insert at the right position
                    std::vector<KernelRecord> toInsert =
                            KernelRecord::decomposeOutput(wallet, mi->second);
                    if(! toInsert.empty()) {    /* only if something to insert */
                        int insert_idx = lowerIndex;
                        for(const KernelRecord &rec: toInsert)
                        {
                            if(! rec.spent) {
                                parent->beginInsertRows(QModelIndex(), insert_idx, insert_idx);
                                cachedWallet.insert(insert_idx, rec);
                                parent->endInsertRows();
                                insert_idx += 1;
                            }
                        }
                    }
                } else if(!inWallet && inModel) {
                    // Removed -- remove entire transaction from table
                    parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
                    cachedWallet.erase(lower, upper);
                    parent->endRemoveRows();
                } else if(inWallet && inModel) {
                    // Updated -- remove spent coins from table
                    std::vector<KernelRecord> toCheck = KernelRecord::decomposeOutput(wallet, mi->second);
                    for(const KernelRecord &rec: toCheck)
                    {
                        if(rec.spent) {
                            for(int i = 0; i < cachedWallet.size(); i++)
                            {
                                KernelRecord cachedRec = cachedWallet.at(i);
                                if((rec.hash == cachedRec.hash)
                                    && (rec.nTime == cachedRec.nTime)
                                    && (rec.nValue == cachedRec.nValue))
                                {
                                    parent->beginRemoveRows(QModelIndex(), i, i);
                                    cachedWallet.removeAt(i);
                                    parent->endRemoveRows();
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    int size()
    {
        return cachedWallet.size();
    }

    KernelRecord *index(int idx)
    {
        if(idx >= 0 && idx < cachedWallet.size()) {
            KernelRecord *rec = &cachedWallet[idx];
            return rec;
        } else {
            return 0;
        }
    }

    QString describe(KernelRecord *rec)
    {
        {
            LOCK(wallet->cs_wallet);
            std::map<uint256, CWalletTx>::iterator mi = wallet->mapWallet.find(rec->hash);
            if(mi != wallet->mapWallet.end()) {
                return TransactionDesc::toHTML(wallet, mi->second);
            }
        }
        return QString("");
    }
};

MintingTableModel::MintingTableModel(CWallet *wallet, WalletModel *parent):
        QAbstractTableModel(parent),
        wallet(wallet),
        walletModel(parent),
        mintingInterval(10),
        priv(new(std::nothrow) MintingTablePriv(wallet, this))
{
    if(! priv)
        throw qt_error("MintingTableModel: out of memory.", nullptr);
    columns << tr("Transaction") <<  tr("Address") << tr("Balance") << tr("Age") << tr("CoinDay") << tr("MintProbability") << tr("MintReward");
    priv->refreshWallet();

    QTimer *timer = new(std::nothrow) QTimer(this);
    if(! timer)
        throw qt_error("MintingTableModel: out of memory.", nullptr);
    connect(timer, SIGNAL(timeout()), this, SLOT(update()));
    timer->start(MODEL_UPDATE_DELAY);
}

MintingTableModel::~MintingTableModel()
{
    delete priv;
}

void MintingTableModel::update()
{
    QList<uint256> updated;

    // Check if there are changes to wallet map
    {
        TRY_LOCK(wallet->cs_wallet, lockWallet);
        if (lockWallet && !wallet->vMintingWalletUpdated.empty()) {
            for(uint256 hash: wallet->vMintingWalletUpdated)
            {
                updated.append(hash);

                // Also check the inputs to remove spent outputs from the table if necessary
                CWalletTx wtx;
                if(wallet->GetTransaction(hash, wtx)) {
                    for(const CTxIn &txin: wtx.get_vin())
                    {
                        updated.append(txin.get_prevout().get_hash());
                    }
                }
            }
            wallet->vMintingWalletUpdated.clear();
        }
    }

    if(! updated.empty()) {
        priv->updateWallet(updated);
        mintingProxyModel->invalidate(); // Force deletion of empty rows
    }
}

void MintingTableModel::setMintingProxyModel(MintingFilterProxy *mintingProxy)
{
    mintingProxyModel = mintingProxy;
}

int MintingTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int MintingTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

#ifndef CLI_MODE_ENABLE
QVariant MintingTableModel::data(const QModelIndex &index, int role) const
{
    if(! index.isValid()) {
        return QVariant();
    }

    KernelRecord *rec = static_cast<KernelRecord *>(index.internalPointer());
    switch(role)
    {
      case Qt::DisplayRole:
        switch(index.column())
        {
        case Address:
            return formatTxAddress(rec, false);
        case TxHash:
            return formatTxHash(rec);
        case Age:
            return formatTxAge(rec);
        case Balance:
            return formatTxBalance(rec);
        case CoinDay:
            return formatTxCoinDay(rec);
        case MintProbability:
            return formatDayToMint(rec);
        case MintReward:
            return formatTxPoSReward(rec);
        }
        break;
      case Qt::TextAlignmentRole:
        return column_alignments[index.column()];
        break;
      case Qt::ToolTipRole:
        switch(index.column())
        {
        case MintProbability:
            {
                int interval = mintingInterval;
                QString unit = tr("minutes");

                int hours = interval / 60;
                int days = hours  / 24;
                if(hours > 1) {
                    interval = hours;
                    unit = tr("hours");
                }
                if(days > 1) {
                    interval = days;
                    unit = tr("days");
                }
                QString str = QString(tr("You have %1 chance to find a POS block if you mint %2 %3 at current difficulty."));
                return str.arg(index.data().toString().toUtf8().constData()).arg(interval).arg(unit);
            }
            break;
        default:
            break;
        }
        break;
      case Qt::EditRole:
        switch(index.column())
        {
        case Address:
            return formatTxAddress(rec, false);
        case TxHash:
            return formatTxHash(rec);
        case Age:
            return static_cast<qlonglong>(rec->getAge());
        case CoinDay:
            return static_cast<qlonglong>(rec->getCoinDay());
        case Balance:
            return static_cast<qlonglong>(rec->nValue);
        case MintProbability:
            return getDayToMint(rec);
        case MintReward:
            return formatTxPoSReward(rec);
        }
        break;
      case Qt::BackgroundColorRole:
        {
            double minAge = (double)block_check::nStakeMinAge / 60 / 60 / 24;
            double maxAge = (double)block_check::nStakeMaxAge / 60 / 60 / 24;
            if((double)(rec->getAge()) < minAge) {
                return COLOR_MINT_YOUNG;
            } else if ((double)(rec->getAge()) >= minAge && (double)(rec->getAge()) < (maxAge + minAge)) {
                return COLOR_MINT_MATURE;
            } else {
                return COLOR_MINT_OLD;
            }
        }
        break;
    }
    return QVariant();
}
#endif

void MintingTableModel::setMintingInterval(int interval)
{
    mintingInterval = interval;
}

QString MintingTableModel::lookupAddress(const std::string &address, bool tooltip) const
{
    QString label = walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(address));
    QString description;
    if(! label.isEmpty()) {
        description += label + QString(" ");
    }
    if(label.isEmpty() || walletModel->getOptionsModel()->getDisplayAddresses() || tooltip) {
        description += QString("(") + QString::fromStdString(address) + QString(")");
    }
    return description;
}

QString MintingTableModel::formatTxPoSReward(KernelRecord *wtx) const
{
    int nBits = diff::spacing::GetLastBlockIndex(block_info::pindexBest, true)->get_nBits();
    QString posReward = QString(QObject::tr("from %4 to %5")).arg(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), wtx->getPoSReward(nBits, 0)), 
                                BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), wtx->getPoSReward(nBits, mintingInterval)));

    return posReward;
}

#ifndef CLI_MODE_ENABLE
double MintingTableModel::getDayToMint(KernelRecord *wtx) const
{
    const CBlockIndex *p = diff::spacing::GetLastBlockIndex(block_info::pindexBest, true);
    double difficulty = QtConsoleRPC::GetDifficulty(p);

    double prob = wtx->getProbToMintWithinNMinutes(difficulty, mintingInterval);
    prob = prob * 100;
    return prob;
}
#endif

#ifndef CLI_MODE_ENABLE
QString MintingTableModel::formatDayToMint(KernelRecord *wtx) const
{
    double prob = getDayToMint(wtx);
    return QString::number(prob, 'f', 3) + "%";
}
#endif

QString MintingTableModel::formatTxAddress(const KernelRecord *wtx, bool tooltip) const
{
    return QString::fromStdString(wtx->address);
}

QString MintingTableModel::formatTxHash(const KernelRecord *wtx) const
{
    return QString::fromStdString(wtx->hash.ToString());
}

QString MintingTableModel::formatTxCoinDay(const KernelRecord *wtx) const
{
    return QString::number(wtx->getCoinDay());
}

QString MintingTableModel::formatTxAge(const KernelRecord *wtx) const
{
    int64_t nAge = wtx->getAge();
    return QString::number(nAge);
}

QString MintingTableModel::formatTxBalance(const KernelRecord *wtx) const
{
    return BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), wtx->nValue);
}

QVariant MintingTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal) {
        if(role == Qt::DisplayRole) {
            return columns[section];
        } else if (role == Qt::TextAlignmentRole) {
            return column_alignments[section];
        } else if (role == Qt::ToolTipRole) {
            switch(section)
            {
            case Address:
                return tr("Destination address of the output.");
            case TxHash:
                return tr("Original transaction id.");
            case Age:
                return tr("Age of the transaction in days.");
            case Balance:
                return tr("Balance of the output.");
            case CoinDay:
                return tr("Coin age in the output.");
            case MintProbability:
                return tr("Chance to mint a block within given time interval.");
            case MintReward:
                return tr("The size of the potential rewards if the block is found at the beginning and the end given time interval.");
            }
        }
    }
    return QVariant();
}

QModelIndex MintingTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    KernelRecord *data = priv->index(row);
    if(data) {
        return createIndex(row, column, priv->index(row));
    } else {
        return QModelIndex();
    }
}
