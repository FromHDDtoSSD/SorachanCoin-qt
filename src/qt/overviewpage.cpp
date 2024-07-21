// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/overviewpage.h>
#include <ui_overviewpage.h>
#include <QDesktopServices>
#include <QUrl>
#include <qt/walletmodel.h>
#include <qt/bitcoinunits.h>
#include <qt/optionsmodel.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionfilterproxy.h>
#include <qt/guiutil.h>
#include <qt/guiconstants.h>
#include <QAbstractItemDelegate>
#include <QPainter>
#include <allocator/qtsecure.h>
#ifdef WIN32
# include <winapi/common.h>
#endif

#define DECORATION_SIZE 64
#define NUM_ITEMS 3

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
private:
    TxViewDelegate(const TxViewDelegate &)=delete;
    TxViewDelegate &operator=(const TxViewDelegate &)=delete;
    TxViewDelegate(const TxViewDelegate &&)=delete;
    TxViewDelegate &operator=(const TxViewDelegate &&)=delete;
public:
    TxViewDelegate(): QAbstractItemDelegate(), unit(BitcoinUnits::BTC)
    {
    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));
        QRect mainRect = option.rect;
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = option.palette.color(QPalette::Text);
#if QT_VERSION < 0x050000
        if(qVariantCanConvert<QColor>(value))
#else
        if(value.canConvert(QMetaType::QColor))
#endif
        {
            foreground = qvariant_cast<QColor>(value);
        }

        painter->setPen(foreground);
        painter->drawText(addressRect, Qt::AlignLeft|Qt::AlignVCenter, address);

        if(amount < 0) {
            foreground = COLOR_NEGATIVE;
        } else if(! confirmed) {
            foreground = COLOR_UNCONFIRMED;
        } else {
            foreground = option.palette.color(QPalette::Text);
        }

        painter->setPen(foreground);
        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true);
        if(! confirmed) {
            amountText = QString("[") + amountText + QString("]");
        }
        painter->drawText(amountRect, Qt::AlignRight|Qt::AlignVCenter, amountText);

        painter->setPen(option.palette.color(QPalette::Text));
        painter->drawText(amountRect, Qt::AlignLeft|Qt::AlignVCenter, GUIUtil::dateTimeStr(date));

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE);
    }

    BitcoinUnits::Unit unit;

};
#include "overviewpage.moc"

OverviewPage::OverviewPage(QWidget *parent) :
    QWidget(parent),
    ui(new(std::nothrow) Ui::OverviewPage),
    currentBalanceTotal(-1),
    currentBalanceWatchOnly(0),
    currentStake(0),
    currentUnconfirmedBalance(-1),
    currentImmatureBalance(-1),
    currentQaiBalance(-1),
    txdelegate(new TxViewDelegate()),
    filter(0)
{
    if(! ui){
        throw qt_error("OverviewPage Failed to allocate memory.", this);
    }

    ui->setupUi(this);

    QFont balance = QApplication::font();
    balance.setPointSize(balance.pointSize() * 1.5);
    balance.setBold(true);
    ui->label_5->setFont(balance);

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, SIGNAL(clicked(QModelIndex)), this, SLOT(handleTransactionClicked(QModelIndex)));

    // init "out of sync" warning labels
    ui->labelWalletStatus->setText("(" + tr("out of sync") + ")");
    ui->labelTransactionsStatus->setText("(" + tr("out of sync") + ")");

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter) {
        emit transactionClicked(filter->mapToSource(index));
    }
}

OverviewPage::~OverviewPage()
{
    delete ui;
}

void OverviewPage::setBalance(qint64 total, qint64 watchOnly, qint64 stake, qint64 unconfirmedBalance, qint64 immatureBalance, qint64 qaiBalance)
{
    BitcoinUnits::Unit unit = model->getOptionsModel()->getDisplayUnit();
    currentBalanceTotal = total;
    currentBalanceWatchOnly = watchOnly;
    currentStake = stake;
    currentUnconfirmedBalance = unconfirmedBalance;
    currentImmatureBalance = immatureBalance;
    currentQaiBalance = qaiBalance;
    ui->labelAvailable->setText(BitcoinUnits::formatWithUnit(unit, total));
    ui->labelBalanceWatchOnly->setText(BitcoinUnits::formatWithUnit(unit, watchOnly));
    ui->labelStake->setText(BitcoinUnits::formatWithUnit(unit, stake));
    ui->labelUnconfirmed->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedBalance));
    ui->labelImmature->setText(BitcoinUnits::formatWithUnit(unit, immatureBalance));
    ui->labelQai->setText(BitcoinUnits::formatWithUnit(unit, qaiBalance));
    qint64 total_view = total + stake + unconfirmedBalance + immatureBalance - qaiBalance;
    if(total_view < 0)
        total_view = 0;
    ui->labelTotal->setText(BitcoinUnits::formatWithUnit(unit, total_view));

    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = immatureBalance != 0;
    ui->labelImmature->setVisible(showImmature);
    ui->labelImmatureText->setVisible(showImmature);

    // only show watch-only balance if it's non-zero, so as not to complicate things
    // for users
    bool showWatchOnly = watchOnly != 0;
    ui->labelBalanceWatchOnly->setVisible(showWatchOnly);
    ui->labelBalanceWatchOnlyText->setVisible(showWatchOnly);

}

// show/hide watch-only labels
void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{
    ui->labelBalanceWatchOnly->setVisible(showWatchOnly);
    ui->labelBalanceWatchOnlyText->setVisible(showWatchOnly);
}

void OverviewPage::setNumTransactions(int count)
{
    ui->labelNumTransactions->setText(QLocale::system().toString(count));
}

void OverviewPage::setModel(WalletModel *model)
{
    this->model = model;
    if(model && model->getOptionsModel()) {
        // Set up transaction list
        filter = new TransactionFilterProxy();
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        // filter->setSortRole(Qt::EditRole);
        filter->setSortRole(TransactionTableModel::DateRole);
        filter->sort(TransactionTableModel::Status, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter);
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        // Keep up to date with wallet
        setBalance(model->getBalance(), model->getBalanceWatchOnly(), model->getStake(), model->getUnconfirmedBalance(), model->getImmatureBalance(), model->getQaiBalance());
        connect(model, SIGNAL(balanceChanged(qint64, qint64, qint64, qint64, qint64, qint64)), this, SLOT(setBalance(qint64, qint64, qint64, qint64, qint64, qint64)));

        setNumTransactions(model->getNumTransactions());
        connect(model, SIGNAL(numTransactionsChanged(int)), this, SLOT(setNumTransactions(int)));

        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

        updateWatchOnlyLabels(model->haveWatchOnly());
        connect(model, SIGNAL(notifyWatchonlyChanged(bool)), this, SLOT(updateWatchOnlyLabels(bool)));
    }

    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void OverviewPage::updateDisplayUnit()
{
    if(model && model->getOptionsModel()) {
        if(currentBalanceTotal != -1) {
            setBalance(currentBalanceTotal, currentBalanceWatchOnly, model->getStake(), currentUnconfirmedBalance, currentImmatureBalance, currentQaiBalance);
        }

        // Update txdelegate->unit with the current unit
        txdelegate->unit = model->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    ui->labelWalletStatus->setVisible(fShow);
    ui->labelTransactionsStatus->setVisible(fShow);
}

#ifndef CLI_MODE_ENABLE
void OverviewPage::on_BenchmarkCommandLinkButton_clicked()
{
#ifdef WIN32
    predsystem::CreateBenchmark();
#else
    QMessageBox::information(this, tr("SORA-QAI benchmark"), tr("under development"), QMessageBox::Ok);
#endif
}
#endif

/*
void OverviewPage::on_DriveVerifyCommandLinkButton_clicked()
{
    QMessageBox::information(this, tr("SORA-QAI benchmark"), tr("under development"), QMessageBox::Ok);
}
*/

/*
void OverviewPage::on_pushButton_clicked()
{
    QString link="https://www.junkhdd.com/";
    QDesktopServices::openUrl(QUrl(link));
}

void OverviewPage::on_pushButton_2_clicked()
{
    QString link="https://discord.gg/ThMeemM/";
    QDesktopServices::openUrl(QUrl(link));
}
*/
