// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef RPCCONSOLE_H
#define RPCCONSOLE_H

#include <allocator/qtsecure.h>
#include <qt/peerswidget.h>
#include <qt/getciphermessageswidget.h>
#include <QWidget>

namespace Ui {
    class RPCConsole;
}
class WalletModel;
class ClientModel;

/** Local Bitcoin RPC console. */
class RPCConsole: public QWidget {
    Q_OBJECT
private:
    RPCConsole()=delete;
    RPCConsole(const RPCConsole &)=delete;
    RPCConsole(RPCConsole &&)=delete;
    RPCConsole &operator=(const RPCConsole &)=delete;
    RPCConsole &operator=(RPCConsole &&)=delete;
public:
    explicit RPCConsole(QWidget *parent = nullptr);
    ~RPCConsole();

    void setWalletModel(WalletModel *model);
    void setClientModel(ClientModel *model);
    enum MessageClass {
        MC_ERROR,
        MC_DEBUG,
        CMD_REQUEST,
        CMD_REPLY,
        CMD_ERROR
    };
protected:
    virtual bool eventFilter(QObject* obj, QEvent *event);
    void keyPressEvent(QKeyEvent *);

private slots:
    void on_lineEdit_returnPressed();
    void on_tabWidget_currentChanged(int index);
    /** open the debug.log from the current datadir */
    void on_openDebugLogfileButton_clicked();
    /** open the SorachanCoin.conf from the current datadir */
    void on_openConfigurationfileButton_clicked();
    /** change the time range of the network traffic graph */
    void on_sldGraphRange_valueChanged(int value);
    /** update traffic statistics */
    void updateTrafficStats(quint64 totalBytesIn, quint64 totalBytesOut);
    void resizeEvent(QResizeEvent *event);
    void showEvent(QShowEvent *event);
    void hideEvent(QHideEvent *event);
    /** display messagebox with program parameters (same as bitcoin-qt --help) */
    void on_showCLOptionsButton_clicked();
    /** Peers display **/
    //void on_updatePushButton_clicked();

public slots:
    void clear();
    void message(int category, const QString &message, bool html = false);
    void peers(bool ban, const QString &message, bool html = false);
    void ciphermessages(const QString &message, bool html = false);
    void ciphermypubkey();
    void sendciphermessage();
    void updateCipherMessage();
    void ciphermessageClear();
    void sentmymessages(const QString &message, bool html = false);
    void updateSentMyMessages();
    void sentmessagesClear();
    void copyrecipientAddress();
    /** Set number of connections shown in the UI */
    void setNumConnections(int count);
    /** Set number of blocks shown in the UI */
    void setNumBlocks(int count, int countOfPeers);
    /** Go forward or back in history */
    void browseHistory(int offset);
    /** Scroll console view to end */
    void scrollToEnd();
signals:
    // For RPC command executor
    void stopExecutor();
    void cmdRequest(const QString &command);

private:
    static QString FormatBytes(quint64 bytes);
    void setTrafficGraphRange(int mins);
    /** show detailed information on ui about selected node */

    enum ColumnWidths
    {
        ADDRESS_COLUMN_WIDTH = 200,
        SUBVERSION_COLUMN_WIDTH = 100,
        PING_COLUMN_WIDTH = 80
    };

    Ui::RPCConsole *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    QStringList history;
    int historyPtr;

    void startExecutor();
};

#endif // RPCCONSOLE_H
