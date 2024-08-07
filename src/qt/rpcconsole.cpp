// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpcconsole.h>
#include <ui_rpcconsole.h>
#include <clientmodel.h>
#include <rpc/bitcoinrpc.h>
#include <qt/walletmodel.h>
#include <qt/addresstablemodel.h>
#include <sorara/aitx.h>
#include <guiutil.h>
#include <dialogwindowflags.h>
#include <QTime>
#include <QTimer>
#include <QThread>
#include <QTextEdit>
#include <QKeyEvent>
#include <QUrl>
#include <QScrollBar>
#include <QClipboard>
#ifdef USE_BERKELEYDB
# include <db_cxx.h>
#endif
#include <allocator/qtsecure.h>
#include <db.h>

namespace {
constexpr int CONSOLE_HISTORY = 50;
constexpr QSize ICON_SIZE(24, 24);
constexpr int INITIAL_TRAFFIC_GRAPH_MINS = 30;
const struct {
    const char *url;
    const char *source;
} ICON_MAPPING[] = {
    {"cmd-request", ":/icons/tx_input"},
    {"cmd-reply", ":/icons/tx_output"},
    {"cmd-error", ":/icons/tx_output"},
    {"misc", ":/icons/tx_inout"},
    {nullptr, nullptr}
};
} // namespace

class RPCExecutor: public QObject
{
    Q_OBJECT
private:
    RPCExecutor(const RPCExecutor &)=delete;
    RPCExecutor(RPCExecutor &&)=delete;
    RPCExecutor &operator=(const RPCExecutor &)=delete;
    RPCExecutor &operator=(RPCExecutor &&)=delete;
public:
    RPCExecutor() {}
public slots:
    void start() {}
#ifndef CLI_MODE_ENABLE
    void request(const QString &command);
#endif
signals:
    void reply(int category, const QString &command);
};

#include <rpcconsole.moc>

/**
 * Split shell command line into a list of arguments. Aims to emulate \c bash and friends.
 *
 * - Arguments are delimited with whitespace
 * - Extra whitespace at the beginning and end and between arguments will be ignored
 * - Text can be "double" or 'single' quoted
 * - The backslash \c \ is used as escape character
 *   - Outside quotes, any character can be escaped
 *   - Within double quotes, only escape \c " and backslashes before a \c " or another backslash
 *   - Within single quotes, no escaping is possible and no special interpretation takes place
 *
 * @param[out]   args        Parsed arguments will be appended to this list
 * @param[in]    strCommand  Command line to split
 */
bool parseCommandLine(std::vector<std::string> &args, const std::string &strCommand)
{
    enum CmdParseState {
        STATE_EATING_SPACES,
        STATE_ARGUMENT,
        STATE_SINGLEQUOTED,
        STATE_DOUBLEQUOTED,
        STATE_ESCAPE_OUTER,
        STATE_ESCAPE_DOUBLEQUOTED
    } state = STATE_EATING_SPACES;

    std::string curarg;
    for(char ch: strCommand) {
        switch(state)
        {
        case STATE_ARGUMENT: // In or after argument
        case STATE_EATING_SPACES: // Handle runs of whitespace
            switch(ch)
            {
            case '"':
                state = STATE_DOUBLEQUOTED;
                break;
            case '\'':
                state = STATE_SINGLEQUOTED;
                break;
            case '\\':
                state = STATE_ESCAPE_OUTER;
                break;
            case ' ': case '\n': case '\t':
                if(state == STATE_ARGUMENT) { // Space ends argument
                    args.push_back(curarg);
                    curarg.clear();
                }
                state = STATE_EATING_SPACES;
                break;
            default:
                curarg += ch;
                state = STATE_ARGUMENT;
                break;
            }
            break;
        case STATE_SINGLEQUOTED: // Single-quoted string
            switch(ch)
            {
            case '\'':
                state = STATE_ARGUMENT;
                break;
            default:
                curarg += ch;
                break;
            }
            break;
        case STATE_DOUBLEQUOTED: // Double-quoted string
            switch(ch)
            {
            case '"':
                state = STATE_ARGUMENT;
                break;
            case '\\':
                state = STATE_ESCAPE_DOUBLEQUOTED;
                break;
            default:
                curarg += ch;
                break;
            }
            break;
        case STATE_ESCAPE_OUTER: // '\' outside quotes
            curarg += ch;
            state = STATE_ARGUMENT;
            break;
        case STATE_ESCAPE_DOUBLEQUOTED: // '\' in double-quoted text
            if(ch != '"' && ch != '\\') curarg += '\\'; // keep '\' for everything but the quote and '\' itself
            curarg += ch;
            state = STATE_DOUBLEQUOTED;
            break;
        }
    }

    switch(state)
    {
    case STATE_EATING_SPACES:
        return true;
    case STATE_ARGUMENT:
        args.push_back(curarg);
        return true;
    default: // ERROR to end in one of the other states
        return false;
    }
}

#ifndef CLI_MODE_ENABLE
void RPCExecutor::request(const QString &command)
{
    std::vector<std::string> args;
    if(! parseCommandLine(args, command.toStdString())) {
        emit reply(RPCConsole::CMD_ERROR, QString("Parse error: unbalanced ' or \""));
        return;
    }
    if(args.empty()) {
        return; // Nothing to do
    }

    try {
        std::string strPrint;
        // Convert argument list to JSON objects in method-dependent way,
        // and pass it along with the method name to the dispatcher.
        json_spirit::Value result = CRPCTable::execute(
            args[0],
            bitrpc::RPCConvertValues(args[0], std::vector<std::string>(args.begin() + 1, args.end())));

        // Format result reply
        if (result.type() == json_spirit::null_type) {
            strPrint = "";
        } else if (result.type() == json_spirit::str_type) {
            strPrint = result.get_str();
        } else {
            strPrint = write_string(result, true);
        }

        emit reply(RPCConsole::CMD_REPLY, QString::fromStdString(strPrint));
    } catch (json_spirit::Object &objError) {
        try {
            // Nice formatting for standard-format error
            int code = find_value(objError, "code").get_int();
            std::string message = find_value(objError, "message").get_str();
            emit reply(RPCConsole::CMD_ERROR, QString::fromStdString(message) + " (code " + QString::number(code) + ")");
        } catch(const std::runtime_error &) {   // raised when converting to invalid type, i.e. missing code or message
            // Show raw JSON object
            emit reply(RPCConsole::CMD_ERROR, QString::fromStdString(write_string(json_spirit::Value(objError), false)));
        }
    } catch (const std::exception &e) {
        emit reply(RPCConsole::CMD_ERROR, QString("Error: ") + QString::fromStdString(e.what()));
    }
}
#endif

RPCConsole::RPCConsole(QWidget *parent) : QWidget(parent), ui(new (std::nothrow) Ui::RPCConsole), historyPtr(0) {
    if(! ui)
        throw qt_error("RPCConsole Failed to allocate memory.", this);
    ui->setupUi(this);
#ifndef Q_OS_MAC
    ui->openDebugLogfileButton->setIcon(QIcon(":/icons/export"));
    ui->openConfigurationfileButton->setIcon(QIcon(":/icons/export"));
    ui->showCLOptionsButton->setIcon(QIcon(":/icons/options"));
#endif
    // Install event filter for up and down arrow
    ui->lineEdit->installEventFilter(this);
    ui->messagesWidget->installEventFilter(this);
    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clear()));
    connect(ui->btnClearTrafficGraph, SIGNAL(clicked()), ui->trafficGraph, SLOT(clear()));

    // set library version labels
    ui->openSSLVersion->setText(SSLeay_version(SSLEAY_VERSION));
#ifndef WALLET_SQL_MODE
    ui->berkeleyDBVersion->setText(DbEnv::version(0, 0, 0));
#else
    ui->berkeleyDBVersion->setText(CSqliteDBEnv::get_version().c_str());
#endif

    startExecutor();
    setTrafficGraphRange(INITIAL_TRAFFIC_GRAPH_MINS);
    clear();
}

RPCConsole::~RPCConsole() {
    emit stopExecutor();
    delete ui;
}

bool RPCConsole::eventFilter(QObject* obj, QEvent *event) {
    if(event->type() == QEvent::KeyPress) { // Special key handling
        QKeyEvent *keyevt = static_cast<QKeyEvent *>(event);
        int key = keyevt->key();
        Qt::KeyboardModifiers mod = keyevt->modifiers();
        switch(key)
        {
        case Qt::Key_Up: if(obj == ui->lineEdit) { browseHistory(-1); return true; } break;
        case Qt::Key_Down: if(obj == ui->lineEdit) { browseHistory(1); return true; } break;
        case Qt::Key_PageUp: /* pass paging keys to messages widget */
        case Qt::Key_PageDown:
            if(obj == ui->lineEdit) {
                QApplication::postEvent(ui->messagesWidget, new QKeyEvent(*keyevt));
                return true;
            }
            break;
        default:
            // Typing in messages widget brings focus to line edit, and redirects key there
            // Exclude most combinations and keys that emit no text, except paste shortcuts
            if(obj == ui->messagesWidget && (
                  (!mod && !keyevt->text().isEmpty() && key != Qt::Key_Tab) ||
                  ((mod & Qt::ControlModifier) && key == Qt::Key_V) ||
                  ((mod & Qt::ShiftModifier) && key == Qt::Key_Insert))) {
                ui->lineEdit->setFocus();
                QApplication::postEvent(ui->lineEdit, new QKeyEvent(*keyevt));
                return true;
            }
        }
    }
    return QWidget::eventFilter(obj, event);
}

void RPCConsole::setWalletModel(WalletModel *model) {
    this->walletModel = model;
}

void RPCConsole::setClientModel(ClientModel *model) {
    this->clientModel = model;
    ui->trafficGraph->setClientModel(model);
    if(model) {
        // Subscribe to information, replies, messages, errors
        connect(model, SIGNAL(numConnectionsChanged(int)), this, SLOT(setNumConnections(int)));
        connect(model, SIGNAL(numBlocksChanged(int,int)), this, SLOT(setNumBlocks(int,int)));

        updateTrafficStats(model->getTotalBytesRecv(), model->getTotalBytesSent());
        connect(model, SIGNAL(bytesChanged(quint64,quint64)), this, SLOT(updateTrafficStats(quint64, quint64)));
        // Provide initial values
        ui->clientVersion->setText(model->formatFullVersion());
        ui->clientName->setText(model->clientName());
        ui->buildDate->setText(model->formatBuildDate());
        ui->startupTime->setText(model->formatClientStartupTime());

        setNumConnections(model->getNumConnections());
        ui->isTestNet->setChecked(model->isTestNet());

        setNumBlocks(model->getNumBlocks(), model->getNumBlocksOfPeers());
    }
}

static QString categoryClass(int category) {
    switch(category)
    {
    case RPCConsole::CMD_REQUEST:  return "cmd-request"; break;
    case RPCConsole::CMD_REPLY:    return "cmd-reply"; break;
    case RPCConsole::CMD_ERROR:    return "cmd-error"; break;
    default:                       return "misc";
    }
}

void RPCConsole::clear() {
    ui->messagesWidget->clear();
    history.clear();
    historyPtr = 0;
    ui->lineEdit->clear();
    ui->lineEdit->setFocus();

    // Add smoothly scaled icon images.
    // (when using width/height on an img, Qt uses nearest instead of linear interpolation)
    for(int i=0; ICON_MAPPING[i].url; ++i) {
        ui->messagesWidget->document()->addResource(
            QTextDocument::ImageResource,
            QUrl(ICON_MAPPING[i].url),
            QImage(ICON_MAPPING[i].source).scaled(ICON_SIZE, Qt::IgnoreAspectRatio, Qt::SmoothTransformation));
    }

    ui->messagesWidget->document()->setDefaultStyleSheet(
                "table { }"
                "td.time { color: #FFFFFF; padding-top: 3px; } "
                "td.message { font-family: Monospace; } "
                "td.cmd-request { color: #FFFFFF; } "
                "td.cmd-error { color: red; } "
                "b { color: #006060; } "
                );

    message(CMD_REPLY, (tr("Welcome to SorachanCoin RPC console.") + "<br />" +
                        tr("Use up and down arrows to navigate history, and <b>Ctrl-L</b> to clear screen.") + "<br />" +
                        tr("Type <b>help</b> for an overview of available commands.")), true);
}

void RPCConsole::peers(bool ban, const QString &message, bool html/*=false*/) {
    (void)ban;
    ui->peersMessagesWidget->document()->setDefaultStyleSheet(
                "table { }"
                "td { font-family: Monospace; } "
                "td.time { color: #FFFFFF; padding-top: 10px; } "
                "td.cmd-request { color: #FFFFFF; } "
                "td.cmd-error { color: red; } "
                "b { color: #006060; } "
                );

    QTime time = QTime::currentTime();
    QString timeString = time.toString();
    QString out;
    out += "<table width=\"600\"><tr><td class=\"time\" width=\"65\">" + timeString + "</td><td>";
    if(html) out += message;
    else out += GUIUtil::HtmlEscape(message, true);
    out += "</td></tr></table>";
    ui->peersMessagesWidget->append(out);
}

void RPCConsole::ciphermessages(const QString &message, bool html/*=false*/) {
    ui->cipherMessagesWidget->document()->setDefaultStyleSheet(
                "table { }"
                "td { font-family: Monospace; } "
                "td.time { color: #FFFFFF; padding-top: 10px; } "
                "td.cmd-request { color: #FFFFFF; } "
                "td.cmd-error { color: red; } "
                "b { color: #006060; } "
                );

    QTime time = QTime::currentTime();
    QString timeString = time.toString();
    QString out;
    out += "<table width=\"100%\"><tr><td class=\"time\" width=\"80\">" + timeString + "</td><td>";
    if(html) out += message;
    else out += GUIUtil::HtmlEscape(message, true);
    out += "</td></tr></table>";
    ui->cipherMessagesWidget->append(out);
}

void RPCConsole::ciphermypubkey() {
    // manual wallet unlock
    AddressTableModel *addressModel = walletModel->getAddressTableModel();
    bool mintonly;
    if(!addressModel->addQai_v3(mintonly))
        return;
    this->raise();

    std::string cipher_address;
    std::string err;
    if(!ai_cipher::getmycipheraddress(cipher_address, err))
        cipher_address = err;

    ui->cipheraddresslineEdit->setText(QString::fromStdString(cipher_address));
    addressModel->addQai_v3_wallet_tolock(mintonly);
}

RPCConsole *g_console = nullptr;
extern "C" void call_raise() {
    if(g_console)
        g_console->raise();
}

void RPCConsole::sendciphermessage() {
    g_console = this;
    if(!QMB(QMB::M_QUESTION).setText(tr("Is it okay to record the ciphered message on the blockchain?").toStdString(), _("")).ask())
        return;
    this->raise();
    QString q_recipient_pubkey = ui->cipheraddresslineEdit->text();
    if(q_recipient_pubkey.size() == 0) {
        QMB(QMB::M_ERROR).setText(tr("The recipient's public cipher address is empty.").toStdString(), _("")).exec();
        this->raise();
        return;
    }
    QString q_cipher = ui->sendciphermessageWidget->toPlainText();
    if(q_cipher.size() == 0) {
        QMB(QMB::M_ERROR).setText(tr("The encrypted message to be sent is empty.").toStdString(), _("")).exec();
        this->raise();
        return;
    }

    // manual wallet unlock
    bool mintflag = walletModel->getMintflag();
    AddressTableModel *addressModel = walletModel->getAddressTableModel();
    bool junk;
    if(!addressModel->addQai_v3(junk))
        return;
    this->raise();

    bool stealth = ui->stealthCheckBox->isChecked();
    std::string recipient_pubkey = q_recipient_pubkey.toStdString();
    std::string cipher = q_cipher.toStdString();
    QMB(QMB::M_INFO).setText(tr("The process of recording to the blockchain has started. "
                               "Please keep your wallet open and wait for a while until the process is completed. "
                               "SORA will notify you once the recording to the blockchain is finished.").toStdString(), _("")).exec();
    this->raise();
    if(!ai_cipher::sendciphermessage(recipient_pubkey, std::move(cipher), stealth, mintflag)) {
        QMB(QMB::M_ERROR).setText(tr("An error occurred during the initiation of the recording process.").toStdString(), _("")).exec();
        this->raise();
    }
}

static void GetCipherMessages(std::string &dest, uint32_t hours) {
    std::vector<std::tuple<time_t, std::string, SecureString>> vdata;
    std::string err;
    if(!ai_cipher::getmessages(hours, vdata, err)) {
        dest = err;
        return;
    }

    dest = "";
    for(const auto &d: vdata) {
        std::string br_str;
        br_str.reserve(std::get<2>(d).size() * 1.2);
        for(auto c: std::get<2>(d)) {
            if(c != '\n')
                br_str.push_back(c);
            else {
                br_str.push_back('<');
                br_str.push_back('b');
                br_str.push_back('r');
                br_str.push_back('>');
            }
        }

        dest += "<table><tr><td>time: </td><td>";
        dest += ai_time::get_localtime_format(std::get<0>(d));
        dest += "</td></tr><tr><td>";
        dest += "from: </td><td>";
        dest += std::get<1>(d);
        dest += "</td></tr><tr><td>";
        dest += "message: </td><td>";
        dest += br_str;
        dest += "</td></tr></table>";
        dest += "<br />";
    }
}

void RPCConsole::updateCipherMessage() {
    // manual wallet unlock
    AddressTableModel *addressModel = walletModel->getAddressTableModel();
    bool mintonly;
    if(!addressModel->addQai_v3(mintonly))
        return;
    this->raise();

    uint32_t hours = ui->gethoursSpinBox->value();
    std::string result;
    GetCipherMessages(result, hours);
    ciphermessages(QString::fromStdString(result), true);
    addressModel->addQai_v3_wallet_tolock(mintonly);
}

void RPCConsole::ciphermessageClear() {
    ui->cipherMessagesWidget->clear();
}

void RPCConsole::sentmymessages(const QString &message, bool html/*=false*/) {
    ui->cipherMessagesWidget->document()->setDefaultStyleSheet(
                "table { }"
                "td { font-family: Monospace; } "
                "td.time { color: #FFFFFF; padding-top: 10px; } "
                "td.cmd-request { color: #FFFFFF; } "
                "td.cmd-error { color: red; } "
                "b { color: #006060; } "
                );

    QTime time = QTime::currentTime();
    QString timeString = time.toString();
    QString out;
    out += "<table width=\"100%\"><tr><td class=\"time\" width=\"80\">" + timeString + "</td><td>";
    if(html) out += message;
    else out += GUIUtil::HtmlEscape(message, true);
    out += "</td></tr></table>";
    ui->sentmessagesTextEdit->append(out);
}

static void GetSentMessages(std::string &dest, const std::string &recipient_address, uint32_t hours) {
    std::vector<std::pair<time_t, SecureString>> vdata;
    std::string err;
    if(!ai_cipher::getsentmymessages(hours, recipient_address, vdata, err)) {
        dest = err;
        return;
    }

    dest = "";
    for(const auto &d: vdata) {
        std::string br_str;
        br_str.reserve(d.second.size() * 1.2);
        for(auto c: d.second) {
            if(c != '\n')
                br_str.push_back(c);
            else {
                br_str.push_back('<');
                br_str.push_back('b');
                br_str.push_back('r');
                br_str.push_back('>');
            }
        }

        dest += "<table><tr><td>time: </td><td>";
        dest += ai_time::get_localtime_format(d.first);
        dest += "</td></tr><tr><td>";
        dest += "message: </td><td>";
        dest += br_str;
        dest += "</td></tr></table>";
        dest += "<br />";
    }
}

void RPCConsole::updateSentMyMessages() {
    if(!QMB(QMB::M_QUESTION).setText(tr("If the number of processes is large, "
                                       "the Schnorr aggregated signature process will take a considerable amount of time. "
                                       "Please wait patiently until the process is completed. "
                                        "SORA will notify you once it is finished.").toStdString(), _("")).ask()) {
        this->raise();
        return;
    }
    this->raise();

    uint32_t hours = ui->getsentmessagesSpinBox->value();
    std::string recipient_address = ui->sentaddressLineEdit->text().toStdString();
    if(recipient_address.size() == 0) {
        QMB(QMB::M_ERROR).setText(tr("The recipient's public cipher address is empty.").toStdString(), _("")).exec();
        this->raise();
        return;
    }

    // manual wallet unlock
    AddressTableModel *addressModel = walletModel->getAddressTableModel();
    bool mintflag;
    if(!addressModel->addQai_v3(mintflag))
        return;
    this->raise();

    std::string result;
    GetSentMessages(result, recipient_address, hours);
    sentmymessages(QString::fromStdString(result), true);
    addressModel->addQai_v3_wallet_tolock(mintflag);
}

void RPCConsole::sentmessagesClear() {
    ui->sentmessagesTextEdit->clear();
}

void RPCConsole::copyrecipientAddress() {
    QClipboard *clipboard = QGuiApplication::clipboard();
    QString text = ui->cipheraddresslineEdit->text();
    if(text.size() > 0)
        clipboard->setText(text);
}

void RPCConsole::message(int category, const QString &message, bool html/*=false*/) {
    QTime time = QTime::currentTime();
    QString timeString = time.toString();
    QString out;
    out += "<table><tr><td class=\"time\" width=\"65\">" + timeString + "</td>";
    out += "<td class=\"icon\" width=\"32\"><img src=\"" + categoryClass(category) + "\"></td>";
    out += "<td class=\"message " + categoryClass(category) + "\" valign=\"middle\">";
    if(html) out += message;
    else out += GUIUtil::HtmlEscape(message, true);
    out += "</td></tr></table>";
    ui->messagesWidget->append(out);
}

void RPCConsole::setNumConnections(int count) {
    if (! clientModel) return;
    QString connections = QString::number(count) + " (";
    connections += tr("Inbound:") + " " + QString::number(clientModel->getNumConnections(CONNECTIONS_IN)) + " / ";
    connections += tr("Outbound:") + " " + QString::number(clientModel->getNumConnections(CONNECTIONS_OUT)) + ")";
    ui->numberOfConnections->setText(connections);
}

void RPCConsole::setNumBlocks(int count, int countOfPeers) {
    ui->numberOfBlocks->setText(QString::number(count));
    ui->totalBlocks->setText(QString::number(countOfPeers));
    if(clientModel) {
        // If there is no current number available display N/A instead of 0, which can't ever be true
        ui->totalBlocks->setText(clientModel->getNumBlocksOfPeers() == 0 ? tr("N/A") : QString::number(clientModel->getNumBlocksOfPeers()));
        ui->lastBlockTime->setText(clientModel->getLastBlockDate().toString());
    }
}

void RPCConsole::on_lineEdit_returnPressed() {
    QString cmd = ui->lineEdit->text();
    ui->lineEdit->clear();
    if(! cmd.isEmpty()) {
        message(CMD_REQUEST, cmd);
        emit cmdRequest(cmd);
        // Remove command, if already in history
        history.removeOne(cmd);
        // Append command to history
        history.append(cmd);
        // Enforce maximum history size
        while(history.size() > CONSOLE_HISTORY) history.removeFirst();
        // Set pointer to end of history
        historyPtr = history.size();
        // Scroll console view to end
        scrollToEnd();
    }
}

void RPCConsole::browseHistory(int offset) {
    historyPtr += offset;
    if(historyPtr < 0) historyPtr = 0;
    if(historyPtr > history.size()) historyPtr = history.size();
    QString cmd;
    if(historyPtr < history.size()) cmd = history.at(historyPtr);
    ui->lineEdit->setText(cmd);
}

void RPCConsole::startExecutor() {
    QThread *thread = new (std::nothrow) QThread;
    RPCExecutor *executor = new (std::nothrow) RPCExecutor;
    PeersWidget *pw = new (std::nothrow) PeersWidget;
    CipherWidget *pcipher = new (std::nothrow) CipherWidget;
    if(!thread || !executor || !pw || !pcipher)
        throw qt_error("RPCConsole Failed to allocate memory.", this);
    executor->moveToThread(thread);

    // Notify executor when thread started (in executor thread)
    connect(thread, SIGNAL(started()), executor, SLOT(start()));
    // Replies from executor object must go to this object
    connect(executor, SIGNAL(reply(int,QString)), this, SLOT(message(int,QString)));
    // Requests from this object must go to executor
    connect(this, SIGNAL(cmdRequest(QString)), executor, SLOT(request(QString)));
    // Peers from executor object must go to this object
    connect(pw, SIGNAL(newnode(bool,QString,bool)), this, SLOT(peers(bool,QString,bool)));
    // Peers connect
    connect(ui->updatePushButton, SIGNAL(clicked()), pw, SLOT(update()));
    // Cipher from executor object must go to this object
    //connect(pcipher, SIGNAL(getciphermessages(QString,bool)), this, SLOT(ciphermessages(QString,bool)));
    // Cipher connect
    connect(ui->getcipherPushButton, SIGNAL(clicked()), this, SLOT(updateCipherMessage()));
    connect(ui->getmyaddressPushButton, SIGNAL(clicked()), this, SLOT(ciphermypubkey()));
    connect(ui->sendPushButton, SIGNAL(clicked()), this, SLOT(sendciphermessage()));
    connect(ui->clearmessagePushButton, SIGNAL(clicked()), this, SLOT(ciphermessageClear()));
    connect(ui->copyaddressPushButton, SIGNAL(clicked()), this, SLOT(copyrecipientAddress()));
    ui->gethoursSpinBox->setValue(168);
    // GetSentMessages connect
    connect(ui->clearsentmessagesPushButton, SIGNAL(clicked()), this, SLOT(sentmessagesClear()));
    connect(ui->sentmessagesPushButton, SIGNAL(clicked()), this, SLOT(updateSentMyMessages()));
    ui->getsentmessagesSpinBox->setValue(168);
    // On stopExecutor signal
    // - queue executor for deletion (in execution thread)
    // - quit the Qt event loop in the execution thread
    connect(this, SIGNAL(stopExecutor()), executor, SLOT(deleteLater()));
    connect(this, SIGNAL(stopExecutor()), thread, SLOT(quit()));
    // Queue the thread for deletion (in this thread) when it is finished
    connect(thread, SIGNAL(finished()), thread, SLOT(deleteLater()));

    // Default implementation of QThread::run() simply spins up an event loop in the thread,
    // which is what we want.
    thread->start();
}

void RPCConsole::on_tabWidget_currentChanged(int index) {
    if(ui->tabWidget->widget(index) == ui->tab_console)
        ui->lineEdit->setFocus();
}

void RPCConsole::on_openDebugLogfileButton_clicked() {
    GUIUtil::openDebugLogfile();
}

void RPCConsole::on_openConfigurationfileButton_clicked() {
    GUIUtil::openConfigfile();
}

void RPCConsole::scrollToEnd() {
    QScrollBar *scrollbar = ui->messagesWidget->verticalScrollBar();
    scrollbar->setValue(scrollbar->maximum());
}

void RPCConsole::on_showCLOptionsButton_clicked() {
    GUIUtil::HelpMessageBox help;
    help.exec();
}

void RPCConsole::on_sldGraphRange_valueChanged(int value) {
    const int multiplier = 5; // each position on the slider represents 5 min
    int mins = value * multiplier;
    setTrafficGraphRange(mins);
}

QString RPCConsole::FormatBytes(quint64 bytes) {
    if(bytes < 1024)
        return QString(tr("%1 B")).arg(bytes);
    if(bytes < 1024 * 1024)
        return QString(tr("%1 KB")).arg(bytes / 1024);
    if(bytes < 1024 * 1024 * 1024)
        return QString(tr("%1 MB")).arg(bytes / 1024 / 1024);
    return QString(tr("%1 GB")).arg(bytes / 1024 / 1024 / 1024);
}

void RPCConsole::setTrafficGraphRange(int mins) {
    ui->trafficGraph->setGraphRangeMins(mins);
    ui->lblGraphRange->setText(GUIUtil::formatDurationStr(mins * 60));
}

void RPCConsole::updateTrafficStats(quint64 totalBytesIn, quint64 totalBytesOut) {
    ui->lblBytesIn->setText(FormatBytes(totalBytesIn));
    ui->lblBytesOut->setText(FormatBytes(totalBytesOut));
}

void RPCConsole::resizeEvent(QResizeEvent *event) {
    QWidget::resizeEvent(event);
}

void RPCConsole::showEvent(QShowEvent *event) {
    QWidget::showEvent(event);
    if (! clientModel) return;
}

void RPCConsole::hideEvent(QHideEvent *event) {
    QWidget::hideEvent(event);
    if (! clientModel) return;
}

void RPCConsole::keyPressEvent(QKeyEvent *event) {
#ifdef ANDROID
    if(windowType() != Qt::Widget && event->key() == Qt::Key_Back)
        close();
#else
    if(windowType() != Qt::Widget && event->key() == Qt::Key_Escape)
        close();
#endif
}

//void RPCConsole::on_updatePushButton_clicked() {}
