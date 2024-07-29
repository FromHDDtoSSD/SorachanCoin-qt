// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
 * W.J. van der Laan 2011-2012
 */

#include <qt/bitcoingui.h>
#include <qt/clientmodel.h>
#include <qt/walletmodel.h>
#include <qt/optionsmodel.h>
#include <qt/autocheckpointsmodel.h>
#include <qt/guiutil.h>
#include <qt/guiconstants.h>
#include <init.h>
#include <ui_interface.h>
#include <qt/qtipcserver.h>
#include <qt/intro.h>
#include <QCoreApplication>
#include <QApplication>
#include <QMessageBox>
#if QT_VERSION < 0x050000
#include <QTextCodec>
#endif
#include <QLocale>
#include <QTranslator>
#include <QSplashScreen>
#include <QLibraryInfo>
#include <QSettings>
#include <QLabel>
#include <QTimer>

#ifdef WIN32
# include <winapi/common.h>
#endif

#if defined(BITCOIN_NEED_QT_PLUGINS) && !defined(_BITCOIN_QT_PLUGINS_INCLUDED)
#define _BITCOIN_QT_PLUGINS_INCLUDED
#define __INSURE__
#include <QtPlugin>
Q_IMPORT_PLUGIN(qcncodecs)
Q_IMPORT_PLUGIN(qjpcodecs)
Q_IMPORT_PLUGIN(qtwcodecs)
Q_IMPORT_PLUGIN(qkrcodecs)
Q_IMPORT_PLUGIN(qtaccessiblewidgets)
#endif

// Need a global reference for the notifications to find the GUI
static BitcoinGUI *guiref;
static QSplashScreen *splashref;

/** Set up translations */
static void initTranslations(QTranslator &qtTranslatorBase, QTranslator &qtTranslator, QTranslator &translatorBase, QTranslator &translator)
{
    QSettings settings;
    // Get desired locale (e.g. "de_DE")

    // 1) System default language
    QString lang_territory = QLocale::system().name();

    // 2) Language from QSettings
    QString lang_territory_qsettings = settings.value("language", "").toString();
    if(! lang_territory_qsettings.isEmpty())
        lang_territory = lang_territory_qsettings;

    // 3) -lang command line argument
    lang_territory = QString::fromStdString(map_arg::GetArg("-lang", lang_territory.toStdString()));

    // Convert to "de" only by truncating "_DE"
    QString lang = lang_territory;
    lang.truncate(lang_territory.lastIndexOf('_'));

    // Load language files for configured locale:
    // - First load the translator for the base language, without territory
    // - Then load the more specific locale translator
    // Load e.g. qt_de.qm
    if (qtTranslatorBase.load("qt_" + lang, QLibraryInfo::location(QLibraryInfo::TranslationsPath)))
        QApplication::installTranslator(&qtTranslatorBase);

    // Load e.g. qt_de_DE.qm
    if (qtTranslator.load("qt_" + lang_territory, QLibraryInfo::location(QLibraryInfo::TranslationsPath)))
        QApplication::installTranslator(&qtTranslator);

    // Load e.g. bitcoin_de.qm (shortcut "de" needs to be defined in bitcoin.qrc)
    if (translatorBase.load(lang, ":/translations/"))
        QApplication::installTranslator(&translatorBase);

    // Load e.g. bitcoin_de_DE.qm (shortcut "de_DE" needs to be defined in bitcoin.qrc)
    if (translator.load(lang_territory, ":/translations/"))
        QApplication::installTranslator(&translator);
}

static void ThreadSafeMessageBox(const std::string &message, const std::string &caption, int style)
{
    // Message from network thread
    if(guiref) {
        bool modal = (style & CClientUIInterface::MODAL);
        // in case of modal message, use blocking connection to wait for user to click OK
        QMetaObject::invokeMethod(guiref, "error",
                                  modal ? GUIUtil::blockingGUIThreadConnection() : Qt::QueuedConnection,
                                  Q_ARG(QString, QString::fromStdString(caption)),
                                  Q_ARG(QString, QString::fromStdString(message)),
                                  Q_ARG(bool, modal));
    } else {
        logging::LogPrintf("%s: %s\n", caption.c_str(), message.c_str());
        fprintf(stderr, "%s: %s\n", caption.c_str(), message.c_str());
    }
}

static void ThreadSafeMessageOk(const std::string &message, const std::string &caption, const std::string &detail, unsigned int style)
{
    if(guiref) {
        QMetaObject::invokeMethod(guiref, "ok",
                                  GUIUtil::blockingGUIThreadConnection(),
                                  Q_ARG(QString, QString::fromStdString(caption)),
                                  Q_ARG(QString, QString::fromStdString(message)),
                                  Q_ARG(unsigned int, style),
                                  Q_ARG(QString, QString::fromStdString(detail)));
    }
}

static bool ThreadSafeMessageAsk(const std::string &message, const std::string &caption, const std::string &detail, unsigned int style)
{
    if(guiref) {
        bool result = false;
        QMetaObject::invokeMethod(guiref, "ask",
                                  GUIUtil::blockingGUIThreadConnection(),
                                  Q_ARG(QString, QString::fromStdString(caption)),
                                  Q_ARG(QString, QString::fromStdString(message)),
                                  Q_ARG(unsigned int, style),
                                  Q_ARG(bool*, &result),
                                  Q_ARG(QString, QString::fromStdString(detail)));
        return result;
    } else {
        logging::LogPrintf("%s: %s\n", caption.c_str(), message.c_str());
        fprintf(stderr, "%s: %s\n", caption.c_str(), message.c_str());
        return true;
    }
}

static bool ThreadSafeAskFee(int64_t nFeeRequired, const std::string &strCaption)
{
    (void)strCaption;
    if(! guiref)
        return false;
    if(nFeeRequired < block_params::MIN_TX_FEE || nFeeRequired <= block_info::nTransactionFee || args_bool::fDaemon)
        return true;

    bool payFee = false;
    QMetaObject::invokeMethod(guiref, "askFee", GUIUtil::blockingGUIThreadConnection(),
                              Q_ARG(qint64, nFeeRequired),
                              Q_ARG(bool*, &payFee));
    return payFee;
}

static void ThreadSafeHandleURI(const std::string &strURI)
{
    if(! guiref) return;
    QMetaObject::invokeMethod(guiref, "handleURI", GUIUtil::blockingGUIThreadConnection(),
                              Q_ARG(QString, QString::fromStdString(strURI)));
}

static void InitMessage(const std::string &message)
{
    if(splashref) {
        splashref->showMessage(QString::fromStdString(message), Qt::AlignBottom|Qt::AlignHCenter, QColor(255,255,200));
        QApplication::instance()->processEvents();
    }
}

static void QueueShutdown()
{
    QMetaObject::invokeMethod(QCoreApplication::instance(), "quit", Qt::QueuedConnection);
}

/*
 * Translate string to current locale using Qt.
 */
static std::string Translate(const char *psz)
{
    return QCoreApplication::translate("bitcoin-core", psz).toStdString();
}

/* Handle runaway exceptions. Shows a message box with the problem and quits the program.
 */
static void handleRunawayException(const std::exception *e)
{
    excep::PrintExceptionContinue(e, "Runaway exception");
    QMessageBox::critical(0, "Runaway exception", BitcoinGUI::tr("A fatal error occurred. " strCoinName " can no longer continue safely and will quit.") + QString("\n\n") + QString::fromStdString(excep::get_strMiscWarning()));
    exit(1);
}

/* Shutdown window
*/
class shutdownRun : public QObject {
    Q_OBJECT
public slots:
    void run() {
        QCoreApplication::exit(0);
    }
};
class shutdownWindow
{
public:
    explicit shutdownWindow(QApplication *app) : shutWindow(new QWidget) {
        QLabel label(QString(_("Don't shut down your computer meanwhile this window is displayed.").c_str()), shutWindow);
        shutWindow->resize(600, 40);
        shutWindow->setWindowTitle(QString(_(strCoinName " shutdown ...").c_str()));
        shutWindow->show();
        label.show();
        shutdownRun obj;
        QTimer::singleShot(2, &obj, SLOT(run()));
        app->exec();
    }
    ~shutdownWindow() {
        shutWindow->close();
        delete shutWindow;
    }
private:
    QWidget *shutWindow;
};
#include "bitcoin.moc"

#if !defined(BITCOIN_QT_TEST) && !defined(CLI_MODE_ENABLE)
int main(int argc, char *argv[])
{
    // Do this early as we don't want to bother initializing if we are just calling IPC
    qti_server::ipcScanRelay(argc, argv);

#if QT_VERSION < 0x050000
    // Internal string conversion is all UTF-8
    QTextCodec::setCodecForTr(QTextCodec::codecForName("UTF-8"));
    QTextCodec::setCodecForCStrings(QTextCodec::codecForTr());
#endif

    Q_INIT_RESOURCE(bitcoin);
    QApplication app(argc, argv);

    // Application identification (must be set before OptionsModel is initialized,
    // as it is used to locate QSettings)
    app.setOrganizationName(strCoinName);
    app.setOrganizationDomain(strCoinName ".su");
    if(map_arg::GetBoolArg("-testnet")) // Separate UI settings for testnet
        app.setApplicationName(strCoinName "-Core-testnet");
    else
        app.setApplicationName(strCoinName "-Core");

    // Now that QSettings are accessible, initialize translations
    QTranslator qtTranslatorBase, qtTranslator, translatorBase, translator;
    initTranslations(qtTranslatorBase, qtTranslator, translatorBase, translator);

    // Command-line options take precedence:
    // map_arg: old core, ARGS: new core
    if(! map_arg::ParseParameters(argc, argv)) {
        QMessageBox::critical(0, strCoinName,
            QObject::tr("Error: map_arg::ParseParameters").arg(QString::fromStdString(map_arg::GetMapArgsString("-datadir"))));
        return 1;
    }
    /* under development
    std::string args_error;
    if(! ARGS.ParseParameters(argc, argv, args_error)) {
        QMessageBox::critical(0, strCoinName,
            QObject::tr("Error: ARGS::ParseParameters %1").arg(args_error.c_str()));
        return 1;
    }
    */

    // User language is set up: pick a data directory
    Intro::pickDataDirectory();

    // Install global event filter that makes sure that long tooltips can be word-wrapped
    app.installEventFilter(new GUIUtil::ToolTipToRichTextFilter(TOOLTIP_WRAP_THRESHOLD, &app));

    // ... then SorachanCoin.conf:
    if (! fs::is_directory(iofs::GetDataDir(false))) {
        QMessageBox::critical(0, strCoinName,
            QObject::tr("Error: Specified data directory \"%1\" does not exist.").arg(QString::fromStdString(map_arg::GetMapArgsString("-datadir"))));
        return 1;
    }
    if(! map_arg::ReadConfigFile()) {
        QMessageBox::critical(0, strCoinName,
            QObject::tr("Error: map_arg::ReadConfigFile()").arg(QString::fromStdString(map_arg::GetMapArgsString("-datadir"))));
        return 1;
    }

    entry::SetupServerArgs();
    /* under developmrnt
    std::string config_error;
    if(! ARGS.ReadConfigFiles(config_error)) {
        QMessageBox::critical(0, strCoinName,
            QObject::tr("Error: ARGS::ReadConfigFile() %1").arg(config_error.c_str()));
        return 1;
    }
    */

    // ... then GUI settings:
    OptionsModel optionsModel;

    // Subscribe to global signals from core
    CClientUIInterface::get().ThreadSafeMessageBox.connect(ThreadSafeMessageBox);
    CClientUIInterface::get().ThreadSafeMessageOk.connect(ThreadSafeMessageOk);
    CClientUIInterface::get().ThreadSafeMessageAsk.connect(ThreadSafeMessageAsk);
    CClientUIInterface::get().ThreadSafeAskFee.connect(ThreadSafeAskFee);
    CClientUIInterface::get().ThreadSafeHandleURI.connect(ThreadSafeHandleURI);
    CClientUIInterface::get().InitMessage.connect(InitMessage);
    CClientUIInterface::get().QueueShutdown.connect(QueueShutdown);
    CClientUIInterface::get().Translate.connect(Translate);

    // Show help message immediately after parsing command-line options (for "-lang") and setting locale,
    // but before showing splash screen.
    if (map_arg::GetMapArgsCount("-?") || map_arg::GetMapArgsCount("--help")) {
        GUIUtil::HelpMessageBox help;
        help.showOrPrint();
        return 1;
    }

    QSplashScreen splash(QPixmap(":/images/splash"), 0);
    if (map_arg::GetBoolArg("-splash", true) && !map_arg::GetBoolArg("-min")) {
        splash.show();
        splash.setAutoFillBackground(true);
        splashref = &splash;
    }

    app.processEvents();
    app.setQuitOnLastWindowClosed(false);

# ifdef WIN32
    if(map_arg::GetBoolArg("-miniw")) {
        bool restart = false;
        try {
            do {
                if(entry::AppInit2(restart)) {
                    if (splashref)
                        splash.finish(nullptr);

                    // Place this here as guiref has to be defined if we don't want to lose URIs
                    qti_server::ipcInit(argc, argv);

                    predsystem::CreateMiniwindow(&restart);
                    guiref = 0;

                    shutdownWindow sdw(&app);

                    // Shutdown the core and its threads, but don't exit Bitcoin-Qt here
                    boot::Shutdown(nullptr);
                } else {
                    return 1;
                }
                // under development
                restart = false;
            } while(restart);
        } catch (std::exception &e) {
            handleRunawayException(&e);
        } catch (...) {
            handleRunawayException(nullptr);
        }
        return 0;
    }
# endif

    try {
        // Regenerate startup link, to fix links to old versions
        if (GUIUtil::GetStartOnSystemStartup()) {
            GUIUtil::SetStartOnSystemStartup(true);
        }

        BitcoinGUI window;
        guiref = &window;
        if(entry::AppInit2()) {
            do {
                // Put this in a block, so that the Model objects are cleaned up before
                // calling Shutdown().
                if (splashref)
                    splash.finish(&window);

                // Smartfee thread
                QSettings settings;
                bool fSmartFee = settings.value("smartFee", QVariant(false)).toBool();
                //print_num("fSmartFee", fSmartFee ? 1: 0);
                if(fSmartFee)
                    OptionsModel::beginSmartFee();

                ClientModel clientModel(&optionsModel);
                WalletModel walletModel(entry::pwalletMain, &optionsModel);
                CheckpointsModel checkpointsModel(&optionsModel);
                window.setClientModel(&clientModel); // clientmodel: bitcoingui => rpcconsole, syncWidget
                window.setWalletModel(&walletModel);
                window.setCheckpointsModel(&checkpointsModel);

                // If -min option passed, start window minimized.
                if(map_arg::GetBoolArg("-min"))
                    window.showMinimized();
                else
                    window.show();

                // Place this here as guiref has to be defined if we don't want to lose URIs
                qti_server::ipcInit(argc, argv);

                app.exec();

                window.hide();
                window.setClientModel(0);
                window.setWalletModel(0);
                guiref = 0;
            } while(false);

            shutdownWindow sdw(&app);

            // Shutdown the core and its threads, but don't exit Bitcoin-Qt here
            boot::Shutdown(nullptr);
        } else {
            return 1;
        }
    } catch (std::exception &e) {
        handleRunawayException(&e);
    } catch (...) {
        handleRunawayException(nullptr);
    }
    return 0;
}
#endif // !BITCOIN_QT_TEST && !CLI_MODE_ENABLE
