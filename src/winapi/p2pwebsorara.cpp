// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <winapi/p2pwebsorara.h>
#include <QThread>
#include <wallet.h>
#include <walletdb.h>
#include <init.h>
#include <vector>
#include <prevector/prevector.h>
#include <map>
#include <QTime>
#include <libstr/cmstring.h>
#include <allocator/qtsecure.h>
#include <guiutil.h>

#include <sorara/drivemodel.h>
#include <sorara/soraradb.h>
#include <sorara/soraramodel.h>
#include <sorara/soraranet.h>

#include "ui_p2pwebsorara.h"

/////////////////////////////////////////////////////////////////////////
// SORARA project.
// p2p web and p2p message on the Blockchain
//
// encode: UTF-8 (because no limit size.)
// data: independent DB
// blockchain: sha256 hash (32bytes) or qhash to sha256 (32bytes)
/////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////
// thread
/////////////////////////////////////////////////////////////////////////

class SoraraTherad : public QObject {
    Q_OBJECT
public:
    SoraraTherad() {}

public slots:
    void start() {}
    void reload();
    void messagesend();

signals:
    void webRequest(const QString &url, bool html);
    void messageRequest(const QString &message, bool html);
};

#include "p2pwebsorara.moc"

/////////////////////////////////////////////////////////////////////////
// Qt Widget
/////////////////////////////////////////////////////////////////////////

SoraraWidget::SoraraWidget(QWidget *parent) : QWidget(parent), ui(new (std::nothrow) Ui::SoraraWidget) {
    if(! ui)
        throw qt_error("SoraraWidget Failed to allocate memory.", this);
    ui->setupUi(this);

    // Sorara
    ui->contentsTextEdit->installEventFilter(this);
    ui->messagesTextEdit->installEventFilter(this);

    startSorara();
}

SoraraWidget::~SoraraWidget() {
    emit stopSorara();
    delete ui;
}

void SoraraWidget::startSorara() {
    QThread *thread = new (std::nothrow) QThread;
    SoraraTherad *executor = new (std::nothrow) SoraraTherad;
    if(!thread || !executor)
        throw qt_error("SoraraWidget Failed to allocate memory.", this);
    executor->moveToThread(thread);

    connect(thread, SIGNAL(started()), executor, SLOT(start()));

    connect(executor, SIGNAL(webRequest(QString,bool)), this, SLOT(web(QString,bool)));
    connect(executor, SIGNAL(messageRequest(QString,bool)), this, SLOT(message(QString,bool)));
    connect(ui->reloadPushButton, SIGNAL(clicked()), executor, SLOT(reload()));
    connect(ui->messagesendPushButton, SIGNAL(clicked()), executor, SLOT(messagesend()));

    connect(this, SIGNAL(stopSorara()), executor, SLOT(deleteLater()));
    connect(this, SIGNAL(stopSorara()), thread, SLOT(quit()));
    connect(thread, SIGNAL(finished()), thread, SLOT(deleteLater()));
    thread->start();
}

// slot (callback SoraraThread, p2pweb reloadPushButton)
void SoraraTherad::reload() {
    emit webRequest(QString("<p>Hello world p2p web!</p>"), true);
}

// slot (callback SoraraThread, p2pmessage messagesendPushButton)
void SoraraTherad::messagesend() {
    emit messageRequest(QString("<p>Hello world p2p message!</p>"), true);
}

// slot (callback SoraraTherad, webRequest)
void SoraraWidget::web(const QString &contents, bool html) {
    ui->contentsTextEdit->document()->setDefaultStyleSheet(
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
    if(html) out += contents;
    else out += GUIUtil::HtmlEscape(contents, true);
    out += "</td></tr></table>";
    ui->contentsTextEdit->append(out);
}

// slot (callback SoraraTherad, messageRequest)
void SoraraWidget::message(const QString &message, bool html) {
    ui->messagesTextEdit->document()->setDefaultStyleSheet(
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
    ui->messagesTextEdit->append(out);
}

// slot (callback bitcoingui)
void SoraraWidget::exportClicked() {}

/////////////////////////////////////////////////////////////////////////
// Library
/////////////////////////////////////////////////////////////////////////

namespace {
typedef struct _ctrl_info {
    HWND hSendButton;
    HWND hClearButton;
    HWND hMainEdit;
    HWND hMessageEdit;
} ctrl_info;
typedef struct _win_userdata {
    ctrl_info *ci;
    HICON hIcon;
    bool restart;
} win_userdata;
} // namespace

/////////////////////////////////////////////////////////////////////////
// SORARA API
/////////////////////////////////////////////////////////////////////////

class CSoraraPool {
public:

private:
    std::map<uint256, CMString> message;
};

/////////////////////////////////////////////////////////////////////////
// Bitcoin Stream
/////////////////////////////////////////////////////////////////////////

class CDataChain {
public:

private:
};

/////////////////////////////////////////////////////////////////////////
// CALLBACK
/////////////////////////////////////////////////////////////////////////

static LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp)
{
    win_userdata *pwu = reinterpret_cast<win_userdata *>(::GetWindowLongPtrW(hWnd, GWLP_USERDATA));
    //std::wstring str;

    switch(msg)
    {
    case WM_CLOSE:
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    default:
        break;
    }

    return ::DefWindowProcW(hWnd, msg, wp, lp);
}

bool predsystem::CreateSorara() noexcept
{
    auto unregister_wc = []{::UnregisterClassW(IDS_SORARA_WINDOWCLASSNAME, ::GetModuleHandleW(nullptr));};
    auto err = []{::UnregisterClassW(IDS_SORARA_WINDOWCLASSNAME, ::GetModuleHandleW(nullptr)); return false;};

    class icon_manage {
    public:
        icon_manage() {
            wchar_t soraPath[MAX_PATH];
            ::GetModuleFileNameW(nullptr, soraPath, MAX_PATH);
            hIcon = ::ExtractIconW(::GetModuleHandleW(nullptr), soraPath, 0);
        }
        ~icon_manage() {
            if(hIcon)
                ::DestroyIcon(hIcon);
        }
        HICON get() const {return hIcon;}
    private:
        HICON hIcon;
    };

    icon_manage icom;
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WindowProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hIcon = wc.hIconSm = icom.get();
    wc.lpszMenuName = nullptr;
    wc.lpszClassName = IDS_SORARA_WINDOWCLASSNAME;
    if(! ::RegisterClassEx(&wc)) {
        logging::LogPrintf(CMString(IDS_ERROR_CLASSREGISTER)+L"\n");
        return err();
    }

    const int desktopWidth = ::GetSystemMetrics(SM_CXSCREEN);
    const int desktopHeight = ::GetSystemMetrics(SM_CYSCREEN);
    HWND hWnd = ::CreateWindowExW(
            0,
            IDS_SORARA_WINDOWCLASSNAME,
            IDS_SORARA_TITLE,
            WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
            (desktopWidth - SORARA_WIDTH) / 2,
            (desktopHeight - SORARA_HEIGHT) / 2,
            SORARA_WIDTH,
            SORARA_HEIGHT,
            nullptr,
            nullptr,
            ::GetModuleHandleW(nullptr),
            nullptr
        );
    if(!hWnd) {
        logging::LogPrintf(CMString(IDS_ERROR_CREATEWINDOW)+L"\n");
        return err();
    }

    ctrl_info ci;
    {
        HWND hMainEdit = ::CreateWindowExA(
            0,
            "EDIT",
            IDS_EDIT_MAIN,
            WS_CHILD | WS_VISIBLE | WS_BORDER,
            10,
            80,
            320,
            30,
            hWnd,
            (HMENU)IDC_EDIT_MAIN,
            ::GetModuleHandleW(nullptr),
            nullptr
        );
        if(! hMainEdit) {
            logging::LogPrintf(CMString(IDS_ERROR_CREATEWINDOW)+L"\n");
            return err();
        }
        ::ShowWindow(hMainEdit, SW_SHOW);
        ci.hMainEdit = hMainEdit;
    }

    {
        HWND hMessageEdit = ::CreateWindowExA(
            0,
            "EDIT",
            IDS_EDIT_MESSAGE,
            WS_CHILD | WS_VISIBLE | WS_BORDER,
            10,
            80,
            320,
            30,
            hWnd,
            (HMENU)IDC_EDIT_MESSAGE,
            ::GetModuleHandleW(nullptr),
            nullptr
        );
        if(! hMessageEdit) {
            logging::LogPrintf(CMString(IDS_ERROR_CREATEWINDOW)+L"\n");
            return err();
        }
        ::ShowWindow(hMessageEdit, SW_SHOW);
        ci.hMessageEdit = hMessageEdit;
    }

    MSG msg;
    WINBOOL ret;
    while ((ret=::GetMessageW(&msg, nullptr, 0, 0))!=0)
    {
        if(ret==-1) break;
        ::TranslateMessage(&msg);
        ::DispatchMessageW(&msg);
    }

    return true;
}
