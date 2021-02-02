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
#include <libstr/cmstring.h>
#include <allocator/qtsecure.h>

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
// Qt
/////////////////////////////////////////////////////////////////////////

SoraraWidget::SoraraWidget(QWidget *parent) : QWidget(parent), ui(new (std::nothrow) Ui::SoraraWidget) {
    if(! ui)
        throw qt_error("SoraraWidget Failed to allocate memory.", this);
    ui->setupUi(this);

    // Sorara
    ui->contentsTextEdit->installEventFilter(this);
    ui->messagesTextEdit->installEventFilter(this);
    connect(ui->reloadPushButton, SIGNAL(clicked()), this, SLOT(reload()));
    connect(ui->messagesendPushButton, SIGNAL(clicked()), this, SLOT(messagesend()));

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

    // Notify executor when thread started (in executor thread)
    connect(thread, SIGNAL(started()), executor, SLOT(start()));
    // executor object must go to this object
    connect(executor, SIGNAL(webRequest(QString,bool)), this, SLOT(web(QString,bool)));
    connect(executor, SIGNAL(messageRequest(QString,bool)), this, SLOT(message(QString,bool)));
    // connect button
    connect(ui->reloadPushButton, SIGNAL(clicked()), this, SLOT(reload()));
    connect(ui->messagesendPushButton, SIGNAL(clicked()), this, SLOT(messagesend()));
    // finish thread connect
    connect(this, SIGNAL(stopSorara()), executor, SLOT(deleteLater()));
    connect(this, SIGNAL(stopSorara()), thread, SLOT(quit()));
    connect(thread, SIGNAL(finished()), thread, SLOT(deleteLater()));
    thread->start();
}

// slot (callback SoraraWidget, p2pweb reloadPushButton clicked())
void SoraraTherad::reload() {

}

// slot (callback SoraraWidget, p2pmessage messagesendPushButton clicked())
void SoraraTherad::messagesend() {

}

// slot (callback SoraraTherad, webRequest)
void SoraraWidget::web(const QString &contents, bool html) {

}

// slot (callback SoraraTherad, messageRequest)
void SoraraWidget::message(const QString &message, bool html) {

}

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
