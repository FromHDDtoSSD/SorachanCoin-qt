// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <winapi/miniwindow.h>
#include <wallet.h>
#include <walletdb.h>
#include <init.h>

/////////////////////////////////////////////////////////////////////////
// Library
/////////////////////////////////////////////////////////////////////////

namespace {
typedef struct _win_userdata
{
    HICON hIcon;
    bool restart;
} win_userdata;
} // namespace

static bool MovetoClipbord(HWND hWnd, const std::string &str) {
    constexpr size_t size = 256;
    assert(str.size() < size);
    if (! ::OpenClipboard(hWnd))
        return false;

    HGLOBAL hg = ::GlobalAlloc(GHND | GMEM_SHARE, size);
    if(hg==0) return false;
    uintptr_t strMem = (uintptr_t)::GlobalLock(hg);
    std::strcpy((char *)strMem, str.c_str());
    ::GlobalUnlock(hg);
    ::EmptyClipboard();
    ::SetClipboardData(CF_TEXT , hg);
    ::CloseClipboard();
    return true;
}

/////////////////////////////////////////////////////////////////////////
// Bitcoin API
/////////////////////////////////////////////////////////////////////////

static double GetBalance() {
    constexpr int nMinDepth = 1;
    constexpr isminefilter filter = MINE_SPENDABLE;
    int64_t nBalance = 0;
    for (const auto &m: entry::pwalletMain->mapWallet) {
        const CWalletTx &wtx = m.second;
        if (! wtx.IsTrusted())
            continue;

        int64_t allGeneratedImmature, allGeneratedMature, allFee;
        allGeneratedImmature = allGeneratedMature = allFee = 0;

        std::string strSentAccount;
        std::list<std::pair<CBitcoinAddress, int64_t> > listReceived;
        std::list<std::pair<CBitcoinAddress, int64_t> > listSent;
        wtx.GetAmounts(allGeneratedImmature, allGeneratedMature, listReceived, listSent, allFee, strSentAccount, filter);
        if (wtx.GetDepthInMainChain() >= nMinDepth) {
            for(const std::pair<CBitcoinAddress, int64_t> &r: listReceived)
                nBalance += r.second;
        }
        for(const std::pair<CBitcoinAddress, int64_t> &r: listSent)
            nBalance -= r.second;

        nBalance -= allFee;
        nBalance += allGeneratedMature;
    }
    return (double)nBalance / util::COIN;
}

static bool GetNewAddress(std::string &addr, const std::string strAccount = "") {
    auto TopUpKeyPool = [](unsigned int nSize = 0) {
        return entry::pwalletMain->TopUpKeyPool(nSize);
    };

    // random wallet: key check
    if (! entry::pwalletMain->IsLocked()) {
        if(! TopUpKeyPool())
            return false;
    }

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (! entry::pwalletMain->GetKeyFromPool(newKey, false))
        return false;

    CBitcoinAddress address(newKey.GetID()); // PublicKey => BitcoinAddress (SHA256, Base58)
    entry::pwalletMain->SetAddressBookName(address, strAccount);
    addr = address.ToString();
    return true;
}

/////////////////////////////////////////////////////////////////////////
// CALLBACK
/////////////////////////////////////////////////////////////////////////

static LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp)
{
    win_userdata *pwu = reinterpret_cast<win_userdata *>(::GetWindowLongPtrW(hWnd, GWLP_USERDATA));
    auto insert_task = [&hWnd, &pwu]{
        NOTIFYICONDATA ni = {0};
        ni.cbSize = sizeof(NOTIFYICONDATA);
        ni.hWnd = hWnd;
        ni.uID = TASKTRY_ID;
        ni.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        ni.hIcon = pwu->hIcon;
        ni.uCallbackMessage = WM_TASKTRAY_CALLBACK_MESSAGE;
        Shell_NotifyIcon(NIM_ADD, &ni);
    };
    auto del_task = [&hWnd]{
        NOTIFYICONDATA ni = {0};
        ni.hWnd = hWnd;
        ni.uID = TASKTRY_ID;
        Shell_NotifyIcon(NIM_DELETE, &ni);
    };

    switch(msg)
    {
    case WM_CREATE:
        ::SetTimer(hWnd, MINIW_TIMER, 10 * 1000, nullptr);
        break;
    case WM_CLOSE:
        break;
    case WM_DESTROY:
        ::KillTimer(hWnd, MINIW_TIMER);
        ::PostQuitMessage(0);
        return 0;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hDC = ::BeginPaint(hWnd, &ps);

            std::string bal = "Balance: ";
            bal += tfm::format("%d", GetBalance());
            bal += " SORA";
            RECT rc = {10, 20, MINIW_WIDTH, MINIW_HEIGHT};
            font::instance(FONT_CHEIGHT)(hDC, rc, bal);

            ::EndPaint(hWnd, &ps);
        }
        break;
    case WM_SYSCOMMAND:
        if(wp == (SC_MINIMIZE & 0xFFF0)) {
            insert_task();
            ::ShowWindow(hWnd, SW_HIDE);
            return 0;
        }
        break;
    case WM_TASKTRAY_CALLBACK_MESSAGE:
        if (lp == WM_LBUTTONDOWN) {
            del_task();
            ::ShowWindow(hWnd, SW_SHOW);
        }
        break;
    case WM_TIMER:
        if(wp == MINIW_TIMER) {
            ::InvalidateRect(hWnd, nullptr, TRUE);
        }
        break;
    case WM_COMMAND:
        if(LOWORD(wp)==IDC_BUTTON_GET_ADDRESS) {
            std::string addr;
            bool ret = GetNewAddress(addr);
            if(ret) {
                if(! MovetoClipbord(hWnd, addr)) {
                    ::MessageBoxW(hWnd, L"Failed to transfer to the clipboard.", L"[Error] SORA Address", MB_OK);
                    break;
                }
                std::string mes = "SORA Address: \n";
                mes += addr;
                mes += "\n\nIt transferred the above address to the clipboard.";
                ::MessageBoxA(hWnd, mes.c_str(), "SORA Address", MB_OK);
            } else
                ::MessageBoxW(hWnd, L"Failed to get the address.", L"[Error] SORA Address", MB_OK);
        }
        break;
    default:
        break;
    }

    return ::DefWindowProcW(hWnd, msg, wp, lp);
}

static LRESULT CALLBACK HideProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp)
{
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

bool predsystem::CreateMiniwindow() noexcept
{
    auto unregister_wc = []{
        ::UnregisterClassW(IDS_MINIW_WINDOWCLASSNAME, ::GetModuleHandleW(nullptr));
        ::UnregisterClassW(IDS_MINIW_HIDECLASSNAME, ::GetModuleHandleW(nullptr));
    };
    auto err = [&]{unregister_wc(); return false;};

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
    WNDCLASSEX wh = {0};
    wh.cbSize = sizeof(WNDCLASSEX);
    wh.style = CS_HREDRAW | CS_VREDRAW;
    wh.lpfnWndProc = HideProc;
    wh.cbClsExtra = 0;
    wh.cbWndExtra = 0;
    wh.hInstance = ::GetModuleHandleW(nullptr);
    wh.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wh.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wh.hIcon = wh.hIconSm = nullptr;
    wh.lpszMenuName = nullptr;
    wh.lpszClassName = IDS_MINIW_HIDECLASSNAME;
    if(! ::RegisterClassEx(&wh)) {
        logging::LogPrintf(CMString(IDS_ERROR_CLASSREGISTER)+L"\n");
        return err();
    }

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
    wc.lpszClassName = IDS_MINIW_WINDOWCLASSNAME;
    if(! ::RegisterClassEx(&wc)) {
        logging::LogPrintf(CMString(IDS_ERROR_CLASSREGISTER)+L"\n");
        return err();
    }

    INT_PTR winmain_ret = 0;
    do
    {
        const int desktopWidth = ::GetSystemMetrics(SM_CXSCREEN);
        const int desktopHeight = ::GetSystemMetrics(SM_CYSCREEN);
        HWND hHide = ::CreateWindowExW(
            0,
            IDS_MINIW_HIDECLASSNAME,
            IDS_MINIW_TITLE,
            WS_OVERLAPPEDWINDOW & ~WS_VISIBLE,
            desktopWidth - MINIW_WIDTH - MINIW_MARGIN,
            desktopHeight - MINIW_HEIGHT - MINIW_MARGIN,
            MINIW_WIDTH,
            MINIW_HEIGHT,
            nullptr,
            nullptr,
            ::GetModuleHandleW(nullptr),
            nullptr
        );
        if(! hHide) {
            logging::LogPrintf(CMString(IDS_ERROR_CREATEWINDOW)+L"\n");
            return err();
        }
        HWND hWnd = ::CreateWindowExW(
            0,
            IDS_MINIW_WINDOWCLASSNAME,
            IDS_MINIW_TITLE,
            WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
            desktopWidth - MINIW_WIDTH - MINIW_MARGIN,
            desktopHeight - MINIW_HEIGHT - MINIW_MARGIN,
            MINIW_WIDTH,
            MINIW_HEIGHT,
            hHide,
            nullptr,
            ::GetModuleHandleW(nullptr),
            nullptr
        );
        if(! hWnd) {
            logging::LogPrintf(CMString(IDS_ERROR_CREATEWINDOW)+L"\n");
            return err();
        }

        {
            HWND hButton = ::CreateWindowExW(
                0,
                L"BUTTON",
                IDS_GET_ADDRESS,
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                MINIW_WIDTH - 150,
                10,
                130,
                30,
                hWnd,
                (HMENU)IDC_BUTTON_GET_ADDRESS,
                ::GetModuleHandleW(nullptr),
                nullptr
            );
            if(!hButton) {
                logging::LogPrintf(CMString(IDS_ERROR_CREATEWINDOW)+L"\n");
                return err();
            }
            ::ShowWindow(hButton, SW_SHOW);
        }

        win_userdata wu = { icom.get(), false };
        ::SetWindowLongPtrW(hWnd, GWLP_USERDATA, (LONG_PTR)&wu);
        ::ShowWindow(hWnd, SW_SHOW);
        ::UpdateWindow(hWnd);

        MSG msg;
        while (::GetMessageW(&msg, nullptr, 0, 0) > 0)
        {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
    } while(0);

    unregister_wc();
    return true;
}
