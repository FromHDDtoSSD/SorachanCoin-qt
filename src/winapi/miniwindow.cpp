// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CLI_MODE_ENABLE

#include <windows.h>
#include <winapi/miniwindow.h>
#include <wallet.h>
#include <walletdb.h>
#include <init.h>
#include <util/thread.h>
#include <allocator/allocators.h>
#include <rpc/bitcoinrpc.h>
#include <cleanse/cleanse.h>

/////////////////////////////////////////////////////////////////////////
// Library
/////////////////////////////////////////////////////////////////////////

namespace {
typedef struct _ctrl_info {
    HWND hDepositButton;
    HWND hWalletButton;
    HWND hPassEdit;
} ctrl_info;
typedef struct _win_userdata
{
    ctrl_info *ci;
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
        std::list<std::pair<CBitcoinAddress, int64_t>> listReceived;
        std::list<std::pair<CBitcoinAddress, int64_t>> listSent;
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

static void ThreadTopUpKeyPool(void *parg) {
    (void)parg;
    // Make this thread recognisable as the key-topping-up thread
    bitthread::RenameThread(strCoinName "-key-top");
    entry::pwalletMain->TopUpKeyPool();
}

static bool IsLockedWallet() {
    return entry::pwalletMain->IsLocked();
}

static bool IsCryptedWallet() {
    return entry::pwalletMain->IsCrypted();
}

static bool UnlockWalletStake(const SecureString &strWalletPass) {
    if(! IsCryptedWallet())
        return false;
    if(! IsLockedWallet()) {
        CWallet::fWalletUnlockMintOnly = true;
        return true;
    }

    if (strWalletPass.length() > 0) {
        if (! entry::pwalletMain->Unlock(strWalletPass))
            return false;
    } else
        return false;

    // [DEBUG] ::fprintf_s(stdout, "Unlock ThreadTopUpKeyPool\n");
    if(! bitthread::NewThread(ThreadTopUpKeyPool, nullptr))
        return false;

    CWallet::fWalletUnlockMintOnly = true;
    return true;
}

static bool LockWallet() {
    if(! IsCryptedWallet())
        return false;
    if(IsLockedWallet())
        return true;

    // Note: auto wallet lock in RPC thread, to disabled
    {
        LOCK(CRPCTable::cs_nWalletUnlockTime);
        entry::pwalletMain->Lock();
        CRPCTable::nWalletUnlockTime = 0;
    }
    CWallet::fWalletUnlockMintOnly = false;
    return true;
}

static bool EncryptWallet(const SecureString &strWalletPass) {
    if (IsCryptedWallet())
        return true;
    if (strWalletPass.length() < 1)
        return false;

    return entry::pwalletMain->EncryptWallet(strWalletPass);
}

/////////////////////////////////////////////////////////////////////////
// CALLBACK
/////////////////////////////////////////////////////////////////////////

static LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp)
{
    const RECT rc = {10, 20, MINIW_WIDTH, MINIW_HEIGHT};
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
            bal += tfm::format("%.2f", GetBalance());
            bal += " SORA";
            font::instance(FONT_CHEIGHT)(hDC, rc, bal);

            ::EndPaint(hWnd, &ps);
        }
        {
            if(!IsCryptedWallet())
                ::SetWindowTextA(pwu->ci->hWalletButton, IDM_TO_ENCRYPT);
            else if (IsLockedWallet())
                ::SetWindowTextA(pwu->ci->hWalletButton, IDM_TO_UNLOCK);
            else {
                ::SetWindowTextA(pwu->ci->hWalletButton, IDM_TO_STAKING);
            }
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
        if(wp==MINIW_TIMER) {
            ::InvalidateRect(hWnd, &rc, TRUE);
        }
        break;
    case WM_COMMAND:
        if(LOWORD(wp)==IDC_BUTTON_GET_ADDRESS) {
            std::string addr;
            bool ret = GetNewAddress(addr);
            if(ret) {
                if(! MovetoClipbord(hWnd, addr)) {
                    ::MessageBoxA(hWnd, TRANS_STRING("Failed to transfer to the clipboard."), TRANS_STRING("[Error] SORA Address"), MB_OK);
                    break;
                }
                std::string mes = _("SORA Address: \n");
                mes += addr;
                mes += _("\n\nIt transferred the above address to the clipboard.");
                ::MessageBoxA(hWnd, mes.c_str(), TRANS_STRING("SORA Address"), MB_OK);
            } else
                ::MessageBoxA(hWnd, TRANS_STRING("Failed to get the address."), TRANS_STRING("[Error] SORA Address"), MB_OK);
        } else if (LOWORD(wp)==IDC_BUTTON_WALLET_STATUS) {
            auto get_edit = [&pwu](SecureString &strWalletPass) {
                constexpr size_t max_size = 100;
                char pass[max_size]; // stack passphrase
                ::GetWindowTextA(pwu->ci->hPassEdit, pass, max_size-1);
                std::string strPass = pass;
                cleanse::OPENSSL_cleanse(pass, max_size); // stack cleanse
                strWalletPass.reserve(max_size);
                strWalletPass(strPass); // strPass cleanse
                // [DEBUG] ::fprintf_s(stdout, strWalletPass.c_str());
            };
            if(! IsCryptedWallet()) {
                SecureString strWalletPass;
                get_edit(strWalletPass);
                if(EncryptWallet(strWalletPass)) {
                    ::MessageBoxA(hWnd, TRANS_STRING("The encryption in wallet was successful."), TRANS_STRING("SorachanCoin"), MB_OK | MB_ICONINFORMATION);
                    //pwu->restart = true;
                    //::PostMessageW(hWnd, WM_CLOSE, 0, 0);
                    ::SetWindowTextA(pwu->ci->hWalletButton, IDM_TO_UNLOCK);
                } else {
                    ::MessageBoxA(hWnd, TRANS_STRING("Failed to encrypt wallet."), TRANS_STRING("[Error] SORA"), MB_OK | MB_ICONWARNING);
                }
                ::EmptyClipboard();
                ::SetWindowTextA(pwu->ci->hPassEdit, "");
            } else if (IsLockedWallet()) {
                SecureString strWalletPass;
                get_edit(strWalletPass);
                if(UnlockWalletStake(strWalletPass)) {
                    ::SetWindowTextA(pwu->ci->hWalletButton, IDM_TO_STAKING);
                } else {
                    ::MessageBoxA(hWnd, TRANS_STRING("Faild to unlock wallet in stake."), TRANS_STRING("[Error] SORA unlock Stake PoS"), MB_OK | MB_ICONWARNING);
                }
                ::EmptyClipboard();
                ::SetWindowTextA(pwu->ci->hPassEdit, "");
            } else {
                if(LockWallet()) {
                    ::SetWindowTextA(pwu->ci->hWalletButton, IDM_TO_UNLOCK);
                } else {
                    ::MessageBoxA(hWnd, TRANS_STRING("Failed to lock wallet."), TRANS_STRING("[ERROR] SORA lock wallet"), MB_OK | MB_ICONWARNING);
                }
            }
            ::InvalidateRect(hWnd, &rc, true);
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

bool predsystem::CreateMiniwindow(bool *restart)
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

    if(restart)
        *restart = false;

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
        logging::LogPrintf(IDS_ERROR_CLASSREGISTER);
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
        logging::LogPrintf(IDS_ERROR_CLASSREGISTER);
        return err();
    }

    //INT_PTR winmain_ret = 0;
    ctrl_info ci;
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
            logging::LogPrintf(IDS_ERROR_CREATEWINDOW);
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
            logging::LogPrintf(IDS_ERROR_CREATEWINDOW);
            return err();
        }

        {
            HWND hButton = ::CreateWindowExA(
                0,
                "BUTTON",
                IDS_BUTTON_GET_ADDRESS,
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
            if(! hButton) {
                logging::LogPrintf(IDS_ERROR_CREATEWINDOW);
                return err();
            }
            ::ShowWindow(hButton, SW_SHOW);
            ci.hDepositButton = hButton;
        }

        {
            const char *label = IsCryptedWallet() ? IDM_TO_UNLOCK: IDM_TO_ENCRYPT;
            HWND hButton = ::CreateWindowExA(
                0,
                "BUTTON",
                label,
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                MINIW_WIDTH - 150,
                50,
                130,
                30,
                hWnd,
                (HMENU)IDC_BUTTON_WALLET_STATUS,
                ::GetModuleHandleW(nullptr),
                nullptr
            );
            if(! hButton) {
                logging::LogPrintf(IDS_ERROR_CREATEWINDOW);
                return err();
            }
            ::ShowWindow(hButton, SW_SHOW);
            ci.hWalletButton = hButton;
        }

        {
            HWND hWallet = ::CreateWindowExA(
                0,
                "EDIT",
                IDS_EDIT_WALLET_STATUS,
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD,
                15,
                75,
                320,
                25,
                hWnd,
                (HMENU)IDC_EDIT_WALLET_STATUS,
                ::GetModuleHandleW(nullptr),
                nullptr
            );
            if(! hWallet) {
                logging::LogPrintf(IDS_ERROR_CREATEWINDOW);
                return err();
            }
            ::ShowWindow(hWallet, SW_SHOW);
            ci.hPassEdit = hWallet;
        }

        win_userdata wu = { &ci, icom.get(), false };
        ::SetWindowLongPtrW(hWnd, GWLP_USERDATA, (LONG_PTR)&wu);
        ::ShowWindow(hWnd, SW_SHOW);
        ::UpdateWindow(hWnd);

        MSG msg;
        WINBOOL ret;
        while ((ret=::GetMessageW(&msg, nullptr, 0, 0))!=0)
        {
            if(ret==-1) break;
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
        if(restart)
            *restart = wu.restart;
    } while(0); // no loop

    unregister_wc();
    return true;
}

#endif // ifndef CLI_MODE_ENABLE
