// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <winapi/miniwindow.h>

/////////////////////////////////////////////////////////////////////////
// CALLBACK
/////////////////////////////////////////////////////////////////////////

static LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch(msg)
    {
    case WM_CLOSE:
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hDC = ::BeginPaint(hWnd, &ps);

            ::EndPaint(hWnd, &ps);
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
