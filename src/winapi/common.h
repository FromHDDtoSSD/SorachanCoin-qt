// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if !defined(CLI_MODE_ENABLE) && defined(QT_GUI) && defined(WIN32)

#ifndef SORACHANCOIN_COMMON_H
#define SORACHANCOIN_COMMON_H
#ifdef WIN32

// winguimain.cpp and miniwindow.cpp WindowsAPI

#include <string>
#include <sstream>
#include <time.h>
#include <shlobj.h>
#include <util/logging.h>

#define IDS_ERROR_CREATEWINDOW               "To Process failed in CreateWindowEx.\n"
#define IDS_ERROR_CLASSREGISTER              "To Process failed in RegisterClassEx.\n"
#define IDS_ERROR_FONT                       "To Create fonts were failure.\n"
#define TRANS_STRING(str)    (_(str)).c_str()

class font
{
private:
    font()=delete;
    font(const font &)=delete;
    font &operator=(const font &)=delete;
    font(font &&)=delete;
    font &operator=(font &&)=delete;

    HFONT hFont;
    font(int cHeight) {
        hFont = ::CreateFontW(cHeight, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_TT_ONLY_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, VARIABLE_PITCH | FF_DONTCARE, nullptr);
        if(! hFont)
            throw std::runtime_error(IDS_ERROR_FONT);
    }
    ~font() {
        if(hFont) {
            ::DeleteObject(hFont);
            hFont = nullptr;
        }
    }
public:
    static const font &instance(int cHeight) {
        static font fobj(cHeight);
        return fobj;
    }
    const font &operator()(HDC hDC, RECT rc, const std::string &obj) const {
        std::ostringstream stream;
        stream << obj;
        HFONT prev = (HFONT)::SelectObject(hDC, hFont);
        ::DrawTextA(hDC, stream.str().c_str(), -1, &rc, DT_WORDBREAK);
        ::SelectObject(hDC, prev);
        return *this;
    }
    template <typename T> const font &operator()(HDC hDC, RECT rc, const T &obj) const {
        std::wostringstream stream;
        stream << obj;
        HFONT prev = (HFONT)::SelectObject(hDC, hFont);
        ::DrawTextW(hDC, stream.str().c_str(), -1, &rc, DT_WORDBREAK);
        ::SelectObject(hDC, prev);
        return *this;
    }
};

namespace predsystem {
    enum ret_code {
        success = 0,
        error_createwindow,
        error_initddk,
        error_createobject,
        error_outofmemory,
    };

    struct result {
        intptr_t window_ret;
        ret_code ret;
        std::string e;
        std::vector<uint8_t> vch;
        result() {
            window_ret = 0;
            ret = success;
        }
    };

    extern result CreateBenchmark();
    extern bool CreateMiniwindow(bool *restart);
    extern bool CreateSorara();
} // namespace predsystem

#endif
#endif // SORACHANCOIN_COMMON_H

#endif // ifndef CLI_MODE_ENABLE
