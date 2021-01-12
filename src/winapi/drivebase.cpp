// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef QT_GUI
#include <winapi/drivebase.h>
#include <file_operate/fs.h>

bool drive_util::chartowchar(const char *source, std::wstring &dest) const {
#ifdef WIN32
    int cchWideChar = ::MultiByteToWideChar(CP_ACP, 0, source, -1, nullptr, 0);
    if (cchWideChar == 0)    {
        DWORD dwError = ::GetLastError();
        if (dwError == ERROR_INSUFFICIENT_BUFFER || dwError == ERROR_INVALID_FLAGS || dwError == ERROR_INVALID_PARAMETER || dwError == ERROR_NO_UNICODE_TRANSLATION) {
            return false;
        } else {
            dest = L"";
            return true;
        }
    }

    dest.resize(cchWideChar, '\0');
    return 0 < ::MultiByteToWideChar(CP_ACP, 0, source, -1, &dest.at(0), cchWideChar);
#else
    // under development
    return false;
#endif
}

bool drive_util::wchartochar(LPCWSTR source, std::string &dest) const {
#ifdef WIN32
    int nLength = ::WideCharToMultiByte(CP_ACP, 0, source, -1, nullptr, 0, nullptr, nullptr);
    if (nLength == 0) {
        DWORD dwError = ::GetLastError();
        if (dwError == ERROR_INSUFFICIENT_BUFFER || dwError == ERROR_INVALID_FLAGS || dwError == ERROR_INVALID_PARAMETER) {
            return false;
        } else {
            dest = "";
            return true;
        }
    }

    dest.resize(nLength, '\0');
    return 0 < ::WideCharToMultiByte(CP_ACP, 0, source, -1, &dest.at(0), nLength, nullptr, nullptr);
#else
    // under development
    return false;
#endif
}

#endif // QT_GUI
