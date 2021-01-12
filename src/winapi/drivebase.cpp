// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef QT_GUI
#include <winapi/drivebase.h>
#include <file_operate/fs.h>

sync drive_handle::cs;

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

bool drive_handle::createdir(LPCWSTR path) const {
#ifdef WIN32
    if(! ::CreateDirectoryW(path, nullptr)) {
        DWORD error = ::GetLastError();
        // debugcs::instance() << L"[CREATE DIR]" << error;
        return (error == ERROR_ALREADY_EXISTS) ? true: false;
    } else {
        return true;
    }
#else
    std::string spath;
    if(! drive_util::wchartochar(path, spath))
        return false;
    fs::path fpath = spath.c_str();
    return fsbridge::dir_create(fpath, true);
#endif
}

bool drive_handle::openread(bool _lock /*= false*/) {
#ifdef WIN32
    close();
    std::wostringstream stream;
    stream << L"\\\\.\\PHYSICALDRIVE" << nDrive;
    DWORD lock_flag = _lock ? FILE_ATTRIBUTE_NORMAL: FILE_FLAG_NO_BUFFERING;
    lock = _lock;
    hDrive = ::CreateFileW( stream.str().c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, lock_flag, nullptr );
    return hDrive != INVALID_HANDLE_VALUE;
#else
    // under development
    return false;
#endif
}

bool drive_handle::openwrite(bool _lock /*= false*/) {
#ifdef WIN32
    close();
    std::wostringstream stream;
    stream << L"\\\\.\\PHYSICALDRIVE" << nDrive;
    DWORD lock_flag = _lock ? FILE_ATTRIBUTE_NORMAL: FILE_FLAG_NO_BUFFERING;
    lock = _lock;
    hDrive = ::CreateFileW( stream.str().c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, lock_flag, nullptr );
    // debugcs::instance() << L"[openwrite GetLastError]" << ::GetLastError();
    return hDrive != INVALID_HANDLE_VALUE;
#else
    // under development
    return false;
#endif
}

bool drive_handle::openwritefile(char letter, LPCWSTR path, bool _lock /*= false*/) {
#ifdef WIN32
    close();
    std::wostringstream stream;
    if(path) {
        stream << path;
        // if(! createdir(stream.str().c_str())) {return false;}
    } else {
        if(letter == '\0') {return false;}
        stream << letter << L":\\" << TEMPFILE_DIR;
        if(! createdir(stream.str().c_str())) {return false;}
        tempfiledir = stream.str();
        stream << L"\\" << TEMPFILE_NAME;
        tempfile = true;
    }
    DWORD lock_flag = _lock ? FILE_ATTRIBUTE_NORMAL: FILE_FLAG_WRITE_THROUGH; // Note: FILE_FLAG_NO_BUFFERING(sector) => FILE_FLAG_WRITE_THROUGH(file)
    lock = _lock;
    hDrive = ::CreateFileW( stream.str().c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, lock_flag, nullptr );
    return hDrive != INVALID_HANDLE_VALUE;
#else
    // under development
    return false;
#endif
}

void drive_handle::close() {
#ifdef WIN32
    if(hDrive) {
        cs.enter();
        if(tempfile) {::FlushFileBuffers(hDrive);}
        ::CloseHandle(hDrive);
        hDrive = nullptr;
        cs.leave();
    }
    if(tempfile) {
        // ::Sleep(50); // file mode benchmark only
        ::SetCurrentDirectoryW(tempfiledir.c_str());
        ::DeleteFileW(TEMPFILE_NAME);
        std::vector<wchar_t> letter;
        letter.resize(4, 0x00);
        ::RtlCopyMemory(&letter.at(0), &tempfiledir.at(0), 3 * sizeof(wchar_t));
        ::SetCurrentDirectoryW((LPCWSTR)&letter.at(0));
        ::RemoveDirectoryW(TEMPFILE_DIR); // Note: Safe Function (empty directory ONLY)
    }
#else
    // under development
    return;
#endif
}

#endif // QT_GUI
