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

bool drive_cmd::cmddrivename() {
#ifdef WIN32
    std::vector<BYTE> vchData;
    vchData.resize(CMD_BUFFER_SIZE, 0x00);

    STORAGE_PROPERTY_QUERY sPQ;
    sPQ.PropertyId = StorageDeviceProperty;
    sPQ.QueryType  = PropertyStandardQuery;
    sPQ.AdditionalParameters[0] = 0x00;
    DWORD dwRet = 0;
    for(int i=0; i < CMD_SEND_LIMIT; ++i) {
        if(! ::DeviceIoControl(gethandle(), IOCTL_STORAGE_QUERY_PROPERTY, &sPQ, sizeof(STORAGE_PROPERTY_QUERY), &vchData.at(0), (DWORD)vchData.size(), &dwRet, nullptr)) {
            return false;
        }
        if(dwRet == vchData.size()) {
            vchData.resize(vchData.size() + CMD_BUFFER_SIZE, '\0');
        } else {
            break;
        }
        ::Sleep(100);
    }
    if(dwRet == vchData.size()) {return false;} // Error

    STORAGE_DEVICE_DESCRIPTOR *pDesc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR *>(&vchData.at(0));
    if (pDesc->ProductIdOffset) {
        std::vector<char> vchProduct;
        vchProduct.resize(pDesc->ProductRevisionOffset - pDesc->ProductIdOffset + 1, '\0'); // Note: +1 is \0 terminate in string.
        for(size_t i=0; i < vchProduct.size() - 1; ++i) {
            BYTE ch = *((BYTE *)pDesc + pDesc->ProductIdOffset + i);
            *(&vchProduct.at(0) + i) = ch;
        }

        size_t n = 0;
        for(; n < vchProduct.size(); ++n) {
            if(vchProduct.at(n) == ' ' || vchProduct.at(n) == '_') {
                if(! chartowchar(&vchProduct.at(n + 1), drive_name)) {
                    return false;
                }
                vchProduct.at(n) = '\0';
                break;
            }
        }
        if(! chartowchar(&vchProduct.at(0), drive_vendor)) {
            return false;
        }
    } else {
        drive_vendor = DRIVEVENDOR_GET_FAILURE;
        drive_name = DRIVENAME_GET_FAILURE;
    }

    // DEBUG
    //for(size_t i=0; i < pDesc->Size - offsetof(STORAGE_DEVICE_DESCRIPTOR, RawPropertiesLength); ++i)
    //{
    //    debugcs::instance() << (char)((pDesc->RawDeviceProperties[i] == '\0') ? '_': pDesc->RawDeviceProperties[i]);
    //}

    return true;
#else
    // under development
    return false;
#endif
}

bool drive_cmd::cmdgeometry() { // sector_size and total_sectors
#ifdef WIN32
    DISK_GEOMETRY dgm = {0};
    DWORD dwRet;
    if (! ::DeviceIoControl(gethandle(), IOCTL_DISK_GET_DRIVE_GEOMETRY, nullptr, 0, &dgm, sizeof(DISK_GEOMETRY), &dwRet, nullptr)) {
        return false;
    }

    sector_size    = dgm.BytesPerSector;
    total_sectors = dgm.Cylinders.QuadPart * dgm.TracksPerCylinder * dgm.SectorsPerTrack;
    return true;
#else
    // under development
    return false;
#endif
}

bool drive_cmd::cmddriveletter() {
#ifdef WIN32
    int nDeviceNum[MAX_DRIVELETTER];
    ::FillMemory(nDeviceNum, sizeof(nDeviceNum), 0xFF); // ALL -1(NO_DRIVELETTER)

    char cLetter = 'A';
    for (int i=0; cLetter <= 'Z'; ++cLetter, ++i) {
        STORAGE_DEVICE_NUMBER sdn = {0};
        std::wostringstream stream;
        stream << L"\\\\.\\" << cLetter << L":";
        HANDLE hVolume = ::CreateFileW(stream.str().c_str(), 0, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hVolume == INVALID_HANDLE_VALUE) {
            continue;
        } else {
            DWORD dwRet;
            BOOL bRet = ::DeviceIoControl(hVolume, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0, &sdn, sizeof(sdn), &dwRet, nullptr);
            if (bRet && sdn.DeviceType != 2) { // '2' value is a CD/DVD/BD device.
                nDeviceNum[i] = (int)sdn.DeviceNumber;
            }
            ::CloseHandle(hVolume);
        }
    }
    for (int i=0, k=0; i < MAX_DRIVELETTER; ++i) {
        if (nDeviceNum[i] == getdrive()) {
            cDriveLetter[k++] = (char)('A' + i);
        }
    }
    return true;
#else
    // under development
    return false;
#endif
}

bool drive_cmd::getparam() {
    bool ret = cmddriveletter() && cmddrivename() && cmdgeometry();
    debugcs::instance() << getdrivevendor() << getdrivename() << getsectorsize() << gettotalsectors() << getdriveletter(0);
    return ret;
}

void drive_cmd::setparam(const drive_cmd *instanced) {
    if(instanced) {
        sector_size = instanced->getsectorsize();
        total_sectors = instanced->gettotalsectors();
        for(int i=0; i < ARRAY_SIZE(cDriveLetter); ++i)
            cDriveLetter[i] = instanced->getdriveletter(i);
        drive_vendor = instanced->getdrivevendor();
        drive_name = instanced->getdrivename();
    }
}

DWORD drive_cmd::getsectorsize() const {
    return sector_size;
}

sector_t drive_cmd::gettotalsectors() const {
    return total_sectors;
}

std::vector<char> drive_cmd::getdriveletter() const {
    std::vector<char> letter;
    for(int i=0; i < ARRAY_SIZE(cDriveLetter); ++i) {
        if(cDriveLetter[i] != '\0')
            letter.push_back(cDriveLetter[i]);
    }
    return letter;
}

char drive_cmd::getdriveletter(int n) const {
    return cDriveLetter[n];
}

const std::wstring &drive_cmd::getdrivevendor() const {
    return drive_vendor;
}

const std::wstring &drive_cmd::getdrivename() const {
    return drive_name;
}

bool drive_stream::readfile(sector_t offset, DWORD _size /*= 0*/) const {
#ifdef WIN32
    LARGE_INTEGER lisec;
    DWORD dwSize;
    lisec.QuadPart = offset;
    DWORD size = (_size == 0) ? (DWORD)getbuffersize(): _size;
    if (! ::SetFilePointerEx(gethandle(), lisec, nullptr, FILE_BEGIN ))    {
        return false;
    }
    if (! ::ReadFile(gethandle(), getbuffer(), size, &dwSize, nullptr))    {
        return false;
    }
    total_size += dwSize;
    return size == dwSize;
#else
    // under development
    return false;
#endif
}

bool drive_stream::writefile(sector_t offset, DWORD _size /*= 0*/) const {
#ifdef WIN32
    LARGE_INTEGER lisec;
    DWORD dwSize;
    lisec.QuadPart = offset;
    DWORD size = (_size == 0) ? (DWORD)getbuffersize(): _size;
    if (! ::SetFilePointerEx(gethandle(), lisec, nullptr, FILE_BEGIN ))    {
        return false;
    }
    if (! ::WriteFile(gethandle(), getbuffer(), size, &dwSize, nullptr))    {
        return false;
    }
    total_size += dwSize;
    return size == dwSize;
#else
    // under development
    return false;
#endif
}

void drive_stream::alloc(size_t size) const {
    buffer.resize(size, 0x00);
}

void drive_stream::allocrand(size_t size) const {
    mcrypto<BYTE> crypt;
    BYTE value = crypt >>= crypt;
    if(getbuffersize() == 0) {
        buffer.resize(size, value);
    } else {
#ifdef WIN32
        ::FillMemory(getbuffer(), getbuffersize(), value);
#else
        std::memset(getbuffer(), value, getbuffersize());
#endif
    }
}

int64_t drive_stream::gettotalsize() const {
    return total_size;
}

void drive_stream::bufclear() const {
    total_size = 0;
    buffer.clear();
}

#endif // QT_GUI
