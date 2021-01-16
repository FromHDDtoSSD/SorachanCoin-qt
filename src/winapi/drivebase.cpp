// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef QT_GUI
#include <winapi/drivebase.h>
#include <file_operate/fs.h>
#ifndef WIN32
# include <unistd.h>
# include <sys/types.h>
# include <stdlib.h>
#endif

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

    dest.resize(cchWideChar, L'\0');
    return 0 < ::MultiByteToWideChar(CP_ACP, 0, source, -1, &dest.at(0), cchWideChar);
#else
    size_t size = ::mbstowcs(nullptr, source, 0) + 1;
    if(size == (size_t)-1)
        return false;
    dest.resize(size, L'\0'); // size is no bytes.
    return ::mbstowcs(&dest.at(0), source, size) != (size_t)-1;
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
    size_t size = ::wcstombs(nullptr, source, 0) + 1;
    if(size == (size_t)-1)
        return false;
    dest.resize(size, '\0');
    return ::wcstombs(&dest.at(0), source, size) != (size_t)-1;
#endif
}

bool drive_handle::createdir(LPCWSTR path) const {
#ifdef WIN32
    if(! ::CreateDirectoryW(path, nullptr)) {
        DWORD error = ::GetLastError();
        debugcs::instance() << "[CREATE DIR]" << error;
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
    close();
    std::string dpath = std::string("/dev/") + nDrive;
    hDrive = ::open(dpath.c_str(), O_RDONLY | O_DIRECT);
    if(hDrive == -1) {
        hDrive = 0;
        return false;
    } else
        return true;
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
    debugcs::instance() << "[openwrite GetLastError]" << ::GetLastError();
    return hDrive != INVALID_HANDLE_VALUE;
#else
    close();
    std::string dpath = std::string("/dev/") + nDrive;
    hDrive = ::open(dpath.c_str(), O_WRONLY | O_DIRECT);
    if(hDrive == -1) {
        hDrive = 0;
        return false;
    } else
        return true;
#endif
}

bool drive_handle::openwritefile(char letter, LPCWSTR path, bool _lock /*= false*/) {
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
#ifdef WIN32
    DWORD lock_flag = _lock ? FILE_ATTRIBUTE_NORMAL: FILE_FLAG_WRITE_THROUGH; // Note: FILE_FLAG_NO_BUFFERING(sector) => FILE_FLAG_WRITE_THROUGH(file)
    lock = _lock;
    hDrive = ::CreateFileW( stream.str().c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, lock_flag, nullptr );
    return hDrive != INVALID_HANDLE_VALUE;
#else
    std::string dpath = stream.str().c_str();
    hDrive = ::open(dpath.c_str(), O_WRONLY);
    if(hDrive == -1) {
        hDrive = 0;
        return false;
    } else
        return true;
#endif
}

void drive_handle::close() {
    if(hDrive) {
        cs.enter();
#ifdef WIN32
        if(tempfile) {::FlushFileBuffers(hDrive);}
        ::CloseHandle(hDrive);
        hDrive = nullptr;
#else
        if(tempfile) {::ftruncate(hDrive);}
        ::close(hDrive);
        hDrive = 0;
#endif
        cs.leave();
    }
    if(tempfile) {
#ifdef WIN32
        // ::Sleep(50); // file mode benchmark only
        ::SetCurrentDirectoryW(tempfiledir.c_str());
        ::DeleteFileW(TEMPFILE_NAME);
        std::vector<wchar_t> letter;
        letter.resize(4, 0x00);
        ::RtlCopyMemory(&letter.at(0), &tempfiledir.at(0), 3 * sizeof(wchar_t));
        ::SetCurrentDirectoryW((LPCWSTR)&letter.at(0));
        ::RemoveDirectoryW(TEMPFILE_DIR); // Note: Safe Function (empty directory ONLY)
#else
        // ::Sleep(50); // file mode benchmark only
#endif
    }
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

unsigned int drive_base::_thread(cla_thread<drive_base>::thread_data *pdata) {
    if(! obj) {
        failure = true;
        return 1;
    }
    if(! obj->acc_thread(pdata->exit_flag)) {
        failure = true;
    }
    return 1;
}

bool drive_base::accsectors(sector_t begin, sector_t end, const bool &exit_flag, bool readflag) const {
    if(! gethandle()) {return false;}
    if(exit_flag) {return true;}
    if(! getlock()) { // Note: When locked, the 'accsectors' is file mode.
        if(readflag) {
            alloc(getsectorsize() * sectors_step);
        } else {
            allocrand(getsectorsize() * sectors_step);
        }
    } else {
        if(readflag) {
            alloc(getsectorsize() * sectors_step);
        }
    }

    if(end == SECTORS_STEP) { // random access.
        end = begin + sectors_step - 1;
    }
    if(gettotalsectors() <= end) {
        end = gettotalsectors() - 1;
    }

    const sector_t range = end - begin + 1;
    const sector_t count = range / sectors_step;
    const int remain = (int)(range % sectors_step);
    const sector_t begin_offset = begin * getsectorsize();

    for(int i=0; i < count; ++i)
    {
        if(exit_flag) {return true;}
        if(readflag) {
            if (! readfile(begin_offset + (getsectorsize() * sectors_step * i))) {
                return false;
            }
        } else {
            if (! writefile(begin_offset + (getsectorsize() * sectors_step * i))) {
                return false;
            }
        }
    }

    if(0 < remain) {
        if(exit_flag) {return true;}
        if(readflag) {
            if (! readfile(begin_offset + (getsectorsize() * sectors_step * count), getsectorsize() * remain)) {
                return false;
            }
        } else {
            if (! writefile(begin_offset + (getsectorsize() * sectors_step * count), getsectorsize() * remain)) {
                return false;
            }
        }
    }

    return true;
}

bool drive_base::base_openhandle(char mode, const drive_base *instanced /*= nullptr*/, bool lock /*= false*/, LPCWSTR path /*= nullptr*/) {
    setparam(instanced);
    if(mode == 'r') {
        if(! openread(lock)) {
            return false;
        }
    } else if (mode == 'w') {
        if(! openwrite(lock)) {
            return false;
        }
    } else if (mode == 'f') {
        if(! openwritefile('\0', path, lock)) {
            return false;
        }
        return true; // Note: unused getparam().
    } else if (mode == 'b') {
        if(! openwritefile(getdriveletter(0), nullptr, false)) {
            return false;
        }
    } else {
        return false;
    }
    return ((instanced == nullptr) ? getparam(): true);
}

std::wstring drive_base::getdriveinfo() const {
    std::wostringstream letter;
    letter << L"DriveLetter: ";
    std::vector<char> vcl = getdriveletter();
    for(std::vector<char>::const_iterator ite = vcl.begin(); ite != vcl.end(); ++ite)
        letter << *ite << L":\\ ";

    DWORD capacity = (DWORD)(gettotalsectors() * getsectorsize() / 1024 / 1024 / 1024);
    std::wostringstream stream;
    stream << getdrivevendor().c_str() << L"\n" << getdrivename().c_str() << L"\n" << L"Capacity: " << capacity << L" GB" << L"\n" << letter.str().c_str();
    return stream.str();
}

bool drive_base::checkdriveletter() const {
    return (getdriveletter(0) != '\0');
}

std::wstring drive_base::getdriveinfo(int) const {
    std::wostringstream stream;
    stream << getdrivevendor().c_str() << L" " << getdrivename().c_str();
    return stream.str();
}

double drive_base::getspeed(double ti) const {
    return (double)gettotalsize() / ti;
}

const std::vector<BYTE> *drive_base::getbufferread() const { // Read => getbuffer
    return getbuffer_lock();
}

std::vector<BYTE> *drive_base::setbufferwrite() { // setbuffer => buffered => Write
    return getbuffer_lock();
}

bool drive_accseq::acc_thread(const bool &exit_flag) {
    if(seqbegin < SCAN_BEGIN_MIN_SECTOR) {seqbegin = SCAN_BEGIN_MIN_SECTOR;}
    const sector_t range = seqend - seqbegin;
    const sector_t unit_sectors = unit_size / getsectorsize();
    const sector_t count = total = range / unit_sectors;
    const int remain = (int)(range % unit_sectors);
    if(0 < remain) {++total;}

    for(int i=0; i < count; ++i)
    {
        if(exit_flag) {return true;}
        if(! _rwfunc(seqbegin + (i * unit_sectors), seqbegin + ((i + 1) * unit_sectors), exit_flag)) {
            return false;
        }
        ++current;
    }
    if(0 < remain) {
        if(exit_flag) {return true;}
        if(! _rwfunc(seqbegin + (count * unit_sectors), seqbegin + remain, exit_flag)) {
            return false;
        }
        ++current;
    }
    return true;
}

bool drive_accrandom::acc_thread(const bool &exit_flag) {
    if(sectors_addr.size() == 0) {return false;}
    current = 0;
    for(std::vector<sector_t>::const_iterator ite = sectors_addr.begin(); ite != sectors_addr.end(); ++ite)
    {
        if(exit_flag) {return true;}
        if(SCAN_BEGIN_MIN_SECTOR <= getbegin()) {
            if(! _rwfunc(getbegin(), SECTORS_STEP, exit_flag)) {
                return false;
            }
        }

        sector_t randombegin = *ite;
        if(! getlock()) {
            if(randombegin < SCAN_BEGIN_MIN_SECTOR) {
                randombegin = SCAN_BEGIN_MIN_SECTOR;
            }
        }
        if(! _rwfunc(randombegin, SECTORS_STEP, exit_flag)) {
            return false;
        }

        if(SCAN_BEGIN_MIN_SECTOR <= getend()) {
            if(! _rwfunc(getend(), SECTORS_STEP, exit_flag)) {
                return false;
            }
        }
        ++current;
    }
    return true;
}

bool drive_datawritefull::_rwfunc(sector_t begin, sector_t end, const bool &exit_flag) const {
#ifdef WIN32
    if(! writesectors(begin, end, exit_flag)) {
        return false;
    } else {
        const std::vector<BYTE> *p = getbufferread();
        LARGE_INTEGER li;
        li.QuadPart = p->size() - padding;
        return (::SetFilePointerEx(gethandle(), li, nullptr, FILE_BEGIN) && ::SetEndOfFile(gethandle())) ? true: false;
    }
#else
    if(! writesectors(begin, end, exit_flag)) {
        return false;
    } else {
        const std::vector<BYTE> *p = getbufferread();
        off_t li = p->size() - padding;
        return (::ftruncate(gethandle(), li)==0 && ::lseek(gethandle(), li, SEEK_SET)!=-1) ? true: false;
    }
#endif
}

#endif // QT_GUI
