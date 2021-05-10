// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/system.h>
#include <util/args.h>

#include <const/chainparamsbase.h>
#include <random/random.h>
#include <serialize.h>
#include <util/strencodings.h>

#include <stdarg.h>

#if (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
#include <pthread.h>
#include <pthread_np.h>
#endif

#ifndef WIN32
// for posix_fallocate
#ifdef __linux__

#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#define _POSIX_C_SOURCE 200112L

#endif // __linux__

#include <algorithm>
#include <fcntl.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/stat.h>

#else

#ifdef _MSC_VER
#pragma warning(disable:4786)
#pragma warning(disable:4804)
#pragma warning(disable:4805)
#pragma warning(disable:4717)
#endif

#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501

#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <codecvt>

#include <io.h> /* for _commit */
#include <shellapi.h>
#include <shlobj.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#ifdef HAVE_MALLOPT_ARENA_MAX
#include <malloc.h>
#endif

#include <thread>

/** A map that contains all the currently held directory locks. After
 * successful locking, these will be held here until the global destructor
 * cleans them up and thus automatically unlocks them, or ReleaseDirectoryLocks
 * is called.
 */
static std::map<std::string, std::unique_ptr<fsbridge::FileLock> > dir_locks;
/** Mutex to protect dir_locks. */
static std::mutex cs_dir_locks;

bool lutil::LockDirectory(const fs::path &directory, const std::string lockfile_name, bool probe_only) {
    std::lock_guard<std::mutex> ulock(cs_dir_locks);
    fs::path pathLockFile = directory / lockfile_name;

    // If a lock for this directory already exists in the map, don't try to re-lock it
    if (dir_locks.count(pathLockFile.string())) {
        return true;
    }

    // Create empty lock file if it doesn't exist.
    FILE* file = fsbridge::fopen(pathLockFile, "a");
    if (file) fclose(file);
    auto lock = MakeUnique<fsbridge::FileLock>(pathLockFile);
    if (! lock->TryLock()) {
        return error("Error while attempting to lock directory %s: %s", directory.string(), lock->GetReason());
    }
    if (! probe_only) {
        // Lock successful and we're not just probing, put it into the map
        dir_locks.emplace(pathLockFile.string(), std::move(lock));
    }
    return true;
}

void lutil::UnlockDirectory(const fs::path &directory, const std::string &lockfile_name) {
    std::lock_guard<std::mutex> lock(cs_dir_locks);
    dir_locks.erase((directory / lockfile_name).string());
}

void lutil::ReleaseDirectoryLocks() {
    std::lock_guard<std::mutex> ulock(cs_dir_locks);
    dir_locks.clear();
}

bool lutil::DirIsWritable(const fs::path &directory) {
    fs::path tmpFile = directory / fs::unique_path();

    FILE *file = fsbridge::fopen(tmpFile, "a");
    if (! file) return false;

    ::fclose(file);
    remove(tmpFile.string().c_str());
    return true;
}

fs::path lutil::GetDefaultDataDir() {
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\SorachanCoin
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\SorachanCoin
    // Mac: ~/Library/Application Support/SorachanCoin
    // Linux/Unix: ~/.SorachanCoin
#ifdef WIN32
    // Windows
    return lutil::GetSpecialFolderPath(CSIDL_APPDATA)/"SorachanCoin";
#else
    fs::path pathRet;
    char *pszHome = ::getenv("HOME");
    if (pszHome == nullptr || ::strlen(pszHome) == 0)
        pathRet = fs::path("/");
    else
        pathRet = fs::path(pszHome);
# ifdef MAC_OSX
    // Mac
    return pathRet / "Library/Application Support/SorachanCoin";
# else
    // Linux/Unix
    return pathRet / ".SorachanCoin";
# endif
#endif
}

static fs::path g_blocks_path_cache_net_specific;
static fs::path pathCached;
static fs::path pathCachedNetSpecific;
static CCriticalSection csPathCached;

const fs::path &lutil::GetBlocksDir() {
    LOCK(csPathCached);
    fs::path &path = g_blocks_path_cache_net_specific;

    // This can be called during exceptions by LogPrintf(), so we cache the
    // value so we don't have to do memory allocations after that.
    if (! path.empty())
        return path;

    if (ARGS.IsArgSet("-blocksdir")) {
        path = fs::system_complete(ARGS.GetArg("-blocksdir", ""));
        if (! fs::is_directory(path)) {
            path = "";
            return path;
        }
    } else {
        path = GetDataDir(false);
    }

    path /= chainparamsbase::BaseParams().DataDir();
    path /= "blocks";
    fs::create_directories(path);
    return path;
}

const fs::path &lutil::GetDataDir(bool fNetSpecific) {
    LOCK(csPathCached);
    fs::path &path = fNetSpecific ? pathCachedNetSpecific : pathCached;

    // This can be called during exceptions by LogPrintf(), so we cache the
    // value so we don't have to do memory allocations after that.
    if (! path.empty())
        return path;

    if (ARGS.IsArgSet("-datadir")) {
        path = fs::system_complete(ARGS.GetArg("-datadir", ""));
        if (! fs::is_directory(path)) {
            path = "";
            return path;
        }
    } else {
        path = GetDefaultDataDir();
    }
    if (fNetSpecific)
        path /= chainparamsbase::BaseParams().DataDir();

    if (fs::create_directories(path)) {
        // This is the first run, create wallets subdirectory too
        fs::create_directories(path / "wallets");
    }

    return path;
}

void lutil::ClearDatadirCache() {
    LOCK(csPathCached);

    pathCached = fs::path();
    pathCachedNetSpecific = fs::path();
    g_blocks_path_cache_net_specific = fs::path();
}

bool lutil::RenameOver(fs::path src, fs::path dest) {
#ifdef WIN32
    return MoveFileExW(src.wstring().c_str(), dest.wstring().c_str(),
                       MOVEFILE_REPLACE_EXISTING) != 0;
#else
    int rc = std::rename(src.string().c_str(), dest.string().c_str());
    return (rc == 0);
#endif /* WIN32 */
}

/**
 * Ignores exceptions thrown by Boost's create_directories if the requested directory exists.
 * Specifically handles case where path p exists, but it wasn't possible for the user to
 * write to the parent directory.
 */
bool lutil::TryCreateDirectories(const fs::path &p) {
    try {
        return fs::create_directories(p);
    } catch (const fs::filesystem_error &) {
        if (!fs::exists(p) || !fs::is_directory(p))
            throw;
    }

    // create_directories didn't create the directory, it had to have existed already
    return false;
}

bool lutil::FileCommit(FILE *file) {
    if (::fflush(file) != 0) { // harmless if redundantly called
        logging::LogPrintf("%s: fflush failed: %d\n", __func__, errno);
        return false;
    }
# ifdef WIN32
    HANDLE hFile = (HANDLE)::_get_osfhandle(::_fileno(file));
    if (::FlushFileBuffers(hFile) == 0) {
        logging::LogPrintf("%s: FlushFileBuffers failed: %d\n", __func__, ::GetLastError());
        return false;
    }
# else
#  if defined(__linux__) || defined(__NetBSD__)
    if (::fdatasync(::fileno(file)) != 0 && errno != EINVAL) { // Ignore EINVAL for filesystems that don't support sync
        logging::LogPrintf("%s: fdatasync failed: %d\n", __func__, errno);
        return false;
    }
#  elif defined(MAC_OSX) && defined(F_FULLFSYNC)
    if (::fcntl(::fileno(file), F_FULLFSYNC, 0) == -1) { // Manpage says "value other than -1" is returned on success
        logging::LogPrintf("%s: fcntl F_FULLFSYNC failed: %d\n", __func__, errno);
        return false;
    }
#  else
    if (::fsync(::fileno(file)) != 0 && errno != EINVAL) {
        logging::LogPrintf("%s: fsync failed: %d\n", __func__, errno);
        return false;
    }
#  endif
# endif
    return true;
}

bool lutil::TruncateFile(FILE *file, unsigned int length) noexcept {
#if defined(WIN32)
    return ::_chsize(::_fileno(file), length) == 0;
#else
    return ::ftruncate(::fileno(file), length) == 0;
#endif
}

/**
 * this function tries to raise the file descriptor limit to the requested number.
 * It returns the actual file descriptor limit (which may be more or less than nMinFD)
 */
int lutil::RaiseFileDescriptorLimit(int nMinFD) noexcept {
#if defined(WIN32)
    return 2048;
#else
    struct rlimit limitFD;
    if (::getrlimit(RLIMIT_NOFILE, &limitFD) != -1) {
        if (limitFD.rlim_cur < (rlim_t)nMinFD) {
            limitFD.rlim_cur = nMinFD;
            if (limitFD.rlim_cur > limitFD.rlim_max)
                limitFD.rlim_cur = limitFD.rlim_max;
            setrlimit(RLIMIT_NOFILE, &limitFD);
            getrlimit(RLIMIT_NOFILE, &limitFD);
        }
        return limitFD.rlim_cur;
    }
    return nMinFD; // getrlimit failed, assume it's fine
#endif
}

/**
 * this function tries to make a particular range of a file allocated (corresponding to disk space)
 * it is advisory, and the range specified in the arguments will never contain live data
 */
void lutil::AllocateFileRange(FILE *file, unsigned int offset, unsigned int length) {
#if defined(WIN32)
    // Windows-specific version
    HANDLE hFile = (HANDLE)::_get_osfhandle(::_fileno(file));
    LARGE_INTEGER nFileSize;
    int64_t nEndPos = (int64_t)offset + length;
    nFileSize.u.LowPart = nEndPos & 0xFFFFFFFF;
    nFileSize.u.HighPart = nEndPos >> 32;
    ::SetFilePointerEx(hFile, nFileSize, 0, FILE_BEGIN);
    ::SetEndOfFile(hFile);
#elif defined(MAC_OSX)
    // OSX specific version
    fstore_t fst;
    fst.fst_flags = F_ALLOCATECONTIG;
    fst.fst_posmode = F_PEOFPOSMODE;
    fst.fst_offset = 0;
    fst.fst_length = (off_t)offset + length;
    fst.fst_bytesalloc = 0;
    if (::fcntl(::fileno(file), F_PREALLOCATE, &fst) == -1) {
        fst.fst_flags = F_ALLOCATEALL;
        ::fcntl(::fileno(file), F_PREALLOCATE, &fst);
    }
    ::ftruncate(fileno(file), fst.fst_length);
#else
# if defined(__linux__)
    // Version using posix_fallocate
    off_t nEndPos = (off_t)offset + length;
    if (0 == ::posix_fallocate(::fileno(file), 0, nEndPos)) return;
# endif
    // Fallback version
    // TODO: just write one byte per block
    static const char buf[65536] = {};
    if (::fseek(file, offset, SEEK_SET)) {
        return;
    }
    while (length > 0) {
        unsigned int now = 65536;
        if (length < now)
            now = length;
        ::fwrite(buf, 1, now, file); // allowed to fail; this function is advisory anyway
        length -= now;
    }
#endif
}

#ifdef WIN32
fs::path lutil::GetSpecialFolderPath(int nFolder, bool fCreate) noexcept {
    char pszPath[MAX_PATH] = {0};
    if(::SHGetSpecialFolderPathA(nullptr, pszPath, nFolder, fCreate)) {
        return fs::path(pszPath);
    }
    logging::LogPrintf("SHGetSpecialFolderPathW() failed, could not obtain requested path.\n");
    return fs::path("");
}
#endif

void lutil::runCommand(const std::string &strCommand) {
    if (strCommand.empty()) return;
#ifndef WIN32
    int nErr = ::system(strCommand.c_str());
#else
    int nErr = ::system(strCommand.c_str());
    //int nErr = ::_wsystem(std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>,wchar_t>().from_bytes(strCommand).c_str());
#endif
    if (nErr)
        logging::LogPrintf("runCommand error: system(%s) returned %d\n", strCommand, nErr);
}

void lutil::SetupEnvironment() {
#ifdef HAVE_MALLOPT_ARENA_MAX
    // glibc-specific: On 32-bit systems set the number of arenas to 1.
    // By default, since glibc 2.10, the C library will create up to two heap
    // arenas per core. This is known to cause excessive virtual address space
    // usage in our usage. Work around it by setting the maximum number of
    // arenas to 1.
    if (sizeof(void *) == 4) {
        ::mallopt(M_ARENA_MAX, 1);
    }
#endif
    // On most POSIX systems (e.g. Linux, but not BSD) the environment's locale
    // may be invalid, in which case the "C" locale is used as fallback.
#if !defined(WIN32) && !defined(MAC_OSX) && !defined(__FreeBSD__) && !defined(__OpenBSD__)
    try {
        std::locale(""); // Raises a runtime error if current locale is invalid
    } catch (const std::runtime_error &) {
        setenv("LC_ALL", "C", 1);
    }
#elif defined(WIN32)
    // Set the default input/output charset is utf-8
    ::SetConsoleCP(CP_UTF8);
    ::SetConsoleOutputCP(CP_UTF8);
#endif
    // The path locale is lazy initialized and to avoid deinitialization errors
    // in multithreading environments, it is set explicitly by the main thread.
    // A dummy locale is used to extract the internal default locale, used by
    // fs::path, which is then used to explicitly imbue the path.
    std::locale loc = fs::path::imbue(std::locale::classic());
#ifndef WIN32
    fs::path::imbue(loc);
#else
    fs::path::imbue(std::locale(loc, new std::codecvt_utf8_utf16<wchar_t>()));
#endif
}

bool lutil::SetupNetworking() noexcept {
#ifdef WIN32
    // Initialize Windows Sockets
    WSADATA wsadata;
    int ret = ::WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR || LOBYTE(wsadata.wVersion ) != 2 || HIBYTE(wsadata.wVersion) != 2)
        return false;
#endif
    return true;
}

int lutil::GetNumCores() {
    return std::thread::hardware_concurrency();
}

/*
std::string lutil::CopyrightHolders(const std::string &strPrefix) {
    const auto copyright_devs = tfm::format(_(COPYRIGHT_HOLDERS), COPYRIGHT_HOLDERS_SUBSTITUTION);
    std::string strCopyrightHolders = strPrefix + copyright_devs;

    // Make sure Bitcoin Core copyright is not removed by accident
    if (copyright_devs.find("Bitcoin Core") == std::string::npos) {
        std::string strYear = strPrefix;
        strYear.replace(strYear.find("2011"), sizeof("2011")-1, "2009");
        strCopyrightHolders += "\n" + strYear + "The Bitcoin Core developers";
    }
    return strCopyrightHolders;
}
*/

fs::path lutil::AbsPathForConfigVal(const fs::path &path, bool net_specific/*= true*/, bool ftestnet/*= false*/) {
    fs::path footer = ftestnet ? fs::path("testnet2")/path: path;
    fs::path abspath = "";
    if(map_arg::GetMapArgsCount("-datadir"))
        return map_arg::GetMapArgsString("-datadir")/footer;
    else
        return GetDefaultDataDir()/footer;
}

int lutil::ScheduleBatchPriority() {
#ifdef SCHED_BATCH
    const static sched_param param{};
    if (int ret = pthread_setschedparam(pthread_self(), SCHED_BATCH, &param)) {
        logging::LogPrintf("Failed to pthread_setschedparam: %s\n", strerror(errno));
        return ret;
    }
    return 0;
#else
    return 1;
#endif
}

#ifdef WIN32
// SorachanCoin: std::wstring_convert is no recommended after C++17.
bool lutil::wchartochar(const wchar_t *source, std::string &dest) noexcept {
    int nLength = ::WideCharToMultiByte(CP_UTF8, 0, source, -1, nullptr, 0, nullptr, nullptr);
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
    return 0 < ::WideCharToMultiByte(CP_UTF8, 0, source, -1, &dest.at(0), nLength, nullptr, nullptr);
}

lutil::WinCmdLineArgs::WinCmdLineArgs() {
    wchar_t **wargv = ::CommandLineToArgvW(::GetCommandLineW(), &argc_);
    assert(wargv);
    argv_ = new char *[argc_];
    assert(argv_);
    args_.resize(argc_);
    for (int i = 0; i < argc_; ++i) {
        assert(lutil::wchartochar(wargv[i], args_[i]));
        argv_[i] = &*args_[i].begin();
    }
    ::LocalFree(wargv);
}

lutil::WinCmdLineArgs::~WinCmdLineArgs() {
    delete [] argv_;
}

std::pair<int, char **> lutil::WinCmdLineArgs::get() {
    return std::make_pair(argc_, argv_);
}
#endif
