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
# include <pthread.h>
# include <pthread_np.h>
#endif

#ifndef WIN32
// for posix_fallocate
# ifdef __linux__
#  ifdef _POSIX_C_SOURCE
#   undef _POSIX_C_SOURCE
#  endif
#  define _POSIX_C_SOURCE 200112L
# endif // __linux__
#include <algorithm>
#include <fcntl.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/stat.h>
#else
# ifdef _MSC_VER
# pragma warning(disable:4786)
# pragma warning(disable:4804)
# pragma warning(disable:4805)
# pragma warning(disable:4717)
# endif
# ifdef _WIN32_IE
#  undef _WIN32_IE
# endif
# define _WIN32_IE 0x0501
# define WIN32_LEAN_AND_MEAN 1
# ifndef NOMINMAX
#  define NOMINMAX
# endif
# include <codecvt>
# include <io.h> /* for _commit */
# include <shellapi.h>
# include <shlobj.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
# include <sys/prctl.h>
#endif

#ifdef HAVE_MALLOPT_ARENA_MAX
# include <malloc.h>
#endif

fs::path util::GetDefaultDataDir() {
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\SorachanCoin
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\SorachanCoin
    // Mac: ~/Library/Application Support/SorachanCoin
    // Linux/Unix: ~/.SorachanCoin
#ifdef WIN32
    // Windows
    return util::GetSpecialFolderPath(CSIDL_APPDATA)/"SorachanCoin";
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

#ifdef WIN32
fs::path util::GetSpecialFolderPath(int nFolder, bool fCreate) {
    char pszPath[MAX_PATH] = {0};
    if(::SHGetSpecialFolderPathA(nullptr, pszPath, nFolder, fCreate)) {
        return fs::path(pszPath);
    }
    logging::LogPrintf("SHGetSpecialFolderPathW() failed, could not obtain requested path.\n");
    return fs::path("");
}
#endif

void util::runCommand(const std::string &strCommand) {
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

fs::path util::AbsPathForConfigVal(const fs::path &path, bool net_specific/*= true*/, bool ftestnet/*= false*/) {
    fs::path footer = ftestnet ? fs::path("testnet2")/path: path;
    fs::path abspath = "";
    if(map_arg::GetMapArgsCount("-datadir"))
        return map_arg::GetMapArgsString("-datadir")/footer;
    else
        return GetDefaultDataDir()/footer;
}
