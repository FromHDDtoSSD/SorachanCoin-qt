// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! for old core. latest core using fs.cpp (fsbridge)

#include <file_operate/iofs.h>
#include <util/args.h> // map_arg, lsync
#include <const/block_params.h>
#include <version.h>

#ifdef WIN32
# ifdef _WIN32_IE
#  undef _WIN32_IE
# endif
# define _WIN32_IE 0x0501
# include <io.h> /* for _commit */
# include <shlobj.h>
#elif defined(__linux__)
# include <sys/prctl.h>
#endif

#ifdef WIN32
fs::path iofs::GetSpecialFolderPath(int nFolder, bool fCreate) {
    char pszPath[MAX_PATH] = "";
    if(::SHGetSpecialFolderPathA(nullptr, pszPath, nFolder, fCreate))
        return fs::path(pszPath);
    logging::LogPrintf("SHGetSpecialFolderPathA() failed, could not obtain requested path.\n");
    return fs::path("");
}
#endif

void iofs::FileCommit(FILE *fileout) {
    ::fflush(fileout);        // harmless if redundantly called
#ifdef WIN32
    ::_commit(::_fileno(fileout));
#else
    ::fsync(fileno(fileout));
#endif
}

int iofs::GetFilesize(FILE *file) {
    int nSavePos = ::ftell(file);
    int nFilesize = -1;
    if (::fseek(file, 0, SEEK_END) == 0)
        nFilesize = ::ftell(file);
    ::fseek(file, nSavePos, SEEK_SET);
    return nFilesize;
}

bool iofs::RenameOver(fs::path src, fs::path dest) {
#ifdef WIN32
    return ::MoveFileExA(src.string().c_str(), dest.string().c_str(), MOVEFILE_REPLACE_EXISTING) != 0;
#else
    int rc = std::rename(src.string().c_str(), dest.string().c_str());
    return (rc == 0);
#endif
}

fs::path iofs::GetDefaultDataDir() {
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\SorachanCoin
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\SorachanCoin
    // Mac: ~/Library/Application Support/SorachanCoin
    // Unix / Linux: ~/.SorachanCoin
#ifdef WIN32
    //debugcs::instance() << "CoinName: " << strCoinName << debugcs::endl();
    return iofs::GetSpecialFolderPath(CSIDL_APPDATA) / strCoinName;
#else
    fs::path pathRet;
    char *pszHome = ::getenv("HOME");
    if (pszHome == nullptr || ::strlen(pszHome) == 0)
        pathRet = fs::path("/");
    else
        pathRet = fs::path(pszHome);
# ifdef MAC_OSX
    // Mac
    pathRet /= "Library/Application Support";
    fs::create_directory(pathRet);
    return pathRet / strCoinName;
# else
    // Unix / Linux
    std::string dsora = ".";
    dsora += strCoinName;
    return pathRet / dsora.c_str();
# endif
#endif
}

const fs::path &iofs::GetDataDir(bool fNetSpecific) {
    static fs::path pathCached[2];
    static LCCriticalSection csPathCached;
    static bool cachedPath[2] = {false, false};

    fs::path &path = pathCached[fNetSpecific];

    // This can be called during exceptions by printf, so we cache the
    // value so we don't have to do memory allocations after that.
    if (cachedPath[fNetSpecific])
        return path;

    LLOCK(csPathCached);
    if (map_arg::GetMapArgsCount("-datadir")) {
        path = fs::system_complete(map_arg::GetMapArgsString("-datadir"));
        if (! fs::is_directory(path)) {
            path = "";
            return path;
        }
    } else {
        path = iofs::GetDefaultDataDir();
    }

    if (fNetSpecific && map_arg::GetBoolArg("-testnet", false))
        path /= "testnet2";

    fs::create_directory(path);
    cachedPath[fNetSpecific]=true;
    return path;
}

fs::path iofs::GetConfigFile() {
    fs::path pathConfigFile(map_arg::GetArg("-conf", (strCoinName ".conf")));
    if (! pathConfigFile.is_complete())
        pathConfigFile = iofs::GetDataDir(false) / pathConfigFile;
    return pathConfigFile;
}

fs::path iofs::GetPidFile() {
    fs::path pathPidFile(map_arg::GetArg("-pid", (strCoinName ".pid")));
    if (! pathPidFile.is_complete()) { pathPidFile = iofs::GetDataDir() / pathPidFile; }
    return pathPidFile;
}

#ifndef WIN32
void iofs::CreatePidFile(const fs::path &path, pid_t pid) {
    FILE *file = ::fopen(path.string().c_str(), "w");
    if (file) {
        ::fprintf(file, "%d\n", pid);
        ::fclose(file);
    }
}
#endif

void iofs::ShrinkDebugFile() {
    // Scroll debug.log if it's getting too big
    fs::path pathLog = iofs::GetDataDir() / "debug.log";

    FILE *file = ::fopen(pathLog.string().c_str(), "r");
    if (file && iofs::GetFilesize(file) > 10 * 1000000) {
        // Restart the file with some of the end
        try {
            std::vector<char>* vBuf = new std::vector <char>(200000, 0);
            ::fseek(file, -((long)(vBuf->size())), SEEK_END);
            size_t nBytes = ::fread(&vBuf->operator[](0), 1, vBuf->size(), file);
            ::fclose(file);

            file = ::fopen(pathLog.string().c_str(), "w");
            if (file) {
                ::fwrite(&vBuf->operator[](0), 1, nBytes, file);
                ::fclose(file);
            }
            delete vBuf;
        } catch (const std::bad_alloc &e) {
            // Bad things happen - no free memory in heap at program startup
            ::fclose(file);
            logging::LogPrintf("Warning: %s in %s:%d\n iofs::ShrinkDebugFile failed - debug.log expands further", e.what(), __FILE__, __LINE__);
        }
    }
}
