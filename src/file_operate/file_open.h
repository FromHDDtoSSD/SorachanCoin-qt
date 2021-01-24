// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_FILEOPEN_H
#define BITCOIN_FILEOPEN_H

#include <boot/shutdown.h>
#include <version.h>
#include <ui_interface.h>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

class file_open : private no_instance
{
private:
    static const uint64_t nMinDiskSpace = 52428800; // Minimum disk space required - used in CheckDiskSpace() 52428800(currently 50MB)
public:
    static FILE *OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char *pszMode="rb") {
        auto BlockFilePath = [](unsigned int nFile) {
            std::string strBlockFn = strprintf("blk%04u.dat", nFile);
            return iofs::GetDataDir() / strBlockFn;
        };

        if ((nFile < 1) || (nFile == std::numeric_limits<uint32_t>::max()))
            return nullptr;

        FILE *file = ::fopen(BlockFilePath(nFile).string().c_str(), pszMode);
        if (! file) return nullptr;
        if (nBlockPos != 0 && !::strchr(pszMode, 'a') && !::strchr(pszMode, 'w')) {
            if (::fseek(file, nBlockPos, SEEK_SET) != 0) {
                ::fclose(file);
                return nullptr;
            }
        }
        return file;
    }
    static bool CheckDiskSpace(uint64_t nAdditionalBytes=0) {
        uint64_t nFreeBytesAvailable = fs::space(iofs::GetDataDir()).available;
        // Check for nMinDiskSpace bytes
        if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes) {
            args_bool::fShutdown = true;
            std::string strMessage = _("Warning: Disk space is low!");
            excep::set_strMiscWarning( strMessage );
            printf("*** %s\n", strMessage.c_str());
            CClientUIInterface::uiInterface.ThreadSafeMessageBox(strMessage, strCoinName, CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
            boot::StartShutdown();
            return false;
        }
        return true;
    }
    static FILE *AppendBlockFile(unsigned int &nFileRet) {
        static CCriticalSection cs;
        static unsigned int nCurrentBlockFile = 1;
        LOCK(cs);
        nFileRet = 0;
        for (;;) {
            FILE *file = file_open::OpenBlockFile(nCurrentBlockFile, 0, "ab");
            if (! file) return nullptr;
            if (::fseek(file, 0, SEEK_END) != 0) return nullptr;

            // FAT32 file size max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
            if (ftell(file) < (long)(0x7F000000 - compact_size::MAX_SIZE)) {
                nFileRet = nCurrentBlockFile;
                return file;
            }
            ::fclose(file);
            ++nCurrentBlockFile;
        }
    }
};

#endif
