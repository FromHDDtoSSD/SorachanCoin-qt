// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_IOFS_H
#define BITCOIN_IOFS_H

#include <file_operate/fs.h>
#include <const/no_instance.h>

class iofs : private no_instance
{
public:
#ifdef WIN32
    static fs::path GetSpecialFolderPath(int nFolder, bool fCreate = true);
#endif

    static void FileCommit(FILE *fileout);
    static int GetFilesize(FILE *file);
    static bool RenameOver(fs::path src, fs::path dest);
    static fs::path GetDefaultDataDir();
    static const fs::path &GetDataDir(bool fNetSpecific = true);
    static fs::path GetConfigFile();
    static fs::path GetPidFile();

#ifndef WIN32
    static void CreatePidFile(const boost::filesystem::path &path, pid_t pid);
#endif

    static void ShrinkDebugFile();
};

#endif
