// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Server/client environment: argument handling, config file parsing,
 * thread wrappers, startup time
 */
#ifndef BITCOIN_UTIL_SYSTEM_H
#define BITCOIN_UTIL_SYSTEM_H

//#if defined(HAVE_CONFIG_H)
//# include <config/bitcoin-config.h>
//#endif

#include <const/assumptions.h>

//#include <const/attributes.h>
#include <compat.h>
#include <file_operate/fs.h>
#include <util/logging.h>
#include <sync/lsync.h>
#include <util/tinyformat.h>
#include <util/memory.h>
#include <util/time.h>

#include <atomic>
#include <exception>
#include <map>
#include <set>
#include <stdint.h>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/thread/condition_variable.hpp> // for boost::thread_interrupted

namespace lutil { // old core: uilt, latest core: lutil

// Application startup time (used for uptime calculation)
inline int64_t GetStartupTime() noexcept {
    const static int64_t nStartupTime = util::GetTime();
    return nStartupTime;
}

inline std::string BITCOIN_CONF_FILENAME() noexcept {
    return "SorachanCoin.conf";
}

/** Translate a message to the native language of the user. */
const extern std::function<std::string(const char *)> G_TRANSLATION_FUN;

/**
 * Translation function.
 * If no translation function is set, simply return the input.
 */
inline std::string _(const char *psz) noexcept {
    return G_TRANSLATION_FUN ? (G_TRANSLATION_FUN)(psz) : psz;
}

void SetupEnvironment();
bool SetupNetworking() noexcept;

template<typename... Args>
bool error(const char* fmt, const Args&... args) noexcept {
    logging::LogPrintf("ERROR: %s\n", tfm::format(fmt, args...));
    return false;
}

void PrintExceptionContinue(const std::exception *pex, const char* pszThread);
bool FileCommit(FILE *file);
bool TruncateFile(FILE *file, unsigned int length) noexcept;
int RaiseFileDescriptorLimit(int nMinFD) noexcept;
void AllocateFileRange(FILE *file, unsigned int offset, unsigned int length);
bool RenameOver(fs::path src, fs::path dest);
bool LockDirectory(const fs::path &directory, const std::string lockfile_name, bool probe_only=false);
void UnlockDirectory(const fs::path &directory, const std::string &lockfile_name);
bool DirIsWritable(const fs::path &directory);
fs::path AbsPathForConfigVal(const fs::path &path, bool net_specific=true, bool ftestnet=false);

/** Release all directory locks. This is used for unit testing only, at runtime
 * the global destructor will take care of the locks.
 */
void ReleaseDirectoryLocks();

bool TryCreateDirectories(const fs::path& p);
fs::path GetDefaultDataDir();
// The blocks directory is always net specific.
const fs::path &GetBlocksDir();
const fs::path &GetDataDir(bool fNetSpecific = true);
void ClearDatadirCache();
#ifdef WIN32
fs::path GetSpecialFolderPath(int nFolder, bool fCreate = true) noexcept;
#endif
void runCommand(const std::string &strCommand);

inline bool IsSwitchChar(char c)
{
#ifdef WIN32
    return c == '-' || c == '/';
#else
    return c == '-';
#endif
}

/**
 * Return the number of cores available on the current system.
 * @note This does count virtual cores, such as those provided by HyperThreading.
 */
int GetNumCores();

void RenameThread(const char *name);

/**
 * .. and a wrapper that just calls func once
 */
template <typename Callable> void TraceThread(const char *name,  Callable func)
{
    std::string s = strprintf("SorachanCoin-%s", name);
    RenameThread(s.c_str());
    try
    {
        logging::LogPrintf("%s thread start\n", name);
        func();
        logging::LogPrintf("%s thread exit\n", name);
    }
    catch (const boost::thread_interrupted &)
    {
        logging::LogPrintf("%s thread interrupt\n", name);
        throw;
    }
    catch (const std::exception &e) {
        PrintExceptionContinue(&e, name);
        throw;
    }
    catch (...) {
        PrintExceptionContinue(nullptr, name);
        throw;
    }
}

//std::string CopyrightHolders(const std::string &strPrefix) noexcept;

/**
 * On platforms that support it, tell the kernel the calling thread is
 * CPU-intensive and non-interactive. See SCHED_BATCH in sched(7) for details.
 *
 * @return The return value of sched_setschedule(), or 1 on systems without
 * sched_setschedule().
 */
int ScheduleBatchPriority();

//! Simplification of std insertion
template <typename Tdst, typename Tsrc>
inline void insert(Tdst &dst, const Tsrc &src) {
    dst.insert(dst.begin(), src.begin(), src.end());
}
template <typename TsetT, typename Tsrc>
inline void insert(std::set<TsetT> &dst, const Tsrc &src) {
    dst.insert(src.begin(), src.end());
}

#ifdef WIN32
bool wchartochar(const wchar_t *source, std::string &dest) noexcept;
class WinCmdLineArgs
{
public:
    WinCmdLineArgs();
    ~WinCmdLineArgs();
    std::pair<int, char **> get();
private:
    WinCmdLineArgs(const WinCmdLineArgs &)=delete;
    WinCmdLineArgs(WinCmdLineArgs &&)=delete;
    WinCmdLineArgs &operator=(const WinCmdLineArgs &)=delete;
    WinCmdLineArgs &operator=(WinCmdLineArgs &&)=delete;
    bool operator==(const WinCmdLineArgs &)=delete;
    int argc_;
    char **argv_;
    std::vector<std::string> args_;
};
#endif

} // namespace lutil

#endif // BITCOIN_UTIL_SYSTEM_H
