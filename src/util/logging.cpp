// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/system.h> // for AbsPathForConfigVal
#include <util/args.h>
#include <util/logging.h>
#include <util/time.h>
#include <version.h>

BCLog::Logger &LogInstance() noexcept {
/**
 * NOTE: the logger instances is leaked on exit. This is ugly, but will be
 * cleaned up by the OS/libc. Defining a logger as a global object doesn't work
 * since the order of destruction of static/global objects is undefined.
 * Consider if the logger gets destroyed, and then some later destructor calls
 * LogPrintf, maybe indirectly, and you get a core dump at shutdown trying to
 * access the logger. When the shutdown sequence is fully audited and tested,
 * explicit destruction of these objects can be implemented by changing this
 * from a raw pointer to a std::unique_ptr.
 * Since the destructor is never called, the logger and all its members must
 * have a trivial destructor.
 *
 * This method of initialization was originally introduced in
 * ee3374234c60aba2cc4c5cd5cac1c0aefc2d817c.
 */
    // SorachanCoin: replace from (BCLog::Logger *) to (void *)
    static unsigned char buf[sizeof(BCLog::Logger)];
    static void *g_logger{(void *)new(buf) BCLog::Logger};
    return *(BCLog::Logger *)g_logger;
}

int BCLog::Logger::FileWriteStr(const std::string &str, FILE *fp) noexcept {
    return ::fwrite(str.data(), 1, str.size(), fp);
}

bool BCLog::Logger::OpenDebugLog() {
    std::lock_guard<std::mutex> scoped_lock(m_file_mutex);

    assert(m_fileout == nullptr);
    // if(m_fileout) ::fclose(m_fileout);
    assert(!m_file_path.empty());
    m_fileout = fsbridge::fopen(m_file_path, "a");
    if (! m_fileout)
        return false;

    setbuf(m_fileout, nullptr); // unbuffered
    // dump buffered messages from before we opened the log
    while (!m_msgs_before_open.empty()) {
        FileWriteStr(m_msgs_before_open.front(), m_fileout);
        m_msgs_before_open.pop_front();
    }

    return true;
}

void BCLog::Logger::EnableCategory(BCLog::LogFlags flag) noexcept {
    m_categories |= flag;
}

bool BCLog::Logger::EnableCategory(const std::string &str) noexcept {
    BCLog::LogFlags flag;
    if (! GetLogCategory(flag, str)) return false;
    EnableCategory(flag);
    return true;
}

void BCLog::Logger::DisableCategory(BCLog::LogFlags flag) noexcept {
    m_categories &= ~flag;
}

bool BCLog::Logger::DisableCategory(const std::string &str) noexcept {
    BCLog::LogFlags flag;
    if (! GetLogCategory(flag, str)) return false;
    DisableCategory(flag);
    return true;
}

bool BCLog::Logger::WillLogCategory(BCLog::LogFlags category) const {
    return (m_categories.load(std::memory_order_relaxed) & category) != 0;
}

bool BCLog::Logger::DefaultShrinkDebugFile() const noexcept {
    return m_categories == BCLog::NONE;
}

namespace {

struct CLogCategoryDesc {
    BCLog::LogFlags flag;
    std::string category;
};

const CLogCategoryDesc LogCategories[] = {
    {BCLog::NONE, "0"},
    {BCLog::NONE, "none"},
    {BCLog::NET, "net"},
    {BCLog::TOR, "tor"},
    {BCLog::MEMPOOL, "mempool"},
    {BCLog::HTTP, "http"},
    {BCLog::BENCH, "bench"},
    {BCLog::ZMQ, "zmq"},
    {BCLog::DB, "db"},
    {BCLog::RPC, "rpc"},
    {BCLog::ESTIMATEFEE, "estimatefee"},
    {BCLog::ADDRMAN, "addrman"},
    {BCLog::SELECTCOINS, "selectcoins"},
    {BCLog::REINDEX, "reindex"},
    {BCLog::CMPCTBLOCK, "cmpctblock"},
    {BCLog::RAND, "rand"},
    {BCLog::PRUNE, "prune"},
    {BCLog::PROXY, "proxy"},
    {BCLog::MEMPOOLREJ, "mempoolrej"},
    {BCLog::LIBEVENT, "libevent"},
    {BCLog::COINDB, "coindb"},
    {BCLog::QT, "qt"},
    {BCLog::LEVELDB, "leveldb"},
    {BCLog::ALL, "1"},
    {BCLog::ALL, "all"},
};

} // namespace

bool GetLogCategory(BCLog::LogFlags &flag, const std::string &str) noexcept {
    if (str == "") {
        flag = BCLog::ALL;
        return true;
    }
    for (const CLogCategoryDesc &category_desc: LogCategories) {
        if (category_desc.category == str) {
            flag = category_desc.flag;
            return true;
        }
    }
    return false;
}

std::string ListLogCategories() {
    std::string ret;
    int outcount = 0;
    for (const CLogCategoryDesc &category_desc: LogCategories) {
        // Omit the special cases.
        if (category_desc.flag != BCLog::NONE && category_desc.flag != BCLog::ALL) {
            if (outcount != 0) ret += ", ";
            ret += category_desc.category;
            outcount++;
        }
    }
    return ret;
}

std::vector<CLogCategoryActive> ListActiveLogCategories() {
    std::vector<CLogCategoryActive> ret;
    for (const CLogCategoryDesc &category_desc: LogCategories) {
        // Omit the special cases.
        if (category_desc.flag != BCLog::NONE && category_desc.flag != BCLog::ALL) {
            CLogCategoryActive catActive;
            catActive.category = category_desc.category;
            catActive.active = LogAcceptCategory(category_desc.flag);
            ret.push_back(catActive);
        }
    }
    return ret;
}

std::string BCLog::Logger::LogTimestampStr(const std::string &str) {
    std::string strStamped;
    if (! m_log_timestamps)
        return str;

    if (m_started_new_line) {
        int64_t nTimeMicros = util::GetTimeMicros();
        strStamped = util::FormatISO8601DateTime(nTimeMicros/1000000);
        if (m_log_time_micros) {
            strStamped.pop_back();
            strStamped += tfm::format(".%06dZ", nTimeMicros%1000000);
        }
        int64_t mocktime = util::GetMockTime();
        if (mocktime) {
            strStamped += " (mocktime: " + util::FormatISO8601DateTime(mocktime) + ")";
        }
        strStamped += ' ' + str;
    } else
        strStamped = str;

    if (!str.empty() && str[str.size()-1] == '\n')
        m_started_new_line = true;
    else
        m_started_new_line = false;

    return strStamped;
}

namespace BCLog {
    /** Belts and suspenders: make sure outgoing log messages don't contain
     * potentially suspicious characters, such as terminal control codes.
     *
     * This escapes control characters except newline ('\n') in C syntax.
     * It escapes instead of removes them to still allow for troubleshooting
     * issues where they accidentally end up in strings.
     */
    std::string LogEscapeMessage(const std::string &str) {
        std::string ret;
        for (char ch_in: str) {
            uint8_t ch = (uint8_t)ch_in;
            if ((ch >= 32 || ch == '\n') && ch != '\x7f') {
                ret += ch_in;
            } else {
                ret += tfm::format("\\x%02x", ch);
            }
        }
        return ret;
    }
}

void BCLog::Logger::LogPrintStr(const std::string &str) {
    std::string strEscaped = LogEscapeMessage(str);
    std::string strTimestamped = LogTimestampStr(strEscaped);
    if (m_print_to_console) {
        // print to console
        ::fwrite(strTimestamped.data(), 1, strTimestamped.size(), stdout);
        ::fflush(stdout);
    }
    if (m_print_to_file) {
        std::lock_guard<std::mutex> scoped_lock(m_file_mutex);

        // buffer if we haven't opened the log yet
        if (m_fileout == nullptr) {
            m_msgs_before_open.push_back(strTimestamped);
        } else {
            // reopen the log file, if requested
            if (m_reopen_file) {
                m_reopen_file = false;
                FILE *new_fileout = fsbridge::fopen(m_file_path, "a");
                if (new_fileout) {
                    ::setbuf(new_fileout, nullptr); // unbuffered
                    ::fclose(m_fileout);
                    m_fileout = new_fileout;
                }
            }
            FileWriteStr(strTimestamped, m_fileout);
        }
    }
}

bool BCLog::Logger::ShrinkDebugFile() {
    // Amount of debug.log to save at end when shrinking (must fit in memory)
    constexpr size_t RECENT_DEBUG_HISTORY_SIZE = 10 * 1000000;
    if(m_file_path.empty())
        return false;

    // Scroll debug.log if it's getting too big
    FILE *file = fsbridge::fopen(m_file_path, "r");
    if(! file) {
        logging::LogPrintf("Failed to shrink debug log file: FILE* get error\n");
        return false;
    }

    // Special files (e.g. device nodes) may not have a size.
    size_t log_size = 0;
    try {
        log_size = fs::file_size(m_file_path);
    } catch (const fs::filesystem_error &) {
        logging::LogPrintf("Failed to shrink debug log file: log_size get error\n");
        fclose(file);
        return false;
    }

    // If debug.log file is more than 10% bigger the RECENT_DEBUG_HISTORY_SIZE
    // trim it down by saving only the last RECENT_DEBUG_HISTORY_SIZE bytes
    if (file && log_size > 11 * (RECENT_DEBUG_HISTORY_SIZE / 10)) {
        // Restart the file with some of the end
        try {
            std::vector<char> vch(RECENT_DEBUG_HISTORY_SIZE, 0);
            if (::fseek(file, -((long)vch.size()), SEEK_END)) {
                fclose(file);
                logging::LogPrintf("Failed to shrink debug log file: fseek(...) failed\n");
                return false;
            }
            int nBytes = ::fread(vch.data(), 1, vch.size(), file);
            ::fclose(file); // "r" fclose
            file = nullptr;

            FILE *wfile = fsbridge::fopen(m_file_path, "w");
            if (wfile) {
                if(::fwrite(vch.data(), 1, nBytes, wfile) != 1) {
                    ::fclose(wfile); // "w" fclose
                    return false;
                }
                ::fclose(wfile); // "w" fclose
            } else {
                logging::LogPrintf("Failed to shrink debug log file: fopen write failed\n");
                return false;
            }
        } catch (const std::bad_alloc &) {
            if(file) ::fclose(file);
            logging::LogPrintf("Failed to shrink debug log file: memory allocate failure\n");
            return false;
        }
    } else if (file != nullptr)
        ::fclose(file);

    return true;
}

/**
 * Initialize global loggers.
 *
 * Note that this is called very early in the process lifetime, so you should be
 * careful about what global state you rely on here.
 */
void InitLogging() {
#ifdef QT_GUI
    LogInstance().m_print_to_file = true; //!gArgs.IsArgNegated("-debuglogfile");
    LogInstance().m_file_path = lutil::AbsPathForConfigVal(ARGS.GetArg("-debuglogfile", DEFAULT_DEBUGLOGFILE), false, args_bool::fTestNet);
    if(args_bool::fTestNet)
        debugcs::instance() << "called: InitLogging() m_file_path: " << LogInstance().m_file_path.string().c_str() << debugcs::endl();
#else
    LogInstance().m_print_to_file = true; //!gArgs.IsArgNegated("-debuglogfile");
    LogInstance().m_file_path = lutil::AbsPathForConfigVal(DEFAULT_DEBUGLOGFILE, false, args_bool::fTestNet);
#endif

    // Add newlines to the logfile to distinguish this execution from the last
    // one; called before console logging is set up, so this is only sent to
    // debug.log.
    logging::LogPrintf("\n\n\n\n\n");

#ifdef QT_GUI
    if(args_bool::fTestNet)
        LogInstance().m_print_to_console = false; // gArgs.GetBoolArg("-printtoconsole", !gArgs.GetBoolArg("-daemon", false));
    else
        LogInstance().m_print_to_console = false;
#else
    LogInstance().m_print_to_console = false;
#endif

    LogInstance().m_log_timestamps = ARGS.GetBoolArg("-logtimestamps", BCLog::Logger::DEFAULT_LOGTIMESTAMPS);
    LogInstance().m_log_time_micros = ARGS.GetBoolArg("-logtimemicros", BCLog::Logger::DEFAULT_LOGTIMEMICROS);

    LogInstance().m_fLogIPs = ARGS.GetBoolArg("-logips", BCLog::Logger::DEFAULT_LOGIPS);

    std::string version_string = format_version::FormatFullVersion();
#ifdef DEBUG
    version_string += " (debug build)";
#else
    version_string += " (release build)";
#endif
    //logging::LogPrintf(PACKAGE_NAME " version %s\n", version_string);
    logging::LogPrintf(" version %s\n", version_string);
}

bool OpenDebugFile() {
    if (LogInstance().m_print_to_file) {
        if (ARGS.GetBoolArg("-shrinkdebugfile", LogInstance().DefaultShrinkDebugFile())) {
            // Do this first since it both loads a bunch of debug.log into memory,
            // and because this needs to happen before any other debug.log printing
            // LogInstance().ShrinkDebugFile(); // after latest core
        }
        if (! LogInstance().OpenDebugLog()) {
            //debugcs::instance() << "Could not open debug log file %s" << LogInstance().m_file_path.string().c_str() << debugcs::endl();
            return false;
        }
    }
    return true;
}
