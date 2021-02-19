// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOGGING_H
#define BITCOIN_LOGGING_H

#include <file_operate/fs.h>
#include <util/tinyformat.h>

#include <atomic>
#include <cstdint>
#include <list>
#include <mutex>
#include <string>
#include <vector>

#define DEFAULT_DEBUGLOGFILE ("debug.log")

struct CLogCategoryActive {
    std::string category;
    bool active;
};

namespace BCLog {
    enum LogFlags : uint32_t {
        NONE        = 0,
        NET         = (1 <<  0),
        TOR         = (1 <<  1),
        MEMPOOL     = (1 <<  2),
        HTTP        = (1 <<  3),
        BENCH       = (1 <<  4),
        ZMQ         = (1 <<  5),
        DB          = (1 <<  6),
        RPC         = (1 <<  7),
        ESTIMATEFEE = (1 <<  8),
        ADDRMAN     = (1 <<  9),
        SELECTCOINS = (1 << 10),
        REINDEX     = (1 << 11),
        CMPCTBLOCK  = (1 << 12),
        RAND        = (1 << 13),
        PRUNE       = (1 << 14),
        PROXY       = (1 << 15),
        MEMPOOLREJ  = (1 << 16),
        LIBEVENT    = (1 << 17),
        COINDB      = (1 << 18),
        QT          = (1 << 19),
        LEVELDB     = (1 << 20),
        ALL         = ~(uint32_t)0,
    };

    class Logger
    {
    private:
        FILE *m_fileout = nullptr;
        std::mutex m_file_mutex;
        std::list<std::string> m_msgs_before_open;
        static int FileWriteStr(const std::string &str, FILE *fp) noexcept;

        /**
         * m_started_new_line is a state variable that will suppress printing of
         * the timestamp when multiple calls are made that don't end in a
         * newline.
         */
        std::atomic_bool m_started_new_line{true};

        /** Log categories bitfield. */
        std::atomic<uint32_t> m_categories{0};

        std::string LogTimestampStr(const std::string &str);

    public:
        static constexpr bool DEFAULT_LOGTIMEMICROS = false;
        static constexpr bool DEFAULT_LOGIPS        = false;
        static constexpr bool DEFAULT_LOGTIMESTAMPS = true;

        bool m_fLogIPs = DEFAULT_LOGIPS;
        bool m_print_to_console = false;
        bool m_print_to_file = false;

        bool m_log_timestamps = DEFAULT_LOGTIMESTAMPS;
        bool m_log_time_micros = DEFAULT_LOGTIMEMICROS;

        fs::path m_file_path;
        std::atomic<bool> m_reopen_file{false};

        //~Logger() {
        //    if(m_fileout) {
        //        ::fclose(m_fileout);
        //        m_fileout = nullptr;
        //    }
        //}

        /** Send a string to the log output */
        void LogPrintStr(const std::string &str);

        /** Returns whether logs will be written to any output */
        bool Enabled() const noexcept { return m_print_to_console || m_print_to_file; }

        bool OpenDebugLog();
        bool ShrinkDebugFile();

        uint32_t GetCategoryMask() const { return m_categories.load(); }

        void EnableCategory(LogFlags flag) noexcept;
        bool EnableCategory(const std::string &str) noexcept;
        void DisableCategory(LogFlags flag) noexcept;
        bool DisableCategory(const std::string &str) noexcept;

        bool WillLogCategory(LogFlags category) const;
        bool DefaultShrinkDebugFile() const noexcept;
    };

} // namespace BCLog

BCLog::Logger &LogInstance() noexcept;

/** Return true if log accepts specified category */
static inline bool LogAcceptCategory(BCLog::LogFlags category) {
    return LogInstance().WillLogCategory(category);
}

/** Returns a string with the log categories. */
std::string ListLogCategories();

/** Returns a vector of the active log categories. */
std::vector<CLogCategoryActive> ListActiveLogCategories();

/** Return true if str parses as a log category and set the flag */
bool GetLogCategory(BCLog::LogFlags &flag, const std::string &str) noexcept;

namespace logging {

// Be conservative when using LogPrintf/error or other things which
// unconditionally log to debug.log! It should not be the case that an inbound
// peer can fill up a user's disk with debug.log entries.
template <typename... Args>
static inline void LogPrintf(const char *fmt, const Args&... args) noexcept {
    if (LogInstance().Enabled()) {
        std::string log_msg;
        try {
            log_msg = tfm::format(fmt, args...);
        } catch (tinyformat::format_error &fmterr) {
            /* Original format string will have newline so don't add one here */
            log_msg = "Error \"" + std::string(fmterr.what()) + "\" while formatting log message: " + fmt;
        }
        LogInstance().LogPrintStr(log_msg);
    }
}

template <typename... Args>
static inline void LogPrint(const BCLog::LogFlags &category, const Args&... args) noexcept {
    if (LogAcceptCategory((category)))
        LogPrintf(args...);
}

template <typename... Args>
NODISCARD static bool error(const char *fmt, const Args&... args) {
    std::ostringstream oss;
    tfm::format(oss, fmt, args...);
    logging::LogPrintf("ERROR: %s\n", oss.str().c_str());
    return false;
}

} // namespace logging

void InitLogging();
bool OpenDebugFile();

#endif // BITCOIN_LOGGING_H
