// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_H
#define BITCOIN_UTIL_H

#include <uint256.h>

#ifndef WIN32
# include <sys/types.h>
# include <sys/time.h>
# include <sys/resource.h>
# include <version.h>
#endif

#include <map>
#include <vector>
#include <string>
#include <boost/date_time/posix_time/posix_time.hpp>

#ifndef Q_MOC_RUN
# include <boost/thread.hpp>
# include <boost/filesystem.hpp>
# include <boost/filesystem/path.hpp>
# include <boost/date_time/gregorian/gregorian_types.hpp>
# include <boost/date_time/posix_time/posix_time_types.hpp>
#endif

#include <stdarg.h>
#include <openssl/rand.h>

#if defined(__USE_MINGW_ANSI_STDIO)
# undef __USE_MINGW_ANSI_STDIO // This constant forces MinGW to conduct stupid behavior
#endif
#include <inttypes.h>
#include <netbase.h> // for AddTimeData
#include <util/args.h>
#include <file_operate/iofs.h>
#include <util/logging.h>
#include <const/macro.h>
#include <random/random.h>
#include <util/c_overload.h>

#ifdef CSCRIPT_PREVECTOR_ENABLE
using util_vector = prevector<PREVECTOR_N, uint8_t>;
#else
using util_vector = std::vector<uint8_t>;
#endif

namespace util // used json-RPC
{
    constexpr int32_t nOneHour = 60 * 60;
    constexpr int32_t nOneDay = 24 * 60 * 60;
    constexpr int64_t nOneWeek = 7 * 24 * 60 * 60;

    constexpr int64_t COIN = 1000000;
    constexpr int64_t CENT = 10000;

#ifdef WIN32 // Windows MAX_PATH 256, ::Sleep(msec)
# define MSG_NOSIGNAL        0
# define MSG_DONTWAIT        0

# ifndef S_IRUSR
#  define S_IRUSR            0400
#  define S_IWUSR            0200
# endif
    inline void Sleep(int64_t n) {
        ::Sleep(n);
    }
#else
# define MAX_PATH            1024
    inline void Sleep(int64_t n) {
        //
        // Boost has a year 2038 problem if the request sleep time is past epoch+2^31 seconds the sleep returns instantly.
        // So we clamp our sleeps here to 10 years and hope that boost is fixed by 2028.
        //
        boost::thread::sleep(boost::get_system_time() + boost::posix_time::milliseconds(n>315576000000LL ? 315576000000LL : n));
    }
#endif

    inline int roundint(double d) {
        return (int)(d > 0 ? d + 0.5 : d - 0.5);
    }

    inline int64_t roundint64(double d) {
        return (int64_t)(d > 0 ? d + 0.5 : d - 0.5);
    }

    inline std::string leftTrim(std::string src, char chr) {
        std::string::size_type pos = src.find_first_not_of(chr, 0);
        if (pos > 0) {
            src.erase(0, pos);
        }
        return src;
    }

    template<typename T>
    inline std::string HexStr(const T itbegin, const T itend, bool fSpaces = false) {
        std::string rv;
        static const char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                         '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
        rv.reserve((itend - itbegin) * 3);
        for (T it = itbegin; it < itend; ++it) {
            unsigned char val = (unsigned char)(*it);
            if (fSpaces && it != itbegin) {
                rv.push_back(' ');
            }

            rv.push_back(hexmap[val >> 4]);
            rv.push_back(hexmap[val & 15]);
        }

        return rv;
    }

    inline std::string HexStr(const util_vector &vch, bool fSpaces = false) {
        return util::HexStr(vch.begin(), vch.end(), fSpaces);
    }

#ifdef CSCRIPT_PREVECTOR_ENABLE
    inline std::string HexStr(const std::vector<unsigned char> &vch, bool fSpaces = false) {
        return util::HexStr(vch.begin(), vch.end(), fSpaces);
    }
#endif

    template<typename T>
    inline void PrintHex(const T pbegin, const T pend, const char *pszFormat = "%s", bool fSpaces = true) {
        logging::LogPrintf(pszFormat, util::HexStr(pbegin, pend, fSpaces).c_str());
    }

    inline void PrintHex(const util_vector &vch, const char *pszFormat = "%s", bool fSpaces = true) {
        logging::LogPrintf(pszFormat, util::HexStr(vch, fSpaces).c_str());
    }

    inline std::string DateTimeStrFormat(const char *pszFormat, int64_t nTime) {
        // std::locale takes ownership of the pointer
        std::locale loc(std::locale::classic(), new boost::posix_time::time_facet(pszFormat));
        std::stringstream ss;
        ss.imbue(loc);
        ss << boost::posix_time::from_time_t(nTime);
        return ss.str();
    }

    const std::string strTimestampFormat = "%Y-%m-%d %H:%M:%S UTC";
    inline std::string DateTimeStrFormat(int64_t nTime) {
        return util::DateTimeStrFormat(strTimestampFormat.c_str(), nTime);
    }

    template<typename T>
    inline void skipspaces(T &it) {
        while (::isspace(*it))
        {
            ++it;
        }
    }

    inline bool IsSwitchChar(char c) {
#ifdef WIN32
        return c == '-' || c == '/';
#else
        return c == '-';
#endif
    }

    inline uint32_t ByteReverse(uint32_t value) {
        value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
        return (value << 16) | (value >> 16);
    }

    //
    // Loop shutdown
    //
    inline void LoopSleep(int64_t t) {
        const int64_t interval = 20;
        const int64_t counter = t / interval;
        for(int64_t i = 0; i < counter; ++i)
        {
            if(args_bool::fShutdown) {
                return;
            }
            util::Sleep(interval);
        }
    }
}

//
// Median filter over a stream of values.
// Returns the median of the last N numbers
//
template <typename T>
class CMedianFilter {
private:
    CMedianFilter(const CMedianFilter &)=delete;
    CMedianFilter(CMedianFilter &&)=delete;
    CMedianFilter &operator=(const CMedianFilter &)=delete;
    CMedianFilter &operator=(CMedianFilter &&)=delete;

    std::vector<T> vValues;
    std::vector<T> vSorted;
    unsigned int nSize;
public:
    CMedianFilter(unsigned int size, T initial_value) : nSize(size) {
        vValues.reserve(size);
        vValues.push_back(initial_value);

        vSorted = vValues;
    }

    void input(T value) {
        if (vValues.size() == nSize) {
            vValues.erase(vValues.begin());
        }

        vValues.push_back(value);
        vSorted.resize(vValues.size());

        std::copy(vValues.begin(), vValues.end(), vSorted.begin());
        std::sort(vSorted.begin(), vSorted.end());
    }

    T median() const {
        size_t size = vSorted.size();
        assert(size > 0);
        if (size & 1) {    // Odd number of elements
            return vSorted[size / 2];
        } else {           // Even number of elements
            return (vSorted[size / 2 - 1] + vSorted[size / 2]) / 2;
        }
    }

    int size() const {
        return static_cast<int>(vValues.size());
    }

    std::vector<T> sorted() const {
        return vSorted;
    }
};

// Trusted NTP offset or median of NTP samples.
namespace ntp_ext    // ntp.h namespace
{
    extern int64_t GetNtpOffset();
}

class bitsystem : private no_instance
{
private:
    // Median of time samples given by other nodes.
    static int64_t nNodesOffset; // = INT64_MAX;

    // Select time offset
    static int64_t GetTimeOffset() {
        if (util::abs64(ntp_ext::GetNtpOffset()) < 40 * 60) {    // If NTP and system clock are in agreement within 40 minutes, then use NTP.
            return ntp_ext::GetNtpOffset();
        }
        if (util::abs64(nNodesOffset) < 70 * 60) {               // If not, then choose between median peer time and system clock.
            return nNodesOffset;
        }
        return 0;
    }

    static CMedianFilter<int64_t> vTimeOffsets; //(200,0);

public:
    //
    // "Never go to sea with two chronometers; take one or three."
    // Our three time sources are:
    //  - System clock
    //  - Median of other nodes clocks
    //  - The user (asking the user to fix the system clock if the first two disagree)
    //
    static int64_t GetTime() {
        int64_t now = ::time(nullptr);
        assert(now > 0);
        return now;
    }
    static int64_t GetAdjustedTime() {
        return bitsystem::GetTime() + bitsystem::GetTimeOffset();
    }

    static int GetRandInt(int nMax) {
        return static_cast<int>(bitsystem::GetRand(nMax));
    }
    static uint64_t GetRand(uint64_t nMax) {
        if (nMax == 0) {
            return 0;
        }

        // The range of the random source must be a multiple of the modulus
        // to give every possible output value an equal possibility
        uint64_t nRange = ((std::numeric_limits<uint64_t>::max)() / nMax) * nMax;
        uint64_t nRand = 0;
        do {
            latest_crypto::random::GetStrongRandBytes((unsigned char *)&nRand, sizeof(nRand));
        } while (nRand >= nRange);

        return (nRand % nMax);
    }
    static uint256 GetRandHash() {
        uint256 hash;
        latest_crypto::random::GetStrongRandBytes((unsigned char *)&hash, sizeof(hash));
        return hash;
    }
    static int64_t GetNodesOffset() {
        return nNodesOffset;
    }

    static void AddTimeData(const CNetAddr &ip, int64_t nTime);
};

class dump : private no_instance
{
private:
    static const std::locale formats[5];

    static std::time_t pt_to_time_t(const boost::posix_time::ptime &pt) {
        boost::posix_time::ptime timet_start(boost::gregorian::date(1970, 1, 1));
        boost::posix_time::time_duration diff = pt - timet_start;
        return diff.ticks() / boost::posix_time::time_duration::rep_type::ticks_per_second;
    }

public:
    static std::string EncodeDumpTime(int64_t nTime);
    static int64_t DecodeDumpTime(const std::string &s);
    static std::string EncodeDumpString(const std::string &str);
    static std::string DecodeDumpString(const std::string &str);
};

class seed : private no_instance
{
public:
    static void RandAddSeed();
    static void RandAddSeedPerfmon();
};

/*
namespace cmd
{
    void runCommand(std::string strCommand);
}
*/

/*
#ifndef THROW_WITH_STACKTRACE
# define THROW_WITH_STACKTRACE(exception)  \
{                                          \
    trace::LogStackTrace();                \
    throw (exception);                     \
}
#endif
*/

//
// tiny format
//
#undef PRIu64
#undef PRId64
#undef PRIx64
#define PRIu64 "u"
#define PRId64 "d"
#define PRIx64 "x"
#define PRIszx "x"
#define PRIszu "u"
#define PRIszd "d"
#define PRIpdx "x"
#define PRIpdu "u"
#define PRIpdd "d"

#endif
