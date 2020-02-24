// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef BITCOIN_UTIL_H
#define BITCOIN_UTIL_H


#include "uint256.h"

#ifndef WIN32
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif

#include <map>
#include <vector>
#include <string>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/foreach.hpp>

#ifndef Q_MOC_RUN
#include <boost/thread.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/date_time/gregorian/gregorian_types.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#endif

#include <stdarg.h>

#include <openssl/rand.h>

#if defined(__USE_MINGW_ANSI_STDIO)
#undef __USE_MINGW_ANSI_STDIO // This constant forces MinGW to conduct stupid behavior
#endif
#include <inttypes.h>

#include "netbase.h" // for AddTimeData

//
// block_info 2
//
namespace block_info
{
    extern unsigned char gpchMessageStart[4];// = { 0xe4, 0xe8, 0xe9, 0xe5 };
}

//
// Args
//
class bool_arg
{
private:
    bool flag;
public:
    bool_arg() : flag(false) {}
    bool_arg(bool b) : flag(b) {}
    bool_arg(const bool_arg &obj) : flag(obj.flag) {}

    bool_arg &operator=(const bool &obj) {
        flag = obj;
        return *this;
    }
    bool_arg &operator=(const bool_arg &obj) {
        flag = obj.flag;
        return *this;
    }

    operator bool() const {
        return flag;
    }
};

namespace args_bool
{
    extern bool_arg fUseMemoryLog;//(false);
    extern bool_arg fConfChange;//(false);
    extern bool_arg fUseFastIndex;//(false);
    extern bool_arg fNoListen;//(false);
    extern bool_arg fDebug;//(false);
    extern bool_arg fDebugNet;//(false);
    extern bool_arg fPrintToConsole;//(false);
    extern bool_arg fPrintToDebugger;//(false);
    extern bool_arg fRequestShutdown;//(false);
    extern bool_arg fShutdown;//(false)
    extern bool_arg fDaemon;//(false)
    extern bool_arg fServer;//(false)
    extern bool_arg fCommandLine;//(false)
    extern bool_arg fTestNet;//(false)
    extern bool_arg fLogTimestamps;//(false)
    extern bool_arg fReopenDebugLog;//(false)
}

namespace args_uint
{
    extern unsigned int nNodeLifespan;// = 0;
}

//
// This GNU C extension enables the compiler to check the format string against the parameters provided.
// X is the number of the "format string" parameter, and Y is the number of the first variadic parameter.
// Parameters count from 1.
//
#ifdef __GNUC__
 #define ATTR_WARN_PRINTF(X,Y) __attribute__((format(printf,X,Y)))
#else
 #define ATTR_WARN_PRINTF(X,Y)
#endif

//
// Redefine printf so that it directs output to debug.log
//

//
// Do this *after* defining the other printf-like functions, because otherwise the
// __attribute__((format(printf,X,Y))) gets expanded to __attribute__((format(print::OutputDebugStringF,X,Y)))
// which confuses gcc.
//
// #define printf print::OutputDebugStringF => gcc confused in this place. under, namespace print.
//

class trace : private no_instance
{
private:
    static FILE *_fileout;

protected:
    static FILE *get_fileout() { return _fileout; }
    static void set_fileout(FILE *f) { _fileout = f; }

public:
    static void LogStackTrace();
};

class print : public trace
{
public:
    static int ATTR_WARN_PRINTF(1,2) OutputDebugStringF(const char *pszFormat, ...);
    static std::string vstrprintf(const char *format, va_list ap);

    //
    // Rationale for the real_strprintf / strprintf construction:
    // It is not allowed to use va_start with a pass-by-reference argument. (C++ standard, 18.7, paragraph 3). 
    //
    // Use a dummy argument to work around this, and use a macro to keep similar semantics.
    //

    /** Overload strprintf for char*, so that GCC format type warnings can be given */
    static std::string ATTR_WARN_PRINTF(1,3) real_strprintf(const char *format, int dummy, ...);

    /** Overload strprintf for std::string, to be able to use it with _ (translation). This will not support GCC format type warnings (-Wformat) so be careful. */
    static std::string real_strprintf(const std::string &format, int dummy, ...);

    static bool ATTR_WARN_PRINTF(1,2) error(const char *format, ...);
};
#define printf(format, ...) print::OutputDebugStringF(format, ##__VA_ARGS__)
#define strprintf(format, ...) print::real_strprintf(format, 0, __VA_ARGS__)

//
// C-Runtime overload
//
inline std::string i64tostr(int64_t n)
{
    return strprintf("%" PRId64, n);
}

inline std::string itostr(int n)
{
    return strprintf("%d", n);
}

inline int64_t atoi64(const char *psz)
{
#ifdef _MSC_VER
    return ::_atoi64(psz);
#else
    return ::strtoll(psz, NULL, 10);
#endif
}

inline int64_t atoi64(const std::string &str)
{
#ifdef _MSC_VER
    return ::_atoi64(str.c_str());
#else
    return ::strtoll(str.c_str(), NULL, 10);
#endif
}

inline int32_t strtol(const char *psz)
{
    return ::strtol(psz, NULL, 10);
}

inline int32_t strtol(const std::string &str)
{
    return ::strtol(str.c_str(), NULL, 10);
}

inline uint32_t strtoul(const char *psz)
{
    return ::strtoul(psz, NULL, 10);
}

inline uint32_t strtoul(const std::string &str)
{
    return ::strtoul(str.c_str(), NULL, 10);
}

inline int atoi(const std::string &str)
{
    return ::atoi(str.c_str());
}

//
// API overload
//
inline int64_t GetPerformanceCounter()
{
    int64_t nCounter = 0;
#ifdef WIN32
    ::QueryPerformanceCounter((LARGE_INTEGER*)&nCounter);
#else
    timeval t;
    ::gettimeofday(&t, NULL);
    nCounter = (int64_t) t.tv_sec * 1000000 + t.tv_usec;
#endif
    return nCounter;
}

class excep : private no_instance
{
private:
    static std::string strMiscWarning;

    static std::string FormatException(const std::exception *pex, const char *pszThread) {
#ifdef WIN32
        char pszModule[MAX_PATH] = "";
        ::GetModuleFileNameA(NULL, pszModule, sizeof(pszModule));
#else
        const char *pszModule = coin_param::strCoinName.c_str();
#endif
        if (pex) {
            return strprintf("EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(), pszModule, pszThread);
        } else {
            return strprintf("UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, pszThread);
        }
    }

public:
    static std::string &get_strMiscWarning() {
        return excep::strMiscWarning;
    }
    static void set_strMiscWarning(const std::string &str) {
        strMiscWarning = str;
    }
    static void LogException(const std::exception *pex, const char *pszThread) {
        std::string message = excep::FormatException(pex, pszThread);
        printf("\n%s", message.c_str());
    }
    static void PrintException(const std::exception *pex, const char *pszThread) {
        excep::PrintExceptionContinue(pex, pszThread);
        throw;
    }
    static void PrintExceptionContinue(const std::exception *pex, const char *pszThread) {
        std::string message = excep::FormatException(pex, pszThread);
        printf("\n\n************************\n%s\n", message.c_str());
        ::fprintf(stderr, "\n\n************************\n%s\n", message.c_str());
        strMiscWarning = message;
    }
};

#ifdef CSCRIPT_PREVECTOR_ENABLE
typedef prevector<PREVECTOR_N, uint8_t> util_vector;
#else
typedef std::vector<uint8_t> util_vector;
#endif

namespace util
{
    const int32_t nOneHour = 60 * 60;
    const int32_t nOneDay = 24 * 60 * 60;
    const int64_t nOneWeek = 7 * 24 * 60 * 60;

    const int64_t COIN = 1000000;
    const int64_t CENT = 10000;

    // Align by increasing pointer, must have extra space at end of buffer
    /*
    template <size_t nBytes, typename T>
    static T *alignup(T *p) {
        union
        {
            T *ptr;
            size_t n;
        } u;
        u.ptr = p;
        u.n = (u.n + (nBytes-1)) & ~(nBytes-1);
        return u.ptr;
    }
    */

#ifdef WIN32 // Windows MAX_PATH 256, ::Sleep(msec)
 #define MSG_NOSIGNAL        0
 #define MSG_DONTWAIT        0

 #ifndef S_IRUSR
  #define S_IRUSR            0400
  #define S_IWUSR            0200
 #endif
 inline void Sleep(int64_t n) {
     ::Sleep(n);
 }
#else
 #define MAX_PATH            1024
    inline void Sleep(int64_t n) {
        //
        // Boost has a year 2038 problem— if the request sleep time is past epoch+2^31 seconds the sleep returns instantly. 
        // So we clamp our sleeps here to 10 years and hope that boost is fixed by 2028.
        //
        boost::thread::sleep(boost::get_system_time() + boost::posix_time::milliseconds(n>315576000000LL?315576000000LL:n));
    }
#endif

    inline void MilliSleep(int64_t n) {
#if BOOST_VERSION >= 105000
        boost::this_thread::sleep_for(boost::chrono::milliseconds(n));
#else
        boost::this_thread::sleep(boost::posix_time::milliseconds(n));
#endif
    }

    inline int roundint(double d) {
        return (int)(d > 0 ? d + 0.5 : d - 0.5);
    }

    inline int64_t roundint64(double d) {
        return (int64_t)(d > 0 ? d + 0.5 : d - 0.5);
    }

    inline int64_t abs64(int64_t n) {
        return (n >= 0 ? n : -n);
    }

    inline std::string leftTrim(std::string src, char chr) {
        std::string::size_type pos = src.find_first_not_of(chr, 0);
        if(pos > 0) {
            src.erase(0, pos);
        }
        return src;
    }

    template<typename T>
    inline std::string HexStr(const T itbegin, const T itend, bool fSpaces=false) {
        std::string rv;
        static const char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                         '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
        rv.reserve((itend - itbegin) * 3);
        for(T it = itbegin; it < itend; ++it)
        {
            unsigned char val = (unsigned char)(*it);
            if(fSpaces && it != itbegin) {
                rv.push_back(' ');
            }

            rv.push_back(hexmap[val >> 4]);
            rv.push_back(hexmap[val & 15]);
        }

        return rv;
    }

    inline std::string HexStr(const util_vector &vch, bool fSpaces=false) {
        return util::HexStr(vch.begin(), vch.end(), fSpaces);
    }

    template<typename T>
    inline void PrintHex(const T pbegin, const T pend, const char *pszFormat="%s", bool fSpaces=true) {
        printf(pszFormat, util::HexStr(pbegin, pend, fSpaces).c_str());
    }

    inline void PrintHex(const util_vector &vch, const char *pszFormat="%s", bool fSpaces=true) {
        printf(pszFormat, util::HexStr(vch, fSpaces).c_str());
    }

    inline int64_t GetTimeMillis() {
        return (boost::posix_time::microsec_clock::universal_time() -
                boost::posix_time::ptime(boost::gregorian::date(1970,1,1))).total_milliseconds();
    }

    inline int64_t GetTimeMicros() {
        return (boost::posix_time::microsec_clock::universal_time() -
                boost::posix_time::ptime(boost::gregorian::date(1970,1,1))).total_microseconds();
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
        return (value<<16) | (value>>16);
    }
}

//
// Median filter over a stream of values.
// Returns the median of the last N numbers
//
template <typename T> class CMedianFilter
{
private:
    CMedianFilter(const CMedianFilter &); // {}
    CMedianFilter &operator=(const CMedianFilter &); // {}

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
        if(vValues.size() == nSize) {
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
        if(size & 1) {    // Odd number of elements
            return vSorted[size / 2];
        } else {        // Even number of elements
            return (vSorted[size / 2 - 1] + vSorted[size / 2]) / 2;
        }
    }

    int size() const {
        return static_cast<int>(vValues.size());
    }

    std::vector<T> sorted () const {
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
        if (util::abs64(nNodesOffset) < 70 * 60) {    // If not, then choose between median peer time and system clock.
            return nNodesOffset;
        }
        return 0;
    }

    static CMedianFilter<int64_t> vTimeOffsets;//(200,0);

public:
    //
    // "Never go to sea with two chronometers; take one or three."
    // Our three time sources are:
    //  - System clock
    //  - Median of other nodes clocks
    //  - The user (asking the user to fix the system clock if the first two disagree)
    //
    static int64_t GetTime() {
        int64_t now = ::time(NULL);
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
        uint64_t nRange = (std::numeric_limits<uint64_t>::max() / nMax) * nMax;
        uint64_t nRand = 0;
        do
        {
            RAND_bytes((unsigned char *)&nRand, sizeof(nRand));
        } while (nRand >= nRange);

        return (nRand % nMax);
    }
    static uint256 GetRandHash() {
        uint256 hash;
        RAND_bytes((unsigned char *)&hash, sizeof(hash));
        return hash;
    }
    static int64_t GetNodesOffset() {
        return nNodesOffset;
    }

    static void AddTimeData(const CNetAddr &ip, int64_t nTime);
};

namespace bitstr
{
    inline void ParseString(const std::string &str, char c, std::vector<std::string> &v) {
        if (str.empty()) {
            return;
        }

        std::string::size_type i1 = 0;
        std::string::size_type i2;
        for ( ; ; )
        {
            i2 = str.find(c, i1);
            if (i2 == str.npos) {
                v.push_back(str.substr(i1));
                return;
            }
            v.push_back(str.substr(i1, i2 - i1));
            i1 = i2 + 1;
        }
    }
    inline std::string FormatMoney(int64_t n, bool fPlus=false) {
        // Note: not using straight sprintf here because we do NOT want
        // localized number formatting.
        int64_t n_abs = (n > 0 ? n : -n);
        int64_t quotient = n_abs / util::COIN;
        int64_t remainder = n_abs % util::COIN;
        std::string str = strprintf("%" PRId64 ".%06" PRId64, quotient, remainder);

        // Right-trim excess zeros before the decimal point:
        size_t nTrim = 0;
        for (size_t i = str.size() - 1; (str[i] == '0' && isdigit(str[i - 2])); --i)
        {
            ++nTrim;
        }
        if (nTrim) {
            str.erase(str.size() - nTrim, nTrim);
        }

        if (n < 0) {
            str.insert(0u, 1, '-');
        } else if (fPlus && n > 0) {
            str.insert(0u, 1, '+');
        }

        return str;
    }
    inline bool ParseMoney(const std::string &str, int64_t &nRet) {
        return bitstr::ParseMoney(str.c_str(), nRet);
    }
    inline bool ParseMoney(const char *pszIn, int64_t &nRet) {
        std::string strWhole;
        int64_t nUnits = 0;

        const char *p = pszIn;
        while (::isspace(*p))
        {
            ++p;
        }
        for (; *p; p++)
        {
            if (*p == '.') {
                ++p;
                int64_t nMult = util::CENT * 10;
                while (::isdigit(*p) && (nMult > 0))
                {
                    nUnits += nMult * (*p++ - '0');
                    nMult /= 10;
                }
                break;
            }
            if (::isspace(*p)) {
                break;
            }
            if (! ::isdigit(*p)) {
                return false;
            }
            strWhole.insert(strWhole.end(), *p);
        }
        for (; *p; p++)
        {
            if (! ::isspace(*p)) {
                return false;
            }
        }
        if (strWhole.size() > 10) { // guard against 63 bit overflow
            return false;
        }
        if (nUnits < 0 || nUnits > util::COIN) {
            return false;
        }
        int64_t nWhole = ::atoi64(strWhole);
        int64_t nValue = nWhole * util::COIN + nUnits;

        nRet = nValue;
        return true;
    }
}

#ifdef CSCRIPT_PREVECTOR_ENABLE
typedef prevector<PREVECTOR_N, uint8_t> hex_vector;
#else
typedef std::vector<uint8_t> hex_vector;
#endif

class hex : private no_instance
{
private:
    static const signed char phexdigit[256];

public:
    static hex_vector ParseHex(const char *psz) {
        // convert hex dump to vector
        hex_vector vch;
        for ( ; ; )
        {
            while (::isspace(*psz))
            {
                psz++;
            }

            signed char c = phexdigit[(unsigned char)*psz++];
            if (c == (signed char)-1) {
                break;
            }

            unsigned char n = (c << 4);
            c = phexdigit[(unsigned char)*psz++];
            if (c == (signed char)-1) {
                break;
            }

            n |= c;
            vch.push_back(n);
        }
        return vch;
    }
    static hex_vector ParseHex(const std::string &str) {
        return hex::ParseHex(str.c_str());
    }
    static bool IsHex(const std::string &str) {
        BOOST_FOREACH(unsigned char c, str)
        {
            if (hex::phexdigit[c] < 0) {
                return false;
            }
        }
        return (str.size() > 0) && (str.size() % 2 == 0);
    }
};

namespace base64
{
    std::vector<unsigned char> DecodeBase64(const char *p, bool *pfInvalid = NULL);
    std::string DecodeBase64(const std::string &str);

    std::string EncodeBase64(const unsigned char *pch, size_t len);
    std::string EncodeBase64(const std::string &str);
}

namespace base32
{
    std::vector<unsigned char> DecodeBase32(const char *p, bool *pfInvalid = NULL);
    std::string DecodeBase32(const std::string &str);

    std::string EncodeBase32(const unsigned char *pch, size_t len);
    std::string EncodeBase32(const std::string &str);
}

class dump : private no_instance
{
private:
    static const std::locale formats[5];

    static std::time_t pt_to_time_t(const boost::posix_time::ptime &pt) {
        boost::posix_time::ptime timet_start(boost::gregorian::date(1970,1,1));
        boost::posix_time::time_duration diff = pt - timet_start;
        return diff.ticks() / boost::posix_time::time_duration::rep_type::ticks_per_second;
    }

public:
    static std::string EncodeDumpTime(int64_t nTime);
    static int64_t DecodeDumpTime(const std::string &s);
    static std::string EncodeDumpString(const std::string &str);
    static std::string DecodeDumpString(const std::string &str);
};

namespace match
{
    bool WildcardMatch(const char *psz, const char *mask);
    bool WildcardMatch(const std::string &str, const std::string &mask);
}

class init : private no_instance
{
protected: // to class config
    static void InterpretNegativeSetting(std::string name, std::map<std::string, std::string> &mapSettingsRet);
};

class iofs : private no_instance
{
public:
#ifdef WIN32
    static boost::filesystem::path GetSpecialFolderPath(int nFolder, bool fCreate = true);
#endif

    static void FileCommit(FILE *fileout);
    static int GetFilesize(FILE *file);
    static bool RenameOver(boost::filesystem::path src, boost::filesystem::path dest);
    static boost::filesystem::path GetDefaultDataDir();
    static const boost::filesystem::path &GetDataDir(bool fNetSpecific = true);
    static boost::filesystem::path GetConfigFile();
    static boost::filesystem::path GetPidFile();
#ifndef WIN32
    static void CreatePidFile(const boost::filesystem::path &path, pid_t pid);
#endif

    static void ShrinkDebugFile();
};

class config : public init
{
private:
    static void createConf();
    static std::string randomStrGen(int length);
protected:    // to class map_arg
    static void ReadConfigFile(std::map<std::string, std::string> &mapSettingsRet, std::map<std::string, std::vector<std::string> > &mapMultiSettingsRet);
};

class CInit;
class seed : private no_instance
{
    friend class CInit;

private:
    static void RandAddSeed();
public:
    static void RandAddSeedPerfmon();
};

class format_version : private no_instance
{
private:
    static std::string FormatVersion(int nVersion);
public:
    static std::string FormatFullVersion();
    static std::string FormatSubVersion(const std::string &name, int nClientVersion, const std::vector<std::string> &comments);
};

namespace cmd
{
    void runCommand(std::string strCommand);
}

#define BEGIN(a)            ((char *)&(a))
#define END(a)              ((char *)&((&(a))[1]))
#define UBEGIN(a)           ((unsigned char *)&(a))
#define UEND(a)             ((unsigned char *)&((&(a))[1]))
#define ARRAYLEN(array)     (sizeof(array)/sizeof((array)[0]))

#define UVOIDBEGIN(a)       ((void *)&(a))
#define CVOIDBEGIN(a)       ((const void *)&(a))
#define UINTBEGIN(a)        ((uint32_t *)&(a))
#define CUINTBEGIN(a)       ((const uint32_t *)&(a))

#ifndef THROW_WITH_STACKTRACE
#define THROW_WITH_STACKTRACE(exception)  \
{                                         \
    trace::LogStackTrace();               \
    throw (exception);                    \
}
#endif

#if defined(_MSC_VER) || defined(__MSVCRT__)
 /* Silence compiler warnings on Windows related to MinGWs inttypes.h */
 #undef PRIu64
 #undef PRId64
 #undef PRIx64

 #define PRIu64 "I64u"
 #define PRId64 "I64d"
 #define PRIx64 "I64x"
#endif

/* Format characters for (s)size_t and ptrdiff_t */
#if defined(_MSC_VER) || defined(__MSVCRT__)
  /* (s)size_t and ptrdiff_t have the same size specifier in MSVC:
     http://msdn.microsoft.com/en-us/library/tcxf1dw6%28v=vs.100%29.aspx
   */
  #define PRIszx    "Ix"
  #define PRIszu    "Iu"
  #define PRIszd    "Id"
  #define PRIpdx    "Ix"
  #define PRIpdu    "Iu"
  #define PRIpdd    "Id"
#else /* C99 standard */
  #define PRIszx    "zx"
  #define PRIszu    "zu"
  #define PRIszd    "zd"
  #define PRIpdx    "tx"
  #define PRIpdu    "tu"
  #define PRIpdd    "td"
#endif

// This is needed because the foreach macro can't get over the comma in pair<t1, t2>
#define PAIRTYPE(t1, t2)    std::pair<t1, t2>

//
// Return : string argument or default(arg) value
//
class map_arg : public config
{
private:
    static std::map<std::string, std::string> mapArgs;
    static std::map<std::string, std::vector<std::string> > mapMultiArgs;

public:

    /**
     * Read argv[]
     */
    static void ParseParameters(int argc, const char *const argv[]);

    /**
     * ReadConfigFile (bitcoin.cpp)
     */
    static void ReadConfigFile() {
        config::ReadConfigFile(mapArgs, mapMultiArgs);
    }

    /**
     * mapArgs interface
     */
    static size_t GetMapArgsCount(const std::string &target) {
        return mapArgs.count(target);
    }
    static std::string GetMapArgsString(const std::string &key) {
        return mapArgs[key];
    }
    static void SetMapArgsString(const std::string &key, const std::string &value) {
        mapArgs[key] = value;
    }

    /**
     * mapMultiArgs interface
     */
    static std::vector<std::string> GetMapMultiArgsString(const std::string &key) {
        return mapMultiArgs[key];
    }

    /**
     * Return string argument or default value
     *
     * @param strArg Argument to get (e.g. "-foo")
     * @param default (e.g. "1")
     * @return command-line argument or default value
     */
    static std::string GetArg(const std::string &strArg, const std::string &strDefault) {
        if (mapArgs.count(strArg)) {
            return mapArgs[strArg];
        }
        return strDefault;
    }

    /**
     * Return 64-bit integer argument or default value
     *
     * @param strArg Argument to get (e.g. "-foo")
     * @param default (e.g. 1)
     * @return command-line argument (0 if invalid number) or default value
     */
    static int64_t GetArg(const std::string &strArg, int64_t nDefault) {
        if (mapArgs.count(strArg)) {
            return ::atoi64(mapArgs[strArg]);
        }
        return nDefault;
    }

    /**
     * Return 32-bit integer argument or default value
     *
     * @param strArg Argument to get (e.g. "-foo")
     * @param default (e.g. 1)
     * @return command-line argument (0 if invalid number) or default value
     */
    static int32_t GetArgInt(const std::string &strArg, int32_t nDefault) {
        if (mapArgs.count(strArg)) {
            return ::strtol(mapArgs[strArg]);
        }
        return nDefault;
    }

    /**
     * Return 32-bit unsigned integer argument or default value
     *
     * @param strArg Argument to get (e.g. "-foo")
     * @param default (e.g. 1)
     * @return command-line argument (0 if invalid number) or default value
     */
    static uint32_t GetArgUInt(const std::string &strArg, uint32_t nDefault) {
        if (mapArgs.count(strArg)) {
            return ::strtoul(mapArgs[strArg]);
        }
        return nDefault;
    }

    /**
     * Return boolean argument or default value
     *
     * @param strArg Argument to get (e.g. "-foo")
     * @param default (true or false)
     * @return command-line argument or default value
     */
    static bool GetBoolArg(const std::string &strArg, bool fDefault=false) {
        if (mapArgs.count(strArg)) {
            if (mapArgs[strArg].empty()) {
                return true;
            }
            return (::atoi(mapArgs[strArg]) != 0);
        }
        return fDefault;
    }

    /**
     * Set an argument if it doesn't already have a value
     *
     * @param strArg Argument to set (e.g. "-foo")
     * @param strValue Value (e.g. "1")
     * @return true if argument gets set, false if it already had a value
     */
    static bool SoftSetArg(const std::string &strArg, const std::string &strValue) {
        if (mapArgs.count(strArg) || mapMultiArgs.count(strArg)) {
            return false;
        }
        mapArgs[strArg] = strValue;
        mapMultiArgs[strArg].push_back(strValue);
        return true;
    }

    /**
     * Set a boolean argument if it doesn't already have a value
     *
     * @param strArg Argument to set (e.g. "-foo")
     * @param fValue Value (e.g. false)
     * @return true if argument gets set, false if it already had a value
     */
    static bool SoftSetBoolArg(const std::string &strArg, bool fValue) {
        if (fValue) {
            return map_arg::SoftSetArg(strArg, std::string("1"));
        } else {
            return map_arg::SoftSetArg(strArg, std::string("0"));
        }
    }

    /**
     * Timing-attack-resistant comparison.
     * Takes time proportional to length
     * of first argument.
     */
    template <typename T>
    static bool TimingResistantEqual(const T &a, const T &b) {
        if (b.size() == 0) {
            return a.size() == 0;
        }
        
        size_t accumulator = a.size() ^ b.size();
        for (size_t i = 0; i < a.size(); ++i)
        {
            accumulator |= a[i] ^ b[i % b.size()];
        }
        
        return accumulator == 0;
    }
};

namespace bitthread
{
    class manage : private no_instance
    {
    public:
        static bool NewThread(void (*pfn)(void *), void *parg) {
            try {
                boost::thread(pfn, parg); // thread detaches when out of scope
            } catch (boost::thread_resource_error &e) {
                printf("Error creating thread: %s\n", e.what());
                return false;
            }

            return true;
        }

#ifdef WIN32
        static void SetThreadPriority(int nPriority) {
            ::SetThreadPriority(::GetCurrentThread(), nPriority);
        }
        static void ExitThread(size_t nExitCode) {
            ::ExitThread(nExitCode);
        }
#else
 #define THREAD_PRIORITY_LOWEST          PRIO_MAX
 #define THREAD_PRIORITY_BELOW_NORMAL    2
 #define THREAD_PRIORITY_NORMAL          0
 #define THREAD_PRIORITY_ABOVE_NORMAL    0

        static void SetThreadPriority(int nPriority) {
        //
        // It's unclear if it's even possible to change thread priorities on Linux,
        // but we really and truly need it for the generation threads.
        //
 #ifdef PRIO_THREAD
            ::setpriority(PRIO_THREAD, 0, nPriority);
 #else
            ::setpriority(PRIO_PROCESS, 0, nPriority);
 #endif
        }
        static void ExitThread(size_t nExitCode) {
            ::pthread_exit((void *)nExitCode);
        }
#endif

        static void RenameThread(const char *name) {
#if defined(PR_SET_NAME)
            //
            // Only the first 15 characters are used (16 - NUL terminator)
            //
            ::prctl(PR_SET_NAME, name, 0, 0, 0);
#elif 0 && (defined(__FreeBSD__) || defined(__OpenBSD__))
            //
            // TODO: This is currently disabled because it needs to be verified to work
            //       on FreeBSD or OpenBSD first. When verified the '0 &&' part can be
            //       removed.
            //
            ::pthread_set_name_np(pthread_self(), name);

            //
            // This is XCode 10.6-and-later; bring back if we drop 10.5 support:
            //
            // #elif defined(MAC_OSX)
            // ::pthread_setname_np(name);
#else
            // Prevent warnings for unused parameters...
            (void)name;
#endif
        }
    };
}

#endif
//@
