// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "sync.h"
#include "version.h"
#include "ui_interface.h"
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()

// Work around clang compilation problem in Boost 1.46:
// /usr/include/boost/program_options/detail/config_file.hpp:163:17: error: call to function 'to_internal' that is neither visible in the template definition nor found by argument-dependent lookup
// See also: http://stackoverflow.com/questions/10020179/compilation-fail-in-boost-librairies-program-options
//           http://clang.debian.net/status.php?version=3.0&key=CANNOT_FIND_FUNCTION
namespace boost {
    namespace program_options {
        std::string to_internal(const std::string &);
    }
}

#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <boost/thread.hpp>
#include <openssl/crypto.h>

#ifdef WIN32
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501
#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501
#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h> /* for _commit */
#include "shlobj.h"
#elif defined(__linux__)
# include <sys/prctl.h>
#endif

#if !defined(WIN32) && !defined(ANDROID)
#include <execinfo.h>
#endif

FILE *trace::_fileout = NULL;
std::string excep::strMiscWarning;
std::map<std::string, std::string> map_arg::mapArgs;
std::map<std::string, std::vector<std::string> > map_arg::mapMultiArgs;
int64_t bitsystem::nNodesOffset = INT64_MAX;
const signed char hex::phexdigit[256] =
{ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, };
// Extended dump::DecodeDumpTime implementation, see this page for details:
// http://stackoverflow.com/questions/3786201/parsing-of-date-time-from-string-boost
const std::locale dump::formats[5] = {
    std::locale(std::locale::classic(),new boost::posix_time::time_input_facet("%Y-%m-%dT%H:%M:%SZ")),
    std::locale(std::locale::classic(),new boost::posix_time::time_input_facet("%Y-%m-%d %H:%M:%S")),
    std::locale(std::locale::classic(),new boost::posix_time::time_input_facet("%Y/%m/%d %H:%M:%S")),
    std::locale(std::locale::classic(),new boost::posix_time::time_input_facet("%d.%m.%Y %H:%M:%S")),
    std::locale(std::locale::classic(),new boost::posix_time::time_input_facet("%Y-%m-%d"))
};
LockedPageManager LockedPageManager::instance;    // allocators.h (Singleton class)
unsigned char block_info::gpchMessageStart[4] = { 0xe4, 0xe8, 0xe9, 0xe5 };
bool_arg args_bool::fUseMemoryLog(false);
bool_arg args_bool::fConfChange(false);
bool_arg args_bool::fUseFastIndex(false);
bool_arg args_bool::fNoListen(false);
bool_arg args_bool::fDebug(false);
bool_arg args_bool::fDebugNet(false);
bool_arg args_bool::fPrintToConsole(false);
bool_arg args_bool::fPrintToDebugger(false);
bool_arg args_bool::fRequestShutdown(false);
bool_arg args_bool::fShutdown(false);
bool_arg args_bool::fDaemon(false);
bool_arg args_bool::fServer(false);
bool_arg args_bool::fCommandLine(false);
bool_arg args_bool::fTestNet(false);
bool_arg args_bool::fLogTimestamps(false);
bool_arg args_bool::fReopenDebugLog(false);
unsigned int args_uint::nNodeLifespan = 0;
CMedianFilter<int64_t> bitsystem::vTimeOffsets(200,0);

//
// Init
//
class CInit
{
private:
    static CInit instance_of_cinit;

private:
    CInit(const CInit &); // {}
    CInit &operator=(const CInit &); // {}

    // Init OpenSSL library multithreading support
    static CCriticalSection **ppmutexOpenSSL;

    static void locking_callback(int mode, int i, const char *file, int line) {
        if (mode & CRYPTO_LOCK) {
            ENTER_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
        } else {
            LEAVE_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
        }
    }

private:
    CInit() {
        // Init OpenSSL library multithreading support
        ppmutexOpenSSL = (CCriticalSection **)OPENSSL_malloc(::CRYPTO_num_locks() * sizeof(CCriticalSection *));
        if(! ppmutexOpenSSL) {
            throw std::runtime_error("CInit OPENSSL_malloc bad allocate.");
        }

        try {
            for (int i = 0; i < CRYPTO_num_locks(); ++i)
            {
                ppmutexOpenSSL[i] = new CCriticalSection();
            }
            ::CRYPTO_set_locking_callback(locking_callback);

#ifdef WIN32
            // Seed random number generator with screen scrape and other hardware sources
            //RAND_screen();
            RAND_poll();
#endif

            // Seed random number generator with performance counter
            seed::RandAddSeed();
        } catch (const std::bad_alloc &) {
            throw std::runtime_error("CInit memory bad allocate.");
        }
    }

    ~CInit() {
        // Shutdown OpenSSL library multithreading support
        ::CRYPTO_set_locking_callback(NULL);
        for (int i = 0; i < ::CRYPTO_num_locks(); ++i)
        {
            delete ppmutexOpenSSL[i];
        }
        OPENSSL_free(ppmutexOpenSSL);
    }
};
CCriticalSection **CInit::ppmutexOpenSSL = NULL;
CInit CInit::instance_of_cinit;

///////////////////////////////////////////////////////////////////////////////////////////////////

void seed::RandAddSeed()
{
    // Seed with CPU performance counter
    int64_t nCounter = ::GetPerformanceCounter();
    RAND_add(&nCounter, sizeof(nCounter), 1.5);
    ::memset(&nCounter, 0, sizeof(nCounter));
}

void seed::RandAddSeedPerfmon()
{
    seed::RandAddSeed();

    // This can take up to 2 seconds, so only do it every 10 minutes
    static int64_t nLastPerfmon = 0;
    if (bitsystem::GetTime() < nLastPerfmon + 10 * 60) {
        return;
    }

    nLastPerfmon = bitsystem::GetTime();

#ifdef WIN32
    // Don't need this on Linux, OpenSSL automatically uses /dev/urandom
    // Seed with the entire set of perfmon data
    unsigned char pdata[250000] = { 0 };
    unsigned long nSize = sizeof(pdata);
    long ret = ::RegQueryValueExA(HKEY_PERFORMANCE_DATA, "Global", NULL, NULL, pdata, &nSize);
    ::RegCloseKey(HKEY_PERFORMANCE_DATA);
    if (ret == ERROR_SUCCESS) {
        RAND_add(pdata, nSize, nSize / 100.0);
        OPENSSL_cleanse(pdata, nSize);
        printf("seed::RandAddSeed() %lu bytes\n", nSize);
    }
#endif
}

void trace::LogStackTrace()
{
    printf("\n\n******* exception encountered *******\n");
    if (trace::_fileout) {
#if !defined(WIN32) && !defined(ANDROID) && !defined(__unix__)
        void *pszBuffer[32];
        size_t size;
        size = ::backtrace(pszBuffer, 32);
        ::backtrace_symbols_fd(pszBuffer, size, ::fileno(trace::_fileout));
#endif
    }
}

int print::OutputDebugStringF(const char *pszFormat, ...)
{
    int ret = 0;
    if (args_bool::fPrintToConsole) {
        // print to console
        va_list arg_ptr;
        va_start(arg_ptr, pszFormat);
        ret = vprintf(pszFormat, arg_ptr);
        va_end(arg_ptr);
    } else if (! args_bool::fPrintToDebugger) {
        // print to debug.log

        if (! trace::get_fileout()) {
            boost::filesystem::path pathDebug = iofs::GetDataDir() / "debug.log";
            trace::set_fileout(fopen(pathDebug.string().c_str(), "a"));
            if (trace::get_fileout()) { ::setbuf(trace::get_fileout(), NULL); } // unbuffered
        }

        if (trace::get_fileout()) {
            static bool fStartedNewLine = true;
            
            //
            // This routine may be called by global destructors during shutdown.
            // Since the order of destruction of static/global objects is undefined,
            // allocate mutexDebugLog on the heap the first time this routine
            // is called to avoid crashes during shutdown.
            //
            static boost::mutex *mutexDebugLog = NULL;
            if (mutexDebugLog == NULL) {
                mutexDebugLog = new boost::mutex();
            }
            boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

            // reopen the log file, if requested
            if (args_bool::fReopenDebugLog) {
                args_bool::fReopenDebugLog = false;
                boost::filesystem::path pathDebug = iofs::GetDataDir() / "debug.log";
                if (::freopen(pathDebug.string().c_str(),"a",trace::get_fileout()) != NULL) {
                    ::setbuf(trace::get_fileout(), NULL); // unbuffered
                }
            }

            // Debug print useful for profiling
            if (args_bool::fLogTimestamps && fStartedNewLine) {
                ::fprintf(trace::get_fileout(), "%s ", util::DateTimeStrFormat("%x %H:%M:%S", bitsystem::GetTime()).c_str());
            }
            if (pszFormat[strlen(pszFormat) - 1] == '\n') {
                fStartedNewLine = true;
            } else {
                fStartedNewLine = false;
            }

            va_list arg_ptr;
            va_start(arg_ptr, pszFormat);
            ret = ::vfprintf(trace::get_fileout(), pszFormat, arg_ptr);
            va_end(arg_ptr);
        }
    }

#ifdef WIN32
    if (args_bool::fPrintToDebugger) {
        static CCriticalSection cs_OutputDebugStringF;

        // accumulate and output a line at a time
        {
            LOCK(cs_OutputDebugStringF);
            static std::string buffer;

            va_list arg_ptr;
            va_start(arg_ptr, pszFormat);
            buffer += vstrprintf(pszFormat, arg_ptr);
            va_end(arg_ptr);

            size_t line_start = 0, line_end;
            while((line_end = buffer.find('\n', line_start)) != -1)
            {
                ::OutputDebugStringA(buffer.substr(line_start, line_end - line_start).c_str());
                line_start = line_end + 1;
            }
            buffer.erase(0, line_start);
        }
    }
#endif
    return ret;
}

std::string print::vstrprintf(const char *format, va_list ap)
{
    char buffer[50000];
    char *p = buffer;
    int limit = sizeof(buffer);
    int ret;
    for ( ; ; )
    {
#ifndef _MSC_VER
        va_list arg_ptr;
        va_copy(arg_ptr, ap);
#else
        va_list arg_ptr = ap;
#endif
#ifdef WIN32
        ret = _vsnprintf(p, limit, format, arg_ptr);
#else
        ret = vsnprintf(p, limit, format, arg_ptr);
#endif
        va_end(arg_ptr);
        if (ret >= 0 && ret < limit) {
            break;
        }
        if (p != buffer) {
            delete[] p;
        }

        limit *= 2;
        p = new(std::nothrow) char[limit];
        if (p == NULL) {
            throw std::bad_alloc();
        }
    }

    std::string str(p, p+ret);
    if (p != buffer) {
        delete[] p;
    }
    return str;
}

std::string print::real_strprintf(const char *format, int dummy, ...)
{
    va_list arg_ptr;
    va_start(arg_ptr, dummy);
    std::string str = print::vstrprintf(format, arg_ptr);
    va_end(arg_ptr);
    return str;
}

std::string print::real_strprintf(const std::string &format, int dummy, ...)
{
    va_list arg_ptr;
    va_start(arg_ptr, dummy);
    std::string str = print::vstrprintf(format.c_str(), arg_ptr);
    va_end(arg_ptr);
    return str;
}

bool print::error(const char *format, ...)
{
    va_list arg_ptr;
    va_start(arg_ptr, format);
    std::string str = print::vstrprintf(format, arg_ptr);
    va_end(arg_ptr);
    printf("ERROR: %s\n", str.c_str());
    return false;
}

void init::InterpretNegativeSetting(std::string name, std::map<std::string, std::string> &mapSettingsRet)
{
    // interpret -nofoo as -foo=0 (and -nofoo=0 as -foo=1) as long as -foo not set
    if (name.find("-no") == 0) {
        std::string positive("-");
        positive.append(name.begin() + 3, name.end());
        if (mapSettingsRet.count(positive) == 0) {
            bool value = !map_arg::GetBoolArg(name);
            mapSettingsRet[positive] = (value ? "1" : "0");
        }
    }
}

void map_arg::ParseParameters(int argc, const char *const argv[])
{
    mapArgs.clear();
    mapMultiArgs.clear();
    for (int i = 1; i < argc; i++)
    {
        std::string str(argv[i]);
        std::string strValue;
        size_t is_index = str.find('=');
        if (is_index != std::string::npos) {
            strValue = str.substr(is_index + 1);
            str = str.substr(0, is_index);
        }
#ifdef WIN32
        boost::to_lower(str);
        if (boost::algorithm::starts_with(str, "/")) {
            str = "-" + str.substr(1);
        }
#endif
        if (str[0] != '-') {
            break;
        }

        mapArgs[str] = strValue;
        mapMultiArgs[str].push_back(strValue);
    }

    // New 0.6 features:
    BOOST_FOREACH(const PAIRTYPE(std::string,std::string) &entry, mapArgs)
    {
        std::string name = entry.first;

        //  interpret --foo as -foo (as long as both are not set)
        if (name.find("--") == 0) {
            std::string singleDash(name.begin()+1, name.end());
            if (mapArgs.count(singleDash) == 0) {
                mapArgs[singleDash] = entry.second;
            }
            name = singleDash;
        }

        // interpret -nofoo as -foo=0 (and -nofoo=0 as -foo=1) as long as -foo not set
        init::InterpretNegativeSetting(name, mapArgs);
    }
}

std::string base64::EncodeBase64(const unsigned char *pch, size_t len)
{
    static const char *pbase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string strRet="";
    strRet.reserve((len+2)/3*4);

    int mode=0, left=0;
    const unsigned char *pchEnd = pch + len;
    while (pch < pchEnd)
    {
        int enc = *(pch++);
        switch (mode)
        {
        case 0: // we have no bits
            strRet += pbase64[enc >> 2];
            left = (enc & 3) << 4;
            mode = 1;
            break;

        case 1: // we have two bits
            strRet += pbase64[left | (enc >> 4)];
            left = (enc & 15) << 2;
            mode = 2;
            break;

        case 2: // we have four bits
            strRet += pbase64[left | (enc >> 6)];
            strRet += pbase64[enc & 63];
            mode = 0;
            break;
        }
    }

    if (mode) {
        strRet += pbase64[left];
        strRet += '=';
        if (mode == 1) {
            strRet += '=';
        }
    }

    return strRet;
}

std::string base64::EncodeBase64(const std::string &str)
{
    return base64::EncodeBase64((const unsigned char *)str.c_str(), str.size());
}

std::vector<unsigned char> base64::DecodeBase64(const char *p, bool *pfInvalid)
{
    static const int decode64_table[256] =
    {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1,
        -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
    };

    if (pfInvalid) {
        *pfInvalid = false;
    }

    std::vector<unsigned char> vchRet;
    vchRet.reserve(::strlen(p) * 3 / 4);

    int mode = 0;
    int left = 0;
    for ( ; ; )
    {
        int dec = decode64_table[(unsigned char)*p];
        if (dec == -1) { break; }

        ++p;
        switch (mode)
        {
        case 0: // we have no bits and get 6
            left = dec;
            mode = 1;
            break;

        case 1: // we have 6 bits and keep 4
            vchRet.push_back((left<<2) | (dec>>4));
            left = dec & 15;
            mode = 2;
            break;

        case 2: // we have 4 bits and get 6, we keep 2
            vchRet.push_back((left<<4) | (dec>>2));
            left = dec & 3;
            mode = 3;
            break;

        case 3: // we have 2 bits and get 6
            vchRet.push_back((left<<6) | dec);
            mode = 0;
            break;
        }
    }

    if (pfInvalid) {
        switch (mode)
        {
        case 0: // 4n base64 characters processed: ok
            break;

        case 1: // 4n+1 base64 character processed: impossible
            *pfInvalid = true;
            break;

        case 2: // 4n+2 base64 characters processed: require '=='
            if (left || p[0] != '=' || p[1] != '=' || decode64_table[(unsigned char)p[2]] != -1) {
                *pfInvalid = true;
            }
            break;

        case 3: // 4n+3 base64 characters processed: require '='
            if (left || p[0] != '=' || decode64_table[(unsigned char)p[1]] != -1) {
                *pfInvalid = true;
            }
            break;
        }
    }

    return vchRet;
}

std::string base64::DecodeBase64(const std::string &str)
{
    std::vector<unsigned char> vchRet = base64::DecodeBase64(str.c_str());
    return std::string((const char *)&vchRet[0], vchRet.size());
}

std::string base32::EncodeBase32(const unsigned char *pch, size_t len)
{
    static const char *pbase32 = "abcdefghijklmnopqrstuvwxyz234567";

    std::string strRet="";
    strRet.reserve((len + 4) / 5 * 8);

    int mode=0, left=0;
    const unsigned char *pchEnd = pch+len;
    while (pch<pchEnd)
    {
        int enc = *(pch++);
        switch (mode)
        {
        case 0: // we have no bits
            strRet += pbase32[enc >> 3];
            left = (enc & 7) << 2;
            mode = 1;
            break;

        case 1: // we have three bits
            strRet += pbase32[left | (enc >> 6)];
            strRet += pbase32[(enc >> 1) & 31];
            left = (enc & 1) << 4;
            mode = 2;
            break;

        case 2: // we have one bit
            strRet += pbase32[left | (enc >> 4)];
            left = (enc & 15) << 1;
            mode = 3;
            break;

        case 3: // we have four bits
            strRet += pbase32[left | (enc >> 7)];
            strRet += pbase32[(enc >> 2) & 31];
            left = (enc & 3) << 3;
            mode = 4;
            break;

        case 4: // we have two bits
            strRet += pbase32[left | (enc >> 5)];
            strRet += pbase32[enc & 31];
            mode = 0;
        }
    }

    static const int nPadding[5] = {0, 6, 4, 3, 1};
    if (mode) {
        strRet += pbase32[left];
        for (int n=0; n < nPadding[mode]; ++n)
        {
             strRet += '=';
        }
    }

    return strRet;
}

std::string base32::EncodeBase32(const std::string &str)
{
    return base32::EncodeBase32((const unsigned char *)str.c_str(), str.size());
}

std::vector<unsigned char> base32::DecodeBase32(const char *p, bool *pfInvalid)
{
    static const int decode32_table[256] =
    {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1,
        -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1,  0,  1,  2,
         3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
    };

    if (pfInvalid) {
        *pfInvalid = false;
    }

    std::vector<unsigned char> vchRet;
    vchRet.reserve((::strlen(p)) * 5 / 8);

    int mode = 0;
    int left = 0;
    for ( ; ; )
    {
        int dec = decode32_table[(unsigned char)*p];
        if (dec == -1) { break; }

        ++p;
        switch (mode)
        {
        case 0: // we have no bits and get 5
            left = dec;
            mode = 1;
            break;

        case 1: // we have 5 bits and keep 2
            vchRet.push_back((left<<3) | (dec>>2));
            left = dec & 3;
            mode = 2;
            break;

        case 2: // we have 2 bits and keep 7
            left = left << 5 | dec;
            mode = 3;
            break;

        case 3: // we have 7 bits and keep 4
            vchRet.push_back((left<<1) | (dec>>4));
            left = dec & 15;
            mode = 4;
            break;

        case 4: // we have 4 bits, and keep 1
            vchRet.push_back((left<<4) | (dec>>1));
            left = dec & 1;
            mode = 5;
            break;

        case 5: // we have 1 bit, and keep 6
            left = left << 5 | dec;
            mode = 6;
            break;

        case 6: // we have 6 bits, and keep 3
            vchRet.push_back((left<<2) | (dec>>3));
            left = dec & 7;
            mode = 7;
            break;

        case 7: // we have 3 bits, and keep 0
            vchRet.push_back((left<<5) | dec);
            mode = 0;
            break;
         }
    }

    if (pfInvalid) {
        switch (mode)
        {
        case 0: // 8n base32 characters processed: ok
            break;

        case 1: // 8n+1 base32 characters processed: impossible
        case 3: //   +3
        case 6: //   +6
            *pfInvalid = true;
            break;

        case 2: // 8n+2 base32 characters processed: require '======'
            if (left || p[0] != '=' || p[1] != '=' || p[2] != '=' || p[3] != '=' || p[4] != '=' || p[5] != '=' || decode32_table[(unsigned char)p[6]] != -1) {
                *pfInvalid = true;
            }
            break;

        case 4: // 8n+4 base32 characters processed: require '===='
            if (left || p[0] != '=' || p[1] != '=' || p[2] != '=' || p[3] != '=' || decode32_table[(unsigned char)p[4]] != -1) {
                *pfInvalid = true;
            }
            break;

        case 5: // 8n+5 base32 characters processed: require '==='
            if (left || p[0] != '=' || p[1] != '=' || p[2] != '=' || decode32_table[(unsigned char)p[3]] != -1) {
                *pfInvalid = true;
            }
            break;

        case 7: // 8n+7 base32 characters processed: require '='
            if (left || p[0] != '=' || decode32_table[(unsigned char)p[1]] != -1) {
                *pfInvalid = true;
            }
            break;
        }
    }

    return vchRet;
}

std::string base32::DecodeBase32(const std::string &str)
{
    std::vector<unsigned char> vchRet = base32::DecodeBase32(str.c_str());
    return std::string((const char *)&vchRet[0], vchRet.size());
}

int64_t dump::DecodeDumpTime(const std::string &s)
{
    boost::posix_time::ptime pt;

    size_t formats_n = sizeof(dump::formats) / sizeof(dump::formats[0]);
    for(size_t i=0; i < formats_n; ++i)
    {
        std::istringstream is(s);
        is.imbue(dump::formats[i]);
        is >> pt;
        if(pt != boost::posix_time::ptime()) { break; }
    }

    return dump::pt_to_time_t(pt);
}

std::string dump::EncodeDumpTime(int64_t nTime) {
    return util::DateTimeStrFormat("%Y-%m-%dT%H:%M:%SZ", nTime);
}

std::string dump::EncodeDumpString(const std::string &str) {
    std::stringstream ret;

    BOOST_FOREACH(unsigned char c, str)
    {
        if (c <= 32 || c >= 128 || c == '%') {
            ret << '%' << util::HexStr(&c, &c + 1);
        } else {
            ret << c;
        }
    }
    return ret.str();
}

std::string dump::DecodeDumpString(const std::string &str)
{
    std::stringstream ret;
    for (unsigned int pos = 0; pos < str.length(); ++pos)
    {
        unsigned char c = str[pos];
        if (c == '%' && pos + 2 < str.length()) {
            c = (((str[pos+1] >> 6) * 9 + ((str[pos+1] - '0')&15)) << 4) | 
                ((str[pos+2] >> 6) * 9+((str[pos+2]-'0')&15));
            pos += 2;
        }
        ret << c;
    }
    return ret.str();
}

bool match::WildcardMatch(const char *psz, const char *mask)
{
    for ( ; ; )
    {
        switch (*mask)
        {
        case '\0':
            return (*psz == '\0');
        case '*':
            return match::WildcardMatch(psz, mask+1) || (*psz && match::WildcardMatch(psz+1, mask));
        case '?':
            if (*psz == '\0') {
                return false;
            }
            break;
        default:
            if (*psz != *mask) {
                return false;
            }
            break;
        }
        psz++;
        mask++;
    }
}

bool match::WildcardMatch(const std::string &str, const std::string &mask)
{
    return match::WildcardMatch(str.c_str(), mask.c_str());
}

boost::filesystem::path iofs::GetDefaultDataDir()
{
    //
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\SorachanCoin
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\SorachanCoin
    // Mac: ~/Library/Application Support/SorachanCoin
    // Unix / Linux: ~/.SorachanCoin
    //
#ifdef WIN32
    //
    // Windows
    //
    return iofs::GetSpecialFolderPath(CSIDL_APPDATA) / coin_param::strCoinName.c_str();
#else
    boost::filesystem::path pathRet;
    char *pszHome = ::getenv("HOME");
    if (pszHome == NULL || ::strlen(pszHome) == 0) {
        pathRet = boost::filesystem::path("/");
    } else {
        pathRet = boost::filesystem::path(pszHome);
    }
 #ifdef MAC_OSX
    // Mac
    pathRet /= "Library/Application Support";
    boost::filesystem::create_directory(pathRet);
    return pathRet / coin_param::strCoinName.c_str();
 #else
    // Unix / Linux
    std::string dsora = ".";
    dsora += coin_param::strCoinName;
    return pathRet / dsora.c_str();
 #endif
#endif
}

const boost::filesystem::path &iofs::GetDataDir(bool fNetSpecific)
{
    static boost::filesystem::path pathCached[2];
    static CCriticalSection csPathCached;
    static bool cachedPath[2] = {false, false};

    boost::filesystem::path &path = pathCached[fNetSpecific];

    //
    // This can be called during exceptions by printf, so we cache the
    // value so we don't have to do memory allocations after that.
    //
    if (cachedPath[fNetSpecific]) {
        return path;
    }

    LOCK(csPathCached);

    if (map_arg::GetMapArgsCount("-datadir")) {
        path = boost::filesystem::system_complete(map_arg::GetMapArgsString("-datadir"));
        if (! boost::filesystem::is_directory(path)) {
            path = "";
            return path;
        }
    } else {
        path = iofs::GetDefaultDataDir();
    }

    if (fNetSpecific && map_arg::GetBoolArg("-testnet", false)) {
        path /= "testnet2";
    }

    boost::filesystem::create_directory(path);
    cachedPath[fNetSpecific]=true;

    return path;
}

std::string config::randomStrGen(int length)
{
    static std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

    std::string result;
    result.resize(length);
    for (int32_t i = 0; i < length; ++i)
    {
        result[i] = charset[::rand() % charset.length()];
    }

    return result;
}

void config::createConf()
{
    ::srand(static_cast<unsigned int>(::time(NULL)));

    std::ofstream pConf;
#if BOOST_FILESYSTEM_VERSION >= 3
    pConf.open(iofs::GetConfigFile().generic_string().c_str());
#else
    pConf.open(iofs::GetConfigFile().string().c_str());
#endif
    pConf << "rpcuser=sora\nrpcpassword="
            + config::randomStrGen(35)
            + "\n\ndaemon=0"
            + "\nserver=0"
            + "\ntestnet=0"
            + "\n\nlisten=1"
            + "\nirc=0"
            + "\n\nrpcallowip=127.0.0.1"
            + "\n";
    pConf.close();
}

boost::filesystem::path iofs::GetConfigFile()
{
    boost::filesystem::path pathConfigFile(map_arg::GetArg("-conf", (coin_param::strCoinName + ".conf").c_str()));
    if (! pathConfigFile.is_complete()) {
        pathConfigFile = iofs::GetDataDir(false) / pathConfigFile;
    }
    return pathConfigFile;
}

void config::ReadConfigFile(std::map<std::string, std::string> &mapSettingsRet, std::map<std::string, std::vector<std::string> > &mapMultiSettingsRet)
{
    boost::filesystem::ifstream streamConfig(iofs::GetConfigFile());
    if (! streamConfig.good()) {
        config::createConf();
        new(&streamConfig) boost::filesystem::ifstream(iofs::GetConfigFile());
        if(! streamConfig.good()) {
            return;
        }
    }

    std::set<std::string> setOptions;
    setOptions.insert("*");

    for (boost::program_options::detail::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it)
    {
        // Don't overwrite existing settings so command line settings override bitcoin.conf
        std::string strKey = std::string("-") + it->string_key;
        if (mapSettingsRet.count(strKey) == 0) {
            mapSettingsRet[strKey] = it->value[0];
            // interpret nofoo=1 as foo=0 (and nofoo=0 as foo=1) as long as foo not set)
            init::InterpretNegativeSetting(strKey, mapSettingsRet);
        }
        mapMultiSettingsRet[strKey].push_back(it->value[0]);
    }
}

boost::filesystem::path iofs::GetPidFile()
{
    boost::filesystem::path pathPidFile(map_arg::GetArg("-pid", (coin_param::strCoinName + ".pid").c_str()));
    if (! pathPidFile.is_complete()) { pathPidFile = iofs::GetDataDir() / pathPidFile; }
    return pathPidFile;
}

#ifndef WIN32
void iofs::CreatePidFile(const boost::filesystem::path &path, pid_t pid)
{
    FILE *file = ::fopen(path.string().c_str(), "w");
    if (file) {
        ::fprintf(file, "%d\n", pid);
        ::fclose(file);
    }
}
#endif

bool iofs::RenameOver(boost::filesystem::path src, boost::filesystem::path dest)
{
#ifdef WIN32
    return ::MoveFileExA(src.string().c_str(), dest.string().c_str(), MOVEFILE_REPLACE_EXISTING) != 0;
#else
    int rc = std::rename(src.string().c_str(), dest.string().c_str());
    return (rc == 0);
#endif
}

void iofs::FileCommit(FILE *fileout)
{
    ::fflush(fileout);        // harmless if redundantly called
#ifdef WIN32
    ::_commit(_fileno(fileout));
#else
    ::fsync(fileno(fileout));
#endif
}

int iofs::GetFilesize(FILE *file)
{
    int nSavePos = ftell(file);
    int nFilesize = -1;
    if (::fseek(file, 0, SEEK_END) == 0) {
        nFilesize = ftell(file);
    }

    ::fseek(file, nSavePos, SEEK_SET);
    return nFilesize;
}

void iofs::ShrinkDebugFile()
{
    // Scroll debug.log if it's getting too big
    boost::filesystem::path pathLog = iofs::GetDataDir() / "debug.log";

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
            printf("Warning: %s in %s:%d\n iofs::ShrinkDebugFile failed - debug.log expands further", e.what(), __FILE__, __LINE__);
        }
    }
}

void bitsystem::AddTimeData(const CNetAddr &ip, int64_t nTime)
{
    int64_t nOffsetSample = nTime - bitsystem::GetTime();

    // Ignore duplicates
    static std::set<CNetAddr> setKnown;
    if (! setKnown.insert(ip).second) {
        return;
    }

    // Add data
    vTimeOffsets.input(nOffsetSample);
    printf("Added time data, samples %d, offset %+" PRId64 " (%+" PRId64 " minutes)\n", vTimeOffsets.size(), nOffsetSample, nOffsetSample / 60);
    if (vTimeOffsets.size() >= 5 && vTimeOffsets.size() % 2 == 1) {
        int64_t nMedian = vTimeOffsets.median();
        std::vector<int64_t> vSorted = vTimeOffsets.sorted();

        // Only let other nodes change our time by so much
        if (util::abs64(nMedian) < 70 * 60) {
            nNodesOffset = nMedian;
        } else {
            nNodesOffset = INT64_MAX;

            static bool fDone;
            if (! fDone) {
                bool fMatch = false;

                // If nobody has a time different than ours but within 5 minutes of ours, give a warning
                BOOST_FOREACH(int64_t nOffset, vSorted)
                {
                    if (nOffset != 0 && util::abs64(nOffset) < 5 * 60) {
                        fMatch = true;
                    }
                }

                if (! fMatch) {
                    fDone = true;
                    std::string strMessage = _(("Warning: Please check that your computer's date and time are correct! If your clock is wrong " + coin_param::strCoinName + " will not work properly.").c_str());
                    excep::set_strMiscWarning( strMessage );
                    printf("*** %s\n", strMessage.c_str());
                    CClientUIInterface::uiInterface.ThreadSafeMessageBox(strMessage+" ", coin_param::strCoinName, CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION);
                }
            }
        }
        if (args_bool::fDebug) {
            BOOST_FOREACH(int64_t n, vSorted)
            {
                printf("%+" PRId64 "  ", n);
            }
            printf("|  ");
        }
        if (nNodesOffset != INT64_MAX) {
            printf("nNodesOffset = %+" PRId64 "  (%+" PRId64 " minutes)\n", nNodesOffset, nNodesOffset / 60);
        }
    }
}

std::string format_version::FormatVersion(int nVersion)
{
    if (nVersion % 100 == 0) {
        return strprintf("%d.%d.%d", nVersion/1000000, (nVersion/10000)%100, (nVersion/100)%100);
    } else {
        return strprintf("%d.%d.%d.%d", nVersion/1000000, (nVersion/10000)%100, (nVersion/100)%100, nVersion%100);
    }
}

std::string format_version::FormatFullVersion()
{
    return version::CLIENT_BUILD;
}

// Format the subversion field according to BIP 14 spec (https://en.bitcoin.it/wiki/BIP_0014)
std::string format_version::FormatSubVersion(const std::string &name, int nClientVersion, const std::vector<std::string> &comments)
{
    std::ostringstream ss;
    ss << "/";
    ss << name << ":" << format_version::FormatVersion(nClientVersion);
    if (! comments.empty()) {
        ss << "(" << boost::algorithm::join(comments, "; ") << ")";
    }

    ss << "/";
    return ss.str();
}

#ifdef WIN32
boost::filesystem::path iofs::GetSpecialFolderPath(int nFolder, bool fCreate)
{
    char pszPath[MAX_PATH] = "";
    if(SHGetSpecialFolderPathA(NULL, pszPath, nFolder, fCreate)) {
        return boost::filesystem::path(pszPath);
    }

    printf("SHGetSpecialFolderPathA() failed, could not obtain requested path.\n");
    return boost::filesystem::path("");
}
#endif

void cmd::runCommand(std::string strCommand)
{
    int nErr = ::system(strCommand.c_str());
    if (nErr) {
        printf("cmd::runCommand error: system(%s) returned %d\n", strCommand.c_str(), nErr);
    }
}
