// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util.h>
#include <sync/sync.h>
#include <version.h>
#include <ui_interface.h>
#include <boost/algorithm/string/join.hpp>
#include <thread/threadsafety.h>
#include <util/strencodings.h>
#include <util/exception.h>

// Work around clang compilation problem in Boost 1.46:
// /usr/include/boost/program_options/detail/config_file.hpp:163:17: error: call to function 'to_internal' that is neither visible in the template definition nor found by argument-dependent lookup
// See also: http://stackoverflow.com/questions/10020179/compilation-fail-in-boost-librairies-program-options
//           http://clang.debian.net/status.php?version=3.0&key=CANNOT_FIND_FUNCTION
/*
namespace boost {
    namespace program_options {
        std::string to_internal(const std::string &);
    }
}
*/

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <boost/thread.hpp>
#include <cleanse/cleanse.h>
#include <openssl/crypto.h>

#if !defined(WIN32) && !defined(ANDROID) && !defined(__OpenBSD__)
# include <execinfo.h>
#endif

//FILE *trace::_fileout = nullptr;
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
CMedianFilter<int64_t> bitsystem::vTimeOffsets(200,0);

void seed::RandAddSeed()
{
    // Seed with CPU performance counter
    int64_t nCounter = ::GetPerformanceCounter();
    ::RAND_add(&nCounter, sizeof(nCounter), 1.5);
    cleanse::OPENSSL_cleanse(&nCounter, sizeof(nCounter));
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
    long ret = ::RegQueryValueExA(HKEY_PERFORMANCE_DATA, "Global", nullptr, nullptr, pdata, &nSize);
    ::RegCloseKey(HKEY_PERFORMANCE_DATA);
    if (ret == ERROR_SUCCESS) {
        ::RAND_add(pdata, nSize, nSize / 100.0);
        cleanse::OPENSSL_cleanse(pdata, nSize);
        logging::LogPrintf("seed::RandAddSeed() %lu bytes\n", nSize);
    }
#endif
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

    for(unsigned char c: str) {
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

std::string bitstr::FormatMoney(int64_t n, bool fPlus /*= false*/) {
    // Note: not using straight sprintf here because we do NOT want
    // localized number formatting.
    int64_t n_abs = (n > 0 ? n : -n);
    int64_t quotient = n_abs / util::COIN;
    int64_t remainder = n_abs % util::COIN;
    std::string str = strprintf("%" PRId64 ".%06" PRId64, quotient, remainder);

    // Right-trim excess zeros before the decimal point:
    size_t nTrim = 0;
    for (size_t i = str.size() - 1; (str[i] == '0' && isdigit(str[i - 2])); --i)
        ++nTrim;
    if (nTrim)
        str.erase(str.size() - nTrim, nTrim);

    if (n < 0)
        str.insert(0u, 1, '-');
    else if (fPlus && n > 0)
        str.insert(0u, 1, '+');

    return str;
}

bool bitstr::ParseMoney(const char *pszIn, int64_t &nRet) {
    std::string strWhole;
    int64_t nUnits = 0;

    const char *p = pszIn;
    while (::isspace(*p)) ++p;
    for (; *p; ++p) {
        if (*p == '.') {
            ++p;
            int64_t nMult = util::CENT * 10;
            while (::isdigit(*p) && (nMult > 0)) {
                nUnits += nMult * (*p++ - '0');
                nMult /= 10;
            }
            break;
        }
        if (::isspace(*p))
            break;
        if (! ::isdigit(*p))
            return false;
        strWhole.insert(strWhole.end(), *p);
    }
    for (; *p; ++p) {
        if (! ::isspace(*p))
            return false;
    }
    if (strWhole.size() > 10) // guard against 63 bit overflow
        return false;
    if (nUnits < 0 || nUnits > util::COIN)
        return false;
    int64_t nWhole = strenc::atoi64(strWhole);
    int64_t nValue = nWhole * util::COIN + nUnits;
    nRet = nValue;
    return true;
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
    logging::LogPrintf("Added time data, samples %d, offset %+" PRId64 " (%+" PRId64 " minutes)\n", vTimeOffsets.size(), nOffsetSample, nOffsetSample / 60);
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
                for(int64_t nOffset: vSorted) {
                    if (nOffset != 0 && util::abs64(nOffset) < 5 * 60) {
                        fMatch = true;
                    }
                }

                if (! fMatch) {
                    fDone = true;
                    std::string strMessage = _("Warning: Please check that your computer's date and time are correct! If your clock is wrong " strCoinName " will not work properly.");
                    excep::set_strMiscWarning( strMessage );
                    logging::LogPrintf("*** %s\n", strMessage.c_str());
                    CClientUIInterface::uiInterface.ThreadSafeMessageBox(strMessage+" ", strCoinName, CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION);
                }
            }
        }
        if (args_bool::fDebug) {
            for(int64_t n: vSorted) {
                logging::LogPrintf("%+" PRId64 "  ", n);
            }
            logging::LogPrintf("|  ");
        }
        if (nNodesOffset != INT64_MAX) {
            logging::LogPrintf("nNodesOffset = %+" PRId64 "  (%+" PRId64 " minutes)\n", nNodesOffset, nNodesOffset / 60);
        }
    }
}

void cmd::runCommand(std::string strCommand)
{
    int nErr = ::system(strCommand.c_str());
    if (nErr) {
        logging::LogPrintf("cmd::runCommand error: system(%s) returned %d\n", strCommand.c_str(), nErr);
    }
}
