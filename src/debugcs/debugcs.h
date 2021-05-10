// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_DEBUGCS_H
#define SORACHANCOIN_DEBUGCS_H

#include <string>
#include <sstream>
#include <compat/compat.h>

#ifdef DEBUG_ALGO_CS_OUTPUT
# define DEBUGCS_OUTPUT(s) debugcs::instance() << (s) << debugcs::endl()
#else
# define DEBUGCS_OUTPUT(s)
#endif

// warning fprintf disable
#ifdef WIN32
static inline void _fprintf_cs(const std::string &e) {
    ::fprintf_s(stdout, e.c_str());
}
static inline void _fprintf_cs(const std::wstring &e) {
    ::fwprintf_s(stdout, e.c_str());
}
#else
static inline void _fprintf_cs(const std::string &e) {
    ::fprintf(stdout, e.c_str());
}
static inline void _fprintf_cs(const std::wstring &e) {
    ::fwprintf(stdout, e.c_str());
}
#endif

class debugcs final {
    debugcs(const debugcs &)=delete;
    debugcs(debugcs &&)=delete;
    debugcs &operator=(const debugcs &)=delete;
    debugcs &operator=(debugcs &&)=delete;
#if defined(WIN32) && defined(DEBUG)
    mutable CRITICAL_SECTION cs;
#endif
public:
    static debugcs &instance() noexcept {
        static debugcs obj;
        return obj;
    }
    const debugcs &operator<<(const std::wstring &obj) const noexcept {
#if defined(WIN32) && defined(DEBUG)
        ::EnterCriticalSection(&cs);
        std::wostringstream stream;
        stream << obj;
        ::_fprintf_cs(stream.str());
        ::LeaveCriticalSection(&cs);
#else
        (void)obj;
#endif
        return *this;
    }
    template <typename T>
    const debugcs &operator<<(const T &obj) const noexcept {
#if defined(WIN32) && defined(DEBUG)
        ::EnterCriticalSection(&cs);
        std::ostringstream stream;
        stream << obj;
        ::_fprintf_cs(stream.str());
        ::LeaveCriticalSection(&cs);
#else
        (void)obj;
#endif
        return *this;
    }
    static const char *endl() noexcept {
        return "\n";
    }

private:
    debugcs() noexcept {
#if defined(WIN32) && defined(DEBUG)
        FILE *fp = nullptr;
        ::AllocConsole();
        ::freopen_s(&fp, "CONOUT$", "w", stdout);
        ::freopen_s(&fp, "CONOUT$", "w", stderr);
        ::InitializeCriticalSection(&cs);
#endif
    }
    ~debugcs() {
#if defined(WIN32) && defined(DEBUG)
        ::FreeConsole();
#endif
    }
};

#endif
