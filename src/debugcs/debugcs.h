// Copyright (c) 2018-2020 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//

#ifndef SORACHANCOIN_DEBUGCS_H
#define SORACHANCOIN_DEBUGCS_H

#include <string>
#include <sstream>

#ifdef _WIN32
# include <windows.h>
#else
# include <unistd.h>
#endif

class debugcs
{
public:
    static debugcs &instance() noexcept {
        static debugcs obj;
        return obj;
    }
    template <typename T> const debugcs &operator<<(const T &obj) const noexcept {
#if defined(_WIN32) && defined(DEBUG)
        std::ostringstream stream;
        stream << obj;
        ::fprintf_s(stdout, stream.str().c_str());
#else
        static_cast<const T &>(obj);
#endif
        return *this;
    }
    static const char *endl() noexcept {
        return "\n";
    }

private:
    debugcs(const debugcs &); // {}
    debugcs &operator=(const debugcs &); // {}

    debugcs() noexcept {
#if defined(_WIN32) && defined(DEBUG)
        //
        // Open Debug Console
        //
        FILE *fp = nullptr;
        ::AllocConsole();
        ::freopen_s(&fp, "CONOUT$", "w", stdout);
        ::freopen_s(&fp, "CONOUT$", "w", stderr);
#endif
    }
    ~debugcs() noexcept {
#if defined(_WIN32) && defined(DEBUG)
        //
        // Close Debug Console
        //
        ::FreeConsole();
#endif
    }
};

#endif
