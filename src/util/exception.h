// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EXCEPTION_H
#define BITCOIN_EXCEPTION_H

#include <string>
#include <const/no_instance.h>

class excep : private no_instance
{
public:
    static std::string &get_strMiscWarning() noexcept {
        return excep::strMiscWarning;
    }
    static void set_strMiscWarning(const std::string &str) {
        strMiscWarning = str;
    }
    static void LogException(const std::exception *pex, const char *pszThread) noexcept;
    static void PrintException(const std::exception *pex, const char *pszThread);
    static void PrintExceptionContinue(const std::exception *pex, const char *pszThread) noexcept;

private:
    static std::string strMiscWarning;
    static std::string FormatException(const std::exception *pex, const char *pszThread) noexcept;
};

#endif // BITCOIN_EXCEPTION_H
