// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/exception.h>
#include <util/logging.h>
#ifdef WIN32
# include <windows.h>
#endif

std::string excep::strMiscWarning;

std::string excep::FormatException(const std::exception *pex, const char *pszThread) {
#ifdef WIN32
    char pszModule[MAX_PATH] = "";
    ::GetModuleFileNameA(nullptr, pszModule, sizeof(pszModule));
#else
    const char* pszModule = "SorachanCoin";
#endif
    if (pex)
        return tfm::format(
            "EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(), pszModule, pszThread);
    else
        return tfm::format(
            "UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, pszThread);
}

void excep::LogException(const std::exception *pex, const char *pszThread) {
    std::string message = excep::FormatException(pex, pszThread);
    logging::LogPrintf("\n%s", message.c_str());
}

void excep::PrintException(const std::exception *pex, const char *pszThread) {
    excep::PrintExceptionContinue(pex, pszThread);
    throw;
}

void excep::PrintExceptionContinue(const std::exception *pex, const char *pszThread) {
    std::string message = excep::FormatException(pex, pszThread);
    logging::LogPrintf("\n\n************************\n%s\n", message);
    tfm::format(std::cerr, "\n\n************************\n%s\n", message.c_str());
    strMiscWarning = message;
}
