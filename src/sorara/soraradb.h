// Copyright (c) 2018-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORA_SORARADB_H
#define SORA_SORARADB_H

#include <db.h>

#if defined(USE_LEBRESSL) && defined(WIN32)
# include <windows.h>
# include <openssl/rand.h>
static inline int RAND_event(UINT message, WPARAM wp, LPARAM lp) {
    ::RAND_seed((char *)&message, sizeof(message)/sizeof(char));
    ::RAND_seed((char *)&wp, sizeof(wp)/sizeof(char));
    ::RAND_seed((char *)&lp, sizeof(lp)/sizeof(char));
    return 1;
}
#endif

class CSoraraDB final {
    CSoraraDB()=delete;
    CSoraraDB(const CSoraraDB &)=delete;
    CSoraraDB(CSoraraDB &&)=delete;
    CSoraraDB &operator=(const CSoraraDB &)=delete;
    CSoraraDB &operator=(CSoraraDB &&)=delete;
public:
    CSoraraDB(const char *mode="r+");

private:
    CSqliteDB sqldb;
};

#endif // SORA_SORARADB_H
