// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_DRIVEWIN_H
#define SORACHANCOIN_DRIVEWIN_H

#include <winapi/drivebase.h>

class cputime
{
    cputime(const cputime &)=delete;
    cputime &operator=(const cputime &)=delete;
    cputime(cputime &&)=delete;
    cputime &operator=(cputime &&)=delete;
public:
    cputime() {
        (void)::QueryPerformanceFrequency(&qf);
    }
    ~cputime() {}
    double operator()();
private:
    LARGE_INTEGER qf, qc;
};

#endif // SORACHANCOIN_DRIVEWIN_H
