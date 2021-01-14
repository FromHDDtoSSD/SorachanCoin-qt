// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//
// include, drivebase.h
//
#ifndef SORACHANCOIN_DRIVEWIN_H
#define SORACHANCOIN_DRIVEWIN_H

#include <winapi/drivebase.h>

class cputime
{
private:
    cputime(const cputime &)=delete;
    cputime &operator=(const cputime &)=delete;
    cputime(cputime &&)=delete;
    cputime &operator=(cputime &&)=delete;
    LARGE_INTEGER qf, qc;
public:
    cputime() {
        (void)::QueryPerformanceFrequency(&qf);
    }
    ~cputime() {}

    double operator()() {
        (void)::QueryPerformanceCounter(&qc);
        return (double)qc.QuadPart / (double)qf.QuadPart;
    }
};

#endif // SORACHANCOIN_DRIVEWIN_H
