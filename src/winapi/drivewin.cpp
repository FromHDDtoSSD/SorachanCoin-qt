// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <winapi/drivewin.h>

double cputime::operator()() {
    (void)::QueryPerformanceCounter(&qc);
    return (double)qc.QuadPart / (double)qf.QuadPart;
}
