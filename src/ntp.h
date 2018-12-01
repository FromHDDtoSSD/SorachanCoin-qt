// Copyright (c) 2013-2016 The NovaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php
//
#ifndef NOVACOIN_NTP_H
#define NOVACOIN_NTP_H

namespace ntp_ext
{
    void SetTrustedUpstream(const std::string &strArg, const std::string &strDefault=tcp_domain::strLocal);

    int64_t NtpGetTime(CNetAddr &ip);
    int64_t NtpGetTime(const std::string &strHostName);

    int64_t GetNtpOffset();
    void ThreadNtpSamples(void *parg);
}

#endif
//@
