// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "netbase.h"
#include "util.h"
#include "hash.h"

#ifndef WIN32
#ifdef ANDROID
#include <fcntl.h>
#else
#include <sys/fcntl.h>
#endif
#endif

#ifdef _MSC_VER
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()

CCriticalSection netbase::manage::cs_proxyInfos;
netbase::proxyType netbase::manage::proxyInfo[netbase::NET_MAX];
netbase::proxyType netbase::manage::nameproxyInfo;
const unsigned char CNetAddr::pchIPv4[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
const unsigned char CNetAddr::pchOnionCat[6] = { 0xFD, 0x87, 0xD8, 0x7E, 0xEB, 0x43 };
const unsigned char CNetAddr::pchGarliCat[6] = { 0xFD, 0x60, 0xDB, 0x4D, 0xDD, 0xB5 };
const int CNetAddr::NET_UNKNOWN = netbase::NET_MAX + 0;
const int CNetAddr::NET_TEREDO = netbase::NET_MAX + 1;
int netbase::nConnectTimeout = 5000;
bool netbase::fNameLookup = false;

enum netbase::Network netbase::manage::ParseNetwork(std::string net)
{
    boost::to_lower(net);
    if (net == "ipv4") {return netbase::NET_IPV4;}
    if (net == "ipv6") {return netbase::NET_IPV6;}
    if (net == "tor" || net == "onion") {return netbase::NET_TOR;}
    if (net == "i2p") {return netbase::NET_I2P;}
    return netbase::NET_UNROUTABLE;
}

void netbase::manage::SplitHostPort(std::string in, uint16_t &portOut, std::string &hostOut)
{
    const size_t colon = in.find_last_of(':');

    // if a : is found, and it either follows a [...], or no other : is in the string, treat it as port separator
    bool fHaveColon = (colon != in.npos);
    bool fBracketed = (fHaveColon && (in[0]=='[' && in[colon - 1]==']'));    // if there is a colon, and in[0]=='[', colon is not 0, so in[colon-1] is safe
    bool fMultiColon = (fHaveColon && (in.find_last_of(':',colon - 1) != in.npos));

    if (fHaveColon && (colon==0 || fBracketed || !fMultiColon)) {
        char *endp = NULL;
        int n = ::strtol(in.c_str() + colon + 1, &endp, 10);
        if (endp && *endp == 0 && n >= 0) {
            in = in.substr(0, colon);
            if (n > 0 && n < 0x10000) {
                portOut = n;
            }
        }
    }
    if (in.size()>0 && in[0] == '[' && in[in.size() - 1] == ']') {
        hostOut = in.substr(1, in.size() - 2);
    } else {
        hostOut = in;
    }
}

bool netbase::manage::LookupIntern(const char *pszName, std::vector<CNetAddr> &vIP, unsigned int nMaxSolutions, bool fAllowLookup)
{
    vIP.clear();

    {
        CNetAddr addr;
        if (addr.SetSpecial(std::string(pszName))) {
            vIP.push_back(addr);
            return true;
        }
    }

    struct addrinfo aiHint = { 0 };

    aiHint.ai_socktype = SOCK_STREAM;
    aiHint.ai_protocol = IPPROTO_TCP;
#ifdef USE_IPV6
    aiHint.ai_family = AF_UNSPEC;
#else
    aiHint.ai_family = AF_INET;
#endif

#ifdef WIN32
    aiHint.ai_flags = fAllowLookup ? 0 : AI_NUMERICHOST;
#else
    aiHint.ai_flags = fAllowLookup ? AI_ADDRCONFIG : AI_NUMERICHOST;
#endif

    struct addrinfo *aiRes = NULL;
    int nErr = ::getaddrinfo(pszName, NULL, &aiHint, &aiRes);
    if (nErr) {
        return false;
    }

    struct addrinfo *aiTrav = aiRes;
    while (aiTrav != NULL && (nMaxSolutions == 0 || vIP.size() < nMaxSolutions))
    {
        switch (aiTrav->ai_family)
        {
        case (AF_INET):
            assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in));
            vIP.push_back(CNetAddr(((struct sockaddr_in *)(aiTrav->ai_addr))->sin_addr));
            break;

#ifdef USE_IPV6
        case (AF_INET6):
            assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in6));
            vIP.push_back(CNetAddr(((struct sockaddr_in6 *)(aiTrav->ai_addr))->sin6_addr));
            break;
#endif
        }

        aiTrav = aiTrav->ai_next;
    }

    ::freeaddrinfo(aiRes);
    return (vIP.size() > 0);
}

bool netbase::manage::LookupHost(const char *pszName, std::vector<CNetAddr> &vIP, unsigned int nMaxSolutions /* = 0 */, bool fAllowLookup /* = true */)
{
    std::string strHost(pszName);
    if (strHost.empty()) {
        return false;
    }
    if (boost::algorithm::starts_with(strHost, "[") && boost::algorithm::ends_with(strHost, "]")) {
        strHost = strHost.substr(1, strHost.size() - 2);
    }

    return netbase::manage::LookupIntern(strHost.c_str(), vIP, nMaxSolutions, fAllowLookup);
}

bool netbase::manage::Lookup(const char *pszName, std::vector<CService> &vAddr, uint16_t portDefault /* = 0 */, bool fAllowLookup /* = true */, unsigned int nMaxSolutions /* = 0 */)
{
    if (pszName[0] == 0) {
        return false;
    }

    uint16_t port = portDefault;
    std::string hostname = "";
    SplitHostPort(std::string(pszName), port, hostname);

    std::vector<CNetAddr> vIP;
    bool fRet = netbase::manage::LookupIntern(hostname.c_str(), vIP, nMaxSolutions, fAllowLookup);
    if (! fRet) {
        return false;
    }

    vAddr.resize(vIP.size());
    for (unsigned int i = 0; i < vIP.size(); ++i)
    {
        vAddr[i] = CService(vIP[i], port);
    }
    return true;
}

bool netbase::manage::Lookup(const char *pszName, CService &addr, uint16_t portDefault /* = 0 */, bool fAllowLookup /* = true */)
{
    std::vector<CService> vService;
    bool fRet = netbase::manage::Lookup(pszName, vService, portDefault, fAllowLookup, 1);
    if (! fRet) {
        return false;
    }

    addr = vService[0];
    return true;
}

bool netbase::manage::LookupNumeric(const char *pszName, CService &addr, uint16_t portDefault /* = 0 */)
{
    return netbase::manage::Lookup(pszName, addr, portDefault, false);
}

bool netbase::manage::Socks4(const CService &addrDest, SOCKET &hSocket)
{
    printf("SOCKS4 connecting %s\n", addrDest.ToString().c_str());
    if (! addrDest.IsIPv4()) {
        netbase::manage::CloseSocket(hSocket);
        return print::error("Proxy destination is not IPv4");
    }

    char pszSocks4IP[] = "\4\1\0\0\0\0\0\0user";
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    if (!addrDest.GetSockAddr((struct sockaddr *)&addr, &len) || addr.sin_family != AF_INET) {
        netbase::manage::CloseSocket(hSocket);
        return print::error("Cannot get proxy destination address");
    }

    ::memcpy(pszSocks4IP + 2, &addr.sin_port, 2);
    ::memcpy(pszSocks4IP + 4, &addr.sin_addr, 4);
    char *pszSocks4 = pszSocks4IP;
    int nSize = sizeof(pszSocks4IP);

    int ret = ::send(hSocket, pszSocks4, nSize, MSG_NOSIGNAL);
    if (ret != nSize) {
        netbase::manage::CloseSocket(hSocket);
        return print::error("Error sending to proxy");
    }

    char pchRet[8];
    if (::recv(hSocket, pchRet, 8, 0) != 8) {
        netbase::manage::CloseSocket(hSocket);
        return print::error("Error reading proxy response");
    }
    if (pchRet[1] != 0x5a) {
        netbase::manage::CloseSocket(hSocket);
        if (pchRet[1] != 0x5b) {
            printf("ERROR: Proxy returned error %d\n", pchRet[1]);
        }
        return false;
    }

    printf("SOCKS4 connected %s\n", addrDest.ToString().c_str());
    return true;
}

bool netbase::manage::Socks5(std::string strDest, uint16_t port, SOCKET &hSocket)
{
    printf("SOCKS5 connecting %s\n", strDest.c_str());
    if (strDest.size() > 255) {
        netbase::manage::CloseSocket(hSocket);
        return print::error("Hostname too long");
    }

    const char pszSocks5Init[] = "\5\1\0";
    ssize_t ret = ::send(hSocket, pszSocks5Init, 3, MSG_NOSIGNAL);
    if (ret != 3) {
        netbase::manage::CloseSocket(hSocket);
        return print::error("Error sending to proxy");
    }

    char pchRet1[2];
    if (recv(hSocket, pchRet1, 2, 0) != 2) {
        netbase::manage::CloseSocket(hSocket);
        return print::error("Error reading proxy response");
    }
    if (pchRet1[0] != 0x05 || pchRet1[1] != 0x00) {
        netbase::manage::CloseSocket(hSocket);
        return print::error("Proxy failed to initialize");
    }

    std::string strSocks5("\5\1");
    strSocks5 += '\000'; strSocks5 += '\003';
    strSocks5 += static_cast<char>(std::min((int)strDest.size(), 255));
    strSocks5 += strDest;
    strSocks5 += static_cast<char>((port >> 8) & 0xFF);
    strSocks5 += static_cast<char>((port >> 0) & 0xFF);
    ret = ::send(hSocket, strSocks5.data(), strSocks5.size(), MSG_NOSIGNAL);
    if (ret != (ssize_t)strSocks5.size()) {
        netbase::manage::CloseSocket(hSocket);
        return print::error("Error sending to proxy");
    }

    char pchRet2[4];
    if (::recv(hSocket, pchRet2, 4, 0) != 4) {
        netbase::manage::CloseSocket(hSocket);
        return print::error("Error reading proxy response");
    }
    if (pchRet2[0] != 0x05) {
        netbase::manage::CloseSocket(hSocket);
        return print::error("Proxy failed to accept request");
    }
    if (pchRet2[1] != 0x00) {
        netbase::manage::CloseSocket(hSocket);
        switch (pchRet2[1])
        {
        case 0x01: return print::error("Proxy error: general failure");
        case 0x02: return print::error("Proxy error: connection not allowed");
        case 0x03: return print::error("Proxy error: network unreachable");
        case 0x04: return print::error("Proxy error: host unreachable");
        case 0x05: return print::error("Proxy error: connection refused");
        case 0x06: return print::error("Proxy error: TTL expired");
        case 0x07: return print::error("Proxy error: protocol error");
        case 0x08: return print::error("Proxy error: address type not supported");
        default:   return print::error("Proxy error: unknown");
        }
        /// return;
    }

    if (pchRet2[2] != 0x00) {
        netbase::manage::CloseSocket(hSocket);
        return print::error("Error: malformed proxy response");
    }

    char pchRet3[256];
    switch (pchRet2[3])
    {
    case 0x01: ret = ::recv(hSocket, pchRet3, 4, 0) != 4; break;
    case 0x04: ret = ::recv(hSocket, pchRet3, 16, 0) != 16; break;
    case 0x03:
        {
            ret = ::recv(hSocket, pchRet3, 1, 0) != 1;
            if (ret) {
                netbase::manage::CloseSocket(hSocket);
                return print::error("Error reading from proxy");
            }
            int nRecv = pchRet3[0];
            ret = ::recv(hSocket, pchRet3, nRecv, 0) != nRecv;
            break;
        }
    default: netbase::manage::CloseSocket(hSocket); return print::error("Error: malformed proxy response");
    }

    if (ret) {
        netbase::manage::CloseSocket(hSocket);
        return print::error("Error reading from proxy");
    }
    if (::recv(hSocket, pchRet3, 2, 0) != 2) {
        netbase::manage::CloseSocket(hSocket);
        return print::error("Error reading from proxy");
    }

    printf("SOCKS5 connected %s\n", strDest.c_str());
    return true;
}

bool netbase::manage::ConnectSocketDirectly(const CService &addrConnect, SOCKET &hSocketRet, int nTimeout)
{
    hSocketRet = INVALID_SOCKET;

#ifdef USE_IPV6
    struct sockaddr_storage sockaddr;
#else
    struct sockaddr sockaddr;
#endif

    socklen_t len = sizeof(sockaddr);
    if (! addrConnect.GetSockAddr((struct sockaddr *)&sockaddr, &len)) {
        printf("Cannot connect to %s: unsupported network\n", addrConnect.ToString().c_str());
        return false;
    }

    SOCKET hSocket = ::socket(((struct sockaddr *)&sockaddr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (hSocket == INVALID_SOCKET) {
        return false;
    }

#ifdef SO_NOSIGPIPE
    int set = 1;
    ::setsockopt(hSocket, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
#endif

#ifdef WIN32
    u_long fNonblock = 1;
    if (::ioctlsocket(hSocket, FIONBIO, &fNonblock) == SOCKET_ERROR)
#else
    int fFlags = ::fcntl(hSocket, F_GETFL, 0);
    if (::fcntl(hSocket, F_SETFL, fFlags | O_NONBLOCK) == -1)
#endif
    {
        netbase::manage::CloseSocket(hSocket);
        return false;
    }

    if (::connect(hSocket, (struct sockaddr *)&sockaddr, len) == SOCKET_ERROR) {
        int nErr = WSAGetLastError();

        // WSAEINVAL is here because some legacy version of winsock uses it
        if (nErr == WSAEINPROGRESS || nErr == WSAEWOULDBLOCK || nErr == WSAEINVAL) {
            struct timeval timeout;
            timeout.tv_sec  = nTimeout / 1000;
            timeout.tv_usec = (nTimeout % 1000) * 1000;

            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(hSocket, &fdset);
            int nRet = ::select(hSocket + 1, NULL, &fdset, NULL, &timeout);
            if (nRet == 0) {
                printf("connection timeout\n");
                netbase::manage::CloseSocket(hSocket);
                return false;
            }
            if (nRet == SOCKET_ERROR) {
                printf("select() for connection failed: %i\n",WSAGetLastError());
                netbase::manage::CloseSocket(hSocket);
                return false;
            }

            socklen_t nRetSize = sizeof(nRet);
#ifdef WIN32
            if (::getsockopt(hSocket, SOL_SOCKET, SO_ERROR, (char*)(&nRet), &nRetSize) == SOCKET_ERROR)
#else
            if (::getsockopt(hSocket, SOL_SOCKET, SO_ERROR, &nRet, &nRetSize) == SOCKET_ERROR)
#endif
            {
                printf("getsockopt() for connection failed: %i\n",WSAGetLastError());
                netbase::manage::CloseSocket(hSocket);
                return false;
            }
            if (nRet != 0) {
                printf("connect() failed after select(): %s\n",strerror(nRet));
                netbase::manage::CloseSocket(hSocket);
                return false;
            }
        }
#ifdef WIN32
        else if (::WSAGetLastError() != WSAEISCONN)
#else
        else
#endif
        {
            printf("connect() failed: %i\n",WSAGetLastError());
            netbase::manage::CloseSocket(hSocket);
            return false;
        }
    }

    // this isn't even strictly necessary
    // ConnectNode immediately turns the socket back to non-blocking
    // but we'll turn it back to blocking just in case
#ifdef WIN32
    fNonblock = 0;
    if (ioctlsocket(hSocket, FIONBIO, &fNonblock) == SOCKET_ERROR)
#else
    fFlags = fcntl(hSocket, F_GETFL, 0);
    if (fcntl(hSocket, F_SETFL, fFlags & ~O_NONBLOCK) == SOCKET_ERROR)
#endif
    {
        netbase::manage::CloseSocket(hSocket);
        return false;
    }

    hSocketRet = hSocket;
    return true;
}

bool netbase::manage::SetProxy(enum netbase::Network net, CService addrProxy, int nSocksVersion /* = 5 */) {
    assert(net >= 0 && net < NET_MAX);
    if (nSocksVersion != 0 && nSocksVersion != 4 && nSocksVersion != 5) {
        return false;
    }
    if (nSocksVersion != 0 && !addrProxy.IsValid()) {
        return false;
    }

    LOCK(manage::cs_proxyInfos);
    manage::proxyInfo[net] = std::make_pair(addrProxy, nSocksVersion);
    return true;
}

bool netbase::manage::GetProxy(enum netbase::Network net, netbase::proxyType &proxyInfoOut) {
    assert(net >= 0 && net < NET_MAX);
    LOCK(manage::cs_proxyInfos);
    if (! proxyInfo[net].second) {
        return false;
    }

    proxyInfoOut = manage::proxyInfo[net];
    return true;
}

bool netbase::manage::SetNameProxy(CService addrProxy, int nSocksVersion /* = 5 */) {
    if (nSocksVersion != 0 && nSocksVersion != 5) {
        return false;
    }
    if (nSocksVersion != 0 && !addrProxy.IsValid()) {
        return false;
    }

    LOCK(manage::cs_proxyInfos);
    manage::nameproxyInfo = std::make_pair(addrProxy, nSocksVersion);
    return true;
}

bool netbase::manage::GetNameProxy(proxyType &nameproxyInfoOut) {
    LOCK(manage::cs_proxyInfos);
    if (! nameproxyInfo.second) {
        return false;
    }

    nameproxyInfoOut = manage::nameproxyInfo;
    return true;
}

bool netbase::manage::HaveNameProxy() {
    LOCK(manage::cs_proxyInfos);
    return nameproxyInfo.second != 0;
}

bool netbase::manage::IsProxy(const CNetAddr &addr) {
    LOCK(manage::cs_proxyInfos);
    for (int i = 0; i < netbase::NET_MAX; ++i)
    {
        if (manage::proxyInfo[i].second && (addr == (CNetAddr)manage::proxyInfo[i].first)) {
            return true;
        }
    }
    return false;
}

bool netbase::manage::ConnectSocket(const CService &addrDest, SOCKET &hSocketRet, int nTimeout /* = netbase::nConnectTimeout */)
{
    proxyType proxy;

    // no proxy needed
    if (! manage::GetProxy(addrDest.GetNetwork(), proxy)) {
        return manage::ConnectSocketDirectly(addrDest, hSocketRet, nTimeout);
    }

    SOCKET hSocket = INVALID_SOCKET;

    // first connect to proxy server
    if (! manage::ConnectSocketDirectly(proxy.first, hSocket, nTimeout)) {
        return false;
    }

    // do socks negotiation
    switch (proxy.second)
    {
    case 4:
        if (! manage::Socks4(addrDest, hSocket)) {
            return false;
        }
        break;
    case 5:
        if (! manage::Socks5(addrDest.ToStringIP(), addrDest.GetPort(), hSocket)) {
            return false;
        }
        break;
    default:
        netbase::manage::CloseSocket(hSocket);
        return false;
    }

    hSocketRet = hSocket;
    return true;
}

bool netbase::manage::ConnectSocketByName(CService &addr, SOCKET &hSocketRet, const char *pszDest, uint16_t portDefault /* = 0 */, int nTimeout /* = netbase::nConnectTimeout */)
{
    std::string strDest;
    uint16_t port = portDefault;
    manage::SplitHostPort(std::string(pszDest), port, strDest);

    SOCKET hSocket = INVALID_SOCKET;

    proxyType nameproxy;
    manage::GetNameProxy(nameproxy);

    CService addrResolved(CNetAddr(strDest, netbase::fNameLookup && !nameproxy.second), port);
    if (addrResolved.IsValid()) {
        addr = addrResolved;
        return ConnectSocket(addr, hSocketRet, nTimeout);
    }

    addr = CService("0.0.0.0:0");
    if (! nameproxy.second) {
        return false;
    }
    if (! manage::ConnectSocketDirectly(nameproxy.first, hSocket, nTimeout)) {
        return false;
    }

    switch(nameproxy.second)
    {
    default:
    case 4:
        netbase::manage::CloseSocket(hSocket);
        return false;
    case 5:
        if (! manage::Socks5(strDest, port, hSocket)) {
            return false;
        }
        break;
    }

    hSocketRet = hSocket;
    return true;
}

bool netbase::manage::CloseSocket(SOCKET &hSocket)
{
    if (hSocket == INVALID_SOCKET) {
        return false;
    }

#ifdef WIN32
    int ret = ::closesocket(hSocket);
#else
    int ret = ::close(hSocket);
#endif

    hSocket = INVALID_SOCKET;
    return ret != SOCKET_ERROR;
}

///////////////////////////////////////////////////////////////////////////////////////////////////

void CNetAddr::Init()
{
    ::memset(ip, 0, sizeof(ip));
}

void CNetAddr::SetIP(const CNetAddr &ipIn)
{
    ::memcpy(ip, ipIn.ip, sizeof(ip));
}

bool CNetAddr::SetSpecial(const std::string &strName)
{
    if (strName.size() > 6 && strName.substr(strName.size() - 6, 6) == ".onion") {
        std::vector<unsigned char> vchAddr = base32::DecodeBase32(strName.substr(0, strName.size() - 6).c_str());
        if (vchAddr.size() != 16 - sizeof(pchOnionCat)) {
            return false;
        }

        ::memcpy(ip, pchOnionCat, sizeof(pchOnionCat));
        for (unsigned int i=0; i < 16 - sizeof(pchOnionCat); ++i)
        {
            ip[i + sizeof(pchOnionCat)] = vchAddr[i];
        }
        return true;
    }

    if (strName.size() > 11 && strName.substr(strName.size() - 11, 11) == ".oc.b32.i2p") {
        std::vector<unsigned char> vchAddr = base32::DecodeBase32(strName.substr(0, strName.size() - 11).c_str());
        if (vchAddr.size() != 16 - sizeof(pchGarliCat)) {
            return false;
        }

        ::memcpy(ip, pchOnionCat, sizeof(pchGarliCat));
        for (unsigned int i=0; i<16-sizeof(pchGarliCat); ++i)
        {
            ip[i + sizeof(pchGarliCat)] = vchAddr[i];
        }
        return true;
    }
    return false;
}

CNetAddr::CNetAddr()
{
    Init();
}

CNetAddr::CNetAddr(const struct in_addr &ipv4Addr)
{
    ::memcpy(ip, CNetAddr::pchIPv4, 12);
    ::memcpy(ip + 12, &ipv4Addr, 4);
}

#ifdef USE_IPV6
CNetAddr::CNetAddr(const struct in6_addr &ipv6Addr)
{
    ::memcpy(ip, &ipv6Addr, 16);
}
#endif

CNetAddr::CNetAddr(const char *pszIp, bool fAllowLookup)
{
    Init();
    std::vector<CNetAddr> vIP;
    if (netbase::manage::LookupHost(pszIp, vIP, 1, fAllowLookup)) {
        *this = vIP[0];
    }
}

CNetAddr::CNetAddr(const std::string &strIp, bool fAllowLookup)
{
    Init();
    std::vector<CNetAddr> vIP;
    if (netbase::manage::LookupHost(strIp.c_str(), vIP, 1, fAllowLookup)) {
        *this = vIP[0];
    }
}

uint8_t CNetAddr::GetByte(int n) const
{
    return ip[15 - n];
}

bool CNetAddr::IsIPv4() const
{
    return (::memcmp(ip, CNetAddr::pchIPv4, sizeof(pchIPv4)) == 0);
}

bool CNetAddr::IsIPv6() const
{
    return (!IsIPv4() && !IsTor() && !IsI2P());
}

bool CNetAddr::IsRFC1918() const
{
    return  IsIPv4() && (
            GetByte(3) == 10 ||
            (GetByte(3) == 192 && GetByte(2) == 168) ||
            (GetByte(3) == 172 && (GetByte(2) >= 16 && GetByte(2) <= 31)));
}

bool CNetAddr::IsRFC3927() const
{
    return IsIPv4() && (GetByte(3) == 169 && GetByte(2) == 254);
}

bool CNetAddr::IsRFC3849() const
{
    return GetByte(15) == 0x20 && GetByte(14) == 0x01 && GetByte(13) == 0x0D && GetByte(12) == 0xB8;
}

bool CNetAddr::IsRFC3964() const
{
    return (GetByte(15) == 0x20 && GetByte(14) == 0x02);
}

bool CNetAddr::IsRFC6052() const
{
    static const unsigned char pchRFC6052[] = {0,0x64,0xFF,0x9B,0,0,0,0,0,0,0,0};
    return (::memcmp(ip, pchRFC6052, sizeof(pchRFC6052)) == 0);
}

bool CNetAddr::IsRFC4380() const
{
    return (GetByte(15) == 0x20 && GetByte(14) == 0x01 && GetByte(13) == 0 && GetByte(12) == 0);
}

bool CNetAddr::IsRFC4862() const
{
    static const unsigned char pchRFC4862[] = {0xFE,0x80,0,0,0,0,0,0};
    return (::memcmp(ip, pchRFC4862, sizeof(pchRFC4862)) == 0);
}

bool CNetAddr::IsRFC4193() const
{
    return ((GetByte(15) & 0xFE) == 0xFC);
}

bool CNetAddr::IsRFC6145() const
{
    static const unsigned char pchRFC6145[] = {0,0,0,0,0,0,0,0,0xFF,0xFF,0,0};
    return (::memcmp(ip, pchRFC6145, sizeof(pchRFC6145)) == 0);
}

bool CNetAddr::IsRFC4843() const
{
    return (GetByte(15) == 0x20 && GetByte(14) == 0x01 && GetByte(13) == 0x00 && (GetByte(12) & 0xF0) == 0x10);
}

bool CNetAddr::IsTor() const
{
    return (memcmp(ip, pchOnionCat, sizeof(pchOnionCat)) == 0);
}

bool CNetAddr::IsI2P() const
{
    return (::memcmp(ip, pchGarliCat, sizeof(pchGarliCat)) == 0);
}

bool CNetAddr::IsLocal() const
{
    // IPv4 loopback
    if (IsIPv4() && (GetByte(3) == 127 || GetByte(3) == 0)) {
       return true;
    }

    // IPv6 loopback (::1/128)
    static const unsigned char pchLocal[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (::memcmp(ip, pchLocal, 16) == 0) {
        return true;
    }

    return false;
}

bool CNetAddr::IsMulticast() const
{
    return    (IsIPv4() && (GetByte(3) & 0xF0) == 0xE0)
           || (GetByte(15) == 0xFF);
}

bool CNetAddr::IsValid() const
{
    //
    // Cleanup 3-byte shifted addresses caused by garbage in size field
    // of addr messages from versions before 0.2.9 checksum.
    // Two consecutive addr messages look like this:
    // header20 vectorlen3 addr26 addr26 addr26 header20 vectorlen3 addr26 addr26 addr26...
    // so if the first length field is garbled, it reads the second batch
    // of addr misaligned by 3 bytes.
    //
    if (::memcmp(ip, CNetAddr::pchIPv4 + 3, sizeof(pchIPv4) - 3) == 0) {
        return false;
    }

    // unspecified IPv6 address (::/128)
    unsigned char ipNone[16] = {};
    if (::memcmp(ip, ipNone, 16) == 0) {
        return false;
    }

    // documentation IPv6 address
    if (IsRFC3849()) {
        return false;
    }

    if (IsIPv4()) {
        // INADDR_NONE
        uint32_t ipNone = INADDR_NONE;
        if (::memcmp(ip + 12, &ipNone, 4) == 0) {
            return false;
        }

        // 0
        ipNone = 0;
        if (::memcmp(ip + 12, &ipNone, 4) == 0) {
            return false;
        }
    }

    return true;
}

bool CNetAddr::IsRoutable() const
{
    return IsValid() && !(IsRFC1918() || IsRFC3927() || IsRFC4862() || (IsRFC4193() && !IsTor() && !IsI2P()) || IsRFC4843() || IsLocal());
}

enum netbase::Network CNetAddr::GetNetwork() const
{
    if (! IsRoutable()) {
        return netbase::NET_UNROUTABLE;
    }

    if (IsIPv4()) {
        return netbase::NET_IPV4;
    }

    if (IsTor()) {
        return netbase::NET_TOR;
    }

    if (IsI2P()) {
        return netbase::NET_I2P;
    }

    return netbase::NET_IPV6;
}

std::string CNetAddr::ToStringIP() const
{
    if (IsTor()) {
        return base32::EncodeBase32(&ip[6], 10) + ".onion";
    }
    if (IsI2P()) {
        return base32::EncodeBase32(&ip[6], 10) + ".oc.b32.i2p";
    }

    CService serv(*this, (uint16_t)0);
#ifdef USE_IPV6
    struct sockaddr_storage sockaddr;
#else
    struct sockaddr sockaddr;
#endif
    socklen_t socklen = sizeof(sockaddr);
    if (serv.GetSockAddr((struct sockaddr *)&sockaddr, &socklen)) {
        char name[1025] = "";
        if (! getnameinfo((const struct sockaddr *)&sockaddr, socklen, name, sizeof(name), NULL, 0, NI_NUMERICHOST)) {
            return std::string(name);
        }
    }

    if (IsIPv4()) {
        return strprintf("%u.%u.%u.%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0));
    } else {
        return strprintf("%x:%x:%x:%x:%x:%x:%x:%x",
                         GetByte(15) << 8 | GetByte(14), GetByte(13) << 8 | GetByte(12),
                         GetByte(11) << 8 | GetByte(10), GetByte(9) << 8 | GetByte(8),
                         GetByte(7) << 8 | GetByte(6), GetByte(5) << 8 | GetByte(4),
                         GetByte(3) << 8 | GetByte(2), GetByte(1) << 8 | GetByte(0));
    }
}

std::string CNetAddr::ToString() const
{
    return ToStringIP();
}

bool CNetAddr::GetInAddr(struct in_addr *pipv4Addr) const
{
    if (! IsIPv4()) {
        return false;
    }

    ::memcpy(pipv4Addr, ip + 12, 4);
    return true;
}

#ifdef USE_IPV6
bool CNetAddr::GetIn6Addr(struct in6_addr *pipv6Addr) const
{
    ::memcpy(pipv6Addr, ip, 16);
    return true;
}
#endif

// get canonical identifier of an address' group
// no two connections will be attempted to addresses with the same group
std::vector<unsigned char> CNetAddr::GetGroup() const
{
    std::vector<unsigned char> vchRet;
    uint8_t nClass = netbase::NET_IPV6;
    int nStartByte = 0;
    int nBits = 16;

    // all local addresses belong to the same group
    if (IsLocal()) {
        nClass = 255;
        nBits = 0;
    }

    if (! IsRoutable()) {
        // all unroutable addresses belong to the same group
        nClass = netbase::NET_UNROUTABLE;
        nBits = 0;
    } else if (IsIPv4() || IsRFC6145() || IsRFC6052()) {
        // for IPv4 addresses, '1' + the 16 higher-order bits of the IP
        // includes mapped IPv4, SIIT translated IPv4, and the well-known prefix
        nClass = netbase::NET_IPV4;
        nStartByte = 12;
    } else if (IsRFC3964()) {
        // for 6to4 tunnelled addresses, use the encapsulated IPv4 address
        nClass = netbase::NET_IPV4;
        nStartByte = 2;
    } else if (IsRFC4380()) {
        // for Teredo-tunnelled IPv6 addresses, use the encapsulated IPv4 address
        vchRet.push_back(netbase::NET_IPV4);
        vchRet.push_back(GetByte(3) ^ 0xFF);
        vchRet.push_back(GetByte(2) ^ 0xFF);
        return vchRet;
    } else if (IsTor()) {
        nClass = netbase::NET_TOR;
        nStartByte = 6;
        nBits = 4;
    } else if (IsI2P()) {
        nClass = netbase::NET_I2P;
        nStartByte = 6;
        nBits = 4;
    } else if (GetByte(15) == 0x20 && GetByte(14) == 0x01 && GetByte(13) == 0x04 && GetByte(12) == 0x70) {
        // for he.net, use /36 groups
        nBits = 36;
    } else {
        // for the rest of the IPv6 network, use /32 groups
        nBits = 32;
    }

    vchRet.push_back(nClass);
    while (nBits >= 8)
    {
        vchRet.push_back(GetByte(15 - nStartByte));
        nStartByte++;
        nBits -= 8;
    }
    if (nBits > 0) {
        vchRet.push_back(GetByte(15 - nStartByte) | ((1 << nBits) - 1));
    }

    return vchRet;
}

uint64_t CNetAddr::GetHash() const
{
    uint256 hash = hash_basis::Hash(&ip[0], &ip[16]);
    uint64_t nRet;
    ::memcpy(&nRet, &hash, sizeof(nRet));
    return nRet;
}

/** Calculates a metric for how reachable (*this) is from a given partner */
int CNetAddr::GetReachabilityFrom(const CNetAddr *paddrPartner) const
{
    enum Reachability
    {
        REACH_UNREACHABLE,
        REACH_DEFAULT,
        REACH_TEREDO,
        REACH_IPV6_WEAK,
        REACH_IPV4,
        REACH_IPV6_STRONG,
        REACH_PRIVATE
    };

    if (! IsRoutable()) {
        return REACH_UNREACHABLE;
    }

    int ourNet = GetExtNetwork(this);
    int theirNet = GetExtNetwork(paddrPartner);
    bool fTunnel = IsRFC3964() || IsRFC6052() || IsRFC6145();

    switch(theirNet)
    {
    case netbase::NET_IPV4:
        switch(ourNet)
        {
        default:
            return REACH_DEFAULT;
        case netbase::NET_IPV4:
            return REACH_IPV4;
        }
    case netbase::NET_IPV6:
        switch(ourNet)
        {
        default:
            return REACH_DEFAULT;
        case NET_TEREDO:
            return REACH_TEREDO;
        case netbase::NET_IPV4:
            return REACH_IPV4;
        case netbase::NET_IPV6:
            return fTunnel ? REACH_IPV6_WEAK : REACH_IPV6_STRONG; // only prefer giving our IPv6 address if it's not tunnelled
        }
    case netbase::NET_TOR:
        switch(ourNet)
        {
        default:
            return REACH_DEFAULT;
        case netbase::NET_IPV4:
            return REACH_IPV4; // Tor users can connect to IPv4 as well
        case netbase::NET_TOR:
            return REACH_PRIVATE;
        }
    case netbase::NET_I2P:
        switch(ourNet)
        {
        default:
            return REACH_DEFAULT;
        case netbase::NET_I2P:
            return REACH_PRIVATE;
        }
    case NET_TEREDO:
        switch(ourNet)
        {
        default:
            return REACH_DEFAULT;
        case NET_TEREDO:
            return REACH_TEREDO;
        case netbase::NET_IPV6:
            return REACH_IPV6_WEAK;
        case netbase::NET_IPV4:
            return REACH_IPV4;
        }
    case NET_UNKNOWN:
    case netbase::NET_UNROUTABLE:
    default:
        switch(ourNet)
        {
        default:
            return REACH_DEFAULT;
        case NET_TEREDO:
            return REACH_TEREDO;
        case netbase::NET_IPV6:
            return REACH_IPV6_WEAK;
        case netbase::NET_IPV4:
            return REACH_IPV4;
        case netbase::NET_I2P:
            return REACH_PRIVATE; // assume connections from unroutable addresses are
        case netbase::NET_TOR:
            return REACH_PRIVATE; // either from Tor/I2P, or don't care about our address
        }
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////

void CService::Init()
{
    port = 0;
}

CService::CService()
{
    Init();
}

CService::CService(const CNetAddr& cip, uint16_t portIn) : CNetAddr(cip), port(portIn) {}

CService::CService(const struct in_addr& ipv4Addr, uint16_t portIn) : CNetAddr(ipv4Addr), port(portIn) {}

#ifdef USE_IPV6
CService::CService(const struct in6_addr& ipv6Addr, uint16_t portIn) : CNetAddr(ipv6Addr), port(portIn){}
#endif

CService::CService(const struct sockaddr_in& addr) : CNetAddr(addr.sin_addr), port(ntohs(addr.sin_port))
{
    assert(addr.sin_family == AF_INET);
}

#ifdef USE_IPV6
CService::CService(const struct sockaddr_in6 &addr) : CNetAddr(addr.sin6_addr), port(ntohs(addr.sin6_port))
{
    assert(addr.sin6_family == AF_INET6);
}
#endif

bool CService::SetSockAddr(const struct sockaddr *paddr)
{
    switch (paddr->sa_family)
    {
    case AF_INET:
        *this = CService(*(const struct sockaddr_in *)paddr);
        return true;
#ifdef USE_IPV6
    case AF_INET6:
        *this = CService(*(const struct sockaddr_in6 *)paddr);
        return true;
#endif
    default:
        return false;
    }
}

CService::CService(const char *pszIpPort, bool fAllowLookup)
{
    Init();
    CService ip;
    if (netbase::manage::Lookup(pszIpPort, ip, 0, fAllowLookup)) {
        *this = ip;
    }
}

CService::CService(const char *pszIpPort, uint16_t portDefault, bool fAllowLookup)
{
    Init();
    CService ip;
    if (netbase::manage::Lookup(pszIpPort, ip, portDefault, fAllowLookup)) {
        *this = ip;
    }
}

CService::CService(const std::string &strIpPort, bool fAllowLookup)
{
    Init();
    CService ip;
    if (netbase::manage::Lookup(strIpPort.c_str(), ip, 0, fAllowLookup)) {
        *this = ip;
    }
}

CService::CService(const std::string &strIpPort, uint16_t portDefault, bool fAllowLookup)
{
    Init();
    CService ip;
    if (netbase::manage::Lookup(strIpPort.c_str(), ip, portDefault, fAllowLookup)) {
        *this = ip;
    }
}

unsigned short CService::GetPort() const
{
    return port;
}

bool CService::GetSockAddr(struct sockaddr *paddr, socklen_t *addrlen) const
{
    if (IsIPv4()) {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in)) {
            return false;
        }

        *addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in *paddrin = (struct sockaddr_in *)paddr;
        ::memset(paddrin, 0, *addrlen);
        if (! GetInAddr(&paddrin->sin_addr)) {
            return false;
        }

        paddrin->sin_family = AF_INET;
        paddrin->sin_port = htons(port);
        return true;
    }
#ifdef USE_IPV6
    if (IsIPv6()) {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in6)) {
            return false;
        }

        *addrlen = sizeof(struct sockaddr_in6);
        struct sockaddr_in6 *paddrin6 = (struct sockaddr_in6 *)paddr;
        ::memset(paddrin6, 0, *addrlen);
        if (! GetIn6Addr(&paddrin6->sin6_addr)) {
            return false;
        }

        paddrin6->sin6_family = AF_INET6;
        paddrin6->sin6_port = htons(port);
        return true;
    }
#endif
    return false;
}

std::vector<unsigned char> CService::GetKey() const
{
     std::vector<unsigned char> vKey;
     vKey.resize(18);
     ::memcpy(&vKey[0], ip, 16);
     vKey[16] = port / 0x100;
     vKey[17] = port & 0x0FF;
     return vKey;
}

std::string CService::ToStringPort() const
{
    return strprintf("%u", port);
}

std::string CService::ToStringIPPort() const
{
    if (IsIPv4() || IsTor() || IsI2P()) {
        return ToStringIP() + ":" + ToStringPort();
    } else {
        return "[" + ToStringIP() + "]:" + ToStringPort();
    }
}

std::string CService::ToString() const
{
    return ToStringIPPort();
}

void CService::SetPort(unsigned short portIn)
{
    port = portIn;
}
