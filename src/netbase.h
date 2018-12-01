// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef BITCOIN_NETBASE_H
#define BITCOIN_NETBASE_H

#include <string>
#include <vector>

#include "serialize.h"
#include "compat.h"
#include "sync.h"

#ifdef WIN32
// In MSVC, this is defined as a macro, undefine it to prevent a compile and link error
#undef SetPort
#endif

class CNetAddr;
class CService;
namespace netbase
{
    extern int nConnectTimeout;// = 5000;
    extern bool fNameLookup;// = false;

    enum Network
    {
        NET_UNROUTABLE,
        NET_IPV4,
        NET_IPV6,
        NET_TOR,
        NET_I2P,

        NET_MAX
    };

    typedef std::pair<CService, int> proxyType;
    class manage : private no_instance
    {
    private:
        static CCriticalSection cs_proxyInfos;
        static proxyType proxyInfo[NET_MAX];
        static proxyType nameproxyInfo;

        static bool LookupIntern(const char *pszName, std::vector<CNetAddr> &vIP, unsigned int nMaxSolutions, bool fAllowLookup);
        static bool Socks4(const CService &addrDest, SOCKET &hSocket);
        static bool Socks5(std::string strDest, uint16_t port, SOCKET &hSocket);
        static bool ConnectSocketDirectly(const CService &addrConnect, SOCKET &hSocketRet, int nTimeout);
        static bool GetNameProxy(proxyType &nameproxyInfoOut);
    public:
        static enum netbase::Network ParseNetwork(std::string net);
        static void SplitHostPort(std::string in, uint16_t &portOut, std::string &hostOut);
        static bool SetProxy(enum netbase::Network net, CService addrProxy, int nSocksVersion = 5);
        static bool GetProxy(enum netbase::Network net, netbase::proxyType &proxyInfoOut);
        static bool IsProxy(const CNetAddr &addr);
        static bool SetNameProxy(CService addrProxy, int nSocksVersion = 5);
        static bool HaveNameProxy();
        static bool LookupHost(const char *pszName, std::vector<CNetAddr> &vIP, unsigned int nMaxSolutions = 0, bool fAllowLookup = true);
        static bool Lookup(const char *pszName, CService &addr, uint16_t portDefault = 0, bool fAllowLookup = true);
        static bool Lookup(const char *pszName, std::vector<CService> &vAddr, uint16_t portDefault = 0, bool fAllowLookup = true, unsigned int nMaxSolutions = 0);
        static bool LookupNumeric(const char *pszName, CService &addr, uint16_t portDefault = 0);
        static bool ConnectSocket(const CService &addr, SOCKET &hSocketRet, int nTimeout = netbase::nConnectTimeout);
        static bool ConnectSocketByName(CService &addr, SOCKET &hSocketRet, const char *pszDest, uint16_t portDefault = 0, int nTimeout = netbase::nConnectTimeout);
        
        //
        // Close socket and set hSocket to INVALID_SOCKET
        //
        static bool CloseSocket(SOCKET &hSocket);
    };
}

// 
// IP address (IPv6, or IPv4 using mapped IPv6 range (::FFFF:0:0/96))
//
class CNetAddr
{
//private:
//    CNetAddr(const CNetAddr &); // {}
//    CNetAddr &operator=(const CNetAddr &); // {}

private:
    static const unsigned char pchIPv4[12]; // = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    static const unsigned char pchOnionCat[6]; // = { 0xFD, 0x87, 0xD8, 0x7E, 0xEB, 0x43 };
    static const unsigned char pchGarliCat[6]; // = { 0xFD, 0x60, 0xDB, 0x4D, 0xDD, 0xB5 };

    // private extensions to enum Network, only returned by GetExtNetwork, and only used in GetReachabilityFrom
    static const int NET_UNKNOWN; // = netbase::NET_MAX + 0;
    static const int NET_TEREDO;  // = netbase::NET_MAX + 1;
    static int GetExtNetwork(const CNetAddr *addr) {
        if (addr == NULL) {
            return NET_UNKNOWN;
        }
        if (addr->IsRFC4380()) {
            return NET_TEREDO;
        }
        return addr->GetNetwork();
    }

protected:
    unsigned char ip[16]; // in network byte order

public:
    CNetAddr();
    CNetAddr(const struct in_addr &ipv4Addr);
    explicit CNetAddr(const char *pszIp, bool fAllowLookup = false);
    explicit CNetAddr(const std::string &strIp, bool fAllowLookup = false);
    void Init();
    void SetIP(const CNetAddr &ipIn);
    bool SetSpecial(const std::string &strName); // for Tor and I2P addresses
    bool IsIPv4() const;    // IPv4 mapped address (::FFFF:0:0/96, 0.0.0.0/0)
    bool IsIPv6() const;    // IPv6 address (not mapped IPv4, not Tor/I2P)
    bool IsRFC1918() const; // IPv4 private networks (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
    bool IsRFC3849() const; // IPv6 documentation address (2001:0DB8::/32)
    bool IsRFC3927() const; // IPv4 autoconfig (169.254.0.0/16)
    bool IsRFC3964() const; // IPv6 6to4 tunnelling (2002::/16)
    bool IsRFC4193() const; // IPv6 unique local (FC00::/15)
    bool IsRFC4380() const; // IPv6 Teredo tunnelling (2001::/32)
    bool IsRFC4843() const; // IPv6 ORCHID (2001:10::/28)
    bool IsRFC4862() const; // IPv6 autoconfig (FE80::/64)
    bool IsRFC6052() const; // IPv6 well-known prefix (64:FF9B::/96)
    bool IsRFC6145() const; // IPv6 IPv4-translated address (::FFFF:0:0:0/96)
    bool IsTor() const;
    bool IsI2P() const;
    bool IsLocal() const;
    bool IsRoutable() const;
    bool IsValid() const;
    bool IsMulticast() const;
    enum netbase::Network GetNetwork() const;
    std::string ToString() const;
    std::string ToStringIP() const;
    uint8_t GetByte(int n) const;
    uint64_t GetHash() const;
    bool GetInAddr(struct in_addr* pipv4Addr) const;
    std::vector<unsigned char> GetGroup() const;
    int GetReachabilityFrom(const CNetAddr *paddrPartner = NULL) const;

#ifdef USE_IPV6
    CNetAddr(const struct in6_addr &pipv6Addr);
    bool GetIn6Addr(struct in6_addr *pipv6Addr) const;
#endif

    friend bool operator==(const CNetAddr &a, const CNetAddr &b) {
        return (::memcmp(a.ip, b.ip, 16) == 0);
    }
    friend bool operator!=(const CNetAddr &a, const CNetAddr &b) {
        return (::memcmp(a.ip, b.ip, 16) != 0);
    }
    friend bool operator<(const CNetAddr &a, const CNetAddr &b) {
        return (::memcmp(a.ip, b.ip, 16) < 0);
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(FLATDATA(this->ip));
    )
};

//
// A combination of a network address (CNetAddr) and a (TCP) port
// Ex, CService("0.0.0.0:0")
//
class CService : public CNetAddr
{
//private:
//    CService(const CService &); // {}
//    CService &operator=(const CService &); // {}

protected:
    unsigned short port; // host order

public:
    CService();
    CService(const CNetAddr &ip, uint16_t port);
    CService(const struct in_addr &ipv4Addr, uint16_t port);
    CService(const struct sockaddr_in &addr);
    explicit CService(const char *pszIpPort, uint16_t portDefault, bool fAllowLookup = false);
    explicit CService(const char *pszIpPort, bool fAllowLookup = false);
    explicit CService(const std::string &strIpPort, uint16_t portDefault, bool fAllowLookup = false);
    explicit CService(const std::string &strIpPort, bool fAllowLookup = false);
    void Init();
    void SetPort(uint16_t portIn);
    unsigned short GetPort() const;
    bool GetSockAddr(struct sockaddr *paddr, socklen_t *addrlen) const;
    bool SetSockAddr(const struct sockaddr *paddr);
    std::vector<unsigned char> GetKey() const;
    std::string ToString() const;
    std::string ToStringPort() const;
    std::string ToStringIPPort() const;

#ifdef USE_IPV6
    CService(const struct in6_addr &ipv6Addr, uint16_t port);
    CService(const struct sockaddr_in6 &addr);
#endif

    friend bool operator==(const CService &a, const CService &b) {
        return (CNetAddr)a == (CNetAddr)b && a.port == b.port;
    }
    friend bool operator!=(const CService &a, const CService &b) {
        return (CNetAddr)a != (CNetAddr)b || a.port != b.port;
    }
    friend bool operator<(const CService &a, const CService &b) {
        return (CNetAddr)a < (CNetAddr)b || ((CNetAddr)a == (CNetAddr)b && a.port < b.port);
    }

    IMPLEMENT_SERIALIZE
    (
        CService *pthis = const_cast<CService *>(this);
        READWRITE(FLATDATA(this->ip));
        unsigned short portN = htons(this->port);
        READWRITE(portN);
        if (fRead) {
            pthis->port = ntohs(portN);
        }
    )
};

#endif
//@
