// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef BITCOIN_NET_H
#define BITCOIN_NET_H

#include <limits>
#include <deque>
#ifndef Q_MOC_RUN
#include <boost/array.hpp>
#include <boost/foreach.hpp>
#endif
#include <openssl/rand.h>

#ifndef WIN32
#include <arpa/inet.h>
#endif

#include "mruset.h"
#include "netbase.h"
#include "addrman.h"
#include "hash.h"

class CRequestTracker;
class CNode;
class CBlockIndex;

//
// Port
//
namespace tcp_port
{
    const unsigned short uMainnet[5] = {6350, 9350, 12350, 15350, 18350};
    const unsigned short uTestnet[5] = {16350, 19350, 22350, 25350, 28350};
    const unsigned int nPortLen = ARRAYLEN(uMainnet);
    const unsigned int nMainnet_default = 0;
    const unsigned int nTestnet_default = 0;

    const unsigned short uJsonRpcMain = 6351;
    const unsigned short uJsonRpcTest = 16351;

    const unsigned short uStun = 17398;
    const unsigned short uSocksDefault = 9714;

    const unsigned short uIrc = 6636;
}

//
// IP
//
namespace tcp_ip
{
    const char *const strIpZero = "0.0.0.0";
    const char *const strLocal = "127.0.0.1";

    const char *const strSeedMaster = "202.229.98.202";
}

//
// domain
//
#define SORACHANCOIN_MAIN_DOMAIN "www.junkhdd.com"
#define SORACHANCOIN_SUB_DOMAIN "www.iuec-recovery.jp"
namespace tcp_domain
{
    const char *const strLocal = "localhost";

    const char *const strMain = SORACHANCOIN_MAIN_DOMAIN;
    const char *const strSub = SORACHANCOIN_SUB_DOMAIN;

    const char *const dnsList[8] = {
        "dns1.junkhdd.com",
        "dns2.junkhdd.com",
        "dns3.junkhdd.com",
        "dns4.junkhdd.com",
        "dns5.junkhdd.com",
        "dns6.junkhdd.com",
        "dns7.junkhdd.com",
        "dns8.junkhdd.com",
    };
}

//
// stun.cpp
//
namespace stun_ext
{
    int GetExternalIPbySTUN(uint64_t rnd, struct sockaddr_in *mapped, const char **srv);
}

//
// shot
//
class shot : private no_instance
{
private:
    static CCriticalSection cs_vOneShots;
    static std::deque<std::string> vOneShots;

protected:
    static CSemaphore *semOutbound;
    static void ProcessOneShot();

public:
    static void AddOneShot(std::string strDest);

    static void semOutbound_cleanup() {
        if(semOutbound) {
            delete semOutbound;
            semOutbound = NULL;
        }
    }
};

//
// net and protocol param
//
class net_basis : private no_instance
{
private:
    static CCriticalSection cs_port;

    static bool IsNoneblock(SOCKET hSocket, char mode, long timeout_usec) {
        fd_set fdset;
        struct timeval timeout;
        FD_ZERO(&fdset);
        FD_SET(hSocket, &fdset);
        timeout.tv_sec = 0;
        timeout.tv_usec = timeout_usec;
        int ret = (mode == 'r') ? ::select(hSocket + 1, &fdset, nullptr, nullptr, &timeout): ::select(hSocket + 1, nullptr, &fdset, nullptr, &timeout);
        return (ret == 1) ? true: false;
    }
protected:
    static std::list<CNode *> vNodesDisconnected;

public:
    static const uint16_t nPortZero = 0;
    static const char *const strIpZero;
    static const char *const strLocal;
    static const char *const strSeedMaster;

    static bool IsNoneblockSend(SOCKET hSocket, long timeout_usec = 20 * 1000) {
        return IsNoneblock(hSocket, 's', timeout_usec);
    }
    static bool IsNoneblockRecv(SOCKET hSocket, long timeout_usec = 20 * 1000) {
        return IsNoneblock(hSocket, 'r', timeout_usec);
    }

    enum GET_PORT_TYPE
    {
        CONNECT_NODE,
        DNS_SEED,
        ONION,
        ARG_DEFAULT_PORT,
        ADD_NODE,
        SHA256_BLOCKCHAIN,
        QUANTUM_BLOCKCHAIN,
    };
    static unsigned short GetDefaultPort(GET_PORT_TYPE type, const CNetAddr *pNetAddr = nullptr, const char *pszDest = nullptr);

    static void vNodeDisconnected_cleanup() {
        BOOST_FOREACH(CNode *pnode, vNodesDisconnected)
        {
            if(pnode) {
                delete pnode;
            }
        }
        vNodesDisconnected.clear();
    }

    static unsigned short GetListenPort(GET_PORT_TYPE type = SHA256_BLOCKCHAIN);
    static bool RecvLine(SOCKET hSocket, std::string &strLine);
};

//
// Thread types
//
enum threadId
{
    THREAD_SOCKETHANDLER,
    THREAD_OPENCONNECTIONS,
    THREAD_MESSAGEHANDLER,
    THREAD_RPCLISTENER,
    THREAD_UPNP,
    THREAD_DNSSEED,
    THREAD_ADDEDCONNECTIONS,
    THREAD_DUMPADDRESS,
    THREAD_RPCHANDLER,
    THREAD_MINTER,
    THREAD_SCRIPTCHECK,
    THREAD_NTP,
    THREAD_IPCOLLECTOR,

    THREAD_MAX
};

//
// net_node (Thread)
//
class net_node : public shot, public net_basis
{
private:
    static const int MAX_OUTBOUND_CONNECTIONS = 16;
    static const uint32_t pnSeed[1];
    static const char *const pchTorSeed[1];

    static CNode *pnodeLocalHost;
    static CNode *pnodeSync;

    static CCriticalSection cs_setservAddNodeAddresses;
    static std::set<CNetAddr> setservAddNodeAddresses;

    static uint64_t ReceiveBufferSize() {
        return 1000 * map_arg::GetArg("-maxreceivebuffer", 5 * 1000);
    }

    static void ThreadDumpAddress(void *parg);
    static void ThreadDumpAddress2(void *parg);

    static void ThreadSocketHandler(void *parg);
    static void ThreadSocketHandler2(void *parg);

    static void ThreadOpenConnections(void *parg);
    static void ThreadOpenConnections2(void *parg);

    static void ThreadOpenAddedConnections(void *parg);
    static void ThreadOpenAddedConnections2(void *parg);

    static void ThreadMessageHandler(void *parg);
    static void ThreadMessageHandler2(void *parg);

    static void DumpAddresses();
    static bool StopNode();

    static void StartSync(const std::vector<CNode *> &__vNodes);

    static void Discover();

    static CNode *FindNode(const CNetAddr &ip);
    static CNode *FindNode(std::string addrName);
    static CNode *FindNode(const CService &addr);
    static CNode *ConnectNode(CAddress addrConnect, const char *strDest = NULL, int64_t nTimeout = 0);

public:
    static CCriticalSection cs_vNodes;
    static CCriticalSection cs_vAddedNodes;
    static std::vector<std::string> vAddedNodes;

    static boost::array<int, THREAD_MAX> vnThreadsRunning;
    static CAddrMan addrman;    // name solution, 1,addrman -> 2,dns_seed

    static std::vector<CNode *> vNodes;
    static std::map<CInv, CDataStream> mapRelay;
    static CCriticalSection cs_mapRelay;

    static std::deque<std::pair<int64_t, CInv> > vRelayExpiration;

    static std::map<CInv, int64_t> mapAlreadyAskedFor;

    static uint64_t nLocalServices;

    static void nodeLocalHost_cleanup() {
        if(pnodeLocalHost) {
            delete pnodeLocalHost;
            pnodeLocalHost = NULL;
        }
    }

    static bool Is_pnodeSync(const CNode *node) {
        return (node == net_node::pnodeSync);
    }
    static void setnull_pnodeSync() {
        net_node::pnodeSync = NULL;
    }

    static uint64_t SendBufferSize() { return 1000 * map_arg::GetArg("-maxsendbuffer", 1 * 1000); }

    /// StartNode: CNode, UPnP, IRC, send/receive, addnode, outbound, message, dump network, StakeMiner, NTP
    static void StartNode(void *parg);        // call to bitthread::manage::NewThread
    static void Shutdown(void *parg);        // init.cpp

    static bool OpenNetworkConnection(const CAddress &addrConnect, CSemaphoreGrant *grantOutbound = NULL, const char *strDest = NULL, bool fOneShot = false);

    static void AddressCurrentlyConnected(const CService &addr);
};

//
// bitsocket
//
class bitsocket : private no_instance
{
    friend class net_node;
    friend class entry;
private:
    static std::vector<SOCKET> vhListenSocket;
public:
    static CAddress addrSeenByPeer;    // addrSeenByPeer(CService(net_basis::strIpZero, net_basis::nPortZero), net_node::nLocalServices)
    static uint64_t nLocalHostNonce;

    static void vhListenSocket_cleanup() {
        BOOST_FOREACH(SOCKET hListenSocket, bitsocket::vhListenSocket)
        {
            if (hListenSocket != INVALID_SOCKET) {
                if (! netbase::manage::CloseSocket(hListenSocket)) {
                    printf("CloseSocket(hListenSocket) failed with error %d\n", WSAGetLastError());
                }
            }
        }
    }
};

//
// DNS seeds (dns_seed::strDNSSeed)
// Each pair gives a source name and a seed name.
//
// The first name is used as information source for net_node::addrman.
// The second name should resolve to a list of seed addresses.
//
class dns_seed : private no_instance
{
private:
    static const char *const strDNSSeed[5][2];

    static void ThreadDNSAddressSeed2(void *parg);
public:
    static void ThreadDNSAddressSeed(void *parg);
};

//
// ExternalIP
//
enum _NET_TYPE
{
    LOCAL_NONE,   // unknown
    LOCAL_IF,     // address a local interface listens on
    LOCAL_BIND,   // address explicit bound to
    LOCAL_UPNP,   // address reported by UPnP
    LOCAL_IRC,    // address reported by IRC (deprecated)
    LOCAL_HTTP,   // address reported by whatismyip.com and similar
    LOCAL_MANUAL, // address explicitly specified (-externalip=)

    LOCAL_MAX
};
class ext_ip : private no_instance
{
private:
    struct LocalServiceInfo
    {
        int nScore;
        uint16_t nPort;
    };

    static CCriticalSection cs_mapLocalHost;
    static std::map<CNetAddr, ext_ip::LocalServiceInfo> mapLocalHost;
    static bool vfLimited[netbase::NET_MAX];
    static bool vfReachable[netbase::NET_MAX];

    static bool GetMyExternalIP(CNetAddr &ipRet);

    static int GetnScore(const CService &addr);
    static bool IsPeerAddrLocalGood(CNode *pnode);

    static void AdvertizeLocal();

public:
    static void ThreadGetMyExternalIP(void *parg);

    static bool AddLocal(const CService &addr, int nScore=LOCAL_NONE);
    static bool AddLocal(const CNetAddr &addr, int nScore=LOCAL_NONE);
    static void SetReachable(enum netbase::Network net, bool fFlag = true);
    static void AdvertiseLocal(CNode *pnode);

    static bool IsLimited(enum netbase::Network net);
    static bool IsLimited(const CNetAddr &addr);
    static bool IsReachable(const CNetAddr &addr);

    static bool IsLocal(const CService &addr);
    static bool SeenLocal(const CService &addr);

    static void SetLimited(enum netbase::Network net, bool fLimited = true);
    static bool GetLocal(CService &addr, const CNetAddr *paddrPeer = NULL);
    static CAddress GetLocalAddress(const CNetAddr *paddrPeer = NULL);
};

//
// UPNP
//
namespace upnp
{
#ifdef USE_UPNP
    void ThreadMapPort(void *parg);
    void ThreadMapPort2(void *parg);
#endif
    void MapPort();
}

class CRequestTracker
{
private:
    CRequestTracker(const CRequestTracker &); // {}
    // CRequestTracker &operator=(const CRequestTracker &);
public:
    void (*fn)(void *, CDataStream &);
    void *param1;

    explicit CRequestTracker(void (*fnIn)(void *, CDataStream &)=NULL, void *param1In=NULL) {
        fn = fnIn;
        param1 = param1In;
    }

    bool IsNull() const {
        return fn == NULL;
    }
};

//
// Args instance
//
namespace args_bool
{
    extern bool_arg fDiscover;//(true);
    extern bool_arg fUseUPnP;//(false);
    extern bool_arg fClient;//(false);
}

class CNodeStats
{
public:
    uint64_t nServices;
    int64_t nLastSend;
    int64_t nLastRecv;
    int64_t nTimeConnected;
    std::string addrName;
    int32_t nVersion;
    std::string strSubVer;
    bool fInbound;
    int64_t nReleaseTime;
    int32_t nStartingHeight;
    int32_t nMisbehavior;
    uint64_t nSendBytes;
    uint64_t nRecvBytes;
    bool fSyncNode;
};

//
// Information about a peer
//
class CNode
{
public:
    // socket
    uint64_t nServices;
    SOCKET hSocket;
    CDataStream vSend;
    CDataStream vRecv;
    uint64_t nSendBytes;
    uint64_t nRecvBytes;
    CCriticalSection cs_vSend;
    CCriticalSection cs_vRecv;
    int64_t nLastSend;
    int64_t nLastRecv;
    int64_t nLastSendEmpty;
    int64_t nTimeConnected;
    int32_t nHeaderStart;
    uint32_t nMessageStart;
    CAddress addr;
    std::string addrName;
    CService addrLocal;
    int32_t nVersion;
    std::string strSubVer;
    bool fOneShot;
    bool fClient;
    bool fInbound;
    bool fNetworkNode;
    bool fSuccessfullyConnected;
    bool fDisconnect;
    CSemaphoreGrant grantOutbound;

protected:
    int nRefCount;

    //
    // Denial-of-service detection/prevention
    // Key is IP address, value is banned-until-time
    //
    static std::map<CNetAddr, int64_t> setBanned;
    static CCriticalSection cs_setBanned;

    int nMisbehavior;

public:
    int64_t nReleaseTime;
    std::map<uint256, CRequestTracker> mapRequests;
    CCriticalSection cs_mapRequests;
    uint256 hashContinue;
    CBlockIndex* pindexLastGetBlocksBegin;
    uint256 hashLastGetBlocksEnd;
    int32_t nStartingHeight;
    bool fStartSync;

    //
    // flood relay
    //
    std::vector<CAddress> vAddrToSend;
    std::set<CAddress> setAddrKnown;
    bool fGetAddr;
    std::set<uint256> setKnown;
    uint256 hashCheckpointKnown; // ppcoin: known sent sync-checkpoint
    int64_t nNextAddrSend;
    int64_t nNextLocalAddrSend;
    int64_t nNextInvSend;

    //
    // inventory based relay
    //
    mruset<CInv> setInventoryKnown;
    std::vector<CInv> vInventoryToSend;
    CCriticalSection cs_inventory;
    std::multimap<int64_t, CInv> mapAskFor;

    CNode(SOCKET hSocketIn, CAddress addrIn, std::string addrNameIn = "", bool fInboundIn=false) : vSend(SER_NETWORK, version::MIN_PROTO_VERSION), vRecv(SER_NETWORK, version::MIN_PROTO_VERSION) {
        nServices = 0;
        hSocket = hSocketIn;
        nLastSend = 0;
        nLastRecv = 0;
        nSendBytes = 0;
        nRecvBytes = 0;
        nLastSendEmpty = bitsystem::GetTime();
        nTimeConnected = bitsystem::GetTime();
        nHeaderStart = -1;
        nMessageStart = std::numeric_limits<uint32_t>::max();
        addr = addrIn;
        addrName = addrNameIn.empty() ? addr.ToStringIPPort() : addrNameIn;
        nVersion = 0;
        strSubVer.clear();
        fOneShot = false;
        fClient = false; // set by version message
        fInbound = fInboundIn;
        fNetworkNode = false;
        fSuccessfullyConnected = false;
        fDisconnect = false;
        nRefCount = 0;
        nReleaseTime = 0;
        hashContinue = 0;
        pindexLastGetBlocksBegin = 0;
        hashLastGetBlocksEnd = 0;
        nStartingHeight = -1;
        nNextLocalAddrSend = 0;
        nNextAddrSend = 0;
        nNextInvSend = 0;
        fStartSync = false;
        fGetAddr = false;
        nMisbehavior = 0;
        hashCheckpointKnown = 0;
        setInventoryKnown.max_size((size_t)net_node::SendBufferSize() / 1000);

        // Be shy and don't send version until we hear
        if (hSocket != INVALID_SOCKET && !fInbound) {
            PushVersion();
        }
    }

    virtual ~CNode() {
        if (hSocket != INVALID_SOCKET) {
            netbase::manage::CloseSocket(hSocket);
        }
    }

private:
    //
    // Network usage totals
    //
    static CCriticalSection cs_totalBytesRecv;
    static CCriticalSection cs_totalBytesSent;
    static uint64_t nTotalBytesRecv;
    static uint64_t nTotalBytesSent;
    
    CNode(const CNode &); // {}
    CNode &operator=(const CNode &); // {}

public:

    int GetRefCount() {
        return std::max(nRefCount, 0) + (bitsystem::GetTime() < nReleaseTime ? 1 : 0);
    }

    CNode *AddRef(int64_t nTimeout=0) {
        if (nTimeout != 0) {
            nReleaseTime = std::max(nReleaseTime, bitsystem::GetTime() + nTimeout);
        } else {
            nRefCount++;
        }
        return this;
    }

    void Release() {
        nRefCount--;
    }

    void AddAddressKnown(const CAddress &addr) {
        setAddrKnown.insert(addr);
    }

    void PushAddress(const CAddress &addr) {
        //
        // Known checking here is only to save space from duplicates.
        // block_process::manage::SendMessages will filter it again for knowns that were added
        // after addresses were pushed.
        //
        if (addr.IsValid() && !setAddrKnown.count(addr)) {
            this->vAddrToSend.push_back(addr);
        }
    }

    void AddInventoryKnown(const CInv &inv) {
        {
            LOCK(cs_inventory);
            setInventoryKnown.insert(inv);
        }
    }

    void PushInventory(const CInv &inv) {
        {
            LOCK(cs_inventory);
            if (! setInventoryKnown.count(inv)) {
                vInventoryToSend.push_back(inv);
            }
        }
    }

    void AskFor(const CInv &inv) {
        //
        // We're using mapAskFor as a priority queue,
        // the key is the earliest time the request can be sent
        //
        int64_t &nRequestTime = net_node::mapAlreadyAskedFor[inv];
        if (args_bool::fDebugNet) {
            printf("askfor %s   %" PRId64 " (%s)\n", inv.ToString().c_str(), nRequestTime, util::DateTimeStrFormat("%H:%M:%S", nRequestTime/1000000).c_str());
        }

        // Make sure not to reuse time indexes to keep things in the same order
        int64_t nNow = (bitsystem::GetTime() - 1) * 1000000;

        static int64_t nLastTime = 0;
        ++nLastTime;

        nNow = std::max(nNow, nLastTime);
        nLastTime = nNow;

        // Each retry is 2 minutes after the last
        nRequestTime = std::max(nRequestTime + 2 * 60 * 1000000, nNow);
        mapAskFor.insert(std::make_pair(nRequestTime, inv));
    }

    void BeginMessage(const char *pszCommand) {
        ENTER_CRITICAL_SECTION(cs_vSend);
        if (nHeaderStart != -1) {
            AbortMessage();
        }

        nHeaderStart = (int32_t)vSend.size();
        vSend << CMessageHeader(pszCommand, 0);

        nMessageStart = (uint32_t)vSend.size();
        if (args_bool::fDebug) {
            printf("sending: %s ", pszCommand);
        }
    }

    void AbortMessage() {
        if (nHeaderStart < 0) {
            return;
        }

        vSend.resize(nHeaderStart);
        nHeaderStart = -1;
        nMessageStart = std::numeric_limits<uint32_t>::max();
        LEAVE_CRITICAL_SECTION(cs_vSend);
        if (args_bool::fDebug) {
            printf("(aborted)\n");
        }
    }

    void EndMessage() {
        if (map_arg::GetMapArgsCount("-dropmessagestest") && bitsystem::GetRand(atoi(map_arg::GetMapArgsString("-dropmessagestest"))) == 0) {
            printf("dropmessages DROPPING SEND MESSAGE\n");
            AbortMessage();
            return;
        }

        if (nHeaderStart < 0) {
            return;
        }

        //
        // Set the size
        //
        uint32_t nSize = (uint32_t)vSend.size() - nMessageStart;
        ::memcpy((char *)&vSend[this->nHeaderStart] + CMessageHeader::GetMessageSizeOffset(), &nSize, sizeof(nSize));

        //
        // Set the checksum
        //
        uint256 hash = hash_basis::Hash(vSend.begin() + nMessageStart, vSend.end());
        uint32_t nChecksum = 0;
        ::memcpy(&nChecksum, &hash, sizeof(nChecksum));

        assert(nMessageStart - nHeaderStart >= CMessageHeader::GetChecksumOffset() + sizeof(nChecksum));
        ::memcpy((char *)&vSend[nHeaderStart] + CMessageHeader::GetChecksumOffset(), &nChecksum, sizeof(nChecksum));

        if (args_bool::fDebug) {
            printf("(%d bytes)\n", nSize);
        }

        nHeaderStart = -1;
        nMessageStart = std::numeric_limits<uint32_t>::max();
        LEAVE_CRITICAL_SECTION(cs_vSend);
    }

    void EndMessageAbortIfEmpty() {
        if (nHeaderStart < 0) {
            return;
        }

        int nSize = (int)vSend.size() - nMessageStart;
        if (nSize > 0) {
            EndMessage();
        } else {
            AbortMessage();
        }
    }

    void PushVersion();

    void PushMessage(const char *pszCommand) {
        try {
            BeginMessage(pszCommand);
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template<typename T1>
    void PushMessage(const char *pszCommand, const T1 &a1) {
        try {
            BeginMessage(pszCommand);
            vSend << a1;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2>
    void PushMessage(const char *pszCommand, const T1 &a1, const T2 &a2) {
        try {
            BeginMessage(pszCommand);
            vSend << a1 << a2;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3>
    void PushMessage(const char *pszCommand, const T1 &a1, const T2 &a2, const T3 &a3) {
        try {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4>
    void PushMessage(const char *pszCommand, const T1 &a1, const T2 &a2, const T3 &a3, const T4 &a4) {
        try {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5>
    void PushMessage(const char *pszCommand, const T1 &a1, const T2 &a2, const T3 &a3, const T4 &a4, const T5 &a5) {
        try {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4 << a5;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6>
    void PushMessage(const char *pszCommand, const T1 &a1, const T2 &a2, const T3 &a3, const T4 &a4, const T5 &a5, const T6 &a6) {
        try {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4 << a5 << a6;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7>
    void PushMessage(const char *pszCommand, const T1 &a1, const T2 &a2, const T3 &a3, const T4 &a4, const T5 &a5, const T6 &a6, const T7 &a7) {
        try {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4 << a5 << a6 << a7;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8>
    void PushMessage(const char *pszCommand, const T1 &a1, const T2 &a2, const T3 &a3, const T4 &a4, const T5 &a5, const T6 &a6, const T7 &a7, const T8 &a8) {
        try {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4 << a5 << a6 << a7 << a8;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9>
    void PushMessage(const char *pszCommand, const T1 &a1, const T2 &a2, const T3 &a3, const T4 &a4, const T5 &a5, const T6 &a6, const T7 &a7, const T8 &a8, const T9 &a9) {
        try {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4 << a5 << a6 << a7 << a8 << a9;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    void PushRequest(const char *pszCommand, void (* fn)(void *, CDataStream &), void *param1) {
        uint256 hashReply;
        RAND_bytes((unsigned char *)&hashReply, sizeof(hashReply));
        {
            LOCK(cs_mapRequests);
            mapRequests[hashReply] = CRequestTracker(fn, param1);
        }
        PushMessage(pszCommand, hashReply);
    }

    template<typename T1>
    void PushRequest(const char *pszCommand, const T1 &a1, void (* fn)(void *, CDataStream &), void *param1) {
        uint256 hashReply;
        RAND_bytes((unsigned char *)&hashReply, sizeof(hashReply));
        {
            LOCK(cs_mapRequests);
            mapRequests[hashReply] = CRequestTracker(fn, param1);
        }
        PushMessage(pszCommand, hashReply, a1);
    }

    template<typename T1, typename T2>
    void PushRequest(const char *pszCommand, const T1 &a1, const T2 &a2, void (* fn)(void *, CDataStream &), void *param1) {
        uint256 hashReply;
        RAND_bytes((unsigned char *)&hashReply, sizeof(hashReply));
        {
            LOCK(cs_mapRequests);
            mapRequests[hashReply] = CRequestTracker(fn, param1);
        }
        PushMessage(pszCommand, hashReply, a1, a2);
    }

    void PushGetBlocks(CBlockIndex *pindexBegin, uint256 hashEnd);

    bool IsSubscribed(unsigned int nChannel);
    void Subscribe(unsigned int nChannel, unsigned int nHops=0);
    void CancelSubscribe(unsigned int nChannel);
    void CloseSocketDisconnect();
    void Cleanup();

    //
    // Denial-of-service detection/prevention
    // The idea is to detect peers that are behaving
    // badly and disconnect/ban them, but do it in a
    // one-coding-mistake-won't-shatter-the-entire-network way.
    //
    // IMPORTANT:  There should be nothing I can give a
    // node that it will forward on that will make that
    // node's peers drop it. If there is, an attacker
    // can isolate a node and/or try to split the network.
    // Dropping a node for sending stuff that is invalid
    // now but might be valid in a later version is also
    // dangerous, because it can cause a network split
    // between nodes running old code and nodes running new code.
    //
    static void ClearBanned(); // needed for unit testing
    static bool IsBanned(CNetAddr ip);
    bool Misbehaving(int howmuch); // 1 == a little, 100 == a lot
    void copyStats(CNodeStats &stats);

    // Network stats
    static void RecordBytesRecv(uint64_t bytes);
    static void RecordBytesSent(uint64_t bytes);

    static uint64_t GetTotalBytesRecv();
    static uint64_t GetTotalBytesSent();
};

class CTransaction;
class bitrelay : private no_instance
{
public:
    static void RelayTransaction(const CTransaction &tx, const uint256 &hash);
    static void RelayTransaction(const CTransaction &tx, const uint256 &hash, const CDataStream &ss);

    static void RelayInventory(const CInv &inv) {
        //
        // Put on lists to offer to the other nodes
        //
        {
            LOCK(net_node::cs_vNodes);
            BOOST_FOREACH(CNode *pnode, net_node::vNodes)
            {
                pnode->PushInventory(inv);
            }
        }
    }
};

//
// Return a timestamp in the future (in microseconds) for exponentially distributed events.
//
namespace future_time
{
    int64_t PoissonNextSend(int64_t nNow, int average_interval_seconds);
}

#endif
//@
