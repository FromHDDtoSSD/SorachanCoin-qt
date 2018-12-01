// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "irc.h"
#include "base58.h"
#include "net.h"

class irc : private no_instance
{
private:
    static int nGotIRCAddresses;

    static bool Send(SOCKET hSocket, const char *pszSend);
    static std::string EncodeAddress(const CService &addr);
    static bool DecodeAddress(std::string str, CService &addr);
    static bool RecvLineIRC(SOCKET hSocket, std::string &strLine);

    static int RecvUntil(SOCKET hSocket, const char *psz1, const char *psz2=NULL, const char *psz3=NULL, const char *psz4=NULL);
    static bool Wait(int nSeconds);
    static bool RecvCodeLine(SOCKET hSocket, const char *psz1, std::string &strRet);
    static bool GetIPFromIRC(SOCKET hSocket, std::string strMyName, CNetAddr &ipRet);

    static void ThreadIRCSeed2(void *parg);

#pragma pack(push, 1)
    struct ircaddr
    {
        struct in_addr ip;
        unsigned short port;
    };
#pragma pack(pop)

public:
    static void ThreadIRCSeed(void *parg);
};

//
// namespace irc_ext (irc.h)
// call to net.cpp( StartNode(void *parg) )
//
void irc_ext::ThreadIRCSeed(void *parg) {
    irc::ThreadIRCSeed(parg);
}

//
// static number valiables
//
int irc::nGotIRCAddresses = 0;

///////////////////////////////////////////////////////////////////////////////////////////////////

std::string irc::EncodeAddress(const CService &addr)
{
    struct ircaddr tmp;
    if (addr.GetInAddr(&tmp.ip)) {
        tmp.port = htons(addr.GetPort());

        std::vector<unsigned char> vch(UBEGIN(tmp), UEND(tmp));
        return std::string("u") + base58::manage::EncodeBase58Check(vch);
    }
    return "";
}

bool irc::DecodeAddress(std::string str, CService &addr)
{
    std::vector<unsigned char> vch;
    if (! base58::manage::DecodeBase58Check(str.substr(1), vch)) {
        return false;
    }

    struct ircaddr tmp;
    if (vch.size() != sizeof(tmp)) {
        return false;
    }
    ::memcpy(&tmp, &vch[0], sizeof(tmp));

    addr = CService(tmp.ip, ntohs(tmp.port));
    return true;
}

bool irc::Send(SOCKET hSocket, const char *pszSend)
{
    if (::strstr(pszSend, "PONG") != pszSend) {
        printf("IRC SENDING: %s\n", pszSend);
    }

    const char *psz = pszSend;
    const char *pszEnd = psz + ::strlen(psz);
    while (psz < pszEnd)
    {
        int ret = ::send(hSocket, psz, pszEnd - psz, MSG_NOSIGNAL);
        if (ret < 0) {
            return false;
        }
        psz += ret;
    }
    return true;
}

bool irc::RecvLineIRC(SOCKET hSocket, std::string &strLine)
{
    for ( ; ; )
    {
        bool fRet = net_basis::RecvLine(hSocket, strLine);
        if (fRet) {
            if (args_bool::fShutdown) {
                return false;
            }

            std::vector<std::string> vWords;
            bitstr::ParseString(strLine, ' ', vWords);
            if (vWords.size() >= 1 && vWords[0] == "PING") {
                strLine[1] = 'O';
                strLine += '\r';
                irc::Send(hSocket, strLine.c_str());
                continue;
            }
        }
        return fRet;
    }
}

int irc::RecvUntil(SOCKET hSocket, const char *psz1, const char *psz2/* =NULL */, const char *psz3/* =NULL */, const char *psz4/* =NULL */)
{
    for ( ; ; )
    {
        std::string strLine;
        strLine.reserve(10000);
        if (! irc::RecvLineIRC(hSocket, strLine)) {
            return 0;
        }

        printf("IRC %s\n", strLine.c_str());
        if (psz1 && strLine.find(psz1) != std::string::npos) {
            return 1;
        }
        if (psz2 && strLine.find(psz2) != std::string::npos) {
            return 2;
        }
        if (psz3 && strLine.find(psz3) != std::string::npos) {
            return 3;
        }
        if (psz4 && strLine.find(psz4) != std::string::npos) {
            return 4;
        }
    }
}

bool irc::Wait(int nSeconds)
{
    if (args_bool::fShutdown) {
        return false;
    }

    printf("IRC waiting %d seconds to reconnect\n", nSeconds);
    for (int i = 0; i < nSeconds; ++i)
    {
        if (args_bool::fShutdown) {
            return false;
        }
        util::Sleep(1000);
    }
    return true;
}

bool irc::RecvCodeLine(SOCKET hSocket, const char *psz1, std::string &strRet)
{
    strRet.clear();
    for ( ; ; )
    {
        std::string strLine;
        if (! irc::RecvLineIRC(hSocket, strLine)) {
            return false;
        }

        std::vector<std::string> vWords;
        bitstr::ParseString(strLine, ' ', vWords);
        if (vWords.size() < 2) {
            continue;
        }

        if (vWords[1] == psz1) {
            printf("IRC %s\n", strLine.c_str());
            strRet = strLine;
            return true;
        }
    }
}

bool irc::GetIPFromIRC(SOCKET hSocket, std::string strMyName, CNetAddr &ipRet)
{
    irc::Send(hSocket, strprintf("USERHOST %s\r", strMyName.c_str()).c_str());

    std::string strLine;
    if (! irc::RecvCodeLine(hSocket, "302", strLine)) {
        return false;
    }

    std::vector<std::string> vWords;
    bitstr::ParseString(strLine, ' ', vWords);
    if (vWords.size() < 4) {
        return false;
    }

    std::string str = vWords[3];
    if (str.rfind("@") == std::string::npos) {
        return false;
    }
    std::string strHost = str.substr(str.rfind("@")+1);

    // Hybrid IRC used by lfnet always returns IP when you userhost yourself,
    // but in case another IRC is ever used this should work.
    printf("irc::GetIPFromIRC() got userhost %s\n", strHost.c_str());
    CNetAddr addr(strHost, true);
    if (! addr.IsValid()) {
        return false;
    }
    
    ipRet = addr;
    return true;
}

void irc::ThreadIRCSeed(void *parg)
{
    // Make this thread recognisable as the IRC seeding thread
    bitthread::manage::RenameThread((coin_param::strCoinName + "coin-ircseed").c_str());

    printf("irc::ThreadIRCSeed started\n");

    try {
        irc::ThreadIRCSeed2(parg);
    } catch (const std::exception &e) {
        excep::PrintExceptionContinue(&e, "irc::ThreadIRCSeed()");
    } catch (...) {
        excep::PrintExceptionContinue(NULL, "irc::ThreadIRCSeed()");
    }
    printf("irc::ThreadIRCSeed exited\n");
}

//
// irc.lfnet.org
//
void irc::ThreadIRCSeed2(void *parg)
{
    // Don't connect to IRC if we won't use IPv4 connections.
    if (ext_ip::IsLimited(netbase::NET_IPV4)) {
        return;
    }

    // ... or if we won't make outbound connections and won't accept inbound ones.
    if (map_arg::GetMapArgsCount("-connect") && args_bool::fNoListen) {
        return;
    }

    // ... or if IRC is not enabled.
    if (! map_arg::GetBoolArg("-irc", true)) {
        return;
    }

    printf("irc::ThreadIRCSeed trying to connect...\n");

    int nErrorWait = 10;
    int nRetryWait = 10;
    int nNameRetry = 0;

    while (! args_bool::fShutdown)
    {
        const uint16_t nIrcPort = tcp_port::uIrc;
        CService addrConnect(tcp_ip::strSeedMaster, nIrcPort); // www.junkhdd.com

        CService addrIRC(tcp_domain::strMain, nIrcPort, true);
        if (addrIRC.IsValid()) {
            addrConnect = addrIRC;
        }

        SOCKET hSocket;
        if (! netbase::manage::ConnectSocket(addrConnect, hSocket)) {
            printf("IRC connect failed\n");
            nErrorWait = nErrorWait * 11 / 10;
            if (irc::Wait(nErrorWait += 60)) {
                continue;
            } else {
                return;
            }
        }

        if (! irc::RecvUntil(hSocket, "Found your hostname", "using your IP address instead", "Couldn't look up your hostname", "ignoring hostname")) {
            netbase::manage::CloseSocket(hSocket);
            nErrorWait = nErrorWait * 11 / 10;
            if (irc::Wait(nErrorWait += 60)) {
                continue;
            } else {
                return;
            }
        }

        CNetAddr addrIPv4("1.2.3.4"); // arbitrary IPv4 address to make GetLocal prefer IPv4 addresses
        CService addrLocal;
        std::string strMyName;

        //
        // Don't use our IP as our nick if we're not listening
        // or if it keeps failing because the nick is already in use.
        //
        if (!args_bool::fNoListen && ext_ip::GetLocal(addrLocal, &addrIPv4) && nNameRetry < 3) {
            strMyName = irc::EncodeAddress(ext_ip::GetLocalAddress(&addrConnect));
        }
        if (strMyName.empty()) {
            strMyName = strprintf("x%" PRIu64 "", bitsystem::GetRand(1000000000));
        }

        irc::Send(hSocket, strprintf("NICK %s\r", strMyName.c_str()).c_str());
        irc::Send(hSocket, strprintf("USER %s 8 * : %s\r", strMyName.c_str(), strMyName.c_str()).c_str());

        int nRet = irc::RecvUntil(hSocket, " 004 ", " 433 ");
        if (nRet != 1) {
            netbase::manage::CloseSocket(hSocket);
            if (nRet == 2) {
                printf("IRC name already in use\n");
                nNameRetry++;
                irc::Wait(10);
                continue;
            }

            nErrorWait = nErrorWait * 11 / 10;
            if (irc::Wait(nErrorWait += 60)) {
                continue;
            } else {
                return;
            }
        }
        nNameRetry = 0;
        util::Sleep(500);

        //
        // Get our external IP from the IRC server and re-nick before joining the channel
        //
        CNetAddr addrFromIRC;
        if (irc::GetIPFromIRC(hSocket, strMyName, addrFromIRC)) {
            printf("irc::GetIPFromIRC() returned %s\n", addrFromIRC.ToString().c_str());

            //
            // Don't use our IP as our nick if we're not listening
            //
            if (!args_bool::fNoListen && addrFromIRC.IsRoutable()) {
                //
                // IRC lets you to re-nick
                //
                ext_ip::AddLocal(addrFromIRC, LOCAL_IRC);
                strMyName = irc::EncodeAddress(ext_ip::GetLocalAddress(&addrConnect));
                irc::Send(hSocket, strprintf("NICK %s\r", strMyName.c_str()).c_str());
            }
        }

        if (args_bool::fTestNet) {
            irc::Send(hSocket, "JOIN #coinTEST2\r");
            irc::Send(hSocket, "WHO #coinTEST2\r");
        } else {
            //
            // randomly join #coin00-#coin05
            // int channel_number = bitsystem::GetRandInt(5);
            //
            // Channel number is always 0 for initial release
            //
            int channel_number = 0;
            irc::Send(hSocket, strprintf("JOIN #coin%02d\r", channel_number).c_str());
            irc::Send(hSocket, strprintf("WHO #coin%02d\r", channel_number).c_str());
        }

        int64_t nStart = bitsystem::GetTime();
        std::string strLine;
        strLine.reserve(10000);
        while (!args_bool::fShutdown && irc::RecvLineIRC(hSocket, strLine))
        {
            if (strLine.empty() || strLine.size() > 900 || strLine[0] != ':') {
                continue;
            }

            std::vector<std::string> vWords;
            bitstr::ParseString(strLine, ' ', vWords);
            if (vWords.size() < 2) {
                continue;
            }

            std::string strName;

            if (vWords[1] == "352" && vWords.size() >= 8) {
                //
                // index 7 is limited to 16 characters
                // could get full length name at index 10, but would be different from join messages
                //
                strName = vWords[7];
                printf("IRC got who\n");
            }

            if (vWords[1] == "JOIN" && vWords[0].size() > 1) {
                //
                // :username!username@50000007.F000000B.90000002.IP JOIN :#channelname
                //
                strName = vWords[0].substr(1, vWords[0].find('!', 1) - 1);
                printf("IRC got join\n");
            }

            if (strName.compare(0,1, "u") == 0) {
                CAddress addr;
                if (irc::DecodeAddress(strName, addr)) {
                    addr.set_nTime( bitsystem::GetAdjustedTime() );
                    if (net_node::addrman.Add(addr, addrConnect, 51 * 60)) {
                        printf("IRC got new address: %s\n", addr.ToString().c_str());
                    }
                    irc::nGotIRCAddresses++;
                } else {
                    printf("IRC decode failed\n");
                }
            }
        }
        netbase::manage::CloseSocket(hSocket);

        if (bitsystem::GetTime() - nStart > 20 * 60) {
            nErrorWait /= 3;
            nRetryWait /= 3;
        }

        nRetryWait = nRetryWait * 11 / 10;
        if (! irc::Wait(nRetryWait += 60)) {
            return;
        }
    }
}

#ifdef TEST
int main(int argc, char *argv[])
{
    WSADATA wsadata;
    if (::WSAStartup(MAKEWORD(2,2), &wsadata) != NO_ERROR) {
        printf("Error at WSAStartup()\n");
        return false;
    }

    irc::ThreadIRCSeed(NULL);

    ::WSACleanup();
    return 0;
}
#endif
