#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#ifndef WIN32
#include <unistd.h>
#endif

#include "netbase.h"
#include "net.h"
//#include "util.h"
#include "ui_interface.h"

/*
 * NTP uses two fixed point formats.  The first (ntp::l_fp) is the "long"
 * format and is 64 bits long with the decimal between bits 31 and 32.
 * This is used for time stamps in the NTP packet header (in network
 * byte order) and for internal computations of offsets (in local host
 * byte order). We use the same structure for both signed and unsigned
 * values, which is a big hack but saves rewriting all the operators
 * twice. Just to confuse this, we also sometimes just carry the
 * fractional part in calculations, in both signed and unsigned forms.
 * Anyway, an ntp::l_fp looks like:
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Integral Part                         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Fractional Part                       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * REF http://www.eecis.udel.edu/~mills/database/rfc/rfc2030.txt
 */
//

class ntp : private no_instance
{
private:
    typedef struct
    {
        union
        {
            uint32_t Xl_ui;
            int32_t Xl_i;
        } Ul_i;
        union
        {
            uint32_t Xl_uf;
            int32_t Xl_f;
        } Ul_f;
    } l_fp;

    struct pkt
    {
        uint8_t  li_vn_mode;        /* leap indicator, version and mode */
        uint8_t  stratum;           /* peer stratum */
        uint8_t  ppoll;             /* peer poll interval */
        int8_t  precision;          /* peer clock precision */
        uint32_t    rootdelay;      /* distance to primary clock */
        uint32_t    rootdispersion; /* clock dispersion */
        uint32_t refid;             /* reference clock ID */
        l_fp    ref;                /* time peer clock was last updated */
        l_fp    org;                /* originate time stamp */
        l_fp    rec;                /* receive time stamp */
        l_fp    xmt;                /* transmit time stamp */

        uint32_t exten[1];          /* misused */
        uint8_t  mac[5 * sizeof(uint32_t)];     /* mac */
    };

    //
    // NTP server, which we unconditionally trust. This may be your own installation of ntpd somewhere, 
    // for example. 
    // "localhost" means "trust no one"
    //
    static std::string strTrustedUpstream;

    //
    // Current offset
    //
    static int64_t nNtpOffset;    // variable (no const)

    // static const int nServersCount = 5;
    static const std::string NtpServers[5];

    static void Ntp2Unix(const uint32_t &n, time_t &u);
    static void ntohl_fp(l_fp *n, l_fp *h);

    static bool InitWithHost(const std::string &strHostName, SOCKET &sockfd, socklen_t &servlen, struct sockaddr *pcliaddr);
    static bool InitWithRandom(SOCKET &sockfd, socklen_t &servlen, struct sockaddr *pcliaddr);

    static int64_t DoReq(SOCKET sockfd, socklen_t servlen, struct sockaddr cliaddr);

public:
    static void SetTrustedUpstream(const std::string &strArg, const std::string &strDefault=tcp_domain::strLocal);

    static int64_t NtpGetTime(CNetAddr &ip);
    static int64_t NtpGetTime(const std::string &strHostName);

    static int64_t GetNtpOffset();
    static void ThreadNtpSamples(void *parg);
};

namespace ntp_ext
{
    void SetTrustedUpstream(const std::string &strArg, const std::string &strDefault=tcp_domain::strLocal) {
        ntp::SetTrustedUpstream(strArg, strDefault);
    }

    int64_t NtpGetTime(CNetAddr &ip) {
        return ntp::NtpGetTime(ip);
    }

    int64_t NtpGetTime(const std::string &strHostName) {
        return ntp::NtpGetTime(strHostName);
    }

    int64_t GetNtpOffset() {
        return ntp::GetNtpOffset();
    }

    void ThreadNtpSamples(void *parg) {
        ntp::ThreadNtpSamples(parg);
    }
}

std::string ntp::strTrustedUpstream = tcp_domain::strLocal;
int64_t ntp::nNtpOffset = INT64_MAX;
// const int ntp::nServersCount = 5;
const std::string ntp::NtpServers[5] = {
    tcp_domain::strSub,

    "time1.google.com",
    "time2.google.com",
    "time3.google.com",
    "time4.google.com"
};

///////////////////////////////////////////////////////////////////////////////////////////////////

void ntp::SetTrustedUpstream(const std::string &strArg, const std::string &strDefault/* =tcp_domain::strLocal */)
{
    ntp::strTrustedUpstream = map_arg::GetArg(strArg, strDefault);
}

void ntp::Ntp2Unix(const uint32_t &n, time_t &u)
{
    // Ntp's time scale starts in 1900, Unix in 1970.

    u = n - 0x83aa7e80; // 2208988800 1970 - 1900 in seconds
}

void ntp::ntohl_fp(l_fp *n, l_fp *h)
{
    (h)->Ul_i.Xl_ui = ntohl((n)->Ul_i.Xl_ui);
    (h)->Ul_f.Xl_uf = ntohl((n)->Ul_f.Xl_uf);
}

bool ntp::InitWithHost(const std::string &strHostName, SOCKET &sockfd, socklen_t &servlen, struct sockaddr *pcliaddr)
{
    sockfd = INVALID_SOCKET;

    std::vector<CNetAddr> vIP;
    bool fRet = netbase::manage::LookupHost(strHostName.c_str(), vIP, 10, true);
    if (! fRet) {
        return false;
    }

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(123);

    bool found = false;
    for(unsigned int i = 0; i < vIP.size(); ++i)
    {
        if ((found = vIP[i].GetInAddr(&servaddr.sin_addr)) != false) {
            break;
        }
    }
    if (! found) {
        return false;
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd == INVALID_SOCKET) {
        return false; // socket initialization error
    }
    if (::connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) == -1 ) {
        return false; // "connection" error
    }

    *pcliaddr = *((struct sockaddr *)&servaddr);
    servlen = sizeof(servaddr);

    return true;
}

bool ntp::InitWithRandom(SOCKET &sockfd, socklen_t &servlen, struct sockaddr *pcliaddr)
{
    // for (int nAttempt = 0; nAttempt < ntp::nServersCount; ++nAttempt)
    for (int nAttempt = 0; nAttempt < ARRAYLEN(ntp::NtpServers); ++nAttempt)
    {
        // int nServerNum = bitsystem::GetRandInt(nServersCount);
        int nServerNum = bitsystem::GetRandInt(ARRAYLEN(ntp::NtpServers));
        if (ntp::InitWithHost(ntp::NtpServers[nServerNum], sockfd, servlen, pcliaddr)) {
            return true;
        }
    }

    return false;
}

int64_t ntp::DoReq(SOCKET sockfd, socklen_t servlen, struct sockaddr cliaddr)
{
#ifdef WIN32
    u_long nOne = 1;
    if (::ioctlsocket(sockfd, FIONBIO, &nOne) == SOCKET_ERROR) {
        printf("ntp::ConnectSocket() : ioctlsocket non-blocking setting failed, error %d\n", WSAGetLastError());
#else
    if (::fcntl(sockfd, F_SETFL, O_NONBLOCK) == SOCKET_ERROR) {
        printf("ntp::ConnectSocket() : fcntl non-blocking setting failed, error %d\n", errno);
#endif
        return -2;
    }

    struct timeval timeout = {10, 0};
    struct pkt *msg = new(std::nothrow) pkt;
    struct pkt *prt  = new(std::nothrow) pkt;
    if(!msg || !prt) {
        if(msg) { delete msg; }
        if(prt) { delete prt; }
        printf("ntp::ConnectSocket() : msg and prt memory allocate failure, error %d\n", errno);
        return -2;
    }

    time_t seconds_transmit;
    int len = 48;

    msg->li_vn_mode=227;
    msg->stratum=0;
    msg->ppoll=4;
    msg->precision=0;
    msg->rootdelay=0;
    msg->rootdispersion=0;

    msg->ref.Ul_i.Xl_i=0;
    msg->ref.Ul_f.Xl_f=0;
    msg->org.Ul_i.Xl_i=0;
    msg->org.Ul_f.Xl_f=0;
    msg->rec.Ul_i.Xl_i=0;
    msg->rec.Ul_f.Xl_f=0;
    msg->xmt.Ul_i.Xl_i=0;
    msg->xmt.Ul_f.Xl_f=0;

    int retcode = ::sendto(sockfd, (char *) msg, len, 0, &cliaddr, servlen);
    if (retcode < 0) {
        printf("sendto() failed: %d\n", retcode);
        seconds_transmit = -3;
        goto _end;
    }

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);

    retcode = ::select(sockfd + 1, &fdset, NULL, NULL, &timeout);
    if (retcode <= 0) {
        printf("ntp recvfrom() error\n");
        seconds_transmit = -4;
        goto _end;
    }

    ::recvfrom(sockfd, (char *) msg, len, 0, NULL, NULL);
    ntohl_fp(&msg->xmt, &prt->xmt);
    Ntp2Unix(prt->xmt.Ul_i.Xl_ui, seconds_transmit);

_end:
    delete msg;
    delete prt;
    return seconds_transmit;
}

int64_t ntp::NtpGetTime(CNetAddr &ip)
{
    struct sockaddr cliaddr;

    SOCKET sockfd;
    socklen_t servlen;
    if (! ntp::InitWithRandom(sockfd, servlen, &cliaddr)) {
        return -1;
    }

    ip = CNetAddr(((sockaddr_in *)&cliaddr)->sin_addr);
    int64_t nTime = ntp::DoReq(sockfd, servlen, cliaddr);

    netbase::manage::CloseSocket(sockfd);
    return nTime;
}

int64_t ntp::NtpGetTime(const std::string &strHostName)
{
    struct sockaddr cliaddr;

    SOCKET sockfd;
    socklen_t servlen;
    if (! ntp::InitWithHost(strHostName, sockfd, servlen, &cliaddr)) {
        return -1;
    }

    int64_t nTime = ntp::DoReq(sockfd, servlen, cliaddr);

    netbase::manage::CloseSocket(sockfd);
    return nTime;
}

int64_t ntp::GetNtpOffset()
{
    return ntp::nNtpOffset;
}

void ntp::ThreadNtpSamples(void *parg)
{
    const int64_t nMaxOffset = util::nOneDay; // Not a real limit, just sanity threshold.

    printf("Trying to find NTP server at localhost...\n");

    std::string strLocalHost = net_basis::strLocal;
    if (NtpGetTime(strLocalHost) == bitsystem::GetTime()) {
        printf("There is NTP server active at localhost,  we don't need NTP thread.\n");
        nNtpOffset = 0;
        return;
    }

    printf("ThreadNtpSamples started\n");
    net_node::vnThreadsRunning[THREAD_NTP]++;

    // Make this thread recognisable as time synchronization thread
    bitthread::manage::RenameThread((coin_param::strCoinName + "-ntp-samples").c_str());

    CMedianFilter<int64_t> vTimeOffsets(200,0);

    while (! args_bool::fShutdown)
    {
        if (strTrustedUpstream != tcp_domain::strLocal) {
            // Trying to get new offset sample from trusted NTP server.
            int64_t nClockOffset = NtpGetTime(strTrustedUpstream) - bitsystem::GetTime();

            if (util::abs64(nClockOffset) < nMaxOffset) {
                // Everything seems right, remember new trusted offset.
                printf("ThreadNtpSamples: new offset sample from %s, offset=%" PRId64 ".\n", strTrustedUpstream.c_str(), nClockOffset);
                nNtpOffset = nClockOffset;
            } else {
                // Something went wrong, disable trusted offset sampling.
                nNtpOffset = INT64_MAX;
                strTrustedUpstream = tcp_domain::strLocal;

                int nSleepMinutes = 1 + bitsystem::GetRandInt(9); // Sleep for 1-10 minutes.
                for (int i = 0; i < nSleepMinutes * 60 && !args_bool::fShutdown; ++i)
                {
                    util::Sleep(1000);
                }

                continue;
            }
        } else {
            // Now, trying to get 2-4 samples from random NTP servers.
            int nSamplesCount = 2 + bitsystem::GetRandInt(2);

            for (int i = 0; i < nSamplesCount; ++i)
            {
                CNetAddr ip;
                int64_t nClockOffset = NtpGetTime(ip) - bitsystem::GetTime();

                if (util::abs64(nClockOffset) < nMaxOffset) { // Skip the deliberately wrong timestamps
                    printf("ThreadNtpSamples: new offset sample from %s, offset=%" PRId64 ".\n", ip.ToString().c_str(), nClockOffset);
                    vTimeOffsets.input(nClockOffset);
                }
            }

            if (vTimeOffsets.size() > 1) {
                nNtpOffset = vTimeOffsets.median();
            } else {
                // Not enough offsets yet, try to collect additional samples later.
                nNtpOffset = INT64_MAX;
                int nSleepMinutes = 1 + bitsystem::GetRandInt(4); // Sleep for 1-5 minutes.
                for (int i = 0; i < nSleepMinutes * 60 && !args_bool::fShutdown; ++i)
                {
                    util::Sleep(1000);
                }

                continue;
            }
        }

        if (bitsystem::GetNodesOffset() == INT_MAX && util::abs64(nNtpOffset) > 40 * 60) {
            // If there is not enough node offsets data and NTP time offset is greater than 40 minutes then give a warning.
            std::string strMessage = _(("Warning: Please check that your computer's date and time are correct! If your clock is wrong " + coin_param::strCoinName + " will not work properly.").c_str());
            excep::set_strMiscWarning( strMessage );
            printf("*** %s\n", strMessage.c_str());
            CClientUIInterface::uiInterface.ThreadSafeMessageBox(strMessage+" ", coin_param::strCoinName, CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION);
        }

        printf("nNtpOffset = %+" PRId64 "  (%+" PRId64 " minutes)\n", nNtpOffset, nNtpOffset/60);

        int nSleepHours = 1 + bitsystem::GetRandInt(5); // Sleep for 1-6 hours.
        for (int i = 0; i < nSleepHours * 3600 && !args_bool::fShutdown; ++i)
        {
            util::Sleep(1000);
        }
    }

    net_node::vnThreadsRunning[THREAD_NTP]--;
    printf("ThreadNtpSamples exited\n");
}
