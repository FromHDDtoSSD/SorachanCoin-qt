/*
 * Get External IP address by STUN protocol
 *
 * Based on project Minimalistic STUN client "ministun"
 * https://code.google.com/p/ministun/
 *
 * This program is free software, distributed under the terms of the GNU General Public License Version 2. See the LICENSE file at the top of the source tree.
 *
 * STUN is described in RFC3489 and it is based on the exchange
 * of UDP packets between a client and one or more servers to
 * determine the externally visible address (and port) of the client
 * once it has gone through the NAT boxes that connect it to the
 * outside.
 * The simplest request packet is just the header defined in
 * struct stun_header, and from the response we may just look at
 * one attribute, STUN_MAPPED_ADDRESS, that we find in the response.
 * By doing more transactions with different server addresses we
 * may determine more about the behaviour of the NAT boxes, of
 * course - the details are in the RFC.
 *
 * All STUN packets start with a simple header made of a type,
 * length (excluding the header) and a 16-byte random transaction id.
 * Following the header we may have zero or more attributes, each
 * structured as a type, length and a value (whose format depends
 * on the type, but often contains addresses).
 * Of course all fields are in network format.
 */

#include <stdio.h>
#include <inttypes.h>
#include <limits>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#ifndef WIN32
#include <unistd.h>
#endif
#include <time.h>
#include <errno.h>

#include "ministun.h"
#include "netbase.h"
#include "net.h"
#include "util.h"

class stun : private no_instance
{
private:
    struct StunSrv 
    {
        char     name[30];
        uint16_t port;
    };

    ///// [STUN protocol] /////

    //
    // callback type to be invoked on stun responses.
    //
    typedef int (stun_cb_f)(struct stun_attr *attr, void *arg);

    // static const int StunSrvListQty;    // Must be PRIME!!!!!
    static const struct StunSrv StunSrvList[2];
    static uint64_t randfiller;            // helper function to generate a random request id

    static int stun_send(int s, struct sockaddr_in *dst, struct stun_header *resp);
    static void stun_req_id(struct stun_header *req);

    static int stun_handle_packet(int s, struct sockaddr_in *src, unsigned char *data, size_t len, stun_cb_f *stun_cb, void *arg);
    static int stun_get_mapped(struct stun_attr *attr, void *arg);

    static int StunRequest2(int sock, struct sockaddr_in *server, struct sockaddr_in *mapped);
    static int StunRequest(const char *host, uint16_t port, struct sockaddr_in *mapped);

public:
    //
    // [STUN protocol] GET External IP
    //
    static int GetExternalIPbySTUN(uint64_t rnd, struct sockaddr_in *mapped, const char **srv);
};

// namespace stun_ext (net.h) call to net.cpp
int stun_ext::GetExternalIPbySTUN(uint64_t rnd, struct sockaddr_in *mapped, const char **srv) {
    return stun::GetExternalIPbySTUN(rnd, mapped, srv);
}

// const int stun::StunSrvListQty = 2; // Must be PRIME!!!!!
const struct stun::StunSrv stun::StunSrvList[2] = {
    {SORACHANCOIN_SUB_DOMAIN, tcp_port::uStun},
    {SORACHANCOIN_MAIN_DOMAIN, tcp_port::uStun}
};
uint64_t stun::randfiller = bitsystem::GetRand(std::numeric_limits<uint64_t>::max());

///////////////////////////////////////////////////////////////////////////////////////////////////

/* wrapper to send an STUN message */
int stun::stun_send(int s, struct sockaddr_in *dst, struct stun_header *resp)
{
    return sendto(s, (const char *)resp, ntohs(resp->msglen) + sizeof(*resp), 0, (struct sockaddr *)dst, sizeof(*dst));
}

void stun::stun_req_id(struct stun_header *req)
{
    const uint64_t *S_block = (const uint64_t *)stun::StunSrvList;

    req->id.id[0] = bitsystem::GetRandInt(std::numeric_limits<int32_t>::max());
    req->id.id[1] = bitsystem::GetRandInt(std::numeric_limits<int32_t>::max());
    req->id.id[2] = bitsystem::GetRandInt(std::numeric_limits<int32_t>::max());
    req->id.id[3] = bitsystem::GetRandInt(std::numeric_limits<int32_t>::max());

    req->id.id[0] |= 0x55555555;
    req->id.id[1] &= 0x55555555;
    req->id.id[2] |= 0x55555555;
    req->id.id[3] &= 0x55555555;
    char x = 20;
    do
    {
        uint32_t s_elm = S_block[(uint8_t)stun::randfiller];
        randfiller ^= (randfiller << 5) | (randfiller >> (64 - 5));
        randfiller += s_elm ^ x;
        req->id.id[x & 3] ^= randfiller + (randfiller >> 13);
    } while(--x);
}

/* handle an incoming STUN message.
 *
 * Do some basic sanity checks on packet size and content,
 * try to extract a bit of information, and possibly reply.
 * At the moment this only processes BIND requests, and returns
 * the externally visible address of the request.
 * If a callback is specified, invoke it with the attribute.
 */
int stun::stun_handle_packet(int s, struct sockaddr_in *src, unsigned char *data, size_t len, stun_cb_f *stun_cb, void *arg)
{
    struct stun_header *hdr = (struct stun_header *)data;
    struct stun_attr *attr;
    int ret = len;
    unsigned int x;

    /* On entry, 'len' is the length of the udp payload. After the initial checks it becomes the size of unprocessed options, while 'data' is advanced accordingly. */
    if (len < sizeof(struct stun_header)) {
        return -20;
    }

    len -= sizeof(struct stun_header);
    data += sizeof(struct stun_header);
    x = ntohs(hdr->msglen); /* len as advertised in the message */
    if(x < len) {
        len = x;
    }

    while (len)
    {
        if (len < sizeof(struct stun_attr)) {
            ret = -21;
            break;
        }
        attr = (struct stun_attr *)data;

        /* compute total attribute length */
        x = ntohs(attr->len) + sizeof(struct stun_attr);
        if (x > len) {
            ret = -22;
            break;
        }
        stun_cb(attr, arg);

        /* Clear attribute id: in case previous entry was a string, this will act as the terminator for the string. */
        attr->attr = 0;
        data += x;
        len -= x;
    }

    /* Null terminate any string.
     * XXX NOTE, we write past the size of the buffer passed by the caller, so this is potentially dangerous. 
     * The only thing that saves us is that usually we read the incoming message in a much larger buffer
     */
    *data = '\0';

    /* Now prepare to generate a reply, which at the moment is done
     * only for properly formed (len == 0) STUN_BINDREQ messages.
     */
    return ret;
}

/* Extract the STUN_MAPPED_ADDRESS from the stun response.
 * This is used as a callback for stun_handle_response
 * when called from stun_request.
 */
int stun::stun_get_mapped(struct stun_attr *attr, void *arg)
{
    struct stun_addr *addr = (struct stun_addr *)(attr + 1);
    struct sockaddr_in *sa = (struct sockaddr_in *)arg;

    if (ntohs(attr->attr) != STUN_MAPPED_ADDRESS || ntohs(attr->len) != 8) {
        return 1; /* not us. */
    }

    sa->sin_port = addr->port;
    sa->sin_addr.s_addr = addr->addr;
    return 0;
}

int stun::StunRequest2(int sock, struct sockaddr_in *server, struct sockaddr_in *mapped)
{
    unsigned char reqdata[1024];

    struct stun_header *req = (struct stun_header *)reqdata;
    stun::stun_req_id(req);
    unsigned short reqlen = 0;
    req->msgtype = 0;
    req->msglen = 0;
    req->msglen = htons(reqlen);
    req->msgtype = htons(STUN_BINDREQ);

    unsigned char reply_buf[1024];
    fd_set rfds;
    struct timeval to = { STUN_TIMEOUT, 0 };
    struct sockaddr_in src;
#ifdef WIN32
    int srclen;
#else
    socklen_t srclen;
#endif

    int res = stun::stun_send(sock, server, req);
    if(res < 0) {
        return -10;
    }

    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    res = ::select(sock + 1, &rfds, NULL, NULL, &to);
    if (res <= 0)  {/* timeout or error */
        return -11;
    }

    ::memset(&src, 0, sizeof(src));
    srclen = sizeof(src);

    /* XXX pass -1 in the size, because stun_handle_packet might
     * write past the end of the buffer.
     */
    res = ::recvfrom(sock, (char *)reply_buf, sizeof(reply_buf) - 1, 0, (struct sockaddr *)&src, &srclen);
    if (res <= 0) {
        return -12;
    }

    ::memset(mapped, 0, sizeof(struct sockaddr_in));
    return stun::stun_handle_packet(sock, &src, reply_buf, res, stun::stun_get_mapped, mapped);
}

int stun::StunRequest(const char *host, uint16_t port, struct sockaddr_in *mapped)
{
    struct hostent *hostinfo = ::gethostbyname(host);
    if(hostinfo == NULL) {
        return -1;
    }

    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server, client;
    ::memset(&server, 0, sizeof(server));
    ::memset(&client, 0, sizeof(client));
    server.sin_family = client.sin_family = AF_INET;

    server.sin_addr = *(struct in_addr *)hostinfo->h_addr;
    server.sin_port = htons(port);

    sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == INVALID_SOCKET) {
        return -2;
    }

    client.sin_addr.s_addr = htonl(INADDR_ANY);

    int rc = -3;
    if(::bind(sock, (struct sockaddr *)&client, sizeof(client)) >= 0) {
        rc = stun::StunRequest2(sock, &server, mapped);
    }

    netbase::manage::CloseSocket(sock);
    return rc;
}

//
// Input: two random values (pos, step) for generate uniuqe way over server
// list
// Output: populate struct struct mapped
// Retval:
//
int stun::GetExternalIPbySTUN(uint64_t rnd, struct sockaddr_in *mapped, const char **srv)
{
    randfiller    = rnd;
    uint16_t pos  = rnd;

    const int StunSrvListQty = ARRAYLEN(stun::StunSrvList);

    uint16_t step;
    do
    {
        rnd = (rnd >> 8) | 0xff00000000000000LL;
        step = rnd % StunSrvListQty;
    } while(step == 0);

    for (uint16_t attempt = 1; attempt < StunSrvListQty * 2; ++attempt)
    {
        pos = (pos + step) % StunSrvListQty;
        int rc = stun::StunRequest(*srv = stun::StunSrvList[pos].name, stun::StunSrvList[pos].port, mapped);
        if(rc >= 0) {
            return attempt;
        }
    }
    return -1;
}
