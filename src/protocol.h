// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef __cplusplus
#error This header can only be compiled as C++.
#endif

#ifndef __INCLUDED_PROTOCOL_H__
#define __INCLUDED_PROTOCOL_H__

#include "serialize.h"
#include "netbase.h"
#include <string>
#include <limits>
#include "uint256.h"
#include "util.h"

namespace protocol
{
    const std::string forfill[] = { "ERROR", "tx", "block" }; // TODO: Replace with initializer list constructor when c++11 comes
    const std::vector<std::string> vpszTypeName(forfill, forfill + 3);

    /** nServices flags */
    enum
    {
        NODE_NETWORK = (1 << 0)
    };
}

/** Message header.
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
class CMessageHeader
{
private:
    CMessageHeader(const CMessageHeader &); // {}
    CMessageHeader &operator=(const CMessageHeader &); // {}

    enum CMD_SIZE
    {
        MESSAGE_START_SIZE    = sizeof(block_info::gpchMessageStart),
        COMMAND_SIZE        = 12,

        MESSAGE_SIZE_SIZE    = sizeof(int),
        CHECKSUM_SIZE        = sizeof(int),
        MESSAGE_SIZE_OFFSET = MESSAGE_START_SIZE + COMMAND_SIZE,
        CHECKSUM_OFFSET        = MESSAGE_SIZE_OFFSET + MESSAGE_SIZE_SIZE
    };

    unsigned int nMessageSize;
    unsigned int nChecksum;
    char mpchMessageStart[CMD_SIZE::MESSAGE_START_SIZE];
    char pchCommand[CMD_SIZE::COMMAND_SIZE];

public:
    CMessageHeader();
    CMessageHeader(const char *pszCommand, unsigned int nMessageSizeIn);

    std::string GetCommand() const;
    bool IsValid() const;

    unsigned int GetMessageSize() const { return nMessageSize; }
    unsigned int GetChecksum() const { return nChecksum; }
    static unsigned int GetMessageSizeOffset() { return CMD_SIZE::MESSAGE_SIZE_OFFSET; }
    static unsigned int GetChecksumOffset() { return CMD_SIZE::CHECKSUM_OFFSET; }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(FLATDATA(this->mpchMessageStart));
        READWRITE(FLATDATA(this->pchCommand));
        READWRITE(this->nMessageSize);
        READWRITE(this->nChecksum);
    )
};

/** A CService with information about it as peer */
class CAddress : public CService
{
//private:
//    CAddress(const CAddress &); // {}
//    CAddress &operator=(const CAddress &); // {}
public:
    CAddress() : CService(), nServices(protocol::NODE_NETWORK), nTime(100000000), nLastTry(0) {}
    explicit CAddress(CService ipIn, uint64_t nServicesIn=protocol::NODE_NETWORK) : CService(ipIn), nServices(nServicesIn), nTime(100000000), nLastTry(0) {}
    explicit CAddress(CService ipIn, uint64_t nServicesIn, unsigned int nTimeIn) : CService(ipIn), nServices(nServicesIn), nTime(nTimeIn), nLastTry(0) {}

protected:
    uint64_t nServices;

    // memory only
    int64_t nLastTry;

    // disk and network only
    unsigned int nTime;

public:
    void add_nServices(uint64_t nServicesIn) { nServices |= nServicesIn; }
    uint64_t get_nServices() const { return nServices; }

    int64_t get_nLastTry() const { return nLastTry; }

    unsigned int get_nTime() const { return nTime; }
    void set_nTime(unsigned int nTimeIn) { nTime = nTimeIn; }

    IMPLEMENT_SERIALIZE
    (
        CAddress *pthis = const_cast<CAddress *>(this);
        CService *pip = (CService *)pthis;
        if (fRead) {
            pthis->Init();
        }
        if (nType & SER_DISK) {
            READWRITE(nVersion);
        }
        if ((nType & SER_DISK) || (nVersion >= version::CADDR_TIME_VERSION && !(nType & SER_GETHASH))) {
            READWRITE(this->nTime);
        }

        READWRITE(this->nServices);
        READWRITE(*pip);
    )
};

//
// inv message data
//
//
// constructor int typeIn param, namespace protocol
// static const std::string forfill[] = { "ERROR", "tx", "block" };
//
enum _CINV_MSG_TYPE: int
{
    MSG_ERROR = 0,
    MSG_TX = 1,
    MSG_BLOCK
};

class CInv
{
//private:
//    CInv(const CInv &obj); // {}
//    CInv &operator=(const CInv &); // {}

public:
    CInv() : type(_CINV_MSG_TYPE::MSG_ERROR), hash(0) {}
    CInv(_CINV_MSG_TYPE typeIn, const uint256 &hashIn) : type(typeIn), hash(hashIn) {}
    CInv(const std::string &strType, const uint256 &hashIn) : hash(hashIn) {
        unsigned int i = 1;    // _CINV_MSG_TYPE::MSG_TX
        for (; i < protocol::vpszTypeName.size(); ++i)
        {
            if (strType.compare(protocol::vpszTypeName[i]) == 0) {
                type = (_CINV_MSG_TYPE)i;
                break;
            }
        }
        if (i == protocol::vpszTypeName.size()) {
            throw std::out_of_range(strprintf("CInv::CInv(std::string, uint256) : unknown type '%s'", strType.c_str()));
        }
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->type);
        READWRITE(this->hash);
    )

    bool IsKnownType() const {
        return (type >= 1 && type < (int)protocol::vpszTypeName.size());
    }
    const char *GetCommand() const {
        if (! IsKnownType()) {
            throw std::out_of_range(strprintf("CInv::GetCommand() : type=%d unknown type", type));
        }
        return protocol::vpszTypeName[type].c_str();
    }
    std::string ToString() const {
        return strprintf("%s %s", GetCommand(), this->hash.ToString().substr(0,20).c_str());
    }

    friend bool operator<(const CInv &a, const CInv &b) {
        return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
    }

private:
    _CINV_MSG_TYPE type;
    uint256 hash;

public:
    _CINV_MSG_TYPE get_type() const { return type; }
    const uint256 &get_hash() const { return hash; }
};

#endif
//@
