// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __cplusplus
#error This header can only be compiled as C++.
#endif

#ifndef __INCLUDED_PROTOCOL_H__
#define __INCLUDED_PROTOCOL_H__

#include <serialize.h>
#include <netbase.h>
#include <string>
#include <limits>
#include <uint256.h>
#include <util.h>
#include <block/block_info.h>

namespace protocol {
    /** nServices flags */
    enum {
        NODE_NETWORK = (1 << 0)
    };
}

/** Message header.
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
class CMessageHeader {
    CMessageHeader(const CMessageHeader &)=delete;
    CMessageHeader &operator=(const CMessageHeader &)=delete;
    CMessageHeader(CMessageHeader &&)=delete;
    CMessageHeader &operator=(CMessageHeader &&)=delete;

private:
    static_assert(sizeof(block_info::gpchMessageStart)==4, "CMessageHeader: MESSAGE_START_SIZE Error");
    static_assert(sizeof(int)==4, "CMessageHeader: sizeof(int) Error");
    enum CMD_SIZE {
        MESSAGE_START_SIZE   = sizeof(block_info::gpchMessageStart),
        COMMAND_SIZE         = 12,

        MESSAGE_SIZE_SIZE    = sizeof(int),
        CHECKSUM_SIZE        = sizeof(int),
        MESSAGE_SIZE_OFFSET  = MESSAGE_START_SIZE + COMMAND_SIZE,
        CHECKSUM_OFFSET      = MESSAGE_SIZE_OFFSET + MESSAGE_SIZE_SIZE,

        HEADER_SIZE          = MESSAGE_START_SIZE + COMMAND_SIZE + MESSAGE_SIZE_SIZE + CHECKSUM_SIZE
    };

    unsigned int nMessageSize;
    unsigned int nChecksum;
    char mpchMessageStart[CMD_SIZE::MESSAGE_START_SIZE];
    char pchCommand[CMD_SIZE::COMMAND_SIZE];

public:
    CMessageHeader();
    CMessageHeader(const char *pszCommand, unsigned int nMessageSizeIn);
    typedef unsigned char MessageStartChars[CMD_SIZE::MESSAGE_START_SIZE];

    std::string GetCommand() const;
    bool IsValid() const;

    unsigned int GetMessageSize() const { return nMessageSize; }
    unsigned int GetChecksum() const { return nChecksum; }
    static unsigned int GetMessageSizeOffset() { return CMD_SIZE::MESSAGE_SIZE_OFFSET; }
    static unsigned int GetChecksumOffset() { return CMD_SIZE::CHECKSUM_OFFSET; }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(FLATDATA(this->mpchMessageStart));
        READWRITE(FLATDATA(this->pchCommand));
        READWRITE(this->nMessageSize);
        READWRITE(this->nChecksum);
    }
};

/** A CService with information about it as peer */
class CAddress : public CService
{
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

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        int nType=0, nVersion=0;
        CAddress *pthis = const_cast<CAddress *>(this);
        CService *pip = (CService *)pthis;
        if (ser_action.ForRead()) {
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
    }
};

//
// inv message data
//
const std::vector<const char *> vpszTypeName = { "ERROR", "tx", "block", "entangle" };
enum _CINV_MSG_TYPE: int
{
    MSG_ERROR = 0,
    MSG_TX = 1,
    MSG_BLOCK = 2,
    MSG_ENTANGLE
};

class CInv
{
public:
    CInv() : type(_CINV_MSG_TYPE::MSG_ERROR), hash(0) {}
    CInv(_CINV_MSG_TYPE typeIn, const uint256 &hashIn) : type(typeIn), hash(hashIn) {}
    CInv(const std::string &strType, const uint256 &hashIn) : hash(hashIn) {
        type = _CINV_MSG_TYPE::MSG_ERROR;
        for (unsigned int i=1; i < vpszTypeName.size(); ++i) {
            if (strType.compare(vpszTypeName[i]) == 0) {
                type = (_CINV_MSG_TYPE)i;
                break;
            }
        }
        if (type == _CINV_MSG_TYPE::MSG_ERROR)
            throw std::out_of_range(tfm::format("CInv::CInv(std::string, uint256) : unknown type '%s'", strType.c_str()));
    }

    bool IsKnownType() const {
        return (type >= 1 && type < (int)vpszTypeName.size());
    }
    const char *GetCommand() const {
        if (! IsKnownType())
            throw std::out_of_range(tfm::format("CInv::GetCommand() : type=%d unknown type", type));

        return vpszTypeName[type];
    }
    std::string ToString() const {
        return tfm::format("%s %s", GetCommand(), this->hash.ToString().substr(0,20).c_str());
    }

    friend bool operator<(const CInv &a, const CInv &b) {
        return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(this->type);
        READWRITE(this->hash);
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
