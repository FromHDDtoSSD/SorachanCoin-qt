// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "protocol.h"
#include "netbase.h"

#ifndef WIN32
#include <arpa/inet.h>
#endif

CMessageHeader::CMessageHeader() : nMessageSize(std::numeric_limits<uint32_t>::max()), nChecksum(0)
{
    ::memcpy(mpchMessageStart, block_info::gpchMessageStart, sizeof(mpchMessageStart));
    ::memset(pchCommand, 0, sizeof(pchCommand));
    pchCommand[1] = 1;
}

CMessageHeader::CMessageHeader(const char *pszCommand, unsigned int nMessageSizeIn) : nMessageSize(nMessageSizeIn), nChecksum(0)
{
    ::memcpy(mpchMessageStart, block_info::gpchMessageStart, sizeof(mpchMessageStart));
    ::strncpy(pchCommand, pszCommand, CMD_SIZE::COMMAND_SIZE);
}

std::string CMessageHeader::GetCommand() const
{
    if (pchCommand[CMD_SIZE::COMMAND_SIZE - 1] == 0) {
        return std::string(pchCommand, pchCommand + ::strlen(pchCommand));
    } else {
        return std::string(pchCommand, pchCommand + CMD_SIZE::COMMAND_SIZE);
    }
}

bool CMessageHeader::IsValid() const
{
    // Check start string
    if (::memcmp(mpchMessageStart, block_info::gpchMessageStart, sizeof(mpchMessageStart)) != 0) {
        return false;
    }

    // Check the command string for errors
    for (const char *p1 = pchCommand; p1 < pchCommand + CMD_SIZE::COMMAND_SIZE; p1++)
    {
        if (*p1 == 0) {
            // Must be all zeros after the first zero
            for (; p1 < pchCommand + CMD_SIZE::COMMAND_SIZE; p1++)
            {
                if (*p1 != 0) {
                    return false;
                }
            }
        } else if (*p1 < ' ' || *p1 > 0x7E) {
            return false;
        }
    }

    // Message size
    if (nMessageSize > compact_size::MAX_SIZE) {
        printf("CMessageHeader::IsValid() : (%s, %u bytes) nMessageSize > compact_size::MAX_SIZE\n", GetCommand().c_str(), nMessageSize);
        return false;
    }

    return true;
}
