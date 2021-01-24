// Copyright (c) 2012-2016 The Novacoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.

#ifdef WIN32
#include <winsock2.h>
#define popen    _popen
#define pclose   _pclose
#endif

#include "net.h"
#include "ipcollector.h"

std::string ip_coll::strCollectorCommand;

std::string ip_coll::exec(const char *cmd)
{
    std::string result = "";
    char buffer[128];
    FILE *fp = popen(cmd, "r");
    while (::fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        result += buffer;
    }
    pclose(fp);
    return result;
}

bool ip_coll::AddPeer(std::string &strIpAddr)
{
    LOCK(net_node::cs_vAddedNodes);

    std::vector<std::string>::iterator it = net_node::vAddedNodes.begin();
    for(; it != net_node::vAddedNodes.end(); it++)
    {
        if (strIpAddr == *it) {
            break;
        }
    }
    if (it != net_node::vAddedNodes.end()) {
        return false;
    }

    printf("Adding node %s\n", strIpAddr.c_str());
    net_node::vAddedNodes.push_back(strIpAddr);

    return true;
}

void ip_coll::ThreadIPCollector(void *parg)
{
    printf("ip_coll::ThreadIPCollector started\n");

    net_node::vnThreadsRunning[THREAD_IPCOLLECTOR]++;

    std::string strExecutableFilePath = "";
#ifdef MAC_OSX
    size_t nameEnd = ip_coll::strCollectorCommand.rfind(".app");
    if (nameEnd != std::string::npos) {
        size_t nameBeginning = ip_coll::strCollectorCommand.rfind("/");
        if (nameBeginning == std::string::npos) {
            nameBeginning = 0;
        }

        std::string strFileName = ip_coll::strCollectorCommand.substr(nameBeginning, nameEnd - nameBeginning);
        strExecutableFilePath = ip_coll::strCollectorCommand + "/Contents/MacOS/" + strFileName;
    } else {
        strExecutableFilePath = ip_coll::strCollectorCommand;
    }
#else

    strExecutableFilePath = ip_coll::strCollectorCommand;
#endif

    if (! strExecutableFilePath.empty()) {
        while(! args_bool::fShutdown)
        {
            if (args_bool::fServer) {
                //
                // If RPC server is enabled then we don't have to parse anything.
                //
                std::string strCollectorOutput = exec(strExecutableFilePath.c_str());
                printf("Peer collector output: %s\n", strCollectorOutput.c_str());
            } else {
                //
                // Otherwise, there is a work to be done.
                //
                std::string strCollectorOutput = exec((strExecutableFilePath + " norpc").c_str());
                std::istringstream collectorStream(strCollectorOutput);

                std::string strIpAddr;
                while (std::getline(collectorStream, strIpAddr)) 
                {
                    AddPeer(strIpAddr);
                }
            }

            int nSleepHours = 1 + bitsystem::GetRandInt(5); // Sleep for 1-6 hours.
            for (int i = 0; i < nSleepHours * 3600 && !args_bool::fShutdown; ++i)
            {
                util::Sleep(1000);
            }
        }
    }

    printf("ip_coll::ThreadIPCollector stopped\n");
    net_node::vnThreadsRunning[THREAD_IPCOLLECTOR]--;
}
