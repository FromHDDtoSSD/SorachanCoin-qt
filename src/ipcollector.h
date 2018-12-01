
#ifndef IPCOLLECTOR_H
#define IPCOLLECTOR_H

class ip_coll : private no_instance
{
private:
    static std::string exec(const char *cmd);
    static bool AddPeer(std::string &strIpAddr);

public:
    static std::string strCollectorCommand;

    static void ThreadIPCollector(void *parg);
};

#endif
//@
