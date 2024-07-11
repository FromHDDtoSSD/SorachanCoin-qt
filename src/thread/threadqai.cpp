// Copyright (c) 2018-2024 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <thread/threadqai.h>

bool CThread::BeginThread(const THREAD_INFO &info) {
    if(!info._stream || !info._func)
        return false;
    std::shared_ptr<CDataStream> cp_stream(new (std::nothrow) CDataStream);
    if(!cp_stream.get())
        return false;
    *cp_stream = *info._stream; // copy
    threads.emplace_back(std::thread([info, cp_stream]() {
        info._func(cp_stream);
    }));
    return true;
}

void CThread::Detach() {
    for (auto &thread: threads) {
        thread.detach();
    }
    if(threads.size() > 0)
        fdetach = true;
}

void CThread::WaitForMultipleThreads() {
    if(!fdetach) {
        for (auto &thread: threads) {
            if (thread.joinable())
                thread.join();
        }
    }
    Reset();
}

uint32_t CThread::Size() const {
    return threads.size();
}

void CThread::Reset() {
    threads.clear();
}
