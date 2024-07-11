// Copyright (c) 2018-2024 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORAQAI_THREAD_H
#define SORAQAI_THREAD_H

#include <serialize.h>

//! SORA-QAI: Thread management class
class CThread
{
public:
    struct THREAD_INFO {
        CDataStream *_stream;
        void (*_func)(std::shared_ptr<CDataStream> stream);
        THREAD_INFO() = delete;
        explicit THREAD_INFO(CDataStream *stream, void (*func)(std::shared_ptr<CDataStream> stream)) {
            _stream = stream;
            _func = func;
        }
    };

    CThread() : fdetach(false) {}
    ~CThread() { WaitForMultipleThreads(); }

    bool BeginThread(const THREAD_INFO &info);
    void Detach();
    void WaitForMultipleThreads();
    uint32_t Size() const;
    void Reset();

private:
    bool fdetach;
    std::vector<std::thread> threads;
};

#endif // SORAQAI_THREAD_H
