// Copyright (c) 2012-2013 The PPCoin developers
// Copyright (c) 2013-2015 The Novacoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NOVACOIN_KERNELWORKER_H
#define NOVACOIN_KERNELWORKER_H

#include <stdint.h>
#include <uint256.h>
#include <vector>
#include <script/scriptnum.h>

class KernelWorker
{
public:
    using kernel_worker_result = std::vector<std::pair<uint256, uint32_t> >;

    KernelWorker(unsigned char *kernel, uint32_t nBits, uint32_t nInputTxTime, int64_t nValueIn, uint32_t nIntervalBegin, uint32_t nIntervalEnd) 
        : kernel(kernel), nBits(nBits), nInputTxTime(nInputTxTime), bnValueIn(nValueIn), nIntervalBegin(nIntervalBegin), nIntervalEnd(nIntervalEnd) {
        solutions = std::vector<std::pair<uint256, uint32_t> >();
    }
    ~KernelWorker() {}

    // Start thread
    void Do() {
        Do_generic();
    }

    // Get result
    kernel_worker_result &GetSolutions() {
        return solutions;
    }
private:
    KernelWorker()=delete;
    KernelWorker(const KernelWorker &)=delete;
    KernelWorker &operator =(const KernelWorker &)=delete;
    KernelWorker(KernelWorker &&)=delete;
    KernelWorker &operator =(KernelWorker &&)=delete;

    // One way hashing.
    void Do_generic();

    // Kernel solutions.
    kernel_worker_result solutions;

    // Kernel metadata.
    uint8_t  *kernel;
    uint32_t nBits;
    uint32_t nInputTxTime;
    CBigNum  bnValueIn;

    // Interval boundaries.
    uint32_t nIntervalBegin;
    uint32_t nIntervalEnd;
public:
    // Scan given kernel for solutions
    static bool ScanKernelBackward(unsigned char *kernel, uint32_t nBits, uint32_t nInputTxTime, int64_t nValueIn, std::pair<uint32_t, uint32_t> &SearchInterval, std::pair<uint256, uint32_t> &solution);
};

#endif
