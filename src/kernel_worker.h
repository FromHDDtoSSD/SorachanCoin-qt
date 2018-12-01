
#ifndef NOVACOIN_KERNELWORKER_H
#define NOVACOIN_KERNELWORKER_H

#include <vector>

class KernelWorker
{
public:
    KernelWorker(unsigned char *kernel, uint32_t nBits, uint32_t nInputTxTime, int64_t nValueIn, uint32_t nIntervalBegin, uint32_t nIntervalEnd) 
        : kernel(kernel), nBits(nBits), nInputTxTime(nInputTxTime), bnValueIn(nValueIn), nIntervalBegin(nIntervalBegin), nIntervalEnd(nIntervalEnd) {
        solutions = std::vector<std::pair<uint256,uint32_t> >();
    }
    ~KernelWorker() {}

    // Start thread
    void Do() {
        Do_generic();
    }

    // Get result
    std::vector<std::pair<uint256,uint32_t> > &GetSolutions() {
        return solutions;
    }
private:
    KernelWorker(); // {}
    KernelWorker(const KernelWorker &); // {}
    KernelWorker &operator =(const KernelWorker &); // {}

    // One way hashing.
    void Do_generic();

    // Kernel solutions.
    std::vector<std::pair<uint256,uint32_t> > solutions;

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
//@
