// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2020 The SorachanCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//
// Note: thanks, verification code.
//
// Lately, all verification of the code currently have been done in "quantum.cpp".
// We are using the instance of "class Quantum_startup" to run the verification code.
//
// Accurately, verification of test ought to begin after the all objects have been instanced. Sorry.
//

#ifndef BITCOIN_COMPAT_SANITY_H
#define BITCOIN_COMPAT_SANITY_H

#include <bench/bench.h>

static inline void _bench_func(const char *name, void (*_f)(benchmark::State &), uint64_t num_evals = 10, double num_iters = 10) noexcept {
    benchmark::ConsolePrinter pobj;
    benchmark::State state(name, num_evals, num_iters, pobj);
    _f(state);
    pobj.result(state);
}

namespace test_sanity
{
    bool glibc_sanity_test();
    bool glibcxx_sanity_test();
}

namespace check_prevector
{
    void PrevectorDestructorTrivial(benchmark::State& state);
    void PrevectorDestructorNontrivial(benchmark::State& state);
    void PrevectorClearTrivial(benchmark::State& state);
    void PrevectorClearNontrivial(benchmark::State& state);
    void PrevectorResizeTrivial(benchmark::State& state);
    void PrevectorResizeNontrivial(benchmark::State& state);
    void PrevectorDeserializeTrivial(benchmark::State& state);
    void PrevectorDeserializeNontrivial(benchmark::State& state);

    void Prevector_s_DestructorTrivial(benchmark::State& state);
    void Prevector_s_DestructorNontrivial(benchmark::State& state);
    void Prevector_s_ClearTrivial(benchmark::State& state);
    void Prevector_s_ClearNontrivial(benchmark::State& state);
    void Prevector_s_ResizeTrivial(benchmark::State& state);
    void Prevector_s_ResizeNontrivial(benchmark::State& state);
    void Prevector_s_DeserializeTrivial(benchmark::State& state);
    void Prevector_s_DeserializeNontrivial(benchmark::State& state);

    void StdvectorDestructorTrivial(benchmark::State& state);
    void StdvectorDestructorNontrivial(benchmark::State& state);
    void StdvectorClearTrivial(benchmark::State& state);
    void StdvectorClearNontrivial(benchmark::State& state);
    void StdvectorResizeTrivial(benchmark::State& state);
    void StdvectorResizeNontrivial(benchmark::State& state);
    void StdvectorDeserializeTrivial(benchmark::State& state);
    void StdvectorDeserializeNontrivial(benchmark::State& state);
}

#endif // BITCOIN_COMPAT_SANITY_H
