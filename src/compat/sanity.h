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

// FIXME: When _bench_func( ... 2, 2), vector object has been brought to break.
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

#ifdef LATEST_CRYPTO_ENABLE
    void Prevector_s_DestructorTrivial(benchmark::State& state);
    void Prevector_s_DestructorNontrivial(benchmark::State& state);
    void Prevector_s_ClearTrivial(benchmark::State& state);
    void Prevector_s_ClearNontrivial(benchmark::State& state);
    void Prevector_s_ResizeTrivial(benchmark::State& state);
    void Prevector_s_ResizeNontrivial(benchmark::State& state);
    void Prevector_s_DeserializeTrivial(benchmark::State& state);
    void Prevector_s_DeserializeNontrivial(benchmark::State& state);
#endif

    void StdvectorDestructorTrivial(benchmark::State& state);
    void StdvectorDestructorNontrivial(benchmark::State& state);
    void StdvectorClearTrivial(benchmark::State& state);
    void StdvectorClearNontrivial(benchmark::State& state);
    void StdvectorResizeTrivial(benchmark::State& state);
    void StdvectorResizeNontrivial(benchmark::State& state);
    void StdvectorDeserializeTrivial(benchmark::State& state);
    void StdvectorDeserializeNontrivial(benchmark::State& state);

    void PrevectorAssertcheckNontrivial(benchmark::State& state);
    void PrevectorAssertcheckTrivial(benchmark::State& state);

#ifdef LATEST_CRYPTO_ENABLE
    void Prevector_s_AssertcheckNontrivial(benchmark::State& state);
    void Prevector_s_AssertcheckTrivial(benchmark::State& state);
#endif

    void SecurevectorAssertcheckNontrivial(benchmark::State& state);
    void SecurevectorAssertcheckTrivial(benchmark::State& state);
}

#ifdef LATEST_CRYPTO_ENABLE
namespace latest_crypto
{
    void bench_AES128(benchmark::State& state);
    void bench_AES192(benchmark::State& state);
    void bench_AES256(benchmark::State& state);
    int check_all_aes();
}
#endif

#if defined(USE_QUANTUM) && defined(LATEST_CRYPTO_ENABLE)
namespace latest_crypto
{
    void Ripemd160Assertcheck(benchmark::State& state);
    void SHA256Assertcheck(benchmark::State& state);
    void SHA512Assertcheck(benchmark::State& state);
    void Blake2Assertcheck(benchmark::State& state);
    void LamportAssertcheck(benchmark::State& state);
}
#endif

namespace latest_json
{
    void JsonAssertcheck(benchmark::State& state);
}

#endif // BITCOIN_COMPAT_SANITY_H
