// Copyright (c) 2015-2018 The Bitcoin Core developers
// Copyright (c) 2018-2020 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compat/compat.h>
#include <vector>
#include <prevector/prevector.h>
#include <prevector/prevector_s.h>
#include <serialize.h>
#include <bench/bench.h>
#include <compat/sanity.h>

namespace check_prevector {

struct nontrivial_t {
    int x;
    nontrivial_t() :x(-1) {}
    IMPLEMENT_SERIALIZE()
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) { int nSerSize=0; READWRITE(x); }
};
static_assert(!IS_TRIVIALLY_CONSTRUCTIBLE<nontrivial_t>::value,
    "expected nontrivial_t to not be trivially constructible");

typedef unsigned char trivial_t;
static_assert(IS_TRIVIALLY_CONSTRUCTIBLE<trivial_t>::value,
    "expected trivial_t to be trivially constructible");

template <typename T, typename VECTOR = prevector<PREVECTOR_N, T> >
static void PrevectorDestructor(benchmark::State& state)
{
    while(state.KeepRunning()) {
        for(auto x = 0; x < 1000; ++x) {
            VECTOR t0;
            VECTOR t1;
            t0.resize(PREVECTOR_N);
            t1.resize(PREVECTOR_N + 1);
        }
    }
}

template <typename T, typename VECTOR = prevector<PREVECTOR_N, T> >
static void PrevectorClear(benchmark::State& state)
{
    while(state.KeepRunning()) {
        for(auto x = 0; x < 1000; ++x) {
            VECTOR t0;
            VECTOR t1;
            t0.resize(PREVECTOR_N);
            t0.clear();
            t1.resize(PREVECTOR_N + 1);
            t1.clear();
        }
    }
}

template <typename T, typename VECTOR = prevector<PREVECTOR_N, T> >
static void PrevectorResize(benchmark::State& state)
{
    while(state.KeepRunning()) {
        VECTOR t0;
        VECTOR t1;
        for(auto x = 0; x < 1000; ++x) {
            t0.resize(PREVECTOR_N);
            t0.resize(0);
            t1.resize(PREVECTOR_N + 1);
            t1.resize(0);
        }
    }
}

template <typename T, typename VECTOR = prevector<PREVECTOR_N, T> >
static void PrevectorDeserialize(benchmark::State& state)
{
    CDataStream s0(0, 0);
    VECTOR t0;
    t0.resize(PREVECTOR_N);
    for(auto x = 0; x < 900; ++x) {
        s0 << t0;
    }
    t0.resize(100);
    for(auto x = 0; x < 101; ++x) {
        s0 << t0;
    }
    while(state.KeepRunning()) {
        VECTOR t1;
        for(auto x = 0; x < 1000; ++x) {
            s0 >> t1;
        }
        s0.Init(0, 0);
    }
}

#define PREVECTOR_TEST(name, nontrivops, trivops)                       \
    void Prevector ## name ## Nontrivial(benchmark::State& state) {     \
        Prevector ## name<nontrivial_t>(state);                         \
    }                                                                   \
    BENCHMARK(Prevector ## name ## Nontrivial, nontrivops);             \
    void Prevector ## name ## Trivial(benchmark::State& state) {        \
        Prevector ## name<trivial_t>(state);                            \
    }                                                                   \
    BENCHMARK(Prevector ## name ## Trivial, trivops);

PREVECTOR_TEST(Clear, 28300, 88600)
PREVECTOR_TEST(Destructor, 28800, 88900)
PREVECTOR_TEST(Resize, 28900, 90300)
PREVECTOR_TEST(Deserialize, 6800, 52000)

#define PREVECTOR_S_TEST(name, nontrivops, trivops)                                          \
    void Prevector_s_ ## name ## Nontrivial(benchmark::State& state) {                       \
        Prevector ## name<nontrivial_t, prevector_s<PREVECTOR_S_N, nontrivial_t> >(state);   \
    }                                                                                        \
    BENCHMARK(Prevector ## name ## Nontrivial, nontrivops);                                  \
    void Prevector_s_ ## name ## Trivial(benchmark::State& state) {                          \
        Prevector ## name<trivial_t, prevector_s<PREVECTOR_S_N, trivial_t> >(state);         \
    }                                                                                        \
    BENCHMARK(Prevector ## name ## Trivial, trivops);

PREVECTOR_S_TEST(Clear, 28300, 88600)
PREVECTOR_S_TEST(Destructor, 28800, 88900)
PREVECTOR_S_TEST(Resize, 28900, 90300)
PREVECTOR_S_TEST(Deserialize, 6800, 52000)

#define STDVECTOR_TEST(name, nontrivops, trivops)                           \
    void Stdvector ## name ## Nontrivial(benchmark::State& state) {         \
        Prevector ## name<nontrivial_t, std::vector<nontrivial_t> >(state); \
    }                                                                       \
    BENCHMARK(Prevector ## name ## Nontrivial, nontrivops);                 \
    void Stdvector ## name ## Trivial(benchmark::State& state) {            \
        Prevector ## name<trivial_t, std::vector<trivial_t> >(state);       \
    }                                                                       \
    BENCHMARK(Prevector ## name ## Trivial, trivops);

STDVECTOR_TEST(Clear, 28300, 88600)
STDVECTOR_TEST(Destructor, 28800, 88900)
STDVECTOR_TEST(Resize, 28900, 90300)
STDVECTOR_TEST(Deserialize, 6800, 52000)

} // namespace check_prevector
