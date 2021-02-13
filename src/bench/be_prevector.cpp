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
    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) { READWRITE(x); }
    bool operator==(const struct nontrivial_t &obj) const { return (x == obj.x); }
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
        s0.Init();
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

#define PREVECTOR_S_TEST(name, nontrivops, trivops)                                                                        \
    void Prevector_s_ ## name ## Nontrivial(benchmark::State& state) {                                                     \
        Prevector ## name<nontrivial_t, latest_crypto::prevector_s<latest_crypto::PREVECTOR_S_N, nontrivial_t> >(state);   \
    }                                                                                                                      \
    BENCHMARK(Prevector_s_ ## name ## Nontrivial, nontrivops);                                                             \
    void Prevector_s_ ## name ## Trivial(benchmark::State& state) {                                                        \
        Prevector ## name<trivial_t, latest_crypto::prevector_s<latest_crypto::PREVECTOR_S_N, trivial_t> >(state);         \
    }                                                                                                                      \
    BENCHMARK(Prevector_s_ ## name ## Trivial, trivops);

PREVECTOR_S_TEST(Clear, 28300, 88600)
PREVECTOR_S_TEST(Destructor, 28800, 88900)
PREVECTOR_S_TEST(Resize, 28900, 90300)
PREVECTOR_S_TEST(Deserialize, 6800, 52000)

#define STDVECTOR_TEST(name, nontrivops, trivops)                           \
    void Stdvector ## name ## Nontrivial(benchmark::State& state) {         \
        Prevector ## name<nontrivial_t, std::vector<nontrivial_t> >(state); \
    }                                                                       \
    BENCHMARK(Stdvector ## name ## Nontrivial, nontrivops);                 \
    void Stdvector ## name ## Trivial(benchmark::State& state) {            \
        Prevector ## name<trivial_t, std::vector<trivial_t> >(state);       \
    }                                                                       \
    BENCHMARK(Stdvector ## name ## Trivial, trivops);

STDVECTOR_TEST(Clear, 28300, 88600)
STDVECTOR_TEST(Destructor, 28800, 88900)
STDVECTOR_TEST(Resize, 28900, 90300)
STDVECTOR_TEST(Deserialize, 6800, 52000)

template <int rsv, typename T>
static void PrevectorAssertcheck(benchmark::State& state)
{
    const int n = 10;
    const int m = rsv;
    while(state.KeepRunning()) {
        for(int i = 0; i < n; ++i)
        {
            prevector<rsv, T> v(10, T());
            std::vector<T> vv(10, T());

            for(int j = 0; j < m; ++j)
            {
                if(IS_TRIVIALLY_CONSTRUCTIBLE<T>::value) {
                    const T *p = reinterpret_cast<const T *>(&j);
                    v.push_back(*p);
                    vv.push_back(*p);
                } else {
                    v.push_back(T());
                    vv.push_back(T());
                }
            }

            for(int j = 0; j < m / 2; ++j)
            {
                typename prevector<rsv, T>::iterator ite = v.begin();
                v.erase(ite);
                typename std::vector<T>::iterator vvite = vv.begin();
                vv.erase(vvite);
            }

            for(int j = 0; j < m / 2; ++j)
            {
                std::vector<T> comp = (std::vector<T>)v.get_std_vector();
                assert(v[j] == comp[j]);
            }
        }
    }
}

template <int rsv, typename T>
static void Prevector_s_Assertcheck(benchmark::State& state)
{
    const int n = 10;
    const int m = rsv;
    while(state.KeepRunning()) {
        for(int i = 0; i < n; ++i)
        {
            prevector<rsv, T> v(10, T());
            latest_crypto::prevector_s<rsv, T> vchs(10, T());
            std::vector<T> vv(10, T());

            for(int j = 0; j < m; ++j)
            {
                if(IS_TRIVIALLY_CONSTRUCTIBLE<T>::value) {
                    const T *p = reinterpret_cast<const T *>(&j);
                    v.push_back(*p);
                    vchs.push_back(*p);
                    vv.push_back(*p);
                } else {
                    v.push_back(T());
                    vchs.push_back(T());
                    vv.push_back(T());
                }
            }

            for(int j = 0; j < m / 2; ++j)
            {
                typename prevector<rsv, T>::iterator ite = v.begin();
                v.erase(ite);
                typename latest_crypto::prevector_s<rsv, T>::iterator vite = vchs.begin();
                vchs.erase(vite);
                typename std::vector<T>::iterator vvite = vv.begin();
                vv.erase(vvite);
            }

            for(int j = 0; j < m / 2; ++j)
            {
                typename latest_crypto::prevector_s<rsv, T>::raw_pointer ptr = vchs.data();
                assert(vv[j] == *((T *)ptr + j));

                std::vector<T> comp = (std::vector<T>)v.get_std_vector();
                assert(v[j] == comp[j]);
            }
        }
    }
}

#define VECTOR_ASSERTCHECK(name, rsv, nontrivops, trivops)           \
    void name ## AssertcheckNontrivial(benchmark::State& state) {    \
        name ## Assertcheck<rsv, nontrivial_t>(state);               \
    }                                                                \
    BENCHMARK(name ## AssertcheckNontrivial, nontrivops);            \
    void name ## AssertcheckTrivial(benchmark::State& state) {       \
        name ## Assertcheck<rsv, trivial_t>(state);                  \
    }                                                                \
    BENCHMARK(name ## AssertcheckTrivial, trivops);

VECTOR_ASSERTCHECK(Prevector, PREVECTOR_N, 28300, 88600)
VECTOR_ASSERTCHECK(Prevector_s_, latest_crypto::PREVECTOR_S_N, 28300, 88600)

template <typename T>
static void SecurevectorAssertcheck(benchmark::State& state)
{
    while(state.KeepRunning()) {
        std::vector<T> data;
        const char ch[] = { 'S', 'O', 'R', 'A', 'C', 'H', 'A', 'N', 'C', 'O', 'I', 'N' };
        if(IS_TRIVIALLY_CONSTRUCTIBLE<T>::value) {
            data.insert(data.end(), (const T *)std::begin(ch), (const T *)std::end(ch));
        } else {
            const T obj[] = { T(), T(), T(), T(), T(), T(), T(), T(), T(), T(), T(), T() };
            data.insert(data.end(), (const T *)std::begin(obj), (const T *)std::end(obj));
        }
        latest_crypto::secure_segment::vector<T> vch(data.begin(), data.end());
        auto ite = vch.begin();
        if(IS_TRIVIALLY_CONSTRUCTIBLE<T>::value) {
            assert(*ite == *((T *)(&ch[0])) && *(ite + 6) == *((T *)&ch[6]));
        } else {
            assert(*ite == T() && *(ite + 6) == T());
        }
    }
}

#define SECVECTOR_ASSERTCHECK(nontrivops, trivops)                    \
    void SecurevectorAssertcheckNontrivial(benchmark::State& state) { \
        SecurevectorAssertcheck<nontrivial_t>(state);                 \
    }                                                                 \
    BENCHMARK(SecurevectorAssertcheckNontrivial, nontrivops);         \
    void SecurevectorAssertcheckTrivial(benchmark::State& state) {    \
        SecurevectorAssertcheck<trivial_t>(state);                    \
    }                                                                 \
    BENCHMARK(SecurevectorAssertcheckTrivial, trivops);
SECVECTOR_ASSERTCHECK(28300, 88600)

} // namespace check_prevector
