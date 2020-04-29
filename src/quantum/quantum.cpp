// Copyright (c) 2018-2020 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <memory>
#include <quantum/quantum.h>
#include <prevector/prevector.h>
#include <prevector/prevector_s.h>
#include <compat/sanity.h>
#ifdef USE_QUANTUM

#if defined(WIN32) && defined(DEBUG)
# include <wincon.h>
# include <process.h>
#endif

//
// TEST: treat runtime.
//
#if DEBUG_RUNTIME_TEST
//# define SANITY_TEST
#endif

//
// CHECK: treat algo.
//
#if defined(WIN32) && defined(DEBUG_ALGO_CHECK)
# define PREVECTOR_CHECK
# define MEMORY_CHECK
# define SECURE_PREVECTOR_CHECK
# define HASH_CHECK
# define LAMPORT_CHECK
# define VECTOR_CHECK
#endif

class Quantum_startup
{
private:
    static const int _test_count = 3;
private:
    typedef std::uint8_t byte;
    static Quantum_startup q_startup;

    static void sanity_check() noexcept {
        bool a = test_sanity::glibc_sanity_test();
        bool b = test_sanity::glibcxx_sanity_test();
        assert(a && b);
        debugcs::instance() << "SorachanCoin sanity_check(): OK" << debugcs::endl();
    }

    template <int rsv, typename T>
    static void prevector_check(int n, int m) noexcept {
        _bench_func("prevector_check() Des Tri", &check_prevector::PrevectorDestructorTrivial);
        _bench_func("prevector_check() Des Nontri", &check_prevector::PrevectorDestructorNontrivial);
        _bench_func("prevector_check() Cle Tri", &check_prevector::PrevectorClearTrivial);
        _bench_func("prevector_check() Cle Nontri", &check_prevector::PrevectorClearNontrivial);
        _bench_func("prevector_check() Res Tri", &check_prevector::PrevectorResizeTrivial);
        _bench_func("prevector_check() Res Nontri", &check_prevector::PrevectorResizeNontrivial);
        _bench_func("prevector_check() Deseria Tri", &check_prevector::PrevectorDeserializeTrivial);
        _bench_func("prevector_check() Deseria Nontri", &check_prevector::PrevectorDeserializeNontrivial);

        _bench_func("std_check() Des Tri", &check_prevector::StdvectorDestructorTrivial);
        _bench_func("std_check() Des Nontri", &check_prevector::StdvectorDestructorNontrivial);
        _bench_func("std_check() Cle Tri", &check_prevector::StdvectorClearTrivial);
        _bench_func("std_check() Cle Nontri", &check_prevector::StdvectorClearNontrivial);
        _bench_func("std_check() Res Tri", &check_prevector::StdvectorResizeTrivial);
        _bench_func("std_check() Res Nontri", &check_prevector::StdvectorResizeNontrivial);
        _bench_func("std_check() Deseria Tri", &check_prevector::StdvectorDeserializeTrivial);
        _bench_func("std_check() Deseria Nontri", &check_prevector::StdvectorDeserializeNontrivial);

        _bench_func("prevector_s_check() Des Tri", &check_prevector::Prevector_s_DestructorTrivial, 1, 1);
        _bench_func("prevector_s_check() Des Nontri", &check_prevector::Prevector_s_DestructorNontrivial, 1, 1);
        _bench_func("prevector_s_check() Cle Tri", &check_prevector::Prevector_s_ClearTrivial, 1, 1);
        _bench_func("prevector_s_check() Cle Nontri", &check_prevector::Prevector_s_ClearNontrivial, 1, 1);
        _bench_func("prevector_s_check() Res Tri", &check_prevector::Prevector_s_ResizeTrivial, 1, 1);
        _bench_func("prevector_s_check() Res Nontri", &check_prevector::Prevector_s_ResizeNontrivial, 1, 1);
        _bench_func("prevector_s_check() Deseria Tri", &check_prevector::Prevector_s_DeserializeTrivial, 1, 1);
        _bench_func("prevector_s_check() Deseria Nontri", &check_prevector::Prevector_s_DeserializeNontrivial, 1, 1);

        for(int i = 0; i < n; ++i)
        {
            prevector<rsv, T> v(10, T());
            prevector_s<rsv, T> vchs(10, T());
            std::vector<T> vv(10, T());

            for(int j = 0; j < m; ++j)
            {
                v.push_back(j + i);
                vchs.push_back(j + i);
                vv.push_back(j + i);
            }

            for(int j = 0; j < m / 2; ++j)
            {
                typename prevector<rsv, T>::iterator ite = v.begin();
                v.erase(ite);
                typename prevector_s<rsv, T>::iterator vite = vchs.begin();
                vchs.erase(vite);
                typename std::vector<T>::iterator vvite = vv.begin();
                vv.erase(vvite);
            }

            for(int j = 0; j < m / 2; ++j)
            {
                typename prevector_s<rsv, T>::raw_pointer ptr = vchs.data();
                assert(vv[j] == *((T *)ptr + j));
            }
        }

        debugcs::instance() << "SorachanCoin prevector_check(): OK" << debugcs::endl();
    }

    static void memory_check() noexcept {
        assert(1);
        debugcs::instance() << "SorachanCoin memory_check(): OK" << debugcs::endl();
    }

    static void hash_check() noexcept {
        Lamport::CPrivateKey pKey;
        Lamport::BLAKE2KeyHash h(pKey);

        byte referenceHash[Lamport::BLAKE2KeyHash::kBytesSize];
        CSecureSegmentRW<byte> guard = pKey.get_secure()->unlockAndInitRW(true);
        quantum_hash::blake2_generichash(referenceHash, Lamport::BLAKE2KeyHash::kBytesSize, guard.get_addr(), guard.get_size());
        assert(::memcmp(h.get_addr(), referenceHash, Lamport::BLAKE2KeyHash::kBytesSize) == 0);
        debugcs::instance() << "SorachanCoin hash_check(): OK" << debugcs::endl();
    }
    template <int rsv, typename T> static void vector_check(int n, int m) noexcept {
        char data[] = { 'S', 'O', 'R', 'A', 'C', 'H', 'A', 'N', 'C', 'O', 'I', 'N' };
        secure_segment::vector<char> vch(std::begin(data), std::end(data));
        auto ite = vch.begin();
        assert(*ite == 'S' && *(ite + 6) == 'A');

        for (int i = 0; i < n; ++i)
        {
            prevector<rsv, T> v(100, T());
            std::vector<T> vch(100, T());

            for (int j = 0; j < m; ++j)
            {
                v.push_back(j + i);
                vch.push_back(j + i);
            }

            for (int j = 0; j < m / 2; ++j)
            {
                typename prevector<rsv, T>::iterator ite = v.begin();
                v.erase(ite);
                typename std::vector<T>::iterator vite = vch.begin();
                vch.erase(vite);
            }

            for (int j = 0; j < m / 2; ++j)
            {
                assert(v[j] == vch[j]);

                std::vector<uint8_t> comp = (std::vector<uint8_t>)v.get_std_vector();
                assert(v[j] == comp[j]);

                prevector<rsv, uint8_t> comp2(vch.begin(), vch.end());
                assert(vch[j] == comp2[j]);
            }
        }
    }
    void static lamport_check() noexcept {
        const size_t buf_size = PREVECTOR_N;

        quantum_lib::secure_stackzero(buf_size);
        prevector<PREVECTOR_N, byte> vdata;
        vdata.resize(buf_size, 0x00);
        byte *data = &vdata.at(0);

        ::RAND_bytes(data, buf_size);
        Lamport::CLamport lamport;
        std::shared_ptr<Lamport::CPublicKey> pubKey = lamport.create_pubkey(data, buf_size);
        assert(lamport.check(data, buf_size, pubKey) == true);

        /*
        const byte *offset = pubKey->get_addr();
        const size_t size = pubKey->get_size();
        for (size_t i = 0; i < size; ++i)
        {
            char buf[8] = { 0 };
            ::sprintf_s(buf, 8, "%X", offset[i]);
            debugcs::instance() << buf << debugcs::endl();
        }
        debugcs::instance() << debugcs::endl() << "--------------------------------" << debugcs::endl() << debugcs::endl();
        */

        debugcs::instance() << "SorachanCoin lamport_check(): OK" << debugcs::endl();
    }

    static unsigned int __stdcall benchmark(void *) noexcept {
        for (int i = 0; i < _test_count; ++i)
        {
#ifdef SANITY_TEST
            sanity_check();
#endif
#ifdef PREVECTOR_CHECK
            prevector_check<PREVECTOR_N, uint8_t>(10, 300);
#endif
#ifdef MEMORY_CHECK
            memory_check();
#endif
#ifdef HASH_CHECK
            hash_check();
#endif
#ifdef VECTOR_CHECK
            vector_check<PREVECTOR_N, uint8_t>(10, 300);
#endif
#ifdef LAMPORT_CHECK
            lamport_check();
#endif
        }
        return 1;
    }
private:
    Quantum_startup() noexcept {
#if defined(WIN32) && defined(DEBUG)
        //
        // Lamport benchmark [Thread Safe]
        //
        HANDLE hHandle[2]; // count of threads
        for (int i = 0; i < sizeof(hHandle) / sizeof(hHandle[0]); ++i)
        {
            hHandle[i] = (HANDLE)::_beginthreadex(nullptr, 0, Quantum_startup::benchmark, nullptr, 0, nullptr);
            if (hHandle[i] == INVALID_HANDLE_VALUE) {
                assert(0);
            }
        }
        ::WaitForMultipleObjects(sizeof(hHandle) / sizeof(hHandle[0]), hHandle, true, INFINITE);
        for (int i = 0; i < sizeof(hHandle) / sizeof(hHandle[0]); ++i)
        {
            ::CloseHandle(hHandle[i]);
        }
#endif
    }
    ~Quantum_startup() noexcept {}
};
Quantum_startup Quantum_startup::q_startup;

#endif
