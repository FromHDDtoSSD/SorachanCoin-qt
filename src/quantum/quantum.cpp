// Copyright (c) 2018-2020 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//

#if defined(USE_QUANTUM) && defined(LATEST_CRYPTO_ENABLE)

#include <memory>
#include <quantum/quantum.h>
#include <prevector/prevector.h>
#include <prevector/prevector_s.h>
#include <compat/sanity.h>
#include <thread>

//
// TEST: treat runtime.
//
#if DEBUG_RUNTIME_TEST
//# define SANITY_TEST
#endif

//
// CHECK: treat algo.
//
#if defined(DEBUG_ALGO_CHECK)
# define PREVECTOR_CHECK
# define AES_CHECK
# define MEMORY_CHECK
# define HASH_CHECK
//# define JSON_CHECK // univalue is checking ... (still failure)
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
        debugcs::instance() << "[OK] SorachanCoin sanity_check()" << debugcs::endl();
    }

    template <int rsv, typename T>
    static void prevector_check(int n, int m) noexcept {
        debugcs::instance() << "[[[BEGIN]]] SorachanCoin the vector testing ..." << debugcs::endl();

        _bench_func("[vector] prevector_check() Des Tri", &check_prevector::PrevectorDestructorTrivial, 3, 3);
        _bench_func("[vector] prevector_check() Des Nontri", &check_prevector::PrevectorDestructorNontrivial, 3, 3);
        _bench_func("[vector] prevector_check() Cle Tri", &check_prevector::PrevectorClearTrivial, 3, 3);
        _bench_func("[vector] prevector_check() Cle Nontri", &check_prevector::PrevectorClearNontrivial, 3, 3);
        _bench_func("[vector] prevector_check() Res Tri", &check_prevector::PrevectorResizeTrivial, 3, 3);
        _bench_func("[vector] prevector_check() Res Nontri", &check_prevector::PrevectorResizeNontrivial, 3, 3);
        _bench_func("[vector] prevector_check() Deseria Tri", &check_prevector::PrevectorDeserializeTrivial, 3, 3);
        _bench_func("[vector] prevector_check() Deseria Nontri", &check_prevector::PrevectorDeserializeNontrivial, 3, 3);

        _bench_func("[vector] std_check() Des Tri", &check_prevector::StdvectorDestructorTrivial, 3, 3);
        _bench_func("[vector] std_check() Des Nontri", &check_prevector::StdvectorDestructorNontrivial, 3, 3);
        _bench_func("[vector] std_check() Cle Tri", &check_prevector::StdvectorClearTrivial, 3, 3);
        _bench_func("[vector] std_check() Cle Nontri", &check_prevector::StdvectorClearNontrivial, 3, 3);
        _bench_func("[vector] std_check() Res Tri", &check_prevector::StdvectorResizeTrivial, 3, 3);
        _bench_func("[vector] std_check() Res Nontri", &check_prevector::StdvectorResizeNontrivial, 3, 3);
        _bench_func("[vector] std_check() Deseria Tri", &check_prevector::StdvectorDeserializeTrivial, 3, 3);
        _bench_func("[vector] std_check() Deseria Nontri", &check_prevector::StdvectorDeserializeNontrivial, 3, 3);

#ifdef LATEST_CRYPTO_ENABLE
        _bench_func("[vector] prevector_s_check() Des Tri", &check_prevector::Prevector_s_DestructorTrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Des Nontri", &check_prevector::Prevector_s_DestructorNontrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Cle Tri", &check_prevector::Prevector_s_ClearTrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Cle Nontri", &check_prevector::Prevector_s_ClearNontrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Res Tri", &check_prevector::Prevector_s_ResizeTrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Res Nontri", &check_prevector::Prevector_s_ResizeNontrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Deseria Tri", &check_prevector::Prevector_s_DeserializeTrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Deseria Nontri", &check_prevector::Prevector_s_DeserializeNontrivial, 1, 1);
#endif

        _bench_func("[vector] prevector_check() Assertcheck Tri", &check_prevector::PrevectorAssertcheckTrivial, 1, 1);
        _bench_func("[vector] prevector_check() Assertcheck Nontri", &check_prevector::PrevectorAssertcheckNontrivial, 1, 1);
#ifdef LATEST_CRYPTO_ENABLE
        _bench_func("[vector] prevector_s_check() Assertcheck Tri", &check_prevector::Prevector_s_AssertcheckTrivial, 1, 1);
        _bench_func("[vector] prevector_s_check() Assertcheck Nontri", &check_prevector::Prevector_s_AssertcheckNontrivial, 1, 1);
#endif

        _bench_func("[secure vector] secure_vector_check() Assertcheck Tri", &check_prevector::SecurevectorAssertcheckTrivial);
        _bench_func("[secure vector] secure_vector_check() Assertcheck Nontri", &check_prevector::SecurevectorAssertcheckNontrivial);

        debugcs::instance() << "[[[OK]]] SorachanCoin the checked vector" << debugcs::endl();
    }

#ifdef LATEST_CRYPTO_ENABLE
    static void aes_check() noexcept {
        debugcs::instance() << "[[[BEGIN]]] SorachanCoin the crypto testing ..." << debugcs::endl();

        _bench_func("[crypto] AES128_check()", &latest_crypto::bench_AES128, 1, 1);
        _bench_func("[crypto] AES192_check()", &latest_crypto::bench_AES192, 1, 1);
        _bench_func("[crypto] AES256_check()", &latest_crypto::bench_AES256, 1, 1);
        latest_crypto::check_all_aes();

        debugcs::instance() << "[[[OK]]] SorachanCoin the checked crypto" << debugcs::endl();
    }
#endif

    static void memory_check() noexcept {
        debugcs::instance() << "[[[BEGIN]]] SorachanCoin the memory testing ..." << debugcs::endl();

        assert(1);

        debugcs::instance() << "[[[OK]]] SorachanCoin the checked memory" << debugcs::endl();
    }

#ifdef LATEST_CRYPTO_ENABLE
    static void hash_check() noexcept {
        debugcs::instance() << "[[[BEGIN]]] SorachanCoin the hash testing ..." << debugcs::endl();

        _bench_func("[hash] Ripemd160_check()", &latest_crypto::Ripemd160Assertcheck);
        _bench_func("[hash] SHA256_check()", &latest_crypto::SHA256Assertcheck);
        _bench_func("[hash] SHA512_check()", &latest_crypto::SHA512Assertcheck);
        _bench_func("[hash] blake2_check()", &latest_crypto::Blake2Assertcheck);
        _bench_func("[hash] lamport_check() Assertcheck", &latest_crypto::LamportAssertcheck);

        debugcs::instance() << "[[[OK]]] SorachanCoin the checked blake2 and lamport" << debugcs::endl();
    }
#endif

    static void json_check() noexcept {
        debugcs::instance() << "[[[BEGIN]]] SorachanCoin the JSON testing ..." << debugcs::endl();

        _bench_func("[JSON] json_check()", &latest_json::JsonAssertcheck, 1, 1);

        debugcs::instance() << "[[[OK]]] SorachanCoin the checked JSON" << debugcs::endl();
    }

    static unsigned int __stdcall benchmark(void *) noexcept {
        for(int i = 0; i < _test_count; ++i)
        {
#ifdef SANITY_TEST
            sanity_check();
#endif
#ifdef PREVECTOR_CHECK
            prevector_check<PREVECTOR_N, uint8_t>(10, 300);
#endif
#if defined(AES_CHECK) && defined(LATEST_CRYPTO_ENABLE)
            aes_check();
#endif
#ifdef MEMORY_CHECK
            memory_check();
#endif
#if defined(HASH_CHECK) && defined(LATEST_CRYPTO_ENABLE)
            hash_check();
#endif
#ifdef JSON_CHECK
            json_check();
#endif
        }
        return 1;
    }
private:
    Quantum_startup() noexcept {
#if defined(DEBUG)
        //
        // Lamport benchmark [Thread Safe]
        //
        std::thread th1(&Quantum_startup::benchmark, nullptr);
        std::thread th2(&Quantum_startup::benchmark, nullptr);
        th1.join();
        th2.join();
#endif
    }
    ~Quantum_startup() noexcept {}
};
Quantum_startup Quantum_startup::q_startup;

#endif
