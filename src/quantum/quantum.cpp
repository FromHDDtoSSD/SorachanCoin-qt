// Copyright (c) 2018-2020 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <memory>
#include <quantum/quantum.h>
#include <prevector/prevector.h>
#include <prevector/prevector_s.h>
#ifdef USE_QUANTUM

#if defined(WIN32) && defined(DEBUG)
# include <wincon.h>
# include <process.h>
#endif

#if defined(WIN32) && defined(DEBUG)
# define MEMORY_CHECK
# define SECURE_PREVECTOR_CHECK
# define HASH_CHECK
# define LAMPORT_CHECK
# define VECTOR_CHECK
#endif

class Quantum_startup
{
private:
    typedef std::uint8_t byte;
    static Quantum_startup q_startup;

    static void memory_check() noexcept {}
    template <int rsv, typename T> static void secure_prevector_check(int n, int m) noexcept {
        for(int i=0; i < n; ++i)
        {
            prevector<rsv, T> v(100, T());
            prevector_s<rsv, T> vchs(100, T());
            std::vector<T> vv(100, T());

            for (int j = 0; j < m; ++j)
            {
                v.push_back(j + i);
                vchs.push_back(j + i);
                vv.push_back(j + i);
            }

            for (int j = 0; j < m / 2; ++j)
            {
                typename prevector<rsv, T>::iterator ite = v.begin();
                v.erase(ite);
                typename prevector_s<rsv, T>::iterator vite = vchs.begin();
                vchs.erase(vite);
                typename std::vector<T>::iterator vvite = vv.begin();
                vv.erase(vvite);
            }

            for (int j = 0; j < m / 2; ++j)
            {
                auto __ref = vchs[j];
                assert(vv[j] == (T)__ref);
            }
        }
    }
    static void hash_check() noexcept {
        Lamport::CPrivateKey pKey;
        Lamport::BLAKE2KeyHash h(pKey);

        byte referenceHash[Lamport::BLAKE2KeyHash::kBytesSize];
        CSecureSegmentRW<byte> guard = pKey.get_secure()->unlockAndInitRW(true);
        quantum_hash::blake2_generichash(referenceHash, Lamport::BLAKE2KeyHash::kBytesSize, guard.get_addr(), guard.get_size());
        assert(::memcmp(h.get_addr(), referenceHash, 32) == 0);
    }
    template <int rsv, typename T> static void vector_check(int n, int m) noexcept {
        char data[] = {'S', 'O', 'R', 'A', 'C', 'H', 'A', 'N', 'C', 'O', 'I', 'N'};
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
        const size_t buf_size = 1024;
        quantum_lib::secure_stackzero(buf_size);
        std::vector<byte> vdata;
        vdata.resize(buf_size, 0x00);
        byte *data = &vdata.at(0);
        ::RAND_bytes(data, buf_size);
        Lamport::CLamport lamport;
        std::shared_ptr<Lamport::CPublicKey> pubKey = lamport.create_pubkey(data, buf_size);

        assert(lamport.check(data, buf_size, pubKey) == true);

        byte *offset = pubKey->get_addr();
        for(int i=0; i < pubKey->get_size(); ++i)
        {
            char buf[8] = {0};
            ::sprintf_s(buf, sizeof(buf) / sizeof(buf[0]), "%X", offset[i]);
            debugcs::instance() << buf;
        }
        debugcs::instance() << debugcs::endl() << "--------------------------------" << debugcs::endl() << debugcs::endl();
    }

    static unsigned int __stdcall benchmark(void *) noexcept {
        for(int i=0; i < 5; ++i)
        {
#ifdef MEMORY_CHECK
            memory_check();
#endif
#ifdef SECURE_PREVECTOR_CHECK
            secure_prevector_check<PREVECTOR_N, uint8_t>(10, 30);
#endif
#ifdef HASH_CHECK
            hash_check();
#endif
#ifdef VECTOR_CHECK
            vector_check<PREVECTOR_N, uint8_t>(10, 30);
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
        HANDLE hHandle[16]; // count of threads
        for(int i=0; i < sizeof(hHandle) / sizeof(hHandle[0]); ++i)
        {
            hHandle[i] = (HANDLE)::_beginthreadex(nullptr, 0, Quantum_startup::benchmark, nullptr, 0, nullptr);
            if(hHandle[i] == INVALID_HANDLE_VALUE){
                assert(0);
            }
        }
        ::WaitForMultipleObjects(sizeof(hHandle) / sizeof(hHandle[0]), hHandle, true, INFINITE);
        for(int i=0; i < sizeof(hHandle) / sizeof(hHandle[0]); ++i)
        {
            ::CloseHandle(hHandle[i]);
        }
#endif
    }
    ~Quantum_startup() noexcept {}
};
Quantum_startup Quantum_startup::q_startup;

#endif
