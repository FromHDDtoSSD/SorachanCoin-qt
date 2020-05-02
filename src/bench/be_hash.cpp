// Copyright (c) 2018-2020 The SorachanCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(USE_QUANTUM) && defined(LATEST_CRYPTO_ENABLE)

#include <memory>
#include <quantum/quantum.h>
#include <prevector/prevector.h>
#include <bench/bench.h>
#include <compat/sanity.h>

namespace latest_crypto {
    typedef std::uint8_t byte;

static void Blake2Assertcheck_(benchmark::State& state)
{
    while(state.KeepRunning()) {
        Lamport::CPrivateKey pKey;
        Lamport::BLAKE2KeyHash h(pKey);

        byte referenceHash[Lamport::BLAKE2KeyHash::kBytesSize];
        CSecureSegmentRW<byte> guard = pKey.get_secure()->unlockAndInitRW(true);
        quantum_hash::blake2_generichash(referenceHash, Lamport::BLAKE2KeyHash::kBytesSize, guard.get_addr(), guard.get_size());
        assert(::memcmp(h.get_addr(), referenceHash, Lamport::BLAKE2KeyHash::kBytesSize) == 0);
    }
}

static void LamportAssertcheck_(benchmark::State& state)
{
    while(state.KeepRunning()) {
        const size_t buf_size = PREVECTOR_N;

        quantum_lib::secure_stackzero(buf_size);
        prevector<PREVECTOR_N, byte> vdata;
        vdata.resize(buf_size, 0x00);
        byte *data = &vdata.at(0);

        ::RAND_bytes(data, buf_size);
        Lamport::CLamport lamport;
        std::shared_ptr<Lamport::CPublicKey> pubKey = lamport.create_pubkey(data, buf_size);
        assert(lamport.check(data, buf_size, pubKey) == true);

        byte tmp = data[0];
        if(tmp - (data[0] = 0xFF))
            assert(lamport.check(data, buf_size, pubKey) == false); // Although data is of changing(insert 0xFF), no changed to pubkey.
        else
            assert(lamport.check(data, buf_size, pubKey) == true); // If data is no change, it can be checking again and again.

        std::shared_ptr<Lamport::CPublicKey> pubKey2 = lamport.create_pubkey(data, buf_size);
        assert(lamport.check(data, buf_size, pubKey2) == false); // Note: lamport object is used limit once.

        {
            Lamport::CLamport lamport3;
            std::shared_ptr<Lamport::CPublicKey> pubKey3 = lamport3.create_pubkey(data, buf_size);
            assert(lamport3.check(data, buf_size, pubKey3) == true);
        }

#ifdef LAMPORT_RESULT_VIEW
        const byte *offset = pubKey->get_addr();
        const size_t size = pubKey->get_size();
        for (size_t i = 0; i < size; ++i)
        {
            char buf[8] = { 0 };
            ::sprintf_s(buf, 8, "%X", offset[i]);
            debugcs::instance() << buf << debugcs::endl();
        }
        debugcs::instance() << debugcs::endl() << "--------------------------------" << debugcs::endl() << debugcs::endl();
#endif
    }
}

#define HASH_TEST(name, iter)                            \
    void name ## Assertcheck(benchmark::State& state) {  \
        name ## Assertcheck_(state);                     \
    }                                                    \
    BENCHMARK(name ## Assertcheck, iter);

HASH_TEST(Blake2, 50000)
HASH_TEST(Lamport, 50000)

} // namespace check_hash

#endif // USE_QUANTUM
