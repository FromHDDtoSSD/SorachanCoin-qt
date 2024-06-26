// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

# include <quantum/quantum.h>
# include <crypto/sha256.h>
# include <uint256.h>
# include <pbkdf2.h>
# include <debug/debug.h>
# include <crypto/qhash65536.h>
# include <crypto/hmac_qhash65536.h>

namespace latest_crypto {

CQHASH65536 &CQHASH65536::operator=(const CQHASH65536 &obj)  {
    if(! plamport) plamport = new (memory) Lamport::CLamport(*(obj.plamport));
    else *plamport = *(obj.plamport);
    return *this;
}

void CQHASH65536::Clean()  {
    plamport->Clean();
}

CQHASH65536::CQHASH65536()  : plamport(nullptr) {
    Reset();
}

CQHASH65536::~CQHASH65536() {
    Reset();
}

CQHASH65536& CQHASH65536::Write(const unsigned char* data, size_t len)  {
    assert(OUTPUT_SIZE == plamport->GetSize());
    if(! plamport) {
        uint131072 key = HMAC_LAMPORT_PRIVATE_HASH::CalculateDigest(data, len);
        plamport = new (memory) Lamport::CLamport((const Lamport::byte *)&key); // sizeof(uint131072)
    }
    plamport->create_hashonly(data, len);
    return *this;
}

void CQHASH65536::Finalize(unsigned char hash[OUTPUT_SIZE])  {
    assert(OUTPUT_SIZE == plamport->GetSize());
    std::memcpy(hash, plamport->GetSignatured(), plamport->GetSize());
}

CQHASH65536& CQHASH65536::Reset()  {
    if(plamport) {
        plamport->~CLamport();
        plamport = nullptr;
    }
    return *this;
}

} // latest_crypto

