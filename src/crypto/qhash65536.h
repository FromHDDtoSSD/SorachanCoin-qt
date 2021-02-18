// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SORACHANCOIN_QHASH65536_H
#define SORACHANCOIN_QHASH65536_H

#include <quantum/quantum.h>

namespace latest_crypto {

class CQHASH65536
{
private:
    CQHASH65536(const CQHASH65536 &)=delete;
    CQHASH65536(CQHASH65536 &&)=delete;
    //CQHASH65536 &operator=(const CQHASH65536 &)=delete;
    //CQHASH65536 &operator=(CQHASH65536 &&)=delete;
    static constexpr size_t OUTPUT_SIZE = 8192;
    unsigned char memory[sizeof(Lamport::CLamport)];
    Lamport::CLamport *plamport;
public:
    static constexpr size_t Size() noexcept {return OUTPUT_SIZE;}

    CQHASH65536 &operator=(const CQHASH65536 &obj) noexcept;
    void Clean() noexcept;
    CQHASH65536() noexcept;
    CQHASH65536& Write(const unsigned char* data, size_t len) noexcept;
    void Finalize(unsigned char hash[OUTPUT_SIZE]) noexcept;
    CQHASH65536& Reset() noexcept;

    ~CQHASH65536();
};

} // namespace latest_crypto

#endif // SORACHANCOIN_QHASH65536_H
