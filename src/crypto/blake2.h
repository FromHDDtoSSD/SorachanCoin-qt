// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_BLAKE2_H
#define CRYPTO_BLAKE2_H

#if defined(USE_QUANTUM)

# include <blake2.h>

namespace latest_crypto {

class CBLAKE2
{
private:
    blake2s_state S;

public:
    static const size_t OUTPUT_SIZE = 32;

    CBLAKE2();
    CBLAKE2& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CBLAKE2& Reset();

    static constexpr size_t Size() {return OUTPUT_SIZE;}
    void Clean();
};

} // latest_crypto

#endif

#endif
