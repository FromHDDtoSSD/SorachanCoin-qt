// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(USE_QUANTUM) && defined(LATEST_CRYPTO_ENABLE)

# include <crypto/hmac_qhash65536.h>
# include <debugcs/debugcs.h>

namespace latest_crypto {

template <typename BASE>
uint131072 HMAC_LAMPORT_PRIVATE_HASH_impl<BASE>::CalculateDigest(const byte *input, size_t length) {
    unsigned char X[BASE::Size()];
    uint131072 result=0;
    BASE CTX;
    CTX.Write(input, length);
    CTX.Finalize(X);
    pbkdf2::PBKDF2_HASH(input, length, (byte *)X, sizeof(X), 1, (byte *)&result, sizeof(uint131072));
    //debugcs::instance() << sizeof(X) << "_" << sizeof(uint131072) << debugcs::endl();
    return result;
}

template class HMAC_LAMPORT_PRIVATE_HASH_impl<latest_crypto::CSHA256>;

} // latest_crypto

#endif
