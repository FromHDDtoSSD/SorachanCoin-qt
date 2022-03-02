// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef HMAC_QHASH65536_H
#define HMAC_QHASH65536_H

# include <const/no_instance.h>
# include <crypto/sha256.h>
# include <uint256.h>
# include <pbkdf2.h>

namespace latest_crypto {

// LAMPORT_PRIVATE_HASH
template<typename BASE>
class HMAC_LAMPORT_PRIVATE_HASH_impl : private no_instance {
private:
    using pbkdf2 = pbkdf2_impl<BASE>;
public:
    using byte = uint8_t;
    static uint131072 CalculateDigest(const byte *input, size_t length);
};
using HMAC_LAMPORT_PRIVATE_HASH = HMAC_LAMPORT_PRIVATE_HASH_impl<latest_crypto::CSHA256>;

} // latest_crypto

#endif // HMAC_QHASH65536_H
