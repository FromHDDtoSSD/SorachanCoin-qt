// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SorachanCoin: No use ctx

//#include <key/privkey.h>
//#include <random/random.h>
//#include <cleanse/cleanse.h>

#ifdef VERIFY // pubkey.h
# define VERIFY_CHECK(cond) do { assert(cond); } while(0)
# define CHECK(cond) VERIFY_CHECK(cond)
#else
# define VERIFY_CHECK(cond) do { (void)(cond); } while(0)
# define CHECK(cond) VERIFY_CHECK(cond)
#endif

#define ARG_CHECK(cond) ARG_CHECK_FUNC(cond, nullptr)
#define ARG_CHECK_FUNC(cond, func) do { if(!(cond)) return CPrivKey::PrivKey_ERROR_callback((func)); } while(0)

/*
void CKey::secp256k1_scalar_clear(CPubKey::secp256k1_unit *r) noexcept {
    //r->d[0] = 0;
    //r->d[1] = 0;
    //r->d[2] = 0;
    //r->d[3] = 0;
    //r->d[4] = 0;
    //r->d[5] = 0;
    //r->d[6] = 0;
    //r->d[7] = 0;

    //! SorachanCoin: if used -03, the above process will be eliminated.
    cleanse::memory_cleanse(r, sizeof(r->d));
}

int CKey::secp256k1_ec_seckey_verify(const unsigned char *seckey) noexcept {
    CPubKey::secp256k1_unit sec;
    int overflow;
    //VERIFY_CHECK(ctx != nullptr);
    ARG_CHECK(seckey != nullptr);

    CPubKey::secp256k1_scalar_set_be32(&sec, seckey, &overflow);
    int ret = !overflow && !CPubKey::secp256k1_scalar_is_zero(&sec);
    secp256k1_scalar_clear(&sec); // Note: should be used ::OPENSSL_Cleanse
    return ret;
}

bool CKey::Check(const unsigned char *vch) noexcept {
    return secp256k1_ec_seckey_verify(vch);
}

void CKey::MakeNewKey(bool fCompressedIn) noexcept {
    do {
        random::GetStrongRandBytes(keydata_.data(), keydata_.size());
    } while (! Check(keydata_.data()));
    fValid_ = true;
    fCompressed_ = fCompressedIn;
}
*/
