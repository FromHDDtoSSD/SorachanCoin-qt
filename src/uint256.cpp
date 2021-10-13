// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2018-2021 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <uint256.h>
#include <key/pubkey.h>

#define no_supported_mul_div_mod(bits) \
    if(bits!=256) { \
        assert(!"no supported */%"); \
        return *this; \
    }

template <unsigned int BITS>
base_uint<BITS> &base_uint<BITS>::operator*=(const base_uint &b) {
    no_supported_mul_div_mod(BITS)
    s256k1_fe fe1, fe2;
    secp256k1_negate_ope::fe_set_uint256(&fe1, (const uint256 *)this);
    secp256k1_negate_ope::fe_set_uint256(&fe2, (const uint256 *)&b);
    secp256k1_negate_ope::fe_mul_to_negate(&fe1, 0, &fe2, 0);
    *this = secp256k1_negate_ope::fe_get_uint256(&fe1);
    return *this;
}

template <unsigned int BITS>
base_uint<BITS> &base_uint<BITS>::operator/=(const base_uint &b) {
    no_supported_mul_div_mod(BITS)
    s256k1_fe fe1, fe2;
    secp256k1_negate_ope::fe_set_uint256(&fe1, (const uint256 *)this);
    secp256k1_negate_ope::fe_set_uint256(&fe2, (const uint256 *)&b);
    secp256k1_negate_ope::fe_div_to_negate(&fe1, 0, &fe2, 0);
    *this = secp256k1_negate_ope::fe_get_uint256(&fe1);
    return *this;
}

template <unsigned int BITS>
base_uint<BITS> &base_uint<BITS>::operator%=(const base_uint &b) {
    no_supported_mul_div_mod(BITS)
    s256k1_fe fe1, fe2;
    secp256k1_negate_ope::fe_set_uint256(&fe1, (const uint256 *)this);
    secp256k1_negate_ope::fe_set_uint256(&fe2, (const uint256 *)&b);
    secp256k1_negate_ope::fe_mod_to_negate(&fe1, 0, &fe2, 0);
    *this = secp256k1_negate_ope::fe_get_uint256(&fe1);
    return *this;
}

//
// Note: must not define base_uint<256> other (because, no supported)
//
template class base_uint<256>;
