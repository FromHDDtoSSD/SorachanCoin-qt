// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Copyright (c) 2014-2018 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Why base-58 instead of standard base-64 encoding?
// - Don't want 0OIl characters that look the same in some fonts and
//      could be used to create visually identical looking account numbers.
// - A string with non-alphanumeric characters is not as easily accepted as an account number.
// - E-mail usually won't line-break if there's no punctuation to break at.
// - Double-clicking selects the whole number as one word if it's all alphanumeric.

#include <string>
#include <vector>
#include <address/base58.h>
#include <util/strencodings.h>

namespace {
/** All alphanumeric characters except for "0", "I", "O", and "l" */
const char *pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const int8_t mapBase58[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
};
} // namespace

bool base58::manage::DecodeBase58(const char *psz, base58_vector &vch) {
    // Skip leading spaces.
    while (*psz && strenc::IsSpace(*psz))
        psz++;
    // Skip and count leading '1's.
    int zeroes = 0;
    int length = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    int size = strlen(psz) * 733 /1000 + 1; // log(58) / log(256), rounded up.
    base58_vector b256(size);
    // Process the characters.
    static_assert(sizeof(mapBase58)/sizeof(mapBase58[0]) == 256, "mapBase58.size() should be 256"); // guarantee not out of range
    while (*psz && !strenc::IsSpace(*psz)) {
        // Decode base58 character
        int carry = mapBase58[(uint8_t)*psz];
        if (carry == -1)  // Invalid b58 character
            return false;
        int i = 0;
        for (base58_vector::reverse_iterator it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
            carry += 58 * (*it);
            *it = (uint8_t)(carry % 256);
            carry /= 256;
        }
        assert(carry == 0);
        length = i;
        psz++;
    }
    // Skip trailing spaces.
    while (strenc::IsSpace(*psz))
        psz++;
    if (*psz != 0)
        return false;
    // Skip leading zeroes in b256.
    base58_vector::iterator it = b256.begin() + (size - length);
    while (it != b256.end() && *it == 0)
        it++;
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, (uint8_t)0x00);
    while (it != b256.end())
        vch.push_back(*(it++));
    return true;
}

std::string base58::manage::EncodeBase58(const unsigned char *pbegin, const unsigned char *pend) {
    // Skip & count leading zeroes.
    int zeroes = 0;
    int length = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }
    // Allocate enough space in big-endian base58 representation.
    int size = (pend - pbegin) * 138 / 100 + 1; // log(256) / log(58), rounded up.
    base58_vector b58(size);
    // Process the bytes.
    while (pbegin != pend) {
        int carry = *pbegin;
        int i = 0;
        // Apply "b58 = b58 * 256 + ch".
        for (base58_vector::reverse_iterator it = b58.rbegin(); (carry != 0 || i < length) && (it != b58.rend()); it++, i++) {
            carry += 256 * (*it);
            *it = (uint8_t)(carry % 58);
            carry /= 58;
        }

        assert(carry == 0);
        length = i;
        pbegin++;
    }
    // Skip leading zeroes in base58 result.
    base58_vector::iterator it = b58.begin() + (size - length);
    while (it != b58.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b58.end() - it));
    str.assign(zeroes, '1');
    while (it != b58.end())
        str += pszBase58[*(it++)];
    return str;
}

std::string base58::manage::EncodeBase58(const base58_vector &vch) {
    return EncodeBase58(vch.data(), vch.data() + vch.size());
}

bool base58::manage::DecodeBase58(const std::string &str, base58_vector &vchRet) {
    return DecodeBase58(str.c_str(), vchRet);
}

#ifdef CSCRIPT_PREVECTOR_ENABLE
std::string base58::manage::EncodeBase58(const std::vector<unsigned char> &vch) {
    if(vch.empty()) return std::string("");
    return EncodeBase58(&vch[0], &vch[0]+vch.size());
}

bool base58::manage::DecodeBase58(const std::string &str, std::vector<unsigned char> &vchRet) {
    base58_vector bch;
    bool ret = DecodeBase58(str, bch);
    if(ret) {
        vchRet.clear();
        vchRet.insert(vchRet.end(), bch.begin(), bch.end());
    }
    return ret;
}
#endif

std::string base58::manage::EncodeBase58Check(const base58_vector &vchIn) {
    // add 4-byte hash check to the end
    base58_vector vch(vchIn);
    uint256 hash = hash_basis::Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}

bool base58::manage::DecodeBase58Check(const char *psz, base58_vector &vchRet) { // psz is base58
    if (!DecodeBase58(psz, vchRet) || (vchRet.size() < 4)) {
        vchRet.clear();
        return false;
    }
    // re-calculate the checksum, ensure it matches the included 4-byte checksum
    uint256 hash = hash_basis::Hash(vchRet.begin(), vchRet.end() - 4);
    if (::memcmp(&hash, &vchRet[vchRet.size() - 4], 4) != 0) {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size() - 4);
    return true;
}

bool base58::manage::DecodeBase58Check(const std::string &str, base58_vector &vchRet) {
    return DecodeBase58Check(str.c_str(), vchRet);
}

/*
std::string base58::manage::EncodeBase58Check(const base58_vector &vchIn) {
    // add 4-byte hash check to the end
    base58_vector vch(vchIn);
    if(g_fbase58_bitcoin_1)
        vch[0] = 0x00;
    else if (g_fbase58_bitcoin_3)
        vch[0] = 0x05;
    else if(g_fbase58_bitcoin_3_b)
        vch[0] = 0x06;
    else if (g_fbase58_dogecoin_D)
        vch[0] = 30;
    else if (g_fbase58_dogecoin_D_b)
        vch[0] = 31;
    else if(g_fbase58_monacoin_M)
        vch[0] = 50;
    else if(g_fbase58_monacoin_M_b)
        vch[0] = 51;
    else if(g_fbase58_litecoin_L)
        vch[0] = 48;
    else if(g_fbase58_tron_T)
        vch[0] = 65;
    else if(g_fbase58_tron_T_b)
        vch[0] = 66;
    else if(g_fbase58_Z)
        vch[0] = 80;
    else if(g_fbase58_Z_b)
        vch[0] = 81;
    else if(g_fbase58_X)
        vch[0] = 75;
    else if(g_fbase58_X_b)
        vch[0] = 76;
    else if(g_fbase58_V)
        vch[0] = 70;
    else if(g_fbase58_V_b)
        vch[0] = 71;
    else if(g_fbase58_N)
        vch[0] = 53;
    else if(g_fbase58_W)
        vch[0] = 73;
    else if(g_fbase58_R)
        vch[0] = 60;
    else if(g_fbase58_F)
        vch[0] = 35;
    else if(g_fbase58_K)
        vch[0] = 45;
    else if(g_fbase58_R_b)
        vch[0] = 61;
    else if(g_fbase58_F_b)
        vch[0] = 36;
    else if(g_fbase58_K_b)
        vch[0] = 46;
    else if(g_fbase58_5)
        vch[0] = 10;
    else if(g_fbase58_B)
        vch[0] = 25;
    else if(g_fbase58_C)
        vch[0] = 28;
    else if(g_fbase58_5_b)
        vch[0] = 11;
    else if(g_fbase58_B_b)
        vch[0] = 26;
    else if(g_fbase58_P)
        vch[0] = 55;
    else if(g_fbase58_7)
        vch[0] = 15;
    else if(g_fbase58_9)
        vch[0] = 20;
    else if(g_fbase58_P_b)
        vch[0] = 56;
    else if(g_fbase58_7_b)
        vch[0] = 16;
    else if(g_fbase58_9_b)
        vch[0] = 21;
    else if(g_fbase58_Q)
        vch[0] = 58;
    else if(g_fbase58_A)
        vch[0] = 23;
    else if(g_fbase58_E)
        vch[0] = 33;
    else if(g_fbase58_G)
        vch[0] = 38;
    else if(g_fbase58_H)
        vch[0] = 40;
    else if(g_fbase58_J)
        vch[0] = 43;
    else if(g_fbase58_L)
        vch[0] = 48;
    else if(g_fbase58_U)
        vch[0] = 68;
    else if(g_fbase58_Y)
        vch[0] = 78;
    else if(g_fbase58_S)
        vch[0] = 91;
    else if(g_fbase58_H_b)
        vch[0] = 41;

    uint256 hash = hash_basis::Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);

#ifdef DEBUG
    ::printf("base58 prefix: %d\n", vchIn[0]);
    ::printf("base58 vchIn size: %d\n", (int)vchIn.size());

    //bech32_vector bc32_vch;
    //bc32_vch.reserve(20);
    //for(int i=0; i < 20; ++i)
    //    bc32_vch.push_back(vchIn[i+1]);
    //std::string bc32_address = bech32::Encode(std::string("bc"), bc32_vch);
    //::printf("bech32 address length: %I64d: %s\n", bc32_address.size(), bc32_address.c_str());
#endif

    return EncodeBase58(vch);
}
*/
