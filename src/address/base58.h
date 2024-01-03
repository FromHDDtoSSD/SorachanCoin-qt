// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Why base-58 instead of standard base-64 encoding?
// - Don't want 0OIl characters that look the same in some fonts and
//      could be used to create visually identical looking account numbers.
// - A string with non-alphanumeric characters is not as easily accepted as an account number.
// - E-mail usually won't line-break if there's no punctuation to break at.
// - Double-clicking selects the whole number as one word if it's all alphanumeric.
#ifndef BITCOIN_BASE58_H
#define BITCOIN_BASE58_H

#include <string>
#include <vector>
#include <cleanse/cleanse.h>
#include <bignum.h>
#include <key.h>
#include <script/script.h>

#ifdef CSCRIPT_PREVECTOR_ENABLE
typedef prevector<PREVECTOR_N, uint8_t> base58_vector;
#else
typedef std::vector<uint8_t> base58_vector;
#endif
namespace base58 {
    class manage : private no_instance {
    private:
        // Decode a base58-encoded string psz into byte vector vchRet
        template <typename T=base58_vector>
        static bool DecodeBase58(const char *psz, T &vchRet);

    public:
        // Encode a byte sequence as a base58-encoded string
        template <typename R=std::string, typename T=base58_vector>
        static R EncodeBase58(const unsigned char *pbegin, const unsigned char *pend);

        // Encode a byte vector as a base58-encoded string
        template <typename R=std::string, typename T=base58_vector>
        static R EncodeBase58(const T &vch);

        // Decode a base58-encoded string str into byte vector vchRet
        //static bool DecodeBase58(const std::string &str, base58_vector &vchRet);

#ifdef CSCRIPT_PREVECTOR_ENABLE
        // Encode a byte vector as a base58-encoded string
        static std::string EncodeBase58(const std::vector<unsigned char> &vch);

        // Decode a base58-encoded string str into byte vector vchRet
        static bool DecodeBase58(const std::string &str, std::vector<unsigned char> &vchRet);
#endif

        // [4 bytes hash check] Encode a byte vector to a base58-encoded string, including checksum
        template <typename R=std::string, typename T=base58_vector>
        static R EncodeBase58Check(const T &vchIn);

        // [4 bytes hash check] Decode a base58-encoded string psz or str that includes a checksum, into byte vector vchRet
        template <typename T=base58_vector>
        static bool DecodeBase58Check(const char *psz, T &vchRet);
        static bool DecodeBase58Check(const std::string &str, base58_vector &vchRet);
        static bool DecodeBase58Check(const SecureString &str, CPrivKey &vchRet);
    };
}

#endif
