// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//

//
// Why base-58 instead of standard base-64 encoding?
// - Don't want 0OIl characters that look the same in some fonts and
//      could be used to create visually identical looking account numbers.
// - A string with non-alphanumeric characters is not as easily accepted as an account number.
// - E-mail usually won't line-break if there's no punctuation to break at.
// - Double-clicking selects the whole number as one word if it's all alphanumeric.
//

#include <string>
#include <vector>
#include <openssl/crypto.h> // for OPENSSL_cleanse()
#include "bignum.h"
#include "key.h"
#include "script.h"
#include "base58.h"

// Encode a byte sequence as a base58-encoded string
std::string base58::manage::EncodeBase58(const unsigned char *pbegin, const unsigned char *pend)
{
    CAutoBN_CTX pctx;
    CBigNum bn58 = 58;
    CBigNum bn0 = 0;

    // Convert big endian data to little endian
    // Extra zero at the end make sure bignum will interpret as a positive number
    std::vector<unsigned char> vchTmp(pend - pbegin + 1, 0);
    std::reverse_copy(pbegin, pend, vchTmp.begin());

    // Convert little endian data to bignum
    CBigNum bn;
    bn.setvch(vchTmp);

    // Convert bignum to std::string
    std::string str;

    // Expected size increase from base58 conversion is approximately 137%
    // use 138% to be safe
    str.reserve((pend - pbegin) * 138 / 100 + 1);
    CBigNum dv;
    CBigNum rem;
    while (bn > bn0)
    {
        if (! ::BN_div(&dv, &rem, &bn, &bn58, pctx)) {
            throw bignum_error("EncodeBase58 : BN_div failed");
        }

        bn = dv;
        unsigned int c = rem.getuint32();
        str += base58::pszBase58[c];
    }

    // Leading zeroes encoded as base58 zeros
    for (const unsigned char *p = pbegin; p < pend && *p == 0; p++)
    {
        str += base58::pszBase58[0];
    }

    // Convert little endian std::string to big endian
    std::reverse(str.begin(), str.end());
    return str;
}

// Encode a byte vector as a base58-encoded string
std::string base58::manage::EncodeBase58(const std::vector<unsigned char> &vch)
{
    return base58::manage::EncodeBase58(&vch[0], &vch[0] + vch.size());
}

// Decode a base58-encoded string psz into byte vector vchRet
// returns true if decoding is successful
bool base58::manage::DecodeBase58(const char *psz, std::vector<unsigned char> &vchRet)
{
    vchRet.clear();

    CAutoBN_CTX pctx;
    const CBigNum bn58 = 58;
    
    CBigNum bn = 0;
    CBigNum bnChar;
    while (::isspace(*psz))
    {
        psz++;
    }

    // Convert big endian string to bignum
    for (const char *p = psz; *p; p++)
    {
        const char* p1 = ::strchr(base58::pszBase58, *p);
        if (p1 == NULL) {
            while (::isspace(*p))
            {
                p++;
            }
            if (*p != '\0') {
                return false;
            }
            break;
        }

        bnChar.setuint32((uint32_t)(p1 - base58::pszBase58));
        if (! ::BN_mul(&bn, &bn, &bn58, pctx)) {
            throw bignum_error("DecodeBase58 : BN_mul failed");
        }
        bn += bnChar;
    }

    // Get bignum as little endian data
    std::vector<unsigned char> vchTmp = bn.getvch();

    // Trim off sign byte if present
    if (vchTmp.size() >= 2 && vchTmp.end()[-1] == 0 && vchTmp.end()[-2] >= 0x80) {
        vchTmp.erase(vchTmp.end() - 1);
    }

    // Restore leading zeros
    int nLeadingZeros = 0;
    for (const char *p = psz; *p == base58::pszBase58[0]; ++p)
    {
        ++nLeadingZeros;
    }
    vchRet.assign(nLeadingZeros + vchTmp.size(), 0);

    // Convert little endian data to big endian
    std::reverse_copy(vchTmp.begin(), vchTmp.end(), vchRet.end() - vchTmp.size());
    return true;
}

// Decode a base58-encoded string str into byte vector vchRet
// returns true if decoding is successful
bool base58::manage::DecodeBase58(const std::string &str, std::vector<unsigned char> &vchRet)
{
    return base58::manage::DecodeBase58(str.c_str(), vchRet);
}

// Encode a byte vector to a base58-encoded string, including checksum
std::string base58::manage::EncodeBase58Check(const std::vector<unsigned char> &vchIn)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(vchIn);

    uint256 hash = hash_basis::Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char *)&hash, (unsigned char *)&hash + 4);
    return base58::manage::EncodeBase58(vch);
}

// Decode a base58-encoded string psz that includes a checksum, into byte vector vchRet
bool base58::manage::DecodeBase58Check(const char *psz, std::vector<unsigned char> &vchRet)
{
    if (! base58::manage::DecodeBase58(psz, vchRet)) {
        return false;
    }

    if (vchRet.size() < 4) {    // 4-byte hash check
        vchRet.clear();
        return false;
    }

    uint256 hash = hash_basis::Hash(vchRet.begin(), vchRet.end() - 4);
    if (::memcmp(&hash, &vchRet.end()[-4], 4) != 0) {    // hash check
        vchRet.clear();
        return false;
    }

    vchRet.resize(vchRet.size() - 4);
    return true;
}

// Decode a base58-encoded string str that includes a checksum, into byte vector vchRet
bool base58::manage::DecodeBase58Check(const std::string &str, std::vector<unsigned char> &vchRet)
{
    return base58::manage::DecodeBase58Check(str.c_str(), vchRet);
}

bool CBitcoinAddress::Set(const CTxDestination &dest) {
    return boost::apply_visitor(CBitcoinAddressVisitor(this), dest);
}

bool CBitcoinAddress::IsValid() const
{
    unsigned int nExpectedSize = 20;
    bool fExpectTestNet = false;
    bool fSimple = true;

    switch(getVersion())
    {
    case PUBKEY_PAIR_ADDRESS:
        nExpectedSize = 68; // Serialized pair of public keys
        fExpectTestNet = false;
        fSimple = false;
        break;
    case PUBKEY_ADDRESS:
        nExpectedSize = 20; // Hash of public key
        fExpectTestNet = false;
        break;
    case SCRIPT_ADDRESS:
        nExpectedSize = 20; // Hash of CScript
        fExpectTestNet = false;
        break;
    case PUBKEY_PAIR_ADDRESS_TEST:
        nExpectedSize = 68;
        fExpectTestNet = true;
        fSimple = false;
        break;
    case PUBKEY_ADDRESS_TEST:
        nExpectedSize = 20;
        fExpectTestNet = true;
        break;
    case SCRIPT_ADDRESS_TEST:
        nExpectedSize = 20;
        fExpectTestNet = true;
        break;
    default:
        return false;
    }

    // Basic format sanity check
    bool fSeemsSane = (fExpectTestNet == args_bool::fTestNet && getvchData().size() == nExpectedSize);

    if (fSeemsSane && !fSimple) {
        // Perform dditional checking
        // for pubkey pair addresses
        CMalleablePubKey mpk;
        mpk.setvch(getvchData());
        return mpk.IsValid();
    } else {
        return fSeemsSane;
    }
}

CTxDestination CBitcoinAddress::Get() const {
    if (! IsValid()) {
        return CNoDestination();
    }

    switch (getVersion())
    {
    case PUBKEY_ADDRESS:
    case PUBKEY_ADDRESS_TEST:
        {
            uint160 id;
            ::memcpy(&id, getvchArray(), 20);
            return CKeyID(id);
        }
        break;
    case SCRIPT_ADDRESS:
    case SCRIPT_ADDRESS_TEST:
        {
            uint160 id;
            ::memcpy(&id, getvchArray(), 20);
            return CScriptID(id);
        }
        break;
    default:
        break;
    }
    return CNoDestination();
}

bool CBitcoinAddress::GetKeyID(CKeyID &keyID) const {
    if (! IsValid()) {
        return false;
    }

    switch (getVersion())
    {
    case PUBKEY_ADDRESS:
    case PUBKEY_ADDRESS_TEST:
        {
            uint160 id;
            ::memcpy(&id, getvchArray(), 20);
            keyID = CKeyID(id);
            return true;
        }
        break;
    case PUBKEY_PAIR_ADDRESS:
    case PUBKEY_PAIR_ADDRESS_TEST:
        {
            CMalleablePubKey mPubKey;
            mPubKey.setvch(getvchData());
            keyID = mPubKey.GetID();
            return true;
        }
        break;
    default:
        return false;
    }
}

bool CBitcoinAddress::IsScript() const {
    if (! IsValid()) {
        return false;
    }

    switch (getVersion())
    {
    case SCRIPT_ADDRESS:
    case SCRIPT_ADDRESS_TEST:
        return true;
    default:
        return false;
    }
}

bool CBitcoinAddress::IsPubKey() const {
    if (! IsValid()) {
        return false;
    }

    switch (getVersion())
    {
    case PUBKEY_ADDRESS:
    case PUBKEY_ADDRESS_TEST:
        return true;
    default:
        return false;
    }
}

bool CBitcoinAddress::IsPair() const {
    if (! IsValid()) {
        return false;
    }

    switch (getVersion())
    {
    case PUBKEY_PAIR_ADDRESS:
    case PUBKEY_PAIR_ADDRESS_TEST:
        return true;
    default: 
        return false;
    }
}
