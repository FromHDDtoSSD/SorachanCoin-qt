// Copyright (c) 2017 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Bech32 is a string encoding format used in newer address types.
// The output consists of a human-readable part (alphanumeric), a
// separator character (1), and a base32 data section, the last
// 6 characters of which are a checksum.
//
// For more information, see BIP 173.

#ifndef BITCOIN_BECH32_H
#define BITCOIN_BECH32_H

#include <stdint.h>
#include <string>
#include <vector>
#include <prevector/prevector.h>

#ifdef CSCRIPT_PREVECTOR_ENABLE
using bech32_vector = prevector<PREVECTOR_N, unsigned char>;
#else
using bech32_vector = std::vector<unsigned char>;
#endif
namespace bech32
{

/** Encode a Bech32 string. Returns the empty string in case of failure. */
std::string Encode(const std::string &hrp, const bech32_vector &values);

/** Decode a Bech32 string. Returns (hrp, data). Empty hrp means failure. */
std::pair<std::string, bech32_vector> Decode(const std::string &str);

} // namespace bech32

#endif // BITCOIN_BECH32_H
