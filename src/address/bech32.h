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

//
// SORA L1 Quantum and AI resistance transaction for Bech32
//
inline bech32_vector EncodeToSoraL1QAItxBech32(const bech32_vector &data) {
    bech32_vector bits5;
    int bitCount = 0;
    uint8_t currentByte = 0;
    for (unsigned char byte: data) {
        for (int i = 7; i >= 0; --i) {
            currentByte = (currentByte << 1) | ((byte >> i) & 1);
            bitCount++;
            if (bitCount == 5) {
                bits5.push_back(currentByte);
                bitCount = 0;
                currentByte = 0;
            }
        }
    }
    if (bitCount > 0) {
        bits5.push_back(currentByte << (5 - bitCount));
    }

    return bits5;
}

inline bech32_vector DecodeFromSoraL1QAItxBech32(const bech32_vector &bits5) {
    bech32_vector bytes;
    int bitCount = 0;
    unsigned char currentByte = 0;
    for (uint8_t bitGroup: bits5) {
        for (int i = 4; i >= 0; --i) {
            currentByte = (currentByte << 1) | ((bitGroup >> i) & 1);
            bitCount++;
            if (bitCount == 8) {
                bytes.push_back(currentByte);
                bitCount = 0;
                currentByte = 0;
            }
        }
    }

    if (bitCount > 0) {
        bytes.push_back(currentByte << (8 - bitCount));
    }

    return bytes;
}

#endif // BITCOIN_BECH32_H
