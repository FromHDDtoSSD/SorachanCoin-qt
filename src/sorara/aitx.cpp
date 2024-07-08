// Copyright (c) 2018-2024 The SorachanCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sorara/aitx.h>
#include <crypto/aes.h>
#include <hash.h>
#include <key/privkey.h>
#include <util/time.h>

namespace {

constexpr static int HASH160_DIGEST_LENGTH = sizeof(uint160);

// Function to build the Merkle tree and compute the Merkle root
void hash160_get_merkle_root(uint160 &merkle_root, const std::vector<uint160> &vhashes) {
    auto compute_hash160 = [](const unsigned char *data, size_t len, unsigned char *hash) {
        latest_crypto::CHash160().Write(data, len).Finalize(hash);
    };

    if (vhashes.size() == 0) {
        merkle_root = uint160(0);
        return;
    }
    size_t num_hashes = vhashes.size();

    // Copy the current level's hashes
    std::vector<uint160> current_level;
    current_level.resize(num_hashes);
    for (size_t i = 0; i < num_hashes; i++)
        ::memcpy(current_level[i].begin(), vhashes[i].begin(), HASH160_DIGEST_LENGTH);

    // Build the Merkle tree
    while (num_hashes > 1) {
        size_t new_num_hashes = (num_hashes + 1) / 2;
        std::vector<uint160> next_level;
        next_level.resize(new_num_hashes);
        for (size_t i = 0; i < new_num_hashes; i++) {
            if (2 * i + 1 < num_hashes) {
                // Combine two child hashes and compute the parent hash
                unsigned char combined[2 * HASH160_DIGEST_LENGTH];
                ::memcpy(combined, current_level[2 * i].begin(), HASH160_DIGEST_LENGTH);
                ::memcpy(combined + HASH160_DIGEST_LENGTH, current_level[2 * i + 1].begin(), HASH160_DIGEST_LENGTH);
                compute_hash160(combined, 2 * HASH160_DIGEST_LENGTH, next_level[i].begin());
            } else {
                // Odd number of hashes, so copy the last hash
                ::memcpy(next_level[i].begin(), current_level[2 * i].begin(), HASH160_DIGEST_LENGTH);
            }
        }

        // Move to the next level
        current_level.clear();
        current_level = std::move(next_level);
        num_hashes = new_num_hashes;
    }

    // The root hash is the only hash in the final level
    ::memcpy(merkle_root.begin(), current_level[0].begin(), HASH160_DIGEST_LENGTH);
}

} // namespace

bool CAIToken03::IsValid() const {
    return crypto.size() > 0;
}

bool CAIToken03::SetTokenMessage(const SymmetricKey &key, const SecureString &message) {
    std::pair<CSecureBytes, bool> cipher;
    latest_crypto::CAES256CBCPKCS7(key.data(), key.size()).Encrypt((const unsigned char *)message.data(), message.size()).Finalize(cipher);
    if(!cipher.second)
        return false;
    crypto = std::move(cipher.first);
    return true;
}

bool CAIToken03::GetTokenMessage(const SymmetricKey &key, SecureString &message) const {
    if(crypto.size() == 0)
        return false;
    std::pair<CSecureBytes, bool> plain;
    latest_crypto::CAES256CBCPKCS7(key.data(), key.size()).Decrypt(crypto.data(), crypto.size()).Finalize(plain);
    if(!plain.second)
        return false;
    message.clear();
    message.shrink_to_fit();
    message.insert(message.end(), plain.first.begin(), plain.first.end());
    return true;
}

std::pair<uint160, bool> CAIToken03::GetHash() const {
    if(crypto.size() == 0)
        return std::make_pair(uint160(0), false);
    uint160 hash;
    latest_crypto::CHash160().Write(crypto.data(), crypto.size()).Finalize(hash.begin());
    return std::make_pair(hash, true);
}

bool CAITransaction::IsValid() const {
    return hashes.size() > 0 && nTime != 0 && schnorrsigHash != CKeyID(0);
}

void CAITransaction::PushTokenHash(uint160 hash) {
    hashes.emplace_back(hash);
}

void CAITransaction::SetSchnorrAggregateKeyID(const XOnlyPubKey &xonly_pubkey) {
    nTime = bitsystem::GetAdjustedTime();
    schnorrsigHash = xonly_pubkey.GetID();
}

void CAITransaction::ClearTx() {
    nTime = 0;
    schnorrsigHash = CKeyID(0);
    hashes.clear();
}

std::pair<uint160, bool> CAITransaction::GetMerkleRoot() const {
    if(!IsValid())
        return std::make_pair(uint160(0), false);
    std::vector<uint160> target = hashes;
    target.push_back(schnorrsigHash);
    uint160 merkle_root;
    hash160_get_merkle_root(merkle_root, target);
    return std::make_pair(merkle_root, true);
}

std::pair<qkey_vector, bool> CAITransaction::GetSchnorrHash() const {
    qkey_vector buf;
    buf.resize(33); // size is CPubKey::COMPRESSED_PUBLIC_KEY_SIZE
    ::memset(&buf.front(), 0xFF, 33);
    buf[0] = 0x02;
    buf[1] = qaiVersion;
    std::pair<uint160, bool> merkle_root = GetMerkleRoot();
    if(!merkle_root.second)
        return std::make_pair(qkey_vector(), false);
    ::memcpy(&buf[2], merkle_root.first.begin(), 20);
    return std::make_pair(buf, true);
}

bool CAITransaction03::IsValid() const {
    return aitx.IsValid();
}

bool CAITransaction03::PushTokenMessage(const SymmetricKey &key, const SecureString &message) {
    CAIToken03 token;
    if(!token.SetTokenMessage(key, message))
        return false;
    std::pair<uint160, bool> hash = token.GetHash();
    if(!hash.second)
        return false;
    aitx.PushTokenHash(hash.first);
    tokens.emplace_back(token);
    return true;
}

void CAITransaction03::SetSchnorrAggregateKeyID(const XOnlyPubKey &xonly_pubkey) {
    aitx.SetSchnorrAggregateKeyID(xonly_pubkey);
}

void CAITransaction03::ClearTokens() {
    tokens.clear();
    aitx.ClearTx();
}

uint32_t CAITransaction03::SizeTokens() const {
    return tokens.size();
}

const CAIToken03 &CAITransaction03::operator[](uint32_t index) const {
    return tokens.at(index);
}

CAIToken03 *CAITransaction03::begin() {
    return &tokens[0];
}

CAIToken03 *CAITransaction03::end() {
    return &tokens[0] + tokens.size();
}

const CAIToken03 *CAITransaction03::begin() const {
    return &tokens[0];
}

const CAIToken03 *CAITransaction03::end() const {
    return &tokens[0] + tokens.size();
}

std::pair<uint160, bool> CAITransaction03::GetMerkleRoot() const {
    return aitx.GetMerkleRoot();
}

std::pair<qkey_vector, bool> CAITransaction03::GetSchnorrHash() const {
    return aitx.GetSchnorrHash();
}
