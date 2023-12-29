#ifndef BITCOIN_CRYPTO_KECCAK256_H
#define BITCOIN_CRYPTO_KECCAK256_H

#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <array>
#include <cleanse/cleanse.h>

// KECCAK256 library
// https://github.com/kazuakiishiguro/cpp-keccak256

namespace keccak256_lib {

// round
// The sequence of step mappigs that is iterated
// inthe calculation of a KECCAK-p permutation
static constexpr int ROUNDS = 24;

// keccak round constant
// For each round of a KECCAK-p permutation, a lane value that is
// determined by the round index. The round constant is the second input to
// the ι step mapping.
static constexpr std::array<std::uint64_t, ROUNDS> RNDC {
  0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
  0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
  0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
  0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
  0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
  0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
  0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
  0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// Keccack-f[b] transform. b = 25w = 1600
void KeccakF(uint64_t st[25]);

class Keccak {
 private:
  union {
    uint8_t b[200]; // The width of a KECCAK-p permutation in bits
    uint64_t w[25]; // The lane of 64-bit 5 * 5 = 25 words. Also b = 25w = 1600
  } st; // state

  int pt, rsiz, mdlen; // mdlen = hash output in bytes
 public:
  Keccak() {}
  Keccak(const void *in, size_t in_len, void *md, int _mdlen);
  int Init(int _mdlen);
  int Update(const void *data, size_t len);
  int Finalize(void *md);
  int Reset();

  void Clean() {
      cleanse::OPENSSL_cleanse(st.b, sizeof(st.b));
  }
};

} // namespace keccak256_lib

namespace latest_crypto {

/** A hasher class for KECCAK256. */
class CKECCAK256
{
private:
    keccak256_lib::Keccak keccak;

public:
    static constexpr size_t OUTPUT_SIZE = 32;

    CKECCAK256();
    CKECCAK256& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CKECCAK256& Reset();

    static constexpr size_t Size() {return OUTPUT_SIZE;}
    void Clean() {
        keccak.Clean();
    }
};

} // namespace latest_crypto

#endif // BITCOIN_CRYPTO_KECCAK256_H
