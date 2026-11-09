
// BITCOIN_RANDOM

#include "random/random.h"

void randombytes(uint8_t *out, size_t len) {
    random::GetStrongRandBytes(out, len);
}

/* OS entropy only; no third-party library. Fail closed on RNG failure. */
/***
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "randombytes.h"
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif
void randombytes(uint8_t *out, size_t len) {
    while (len) {
        ULONG n = (len > 1048576) ? 1048576UL : (ULONG)len;
        if (BCryptGenRandom(NULL, out, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
            abort();
        out += n;
        len -= n;
    }
}
#else
#include <errno.h>
#include <sys/random.h>
void randombytes(uint8_t *out, size_t len) {
    while (len) {
        ssize_t n = getrandom(out, len, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) abort();
        out += (size_t)n;
        len -= (size_t)n;
    }
}
#endif
***/
