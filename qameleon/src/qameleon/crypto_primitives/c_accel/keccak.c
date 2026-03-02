/* Keccak-f[1600] with SHA3-256, SHA3-512, and SHAKE-256 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const int RHO[24] = {
    1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
    25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
};

static const int PI[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static void keccak_f(uint64_t *st) {
    uint64_t bc[5], t;
    for (int round = 0; round < 24; round++) {
        /* Theta */
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i+4)%5] ^ ROTL64(bc[(i+1)%5], 1);
            for (int j = 0; j < 25; j += 5) st[j+i] ^= t;
        }
        /* Rho and Pi */
        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = PI[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, RHO[i]);
            t = bc[0];
        }
        /* Chi */
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) bc[i] = st[j+i];
            for (int i = 0; i < 5; i++) st[j+i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5];
        }
        /* Iota */
        st[0] ^= RC[round];
    }
}

static void keccak_absorb(uint64_t *st, const uint8_t *in, size_t inlen,
                           size_t rate, uint8_t pad) {
    memset(st, 0, 200);
    while (inlen >= rate) {
        for (size_t i = 0; i < rate / 8; i++)
            st[i] ^= ((uint64_t *)in)[i];
        keccak_f(st);
        in += rate; inlen -= rate;
    }
    uint8_t tmp[200] = {0};
    memcpy(tmp, in, inlen);
    tmp[inlen] = pad;
    tmp[rate - 1] |= 0x80;
    for (size_t i = 0; i < rate / 8; i++)
        st[i] ^= ((uint64_t *)tmp)[i];
    keccak_f(st);
}

void sha3_256_c(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint64_t st[25];
    keccak_absorb(st, in, inlen, 136, 0x06);
    memcpy(out, st, 32);
}

void sha3_512_c(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint64_t st[25];
    keccak_absorb(st, in, inlen, 72, 0x06);
    memcpy(out, st, 64);
}

void shake256_c(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    uint64_t st[25];
    keccak_absorb(st, in, inlen, 136, 0x1F);
    size_t written = 0;
    while (written < outlen) {
        size_t n = outlen - written;
        if (n > 136) n = 136;
        memcpy(out + written, st, n);
        written += n;
        if (written < outlen) keccak_f(st);
    }
}
