/* Kyber NTT (q=3329) with Barrett reduction */
#include <stdint.h>
#include <string.h>

#define KYBER_Q 3329
#define KYBER_N 256

static const int32_t KYBER_ZETAS[128] = {
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
};

static int32_t barrett_reduce(int32_t a) {
    int32_t t = ((int64_t)a * 20159) >> 26;
    return a - t * KYBER_Q;
}

static int32_t fqmul(int32_t a, int32_t b) {
    return barrett_reduce((int32_t)((int64_t)a * b));
}

void kyber_ntt_c(int32_t *a, int n) {
    int k = 1, len = 128;
    while (len >= 2) {
        for (int start = 0; start < n; start += 2 * len) {
            int32_t zeta = KYBER_ZETAS[k++];
            for (int j = start; j < start + len; j++) {
                int32_t t = fqmul(zeta, a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
        len >>= 1;
    }
    for (int i = 0; i < n; i++) {
        a[i] = barrett_reduce(a[i]);
    }
}

void kyber_ntt_inv_c(int32_t *a, int n) {
    int k = 127, len = 2;
    while (len <= 128) {
        for (int start = 0; start < n; start += 2 * len) {
            int32_t zeta = KYBER_ZETAS[k--];
            for (int j = start; j < start + len; j++) {
                int32_t t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = fqmul(zeta, a[j + len] - t);
            }
        }
        len <<= 1;
    }
    /* Multiply by n^{-1} = 3303 mod q */
    for (int i = 0; i < n; i++) {
        a[i] = fqmul(a[i], 3303);
    }
}

void kyber_pointwise_mul_c(int32_t *a, const int32_t *b, int n) {
    for (int i = 0; i < n; i++) {
        a[i] = fqmul(a[i], b[i]);
    }
}
