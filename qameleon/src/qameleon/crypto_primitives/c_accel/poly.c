/* Kyber polynomial operations */
#include <stdint.h>
#include <string.h>

#define KYBER_Q 3329
#define KYBER_N 256

void poly_add_c(int32_t *a, const int32_t *b, int n) {
    for (int i = 0; i < n; i++)
        a[i] = (a[i] + b[i]) % KYBER_Q;
}

void poly_sub_c(int32_t *a, const int32_t *b, int n) {
    for (int i = 0; i < n; i++)
        a[i] = ((a[i] - b[i]) % KYBER_Q + KYBER_Q) % KYBER_Q;
}

void poly_compress_c(int32_t *a, uint8_t *out, int n, int d) {
    for (int i = 0; i < n; i++) {
        int32_t t = ((a[i] * (1 << d) + KYBER_Q / 2) / KYBER_Q) % (1 << d);
        out[i] = (uint8_t)(t & 0xFF);
    }
}

void poly_decompress_c(const uint8_t *in, int32_t *out, int n, int d) {
    for (int i = 0; i < n; i++) {
        out[i] = (in[i] * KYBER_Q + (1 << (d - 1))) >> d;
    }
}

void poly_cbd_c(const uint8_t *buf, int32_t *out, int n, int eta) {
    int bit_offset = 0;
    for (int i = 0; i < n; i++) {
        int a = 0, b = 0;
        for (int j = 0; j < eta; j++) {
            int byte_idx = (bit_offset + j) / 8;
            int bit_in_byte = (bit_offset + j) % 8;
            a += (buf[byte_idx] >> bit_in_byte) & 1;
        }
        for (int j = 0; j < eta; j++) {
            int byte_idx = (bit_offset + eta + j) / 8;
            int bit_in_byte = (bit_offset + eta + j) % 8;
            b += (buf[byte_idx] >> bit_in_byte) & 1;
        }
        out[i] = ((a - b) % KYBER_Q + KYBER_Q) % KYBER_Q;
        bit_offset += 2 * eta;
    }
}

void poly_to_bytes_c(const int32_t *a, uint8_t *out, int n) {
    for (int i = 0; i < n / 2; i++) {
        int32_t t0 = a[2*i] % KYBER_Q;
        int32_t t1 = a[2*i+1] % KYBER_Q;
        out[3*i]   = (uint8_t)(t0);
        out[3*i+1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        out[3*i+2] = (uint8_t)(t1 >> 4);
    }
}

void poly_from_bytes_c(const uint8_t *in, int32_t *out, int n) {
    for (int i = 0; i < n / 2; i++) {
        out[2*i]   = in[3*i] | ((in[3*i+1] & 0x0F) << 8);
        out[2*i+1] = (in[3*i+1] >> 4) | (in[3*i+2] << 4);
        out[2*i]   %= KYBER_Q;
        out[2*i+1] %= KYBER_Q;
    }
}
