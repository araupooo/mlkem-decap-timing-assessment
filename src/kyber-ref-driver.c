// Driver for the pq-crystals Kyber768 reference implementation (round-3 Kyber,
// pre-FIPS 203 lineage reference). Commands on stdin, one per line:
//   keygen            -> PK <hex 1184> SK <hex 2400>
//   enc <hex pk>      -> CT <hex 1088> SS <hex 32>
//   dec <hex sk> <hex ct> -> SS <hex 32> | ERR <message>
// Lengths are validated in this driver before any library call; a wrong-length
// ciphertext or key is rejected here and never passed to the fixed-size C API.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "api.h"

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int unhex(const char *s, uint8_t *out, size_t want) {
    if (strlen(s) != want * 2) return -1;
    for (size_t i = 0; i < want; i++) {
        int hi = hexval((unsigned char)s[2*i]);
        int lo = hexval((unsigned char)s[2*i+1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void puthex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

int main(void) {
    char line[16384];
    printf("READY kyber-ref pq-crystals/kyber Kyber768 (round-3, pre-FIPS-203)\n");
    fflush(stdout);
    while (fgets(line, sizeof(line), stdin)) {
        char cmd[32] = {0};
        char a[8192] = {0}, b[8192] = {0};
        int n = sscanf(line, "%31s %8191s %8191s", cmd, a, b);
        if (n < 1) continue;
        if (strcmp(cmd, "keygen") == 0) {
            uint8_t pk[pqcrystals_kyber768_PUBLICKEYBYTES];
            uint8_t sk[pqcrystals_kyber768_SECRETKEYBYTES];
            if (pqcrystals_kyber768_ref_keypair(pk, sk) != 0) {
                printf("ERR keygen failed\n");
            } else {
                printf("PK "); puthex(pk, sizeof(pk));
                printf(" SK "); puthex(sk, sizeof(sk));
                printf("\n");
            }
        } else if (strcmp(cmd, "enc") == 0 && n >= 2) {
            uint8_t pk[pqcrystals_kyber768_PUBLICKEYBYTES];
            uint8_t ct[pqcrystals_kyber768_CIPHERTEXTBYTES];
            uint8_t ss[pqcrystals_kyber768_BYTES];
            if (unhex(a, pk, sizeof(pk)) != 0) {
                printf("ERR bad pk: need %d bytes hex\n", pqcrystals_kyber768_PUBLICKEYBYTES);
            } else if (pqcrystals_kyber768_ref_enc(ct, ss, pk) != 0) {
                printf("ERR enc failed\n");
            } else {
                printf("CT "); puthex(ct, sizeof(ct));
                printf(" SS "); puthex(ss, sizeof(ss));
                printf("\n");
            }
        } else if (strcmp(cmd, "dec") == 0 && n >= 3) {
            uint8_t sk[pqcrystals_kyber768_SECRETKEYBYTES];
            uint8_t ct[pqcrystals_kyber768_CIPHERTEXTBYTES];
            uint8_t ss[pqcrystals_kyber768_BYTES];
            if (unhex(a, sk, sizeof(sk)) != 0) {
                printf("ERR bad sk: need %d bytes hex\n", pqcrystals_kyber768_SECRETKEYBYTES);
            } else if (unhex(b, ct, sizeof(ct)) != 0) {
                printf("ERR bad ct: need %d bytes hex\n", pqcrystals_kyber768_CIPHERTEXTBYTES);
            } else if (pqcrystals_kyber768_ref_dec(ss, ct, sk) != 0) {
                printf("ERR dec failed\n");
            } else {
                printf("SS "); puthex(ss, sizeof(ss));
                printf("\n");
            }
        } else if (strcmp(cmd, "timedecap") == 0 && n >= 3) {
            /* timedecap <sk hex> <ct hex> <n> -> TIMED <total_ns> <n>.
               Loops n decapsulations inside the process so the measurement
               excludes stdin/stdout pipe overhead. Note: the initial sscanf
               reads only 3 tokens, so the count is re-parsed below. */
            uint8_t sk[pqcrystals_kyber768_SECRETKEYBYTES];
            uint8_t ct[pqcrystals_kyber768_CIPHERTEXTBYTES];
            uint8_t ss[pqcrystals_kyber768_BYTES];
            long reps = 0;
            /* The initial sscanf reads only 3 tokens; re-parse the full line
               for the 4th token (the repetition count). */
            char *save = NULL;
            char *tok = strtok_r(line, " \t\r\n", &save); /* cmd */
            tok = strtok_r(NULL, " \t\r\n", &save);        /* sk */
            char skhex[8192]; snprintf(skhex, sizeof(skhex), "%s", tok ? tok : "");
            tok = strtok_r(NULL, " \t\r\n", &save);        /* ct */
            char cthex[8192]; snprintf(cthex, sizeof(cthex), "%s", tok ? tok : "");
            tok = strtok_r(NULL, " \t\r\n", &save);        /* n */
            reps = tok ? atol(tok) : 0;
            if (reps <= 0) {
                printf("ERR bad n\n");
            } else if (unhex(skhex, sk, sizeof(sk)) != 0) {
                printf("ERR bad sk: need %d bytes hex\n", pqcrystals_kyber768_SECRETKEYBYTES);
            } else if (unhex(cthex, ct, sizeof(ct)) != 0) {
                printf("ERR bad ct: need %d bytes hex\n", pqcrystals_kyber768_CIPHERTEXTBYTES);
            } else {
                struct timespec t0, t1;
                clock_gettime(CLOCK_MONOTONIC, &t0);
                for (long i = 0; i < reps; i++) {
                    if (pqcrystals_kyber768_ref_dec(ss, ct, sk) != 0) {
                        printf("ERR dec failed\n");
                        break;
                    }
                }
                clock_gettime(CLOCK_MONOTONIC, &t1);
                long long ns = (long long)(t1.tv_sec - t0.tv_sec) * 1000000000LL
                             + (t1.tv_nsec - t0.tv_nsec);
                printf("TIMED %lld %ld\n", ns, reps);
            }
        } else {
            printf("ERR unknown command\n");
        }
        fflush(stdout);
    }
    return 0;
}
