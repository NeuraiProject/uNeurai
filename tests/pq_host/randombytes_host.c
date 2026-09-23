/* Host replacement for the ESP32 TRNG that mldsa-esp32 uses (its randombytes.c
 * includes esp_random.h). Only compiled when the tests are built with
 * MLDSA_DIR=... (see Makefile). */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

int randombytes(uint8_t *out, size_t outlen){
    FILE *f = fopen("/dev/urandom", "rb");
    if(f == NULL){
        return -1;
    }
    size_t n = fread(out, 1, outlen, f);
    fclose(f);
    return n == outlen ? 0 : -1;
}
