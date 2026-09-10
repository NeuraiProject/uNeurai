#ifdef UXNA_TEST // only compile with test flag

/* Regression: parsing a compressed public key whose x is not on the curve
 * must fail deterministically. ECPoint::from_stream() used to ignore the
 * result of ecdsa_uncompress_pubkey() and keep whatever the stack held in
 * the scratch buffer — which could be the previously parsed (valid) point,
 * so an off-curve key "became" a different valid key depending on history. */

#include <string.h>
#include "minunit.h"
#include "Neurai.h"
#include "Conversion.h"

static const char GENERATOR[] = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

static void keyFromHex(const char * hex, uint8_t out[33]) { fromHex(hex, out, 33); }

MU_TEST(test_off_curve_after_valid_parse) {
    uint8_t good[33], zeroX[33], fiveX[33];
    keyFromHex(GENERATOR, good);
    memset(zeroX, 0x00, 33); zeroX[0] = 0x02;      /* x = 0: 7 is a non-residue mod p */
    memset(fiveX, 0x05, 33); fiveX[0] = 0x02;      /* x = 0x0505..05: not on the curve */

    PublicKey g(good);
    mu_assert(g.isValid(), "generator parses as valid");

    /* the very next parse used to inherit G's coordinates from the stack */
    PublicKey z(zeroX);
    mu_assert(!z.isValid(), "x = 0 must be invalid right after a valid parse");
    mu_assert(!(z == g), "off-curve key must not silently become the previous point");
    uint8_t sec[65];
    memset(sec, 0xaa, sizeof(sec));
    z.sec(sec, 65);
    uint8_t zeros[64] = { 0 };
    mu_assert(memcmp(sec + 1, zeros, 64) == 0 || !z.isValid(), "invalid point carries no coordinates");

    PublicKey f(fiveX);
    mu_assert(!f.isValid(), "x = 0x05..05 invalid");
    mu_assert(!(f == g), "not the previous point either");

    /* interleaved: valid, invalid, valid, invalid */
    for (int i = 0; i < 4; i++) {
        PublicKey a(good);
        mu_assert(a.isValid() && a == g, "valid key still parses after failures");
        PublicKey b(i & 1 ? zeroX : fiveX);
        mu_assert(!b.isValid(), "invalid key stays invalid in a loop");
    }
}

MU_TEST(test_hex_constructor_off_curve) {
    PublicKey z("020000000000000000000000000000000000000000000000000000000000000000");
    mu_assert(!z.isValid(), "hex constructor: x = 0 invalid");
    PublicKey g(GENERATOR);
    mu_assert(g.isValid(), "hex constructor: generator valid");
    PublicKey z2("020000000000000000000000000000000000000000000000000000000000000000");
    mu_assert(!z2.isValid() && !(z2 == g), "hex constructor: still invalid after a valid parse");
}

MU_TEST_SUITE(test_pubkey_parse) {
    MU_RUN_TEST(test_off_curve_after_valid_parse);
    MU_RUN_TEST(test_hex_constructor_off_curve);
}

int main(int argc, char *argv[]) {
    MU_RUN_SUITE(test_pubkey_parse);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif // UXNA_TEST
