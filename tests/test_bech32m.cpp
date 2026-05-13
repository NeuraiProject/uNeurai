#ifdef UXNA_TEST

#include <string.h>
#include "minunit.h"
#include "utility/segwit_addr.h"

/* ----------------------------- helpers ----------------------------- */

static int decode_with_hrp(const char *expected_hrp, const char *addr,
                           int *witver_out, uint8_t *prog_out, size_t *prog_len_out){
    return segwit_addr_decode(witver_out, prog_out, prog_len_out, expected_hrp, addr);
}

/* ----------------------------- BIP-173 v0 (should still work) ----------------------------- */

MU_TEST(test_segwit_v0_bech32_roundtrip){
    /* P2WPKH from BIP-173 test vectors. */
    const char *hrp = "bc";
    uint8_t prog[20] = {
        0x75,0x1e,0x76,0xe8,0x19,0x91,0x96,0xd4,0x54,0x94,
        0x1c,0x45,0xd1,0xb3,0xa3,0x23,0xf1,0x43,0x3b,0xd6
    };
    char addr[100] = {0};
    mu_check(segwit_addr_encode(addr, hrp, 0, prog, sizeof(prog)) == 1);
    mu_check(strcmp(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == 0);

    int witver = -1;
    uint8_t got[40] = {0};
    size_t got_len = 0;
    mu_check(decode_with_hrp(hrp, addr, &witver, got, &got_len) == 1);
    mu_assert_int_eq(0, witver);
    mu_assert_int_eq(20, (int)got_len);
    mu_check(memcmp(prog, got, 20) == 0);
}

/* ----------------------------- BIP-350 v1 (new) ----------------------------- */

MU_TEST(test_segwit_v1_bech32m_roundtrip){
    /* P2TR from BIP-350 example: tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c
       Here we encode an arbitrary 32-byte program and decode it back. */
    const char *hrp = "tb";
    uint8_t prog[32];
    for (int i = 0; i < 32; i++) prog[i] = (uint8_t)(0x42 + i);

    char addr[100] = {0};
    mu_check(segwit_addr_encode(addr, hrp, 1, prog, sizeof(prog)) == 1);
    /* Must start with hrp + "1p" (witver 1 -> 'p' in bech32 charset is index 1). */
    mu_check(strncmp(addr, "tb1p", 4) == 0);

    int witver = -1;
    uint8_t got[40] = {0};
    size_t got_len = 0;
    mu_check(decode_with_hrp(hrp, addr, &witver, got, &got_len) == 1);
    mu_assert_int_eq(1, witver);
    mu_assert_int_eq(32, (int)got_len);
    mu_check(memcmp(prog, got, 32) == 0);
}

MU_TEST(test_segwit_v1_known_bip350_vector){
    /* Official BIP-350 vector. */
    const char *addr = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y";
    int witver = -1;
    uint8_t got[40] = {0};
    size_t got_len = 0;
    mu_check(decode_with_hrp("bc", addr, &witver, got, &got_len) == 1);
    mu_assert_int_eq(1, witver);
    mu_assert_int_eq(40, (int)got_len);
}

/* ----------------------------- cross-variant rejection ----------------------------- */

MU_TEST(test_reject_v0_with_bech32m_checksum){
    /* Build a v0 program but force bech32m checksum -> segwit_addr_decode must reject. */
    const char *hrp = "bc";
    uint8_t prog[20] = {0};
    uint8_t data[1 + 33] = {0};   /* witver byte + 32 5-bit chars max for 20B prog */
    size_t datalen = 0;
    data[0] = 0;
    mu_check(convert_bits(data + 1, &datalen, 5, prog, sizeof(prog), 8, 1) == 1);
    datalen += 1;

    char addr[100] = {0};
    /* Force BECH32M on a v0 program. */
    mu_check(bech32_encode_variant(addr, hrp, data, datalen, BECH32M) == 1);

    int witver = -1;
    uint8_t got[40] = {0};
    size_t got_len = 0;
    mu_check(segwit_addr_decode(&witver, got, &got_len, hrp, addr) == 0);
}

MU_TEST(test_reject_v1_with_bech32_checksum){
    /* v1 program but classic bech32 checksum -> must reject. */
    const char *hrp = "bc";
    uint8_t prog[32] = {0};
    for (int i = 0; i < 32; i++) prog[i] = (uint8_t)i;
    uint8_t data[1 + 65] = {0};
    size_t datalen = 0;
    data[0] = 1;
    mu_check(convert_bits(data + 1, &datalen, 5, prog, sizeof(prog), 8, 1) == 1);
    datalen += 1;

    char addr[100] = {0};
    mu_check(bech32_encode_variant(addr, hrp, data, datalen, BECH32) == 1);

    int witver = -1;
    uint8_t got[40] = {0};
    size_t got_len = 0;
    mu_check(segwit_addr_decode(&witver, got, &got_len, hrp, addr) == 0);
}

MU_TEST(test_variant_decode_reports_kind){
    /* bech32_decode_variant should report which checksum matched. */
    const char *hrp = "bc";
    uint8_t prog[32] = {0};
    uint8_t data[1 + 65] = {0};
    size_t datalen = 0;
    data[0] = 1;
    mu_check(convert_bits(data + 1, &datalen, 5, prog, sizeof(prog), 8, 1) == 1);
    datalen += 1;

    char addr_m[100] = {0};
    char addr_c[100] = {0};
    mu_check(bech32_encode_variant(addr_m, hrp, data, datalen, BECH32M) == 1);
    mu_check(bech32_encode_variant(addr_c, hrp, data, datalen, BECH32) == 1);

    char hrp_out[100] = {0};
    uint8_t data_out[100] = {0};
    size_t data_out_len = 0;
    enum bech32_variant v = (enum bech32_variant)0;

    mu_check(bech32_decode_variant(hrp_out, data_out, &data_out_len, addr_m, &v) == 1);
    mu_check(v == BECH32M);

    mu_check(bech32_decode_variant(hrp_out, data_out, &data_out_len, addr_c, &v) == 1);
    mu_check(v == BECH32);
}

MU_TEST(test_legacy_bech32_decode_rejects_bech32m){
    /* The legacy strict bech32_decode (no variant out) must still reject bech32m
       so existing callers keep their BIP-173 semantics. */
    const char *hrp = "bc";
    uint8_t prog[32] = {0};
    uint8_t data[1 + 65] = {0};
    size_t datalen = 0;
    data[0] = 1;
    mu_check(convert_bits(data + 1, &datalen, 5, prog, sizeof(prog), 8, 1) == 1);
    datalen += 1;

    char addr_m[100] = {0};
    mu_check(bech32_encode_variant(addr_m, hrp, data, datalen, BECH32M) == 1);

    char hrp_out[100] = {0};
    uint8_t data_out[100] = {0};
    size_t data_out_len = 0;
    mu_check(bech32_decode(hrp_out, data_out, &data_out_len, addr_m) == 0);
}

MU_TEST_SUITE(test_suite){
    MU_RUN_TEST(test_segwit_v0_bech32_roundtrip);
    MU_RUN_TEST(test_segwit_v1_bech32m_roundtrip);
    MU_RUN_TEST(test_segwit_v1_known_bip350_vector);
    MU_RUN_TEST(test_reject_v0_with_bech32m_checksum);
    MU_RUN_TEST(test_reject_v1_with_bech32_checksum);
    MU_RUN_TEST(test_variant_decode_reports_kind);
    MU_RUN_TEST(test_legacy_bech32_decode_rejects_bech32m);
}

int main(int argc, char *argv[]){
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif
