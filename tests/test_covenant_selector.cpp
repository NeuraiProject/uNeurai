#ifdef UXNA_TEST

/* parseCovenantPQTxHashSelector: locate the OP_TXHASH selector embedded in a
 * PQ partial-fill covenant cancel branch. */

#include <string.h>
#include "minunit.h"
#include "NeuraiPQ.h"

/* Build the fixed cancel-branch prefix and append the selector push. */
static size_t buildBranch(uint8_t *out, const uint8_t *pushBytes, size_t pushLen){
    size_t p = 0;
    out[p++] = 0x63; out[p++] = 0x76; out[p++] = 0xa8; out[p++] = 0x20;
    memset(out + p, 0xcc, 32); p += 32;       /* pubKeyCommitment placeholder */
    out[p++] = 0x88;                          /* OP_EQUALVERIFY */
    memcpy(out + p, pushBytes, pushLen); p += pushLen;
    out[p++] = 0xb5;                          /* OP_TXHASH */
    return p;
}

MU_TEST(test_selector_2byte_push_all){
    uint8_t script[80];
    const uint8_t push[3] = { 0x02, 0xff, 0x01 };
    size_t n = buildBranch(script, push, sizeof(push));
    uint16_t sel = 0;
    mu_assert_int_eq(1, parseCovenantPQTxHashSelector(script, n, &sel));
    mu_assert_int_eq(0x1ff, (int)sel);
}

MU_TEST(test_selector_rejects_legacy_push){
    uint8_t script[80];
    const uint8_t push[2] = { 0x01, 0xff };
    size_t n = buildBranch(script, push, sizeof(push));
    uint16_t sel = 0;
    mu_assert_int_eq(0, parseCovenantPQTxHashSelector(script, n, &sel));
}

MU_TEST(test_selector_rejects_bad_prefix){
    uint8_t script[80];
    const uint8_t push[3] = { 0x02, 0x01, 0x00 };
    size_t n = buildBranch(script, push, sizeof(push));
    script[2] = 0x00;
    uint16_t sel = 0;
    mu_assert_int_eq(0, parseCovenantPQTxHashSelector(script, n, &sel));
}

MU_TEST(test_selector_rejects_zero_and_reserved_bits){
    uint8_t script[80];
    uint8_t push[3] = { 0x02, 0x00, 0x00 };
    size_t n = buildBranch(script, push, sizeof(push));
    uint16_t sel = 0;
    mu_assert_int_eq(0, parseCovenantPQTxHashSelector(script, n, &sel));
    push[2] = 0x02;
    n = buildBranch(script, push, sizeof(push));
    mu_assert_int_eq(0, parseCovenantPQTxHashSelector(script, n, &sel));
}

MU_TEST_SUITE(test_suite){
    MU_RUN_TEST(test_selector_2byte_push_all);
    MU_RUN_TEST(test_selector_rejects_legacy_push);
    MU_RUN_TEST(test_selector_rejects_bad_prefix);
    MU_RUN_TEST(test_selector_rejects_zero_and_reserved_bits);
}

int main(int argc, char *argv[]){
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif
