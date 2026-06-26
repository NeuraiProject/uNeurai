#ifdef UXNA_TEST

/* parseCovenantPQTxHashSelector: locate the OP_TXHASH selector embedded in a
 * PQ partial-fill covenant cancel branch. */

#include <string.h>
#include "minunit.h"
#include "NeuraiPQ.h"

/* Build the fixed cancel-branch prefix: OP_IF OP_DUP OP_SHA256 push32 <32>
 * OP_EQUALVERIFY, then append `pushBytes` (the selector push) + OP_TXHASH(0xbb). */
static size_t buildBranch(uint8_t *out, const uint8_t *pushBytes, size_t pushLen){
    size_t p = 0;
    out[p++] = 0x63; out[p++] = 0x76; out[p++] = 0xa8; out[p++] = 0x20;
    memset(out + p, 0xcc, 32); p += 32;       /* pubKeyCommitment placeholder */
    out[p++] = 0x88;                          /* OP_EQUALVERIFY */
    memcpy(out + p, pushBytes, pushLen); p += pushLen;
    out[p++] = 0xbb;                          /* OP_TXHASH (placeholder body) */
    return p;
}

MU_TEST(test_selector_1byte_push_ff){
    uint8_t script[80];
    const uint8_t push[2] = { 0x01, 0xff };   /* push 1 byte = 0xff */
    size_t n = buildBranch(script, push, sizeof(push));
    uint8_t sel = 0;
    mu_assert_int_eq(1, parseCovenantPQTxHashSelector(script, n, &sel));
    mu_assert_int_eq(0xff, (int)sel);
}

MU_TEST(test_selector_op16){
    uint8_t script[80];
    const uint8_t push[1] = { 0x60 };         /* OP_16 -> 16 */
    size_t n = buildBranch(script, push, sizeof(push));
    uint8_t sel = 0;
    mu_assert_int_eq(1, parseCovenantPQTxHashSelector(script, n, &sel));
    mu_assert_int_eq(16, (int)sel);
}

MU_TEST(test_selector_rejects_bad_prefix){
    uint8_t script[80];
    const uint8_t push[2] = { 0x01, 0xff };
    size_t n = buildBranch(script, push, sizeof(push));
    script[2] = 0x00;                         /* corrupt OP_SHA256 */
    uint8_t sel = 0;
    mu_assert_int_eq(0, parseCovenantPQTxHashSelector(script, n, &sel));
}

MU_TEST(test_selector_rejects_zero){
    uint8_t script[80];
    const uint8_t push[2] = { 0x01, 0x00 };   /* push selector 0 (invalid) */
    size_t n = buildBranch(script, push, sizeof(push));
    uint8_t sel = 0;
    mu_assert_int_eq(0, parseCovenantPQTxHashSelector(script, n, &sel));
}

MU_TEST_SUITE(test_suite){
    MU_RUN_TEST(test_selector_1byte_push_ff);
    MU_RUN_TEST(test_selector_op16);
    MU_RUN_TEST(test_selector_rejects_bad_prefix);
    MU_RUN_TEST(test_selector_rejects_zero);
}

int main(int argc, char *argv[]){
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif
