#ifdef UXNA_TEST

/* Tx::computeOpTxHash against the neurai-sign-transaction reference.
 *
 * Vectors generated with the library's exact computeOpTxHash/contributionFor
 * helpers over a fixed 2-input / 2-output tx (non-symmetric prevout hashes so a
 * txid byte-order bug would be caught). The C++ port must reproduce them. */

#include <string.h>
#include "minunit.h"
#include "Neurai.h"
#include "Conversion.h"

using std::string;

static const char RAW_TX_HEX[] =
    "0200000002"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" "07000000" "00" "feffffff"
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" "01000000" "00" "ffffffff"
    "02"
    "e803000000000000" "1976a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac"
    "80b2e60e00000000" "225120bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    "00000000";

struct Vec { uint8_t selector; uint8_t inIndex; const char* opTxHash; };

/* selector bits: 0x01 ver, 0x02 locktime, 0x04 prevouts, 0x08 seqs,
 * 0x10 outputs, 0x20 cur-prevout, 0x40 cur-seq, 0x80 cur-index. */
static const Vec VECS[] = {
    { 0xff, 0, "eef6094fd6f561b88fc74c4a3e2f54586f4b7be3507798fee3d6beaa02901343" },
    { 0xff, 1, "748834e3ebc02cc56f48cf185474ea4a7a554d8e8ce872a8ecffd29f05c9e203" },
    { 0x14, 0, "42111c4020076c5b60a7d43dbc231a8dba88ea3aa55b278ee278a83e89f4de5c" }, /* prevouts+outputs */
    { 0xb6, 0, "2f0977a154a7da040fef547cbb508c2902d02338698a258af2a3dad89a63200b" }, /* mixed */
};

MU_TEST(test_optxhash_matches_oracle){
    uint8_t txBytes[256];
    size_t txLen = fromHex(RAW_TX_HEX, sizeof(RAW_TX_HEX) - 1, txBytes, sizeof(txBytes));
    mu_check(txLen > 0);

    Tx tx;
    size_t consumed = tx.parse(txBytes, txLen);
    mu_check(consumed > 0);
    mu_assert_int_eq(2, (int)tx.inputsNumber);
    mu_assert_int_eq(2, (int)tx.outputsNumber);

    for(size_t k = 0; k < sizeof(VECS) / sizeof(VECS[0]); k++){
        uint8_t out[32] = {0};
        int n = tx.computeOpTxHash(VECS[k].selector, VECS[k].inIndex, out);
        mu_assert_int_eq(32, n);
        string got = toHex(out, 32);
        mu_assert_string_eq(VECS[k].opTxHash, got.c_str());
    }
}

MU_TEST(test_optxhash_selector_changes_digest){
    uint8_t txBytes[256];
    size_t txLen = fromHex(RAW_TX_HEX, sizeof(RAW_TX_HEX) - 1, txBytes, sizeof(txBytes));
    Tx tx;
    tx.parse(txBytes, txLen);

    uint8_t a[32], b[32];
    tx.computeOpTxHash(0xff, 0, a);
    tx.computeOpTxHash(0xff, 1, b); /* only current input differs */
    mu_check(memcmp(a, b, 32) != 0);
}

MU_TEST_SUITE(test_suite){
    MU_RUN_TEST(test_optxhash_matches_oracle);
    MU_RUN_TEST(test_optxhash_selector_changes_digest);
}

int main(int argc, char *argv[]){
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif
