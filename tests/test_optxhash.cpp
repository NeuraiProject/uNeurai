#ifdef UXNA_TEST

/* NIP-042 tagged OP_TXHASH vectors over a fixed two-input, two-output tx.
 * Non-symmetric prevouts catch byte-order errors. */

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

struct Vec { uint16_t selector; uint8_t inIndex; const char* opTxHash; };

/* selector bits: 0x01 ver, 0x02 locktime, 0x04 prevouts, 0x08 seqs,
 * 0x10 outputs, 0x20 cur-prevout, 0x40 cur-seq, 0x80 cur-index. */
static const Vec VECS[] = {
    { 0xff, 0, "d0c5af47ae557e7db9878285b60e2ebd32d927e4a5a57717b20fbdca9152477f" },
    { 0xff, 1, "1d480819fffac23d97267a97e466999f51e1104b7e9b046ac1459a47e909564d" },
    { 0x14, 0, "b2ec8ac862dd2337ad5d527ae4992e492ba5c24880ac4420db97c00f25d13851" },
    { 0xb6, 0, "2b2d29fe03ceb18c526ddf3f0758dd0a2c8b245e5103b1108601dfebc462e824" },
    { 0x1ff, 0, "a2e385830de2b580072b164675333992b32211b7fd0ca7eca5e14fb6a41682f0" },
    { 0x100, 0, "308542cb639a0e6ac414070f3be7c7e13827c7dde337c4d1202853376519fab1" },
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

MU_TEST(test_optxhash_rejects_reserved_masks){
    uint8_t txBytes[256];
    size_t txLen = fromHex(RAW_TX_HEX, sizeof(RAW_TX_HEX) - 1, txBytes, sizeof(txBytes));
    Tx tx;
    mu_check(tx.parse(txBytes, txLen) > 0);
    uint8_t digest[32];
    mu_assert_int_eq(0, tx.computeOpTxHash(0, 0, digest));
    mu_assert_int_eq(0, tx.computeOpTxHash(0x200, 0, digest));
}

MU_TEST_SUITE(test_suite){
    MU_RUN_TEST(test_optxhash_matches_oracle);
    MU_RUN_TEST(test_optxhash_selector_changes_digest);
    MU_RUN_TEST(test_optxhash_rejects_reserved_masks);
}

int main(int argc, char *argv[]){
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif
