#ifdef UXNA_TEST

/* Tx::sigHashAuthScript against the JS oracle (vectors.json). */

#include <string.h>
#include "minunit.h"
#include "Neurai.h"
#include "Conversion.h"

using std::string;

/* From tmp/oracle/vectors.json -> sighash_authscript_v1 */
static const char RAW_TX_HEX[] =
    "020000000111111111111111111111111111111111111111111111111111111111"
    "1111111100000000" "00" /* empty scriptSig (varint=0) */
    "fdffffff" /* sequence */
    "01" /* outputs count */
    "f0b9f50500000000" /* 99_990_000 sat little-endian */
    "1976a914abababababababababababababababababababab88ac"
    "00000000";

static const char EXPECTED_HASH_HEX[] =
    "5072b85972bb57bd5a9b4a3728121cc8b8e3dee8db647ae9b3a5bf2efdd6b968";

MU_TEST(test_sighash_authscript_matches_oracle){
    /* Parse the raw tx. */
    uint8_t txBytes[200];
    size_t txLen = fromHex(RAW_TX_HEX, sizeof(RAW_TX_HEX) - 1, txBytes, sizeof(txBytes));
    mu_check(txLen > 0);

    Tx tx;
    size_t consumed = tx.parse(txBytes, txLen);
    mu_check(consumed > 0);
    mu_assert_int_eq(2, (int)tx.version);
    mu_assert_int_eq(1, (int)tx.inputsNumber);
    mu_assert_int_eq(1, (int)tx.outputsNumber);

    /* witnessScript = OP_TRUE (single byte 0x51). */
    const uint8_t opTrue[1] = { 0x51 };
    Script witnessScript(opTrue, sizeof(opTrue));

    uint8_t h[32] = {0};
    int n = tx.sigHashAuthScript(h, 0, witnessScript,
                                 /* amount */ 100000000ULL,
                                 /* authType */ 0x01,
                                 SIGHASH_ALL);
    mu_assert_int_eq(32, n);

    string got = toHex(h, 32);
    mu_assert_string_eq(EXPECTED_HASH_HEX, got.c_str());
}

MU_TEST(test_sighash_authscript_differs_from_segwit){
    /* Sanity: the segwit BIP-143 sighash must NOT match the AuthScript one
     * (proving the authType byte actually entered the preimage). */
    uint8_t txBytes[200];
    size_t txLen = fromHex(RAW_TX_HEX, sizeof(RAW_TX_HEX) - 1, txBytes, sizeof(txBytes));
    Tx tx;
    tx.parse(txBytes, txLen);

    const uint8_t opTrue[1] = { 0x51 };
    Script witnessScript(opTrue, sizeof(opTrue));

    uint8_t hAuth[32], hSegwit[32];
    tx.sigHashAuthScript(hAuth, 0, witnessScript, 100000000ULL, 0x01, SIGHASH_ALL);
    tx.sigHashSegwit(hSegwit, 0, witnessScript, 100000000ULL, SIGHASH_ALL);
    mu_check(memcmp(hAuth, hSegwit, 32) != 0);
}

MU_TEST_SUITE(test_suite){
    MU_RUN_TEST(test_sighash_authscript_matches_oracle);
    MU_RUN_TEST(test_sighash_authscript_differs_from_segwit);
}

int main(int argc, char *argv[]){
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif
