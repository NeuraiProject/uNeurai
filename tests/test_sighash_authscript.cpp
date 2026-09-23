#ifdef UXNA_TEST

/* Tx::sigHashAuthScript against the JS oracle (vectors.json), and
 * Tx::sigHashAuthScriptStrict / Tx::signAuthScriptInputECDSA against spends a
 * Neurai-DePIN regtest node accepted (testmempoolaccept "allowed": 1). */

#include <string.h>
#include "minunit.h"
#include "Neurai.h"
#include "Conversion.h"
#include "NeuraiPQ.h"

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

/* ---------------------------- Node-accepted spends ---------------------------- */

/* Each unsigned tx spends one 10 XNA regtest output (vout 1) to the generic v1
 * address tnc1pvjuphw…, version 2, sequence 0xfffffffd, locktime 0. */
static const uint64_t PREVOUT_AMOUNT = 1000000000ULL;

/* v1 PQ prevout 51205ea4ce2f…e736 (tnc1pt6jvut…): signed with
 * signAuthScriptInputPQ over this sighash, accepted by the node. */
static const char V1_UNSIGNED_HEX[] =
    "020000000168d8640596934b5a2b3fc4d589e1f0cca25b7a753a5945b3ef2b9a4f961f2d1f"
    "0100000000fdffffff0100e9a4350000000022512064b81bba382146a740d567a1e64b2d55"
    "88b2d75490751793bf038219220c1f8800000000";
static const char V1_SIGHASH_HEX[] =
    "0a4210d5c4ea5e199def9abf488ed470902fab4aa2ca6315c2b2c0f4b332e368";

/* Strict PQ v2 prevout 5220568d93f9…413a (tpq1z26xe87…): signed with
 * signAuthScriptInputPQStrict over this sighash, accepted by the node. */
static const char V2_UNSIGNED_HEX[] =
    "02000000010f0c8895d014c86373b126151e1ee2157156dfed23f6e621552aae53890126d2"
    "0100000000fdffffff0100e9a4350000000022512064b81bba382146a740d567a1e64b2d55"
    "88b2d75490751793bf038219220c1f8800000000";
static const char V2_SIGHASH_HEX[] =
    "ff9baea5abcdb915b5fd51b6f1faafc471a984a316fab9e067584bc4278b8b4f";

/* Strict ECDSA v3 prevout 532085801315…0e88 (tnq1rskqpx…), key below. */
static const char V3_WIF[] = "cQD6aaT9qYrdPEGnek4F3RSwWmCpUTZGudhvyh46A55dqH6ikugC";
static const char V3_UNSIGNED_HEX[] =
    "0200000001f11a302a9c828262edf0cca282cf1048b4b5275d3aaaac4e21c3e5ec94ab3ad5"
    "0100000000fdffffff01c0878b3b0000000022512064b81bba382146a740d567a1e64b2d55"
    "88b2d75490751793bf038219220c1f8800000000";
static const char V3_SIGHASH_HEX[] =
    "a149e4ad75704c4572edaec817565d7a5c4025756ae2ab178510c26fa4dffabd";
/* signAuthScriptInputECDSA output (RFC 6979, deterministic), accepted by the
 * node as txid 86fb8ccb5b30a38320a4300268353c24acdc3409be92106e6f8f4a344b2e8e25. */
static const char V3_SIGNED_HEX[] =
    "02000000000101f11a302a9c828262edf0cca282cf1048b4b5275d3aaaac4e21c3e5ec94ab"
    "3ad50100000000fdffffff01c0878b3b0000000022512064b81bba382146a740d567a1e64b"
    "2d5588b2d75490751793bf038219220c1f8804010247304402204d9a28cccac75b7face742"
    "8f68d5f6f7d93e6d7b563c087fead0a8ed35ca59f80220657bd2fe24de44ea2eb9061fa17b"
    "38360a870681d3edb32af4de643b145720e0012103c686edd6a7df742a8bf13daf7d992c39"
    "ecc38ad2e503c67dc5c9177dc66db991015100000000";

static void parseTx(const char * hex, size_t hexLen, Tx & tx){
    uint8_t bytes[400];
    size_t n = fromHex(hex, hexLen, bytes, sizeof(bytes));
    mu_check(n > 0);
    mu_check(tx.parse(bytes, n) == n);
}

MU_TEST(test_sighash_v1_node_vector){
    Tx tx;
    parseTx(V1_UNSIGNED_HEX, sizeof(V1_UNSIGNED_HEX) - 1, tx);
    const uint8_t opTrue[1] = { 0x51 };
    uint8_t h[32];
    mu_assert_int_eq(32, tx.sigHashAuthScript(h, 0, Script(opTrue, 1), PREVOUT_AMOUNT, 0x01, SIGHASH_ALL));
    string got = toHex(h, 32);
    mu_assert_string_eq(V1_SIGHASH_HEX, got.c_str());
}

MU_TEST(test_sighash_strict_node_vectors){
    uint8_t h[32];
    Tx tx2;
    parseTx(V2_UNSIGNED_HEX, sizeof(V2_UNSIGNED_HEX) - 1, tx2);
    mu_assert_int_eq(32, tx2.sigHashAuthScriptStrict(h, 0, PREVOUT_AMOUNT, 2, SIGHASH_ALL));
    string got = toHex(h, 32);
    mu_assert_string_eq(V2_SIGHASH_HEX, got.c_str());

    Tx tx3;
    parseTx(V3_UNSIGNED_HEX, sizeof(V3_UNSIGNED_HEX) - 1, tx3);
    mu_assert_int_eq(32, tx3.sigHashAuthScriptStrict(h, 0, PREVOUT_AMOUNT, 3, SIGHASH_ALL));
    got = toHex(h, 32);
    mu_assert_string_eq(V3_SIGHASH_HEX, got.c_str());

    /* The strict preimage differs from the generic one with the same authType
     * (the witness version byte), so v1-style signatures never verify. */
    const uint8_t opTrue[1] = { 0x51 };
    uint8_t generic[32];
    tx3.sigHashAuthScript(generic, 0, Script(opTrue, 1), PREVOUT_AMOUNT, 0x02, SIGHASH_ALL);
    mu_check(memcmp(generic, h, 32) != 0);
}

MU_TEST(test_sighash_strict_rejects_bad_input){
    Tx tx;
    parseTx(V3_UNSIGNED_HEX, sizeof(V3_UNSIGNED_HEX) - 1, tx);
    uint8_t h[32];
    /* Only witness versions 2 and 3 are strict. */
    mu_assert_int_eq(0, tx.sigHashAuthScriptStrict(h, 0, PREVOUT_AMOUNT, 1, SIGHASH_ALL));
    mu_assert_int_eq(0, tx.sigHashAuthScriptStrict(h, 0, PREVOUT_AMOUNT, 4, SIGHASH_ALL));
    /* Out-of-range input. */
    mu_assert_int_eq(0, tx.sigHashAuthScriptStrict(h, 1, PREVOUT_AMOUNT, 3, SIGHASH_ALL));
    /* Version-3 transactions (NIP-014 reference inputs) are not supported. */
    tx.version = 3;
    mu_assert_int_eq(0, tx.sigHashAuthScriptStrict(h, 0, PREVOUT_AMOUNT, 3, SIGHASH_ALL));
    const uint8_t opTrue[1] = { 0x51 };
    mu_assert_int_eq(0, tx.sigHashAuthScript(h, 0, Script(opTrue, 1), PREVOUT_AMOUNT, 0x01, SIGHASH_ALL));
}

MU_TEST(test_sign_ecdsa_v3_matches_node_accepted_tx){
    Tx tx;
    parseTx(V3_UNSIGNED_HEX, sizeof(V3_UNSIGNED_HEX) - 1, tx);
    PrivateKey pk(V3_WIF);
    mu_assert_int_eq(1, tx.signAuthScriptInputECDSA(0, pk, PREVOUT_AMOUNT, SIGHASH_ALL));
    mu_assert_int_eq(4, tx.txIns[0].witness.count());
    mu_assert_int_eq(0, (int)tx.txIns[0].scriptSig.scriptLen);
    string got = tx.toString();
    mu_assert_string_eq(V3_SIGNED_HEX, got.c_str());

    /* Out-of-range input. */
    mu_assert_int_eq(0, tx.signAuthScriptInputECDSA(1, pk, PREVOUT_AMOUNT, SIGHASH_ALL));
}

MU_TEST_SUITE(test_suite){
    MU_RUN_TEST(test_sighash_authscript_matches_oracle);
    MU_RUN_TEST(test_sighash_authscript_differs_from_segwit);
    MU_RUN_TEST(test_sighash_v1_node_vector);
    MU_RUN_TEST(test_sighash_strict_node_vectors);
    MU_RUN_TEST(test_sighash_strict_rejects_bad_input);
    MU_RUN_TEST(test_sign_ecdsa_v3_matches_node_accepted_tx);
}

int main(int argc, char *argv[]){
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif
