#ifdef UXNA_TEST

/* PSBT::sign with AuthScript prevouts.
 *
 * The PSBTs were built by @neuraiproject/neurai-sign-esp32 0.7.0 (buildPSBT,
 * network xna-test) for the oracle mnemonic key at m/84'/1'/0'/0/0
 * (fingerprint 94280ed5, tnq1rgyglq…), each spending a 10 XNA prevout:
 *   PSBT_V3       -> the key's own strict ECDSA v3 output: signed with the
 *                    strict sighash (the same flow, with a real prevout, was
 *                    finalized by neurai-sign-esp32 and accepted by a regtest
 *                    node);
 *   PSBT_V1       -> a generic AuthScript v1 output: never signed via PSBT;
 *   PSBT_V3_OTHER -> a v3 output of another key: not signed.
 */

#include <string.h>
#include "minunit.h"
#include "Neurai.h"
#include "NeuraiPQ.h"
#include "PSBT.h"
#include "Networks.h"
#include "Conversion.h"

using std::string;

static const char MNEMONIC[] =
    "result pact model attract result puzzle final boss private educate luggage era";
static const char KEY_PUBKEY_HEX[] =
    "03cca0624a268fa661ec9c59d9d107976799d5b2e4bf2e7a21762d230d45ea6970";
/* strictAuthScriptSighash(PSBT_V3 tx, 0, 10 XNA, 3) computed by neurai-sign-esp32. */
static const char V3_SIGHASH_HEX[] =
    "dadbcda6ae8d37f9801c5224e613494bc4f720164b1bd78943d48f66f74c30cb";

static const char PSBT_V3[] =
    "cHNidP8BAIkCAAAAAbBdKkmPEV6ApUOXR0hiFg3Z8DmeA4hTGyDLc/1iDPb6AAAAAAD/////AgDp"
    "pDUAAAAAIlEgZLgbujghRqdA1Weh5kstVYiy11SQdReTvwOCGSIMH4gATfMFAAAAACJTIEER8A5z"
    "w5IDULXm/Jpf8ZyjFz9o6bwM8hbvTbXAUrPTAAAAAAABAF4CAAAAATMzMzMzMzMzMzMzMzMzMzMz"
    "MzMzMzMzMzMzMzMzMzMzAAAAAAD/////AQDKmjsAAAAAIlMgQRHwDnPDkgNQteb8ml/xnKMXP2jp"
    "vAzyFu9NtcBSs9MAAAAAIgYDzKBiSiaPpmHsnFnZ0QeXZ5nVsuS/Lnohdi0jDUXqaXAYlCgO1VQA"
    "AIABAACAAAAAgAAAAAAAAAAAAAAiAgPMoGJKJo+mYeycWdnRB5dnmdWy5L8ueiF2LSMNReppcBiU"
    "KA7VVAAAgAEAAIAAAACAAAAAAAAAAAAA";
static const char PSBT_V1[] =
    "cHNidP8BAIkCAAAAAbfsMg/ZeS35s4QalKVesCcG267mWga0oX7/PXCh40upAAAAAAD/////AgDp"
    "pDUAAAAAIlEgZLgbujghRqdA1Weh5kstVYiy11SQdReTvwOCGSIMH4gAEfIFAAAAACJTIEER8A5z"
    "w5IDULXm/Jpf8ZyjFz9o6bwM8hbvTbXAUrPTAAAAAAABAF4CAAAAATMzMzMzMzMzMzMzMzMzMzMz"
    "MzMzMzMzMzMzMzMzMzMzAAAAAAD/////AQDKmjsAAAAAIlEgXqTOLxBwlRcU8WL+F7o2XXuruSjC"
    "3RLrkZf9HBU65zYAAAAAIgYDzKBiSiaPpmHsnFnZ0QeXZ5nVsuS/Lnohdi0jDUXqaXAYlCgO1VQA"
    "AIABAACAAAAAgAAAAAAAAAAAAAAiAgPMoGJKJo+mYeycWdnRB5dnmdWy5L8ueiF2LSMNReppcBiU"
    "KA7VVAAAgAEAAIAAAACAAAAAAAAAAAAA";
static const char PSBT_V3_OTHER[] =
    "cHNidP8BAIkCAAAAAVat5eudDMaXluA3JxLm7XURITxReMEjKki/YdLel7kGAAAAAAD/////AgDp"
    "pDUAAAAAIlEgZLgbujghRqdA1Weh5kstVYiy11SQdReTvwOCGSIMH4gATfMFAAAAACJTIEER8A5z"
    "w5IDULXm/Jpf8ZyjFz9o6bwM8hbvTbXAUrPTAAAAAAABAF4CAAAAATMzMzMzMzMzMzMzMzMzMzMz"
    "MzMzMzMzMzMzMzMzMzMzAAAAAAD/////AQDKmjsAAAAAIlMghYATFbTGOyPkPxi8P4SthRxXBCHY"
    "EZmzYsp/v+8nDogAAAAAIgYDzKBiSiaPpmHsnFnZ0QeXZ5nVsuS/Lnohdi0jDUXqaXAYlCgO1VQA"
    "AIABAACAAAAAgAAAAAAAAAAAAAAiAgPMoGJKJo+mYeycWdnRB5dnmdWy5L8ueiF2LSMNReppcBiU"
    "KA7VVAAAgAEAAIAAAACAAAAAAAAAAAAA";

static uint8_t signPsbt(const char * b64, PSBT & psbt){
    psbt.parseBase64(string(b64));
    if(!psbt){
        return 0xff;
    }
    HDPrivateKey root(MNEMONIC, "", &NeuraiTest);
    return psbt.sign(root);
}

MU_TEST(test_psbt_signs_own_strict_ecdsa_input){
    PSBT psbt;
    mu_assert_int_eq(1, signPsbt(PSBT_V3, psbt));
    mu_assert_int_eq(1, psbt.txInsMeta[0].signaturesLen);

    PSBTPartialSignature & ps = psbt.txInsMeta[0].signatures[0];
    string pub = ps.pubkey.toString();
    mu_assert_string_eq(KEY_PUBKEY_HEX, pub.c_str());
    mu_assert_int_eq(SIGHASH_ALL, ps.sighashType);

    /* Signed over the strict v3 sighash (not the legacy one). */
    uint8_t h[32];
    mu_assert_int_eq(32, psbt.tx.sigHashAuthScriptStrict(h, 0, psbt.txInsMeta[0].txOut.amount, 3, SIGHASH_ALL));
    string got = toHex(h, 32);
    mu_assert_string_eq(V3_SIGHASH_HEX, got.c_str());
    mu_check(ps.pubkey.verify(ps.signature, h));

    uint8_t legacy[32];
    psbt.tx.sigHash(legacy, 0, psbt.txInsMeta[0].txOut.scriptPubkey, SIGHASH_ALL);
    mu_check(!ps.pubkey.verify(ps.signature, legacy));
}

MU_TEST(test_psbt_skips_generic_authscript_input){
    PSBT psbt;
    mu_assert_int_eq(0, signPsbt(PSBT_V1, psbt));
    mu_assert_int_eq(0, psbt.txInsMeta[0].signaturesLen);
}

MU_TEST(test_psbt_skips_foreign_strict_ecdsa_input){
    PSBT psbt;
    mu_assert_int_eq(0, signPsbt(PSBT_V3_OTHER, psbt));
    mu_assert_int_eq(0, psbt.txInsMeta[0].signaturesLen);
}

MU_TEST_SUITE(test_suite){
    MU_RUN_TEST(test_psbt_signs_own_strict_ecdsa_input);
    MU_RUN_TEST(test_psbt_skips_generic_authscript_input);
    MU_RUN_TEST(test_psbt_skips_foreign_strict_ecdsa_input);
}

int main(int argc, char *argv[]){
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif
