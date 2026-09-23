#ifdef UXNA_TEST

/* ML-DSA-44 signers (Tx::signAuthScriptInputPQ / signAuthScriptInputPQStrict).
 *
 * They need the mldsa-esp32 backend, so on the host these tests only run when
 * the suite is built with it:  make run MLDSA_DIR=/path/to/mldsa-esp32/src
 * Otherwise this binary reports 0 tests.
 */

#include <string.h>
#include "minunit.h"
#include "Neurai.h"
#include "NeuraiPQ.h"
#include "Conversion.h"

using std::string;

#if defined(UNEURAI_ENABLE_PQ) && defined(ARDUINO_ARCH_ESP32)
#include <MLDSA44.h>

/* Same oracle key as test_pq_hdkey / test_pq_address. */
static const char MNEMONIC[] =
    "result pact model attract result puzzle final boss private educate luggage era";
static const char ORACLE_V1_ADDRESS[] =
    "tnc1pdsj0aztvgwv3rwgml360stpyp228zrggyga6n4sdenmetm6wv3tqse52vk";
static const char ORACLE_V2_ADDRESS[] =
    "tpq1zxsjnzvjnwn7vt04nkx6qthvylqwej33r53duxawl0uwd3ewme4nsy38hld";

/* A strict PQ v2 spend signed by signAuthScriptInputPQStrict with the key of
 * a regtest node's `getnewaddress "" pq` (tpq1z26xe87…), prevout 10 XNA, and
 * accepted by that node (testmempoolaccept "allowed": 1). */
static const uint64_t NODE_V2_PREVOUT_AMOUNT = 1000000000ULL;
static const char NODE_V2_SIGNED_HEX[] =
    "020000000001010f0c8895d014c86373b126151e1ee2157156dfed23f6e621552aae53890126"
    "d20100000000fdffffff0100e9a4350000000022512064b81bba382146a740d567a1e64b2d55"
    "88b2d75490751793bf038219220c1f88040101fd75091946387d1f5da4d4db9f9475245fddc9"
    "051cedddb96fe65e001e6d0344e8e4eb4e7cb6d90502d0cb536addcb1c4cfe7612f7f46c22c8"
    "99ca33c1fd7dc030c4fc66527297b7a60f36ad36c1580c736d14f012afca3219a843876e8cbd"
    "b01cbb6e7bd2d166cc4f52d31dc98a4c1f289a0026251c2b22d4b142260f67c6b8099d3e8df8"
    "5ce6e84d99964ebcc0584ea2886637129c8bd2ac4643894be6ebaf0ac1e5ac11ca0fd7a4e66a"
    "47320db921d807e1c3014c177eba684b61c00e29647beb31a275ad6275fe3e332d3a686bb9b3"
    "1f293acab9e327b4956c5c463d179316c58e19c11fec090e025b372197c7f0966e690db981f6"
    "40478654bf940fad456a2185d646c703559785500b50be11c1c69a36500350e610a602b6db1a"
    "9789faf53fe6fa829cb113f58fc1d641b947153fe59be7b8e7e0d0b951b30a129c1ca4fe825c"
    "b049f913dabde342c505ade3a085f74e72082d8f92280e7425b6491c89aa9c423501910b2b2c"
    "d1184e2c24f0662c094995219deac1504046576912df5b91e40bf4868844b9eee4e245df816f"
    "5ecc31372cbe5f4454d98ad00dc29c6fa6fb5f5e5b060469644d87519e65d60513a871672f50"
    "ec64b0224aed4a36683f8cc1d5566f29011dd209ed1104b2f2146040264dcfb5d50207bd32c8"
    "50d6d5eca292781fa224e19233e214ef61b3825593c4ed534de466b47609747c2a2a4362eead"
    "b779fa1c3a1d75ad12808b80f594f810ddc8995f8d3e51611076aeb90ffcad03b7d50bdc7307"
    "7bf3bce9793bc203d394ceefc969bd0434700f3e7303a1f5e5bc1da5b77fe794dc35d44d93ed"
    "77a436fdc7cd206c71b92e8f0ca2ac38ff6412bf370b5cf52b60a269ed175644c2a2274f237f"
    "ea76b6679f06c71eb5fc063c210d67f6777fe2088fcb88d275c7d4432200b65441f3f96a4a20"
    "1d38d0b2aed2e44f6ec9b4978a28c2bab222ec2d63e7bf61d3e1a1c2e299bbeeadc500e09690"
    "01c53d0f9f134661162613ae3edfaf447af82fa7c4fdac6d2084e60df667c2ea09e60008a795"
    "ae38f090fa45731bf009d6ec9766fb52c2a79ab5490504d73c70b4932c960a2fa3d97055a5aa"
    "52b4d9ef77525d9e88522f98544791bc30ef52d2429c96c4cc7fe6db7c7a514911979aaa2ed6"
    "6277ecaf8c29b7cc34a020524f3a12367288e09ef10c7ecb8be9bd7f93957cf14103b3fefb6e"
    "f6941acdb7638cf7c54de1170e148ede7f62b02c80fe1bd4336695e5410f10e9135a61c3d8d4"
    "674c9ea352158c1135901ade35520d79bb4840cfcfc226538d554076e38264c3d612f15c7c87"
    "e3deedcc8d68c72719133043d04a5702de561b7059746cbf1db9a4d3af61e8952103baef7630"
    "db03faffd8830ec3f2983fa5cb2819721fc883e8bea31266ffb2d79e9a07b6da5585884b362f"
    "f664ef10daf4c6fe774e8487beefacb6d6ffe72d8816e73d0eaa152f56b2c1b3c25be98a5eb7"
    "3b9890494e47c6001c537c06e21dab717ab7ef44cb5e8563d7113ecf13416c9c7bf8302886ae"
    "68d86e5f954be1b451560f8ecdd66125c3e6792967bf222c91356c8c32b13e1f947f3075d17f"
    "ce28e3d053625ef9d8d976dd6874618fd7f236c7c146d332384fb6501ee23749a1c34ab53fb8"
    "cfc422e4c8cad0c8a5a61e53ce6d50f8fd61459cb9c6014db4f0f69b94bf1b17ae7922b5a7bb"
    "68dcc803847aa3b913863e8751881ce1b87e13ea4a45ef3156dfb1dfcb60f83621aabd10d313"
    "1372f0f3af2201c9a6553ddfb02e35b261dabb8308a5d661015752cc3385c3555dd2b190db8b"
    "e7fa3dfb507f135d986a4196349c3c3386549f21f5442c716c27b2b3e5b19fef0ae2cf83e2e5"
    "15096b3d31a1b5bd7992f8b6f747086e7879bbb4a49ecaa6df468f35150b70628764b37109a1"
    "de86612860490e311878894e1a30f77c53f6d0d45c75685cff588492de34d9cb0f80eed7abdd"
    "3f02117470cca86dce4a15a911601721b1f6d5558057fa577817534dfad16076c5deddb05eeb"
    "7d5c8fed3fd5bf766a53ae32703a4e3339dd5803c4eea3c2af68a29ad257fe38a6ef89f98144"
    "5c0927ead5356068180e83535ff1be10e5e7743bc1b713025d118a23ad26e58368aa1cd47c97"
    "60862468f4328daf6859d091a2b7b3ec12818c0739f88077a17c3cbef38f12219e47d798c9e9"
    "6746d9f4e0cb817afde98a01fa166870b76d09a4b558718eae68253c8421c1da4878e54d7c46"
    "a25f19066ae0c9270c06359929a788b5326117082bf8e729c8d1a5cd2cbb6e24db8ba8d0b055"
    "2b54f10dce9f8225808c60e5213ec35555833bf1d40bafefc33195686098b67a04825fab2e1c"
    "192492f56c297317c8b18ebba73cc2b3787f10b7a84b2a6a528f4e3f9e375e1609b021d2c573"
    "d8c8c3a75d7b4cd3bec847198cc51665754193807c3fbffbbeadbf4cb9e357c15988f611fa68"
    "6e10a3446ded2a3bc3dbe240a4ab0b0249434703c09341969adb94107f700e98c144d5b9a56a"
    "6bca8600302d70d66e7d3670aa889e2305ceb948ad9427b1eb2dd4e6bdd764b9224987d53c1c"
    "438ab1784411458200a49aab13fd3b777a74d4ddf434fd94e043588f3d05a6291556c92fcdb6"
    "176bac14833ffd00956fdac95930767510fc0144af2983d33605ce2eb18bd73c9fb3c9ca1a75"
    "d48fd4d91040cd8a7116752db1177b71160ef59fc3f938b2da54f385bd75d00a7b3bbdad5fbc"
    "3896ad082551886f6b504ca6843b02dbdfb272fcf68fce3751352cd0333ec4a1993b7ef60fa7"
    "904b039bbce0b2bb2e4d711dede53552896a5c26e1650ec1c0555724fde739093c969ef8dd5b"
    "4f47e7d703f5b4f06bdc07fa413a14f43f1d93fcb2c4a41912bd4b72dbb428f22cb6be25f59c"
    "8bdaa026df06d77eb1682a253751d910693b2e91968931b7bc11063c42a93cd2de89039125da"
    "b75dda9946442672e817257e6e09bcf27a810148e26ed5c5e303e1675a68d0b7d43e5916f58c"
    "fd7e26976f2326fdda8388dde15a711ad5e1031b1fd2d71c38007c86fdab7ca468693a11ca8a"
    "846359645224237e73e72a18963183ad26152db1c2f4f0b36337d43587935b254cb45cc30b5a"
    "c8eff8376263c63929a6c3dbc007220ca0aaa3bf9d345e8aecbb357d53c636f958caa801f009"
    "eb39a9cc074e37661c20aa5040dffaa6fbba8a2089a9f01206aaad0328954683c055d6947af0"
    "01e7d765981eec81dbfc9b78f19399b20f4e9705ff544a3ba2ac41a8d96804fa58361f6cb21e"
    "d157a39ac6f8e92fd11d9262e4b5df0bf1af7ce47c49340ea7fbe9471cb0e1991a3d42b8b7ba"
    "90080a1228405c5e62636c97b5b8d31c2e3e565868767d95a4aeb8b9cdebf8fa3a46474f63a9"
    "b4c0c6cbe3ebf306122a2c3f45507e8c9b9ea2b9babdd4e1e8ebf6f900000000000000000000"
    "0000000000000d1e2b4001fd210505556270eef4f15254ead0968e2de14c4bd6ae9f0467ff07"
    "3842fbb4e2c49e3f4e39c1636ca5703e2b7755e5bc05d66b5ef6adc5fdbdfbbcd1b3ee54b9e8"
    "79fe604bfbc42da0957795bcbc0bccd091e390ca9efb1ade2d15831f5ffaa0b1eabce7df1b0c"
    "aae239cfcf682bb172b2f92726ef1e98900505dda7818c60420f13e13d6cdf585c74ccaf1bd3"
    "c2458b7bfb87b5e7431d4e1f12d80f61046e607620228d96e63999a288f7c9e2375e7467f480"
    "70fc9b65829fcaaa39bacbe612181c3be2be6f61e76436910cf2024ff241d692924fae138665"
    "82cb71f39333b1313205984f0edd1176cb27b7547a9e721775e101eecc6e2d6bd30d4328e4e5"
    "d4fd99c3fbbe5d227f68a9575929a6b839080ba8cf58c628bf3f6e6763524f56a0a5d53d1854"
    "7a4832548c10e402bbc53a03c2e274a87f8ef8866187a7477826d35a0b13e105c0ca6af4a34e"
    "529c9174fee36481ceebe1040f8f3cff7c6ab6ba2bf2c105801bb1e33dda677452c356a1da82"
    "561a72f69e66af17ca991b9ee4147341aa1cbedc985535a4a71f89bc6f33353e7074d7294286"
    "1f749e5b240e9417ee9e78bb1e474b15cde7ad78abae031222d3754e55cd8cda66df0d91acab"
    "457708ccffb6dceb604836297fa1768c10aca555d9f5a69550abafd5d533b454367e01c5cec2"
    "706a22df7f22ada7ed1d941cc54af924da1c04a08602286fe1689e9fb744d7dfcf138f32dd4e"
    "482f6bf6a2925bf0a0aedc155b4e8eede97f8b6d54b584698b2203a4a2e02fc4801170d3a3a6"
    "2aeba47441bd16ecff54977bf6491f4f7bec46090ba71867450e3442bf9009023e0fcaa53899"
    "0dc2c41474ea4ce2065a0561d104db93f08f8f70e23d1ffe80da5c3dee92cf9dccbcf122d6cb"
    "397b3c20aa234a136640e9defd0d41ffb2a1ad525e6f150f64d77a0254a8101c9cdc0815dbde"
    "9c5e9f0f8c2bb6679f14fe810ed12431bba183e116b03f4a3db91df462385e879b7a7b824fb1"
    "8eb4e2e133234266977e42e3264740691e81732926c5561aa92b6e35427829ef1d89e11098ce"
    "719fc4eccdd71efaf5cb9ef8f60e21a5eb89966235db34332fc8172eb908d31e1b441c6ce87f"
    "4cfce774487195ee568d05c8197aed610345f8fbda3344377e022ca8664b27f6e9150047ba32"
    "840076d3f0b4b249c87455b479a2c6a516398011b744fa7ad7fe42e033536f2c134760d8b7dd"
    "a6c602d90d60a9ba55d80acba0e8e6404bef36619089e32170a21af72ab5b6518626b7dbc70c"
    "2365288321e36fd05b634a2779ba206ab0a9f670163da96714dcb80c5ba51d1763aa36582d8f"
    "f980f60e01ea8cad6b3f038b14cded4fae8d724ec65704721234ffc895791d80a9c0026545dd"
    "9a5a4307845337266bf3901227635f6ba0d0b129036ea623808b237bbaaa13e1051075e09753"
    "b05f70a3fdc9c404e4712768021ecdd70c44345223420015a5a0de04b1c8b5930bdca21c10ef"
    "42b5799a4b3d6997889eee923bba9bf0884b915cee401ae95238c857cfd2712698b9e6e1992b"
    "dcc33ce519905cec202a126a877c8f5e7c5f79915cea24f83679b201898294f361ae9d0537c5"
    "c759dbb61d4b2b86a80edcbcfe0a6452d9a92fdd542e16709947008e57a88e50d3562a410c71"
    "318e06e9cdded13dcf55a74423efaffe02329b8e581d50a3e989a10aa212ba778c9754975973"
    "4223b9ecbbce487b7ab39f24225b52ac1e4112d5f7a415f6ddef8b39a51513d2110d6f196578"
    "683cbaa05ef5930d3d392ebb46351c4b7d0591d2aea117ebdf1505d52833965be46cc6a115e9"
    "9fd626489adea88fafa6c4135ce006900fc040fd1653de00487fb7a96862044236db49015100"
    "000000";

static uint8_t sk[MLDSA44::SECRET_KEY_SIZE];
static uint8_t pk[UNEURAI_PQ_PUBKEY_RAW_LEN];

static void loadOracleKey(){
    PQHDPrivateKey master, child;
    mu_assert_int_eq(1, master.fromMnemonic(MNEMONIC, sizeof(MNEMONIC) - 1, "", 0, &NeuraiPQTest));
    mu_assert_int_eq(1, master.derive("m_pq/100'/1'/0'/0'/0'", &child));
    mu_assert_int_eq(1, child.materializeKeyPair(pk, sk));
}

/* Split a serialized witness into its items (pointers into `buf`).
 * Returns the item count, or 0 if the serialization is inconsistent. */
static size_t witnessItems(const Witness & w, uint8_t * buf, size_t cap,
                           const uint8_t ** items, size_t * lens, size_t maxItems){
    size_t n = w.serialize(buf, cap);
    size_t off = 0;
    size_t count = buf[off++];
    for(size_t i = 0; i < count && i < maxItems; i++){
        size_t l = buf[off++];
        if(l == 0xfd){
            l = (size_t)buf[off] | ((size_t)buf[off + 1] << 8);
            off += 2;
        }
        items[i] = buf + off;
        lens[i] = l;
        off += l;
    }
    return off == n ? count : 0;
}

/* One-input tx spending `prevTxid:0` to a P2PKH placeholder. */
static void buildTx(Tx & tx){
    tx.version = 2;
    tx.locktime = 0;
    uint8_t prevTxid[32];
    memset(prevTxid, 0x11, sizeof(prevTxid));
    tx.addInput(TxIn(prevTxid, 0, 0xfffffffdU));
    tx.addOutput(TxOut(99990000ULL, "tRATqx227pog5df6cWrgP9gecLr41mEw7u"));
}

static uint8_t witnessBuf[4000];

MU_TEST(test_keypair_addresses){
    loadOracleKey();
    char addr[UNEURAI_AUTHSCRIPT_ADDRESS_MAX] = {0};
    mu_check(pqAddressFromPubKey(&NeuraiPQTest, pk, addr, sizeof(addr)) > 0);
    mu_assert_string_eq(ORACLE_V1_ADDRESS, addr);
    mu_check(pqAddressFromPubKey(&NeuraiPQV2Test, pk, addr, sizeof(addr)) > 0);
    mu_assert_string_eq(ORACLE_V2_ADDRESS, addr);
}

MU_TEST(test_sign_generic_v1){
    loadOracleKey();
    Tx tx;
    buildTx(tx);
    const uint8_t opTrue[1] = { 0x51 };
    Script ws(opTrue, 1);
    mu_assert_int_eq(1, tx.signAuthScriptInputPQ(0, sk, pk, 100000000ULL, ws, SIGHASH_ALL));

    const uint8_t * items[4];
    size_t lens[4];
    mu_assert_int_eq(4, (int)witnessItems(tx.txIns[0].witness, witnessBuf, sizeof(witnessBuf), items, lens, 4));
    mu_assert_int_eq(1, (int)lens[0]);
    mu_assert_int_eq(UNEURAI_AUTHTYPE_PQ, items[0][0]);
    mu_assert_int_eq((int)MLDSA44::SIGNATURE_SIZE + 1, (int)lens[1]);
    mu_assert_int_eq(SIGHASH_ALL, items[1][lens[1] - 1]);
    mu_assert_int_eq(1 + UNEURAI_PQ_PUBKEY_RAW_LEN, (int)lens[2]);
    mu_assert_int_eq(UNEURAI_PQ_PUBKEY_PREFIX, items[2][0]);
    mu_check(memcmp(items[2] + 1, pk, UNEURAI_PQ_PUBKEY_RAW_LEN) == 0);
    mu_assert_int_eq(1, (int)lens[3]);
    mu_assert_int_eq(0x51, items[3][0]);

    uint8_t h[32];
    mu_assert_int_eq(32, tx.sigHashAuthScript(h, 0, ws, 100000000ULL, UNEURAI_AUTHTYPE_PQ, SIGHASH_ALL));
    mu_assert_int_eq(0, MLDSA44::verify(items[1], MLDSA44::SIGNATURE_SIZE, h, 32, pk));
}

MU_TEST(test_sign_strict_v2){
    loadOracleKey();
    Tx tx;
    buildTx(tx);
    mu_assert_int_eq(1, tx.signAuthScriptInputPQStrict(0, sk, pk, 100000000ULL, SIGHASH_ALL));

    const uint8_t * items[4];
    size_t lens[4];
    mu_assert_int_eq(4, (int)witnessItems(tx.txIns[0].witness, witnessBuf, sizeof(witnessBuf), items, lens, 4));
    mu_assert_int_eq(UNEURAI_AUTHTYPE_PQ, items[0][0]);
    mu_assert_int_eq(UNEURAI_PQ_PUBKEY_PREFIX, items[2][0]);
    mu_assert_int_eq(1, (int)lens[3]);
    mu_assert_int_eq(0x51, items[3][0]);

    /* Signed over the strict sighash, not over the generic one. */
    uint8_t strict[32], generic[32];
    mu_assert_int_eq(32, tx.sigHashAuthScriptStrict(strict, 0, 100000000ULL, 2, SIGHASH_ALL));
    const uint8_t opTrue[1] = { 0x51 };
    tx.sigHashAuthScript(generic, 0, Script(opTrue, 1), 100000000ULL, UNEURAI_AUTHTYPE_PQ, SIGHASH_ALL);
    mu_assert_int_eq(0, MLDSA44::verify(items[1], MLDSA44::SIGNATURE_SIZE, strict, 32, pk));
    mu_check(MLDSA44::verify(items[1], MLDSA44::SIGNATURE_SIZE, generic, 32, pk) != 0);

    /* Out-of-range input. */
    mu_assert_int_eq(0, tx.signAuthScriptInputPQStrict(1, sk, pk, 100000000ULL, SIGHASH_ALL));
}

MU_TEST(test_node_accepted_strict_v2_spend){
    static uint8_t raw[4000];
    size_t n = fromHex(NODE_V2_SIGNED_HEX, sizeof(NODE_V2_SIGNED_HEX) - 1, raw, sizeof(raw));
    mu_check(n > 0);
    Tx tx;
    mu_check(tx.parse(raw, n) == n);

    const uint8_t * items[4];
    size_t lens[4];
    mu_assert_int_eq(4, (int)witnessItems(tx.txIns[0].witness, witnessBuf, sizeof(witnessBuf), items, lens, 4));
    mu_assert_int_eq(1 + UNEURAI_PQ_PUBKEY_RAW_LEN, (int)lens[2]);

    /* The node-accepted signature verifies over our strict sighash. */
    uint8_t h[32];
    mu_assert_int_eq(32, tx.sigHashAuthScriptStrict(h, 0, NODE_V2_PREVOUT_AMOUNT, 2, SIGHASH_ALL));
    mu_assert_int_eq(0, MLDSA44::verify(items[1], MLDSA44::SIGNATURE_SIZE, h, 32, items[2] + 1));

    /* And the witness key is the one behind the spent tpq1z… output. */
    char addr[UNEURAI_AUTHSCRIPT_ADDRESS_MAX] = {0};
    mu_check(pqAddressFromPubKey(&NeuraiPQV2Test, items[2] + 1, addr, sizeof(addr)) > 0);
    mu_assert_string_eq("tpq1z26xe87v03dum5sugz0h5sdwhur6kftsn9ccl9f6agsdp7atcgyaqdex2vu", addr);
}
#endif // PQ backend

MU_TEST_SUITE(test_suite){
#if defined(UNEURAI_ENABLE_PQ) && defined(ARDUINO_ARCH_ESP32)
    MU_RUN_TEST(test_keypair_addresses);
    MU_RUN_TEST(test_sign_generic_v1);
    MU_RUN_TEST(test_sign_strict_v2);
    MU_RUN_TEST(test_node_accepted_strict_v2_spend);
#endif
}

int main(int argc, char *argv[]){
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif
