#ifdef UXNA_TEST

/* PQ address encode/decode against the JS oracle (vectors.json). */

#include <string.h>
#include "minunit.h"
#include "NeuraiPQ.h"
#include "Neurai.h"
#include "Hash.h"
#include "Conversion.h"

using std::string;

extern const char PQ_PUBKEY_HEX[]; /* defined in test_authscript.cpp? — not visible across binaries */

/* Keep the 1312-byte pubkey local: each test binary links independently, so
 * we can't share the symbol with test_authscript.cpp. Copy the same hex blob. */
static const char ORACLE_PUBKEY_HEX[] =
    "08032325648fd2c6f999035838f3e2baaa9a3034d31219e76ad109982c041b99"
    "0493e195b02e4cddaa19ab4ae2e6e4354abd2bcc4037b58dffc0768c704f3422"
    "a57b8aa0b05ce4ec7c5d51c9f8da20deae695bc75039a9a4d57750c384168858"
    "d8f02f9c0149cff0ebcb6323cb3463a4f4b55d3e9349e9d42a4d24f4302c1446"
    "1df023e5303f816fd99fdbb7da9305867c13ec6e896465f43b6e4fada0f55ecc"
    "4bf3f7e8548c94ca90f0821688aa00aac312b52e5b75bcdd3ce972f9fe2547a8"
    "d81c3207f1360fabe1a642fa9cfafe1acf2c08b96e39dea42d0011b1673a6820"
    "3d4708b03d0535f577968f2fa844da95bee47aa66d7db7f79d9d869837cd59fe"
    "b035a5d7dd43b88972b39bddc643829512c5491f6e5ee76317d429b15797a250"
    "0e4e82e39f53b4cf0b37a015a456db9209dee3a7b22ca6a170dbfd0e04b9ce4c"
    "d007cc41fee0abab7035f9941bf8ec3eb5b2f57adb8cf2186854ee0da20f1bb1"
    "00d140087150fab9c71e51db8beb2f8a6ab330fa5b392b2df6ca138d9ee861eb"
    "1d54d010a0cf7a682f08b33a3375c9fa889ebe105b2277b1ebdd23bbdcdff5f5"
    "4637fcc397d7cb07434f92f4e2d0e08187cd002504136c082ef043e4acaad740"
    "b090fa869448a0a3873358ec5ff31be481ea3d6d4a4a51982b21201607bf36e0"
    "50e1c5561c0826c137811eb2ac324e1874484c8994b57c81b09ba89031e3215f"
    "605d906e8cdf8e3b8dc4a52995a28988ccb9eebd6163ae7f932fdbaa7e165291"
    "e71cf0c811307c537e0b479e64a54ce4d44adc6999f6c17aea82e97fa38c17a8"
    "0a95df905d6eff165f5e588cedf7dbdb9f31082fcf7f43932384ab36efca0999"
    "3660ecf36b7de6ebbfb923de730b6697926d289eb2ac134da1c4f7fec864590f"
    "10b4e359e3e93c3494dee016de14fca8dfc514a78d6b139bfddbf1383a9000b3"
    "c1649eb82344ff581f8339991cd5fb4bf9c4d065e56e3bfde6431dd62248b700"
    "77cffb7c314ecc75096795a232f0153ee8031885d86c9e1d9bb78a3a3800eefe"
    "84c189e9dd0e980d9dea37465fca8b3c692d6238542e8a384015f87c7f259114"
    "8ec9f634c2468bf21d3a6dcd893261e95cbce690209f9b9308da40b55e73773a"
    "8f66cdb9410e2fd1813e8637fe132970357089ff86c94b253e95e6dab83d236c"
    "c7ddfdd819909f55b1b7b82a4c5ec4033a5593c2cb8a88103d53668397d6a8d8"
    "91eb013840edccbaea203cad59014918f771ab2bbf8c6e475ff1f962b7ff53f4"
    "7c6d8fafc20c32c73493f2adc1c0fcefa1d196e3011f1af58a2cc027a35c7d2d"
    "a6ddc99d858a71bcdb2d1e9d550b7c525d331cd617fc88346c9d9c4f90c3bd7a"
    "1174c9c476e935f6768a2606e767d326278b95d3efd127c6c4d8b3a6117877b0"
    "8adf5f4949f4bdec84437fc39db1ac148116ce996b87ee869aa9ec79a873dee8"
    "c83723692e68f5dc42d3e708312185b292b2d00974d45aeb37fe8212a9692776"
    "216cbc463e92e64d0d94c8e7a2c44d17f0862f872f87c09b6e95708d4b93af60"
    "596bfff0bd98cf499a62d7009c75f47c185d068c5a783995f3d036f1d015b546"
    "cd6395734e68fea42a6dae9c815a40c2d949ff2b64983a7284674d0ac669573f"
    "3de44840a6df7f5f77546b2147edb8653290a11849ac75bbf49f2ee0c471797f"
    "9e0dc4fefd8cc9f466f66a43f6940dd7d6d4158a751e694246740f0d52228ddee"
    "4453b4b94a64327fc96eaaf89a028aa1fecba585f2c0930d0be80445019fc271"
    "8febfadcaa9e93077f610c011bde026aad266cfe5d58f09a0ba19739ffc1b661"
    "f6bce088971d95fcbdb063e0229cc4238aebebf7d5ccfd9c7e24e4b73f5d51e";

static const char EXPECTED_ADDRESS[] =
    "tnq1pdsj0aztvgwv3rwgml360stpyp228zrggyga6n4sdenmetm6wv3tqzddk95";

static const char EXPECTED_COMMITMENT[] =
    "6c24fe896c439911b91bfc74f82c240a94710d08223ba9d60dccf795ef4e6456";

MU_TEST(test_address_from_oracle_pubkey){
    uint8_t pk[UNEURAI_PQ_PUBKEY_RAW_LEN];
    size_t pkLen = fromHex(ORACLE_PUBKEY_HEX, sizeof(ORACLE_PUBKEY_HEX) - 1, pk, sizeof(pk));
    mu_assert_int_eq(UNEURAI_PQ_PUBKEY_RAW_LEN, (int)pkLen);

    char addr[100] = {0};
    size_t l = pqAddressFromPubKey(&NeuraiPQTest, pk, addr, sizeof(addr));
    mu_assert_int_eq((int)strlen(EXPECTED_ADDRESS), (int)l);
    mu_assert_string_eq(EXPECTED_ADDRESS, addr);
}

MU_TEST(test_address_decode_matches_commitment){
    uint8_t commitment[32];
    int ok = pqAddressDecode(EXPECTED_ADDRESS, &NeuraiPQTest, commitment);
    mu_assert_int_eq(1, ok);

    string got = toHex(commitment, 32);
    mu_assert_string_eq(EXPECTED_COMMITMENT, got.c_str());
}

MU_TEST(test_address_decode_wrong_network_fails){
    /* tnq1... must NOT decode under the mainnet "nq" HRP. */
    uint8_t commitment[32];
    int ok = pqAddressDecode(EXPECTED_ADDRESS, &NeuraiPQ, commitment);
    mu_assert_int_eq(0, ok);
}

MU_TEST(test_script_round_trip_pq){
    /* Build a Script from the address, regenerate the address via the
     * ChainNetworkPQ overload. */
    Script s(EXPECTED_ADDRESS);
    mu_check(s.type() == P2AUTHSCRIPT);

    char back[100] = {0};
    size_t l = s.address(back, sizeof(back), &NeuraiPQTest);
    mu_assert_int_eq((int)strlen(EXPECTED_ADDRESS), (int)l);
    mu_assert_string_eq(EXPECTED_ADDRESS, back);
}

MU_TEST_SUITE(test_suite){
    MU_RUN_TEST(test_address_from_oracle_pubkey);
    MU_RUN_TEST(test_address_decode_matches_commitment);
    MU_RUN_TEST(test_address_decode_wrong_network_fails);
    MU_RUN_TEST(test_script_round_trip_pq);
}

int main(int argc, char *argv[]){
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif
