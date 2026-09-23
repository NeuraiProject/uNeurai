#include "minunit.h"
#include "Networks.h"

MU_TEST(test_networks_params) {
    mu_assert_int_eq(1900, Neurai.bip32);
    mu_assert_int_eq(0, NeuraiLegacy.bip32);
    mu_assert_int_eq(1, NeuraiTest.bip32);
}

/* Base58 prefixes, mirror of the node's chainparams.cpp base58Prefixes[]. */
MU_TEST(test_networks_prefixes) {
    mu_assert_int_eq(0x35, Neurai.p2pkh);
    mu_assert_int_eq(0x75, Neurai.p2sh);
    mu_assert_int_eq(0x80, Neurai.wif);
    mu_assert_int_eq(0x7f, NeuraiTest.p2pkh);
    mu_assert_int_eq(0xc4, NeuraiTest.p2sh);
    mu_assert_int_eq(0xef, NeuraiTest.wif);
}

/* Mainnet / testnet selector for the AuthScript HRPs (nc|tnc, pq|tpq, nq|tnq). */
MU_TEST(test_networks_testnet_flag) {
    mu_check(!chainNetworkIsTestnet(&Neurai));
    mu_check(!chainNetworkIsTestnet(&NeuraiLegacy));
    mu_check(chainNetworkIsTestnet(&NeuraiTest));
    mu_check(!chainNetworkIsTestnet(NULL));
}

MU_TEST_SUITE(test_suite) {
    MU_RUN_TEST(test_networks_params);
    MU_RUN_TEST(test_networks_prefixes);
    MU_RUN_TEST(test_networks_testnet_flag);
}

int main(int argc, char *argv[]) {
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}
