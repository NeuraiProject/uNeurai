#include "minunit.h"
#include "Networks.h"

MU_TEST(test_networks_params) {
    mu_assert_int_eq(1900, Neurai.bip32);
    mu_assert_int_eq(0, NeuraiLegacy.bip32);
}

MU_TEST_SUITE(test_suite) {
    MU_RUN_TEST(test_networks_params);
}

int main(int argc, char *argv[]) {
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}
