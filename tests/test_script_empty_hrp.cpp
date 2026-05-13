#ifdef UXNA_TEST

/* Regression test: the legacy networks in Networks.cpp use bech32="" for the
 * non-segwit chains. Before the M2 fix, Script::fromAddress() did
 *     memcmp(address, bech32, strlen(bech32))
 * with strlen("") == 0, which matches every address and would steer a real
 * nq1... / tnq1... into the legacy bech32 decode path. This test confirms
 * the hardened HRP loop classifies the address correctly as P2AUTHSCRIPT. */

#include "minunit.h"
#include "Neurai.h"
#include "NeuraiPQ.h"
#include "Networks.h"

MU_TEST(test_legacy_empty_hrp_does_not_swallow_pq){
    /* Sanity: confirm the legacy networks indeed have empty bech32 HRPs. */
    mu_assert_int_eq(0, (int)strlen(Neurai.bech32));
    mu_assert_int_eq(0, (int)strlen(NeuraiLegacy.bech32));
    mu_assert_int_eq(0, (int)strlen(NeuraiTest.bech32));

    /* Build a valid tnq1... address. If the legacy loop matched empty HRPs
     * it would short-circuit to P2WPKH and fail decode. */
    uint8_t prog[32];
    for(int i = 0; i < 32; i++) prog[i] = (uint8_t)i;
    char addr[100] = {0};
    mu_check(segwit_addr_encode(addr, "tnq", 1, prog, 32) == 1);
    mu_check(memcmp(addr, "tnq1", 4) == 0);

    Script s(addr);
    mu_check(s.type() == P2AUTHSCRIPT);
    mu_assert_int_eq(34, (int)s.scriptLen);
}

MU_TEST(test_legacy_address_still_recognized){
    /* Make sure the empty-HRP fix didn't break P2PKH/P2SH detection. */
    uint8_t pkh_buf[25] = {
        0x76, 0xa9, 0x14,
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,
        0x88, 0xac
    };
    Script pkh_script(pkh_buf, sizeof(pkh_buf));
    char addr[100] = {0};
    size_t l = pkh_script.address(addr, sizeof(addr), &Neurai);
    mu_check(l > 0);

    /* Round-trip: the address should reconstruct an equivalent script. */
    Script reconstructed(addr);
    mu_check(reconstructed.type() == P2PKH);
}

MU_TEST_SUITE(test_suite){
    MU_RUN_TEST(test_legacy_empty_hrp_does_not_swallow_pq);
    MU_RUN_TEST(test_legacy_address_still_recognized);
}

int main(int argc, char *argv[]){
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif
