#ifdef UXNA_TEST

#include "minunit.h"
#include "Neurai.h"
#include "NeuraiPQ.h"

/* The helpers themselves are static in Script.cpp, so we exercise them indirectly
 * through Script::fromAddress + Script::type + Script::address(ChainNetworkPQ*).
 * The round-trip ensures the witver<->opcode mapping is consistent across encode
 * and decode paths. */

MU_TEST(test_p2authscript_roundtrip_mainnet){
    /* Build a v1, 32-byte program address with the "nq" HRP. */
    uint8_t prog[32];
    for(int i = 0; i < 32; i++) prog[i] = (uint8_t)(i + 1);
    char addr[100] = {0};
    mu_check(segwit_addr_encode(addr, "nq", 1, prog, 32) == 1);

    Script s(addr);
    mu_check(s.type() == P2AUTHSCRIPT);
    mu_assert_int_eq(34, (int)s.scriptLen);
    mu_assert_int_eq(0x51, s.scriptArray[0]);   /* OP_1, not raw 0x01 */
    mu_assert_int_eq(32,   s.scriptArray[1]);
    mu_check(memcmp(s.scriptArray + 2, prog, 32) == 0);

    char back[100] = {0};
    size_t l = s.address(back, sizeof(back), &NeuraiPQ);
    mu_assert_int_eq((int)strlen(addr), (int)l);
    mu_check(memcmp(back, addr, l) == 0);
}

MU_TEST(test_p2authscript_roundtrip_testnet){
    uint8_t prog[32] = {0};
    for(int i = 0; i < 32; i++) prog[i] = (uint8_t)(0xAA ^ i);
    char addr[100] = {0};
    mu_check(segwit_addr_encode(addr, "tnq", 1, prog, 32) == 1);

    Script s(addr);
    mu_check(s.type() == P2AUTHSCRIPT);
    mu_assert_int_eq(0x51, s.scriptArray[0]);

    char back[100] = {0};
    size_t l = s.address(back, sizeof(back), &NeuraiPQTest);
    mu_assert_int_eq((int)strlen(addr), (int)l);
    mu_check(memcmp(back, addr, l) == 0);
}

MU_TEST(test_pq_overload_rejects_non_pq){
    /* P2PKH script — the PQ address overload must return 0 (not coincidentally
     * generate something). */
    uint8_t buf[25] = {
        0x76, 0xa9, 0x14,
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,
        0x88, 0xac
    };
    Script s(buf, sizeof(buf));
    mu_check(s.type() == P2PKH);
    char addr[100] = {0};
    mu_assert_int_eq(0, (int)s.address(addr, sizeof(addr), &NeuraiPQ));
}

MU_TEST(test_p2authscript_rejects_v0){
    /* A v0/32-byte program (would be P2WSH) must NOT be classified as P2AUTHSCRIPT. */
    uint8_t prog[32] = {0};
    char addr[100] = {0};
    mu_check(segwit_addr_encode(addr, "nq", 0, prog, 32) == 1);
    Script s(addr);
    /* The HRP "nq" with v0 should decode but our PQ branch requires ver==1.
     * fromAddress should reject (scriptLen stays 0) since v0+bech32m mismatch
     * already rules it out at segwit_addr_decode. */
    mu_check(s.type() != P2AUTHSCRIPT);
}

MU_TEST_SUITE(test_suite){
    MU_RUN_TEST(test_p2authscript_roundtrip_mainnet);
    MU_RUN_TEST(test_p2authscript_roundtrip_testnet);
    MU_RUN_TEST(test_pq_overload_rejects_non_pq);
    MU_RUN_TEST(test_p2authscript_rejects_v0);
}

int main(int argc, char *argv[]){
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif
