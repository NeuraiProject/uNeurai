#ifdef UXNA_TEST

#include "minunit.h"
#include "Neurai.h"
#include "NeuraiPQ.h"

/* The helpers themselves are static in Script.cpp, so we exercise them indirectly
 * through Script::fromAddress + Script::type + Script::address(ChainNetworkPQ*).
 * The round-trip ensures the witver<->opcode mapping is consistent across encode
 * and decode paths. */

MU_TEST(test_p2authscript_roundtrip_mainnet){
    /* Build a v1, 32-byte program address with the "nc" HRP. */
    uint8_t prog[32];
    for(int i = 0; i < 32; i++) prog[i] = (uint8_t)(i + 1);
    char addr[100] = {0};
    mu_check(segwit_addr_encode(addr, "nc", 1, prog, 32) == 1);

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
    mu_check(segwit_addr_encode(addr, "tnc", 1, prog, 32) == 1);

    Script s(addr);
    mu_check(s.type() == P2AUTHSCRIPT);
    mu_assert_int_eq(0x51, s.scriptArray[0]);

    char back[100] = {0};
    size_t l = s.address(back, sizeof(back), &NeuraiPQTest);
    mu_assert_int_eq((int)strlen(addr), (int)l);
    mu_check(memcmp(back, addr, l) == 0);
}

MU_TEST(test_strict_roundtrip_opcodes){
    /* v2 under "tpq" -> OP_2 (0x52), v3 under "tnq" -> OP_3 (0x53). */
    const char * hrps[2] = { "tpq", "tnq" };
    const uint8_t versions[2] = { 2, 3 };
    const ScriptType types[2] = { P2AUTHSCRIPT_V2, P2AUTHSCRIPT_V3 };
    for(int k = 0; k < 2; k++){
        uint8_t prog[32];
        for(int i = 0; i < 32; i++) prog[i] = (uint8_t)(0x30 + i + k);
        char addr[100] = {0};
        mu_check(segwit_addr_encode(addr, hrps[k], versions[k], prog, 32) == 1);

        Script s(addr);
        mu_check(s.type() == types[k]);
        mu_assert_int_eq(0x50 + versions[k], s.scriptArray[0]);
        mu_assert_int_eq(32, s.scriptArray[1]);
        mu_check(memcmp(s.scriptArray + 2, prog, 32) == 0);

        char back[100] = {0};
        size_t l = s.address(back, sizeof(back), &NeuraiTest);
        mu_assert_int_eq((int)strlen(addr), (int)l);
        mu_check(memcmp(back, addr, l) == 0);
    }
}

MU_TEST(test_v1_under_ecdsa_hrp_rejected){
    /* "nq" only encodes witness v3 now: the old nq1p… (v1) form is invalid. */
    uint8_t prog[32];
    for(int i = 0; i < 32; i++) prog[i] = (uint8_t)(i + 1);
    char addr[100] = {0};
    mu_check(segwit_addr_encode(addr, "nq", 1, prog, 32) == 1);
    Script s(addr);
    mu_check(s.type() == UNKNOWN_TYPE);
    mu_assert_int_eq(0, (int)s.scriptLen);
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
    /* A v0/32-byte program (would be P2WSH) must NOT be classified as AuthScript. */
    uint8_t prog[32] = {0};
    char addr[100] = {0};
    mu_check(segwit_addr_encode(addr, "nc", 0, prog, 32) == 1);
    Script s(addr);
    /* "nc" only pairs with witness v1 (and a v0 program uses the bech32, not
     * bech32m, checksum), so fromAddress leaves the script empty. */
    mu_check(s.type() != P2AUTHSCRIPT);
    mu_assert_int_eq(0, (int)s.scriptLen);
}

MU_TEST_SUITE(test_suite){
    MU_RUN_TEST(test_p2authscript_roundtrip_mainnet);
    MU_RUN_TEST(test_p2authscript_roundtrip_testnet);
    MU_RUN_TEST(test_strict_roundtrip_opcodes);
    MU_RUN_TEST(test_v1_under_ecdsa_hrp_rejected);
    MU_RUN_TEST(test_pq_overload_rejects_non_pq);
    MU_RUN_TEST(test_p2authscript_rejects_v0);
}

int main(int argc, char *argv[]){
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif
