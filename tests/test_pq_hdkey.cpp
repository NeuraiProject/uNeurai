#ifdef UXNA_TEST

/* PQHDPrivateKey against the JS oracle (vectors.json). */

#include <string.h>
#include "minunit.h"
#include "NeuraiPQ.h"
#include "Hash.h"
#include "Conversion.h"

using std::string;

static const char MNEMONIC[] =
    "result pact model attract result puzzle final boss private educate luggage era";

static const char EXPECTED_MASTER_PQ_SEED[] =
    "cd0138993c9c9b5b65ff4073c6e08a18702bfd2da516c82fc7f6751bd0aeb218";
static const char EXPECTED_MASTER_CHAIN_CODE[] =
    "518e78876397a4bb486c5532a8774db35239b4a99150c25bc474a8cf96663d64";

static const char EXPECTED_FIRST_PQ_SEED[] =
    "01c90ab4a59fea37beee5e5a26a3a34fa33bbeed8760976beb9bfe02ce345d15";
static const char EXPECTED_FIRST_CHAIN_CODE[] =
    "d9d849f50b4b423a79642de9bfac51949d5a9bca661d6bfc17379e1b33d8bcb3";

static const char EXPECTED_TPQPRIV[] =
    "tpqp898ggXX5fM3NCkJunugoNYzk9tW9Jd5zNC594L4aknnZpXMadS4vyxZ5MGjA6HkJxwtco7vfVUnWTTwaWYvTEBcf8dirRbutCm6tHtf82uN";

MU_TEST(test_master_from_mnemonic){
    PQHDPrivateKey master;
    int ok = master.fromMnemonic(MNEMONIC, sizeof(MNEMONIC) - 1, "", 0, &NeuraiPQTest);
    mu_assert_int_eq(1, ok);

    string seedHex = toHex(master.pqSeed, 32);
    string ccHex   = toHex(master.chainCode, 32);
    mu_assert_string_eq(EXPECTED_MASTER_PQ_SEED,    seedHex.c_str());
    mu_assert_string_eq(EXPECTED_MASTER_CHAIN_CODE, ccHex.c_str());
    mu_assert_int_eq(0, master.depth);
    mu_assert_int_eq(0, (int)master.childNumber);
}

MU_TEST(test_derive_path_matches_oracle){
    PQHDPrivateKey master;
    master.fromMnemonic(MNEMONIC, sizeof(MNEMONIC) - 1, "", 0, &NeuraiPQTest);

    PQHDPrivateKey derived;
    int ok = master.derive("m_pq/100'/1'/0'/0'/0'", &derived);
    mu_assert_int_eq(1, ok);

    string seedHex = toHex(derived.pqSeed, 32);
    string ccHex   = toHex(derived.chainCode, 32);
    mu_assert_string_eq(EXPECTED_FIRST_PQ_SEED,    seedHex.c_str());
    mu_assert_string_eq(EXPECTED_FIRST_CHAIN_CODE, ccHex.c_str());
    mu_assert_int_eq(5, derived.depth);
    /* last child index: 0' = 0 | 0x80000000 */
    mu_check(derived.childNumber == 0x80000000UL);
}

MU_TEST(test_non_hardened_segment_rejected){
    PQHDPrivateKey master;
    master.fromMnemonic(MNEMONIC, sizeof(MNEMONIC) - 1, "", 0, &NeuraiPQTest);

    PQHDPrivateKey derived;
    /* Missing ' on the last segment. */
    int ok = master.derive("m_pq/100'/1'/0'/0'/0", &derived);
    mu_assert_int_eq(0, ok);
}

MU_TEST(test_derive_child_requires_hardened){
    PQHDPrivateKey master;
    master.fromMnemonic(MNEMONIC, sizeof(MNEMONIC) - 1, "", 0, &NeuraiPQTest);
    PQHDPrivateKey out;
    /* index 0 (non-hardened) -> reject */
    mu_assert_int_eq(0, master.deriveChild(0, &out));
    /* index with HARDENED bit -> succeed */
    mu_assert_int_eq(1, master.deriveChild(0x80000000UL, &out));
}

MU_TEST(test_xpqp_roundtrip){
    PQHDPrivateKey master;
    master.fromMnemonic(MNEMONIC, sizeof(MNEMONIC) - 1, "", 0, &NeuraiPQTest);

    char serialized[UNEURAI_PQ_EXTKEY_BASE58_MAX] = {0};
    size_t l = master.xpqp(serialized, sizeof(serialized));
    mu_check(l > 0);
    mu_assert_string_eq(EXPECTED_TPQPRIV, serialized);

    /* Round-trip via fromXpqp. */
    PQHDPrivateKey restored;
    int ok = restored.fromXpqp(serialized, &NeuraiPQTest);
    mu_assert_int_eq(1, ok);
    mu_check(memcmp(restored.pqSeed,    master.pqSeed,    32) == 0);
    mu_check(memcmp(restored.chainCode, master.chainCode, 32) == 0);
    mu_assert_int_eq(master.depth, restored.depth);
}

MU_TEST(test_xpqp_wrong_network_rejected){
    PQHDPrivateKey master;
    master.fromMnemonic(MNEMONIC, sizeof(MNEMONIC) - 1, "", 0, &NeuraiPQTest);

    char serialized[UNEURAI_PQ_EXTKEY_BASE58_MAX] = {0};
    master.xpqp(serialized, sizeof(serialized));

    PQHDPrivateKey wrong;
    int ok = wrong.fromXpqp(serialized, &NeuraiPQ); // mainnet version
    mu_assert_int_eq(0, ok);
}

MU_TEST_SUITE(test_suite){
    MU_RUN_TEST(test_master_from_mnemonic);
    MU_RUN_TEST(test_derive_path_matches_oracle);
    MU_RUN_TEST(test_non_hardened_segment_rejected);
    MU_RUN_TEST(test_derive_child_requires_hardened);
    MU_RUN_TEST(test_xpqp_roundtrip);
    MU_RUN_TEST(test_xpqp_wrong_network_rejected);
}

int main(int argc, char *argv[]){
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif
