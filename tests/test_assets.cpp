#ifdef UXNA_TEST // only compile with test flag

#include "minunit.h"
#include "Asset.h"
#include "Conversion.h"
#include <string.h>

/*
 * Golden vectors generated from @neuraiproject/neurai-create-transaction
 * (the canonical TS encoder). Each `script` is the exact on-chain scriptPubkey
 * hex; the C++ parser must reproduce op / base / name / amount / units /
 * reissuable byte-for-byte. Addresses used: mainnet legacy (N…), testnet legacy
 * (t…) and testnet AuthScript/PQ (tnq1…).
 */

static uint8_t bufScript[256];
static uint8_t bufBase[64];

// Parse hex into a static buffer; returns the byte length.
static size_t hx(const char * hex, uint8_t * out, size_t cap) {
    return fromHex(hex, out, cap);
}

// Common assertion: parse `scriptHex`, compare base bytes and op.
static void checkBaseAndOp(const char * scriptHex, const char * baseHex,
                           AssetOp expectOp, AssetInfo * info) {
    size_t sl = hx(scriptHex, bufScript, sizeof(bufScript));
    size_t bl = hx(baseHex, bufBase, sizeof(bufBase));
    mu_assert(assetParseScript(bufScript, sl, info), "assetParseScript should succeed");
    mu_assert(info->op == expectOp, "asset op mismatch");
    mu_assert(info->baseLen == bl, "base length mismatch");
    mu_assert(info->base != NULL && memcmp(info->base, bufBase, bl) == 0, "base bytes mismatch");
    mu_assert(assetIsAssetScript(bufScript, sl), "assetIsAssetScript should be true");
}

MU_TEST(test_transfer_p2pkh_mainnet) {
    AssetInfo info;
    checkBaseAndOp(
        "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01672766e74095445535441535345544e61bc000000000075",
        "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688ac",
        ASSET_TRANSFER, &info);
    mu_assert(strcmp(info.name, "TESTASSET") == 0, "transfer name mismatch");
    mu_assert(info.amount == 12345678ULL, "transfer amount mismatch");
    mu_assert(info.hasIpfs == 0, "transfer should have no ipfs");
}

MU_TEST(test_transfer_p2pkh_testnet) {
    AssetInfo info;
    checkBaseAndOp(
        "76a9142b5c482167e693950cd303a2806a8cc6c7161db088acc01472766e7407464f4f2e42415200e1f5050000000075",
        "76a9142b5c482167e693950cd303a2806a8cc6c7161db088ac",
        ASSET_TRANSFER, &info);
    mu_assert(strcmp(info.name, "FOO.BAR") == 0, "transfer name mismatch");
    mu_assert(info.amount == 100000000ULL, "transfer amount mismatch");
}

MU_TEST(test_transfer_authscript_pq) {
    AssetInfo info;
    checkBaseAndOp(
        "51206c24fe896c439911b91bfc74f82c240a94710d08223ba9d60dccf795ef4e6456c01672766e74095355422f4348494c44050000000000000075",
        "51206c24fe896c439911b91bfc74f82c240a94710d08223ba9d60dccf795ef4e6456",
        ASSET_TRANSFER, &info);
    mu_assert(info.baseLen == 34, "PQ base must be 34 bytes (OP_1 0x20 <32>)");
    mu_assert(strcmp(info.name, "SUB/CHILD") == 0, "transfer name mismatch");
    mu_assert(info.amount == 5ULL, "transfer amount mismatch");
}

MU_TEST(test_issue_mainnet) {
    AssetInfo info;
    checkBaseAndOp(
        "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01772766e71074d59415353455400e876481700000004010075",
        "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688ac",
        ASSET_ISSUE, &info);
    mu_assert(strcmp(info.name, "MYASSET") == 0, "issue name mismatch");
    mu_assert(info.amount == 100000000000ULL, "issue quantity mismatch");
    mu_assert(info.units == 4, "issue units mismatch");
    mu_assert(info.reissuable == 1, "issue reissuable mismatch");
    mu_assert(info.hasIpfs == 0, "issue should have no ipfs");
}

MU_TEST(test_owner_mainnet) {
    AssetInfo info;
    checkBaseAndOp(
        "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc00d72766e6f084d5941535345542175",
        "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688ac",
        ASSET_OWNER, &info);
    mu_assert(strcmp(info.name, "MYASSET!") == 0, "owner token name mismatch");
}

MU_TEST(test_reissue_mainnet) {
    AssetInfo info;
    checkBaseAndOp(
        "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01672766e72074d59415353455400743ba40b000000040075",
        "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688ac",
        ASSET_REISSUE, &info);
    mu_assert(strcmp(info.name, "MYASSET") == 0, "reissue name mismatch");
    mu_assert(info.amount == 50000000000ULL, "reissue quantity mismatch");
    mu_assert(info.units == 4, "reissue units mismatch");
    mu_assert(info.reissuable == 0, "reissue reissuable mismatch");
}

MU_TEST(test_plain_p2pkh_is_not_asset) {
    AssetInfo info;
    // A bare P2PKH script must NOT be detected as an asset.
    size_t sl = hx("76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688ac", bufScript, sizeof(bufScript));
    mu_assert(!assetParseScript(bufScript, sl, &info), "plain P2PKH must not parse as asset");
    mu_assert(info.op == ASSET_NONE, "op must be ASSET_NONE for non-asset");
    mu_assert(!assetIsAssetScript(bufScript, sl), "assetIsAssetScript must be false for P2PKH");
}

MU_TEST(test_truncated_is_rejected) {
    AssetInfo info;
    // Asset script with the payload chopped off → must be rejected, not crash.
    size_t sl = hx("76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01672766e74", bufScript, sizeof(bufScript));
    mu_assert(!assetParseScript(bufScript, sl, &info), "truncated asset script must be rejected");
}

MU_TEST_SUITE(test_assets) {
    MU_RUN_TEST(test_transfer_p2pkh_mainnet);
    MU_RUN_TEST(test_transfer_p2pkh_testnet);
    MU_RUN_TEST(test_transfer_authscript_pq);
    MU_RUN_TEST(test_issue_mainnet);
    MU_RUN_TEST(test_owner_mainnet);
    MU_RUN_TEST(test_reissue_mainnet);
    MU_RUN_TEST(test_plain_p2pkh_is_not_asset);
    MU_RUN_TEST(test_truncated_is_rejected);
}

int main(int argc, char *argv[]) {
    MU_RUN_SUITE(test_assets);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif // UXNA_TEST
