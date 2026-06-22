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
static uint8_t bufEnc[256];

#define BASE_MAIN "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688ac"
#define BASE_TEST "76a9142b5c482167e693950cd303a2806a8cc6c7161db088ac"
#define BASE_PQ   "51206c24fe896c439911b91bfc74f82c240a94710d08223ba9d60dccf795ef4e6456"
#define IPFS_HEX  "12209d6c2be50f706953479ab9df2ce3edca90b68053c00b3004b7f0accbe1e8eedf"

// Parse hex into a static buffer; returns the byte length.
static size_t hx(const char * hex, uint8_t * out, size_t cap) {
    return fromHex(hex, out, cap);
}

// Assert produced bytes equal the expected hex (byte-for-byte vs the TS encoder).
static void eqHex(const uint8_t * got, size_t gotLen, const char * expectHex, const char * msg) {
    uint8_t exp[256];
    size_t el = fromHex(expectHex, exp, sizeof(exp));
    mu_assert(gotLen == el, msg);
    mu_assert(memcmp(got, exp, el) == 0, msg);
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

/* ── Encode (phase 2): C++ output must equal the canonical TS encoder ──────── */

MU_TEST(test_encode_transfer_mainnet) {
    size_t bl = hx(BASE_MAIN, bufBase, sizeof(bufBase));
    size_t n = assetEncodeTransferScript(bufBase, bl, "TESTASSET", 12345678ULL, bufEnc, sizeof(bufEnc));
    eqHex(bufEnc, n,
        "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01672766e74095445535441535345544e61bc000000000075",
        "encode transfer mainnet");
}

MU_TEST(test_encode_transfer_testnet) {
    size_t bl = hx(BASE_TEST, bufBase, sizeof(bufBase));
    size_t n = assetEncodeTransferScript(bufBase, bl, "FOO.BAR", 100000000ULL, bufEnc, sizeof(bufEnc));
    eqHex(bufEnc, n,
        "76a9142b5c482167e693950cd303a2806a8cc6c7161db088acc01472766e7407464f4f2e42415200e1f5050000000075",
        "encode transfer testnet");
}

MU_TEST(test_encode_transfer_pq) {
    size_t bl = hx(BASE_PQ, bufBase, sizeof(bufBase));
    size_t n = assetEncodeTransferScript(bufBase, bl, "SUB/CHILD", 5ULL, bufEnc, sizeof(bufEnc));
    eqHex(bufEnc, n,
        "51206c24fe896c439911b91bfc74f82c240a94710d08223ba9d60dccf795ef4e6456c01672766e74095355422f4348494c44050000000000000075",
        "encode transfer PQ/AuthScript");
}

MU_TEST(test_encode_transfer_long_name_pushdata1) {
    // 70-char name → payload 83 bytes → must use OP_PUSHDATA1 (0x4c).
    size_t bl = hx(BASE_MAIN, bufBase, sizeof(bufBase));
    const char * longName = "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL";
    size_t n = assetEncodeTransferScript(bufBase, bl, longName, 1ULL, bufEnc, sizeof(bufEnc));
    eqHex(bufEnc, n,
        "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc04c5372766e74464c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c010000000000000075",
        "encode transfer long name (OP_PUSHDATA1)");
}

MU_TEST(test_encode_issue_mainnet) {
    size_t bl = hx(BASE_MAIN, bufBase, sizeof(bufBase));
    size_t n = assetEncodeIssueScript(bufBase, bl, "MYASSET", 100000000000ULL, 4, true, NULL, 0, bufEnc, sizeof(bufEnc));
    eqHex(bufEnc, n,
        "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01772766e71074d59415353455400e876481700000004010075",
        "encode issue mainnet");
}

MU_TEST(test_encode_issue_with_ipfs) {
    size_t bl = hx(BASE_MAIN, bufBase, sizeof(bufBase));
    uint8_t ipfs[34];
    size_t il = hx(IPFS_HEX, ipfs, sizeof(ipfs));
    size_t n = assetEncodeIssueScript(bufBase, bl, "MYASSET", 100000000000ULL, 4, true, ipfs, il, bufEnc, sizeof(bufEnc));
    eqHex(bufEnc, n,
        "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc03972766e71074d59415353455400e876481700000004010112209d6c2be50f706953479ab9df2ce3edca90b68053c00b3004b7f0accbe1e8eedf75",
        "encode issue with IPFS");
}

MU_TEST(test_encode_owner_mainnet) {
    size_t bl = hx(BASE_MAIN, bufBase, sizeof(bufBase));
    size_t n = assetEncodeOwnerScript(bufBase, bl, "MYASSET!", bufEnc, sizeof(bufEnc));
    eqHex(bufEnc, n,
        "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc00d72766e6f084d5941535345542175",
        "encode owner token");
}

MU_TEST(test_encode_reissue_mainnet) {
    size_t bl = hx(BASE_MAIN, bufBase, sizeof(bufBase));
    size_t n = assetEncodeReissueScript(bufBase, bl, "MYASSET", 50000000000ULL, 4, false, NULL, 0, bufEnc, sizeof(bufEnc));
    eqHex(bufEnc, n,
        "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01672766e72074d59415353455400743ba40b000000040075",
        "encode reissue mainnet");
}

MU_TEST(test_encode_overflow_returns_zero) {
    // Output buffer too small → must return 0, never overflow.
    size_t bl = hx(BASE_MAIN, bufBase, sizeof(bufBase));
    uint8_t tiny[8];
    size_t n = assetEncodeTransferScript(bufBase, bl, "TESTASSET", 12345678ULL, tiny, sizeof(tiny));
    mu_assert(n == 0, "encode into too-small buffer must return 0");
}

MU_TEST(test_encode_parse_roundtrip) {
    size_t bl = hx(BASE_MAIN, bufBase, sizeof(bufBase));
    size_t n = assetEncodeIssueScript(bufBase, bl, "ROUNDTRIP", 777ULL, 2, true, NULL, 0, bufEnc, sizeof(bufEnc));
    mu_assert(n > 0, "encode failed");
    AssetInfo info;
    mu_assert(assetParseScript(bufEnc, n, &info), "parse of encoded script failed");
    mu_assert(info.op == ASSET_ISSUE, "roundtrip op mismatch");
    mu_assert(strcmp(info.name, "ROUNDTRIP") == 0, "roundtrip name mismatch");
    mu_assert(info.amount == 777ULL, "roundtrip amount mismatch");
    mu_assert(info.units == 2, "roundtrip units mismatch");
    mu_assert(info.reissuable == 1, "roundtrip reissuable mismatch");
    mu_assert(info.baseLen == bl && memcmp(info.base, bufBase, bl) == 0, "roundtrip base mismatch");
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
    MU_RUN_TEST(test_encode_transfer_mainnet);
    MU_RUN_TEST(test_encode_transfer_testnet);
    MU_RUN_TEST(test_encode_transfer_pq);
    MU_RUN_TEST(test_encode_transfer_long_name_pushdata1);
    MU_RUN_TEST(test_encode_issue_mainnet);
    MU_RUN_TEST(test_encode_issue_with_ipfs);
    MU_RUN_TEST(test_encode_owner_mainnet);
    MU_RUN_TEST(test_encode_reissue_mainnet);
    MU_RUN_TEST(test_encode_overflow_returns_zero);
    MU_RUN_TEST(test_encode_parse_roundtrip);
}

int main(int argc, char *argv[]) {
    MU_RUN_SUITE(test_assets);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif // UXNA_TEST
