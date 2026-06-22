#ifdef UXNA_TEST // only compile with test flag

#include "minunit.h"
#include "Asset.h"
#include "AssetConstants.h"
#include "AssetBuilder.h"
#include "AssetName.h"
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
#define ADDR_A    "NXReissueAssetXXXXXXXXXXXXXXWLe4Ao"

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

/* ── Phase 3: constants + output builders (vs the canonical TS builders) ──── */

// Compare a built output's amount + scriptPubkey bytes to a golden value.
static void checkOut(Tx & tx, size_t i, uint64_t amount, const char * scriptHex, const char * msg) {
    mu_assert(i < tx.outputsNumber, msg);
    mu_assert(tx.txOuts[i].amount == amount, msg);
    uint8_t exp[256];
    size_t el = fromHex(scriptHex, exp, sizeof(exp));
    mu_assert(tx.txOuts[i].scriptPubkey.scriptLen == el, msg);
    mu_assert(memcmp(tx.txOuts[i].scriptPubkey.scriptArray, exp, el) == 0, msg);
}

MU_TEST(test_constants_burn_and_names) {
    mu_assert(strcmp(assetBurnAddress(BURN_ISSUE_ROOT, false), "NbURNXXXXXXXXXXXXXXXXXXXXXXXT65Gdr") == 0, "mainnet ISSUE_ROOT burn");
    mu_assert(strcmp(assetBurnAddress(BURN_ISSUE_ROOT, true),  "tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy") == 0, "testnet ISSUE_ROOT burn");
    mu_assert(assetBurnAddress(BURN_OP_COUNT, false) == NULL, "out-of-range op returns NULL");
    mu_assert(strcmp(assetBurnAddress(BURN_TAG_ADDRESS, true), "tTagBurnXXXXXXXXXXXXXXXXXXXXYm6pxA") == 0, "testnet TAG burn");
    mu_assert(assetBurnAmountSats(BURN_ISSUE_ROOT, 1) == 100000000000ULL, "ISSUE_ROOT fee");
    mu_assert(assetBurnAmountSats(BURN_ISSUE_RESTRICTED, 1) == 300000000000ULL, "ISSUE_RESTRICTED fee");
    mu_assert(assetBurnAmountSats(BURN_TAG_ADDRESS, 3) == 60000000ULL, "TAG fee x3 (0.6 XNA)");
    mu_assert(assetBurnAmountSats(BURN_ISSUE_UNIQUE, 5) == 5000000000ULL, "UNIQUE fee x5 (50 XNA)");

    char buf[64];
    mu_assert(assetOwnerTokenName("MYASSET", buf, sizeof(buf)) > 0 && strcmp(buf, "MYASSET!") == 0, "owner name");
    mu_assert(assetOwnerTokenName("$SECURE", buf, sizeof(buf)) > 0 && strcmp(buf, "SECURE!") == 0, "owner name (restricted strips $)");
    mu_assert(assetParentName("ROOT/SUB", buf, sizeof(buf)) > 0 && strcmp(buf, "ROOT") == 0, "parent name");
    mu_assert(assetParentName("ROOT", buf, sizeof(buf)) == 0, "no parent for root");
    mu_assert(assetUniqueName("ROOT", "tag1", buf, sizeof(buf)) > 0 && strcmp(buf, "ROOT#tag1") == 0, "unique name");
}

MU_TEST(test_build_issue_root) {
    Tx tx;
    bool ok = assetBuildIssue(tx,
        "NbURNXXXXXXXXXXXXXXXXXXXXXXXT65Gdr", assetBurnAmountSats(BURN_ISSUE_ROOT, 1),
        "NXReissueAssetXXXXXXXXXXXXXXWLe4Ao", 5000ULL,
        "NXReissueAssetXXXXXXXXXXXXXXWLe4Ao", "MYASSET",
        100000000000ULL, 4, true, NULL, 0, NULL);
    mu_assert(ok, "assetBuildIssue failed");
    mu_assert(tx.outputsNumber == 4, "issue must produce 4 outputs (burn, change, owner, issue)");
    checkOut(tx, 0, 100000000000ULL, "76a914aaad0e674ef84b4fa48bd144e780cbc0e5b0d24688ac", "issue out0 burn");
    checkOut(tx, 1, 5000ULL,         "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688ac", "issue out1 change");
    checkOut(tx, 2, 0ULL,            "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc00d72766e6f084d5941535345542175", "issue out2 owner");
    checkOut(tx, 3, 0ULL,            "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01772766e71074d59415353455400e876481700000004010075", "issue out3 issue");
}

MU_TEST(test_build_transfer) {
    Tx tx;
    bool ok = assetBuildTransfer(tx, "NXReissueAssetXXXXXXXXXXXXXXWLe4Ao", "MYTOKEN", 250000000ULL);
    mu_assert(ok, "assetBuildTransfer failed");
    mu_assert(tx.outputsNumber == 1, "transfer must produce 1 output");
    checkOut(tx, 0, 0ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01472766e74074d59544f4b454e80b2e60e0000000075", "transfer out0");
}

MU_TEST(test_build_reissue) {
    Tx tx;
    bool ok = assetBuildReissue(tx,
        "NXReissueAssetXXXXXXXXXXXXXXWLe4Ao", assetBurnAmountSats(BURN_REISSUE, 1),
        NULL, 0,
        "NXReissueAssetXXXXXXXXXXXXXXWLe4Ao", "NXReissueAssetXXXXXXXXXXXXXXWLe4Ao",
        "MYASSET", 1000000000ULL, 4, false, NULL, 0);
    mu_assert(ok, "assetBuildReissue failed");
    mu_assert(tx.outputsNumber == 3, "reissue must produce 3 outputs (burn, owner-transfer, reissue)");
    checkOut(tx, 0, 20000000000ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688ac", "reissue out0 burn");
    checkOut(tx, 1, 0ULL,           "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01572766e74084d5941535345542100e1f5050000000075", "reissue out1 owner-transfer");
    checkOut(tx, 2, 0ULL,           "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01672766e72074d59415353455400ca9a3b00000000040075", "reissue out2 reissue");
}

MU_TEST(test_build_invalid_address_fails) {
    Tx tx;
    mu_assert(!assetBuildTransfer(tx, "not-an-address", "MYTOKEN", 1ULL), "bad address must fail");
}

/* ── Phase 4: null-asset encode / parse / builders (vs the canonical TS) ──── */

MU_TEST(test_encode_null_tag_legacy) {
    size_t bl = hx(BASE_MAIN, bufBase, sizeof(bufBase));
    size_t n = assetEncodeNullTagScript(bufBase, bl, "#KYC", true, bufEnc, sizeof(bufEnc));
    eqHex(bufEnc, n, "c0147e467332d7bf7d6f85673f075bf1c70f99b7b1f60604234b594301", "encode null tag legacy");
    n = assetEncodeNullTagScript(bufBase, bl, "#KYC", false, bufEnc, sizeof(bufEnc));
    eqHex(bufEnc, n, "c0147e467332d7bf7d6f85673f075bf1c70f99b7b1f60604234b594300", "encode null untag legacy");
}

MU_TEST(test_encode_null_tag_pq) {
    size_t bl = hx(BASE_PQ, bufBase, sizeof(bufBase));
    size_t n = assetEncodeNullTagScript(bufBase, bl, "#KYC", true, bufEnc, sizeof(bufEnc));
    eqHex(bufEnc, n,
        "c051206c24fe896c439911b91bfc74f82c240a94710d08223ba9d60dccf795ef4e64560604234b594301",
        "encode null tag PQ/AuthScript");
}

MU_TEST(test_encode_freeze_address) {
    size_t bl = hx(BASE_MAIN, bufBase, sizeof(bufBase));
    size_t n = assetEncodeNullRestrictionScript(bufBase, bl, "$REST", 1, bufEnc, sizeof(bufEnc));
    eqHex(bufEnc, n, "c0147e467332d7bf7d6f85673f075bf1c70f99b7b1f60705245245535401", "encode freeze address");
}

MU_TEST(test_encode_verifier_and_global) {
    size_t n = assetEncodeVerifierScript("KYC&ACC", bufEnc, sizeof(bufEnc));
    eqHex(bufEnc, n, "c05008074b594326414343", "encode verifier string");
    n = assetEncodeGlobalRestrictionScript("$REST", 3, bufEnc, sizeof(bufEnc));
    eqHex(bufEnc, n, "c050500705245245535403", "encode global restriction");
}

MU_TEST(test_normalize_verifier) {
    char out[64];
    size_t n = assetNormalizeVerifier("#KYC & #ACC", out, sizeof(out));
    mu_assert(n > 0 && strcmp(out, "KYC&ACC") == 0, "normalize strips '#' and whitespace");
}

MU_TEST(test_parse_null_asset) {
    AssetInfo info;
    size_t sl = hx("c0147e467332d7bf7d6f85673f075bf1c70f99b7b1f60604234b594301", bufScript, sizeof(bufScript));
    mu_assert(assetParseScript(bufScript, sl, &info), "parse null tag");
    mu_assert(info.op == ASSET_NULL_TAG, "null tag op");
    mu_assert(strcmp(info.name, "#KYC") == 0, "null tag name");
    mu_assert(info.flag == 1, "null tag flag");
    mu_assert(info.baseLen == 20, "null tag dest is a 20-byte hash");

    sl = hx("c05008074b594326414343", bufScript, sizeof(bufScript));
    mu_assert(assetParseScript(bufScript, sl, &info), "parse verifier");
    mu_assert(info.op == ASSET_VERIFIER, "verifier op");
    mu_assert(strcmp(info.name, "KYC&ACC") == 0, "verifier string");

    sl = hx("c050500705245245535403", bufScript, sizeof(bufScript));
    mu_assert(assetParseScript(bufScript, sl, &info), "parse global restriction");
    mu_assert(info.op == ASSET_GLOBAL_RESTRICTION, "global op");
    mu_assert(strcmp(info.name, "$REST") == 0, "global name");
    mu_assert(info.flag == 3, "global flag");
}

MU_TEST(test_build_issue_restricted) {
    Tx tx;
    bool ok = assetBuildIssueRestricted(tx,
        "NXissueRestrictedXXXXXXXXXXXWpXx4H", assetBurnAmountSats(BURN_ISSUE_RESTRICTED, 1),
        NULL, 0, ADDR_A, ADDR_A, "$REST", "KYC&ACC", 100000000000ULL, 0, true, NULL, 0);
    mu_assert(ok, "assetBuildIssueRestricted failed");
    mu_assert(tx.outputsNumber == 4, "issue restricted must have 4 outputs");
    checkOut(tx, 0, 300000000000ULL, "76a914818880cfa65a9e036061ed18bad3fd135ef4953c88ac", "ir out0 burn");
    checkOut(tx, 1, 0ULL, "c05008074b594326414343", "ir out1 verifier");
    checkOut(tx, 2, 0ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01272766e7405524553542100e1f5050000000075", "ir out2 owner-transfer");
    checkOut(tx, 3, 0ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01572766e7105245245535400e876481700000000010075", "ir out3 issue");
}

MU_TEST(test_build_qualifier_tag) {
    Tx tx;
    const char * targets[] = { ADDR_A };
    bool ok = assetBuildQualifierTag(tx,
        "NXaddTagBurnXXXXXXXXXXXXXXXXWucUTr", assetBurnAmountSats(BURN_TAG_ADDRESS, 1),
        NULL, 0, ADDR_A, "#KYC", 1ULL, targets, 1, true);
    mu_assert(ok, "assetBuildQualifierTag failed");
    mu_assert(tx.outputsNumber == 3, "qualifier tag must have 3 outputs");
    checkOut(tx, 0, 20000000ULL, "76a9147ff947e92aeaeff3cc873f0939102e9646653e8788ac", "qt out0 burn");
    checkOut(tx, 1, 0ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01172766e7404234b5943010000000000000075", "qt out1 qualifier transfer");
    checkOut(tx, 2, 0ULL, "c0147e467332d7bf7d6f85673f075bf1c70f99b7b1f60604234b594301", "qt out2 tag");
}

MU_TEST(test_build_freeze_addresses) {
    Tx tx;
    const char * targets[] = { ADDR_A };
    bool ok = assetBuildFreezeAddresses(tx, NULL, 0, ADDR_A, "$REST", targets, 1, true);
    mu_assert(ok, "assetBuildFreezeAddresses failed");
    mu_assert(tx.outputsNumber == 2, "freeze addresses must have 2 outputs");
    checkOut(tx, 0, 0ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01272766e7405524553542100e1f5050000000075", "fa out0 owner-transfer");
    checkOut(tx, 1, 0ULL, "c0147e467332d7bf7d6f85673f075bf1c70f99b7b1f60705245245535401", "fa out1 restriction");
}

MU_TEST(test_build_freeze_asset) {
    Tx tx;
    bool ok = assetBuildFreezeAsset(tx, NULL, 0, ADDR_A, "$REST", true);
    mu_assert(ok, "assetBuildFreezeAsset failed");
    mu_assert(tx.outputsNumber == 2, "freeze asset must have 2 outputs");
    checkOut(tx, 0, 0ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01272766e7405524553542100e1f5050000000075", "fz out0 owner-transfer");
    checkOut(tx, 1, 0ULL, "c050500705245245535403", "fz out1 global");
}

/* ── Issue variants: sub / unique / qualifier (vs the canonical TS) ───────── */

MU_TEST(test_build_issue_sub) {
    Tx tx;
    bool ok = assetBuildIssueSub(tx,
        "NXissueSubAssetXXXXXXXXXXXXXX6B2JF", assetBurnAmountSats(BURN_ISSUE_SUB, 1),
        NULL, 0, NULL, NULL, ADDR_A, "ROOT/SUB", 500000000ULL, 2, true, NULL, 0);
    mu_assert(ok, "assetBuildIssueSub failed");
    mu_assert(tx.outputsNumber == 4, "issue sub must have 4 outputs");
    checkOut(tx, 0, 20000000000ULL, "76a914818880cfa7e7cb6cae4b905ba24ada8bd697f73088ac", "sub out0 burn");
    checkOut(tx, 1, 0ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01272766e7405524f4f542100e1f5050000000075", "sub out1 parent-owner transfer");
    checkOut(tx, 2, 0ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc00e72766e6f09524f4f542f5355422175", "sub out2 sub-owner issue");
    checkOut(tx, 3, 0ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01872766e7108524f4f542f5355420065cd1d0000000002010075", "sub out3 issue");
}

MU_TEST(test_build_issue_unique) {
    Tx tx;
    const char * tags[] = { "nft1", "nft2" };
    bool ok = assetBuildIssueUnique(tx,
        "NXissueUniqueAssetXXXXXXXXXXUBzP4Z", assetBurnAmountSats(BURN_ISSUE_UNIQUE, 2),
        NULL, 0, NULL, ADDR_A, "ROOT", tags, 2, NULL, NULL);
    mu_assert(ok, "assetBuildIssueUnique failed");
    mu_assert(tx.outputsNumber == 4, "issue unique must have 4 outputs (burn, owner, 2 NFTs)");
    checkOut(tx, 0, 2000000000ULL, "76a914818880cfaa3bea2940b319fbda08c9e4c5bd831088ac", "unique out0 burn");
    checkOut(tx, 1, 0ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01272766e7405524f4f542100e1f5050000000075", "unique out1 root-owner transfer");
    checkOut(tx, 2, 0ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01972766e7109524f4f54236e66743100e1f5050000000000000075", "unique out2 nft1");
    checkOut(tx, 3, 0ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01972766e7109524f4f54236e66743200e1f5050000000000000075", "unique out3 nft2");
}

MU_TEST(test_build_issue_qualifier_root) {
    Tx tx;
    bool ok = assetBuildIssueQualifier(tx,
        "NXissueQuaLifierXXXXXXXXXXXXWurNcU", assetBurnAmountSats(BURN_ISSUE_QUALIFIER, 1),
        NULL, 0, NULL, ADDR_A, "#KYC", 5ULL, 0, NULL, 0);
    mu_assert(ok, "assetBuildIssueQualifier (root) failed");
    mu_assert(tx.outputsNumber == 2, "qualifier root must have 2 outputs (burn, issue)");
    checkOut(tx, 0, 200000000000ULL, "76a914818880cfa56e151bf5ff9dd9011348b56ec13b4a88ac", "qr out0 burn");
    checkOut(tx, 1, 0ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01472766e7104234b5943050000000000000000000075", "qr out1 issue");
}

MU_TEST(test_build_issue_qualifier_sub) {
    Tx tx;
    bool ok = assetBuildIssueQualifier(tx,
        "NXissueSubQuaLifierXXXXXXXXXV71vM3", assetBurnAmountSats(BURN_ISSUE_SUB_QUALIFIER, 1),
        NULL, 0, NULL, ADDR_A, "#KYC/SUB", 3ULL, 100000000ULL, NULL, 0);
    mu_assert(ok, "assetBuildIssueQualifier (sub) failed");
    mu_assert(tx.outputsNumber == 3, "qualifier sub must have 3 outputs (burn, parent transfer, issue)");
    checkOut(tx, 0, 20000000000ULL, "76a914818880cfa7e7d1419e352896d777a01c44a15ab188ac", "qs out0 burn");
    checkOut(tx, 1, 0ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01172766e7404234b594300e1f5050000000075", "qs out1 parent-qualifier transfer");
    checkOut(tx, 2, 0ULL, "76a9147e467332d7bf7d6f85673f075bf1c70f99b7b1f688acc01872766e7108234b59432f535542030000000000000000000075", "qs out2 issue");
}

/* ── Phase 5: name validation (golden table from the TS validateAndDetectType) */

MU_TEST(test_name_validation) {
    const AssetNameType R = ASSET_NAME_ROOT, S = ASSET_NAME_SUB, U = ASSET_NAME_UNIQUE,
                        Q = ASSET_NAME_QUALIFIER, SQ = ASSET_NAME_SUB_QUALIFIER,
                        RS = ASSET_NAME_RESTRICTED, D = ASSET_NAME_DEPIN,
                        O = ASSET_NAME_OWNER, X = ASSET_NAME_INVALID;
    struct Case { const char * name; AssetNameType m; AssetNameType t; };
    static const struct Case cases[] = {
        {"ABC", R, R}, {"AB", X, X}, {"MYTOKEN", R, R}, {"XNA", X, X}, {"NEURAI", X, X},
        {"NEURAICOIN", X, X}, {"A.B", R, R}, {"A..B", X, X}, {".AB", X, X}, {"AB.", X, X},
        {"A_B", R, R}, {"abc", X, X}, {"A-B", X, X},
        {"ROOT/SUB", S, S}, {"ROOT/SUB/X", S, S}, {"ROOT/sub", X, X}, {"ROOT/", X, X},
        {"AB/CD", X, X}, {"ROOT/.X", X, X}, {"ROOT/SUB.", X, X},
        {"ROOT#tag", U, U}, {"ROOT#Tag_1", U, U}, {"ROOT#", X, X}, {"ROOT#a#b", X, X},
        {"AB#tag", X, X}, {"ROOT/SUB#tag", U, U}, {"ROOT#ta g", X, X}, {"ROOT#n@m3", U, U},
        {"#KYC", Q, Q}, {"#KY", X, X}, {"#KYC/SUB", X, X}, {"#KYC/#SUB", SQ, SQ},
        {"#kyc", X, X}, {"#.KYC", X, X}, {"#XNA", X, X}, {"#KYC/A/B", X, X}, {"#A_B", Q, Q},
        {"$REST", RS, RS}, {"$RE", X, X}, {"$.REST", RS, RS}, {"$rest", X, X},
        {"$XNA", RS, RS}, {"$SEC_1", RS, RS},
        {"&SENSOR", X, D}, {"&AB", X, X}, {"&SENSOR/DATA", X, D}, {"&SE/DATA", X, D},
        {"&SENSOR/da", X, X}, {"&sensor", X, X},
        {"MYTOKEN!", O, O}, {"REST!", O, O}, {"ROOT/SUB!", O, O}, {"#KYC!", X, X},
        {"&SENSOR!", X, O}, {"!", X, X}, {"AB!", X, X}, {"ROOT!", O, O}, {"$REST!", X, X},
    };
    size_t count = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < count; i++) {
        mu_assert(assetDetectAndValidate(cases[i].name, false) == cases[i].m, cases[i].name);
        mu_assert(assetDetectAndValidate(cases[i].name, true)  == cases[i].t, cases[i].name);
    }
}

MU_TEST(test_name_length_limits) {
    char buf[160];
    memset(buf, 'A', sizeof(buf));
    /* root/sub max is 31 (mainnet) / 120 (testnet). */
    buf[31] = '\0';
    mu_assert(assetDetectAndValidate(buf, false) == ASSET_NAME_ROOT, "31 chars valid on mainnet");
    mu_assert(assetDetectAndValidate(buf, true)  == ASSET_NAME_ROOT, "31 chars valid on testnet");
    buf[31] = 'A'; buf[32] = '\0';
    mu_assert(assetDetectAndValidate(buf, false) == ASSET_NAME_INVALID, "32 chars invalid on mainnet");
    mu_assert(assetDetectAndValidate(buf, true)  == ASSET_NAME_ROOT,    "32 chars valid on testnet");
    buf[32] = 'A'; buf[120] = '\0';
    mu_assert(assetDetectAndValidate(buf, true)  == ASSET_NAME_ROOT,    "120 chars valid on testnet");
    buf[120] = 'A'; buf[121] = '\0';
    mu_assert(assetDetectAndValidate(buf, true)  == ASSET_NAME_INVALID, "121 chars invalid on testnet");
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
    MU_RUN_TEST(test_constants_burn_and_names);
    MU_RUN_TEST(test_build_issue_root);
    MU_RUN_TEST(test_build_transfer);
    MU_RUN_TEST(test_build_reissue);
    MU_RUN_TEST(test_build_invalid_address_fails);
    MU_RUN_TEST(test_encode_null_tag_legacy);
    MU_RUN_TEST(test_encode_null_tag_pq);
    MU_RUN_TEST(test_encode_freeze_address);
    MU_RUN_TEST(test_encode_verifier_and_global);
    MU_RUN_TEST(test_normalize_verifier);
    MU_RUN_TEST(test_parse_null_asset);
    MU_RUN_TEST(test_build_issue_restricted);
    MU_RUN_TEST(test_build_qualifier_tag);
    MU_RUN_TEST(test_build_freeze_addresses);
    MU_RUN_TEST(test_build_freeze_asset);
    MU_RUN_TEST(test_build_issue_sub);
    MU_RUN_TEST(test_build_issue_unique);
    MU_RUN_TEST(test_build_issue_qualifier_root);
    MU_RUN_TEST(test_build_issue_qualifier_sub);
    MU_RUN_TEST(test_name_validation);
    MU_RUN_TEST(test_name_length_limits);
}

int main(int argc, char *argv[]) {
    MU_RUN_SUITE(test_assets);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif // UXNA_TEST
