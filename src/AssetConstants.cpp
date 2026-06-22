#include "AssetConstants.h"
#include <string.h>

/* Indexed by BurnOp. Keep in sync with the enum order. */
static const char * const MAINNET_BURN[BURN_OP_COUNT] = {
    "NbURNXXXXXXXXXXXXXXXXXXXXXXXT65Gdr", /* ISSUE_ROOT          */
    "NXissueSubAssetXXXXXXXXXXXXXX6B2JF", /* ISSUE_SUB           */
    "NXissueUniqueAssetXXXXXXXXXXUBzP4Z", /* ISSUE_UNIQUE        */
    "NXissueUniqueAssetXXXXXXXXXXUBzP4Z", /* ISSUE_DEPIN         */
    "NXissueMsgChanneLAssetXXXXXXTUzrtJ", /* ISSUE_MSGCHANNEL    */
    "NXissueQuaLifierXXXXXXXXXXXXWurNcU", /* ISSUE_QUALIFIER     */
    "NXissueSubQuaLifierXXXXXXXXXV71vM3", /* ISSUE_SUB_QUALIFIER */
    "NXissueRestrictedXXXXXXXXXXXWpXx4H", /* ISSUE_RESTRICTED    */
    "NXReissueAssetXXXXXXXXXXXXXXWLe4Ao", /* REISSUE             */
    "NXReissueAssetXXXXXXXXXXXXXXWLe4Ao", /* REISSUE_RESTRICTED  */
    "NXaddTagBurnXXXXXXXXXXXXXXXXWucUTr", /* TAG_ADDRESS         */
    "NXaddTagBurnXXXXXXXXXXXXXXXXWucUTr"  /* UNTAG_ADDRESS       */
};

static const char * const TESTNET_BURN[BURN_OP_COUNT] = {
    "tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy", /* ISSUE_ROOT          */
    "tSubAssetXXXXXXXXXXXXXXXXXXXXGTvF4", /* ISSUE_SUB           */
    "tUniqueAssetXXXXXXXXXXXXXXXXVCgpLs", /* ISSUE_UNIQUE        */
    "tUniqueAssetXXXXXXXXXXXXXXXXVCgpLs", /* ISSUE_DEPIN         */
    "tMsgChanneLAssetXXXXXXXXXXXXVsJoya", /* ISSUE_MSGCHANNEL    */
    "tQuaLifierXXXXXXXXXXXXXXXXXXT5czoV", /* ISSUE_QUALIFIER     */
    "tSubQuaLifierXXXXXXXXXXXXXXXW5MmGk", /* ISSUE_SUB_QUALIFIER */
    "tRestrictedXXXXXXXXXXXXXXXXXVyPBEK", /* ISSUE_RESTRICTED    */
    "tAssetXXXXXXXXXXXXXXXXXXXXXXas6pz8", /* REISSUE             */
    "tAssetXXXXXXXXXXXXXXXXXXXXXXas6pz8", /* REISSUE_RESTRICTED  */
    "tTagBurnXXXXXXXXXXXXXXXXXXXXYm6pxA", /* TAG_ADDRESS         */
    "tTagBurnXXXXXXXXXXXXXXXXXXXXYm6pxA"  /* UNTAG_ADDRESS       */
};

/* Fees in satoshis (XNA * 1e8). TAG/UNTAG are 0.2 XNA. */
static const uint64_t BURN_SATS[BURN_OP_COUNT] = {
    100000000000ULL, /* ISSUE_ROOT          1000  */
     20000000000ULL, /* ISSUE_SUB            200  */
      1000000000ULL, /* ISSUE_UNIQUE          10  */
      1000000000ULL, /* ISSUE_DEPIN           10  */
     20000000000ULL, /* ISSUE_MSGCHANNEL     200  */
    200000000000ULL, /* ISSUE_QUALIFIER     2000  */
     20000000000ULL, /* ISSUE_SUB_QUALIFIER  200  */
    300000000000ULL, /* ISSUE_RESTRICTED    3000  */
     20000000000ULL, /* REISSUE              200  */
     20000000000ULL, /* REISSUE_RESTRICTED   200  */
        20000000ULL, /* TAG_ADDRESS          0.2  */
        20000000ULL  /* UNTAG_ADDRESS        0.2  */
};

const char * assetBurnAddress(BurnOp op, bool testnet) {
    if (op < 0 || op >= BURN_OP_COUNT) return NULL;
    return testnet ? TESTNET_BURN[op] : MAINNET_BURN[op];
}

uint64_t assetBurnAmountSats(BurnOp op, uint32_t multiplier) {
    if (op < 0 || op >= BURN_OP_COUNT) return 0;
    return BURN_SATS[op] * (uint64_t)multiplier;
}

size_t assetOwnerTokenName(const char * assetName, char * out, size_t cap) {
    if (!assetName || !out) return 0;
    const char * p = assetName;
    if (p[0] == '$') p++;               /* restricted: drop the leading '$' */
    size_t n = strlen(p);
    if (n + 2 > cap) return 0;          /* n chars + '!' + NUL */
    memcpy(out, p, n);
    out[n] = '!';
    out[n + 1] = '\0';
    return n + 1;
}

size_t assetParentName(const char * assetName, char * out, size_t cap) {
    if (!assetName || !out) return 0;
    const char * slash = strchr(assetName, '/');
    if (!slash) return 0;
    size_t n = (size_t)(slash - assetName);
    if (n + 1 > cap) return 0;
    memcpy(out, assetName, n);
    out[n] = '\0';
    return n;
}

size_t assetUniqueName(const char * root, const char * tag, char * out, size_t cap) {
    if (!root || !tag || !out) return 0;
    size_t a = strlen(root), b = strlen(tag);
    if (a + 1 + b + 1 > cap) return 0;
    memcpy(out, root, a);
    out[a] = '#';
    memcpy(out + a + 1, tag, b);
    out[a + 1 + b] = '\0';
    return a + 1 + b;
}
