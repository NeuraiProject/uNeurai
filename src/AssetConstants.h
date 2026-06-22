#ifndef __UNEURAI_ASSETCONSTANTS_H__R3NU8EN25O
#define __UNEURAI_ASSETCONSTANTS_H__R3NU8EN25O

#include <stdint.h>
#include <stddef.h>

/*
 * Neurai asset network constants: burn (fee) addresses and amounts per
 * operation, fixed asset amounts and the small name helpers. Values mirror
 * @neuraiproject/neurai-create-transaction (constants.ts) exactly, for Mainnet
 * and Testnet. Pure data + string helpers — no dependency on the rest of the
 * library, so it stays trivially testable.
 */

/* Fixed raw amounts (value * 1e8). */
#define ASSET_OWNER_AMOUNT       100000000ULL  /* the "NAME!" owner token   */
#define ASSET_UNIQUE_AMOUNT      100000000ULL  /* one NFT (qty 1)           */
#define ASSET_UNIQUE_UNITS       0
#define ASSET_UNIQUE_REISSUABLE  0

/* Operations that burn a fee to a per-network burn address. */
enum BurnOp {
    BURN_ISSUE_ROOT = 0,
    BURN_ISSUE_SUB,
    BURN_ISSUE_UNIQUE,
    BURN_ISSUE_DEPIN,
    BURN_ISSUE_MSGCHANNEL,
    BURN_ISSUE_QUALIFIER,
    BURN_ISSUE_SUB_QUALIFIER,
    BURN_ISSUE_RESTRICTED,
    BURN_REISSUE,
    BURN_REISSUE_RESTRICTED,
    BURN_TAG_ADDRESS,
    BURN_UNTAG_ADDRESS,
    BURN_OP_COUNT
};

/* Burn address for an operation on the given network (NULL if op out of range).
 * The returned pointer is a static string — do not free. */
const char * assetBurnAddress(BurnOp op, bool testnet);

/* Burn amount in satoshis. `multiplier` scales per-item operations
 * (per NFT for ISSUE_UNIQUE, per address for TAG/UNTAG). */
uint64_t assetBurnAmountSats(BurnOp op, uint32_t multiplier /* = 1 */);

/* Owner token name: "$NAME" -> "NAME!", otherwise NAME + "!". Writes a
 * NUL-terminated string; returns its length, or 0 on overflow. */
size_t assetOwnerTokenName(const char * assetName, char * out, size_t cap);

/* Parent name (the part before '/'). Returns length, or 0 if there is no
 * parent or it does not fit. */
size_t assetParentName(const char * assetName, char * out, size_t cap);

/* Build "ROOT#TAG". Returns length, or 0 on overflow. */
size_t assetUniqueName(const char * root, const char * tag, char * out, size_t cap);

#endif /* __UNEURAI_ASSETCONSTANTS_H__R3NU8EN25O */
