#ifndef __UNEURAI_ASSETBUILDER_H__R3NU8EN25O
#define __UNEURAI_ASSETBUILDER_H__R3NU8EN25O

#include "Neurai.h"
#include "Asset.h"
#include "AssetConstants.h"

/*
 * High-level asset output assembly: append the correct, correctly-ordered
 * TxOut set for each operation to a Tx, mirroring
 * @neuraiproject/neurai-create-transaction (builders.ts). All asset outputs
 * carry value 0 (the asset amount lives in the script); only the burn and
 * change outputs carry XNA. These helpers do NOT select UTXOs or compute fees
 * — the caller supplies inputs, burn/change addresses and amounts (use
 * AssetConstants for the canonical burn address/amount).
 *
 * Every function returns true on success and false on a bad address / encode
 * overflow (in which case the partially-built tx should be discarded).
 * `ipfs`/`ipfsLen` is the already-encoded 34-byte data reference, or NULL/0.
 *
 * NIP-040: every function that emits a transfer / issue / owner / reissue
 * output takes a trailing `marker` (ASSET_MARKER_RVN | ASSET_MARKER_XNA) that
 * selects the payload marker. It defaults to ASSET_MARKER_RVN, like
 * neurai-create-transaction; pass the value the node reports in
 * `getblockchaininfo.asset_marker` (today: "rvn" on mainnet, "xna" on testnet).
 * Null-asset outputs (tag / freeze / verifier / global) carry no marker.
 */

/* ── Single outputs (append one TxOut to `tx`) ───────────────────────────── */

/* Plain XNA payment / burn / change. */
bool assetAddXnaOutput(Tx & tx, const char * address, uint64_t valueSats);

/* Asset transfer (<marker>t), value 0. */
bool assetAddTransferOutput(Tx & tx, const char * address,
                            const char * assetName, uint64_t amountRaw,
                            AssetMarker marker = ASSET_MARKER_DEFAULT);

/* New-asset issue (<marker>q), value 0. */
bool assetAddIssueOutput(Tx & tx, const char * address, const char * assetName,
                         uint64_t quantityRaw, uint8_t units, bool reissuable,
                         const uint8_t * ipfs, size_t ipfsLen,
                         AssetMarker marker = ASSET_MARKER_DEFAULT);

/* Owner token issue (<marker>o), value 0. */
bool assetAddOwnerIssueOutput(Tx & tx, const char * address, const char * ownerName,
                              AssetMarker marker = ASSET_MARKER_DEFAULT);

/* Reissue (<marker>r), value 0. */
bool assetAddReissueOutput(Tx & tx, const char * address, const char * assetName,
                           uint64_t quantityRaw, uint8_t units, bool reissuable,
                           const uint8_t * ipfs, size_t ipfsLen,
                           AssetMarker marker = ASSET_MARKER_DEFAULT);

/* ── Full operations (append the whole ordered output set) ───────────────── */

/* ISSUE (root): burn, [change], owner!, issue. `ownerTokenAddress` may be NULL
 * to default to `toAddress`. Pass burnAddress=NULL or burnSats=0 / changeSats=0
 * to skip those outputs. */
bool assetBuildIssue(Tx & tx,
                     const char * burnAddress, uint64_t burnSats,
                     const char * changeAddress, uint64_t changeSats,
                     const char * toAddress, const char * assetName,
                     uint64_t quantityRaw, uint8_t units, bool reissuable,
                     const uint8_t * ipfs, size_t ipfsLen,
                     const char * ownerTokenAddress,
                     AssetMarker marker = ASSET_MARKER_DEFAULT);

/* REISSUE: burn, [change], owner-token transfer, reissue. */
bool assetBuildReissue(Tx & tx,
                       const char * burnAddress, uint64_t burnSats,
                       const char * changeAddress, uint64_t changeSats,
                       const char * ownerChangeAddress, const char * toAddress,
                       const char * assetName, uint64_t quantityRaw,
                       uint8_t units, bool reissuable,
                       const uint8_t * ipfs, size_t ipfsLen,
                       AssetMarker marker = ASSET_MARKER_DEFAULT);

/* Plain asset transfer (one transfer output). */
bool assetBuildTransfer(Tx & tx, const char * toAddress,
                        const char * assetName, uint64_t amountRaw,
                        AssetMarker marker = ASSET_MARKER_DEFAULT);

/* ── Null-asset single outputs (phase 4) ─────────────────────────────────── */

/* Qualifier tag / untag on `address`. */
bool assetAddNullTagOutput(Tx & tx, const char * address,
                           const char * qualifierName, bool tag);
/* Address freeze / unfreeze (freezeFlag 0 / 1). */
bool assetAddNullRestrictionOutput(Tx & tx, const char * address,
                                   const char * assetName, uint8_t freezeFlag);
/* Verifier string output (the string is normalised internally). */
bool assetAddVerifierOutput(Tx & tx, const char * verifierString);
/* Global asset freeze / unfreeze (freezeFlag 2 / 3). */
bool assetAddGlobalRestrictionOutput(Tx & tx, const char * assetName, uint8_t freezeFlag);

/* ── Null-asset / restricted operations (append the whole output set) ─────── */

/* ISSUE RESTRICTED: burn, [change], verifier, owner-token transfer, issue. */
bool assetBuildIssueRestricted(Tx & tx,
                               const char * burnAddress, uint64_t burnSats,
                               const char * changeAddress, uint64_t changeSats,
                               const char * ownerChangeAddress, const char * toAddress,
                               const char * assetName, const char * verifierString,
                               uint64_t quantityRaw, uint8_t units, bool reissuable,
                               const uint8_t * ipfs, size_t ipfsLen,
                               AssetMarker marker = ASSET_MARKER_DEFAULT);

/* QUALIFIER TAG / UNTAG: burn, [change], qualifier transfer, one tag output per
 * target address. `targetAddresses` is an array of `count` C-strings. */
bool assetBuildQualifierTag(Tx & tx,
                            const char * burnAddress, uint64_t burnSats,
                            const char * changeAddress, uint64_t changeSats,
                            const char * qualifierChangeAddress, const char * qualifierName,
                            uint64_t qualifierChangeAmountRaw,
                            const char * const * targetAddresses, size_t count, bool tag,
                            AssetMarker marker = ASSET_MARKER_DEFAULT);

/* FREEZE / UNFREEZE ADDRESSES: [change], owner-token transfer, one restriction
 * output per target address (no burn). */
bool assetBuildFreezeAddresses(Tx & tx,
                               const char * changeAddress, uint64_t changeSats,
                               const char * ownerChangeAddress, const char * assetName,
                               const char * const * targetAddresses, size_t count, bool freeze,
                               AssetMarker marker = ASSET_MARKER_DEFAULT);

/* FREEZE / UNFREEZE ASSET (global): [change], owner-token transfer, global
 * restriction (no burn). */
bool assetBuildFreezeAsset(Tx & tx,
                           const char * changeAddress, uint64_t changeSats,
                           const char * ownerChangeAddress, const char * assetName, bool freeze,
                           AssetMarker marker = ASSET_MARKER_DEFAULT);

/* ── More issue variants ─────────────────────────────────────────────────── */

/* ISSUE SUB-ASSET ("PARENT/SUB"): burn, [change], parent-owner transfer,
 * sub-owner issue, sub issue. `assetName` must contain '/'. `parentOwnerAddress`
 * / `ownerTokenAddress` may be NULL (default to changeAddress/toAddress). */
bool assetBuildIssueSub(Tx & tx,
                        const char * burnAddress, uint64_t burnSats,
                        const char * changeAddress, uint64_t changeSats,
                        const char * parentOwnerAddress, const char * ownerTokenAddress,
                        const char * toAddress, const char * assetName,
                        uint64_t quantityRaw, uint8_t units, bool reissuable,
                        const uint8_t * ipfs, size_t ipfsLen,
                        AssetMarker marker = ASSET_MARKER_DEFAULT);

/* ISSUE UNIQUE (NFTs): burn, [change], root-owner transfer, then one issue
 * output per tag ("ROOT#tag", qty 1, units 0, non-reissuable). `ipfsArr` /
 * `ipfsLens` may be NULL (no metadata) or per-tag arrays of length `count`
 * (a NULL entry => that NFT has no ipfs). */
bool assetBuildIssueUnique(Tx & tx,
                           const char * burnAddress, uint64_t burnSats,
                           const char * changeAddress, uint64_t changeSats,
                           const char * ownerTokenAddress, const char * toAddress,
                           const char * rootName,
                           const char * const * tags, size_t count,
                           const uint8_t * const * ipfsArr, const size_t * ipfsLens,
                           AssetMarker marker = ASSET_MARKER_DEFAULT);

/* ISSUE QUALIFIER ("#NAME" or "#ROOT/SUB"): burn, [change], [parent-qualifier
 * transfer if sub], issue (units 0, non-reissuable). `changeQuantityRaw` is the
 * parent-qualifier transfer amount (0 => ASSET_OWNER_AMOUNT). */
bool assetBuildIssueQualifier(Tx & tx,
                              const char * burnAddress, uint64_t burnSats,
                              const char * changeAddress, uint64_t changeSats,
                              const char * rootChangeAddress, const char * toAddress,
                              const char * assetName, uint64_t quantityRaw,
                              uint64_t changeQuantityRaw,
                              const uint8_t * ipfs, size_t ipfsLen,
                              AssetMarker marker = ASSET_MARKER_DEFAULT);

#endif /* __UNEURAI_ASSETBUILDER_H__R3NU8EN25O */
