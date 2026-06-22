#ifndef __UNEURAI_ASSET_H__R3NU8EN25O
#define __UNEURAI_ASSET_H__R3NU8EN25O

#include <stdint.h>
#include <stddef.h>

/*
 * Neurai asset script codec (decode side — phase 1).
 *
 * Neurai is a Ravencoin fork: an asset rides on a normal output by appending an
 * asset marker after the base destination script. The two on-chain shapes are:
 *
 *   Standard op (transfer / issue / owner / reissue):
 *       <baseScript> OP_XNA_ASSET(0xc0) <pushData(payload)> OP_DROP(0x75)
 *     baseScript = P2PKH (25B) | P2SH (23B) | AuthScript/PQ (OP_1 0x20 <32>)
 *     payload    = 4-byte ASCII tag ("rvnt"/"rvnq"/"rvno"/"rvnr") + fields
 *
 *   Null-asset op (qualifier tag/untag, address freeze, verifier, global freeze):
 *       OP_XNA_ASSET ... (no trailing OP_DROP; the destination is embedded)
 *
 * This module is intentionally standalone (it works on raw script bytes, not on
 * the Script class) so it adds zero risk to the existing parse/sign paths and is
 * trivially unit-testable. The encoder and the high-level builders are added in
 * later phases. The byte layout mirrors @neuraiproject/neurai-create-transaction.
 */

/* Longest asset name we accept: 32 (mainnet) / 121 (testnet) chars + NUL. */
#define NEURAI_ASSET_NAME_MAX 128

/* 4-byte ASCII payload tags ("rvn" + op letter). */
extern const uint8_t XNA_TRANSFER_PREFIX[4]; /* "rvnt" */
extern const uint8_t XNA_ISSUE_PREFIX[4];    /* "rvnq" */
extern const uint8_t XNA_OWNER_PREFIX[4];    /* "rvno" */
extern const uint8_t XNA_REISSUE_PREFIX[4];  /* "rvnr" */

enum AssetOp {
    ASSET_NONE = 0,
    ASSET_TRANSFER,            /* rvnt: move an existing asset                 */
    ASSET_ISSUE,               /* rvnq: create a new asset                     */
    ASSET_OWNER,               /* rvno: the "NAME!" ownership token            */
    ASSET_REISSUE,             /* rvnr: mint more / change an existing asset   */
    ASSET_NULL_TAG,            /* address-scoped null asset (qualifier tag /   */
                               /* untag, restricted freeze/unfreeze address)   */
    ASSET_GLOBAL_RESTRICTION,  /* OP_XNA_ASSET OP_RESERVED OP_RESERVED ...      */
    ASSET_VERIFIER             /* OP_XNA_ASSET OP_RESERVED <verifier string>    */
};

struct AssetInfo {
    AssetOp op;

    /* Base destination script (the part BEFORE OP_XNA_ASSET) for standard ops,
     * or the embedded hash20/commitment for null-asset ops. Points INTO the
     * caller's script buffer — valid only while that buffer lives. */
    const uint8_t * base;
    size_t          baseLen;

    /* Asset name, NUL-terminated. For ASSET_OWNER this is the "NAME!" token. */
    char   name[NEURAI_ASSET_NAME_MAX + 1];
    size_t nameLen;

    /* Raw amount (value * 1e8). Set for transfer / issue / reissue. */
    uint64_t amount;

    /* issue / reissue metadata. */
    uint8_t units;        /* divisibility 0..8                         */
    uint8_t reissuable;   /* 0 / 1                                     */
    uint8_t hasIpfs;      /* 0 / 1                                     */
    const uint8_t * ipfs; /* points into the buffer, NULL if none      */
    size_t  ipfsLen;

    /* null-asset / restriction flag (tag=1 / untag=0; freeze 0..3). */
    uint8_t flag;
};

/* Parse `script` as an asset script. On success fills `info` and returns true.
 * Returns false (and leaves info->op == ASSET_NONE) for non-asset scripts. */
bool assetParseScript(const uint8_t * script, size_t scriptLen, AssetInfo * info);

/* Lightweight check: true if the script carries any asset marker. */
bool assetIsAssetScript(const uint8_t * script, size_t scriptLen);

/* ── Encoders (phase 2) ──────────────────────────────────────────────────────
 *
 * All encoders write into a caller-provided buffer and return the number of
 * bytes written, or 0 on overflow / bad input (so they are allocation-free and
 * embedded-friendly). The byte layout matches @neuraiproject/neurai-create-
 * transaction exactly. `ipfs`/`ipfsLen` is the ALREADY-encoded 34-byte data
 * reference (CIDv0 / TXID / raw) or NULL/0 for none — the host resolves the
 * string form; uNeurai only embeds the bytes.
 */

/* Asset payloads (the bytes that go inside the OP_XNA_ASSET pushData). */
size_t assetEncodeTransferPayload(const char * name, uint64_t amountRaw,
                                  uint8_t * out, size_t cap);
size_t assetEncodeIssuePayload(const char * name, uint64_t quantityRaw,
                               uint8_t units, bool reissuable,
                               const uint8_t * ipfs, size_t ipfsLen,
                               uint8_t * out, size_t cap);
size_t assetEncodeOwnerPayload(const char * ownerName, uint8_t * out, size_t cap);
size_t assetEncodeReissuePayload(const char * name, uint64_t quantityRaw,
                                 uint8_t units, bool reissuable,
                                 const uint8_t * ipfs, size_t ipfsLen,
                                 uint8_t * out, size_t cap);

/* Wrap a base destination script + payload into a full asset scriptPubkey:
 *     <base> OP_XNA_ASSET pushData(payload) OP_DROP
 * `base` is the raw destination script (P2PKH 25B, P2SH 23B or AuthScript 34B). */
size_t assetWrapScript(const uint8_t * base, size_t baseLen,
                       const uint8_t * payload, size_t payloadLen,
                       uint8_t * out, size_t cap);

/* All-in-one: base script + fields → full asset scriptPubkey. */
size_t assetEncodeTransferScript(const uint8_t * base, size_t baseLen,
                                 const char * name, uint64_t amountRaw,
                                 uint8_t * out, size_t cap);
size_t assetEncodeIssueScript(const uint8_t * base, size_t baseLen,
                              const char * name, uint64_t quantityRaw,
                              uint8_t units, bool reissuable,
                              const uint8_t * ipfs, size_t ipfsLen,
                              uint8_t * out, size_t cap);
size_t assetEncodeOwnerScript(const uint8_t * base, size_t baseLen,
                              const char * ownerName, uint8_t * out, size_t cap);
size_t assetEncodeReissueScript(const uint8_t * base, size_t baseLen,
                                const char * name, uint64_t quantityRaw,
                                uint8_t units, bool reissuable,
                                const uint8_t * ipfs, size_t ipfsLen,
                                uint8_t * out, size_t cap);

#endif /* __UNEURAI_ASSET_H__R3NU8EN25O */
