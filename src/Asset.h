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
 *     payload    = 3-byte marker ("rvn" | "xna") + op letter (t/q/o/r) + fields
 *
 *   NIP-040 (asset marker migration): historic outputs carry the Ravencoin
 *   marker "rvn"; from the activation height the node only accepts "xna" on
 *   new outputs and rejects "rvn" (bad-txns-legacy-asset-marker-after-nip040).
 *   Testnet activated at block 303000; mainnet has no scheduled height yet.
 *   The parser accepts BOTH markers (legacy UTXOs stay valid and spendable) and
 *   reports which one it found in AssetInfo.marker. The encoders take an
 *   explicit AssetMarker; this library never infers it from the network — the
 *   node publishes the marker required for the next block in
 *   `getblockchaininfo.asset_marker` and the host passes it through. The
 *   default is ASSET_MARKER_RVN, mirroring neurai-create-transaction.
 *
 *   Null-asset op (qualifier tag/untag, address freeze, verifier, global freeze):
 *       OP_XNA_ASSET ... (no trailing OP_DROP; the destination is embedded)
 *
 * This module is intentionally standalone (it works on raw script bytes, not on
 * the Script class) so it adds zero risk to the existing parse/sign paths and is
 * trivially unit-testable. The encoder and the high-level builders are added in
 * later phases. The byte layout mirrors @neuraiproject/neurai-create-transaction.
 */

/* Longest asset name we accept: 31 (mainnet) / 121 (testnet) chars + NUL. */
#define NEURAI_ASSET_NAME_MAX 128

/* NIP-040 asset payload marker: the 3 ASCII bytes that open every standard
 * asset payload, followed by the op letter. */
enum AssetMarker {
    ASSET_MARKER_RVN = 0,   /* "rvn": legacy (Ravencoin) marker, mainnet today  */
    ASSET_MARKER_XNA = 1    /* "xna": NIP-040 marker, testnet since block 303000 */
};
#define ASSET_MARKER_DEFAULT ASSET_MARKER_RVN

/* The 3 marker bytes / name ("rvn" / "xna"); NULL for an unknown value. */
const uint8_t * assetMarkerBytes(AssetMarker marker);
const char *    assetMarkerName(AssetMarker marker);

/* Legacy 4-byte payload tags ("rvn" + op letter), kept for existing callers.
 * New code should use assetMarkerPrefix(), which handles both markers. */
extern const uint8_t XNA_TRANSFER_PREFIX[4]; /* "rvnt" */
extern const uint8_t XNA_ISSUE_PREFIX[4];    /* "rvnq" */
extern const uint8_t XNA_OWNER_PREFIX[4];    /* "rvno" */
extern const uint8_t XNA_REISSUE_PREFIX[4];  /* "rvnr" */

enum AssetOp {
    ASSET_NONE = 0,
    ASSET_TRANSFER,            /* <marker>t: move an existing asset                */
    ASSET_ISSUE,               /* <marker>q: create a new asset                    */
    ASSET_OWNER,               /* <marker>o: the "NAME!" ownership token           */
    ASSET_REISSUE,             /* <marker>r: mint more / change an existing asset  */
    ASSET_NULL_TAG,            /* address-scoped null asset (qualifier tag /   */
                               /* untag, restricted freeze/unfreeze address)   */
    ASSET_GLOBAL_RESTRICTION,  /* OP_XNA_ASSET OP_RESERVED OP_RESERVED ...      */
    ASSET_VERIFIER             /* OP_XNA_ASSET OP_RESERVED <verifier string>    */
};

struct AssetInfo {
    AssetOp op;

    /* Marker found in the payload (standard ops only). Null-asset scripts
     * carry no marker bytes; for them this stays ASSET_MARKER_RVN. */
    AssetMarker marker;

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

/* Write the 4-byte payload prefix (<marker 3B> <op letter>) for a standard op
 * (mirror of the node's AppendAssetMarkerPrefix). Returns 4, or 0 for an
 * unknown marker / non-standard op. */
size_t assetMarkerPrefix(AssetMarker marker, AssetOp op, uint8_t out[4]);

/* ── Encoders (phase 2) ──────────────────────────────────────────────────────
 *
 * All encoders write into a caller-provided buffer and return the number of
 * bytes written, or 0 on overflow / bad input (so they are allocation-free and
 * embedded-friendly). The byte layout matches @neuraiproject/neurai-create-
 * transaction exactly. `ipfs`/`ipfsLen` is the ALREADY-encoded 34-byte data
 * reference (CIDv0 / TXID / raw) or NULL/0 for none — the host resolves the
 * string form; uNeurai only embeds the bytes.
 *
 * `marker` selects the NIP-040 payload marker (see the header comment). It
 * defaults to ASSET_MARKER_RVN like neurai-create-transaction; pass
 * ASSET_MARKER_XNA where the node reports `asset_marker: "xna"` (testnet today).
 */

/* Asset payloads (the bytes that go inside the OP_XNA_ASSET pushData). */
size_t assetEncodeTransferPayload(const char * name, uint64_t amountRaw,
                                  uint8_t * out, size_t cap,
                                  AssetMarker marker = ASSET_MARKER_DEFAULT);
size_t assetEncodeIssuePayload(const char * name, uint64_t quantityRaw,
                               uint8_t units, bool reissuable,
                               const uint8_t * ipfs, size_t ipfsLen,
                               uint8_t * out, size_t cap,
                               AssetMarker marker = ASSET_MARKER_DEFAULT);
size_t assetEncodeOwnerPayload(const char * ownerName, uint8_t * out, size_t cap,
                               AssetMarker marker = ASSET_MARKER_DEFAULT);
size_t assetEncodeReissuePayload(const char * name, uint64_t quantityRaw,
                                 uint8_t units, bool reissuable,
                                 const uint8_t * ipfs, size_t ipfsLen,
                                 uint8_t * out, size_t cap,
                                 AssetMarker marker = ASSET_MARKER_DEFAULT);

/* Wrap a base destination script + payload into a full asset scriptPubkey:
 *     <base> OP_XNA_ASSET pushData(payload) OP_DROP
 * `base` is the raw destination script (P2PKH 25B, P2SH 23B or AuthScript 34B). */
size_t assetWrapScript(const uint8_t * base, size_t baseLen,
                       const uint8_t * payload, size_t payloadLen,
                       uint8_t * out, size_t cap);

/* All-in-one: base script + fields → full asset scriptPubkey. */
size_t assetEncodeTransferScript(const uint8_t * base, size_t baseLen,
                                 const char * name, uint64_t amountRaw,
                                 uint8_t * out, size_t cap,
                                 AssetMarker marker = ASSET_MARKER_DEFAULT);
size_t assetEncodeIssueScript(const uint8_t * base, size_t baseLen,
                              const char * name, uint64_t quantityRaw,
                              uint8_t units, bool reissuable,
                              const uint8_t * ipfs, size_t ipfsLen,
                              uint8_t * out, size_t cap,
                              AssetMarker marker = ASSET_MARKER_DEFAULT);
size_t assetEncodeOwnerScript(const uint8_t * base, size_t baseLen,
                              const char * ownerName, uint8_t * out, size_t cap,
                              AssetMarker marker = ASSET_MARKER_DEFAULT);
size_t assetEncodeReissueScript(const uint8_t * base, size_t baseLen,
                                const char * name, uint64_t quantityRaw,
                                uint8_t units, bool reissuable,
                                const uint8_t * ipfs, size_t ipfsLen,
                                uint8_t * out, size_t cap,
                                AssetMarker marker = ASSET_MARKER_DEFAULT);

/* ── Null-asset encoders (phase 4) ───────────────────────────────────────────
 *
 * These carry no NIP-040 marker bytes (unaffected by the rvn/xna migration).
 * They have no trailing OP_DROP; the destination is embedded as a raw hash:
 *   address-scoped: OP_XNA_ASSET [OP_1] pushData(hash20|commitment32) pushData(name+flag)
 *   verifier:       OP_XNA_ASSET OP_RESERVED pushData(serializeString(verifier))
 *   global:         OP_XNA_ASSET OP_RESERVED OP_RESERVED pushData(name+flag)
 *
 * `base` is the destination's standard script (P2PKH 25B or AuthScript 34B); the
 * 20-byte hash / 32-byte commitment is extracted from it (P2SH is not used for
 * null-asset destinations, matching the TS encoder).
 */

/* Qualifier tag / untag (tag => flag 1, untag => flag 0). */
size_t assetEncodeNullTagScript(const uint8_t * base, size_t baseLen,
                                const char * qualifierName, bool tag,
                                uint8_t * out, size_t cap);

/* Address freeze / unfreeze (restricted assets). freezeFlag: 0 unfreeze, 1 freeze. */
size_t assetEncodeNullRestrictionScript(const uint8_t * base, size_t baseLen,
                                        const char * assetName, uint8_t freezeFlag,
                                        uint8_t * out, size_t cap);

/* Verifier string (restricted asset setup). Pass the ALREADY-normalised string
 * (no whitespace, no '#'); see assetNormalizeVerifier in AssetConstants. */
size_t assetEncodeVerifierScript(const char * verifierString, uint8_t * out, size_t cap);

/* Global freeze / unfreeze of an asset. freezeFlag: 2 unfreeze, 3 freeze. */
size_t assetEncodeGlobalRestrictionScript(const char * assetName, uint8_t freezeFlag,
                                          uint8_t * out, size_t cap);

#endif /* __UNEURAI_ASSET_H__R3NU8EN25O */
