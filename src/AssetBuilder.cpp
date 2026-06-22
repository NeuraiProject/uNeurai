#include "AssetBuilder.h"
#include <string.h>

/* Scratch sizes: an asset scriptPubkey is base(<=34) + marker(1) + pushdata
 * header(<=3) + payload(<= name 128 + 64) + OP_DROP(1). 320 is comfortable. */
#define ASSET_SCRIPT_SCRATCH 320

/* Copy the destination script bytes for `address` (legacy base58 or PQ bech32m).
 * Returns the base length, or 0 if the address is invalid / does not fit. */
static size_t baseFromAddress(const char * address, uint8_t * buf, size_t cap) {
    if (!address) return 0;
    Script base(address);
    if (base.scriptLen == 0 || base.scriptLen > cap) return 0;
    memcpy(buf, base.scriptArray, base.scriptLen);
    return base.scriptLen;
}

/* Append a TxOut from raw script bytes; false on empty script. */
static bool addScriptOut(Tx & tx, uint64_t value, const uint8_t * script, size_t len) {
    if (len == 0) return false;
    Script s(script, len);
    TxOut out(value, s);
    tx.addOutput(out);
    return true;
}

bool assetAddXnaOutput(Tx & tx, const char * address, uint64_t valueSats) {
    if (!address) return false;
    Script s(address);
    if (s.scriptLen == 0) return false;
    TxOut out(valueSats, s);
    tx.addOutput(out);
    return true;
}

bool assetAddTransferOutput(Tx & tx, const char * address,
                            const char * assetName, uint64_t amountRaw) {
    uint8_t base[64];
    size_t bl = baseFromAddress(address, base, sizeof(base));
    if (!bl) return false;
    uint8_t scr[ASSET_SCRIPT_SCRATCH];
    size_t n = assetEncodeTransferScript(base, bl, assetName, amountRaw, scr, sizeof(scr));
    return addScriptOut(tx, 0, scr, n);
}

bool assetAddIssueOutput(Tx & tx, const char * address, const char * assetName,
                         uint64_t quantityRaw, uint8_t units, bool reissuable,
                         const uint8_t * ipfs, size_t ipfsLen) {
    uint8_t base[64];
    size_t bl = baseFromAddress(address, base, sizeof(base));
    if (!bl) return false;
    uint8_t scr[ASSET_SCRIPT_SCRATCH];
    size_t n = assetEncodeIssueScript(base, bl, assetName, quantityRaw, units, reissuable,
                                      ipfs, ipfsLen, scr, sizeof(scr));
    return addScriptOut(tx, 0, scr, n);
}

bool assetAddOwnerIssueOutput(Tx & tx, const char * address, const char * ownerName) {
    uint8_t base[64];
    size_t bl = baseFromAddress(address, base, sizeof(base));
    if (!bl) return false;
    uint8_t scr[ASSET_SCRIPT_SCRATCH];
    size_t n = assetEncodeOwnerScript(base, bl, ownerName, scr, sizeof(scr));
    return addScriptOut(tx, 0, scr, n);
}

bool assetAddReissueOutput(Tx & tx, const char * address, const char * assetName,
                           uint64_t quantityRaw, uint8_t units, bool reissuable,
                           const uint8_t * ipfs, size_t ipfsLen) {
    uint8_t base[64];
    size_t bl = baseFromAddress(address, base, sizeof(base));
    if (!bl) return false;
    uint8_t scr[ASSET_SCRIPT_SCRATCH];
    size_t n = assetEncodeReissueScript(base, bl, assetName, quantityRaw, units, reissuable,
                                        ipfs, ipfsLen, scr, sizeof(scr));
    return addScriptOut(tx, 0, scr, n);
}

/* burn + change envelope, mirroring appendXnaEnvelope(). */
static bool addEnvelope(Tx & tx, const char * burnAddress, uint64_t burnSats,
                        const char * changeAddress, uint64_t changeSats) {
    if (burnAddress && burnSats > 0) {
        if (!assetAddXnaOutput(tx, burnAddress, burnSats)) return false;
    }
    if (changeAddress && changeSats > 0) {
        if (!assetAddXnaOutput(tx, changeAddress, changeSats)) return false;
    }
    return true;
}

bool assetBuildIssue(Tx & tx,
                     const char * burnAddress, uint64_t burnSats,
                     const char * changeAddress, uint64_t changeSats,
                     const char * toAddress, const char * assetName,
                     uint64_t quantityRaw, uint8_t units, bool reissuable,
                     const uint8_t * ipfs, size_t ipfsLen,
                     const char * ownerTokenAddress) {
    if (!addEnvelope(tx, burnAddress, burnSats, changeAddress, changeSats)) return false;

    char ownerName[NEURAI_ASSET_NAME_MAX + 2];
    if (!assetOwnerTokenName(assetName, ownerName, sizeof(ownerName))) return false;
    if (!assetAddOwnerIssueOutput(tx, ownerTokenAddress ? ownerTokenAddress : toAddress, ownerName))
        return false;

    return assetAddIssueOutput(tx, toAddress, assetName, quantityRaw, units, reissuable, ipfs, ipfsLen);
}

bool assetBuildReissue(Tx & tx,
                       const char * burnAddress, uint64_t burnSats,
                       const char * changeAddress, uint64_t changeSats,
                       const char * ownerChangeAddress, const char * toAddress,
                       const char * assetName, uint64_t quantityRaw,
                       uint8_t units, bool reissuable,
                       const uint8_t * ipfs, size_t ipfsLen) {
    if (!addEnvelope(tx, burnAddress, burnSats, changeAddress, changeSats)) return false;

    char ownerName[NEURAI_ASSET_NAME_MAX + 2];
    if (!assetOwnerTokenName(assetName, ownerName, sizeof(ownerName))) return false;
    /* The owner token is moved back to ourselves as a transfer of OWNER amount. */
    if (!assetAddTransferOutput(tx, ownerChangeAddress, ownerName, ASSET_OWNER_AMOUNT))
        return false;

    return assetAddReissueOutput(tx, toAddress, assetName, quantityRaw, units, reissuable, ipfs, ipfsLen);
}

bool assetBuildTransfer(Tx & tx, const char * toAddress,
                        const char * assetName, uint64_t amountRaw) {
    return assetAddTransferOutput(tx, toAddress, assetName, amountRaw);
}
