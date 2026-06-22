#include "Asset.h"
#include "Conversion.h"
#include "OpCodes.h"
#include <string.h>

const uint8_t XNA_TRANSFER_PREFIX[4] = { 0x72, 0x76, 0x6e, 0x74 }; /* "rvnt" */
const uint8_t XNA_ISSUE_PREFIX[4]    = { 0x72, 0x76, 0x6e, 0x71 }; /* "rvnq" */
const uint8_t XNA_OWNER_PREFIX[4]    = { 0x72, 0x76, 0x6e, 0x6f }; /* "rvno" */
const uint8_t XNA_REISSUE_PREFIX[4]  = { 0x72, 0x76, 0x6e, 0x72 }; /* "rvnr" */

/* ── Low-level readers ──────────────────────────────────────────────────────
 * All bounds-checked; they never read past `len`. Offsets are absolute into the
 * original script buffer so AssetInfo.base/ipfs can point straight into it.
 */

/* Read one minimal pushdata element starting at `off`.
 * Fills the data span [*dataOff, *dataOff+*dataLen) and the next offset.
 * Supports direct pushes (0x01..0x4b), OP_PUSHDATA1 and OP_PUSHDATA2. */
static bool readPush(const uint8_t * s, size_t len, size_t off,
                     size_t * dataOff, size_t * dataLen, size_t * next) {
    if (off >= len) return false;
    uint8_t op = s[off];
    size_t dlen, doff;
    if (op < OP_PUSHDATA1) {            /* 0x00..0x4b: length is the opcode */
        dlen = op;
        doff = off + 1;
    } else if (op == OP_PUSHDATA1) {    /* 0x4c <len1> */
        if (off + 2 > len) return false;
        dlen = s[off + 1];
        doff = off + 2;
    } else if (op == OP_PUSHDATA2) {    /* 0x4d <len2 LE> */
        if (off + 3 > len) return false;
        dlen = (size_t)s[off + 1] | ((size_t)s[off + 2] << 8);
        doff = off + 3;
    } else {
        return false;                   /* OP_PUSHDATA4 or a non-push opcode */
    }
    if (doff + dlen > len) return false;
    *dataOff = doff;
    *dataLen = dlen;
    *next = doff + dlen;
    return true;
}

/* Read a serialized string (Bitcoin varint length + raw bytes) at `off` into a
 * NUL-terminated buffer. Rejects names that do not fit (incl. the terminator). */
static bool readVarStr(const uint8_t * s, size_t len, size_t off,
                       char * out, size_t outCap, size_t * outLen, size_t * next) {
    if (off >= len) return false;
    uint8_t first = s[off];
    uint64_t n;
    size_t consumed;
    if (first < 0xfd)      { n = first;                            consumed = 1; }
    else if (first == 0xfd){ if (off + 3 > len) return false; n = littleEndianToInt(s + off + 1, 2); consumed = 3; }
    else if (first == 0xfe){ if (off + 5 > len) return false; n = littleEndianToInt(s + off + 1, 4); consumed = 5; }
    else                   { if (off + 9 > len) return false; n = littleEndianToInt(s + off + 1, 8); consumed = 9; }

    size_t strOff = off + consumed;
    if (strOff + n > len) return false;
    if (n + 1 > outCap) return false;          /* leave room for the NUL */
    memcpy(out, s + strOff, (size_t)n);
    out[n] = '\0';
    *outLen = (size_t)n;
    *next = strOff + (size_t)n;
    return true;
}

/* Length of a leading standard destination script, or 0 if none matches.
 * Mirrors Script::type() shapes so baseScript().address() decodes cleanly. */
static size_t leadingBaseLen(const uint8_t * s, size_t len) {
    /* P2PKH: OP_DUP OP_HASH160 0x14 <20> OP_EQUALVERIFY OP_CHECKSIG */
    if (len >= 25 && s[0] == OP_DUP && s[1] == OP_HASH160 && s[2] == 20 &&
        s[23] == OP_EQUALVERIFY && s[24] == OP_CHECKSIG) return 25;
    /* P2SH: OP_HASH160 0x14 <20> OP_EQUAL */
    if (len >= 23 && s[0] == OP_HASH160 && s[1] == 20 && s[22] == OP_EQUAL) return 23;
    /* AuthScript (witness v1 / PQ): OP_1 0x20 <32> */
    if (len >= 34 && s[0] == OP_1 && s[1] == 32) return 34;
    /* P2WPKH: 0x00 0x14 <20> */
    if (len >= 22 && s[0] == OP_0 && s[1] == 20) return 22;
    /* P2WSH: 0x00 0x20 <32> */
    if (len >= 34 && s[0] == OP_0 && s[1] == 32) return 34;
    return 0;
}

static void resetInfo(AssetInfo * info) {
    info->op = ASSET_NONE;
    info->base = NULL;     info->baseLen = 0;
    info->name[0] = '\0';  info->nameLen = 0;
    info->amount = 0;
    info->units = 0; info->reissuable = 0; info->hasIpfs = 0;
    info->ipfs = NULL; info->ipfsLen = 0;
    info->flag = 0;
}

/* Classify + parse a standard payload (4-byte tag + fields). */
static bool parsePayload(const uint8_t * p, size_t plen, AssetInfo * info) {
    if (plen < 4) return false;
    if      (memcmp(p, XNA_TRANSFER_PREFIX, 4) == 0) info->op = ASSET_TRANSFER;
    else if (memcmp(p, XNA_ISSUE_PREFIX,    4) == 0) info->op = ASSET_ISSUE;
    else if (memcmp(p, XNA_OWNER_PREFIX,    4) == 0) info->op = ASSET_OWNER;
    else if (memcmp(p, XNA_REISSUE_PREFIX,  4) == 0) info->op = ASSET_REISSUE;
    else return false;

    size_t off = 4;
    if (!readVarStr(p, plen, off, info->name, sizeof(info->name), &info->nameLen, &off))
        return false;

    if (info->op == ASSET_OWNER) {
        return true;                       /* owner token: name only */
    }

    if (off + 8 > plen) return false;      /* amount / quantity (u64LE) */
    info->amount = littleEndianToInt(p + off, 8);
    off += 8;

    if (info->op == ASSET_TRANSFER) {
        if (off < plen) { info->hasIpfs = 1; info->ipfs = p + off; info->ipfsLen = plen - off; }
        return true;
    }
    if (info->op == ASSET_ISSUE) {
        if (off + 3 > plen) return false;  /* units, reissuable, hasIpfs */
        info->units      = p[off++];
        info->reissuable = p[off++];
        info->hasIpfs    = p[off++];
        if (info->hasIpfs && off < plen) { info->ipfs = p + off; info->ipfsLen = plen - off; }
        return true;
    }
    /* ASSET_REISSUE: units, reissuable, optional ipfs (no hasIpfs flag byte) */
    if (off + 2 > plen) return false;
    info->units      = p[off++];
    info->reissuable = p[off++];
    if (off < plen) { info->hasIpfs = 1; info->ipfs = p + off; info->ipfsLen = plen - off; }
    return true;
}

/* Parse a null-asset / verifier / global-restriction script (starts with
 * OP_XNA_ASSET, no trailing OP_DROP). Phase-1: classify and read name+flag. */
static bool parseNullAsset(const uint8_t * s, size_t len, AssetInfo * info) {
    /* global restriction: OP_XNA_ASSET OP_RESERVED OP_RESERVED pushData(name+flag) */
    if (len >= 3 && s[1] == OP_RESERVED && s[2] == OP_RESERVED) {
        info->op = ASSET_GLOBAL_RESTRICTION;
        size_t dOff, dLen, nx;
        if (!readPush(s, len, 3, &dOff, &dLen, &nx) || dLen < 1) return false;
        size_t nameOff;
        if (!readVarStr(s, dOff + dLen, dOff, info->name, sizeof(info->name), &info->nameLen, &nameOff))
            return false;
        info->flag = s[dOff + dLen - 1];
        return true;
    }
    /* verifier string: OP_XNA_ASSET OP_RESERVED pushData(serializeString(verifier)) */
    if (len >= 2 && s[1] == OP_RESERVED) {
        info->op = ASSET_VERIFIER;
        size_t dOff, dLen, nx, nameOff;
        if (!readPush(s, len, 2, &dOff, &dLen, &nx)) return false;
        readVarStr(s, dOff + dLen, dOff, info->name, sizeof(info->name), &info->nameLen, &nameOff);
        return true;
    }
    /* address-scoped null asset (tag/untag, freeze/unfreeze address):
     *   OP_XNA_ASSET [OP_1] pushData(dest) pushData(name+flag) */
    size_t o = 1;
    if (len >= 2 && s[1] == OP_1) o = 2;     /* AuthScript destination */
    size_t destOff, destLen, afterDest;
    if (!readPush(s, len, o, &destOff, &destLen, &afterDest)) return false;
    info->base = s + destOff;
    info->baseLen = destLen;

    size_t pOff, pLen, nx;
    if (!readPush(s, len, afterDest, &pOff, &pLen, &nx) || pLen < 1) return false;
    size_t nameOff;
    if (!readVarStr(s, pOff + pLen, pOff, info->name, sizeof(info->name), &info->nameLen, &nameOff))
        return false;
    info->flag = s[pOff + pLen - 1];
    info->op = ASSET_NULL_TAG;
    return true;
}

bool assetParseScript(const uint8_t * script, size_t scriptLen, AssetInfo * info) {
    if (!info) return false;
    resetInfo(info);
    if (!script || scriptLen < 2) return false;

    /* Standard op: <base> OP_XNA_ASSET pushData(payload) OP_DROP */
    size_t bl = leadingBaseLen(script, scriptLen);
    if (bl > 0 && bl < scriptLen && script[bl] == OP_XNA_ASSET) {
        size_t pdOff, pdLen, next;
        if (!readPush(script, scriptLen, bl + 1, &pdOff, &pdLen, &next)) return false;
        if (next + 1 != scriptLen || script[next] != OP_DROP) return false;  /* exact tail */
        info->base = script;
        info->baseLen = bl;
        if (!parsePayload(script + pdOff, pdLen, info)) { resetInfo(info); return false; }
        return true;
    }

    /* Null-asset family: starts with the marker, no base address. */
    if (script[0] == OP_XNA_ASSET) {
        if (!parseNullAsset(script, scriptLen, info)) { resetInfo(info); return false; }
        return true;
    }

    return false;
}

bool assetIsAssetScript(const uint8_t * script, size_t scriptLen) {
    AssetInfo info;
    return assetParseScript(script, scriptLen, &info);
}
