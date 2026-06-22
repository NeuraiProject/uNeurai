#include "AssetName.h"
#include <string.h>

/* ── Character classes (the regex equivalents) ──────────────────────────── */

static bool isAZ09dotus(char c) {  /* [A-Z0-9._] */
    return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.';
}

static bool isUniqueTag(char c) {  /* [-A-Za-z0-9@$%&*()[]{}_.?:] */
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) return true;
    switch (c) {
        case '-': case '@': case '$': case '%': case '&': case '*':
        case '(': case ')': case '[': case ']': case '{': case '}':
        case '_': case '.': case '?': case ':':
            return true;
    }
    return false;
}

/* ── Segment predicates (operate on s[0..n) without a NUL) ───────────────── */

static bool segAllAZ09dotus(const char * s, size_t n) {
    if (n == 0) return false;
    for (size_t i = 0; i < n; i++) if (!isAZ09dotus(s[i])) return false;
    return true;
}
static bool segDoublePunct(const char * s, size_t n) {          /* [._]{2,} anywhere */
    for (size_t i = 0; i + 1 < n; i++) {
        bool a = (s[i] == '.' || s[i] == '_');
        bool b = (s[i + 1] == '.' || s[i + 1] == '_');
        if (a && b) return true;
    }
    return false;
}
static bool segLeadPunct(const char * s, size_t n)  { return n > 0 && (s[0] == '.' || s[0] == '_'); }
static bool segTrailPunct(const char * s, size_t n) { return n > 0 && (s[n - 1] == '.' || s[n - 1] == '_'); }

static bool segEq(const char * s, size_t n, const char * lit) {
    size_t l = strlen(lit);
    return n == l && memcmp(s, lit, l) == 0;
}
/* NEURAI_NAMES: ^XNA$|^NEURAI$|^NEURAICOIN$|^#XNA$|^#NEURAI$|^#NEURAICOIN$ */
static bool segReserved(const char * s, size_t n) {
    return segEq(s, n, "XNA") || segEq(s, n, "NEURAI") || segEq(s, n, "NEURAICOIN") ||
           segEq(s, n, "#XNA") || segEq(s, n, "#NEURAI") || segEq(s, n, "#NEURAICOIN");
}

/* ── Per-type segment validators (mirror isXxxNameValid) ─────────────────── */

static bool segIsRoot(const char * s, size_t n) {
    if (n < 3) return false;                              /* {3,} */
    if (!segAllAZ09dotus(s, n)) return false;
    if (segDoublePunct(s, n) || segLeadPunct(s, n) || segTrailPunct(s, n)) return false;
    if (segReserved(s, n)) return false;
    return true;
}
static bool segIsSub(const char * s, size_t n) {
    if (n < 1) return false;
    if (!segAllAZ09dotus(s, n)) return false;
    if (segDoublePunct(s, n) || segLeadPunct(s, n) || segTrailPunct(s, n)) return false;
    return true;
}
static bool segIsQualifier(const char * s, size_t n) {   /* ^#[A-Z0-9._]{3,}$ */
    if (n < 4 || s[0] != '#') return false;
    if (!segAllAZ09dotus(s + 1, n - 1)) return false;
    if (segDoublePunct(s, n)) return false;
    /* QUALIFIER_LEADING_PUNCTUATION ^[#$][._] */
    if ((s[0] == '#' || s[0] == '$') && n > 1 && (s[1] == '.' || s[1] == '_')) return false;
    if (segTrailPunct(s, n)) return false;
    if (segReserved(s, n)) return false;
    return true;
}
static bool segIsSubQualifier(const char * s, size_t n) { /* ^#[A-Z0-9._]+$ */
    if (n < 2 || s[0] != '#') return false;
    if (!segAllAZ09dotus(s + 1, n - 1)) return false;
    if (segDoublePunct(s, n) || segLeadPunct(s, n) || segTrailPunct(s, n)) return false;
    return true;
}

/* name (root + optional '/' sub-parts) is valid before a tag */
static bool nameValidBeforeTag(const char * s, size_t n) {
    if (n == 0) return false;
    size_t start = 0;
    bool first = true;
    for (size_t i = 0; i <= n; i++) {
        if (i == n || s[i] == '/') {
            size_t segLen = i - start;
            if (first) { if (!segIsRoot(s + start, segLen)) return false; first = false; }
            else       { if (!segIsSub(s + start, segLen))  return false; }
            start = i + 1;
        }
    }
    return true;
}

/* ── Full-name validators (length checks done by the dispatcher) ─────────── */

static bool restrictedValid(const char * s, size_t n) {  /* ^\$[A-Z0-9._]{3,}$ ... */
    if (n < 4 || s[0] != '$') return false;
    if (!segAllAZ09dotus(s + 1, n - 1)) return false;
    if (segDoublePunct(s, n) || segLeadPunct(s, n) || segTrailPunct(s, n)) return false;
    if (segReserved(s, n)) return false;
    return true;
}

static bool qualifierBeforeTag(const char * s, size_t n) {
    const char * slash = (const char *)memchr(s, '/', n);
    size_t p0 = slash ? (size_t)(slash - s) : n;
    if (!segIsQualifier(s, p0)) return false;
    if (!slash) return true;
    const char * rest = slash + 1;
    size_t restLen = n - (p0 + 1);
    if (memchr(rest, '/', restLen) != NULL) return false;     /* parts.length > 2 */
    return segIsSubQualifier(rest, restLen);
}

static bool uniqueValid(const char * s, size_t n) {
    const char * hash = (const char *)memchr(s, '#', n);
    if (!hash) return false;
    size_t rootLen = (size_t)(hash - s);
    const char * tag = hash + 1;
    size_t tagLen = n - (rootLen + 1);
    if (memchr(tag, '#', tagLen) != NULL) return false;       /* exactly 2 parts */
    if (!nameValidBeforeTag(s, rootLen)) return false;
    if (tagLen < 1) return false;
    for (size_t i = 0; i < tagLen; i++) if (!isUniqueTag(tag[i])) return false;
    return true;
}

static bool depinValid(const char * s, size_t n) {
    if (n < 1 || s[0] != '&') return false;
    const char * slash = (const char *)memchr(s, '/', n);
    if (!slash) {
        /* DEPIN_CHARS ^&[A-Z0-9._]{3,}$ ; single part needs length >= MIN+1 (4) */
        if (n < 4) return false;
        if (!segAllAZ09dotus(s + 1, n - 1)) return false;
        return true;
    }
    /* SUB_DEPIN ^&[A-Z0-9._]+\/[A-Z0-9._/]+$ */
    size_t firstSlash = (size_t)(slash - s);
    if (firstSlash < 2) return false;                          /* need '&' + >=1 char */
    if (!segAllAZ09dotus(s + 1, firstSlash - 1)) return false;
    if (firstSlash + 1 >= n) return false;
    for (size_t i = firstSlash + 1; i < n; i++) {
        char c = s[i];
        if (!(isAZ09dotus(c) || c == '/')) return false;
    }
    /* each '/'-separated part (part[0] includes '&') must be >= 3 chars */
    size_t start = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n || s[i] == '/') {
            if (i - start < 3) return false;
            start = i + 1;
        }
    }
    return true;
}

static bool ownerValid(const char * s, size_t n, bool testnet, size_t fullMax) {
    if (n == 0 || n > fullMax) return false;
    if (s[n - 1] != '!') return false;
    size_t baseLen = n - 1;
    if (baseLen == 0) return false;
    if (nameValidBeforeTag(s, baseLen)) return true;
    /* or a DEPIN base (testnet only) */
    if (s[0] == '&') {
        if (!testnet) return false;
        return depinValid(s, baseLen);
    }
    return false;
}

/* ── Public dispatch (mirror validateAndDetectType) ──────────────────────── */

AssetNameType assetDetectAndValidate(const char * name, bool testnet) {
    if (!name) return ASSET_NAME_INVALID;
    size_t n = strlen(name);
    if (n == 0) return ASSET_NAME_INVALID;

    const size_t fullMax    = testnet ? 121 : 32;
    const size_t rootSubMax = fullMax - 1;

    if (name[n - 1] == '!')
        return ownerValid(name, n, testnet, fullMax) ? ASSET_NAME_OWNER : ASSET_NAME_INVALID;

    if (name[0] == '#') {
        if (n > fullMax) return ASSET_NAME_INVALID;
        if (!qualifierBeforeTag(name, n)) return ASSET_NAME_INVALID;
        return memchr(name, '/', n) ? ASSET_NAME_SUB_QUALIFIER : ASSET_NAME_QUALIFIER;
    }
    if (name[0] == '$') {
        if (n > fullMax) return ASSET_NAME_INVALID;
        return restrictedValid(name, n) ? ASSET_NAME_RESTRICTED : ASSET_NAME_INVALID;
    }
    if (name[0] == '&') {
        if (!testnet) return ASSET_NAME_INVALID;            /* DEPIN is testnet-only */
        if (n > fullMax) return ASSET_NAME_INVALID;
        return depinValid(name, n) ? ASSET_NAME_DEPIN : ASSET_NAME_INVALID;
    }
    if (memchr(name, '#', n)) {
        if (n > fullMax) return ASSET_NAME_INVALID;
        return uniqueValid(name, n) ? ASSET_NAME_UNIQUE : ASSET_NAME_INVALID;
    }
    if (memchr(name, '/', n)) {
        if (n > rootSubMax) return ASSET_NAME_INVALID;
        return nameValidBeforeTag(name, n) ? ASSET_NAME_SUB : ASSET_NAME_INVALID;
    }
    if (n < 3 || n > rootSubMax) return ASSET_NAME_INVALID;
    return segIsRoot(name, n) ? ASSET_NAME_ROOT : ASSET_NAME_INVALID;
}

bool assetNameIsValid(const char * name, bool testnet) {
    return assetDetectAndValidate(name, testnet) != ASSET_NAME_INVALID;
}
