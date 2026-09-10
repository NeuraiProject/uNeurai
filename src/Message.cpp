#include "Message.h"
#include "Hash.h"
#include "Conversion.h"
#include "utility/trezor/ecdsa.h"
#include "utility/trezor/secp256k1.h"
#include "utility/trezor/memzero.h"
#include "utility/trezor/bignum.h"
#include "Networks.h"
#include <string.h>

/* ── magic hash ───────────────────────────────────────────────────────────── */

static void hashSerString(DoubleSha & h, const uint8_t * data, size_t len) {
    uint8_t vi[9];
    size_t vl = writeVarInt(len, vi, sizeof(vi));
    h.write(vi, vl);
    if (len) h.write(data, len);
}

void messageMagicHash(const uint8_t * text, size_t len, uint8_t out[32]) {
    DoubleSha h;
    h.begin();
    hashSerString(h, (const uint8_t *)NEURAI_MESSAGE_MAGIC, sizeof(NEURAI_MESSAGE_MAGIC) - 1);
    hashSerString(h, text, len);
    h.end(out);
}

void messageMagicHash(const char * text, uint8_t out[32]) {
    messageMagicHash((const uint8_t *)text, text ? strlen(text) : 0, out);
}

/* ── sign ─────────────────────────────────────────────────────────────────── */

/* 0 < d < n: an all-zero PrivateKey() (or one outside the group order) must
 * never produce a signature, and its "public key" is not a curve point. */
static bool privateKeyInRange(const PrivateKey & key) {
    uint8_t secret[32];
    key.getSecret(secret);
    bignum256 d;
    bn_read_be(secret, &d);
    memzero(secret, sizeof(secret));
    bool ok = !bn_is_zero(&d) && bn_is_less(&d, &secp256k1.order);
    memzero(&d, sizeof(d));
    return ok;
}

size_t signMessage(const PrivateKey & key, const uint8_t * text, size_t len, uint8_t out[NEURAI_MESSAGE_SIG_LEN]) {
    if (!out || (!text && len)) return 0;
    if (!privateKeyInRange(key)) return 0;
    PublicKey pub = key.publicKey();
    if (!pub.isValid()) return 0;

    uint8_t digest[32];
    messageMagicHash(text, len, digest);

    Signature sig = key.sign(digest);
    if (!sig.isValid()) return 0;          /* signing failure */
    uint8_t bin[65];                       /* r[32] || s[32] || recid */
    sig.bin(bin, sizeof(bin));

    out[0] = (uint8_t)(27 + (bin[64] & 3) + (pub.compressed ? 4 : 0));
    memcpy(out + 1, bin, 64);
    memzero(bin, sizeof(bin));
    return NEURAI_MESSAGE_SIG_LEN;
}

size_t signMessage(const PrivateKey & key, const char * text, uint8_t out[NEURAI_MESSAGE_SIG_LEN]) {
    return signMessage(key, (const uint8_t *)text, text ? strlen(text) : 0, out);
}

size_t signMessageBase64(const PrivateKey & key, const uint8_t * text, size_t len, char * out, size_t cap) {
    if (!out || cap < NEURAI_MESSAGE_SIG_B64_LEN + 1) return 0;
    uint8_t sig[NEURAI_MESSAGE_SIG_LEN];
    if (!signMessage(key, text, len, sig)) return 0;
    size_t n = toBase64(sig, sizeof(sig), out, cap);
    if (n != NEURAI_MESSAGE_SIG_B64_LEN) { out[0] = '\0'; return 0; }
    out[n] = '\0';
    return n;
}

size_t signMessageBase64(const PrivateKey & key, const char * text, char * out, size_t cap) {
    return signMessageBase64(key, (const uint8_t *)text, text ? strlen(text) : 0, out, cap);
}

#if USE_ARDUINO_STRING
String signMessageBase64(const PrivateKey & key, const String text) {
    char buf[NEURAI_MESSAGE_SIG_B64_LEN + 1];
    if (!signMessageBase64(key, (const uint8_t *)text.c_str(), text.length(), buf, sizeof(buf))) return String("");
    return String(buf);
}
#endif
#if USE_STD_STRING
std::string signMessageBase64(const PrivateKey & key, const std::string text) {
    char buf[NEURAI_MESSAGE_SIG_B64_LEN + 1];
    if (!signMessageBase64(key, (const uint8_t *)text.c_str(), text.length(), buf, sizeof(buf))) return std::string("");
    return std::string(buf);
}
#endif

/* ── recover / verify ─────────────────────────────────────────────────────── */

int recoverMessageSigner(const uint8_t sig[NEURAI_MESSAGE_SIG_LEN], const uint8_t * text, size_t len, uint8_t pubOut[33]) {
    if (!sig || !pubOut || (!text && len)) return 0;
    uint8_t header = sig[0];
    if (header < 27 || header > 34) return 0;
    int recid = (header - 27) & 3;

    uint8_t digest[32];
    messageMagicHash(text, len, digest);

    uint8_t pub65[65];
    if (ecdsa_recover_pub_from_sig(&secp256k1, pub65, sig + 1, digest, recid) != 0) return 0;

    /* the recovered point must be on the curve (never the zero / infinity
     * point); always hand back the compressed form — the header only says how
     * the signer's address was derived, which verifyMessage() re-checks */
    PublicKey pub(pub65);
    pub.compressed = true;
    if (!pub.isValid()) return 0;
    return pub.sec(pubOut, 33) == 33 ? 1 : 0;
}

/* Strict base64: exactly 88 chars that decode to 65 bytes AND re-encode to
 * the same string, so stray padding bits or a non-canonical tail (which the
 * reference implementations reject) cannot pass as the same signature. */
static int decodeSigB64(const char * sigB64, uint8_t sig[NEURAI_MESSAGE_SIG_LEN]) {
    if (!sigB64) return 0;
    size_t l = strlen(sigB64);
    if (l != NEURAI_MESSAGE_SIG_B64_LEN) return 0;
    if (fromBase64(sigB64, l, sig, NEURAI_MESSAGE_SIG_LEN) != NEURAI_MESSAGE_SIG_LEN) return 0;
    char canon[NEURAI_MESSAGE_SIG_B64_LEN + 1];
    size_t n = toBase64(sig, NEURAI_MESSAGE_SIG_LEN, canon, sizeof(canon));
    if (n != NEURAI_MESSAGE_SIG_B64_LEN) return 0;
    canon[n] = '\0';
    return strcmp(canon, sigB64) == 0 ? 1 : 0;
}

int recoverMessageSigner(const char * sigB64, const uint8_t * text, size_t len, uint8_t pubOut[33]) {
    uint8_t sig[NEURAI_MESSAGE_SIG_LEN];
    if (!decodeSigB64(sigB64, sig)) return 0;
    return recoverMessageSigner(sig, text, len, pubOut);
}

int recoverMessageSigner(const char * sigB64, const char * text, uint8_t pubOut[33]) {
    return recoverMessageSigner(sigB64, (const uint8_t *)text, text ? strlen(text) : 0, pubOut);
}

/* hash160 of the recovered key, honouring the header's compressed flag so an
 * uncompressed-key signature still matches its (uncompressed) address. */
static int recoveredHash160(const char * sigB64, const uint8_t * text, size_t len, uint8_t h160[20]) {
    uint8_t sig[NEURAI_MESSAGE_SIG_LEN];
    if (!decodeSigB64(sigB64, sig)) return 0;
    uint8_t pub33[33];
    if (!recoverMessageSigner(sig, text, len, pub33)) return 0;
    bool compressed = sig[0] >= 31;
    if (compressed) {
        hash160(pub33, 33, h160);
    } else {
        uint8_t pub65[65];
        if (ecdsa_uncompress_pubkey(&secp256k1, pub33, pub65) != 1) return 0;
        hash160(pub65, 65, h160);
    }
    return 1;
}

/* P2PKH version byte check: the given network's, or any known network's when
 * net is NULL. P2SH (and any other) prefixes are rejected — a message
 * signature only proves ownership of a pay-to-pubkey-hash address. */
static bool isP2PKHPrefix(uint8_t version, const ChainNetwork * net) {
    if (net) return version == net->p2pkh;
    for (uint8_t i = 0; i < networks_len; i++) {
        if (version == networks[i]->p2pkh) return true;
    }
    return false;
}

int verifyMessage(const char * address, const char * sigB64, const uint8_t * text, size_t len,
                  const ChainNetwork * net) {
    if (!address) return 0;
    uint8_t payload[25];
    size_t l = fromBase58Check(address, strlen(address), payload, sizeof(payload));
    if (l != 21) return 0;                 /* version || hash160 */
    if (!isP2PKHPrefix(payload[0], net)) return 0;
    uint8_t h160[20];
    if (!recoveredHash160(sigB64, text, len, h160)) return 0;
    return memcmp(payload + 1, h160, 20) == 0 ? 1 : 0;
}

int verifyMessage(const char * address, const char * sigB64, const char * text, const ChainNetwork * net) {
    return verifyMessage(address, sigB64, (const uint8_t *)text, text ? strlen(text) : 0, net);
}

int verifyMessage(const PublicKey & pub, const char * sigB64, const uint8_t * text, size_t len) {
    if (!pub.isValid()) return 0;          /* PublicKey() / off-curve point */
    uint8_t got[33];
    if (!recoverMessageSigner(sigB64, text, len, got)) return 0;
    PublicKey want = pub;
    want.compressed = true;
    uint8_t exp[33];
    if (want.sec(exp, 33) != 33) return 0;
    return memcmp(got, exp, 33) == 0 ? 1 : 0;
}

int verifyMessage(const PublicKey & pub, const char * sigB64, const char * text) {
    return verifyMessage(pub, sigB64, (const uint8_t *)text, text ? strlen(text) : 0);
}
