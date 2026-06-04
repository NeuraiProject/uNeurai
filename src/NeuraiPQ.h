#ifndef __UXNA_NEURAI_PQ_H__
#define __UXNA_NEURAI_PQ_H__

#include "uNeurai_conf.h"   // so UNEURAI_ENABLE_PQ reaches the guards below and NeuraiPQ.cpp
#include <stdint.h>
#include <stddef.h>

/**
 * \brief Network parameters for the Neurai Post-Quantum chain (NIP-022 / ML-DSA-44).
 *
 * Kept separate from ChainNetwork so the legacy structure stays untouched.
 */
struct ChainNetworkPQ {
    const char *bech32;           // HRP: "nq" / "tnq"
    uint8_t     witnessVersion;   // always 1 in phase 1
    uint32_t    bip32Purpose;     // 100 (NIP-022)
    uint32_t    coinType;         // 1900 / 1
    uint8_t     pqExtPrivVersion[4]; // base58check version for xpqpriv / tpqpriv
};

extern const ChainNetworkPQ NeuraiPQ;
extern const ChainNetworkPQ NeuraiPQTest;

/* Listed for Script::fromAddress() to detect "nq" / "tnq" HRPs. */
extern const ChainNetworkPQ *const pqNetworks[];
extern const size_t pqNetworks_len;

/* ML-DSA-44 public key serialization prefix. */
#define UNEURAI_PQ_PUBKEY_PREFIX 0x05
#define UNEURAI_PQ_PUBKEY_RAW_LEN 1312

/* AuthScript domain separation tag and on-chain version. */
#define UNEURAI_AUTHSCRIPT_TAG "NeuraiAuthScript"
#define UNEURAI_AUTHSCRIPT_VERSION 0x01

/* AuthScript auth types. */
#define UNEURAI_AUTHTYPE_NOAUTH  0x00
#define UNEURAI_AUTHTYPE_PQ      0x01
#define UNEURAI_AUTHTYPE_LEGACY  0x02

/* taggedHash("NeuraiAuthScript", data) = SHA256(SHA256(tag) || SHA256(tag) || data) */
void taggedHashAuthScript(const uint8_t *data, size_t len, uint8_t out[32]);

/*
 * auth_descriptor:
 *   authType == 0x00 (NoAuth)  -> 1 byte:  [0x00]
 *   authType == 0x01 (PQ)      -> 21 bytes: [0x01 || hash160(0x05 || pqPubKey1312)]
 *   authType == 0x02 (Legacy)  -> 21 bytes: [0x02 || hash160(compressedSecp256k1Pub)]
 *
 * `pubkey` is the RAW public-key bytes. For PQ this means 1312 B (no leading 0x05).
 * For Legacy, the compressed secp256k1 33 B. For NoAuth, may be NULL.
 *
 * `out` must be at least 22 bytes. Returns bytes written or 0 on error.
 */
size_t buildAuthDescriptor(uint8_t authType,
                           const uint8_t *pubkey, size_t pkLen,
                           uint8_t *out, size_t outLen);

/*
 * commitment = taggedHash("NeuraiAuthScript", 0x01 || auth_descriptor || SHA256(witnessScript))
 * `pubkey` and `pkLen` follow the same convention as buildAuthDescriptor().
 * `out` must hold 32 bytes. Returns 1 on success, 0 on error.
 */
int buildAuthScriptCommitment(uint8_t authType,
                              const uint8_t *pubkey, size_t pkLen,
                              const uint8_t *witnessScript, size_t wsLen,
                              uint8_t out[32]);

/*
 * scriptPubKey for an AuthScript output: 34 bytes  [OP_1, 0x20, ...commitment...]
 * Returns 34 on success, 0 on error.
 */
size_t buildAuthScriptScriptPubKey(const uint8_t commitment[32],
                                   uint8_t *out, size_t outLen);

/*
 * Encode a PQ address from a raw 1312-byte ML-DSA-44 public key.
 * Uses witnessScript = OP_TRUE (single byte 0x51) — the phase-1 default.
 * Returns the length of the address written (excluding NUL), or 0 on error.
 */
size_t pqAddressFromPubKey(const ChainNetworkPQ *net,
                           const uint8_t pqPubKey[UNEURAI_PQ_PUBKEY_RAW_LEN],
                           char *out, size_t outLen);

/*
 * Decode a PQ address back to its 32-byte commitment.
 * Returns 1 on success (with `commitment` populated), 0 otherwise.
 */
int pqAddressDecode(const char *addr,
                    const ChainNetworkPQ *net,
                    uint8_t commitment[32]);

/* ---------------------------- PQ HD key (NIP-022) ---------------------------- */

#define UNEURAI_PQ_HARDENED_OFFSET 0x80000000UL
#define UNEURAI_PQ_EXTKEY_PAYLOAD_LEN 74
/* 4-byte version + 74-byte payload + 4-byte checksum = 82 bytes, encodes to 111 chars. */
#define UNEURAI_PQ_EXTKEY_BASE58_MAX 120

class PQHDPrivateKey {
  public:
    uint8_t  pqSeed[32];
    uint8_t  chainCode[32];
    uint8_t  parentFingerprint[4];
    uint8_t  depth;
    uint32_t childNumber;
    const ChainNetworkPQ *network;

    PQHDPrivateKey();

    /* I = HMAC-SHA512("Neurai PQ seed", bip39_seed)
     *   pqSeed    = I[0..32]
     *   chainCode = I[32..64]
     * Returns 1 on success, 0 on error.
     */
    int fromMnemonic(const char *mnemonic, size_t mnemonicLen,
                     const char *password, size_t passwordLen,
                     const ChainNetworkPQ *net);

    /* Derive a child key. The index MUST be hardened (>= 0x80000000); otherwise 0. */
    int deriveChild(uint32_t index, PQHDPrivateKey *out) const;

    /* Derive along a path like "m_pq/100'/1'/0'/0'/0'". Hardened-only. */
    int derive(const char *path, PQHDPrivateKey *out) const;

    /* fingerprint = hash160(0x05 || pubkey).first4. The caller supplies the
     * raw 1312-byte ML-DSA public key (host code can't materialize it). */
    void fingerprintFromPubKey(const uint8_t pqPubKey[UNEURAI_PQ_PUBKEY_RAW_LEN],
                               uint8_t out[4]) const;

    /* Serialize as xpqpriv… / tpqpriv… (base58check, 111 chars typical).
     * Returns length written (excluding NUL) or 0 on error.
     */
    size_t xpqp(char *out, size_t outLen) const;

    /* Decode an xpqpriv / tpqpriv string. Validates version against `net`. */
    int fromXpqp(const char *str, const ChainNetworkPQ *net);

#if defined(UNEURAI_ENABLE_PQ) && defined(ARDUINO_ARCH_ESP32)
    /* Materialize the ML-DSA-44 keypair from pqSeed. Only available with the
     * mldsa-esp32 backend. */
    int materializeKeyPair(uint8_t pk[UNEURAI_PQ_PUBKEY_RAW_LEN], uint8_t sk[2560]) const;
#endif
};

#endif // __UXNA_NEURAI_PQ_H__
