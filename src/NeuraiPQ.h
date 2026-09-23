#ifndef __UXNA_NEURAI_PQ_H__
#define __UXNA_NEURAI_PQ_H__

#include "uNeurai_conf.h"   // so UNEURAI_ENABLE_PQ reaches the guards below and NeuraiPQ.cpp
#include <stdint.h>
#include <stddef.h>

/*
 * Neurai witness address families (Bech32m, 32-byte program, BIP-350 checksum).
 * The node only accepts these HRP / witness-version pairs (base58.cpp
 * DecodeDestination); any other combination is rejected even with a valid
 * checksum, including the old "nq1p…" / "tnq1p…" encoding of witness v1:
 *
 *   family       witver  HRP (main / test)  scriptPubKey    authType  witnessScript
 *   AuthScript     1     nc   / tnc         OP_1 0x20 <C>   any       any
 *   PQ (strict)    2     pq   / tpq         OP_2 0x20 <C>   0x01      0x51 (fixed)
 *   ECDSA (strict) 3     nq   / tnq         OP_3 0x20 <C>   0x02      0x51 (fixed)
 *
 *   C = taggedHash("NeuraiAuthScript", witver || auth_descriptor || SHA256(witnessScript))
 *
 * Regtest uses the testnet HRPs. The witness version is also the first byte of
 * the commitment preimage, so the same key has a different program per family.
 *
 * Activation: the strict families (v2/v3) are only spendable where the node
 * activated them (regtest today; not mainnet/testnet). Before activation the
 * node refuses to decode pq1…/nq1… addresses because an OP_2/OP_3 output is
 * anyone-can-spend there. This library cannot know the activation state: do
 * not pay to v2/v3 destinations on a chain where they are not active.
 */
#define UNEURAI_WITVER_AUTHSCRIPT 1   /* generic AuthScript (contracts, phase-1 PQ) */
#define UNEURAI_WITVER_PQ         2   /* strict PQ (ML-DSA-44) */
#define UNEURAI_WITVER_ECDSA      3   /* strict ECDSA (compressed secp256k1) */

#define UNEURAI_HRP_AUTHSCRIPT       "nc"
#define UNEURAI_HRP_AUTHSCRIPT_TEST  "tnc"
#define UNEURAI_HRP_PQ               "pq"
#define UNEURAI_HRP_PQ_TEST          "tpq"
#define UNEURAI_HRP_ECDSA            "nq"
#define UNEURAI_HRP_ECDSA_TEST       "tnq"

/* Maximum length of an encoded AuthScript address (plus NUL): hrp(3) + '1' +
 * 1 version + 52 data + 6 checksum = 63 characters. */
#define UNEURAI_AUTHSCRIPT_ADDRESS_MAX 64

/**
 * \brief Network parameters for a Neurai AuthScript address family that uses
 *        ML-DSA-44 keys (NIP-022 HD tree, `m_pq/100'/coin'/…`).
 *
 * Kept separate from ChainNetwork so the legacy structure stays untouched.
 * `bech32` and `witnessVersion` must be one of the canonical pairs above.
 */
struct ChainNetworkPQ {
    const char *bech32;           // HRP: "nc"/"tnc" (v1) or "pq"/"tpq" (v2)
    uint8_t     witnessVersion;   // 1 (generic AuthScript) or 2 (strict PQ)
    uint32_t    bip32Purpose;     // 100 (NIP-022)
    uint32_t    coinType;         // 1900 / 1
    uint8_t     pqExtPrivVersion[4]; // base58check version for xpqpriv / tpqpriv
};

/*
 * Generic AuthScript witness v1 with a PQ key (authType 0x01, witnessScript
 * OP_TRUE): the phase-1 PQ flow of the NeuraiHW firmware. neurai-key 5 calls
 * this family "xna-authscript" / "xna-authscript-test".
 *
 * Since 0.2.0 the HRP is "nc" / "tnc" (nc1p… / tnc1p…). Up to 0.0.11 it was
 * "nq" / "tnq" (nq1p… / tnq1p…), which the node now rejects; the
 * scriptPubKey (OP_1 0x20 <C>) and the commitment did not change, so funds on
 * old addresses are reachable through the re-encoded address.
 */
extern const ChainNetworkPQ NeuraiPQ;
extern const ChainNetworkPQ NeuraiPQTest;
/* Explicit names for the same two objects (&NeuraiPQV1 == &NeuraiPQ). */
extern const ChainNetworkPQ &NeuraiPQV1;
extern const ChainNetworkPQ &NeuraiPQV1Test;

/*
 * Strict PQ witness v2 (pq1z… / tpq1z…): authType 0x01 and witnessScript
 * OP_TRUE are fixed by consensus. neurai-key 5 calls this family "xna-pq" /
 * "xna-pq-test". Same NIP-022 key tree and xpqpriv versions as NeuraiPQ.
 */
extern const ChainNetworkPQ NeuraiPQV2;
extern const ChainNetworkPQ NeuraiPQV2Test;

/* Every ChainNetworkPQ defined by the library (v1 and v2, main and test). */
extern const ChainNetworkPQ *const pqNetworks[];
extern const size_t pqNetworks_len;

/* ML-DSA-44 public key serialization prefix. */
#define UNEURAI_PQ_PUBKEY_PREFIX 0x05
#define UNEURAI_PQ_PUBKEY_RAW_LEN 1312

/* AuthScript domain separation tag. UNEURAI_AUTHSCRIPT_VERSION is the lead
 * byte of the generic (witness v1) commitment preimage; the strict families
 * use their own witness version (UNEURAI_WITVER_PQ / UNEURAI_WITVER_ECDSA). */
#define UNEURAI_AUTHSCRIPT_TAG "NeuraiAuthScript"
#define UNEURAI_AUTHSCRIPT_VERSION 0x01

/* AuthScript auth types. */
#define UNEURAI_AUTHTYPE_NOAUTH  0x00
#define UNEURAI_AUTHTYPE_PQ      0x01
#define UNEURAI_AUTHTYPE_LEGACY  0x02
/* Alias: the secp256k1 auth type is the one bound to the strict ECDSA family. */
#define UNEURAI_AUTHTYPE_ECDSA   UNEURAI_AUTHTYPE_LEGACY

/* The single-byte witnessScript (OP_TRUE) mandated by the strict families. */
#define UNEURAI_STRICT_WITNESS_SCRIPT 0x51

/* Strict family helpers (mirror the node's interpreter.h):
 *   authType 0x01 <-> witness v2, authType 0x02 <-> witness v3. */
uint8_t strictAuthScriptWitnessVersion(uint8_t authType); /* 0 if none */
uint8_t strictAuthScriptAuthType(uint8_t witnessVersion); /* 0 if none */
bool isStrictAuthScriptWitnessVersion(uint8_t witnessVersion);

/* ---------------------------- Address families ---------------------------- */

/* HRP of the family bound to `witnessVersion` (1, 2 or 3) on mainnet or on
 * testnet/regtest. Returns NULL for any other witness version. */
const char *authScriptHrp(uint8_t witnessVersion, bool testnet);

/*
 * Encode a 32-byte witness program as the canonical address of its family
 * (nc1p… / pq1z… / nq1r…, or the testnet t… forms).
 * Returns the address length (excluding NUL) or 0 on error.
 */
size_t authScriptAddressEncode(uint8_t witnessVersion, bool testnet,
                               const uint8_t program[32],
                               char *out, size_t outLen);

/*
 * Decode any Neurai AuthScript address (v1 nc/tnc, v2 pq/tpq, v3 nq/tnq; upper
 * or lower case). Only canonical HRP/version pairs with a 32-byte program are
 * accepted, exactly like the node: "nq1p…" / "tnq1p…" (old v1) return 0.
 * Any out-pointer may be NULL. Returns 1 on success, 0 otherwise.
 */
int authScriptAddressDecode(const char *addr,
                            uint8_t *witnessVersion, bool *testnet,
                            uint8_t program[32]);

/*
 * Witness version (1, 2 or 3) of an AuthScript scriptPubKey `OP_n 0x20 <32>`,
 * either exactly that (34 bytes) or followed by an asset payload starting with
 * OP_XNA_ASSET (0xc0). Returns 0 for any other script.
 */
uint8_t authScriptWitnessVersionOf(const uint8_t *script, size_t len);

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
 * Generic AuthScript (witness v1) commitment:
 *   taggedHash("NeuraiAuthScript", 0x01 || auth_descriptor || SHA256(witnessScript))
 * `pubkey` and `pkLen` follow the same convention as buildAuthDescriptor().
 * `out` must hold 32 bytes. Returns 1 on success, 0 on error.
 * Equivalent to buildVersionedAuthScriptCommitment(1, …).
 */
int buildAuthScriptCommitment(uint8_t authType,
                              const uint8_t *pubkey, size_t pkLen,
                              const uint8_t *witnessScript, size_t wsLen,
                              uint8_t out[32]);

/*
 * Commitment for any family:
 *   taggedHash("NeuraiAuthScript", witnessVersion || auth_descriptor || SHA256(witnessScript))
 * witnessVersion 1 accepts any authType / witnessScript. The strict families
 * enforce the consensus template, so an unspendable program is never built:
 *   2 (PQ):    authType 0x01, 1312-byte raw ML-DSA-44 key, witnessScript {0x51}
 *   3 (ECDSA): authType 0x02, 33-byte compressed secp256k1 key, witnessScript {0x51}
 * Returns 1 on success, 0 on error.
 */
int buildVersionedAuthScriptCommitment(uint8_t witnessVersion, uint8_t authType,
                                       const uint8_t *pubkey, size_t pkLen,
                                       const uint8_t *witnessScript, size_t wsLen,
                                       uint8_t out[32]);

/*
 * scriptPubKey for a generic AuthScript (v1) output: 34 bytes
 * [OP_1, 0x20, ...commitment...]. Returns 34 on success, 0 on error.
 */
size_t buildAuthScriptScriptPubKey(const uint8_t commitment[32],
                                   uint8_t *out, size_t outLen);

/*
 * scriptPubKey for any family: [OP_n, 0x20, ...commitment...] with
 * OP_n = OP_1 / OP_2 / OP_3 for witness version 1 / 2 / 3.
 * Returns 34 on success, 0 on error (including other witness versions).
 */
size_t buildVersionedAuthScriptScriptPubKey(uint8_t witnessVersion,
                                            const uint8_t commitment[32],
                                            uint8_t *out, size_t outLen);

/*
 * Strict ECDSA (witness v3) commitment of a 33-byte compressed secp256k1 key:
 *   taggedHash("NeuraiAuthScript", 0x03 || 0x02 || HASH160(pubkey) || SHA256(0x51))
 * Returns 1 on success, 0 on error (e.g. an uncompressed key).
 */
int ecdsaCommitmentFromPubKey(const uint8_t pubkey[33], uint8_t out[32]);

/*
 * Strict ECDSA address (nq1r… mainnet / tnq1r… testnet and regtest) of a
 * 33-byte compressed secp256k1 key. neurai-key 5 derives it at
 * m/84'/1900'/account'/change/index (coin type 1 on testnet), networks
 * "xna" / "xna-test". Returns the length written (excluding NUL) or 0.
 */
size_t ecdsaAddressFromPubKey(const uint8_t pubkey[33], bool testnet,
                              char *out, size_t outLen);

/*
 * Extract the OP_TXHASH selector from a PQ partial-fill covenant's CANCEL branch.
 * The branch begins with a fixed prefix:
 *   OP_IF OP_DUP OP_SHA256 <push32 pubKeyCommitment> OP_EQUALVERIFY <push selector> OP_TXHASH ...
 * The selector push is either OP_1..OP_16 (values 1..16) or a 1-byte data push.
 * The device must use the in-script selector (consensus reads it from here), so
 * never trust a host-supplied value. Writes *outSelector and returns 1 on a
 * matching script, 0 otherwise.
 */
int parseCovenantPQTxHashSelector(const uint8_t *script, size_t len,
                                  uint8_t *outSelector);

/*
 * Encode a PQ address from a raw 1312-byte ML-DSA-44 public key, with
 * authType 0x01 and witnessScript = OP_TRUE (single byte 0x51).
 * The family follows `net`: NeuraiPQ / NeuraiPQTest give the generic v1
 * address (nc1p… / tnc1p…), NeuraiPQV2 / NeuraiPQV2Test the strict v2 address
 * (pq1z… / tpq1z…). The commitment uses net->witnessVersion as lead byte.
 * Returns the length of the address written (excluding NUL), or 0 on error.
 */
size_t pqAddressFromPubKey(const ChainNetworkPQ *net,
                           const uint8_t pqPubKey[UNEURAI_PQ_PUBKEY_RAW_LEN],
                           char *out, size_t outLen);

/*
 * Decode an address of `net`'s family (net->bech32 HRP and
 * net->witnessVersion) back to its 32-byte commitment.
 * Returns 1 on success (with `commitment` populated), 0 otherwise.
 * Use authScriptAddressDecode() to accept every family.
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
