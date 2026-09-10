#ifndef __UNEURAI_MESSAGE_H__R3NU8EN25O
#define __UNEURAI_MESSAGE_H__R3NU8EN25O

#include "Neurai.h"

/*
 * Neurai message signing (`signmessage` / `verifymessage` compatible).
 *
 * The digest is the classic Bitcoin "magic hash":
 *
 *     msghash(text) = SHA256d( ser_string(MAGIC) || ser_string(text) )
 *     MAGIC         = "Neurai Signed Message:\n"
 *     ser_string(x) = CompactSize(len(x)) || x
 *
 * and the signature is the 65-byte *compact recoverable* ECDSA form
 *
 *     header || r[32] || s[32]      header = 27 + recid + (compressed ? 4 : 0)
 *
 * usually carried as base64 (88 chars). Signing is deterministic (RFC 6979),
 * so the same key and text always give the same signature. Any wallet's
 * `signmessage` / `verifymessage` is interoperable, and it is the primitive
 * the DePIN messaging protocol 2 uses for challenge requests (`DEPIN-REQ`),
 * challenge use (`DEPIN-GET` / `DEPIN-CLEAR`) and reply authentication
 * (`poolsig`, `DEPIN-RESP`) — see Neurai/doc/depin-messaging-protocol.md §3.3.
 *
 * Everything here is pure secp256k1 + hashing and compiles on host, so the
 * protocol vectors (§13.2, §13.3) are checked in tests/test_message.cpp.
 */

#define NEURAI_MESSAGE_MAGIC        "Neurai Signed Message:\n"
#define NEURAI_MESSAGE_SIG_LEN      65   /* header || r || s                    */
#define NEURAI_MESSAGE_SIG_B64_LEN  88   /* base64 of 65 bytes, without the NUL */

/* SHA256d( ser_string(MAGIC) || ser_string(text) ) */
void messageMagicHash(const uint8_t * text, size_t len, uint8_t out[32]);
void messageMagicHash(const char * text, uint8_t out[32]);

/* Compact recoverable signature (65 bytes). Returns 65, or 0 on error
 * (private key zero or outside the group order, signing failure). */
size_t signMessage(const PrivateKey & key, const uint8_t * text, size_t len, uint8_t out[NEURAI_MESSAGE_SIG_LEN]);
size_t signMessage(const PrivateKey & key, const char * text, uint8_t out[NEURAI_MESSAGE_SIG_LEN]);

/* Same signature, base64-encoded and NUL-terminated into `out` (cap >= 89).
 * Returns the number of characters written (88), or 0 on error. */
size_t signMessageBase64(const PrivateKey & key, const uint8_t * text, size_t len, char * out, size_t cap);
size_t signMessageBase64(const PrivateKey & key, const char * text, char * out, size_t cap);
#if USE_ARDUINO_STRING
String signMessageBase64(const PrivateKey & key, const String text);
#endif
#if USE_STD_STRING
std::string signMessageBase64(const PrivateKey & key, const std::string text);
#endif

/* Recover the signer's public key from a compact signature over `text`.
 * Accepts headers 27..34 (compressed and uncompressed). `pubOut` receives the
 * 33-byte compressed SEC encoding. Returns 1 on success, 0 on error (bad
 * header, recovered point not on the curve, or — for the base64 forms — a
 * string that is not exactly the canonical 88-char encoding of 65 bytes). */
int recoverMessageSigner(const uint8_t sig[NEURAI_MESSAGE_SIG_LEN], const uint8_t * text, size_t len, uint8_t pubOut[33]);
int recoverMessageSigner(const char * sigB64, const uint8_t * text, size_t len, uint8_t pubOut[33]);
int recoverMessageSigner(const char * sigB64, const char * text, uint8_t pubOut[33]);

/* Verify a base64 signature against a P2PKH address: the address version byte
 * must be the P2PKH prefix of `net` (or of any known network when `net` is
 * NULL — mainnet 0x35, testnet/regtest 0x7f; P2SH prefixes are rejected) and
 * the recovered key must satisfy hash160(key) == address payload.
 * Returns 1 if valid, 0 otherwise. */
int verifyMessage(const char * address, const char * sigB64, const uint8_t * text, size_t len,
                  const ChainNetwork * net = NULL);
int verifyMessage(const char * address, const char * sigB64, const char * text,
                  const ChainNetwork * net = NULL);

/* Verify against a known public key (33 or 65 byte SEC; must be a valid
 * curve point). 1 / 0. */
int verifyMessage(const PublicKey & pub, const char * sigB64, const uint8_t * text, size_t len);
int verifyMessage(const PublicKey & pub, const char * sigB64, const char * text);

#endif /* __UNEURAI_MESSAGE_H__R3NU8EN25O */
