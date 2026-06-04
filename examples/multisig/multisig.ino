/*
 * Neurai multisig example (legacy P2SH).
 *
 * Neurai has NO segwit/bech32, so multisig addresses are legacy *P2SH*
 * (base58, "Y..." on mainnet) wrapping a sorted-multisig redeem script -- not
 * native segwit P2WSH.
 *
 * This derives the cosigner account xpubs from BIP-39 mnemonics so the example
 * is fully self-contained (the mnemonics below are well-known test vectors -
 * NEVER use them with real funds). For each receive index it builds the
 * 2-of-3 redeem script with sortedmulti(), wraps it as P2SH with sh(), and
 * prints the resulting address on both Neurai mainnet and NeuraiTest.
 */

#include <Arduino.h>
#include "Neurai.h"

// 2 of 3 multisig
#define NUM_KEYS 3
#define THRESHOLD 2

// Cosigner mnemonics (TEST VECTORS - do not use with real funds).
static const char * COSIGNER_MNEMONICS[NUM_KEYS] = {
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  "ability ability ability ability ability ability ability ability ability ability ability acid",
  "able able able able able able able able able able able acid",
};

// Account-level public keys for each cosigner (BIP-45-style account 0).
HDPublicKey cosignerXpubs[NUM_KEYS];

void setup() {
  Serial.begin(115200);
  while(!Serial){ ; }

  // 1. Derive each cosigner's account xpub from its mnemonic.
  for(int i = 0; i < NUM_KEYS; i++){
    HDPrivateKey root(COSIGNER_MNEMONICS[i], "", &Neurai);
    cosignerXpubs[i] = root.derive("m/45'/0'/0'/").xpub();
    Serial.print("cosigner "); Serial.print(i); Serial.print(" account xpub: ");
    Serial.println(cosignerXpubs[i]);
  }

  Serial.println();
  Serial.println("2-of-3 P2SH multisig receive addresses:");

  // 2. For each receive index build the redeem script and P2SH address.
  for(int idx = 0; idx < 5; idx++){
    String derivation = String("m/0/") + String(idx);

    // Derive each cosigner's public key for this index (public derivation).
    PublicKey pubkeys[NUM_KEYS];
    for(int i = 0; i < NUM_KEYS; i++){
      pubkeys[i] = cosignerXpubs[i].derive(derivation);
    }

    // Sorted multisig redeem script (BIP-67 deterministic key ordering).
    Script redeemScript = sortedmulti(THRESHOLD, pubkeys, NUM_KEYS);
    // Legacy P2SH script-pubkey wrapping the redeem script.
    Script scriptPubkey = sh(redeemScript);

    Serial.print(derivation);
    Serial.print("  mainnet: ");
    Serial.print(scriptPubkey.address(&Neurai));
    Serial.print("   testnet: ");
    Serial.println(scriptPubkey.address(&NeuraiTest));
  }
}

void loop() {
  delay(1000);
}
