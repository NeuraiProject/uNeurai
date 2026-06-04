/*
 * Neurai legacy transaction build + sign demo.
 *
 * (This example used to parse a hard-coded Bitcoin-testnet PSBT. Neurai uses
 * legacy P2PKH transactions, so it now derives a key from a BIP-39 mnemonic,
 * builds a 1-input / 2-output P2PKH transaction and signs it with SIGHASH_ALL.)
 *
 * The same flow runs on both Neurai mainnet and NeuraiTest. The previous-output
 * reference (txid/vout/amount) is illustrative - replace it with a real UTXO you
 * own before broadcasting. The mnemonic below is a well-known test vector;
 * NEVER use it with real funds.
 */

#include <Arduino.h>
#include "Neurai.h"

static const char MNEMONIC[] =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Illustrative UTXO being spent (replace with a real one to broadcast).
static const char PREV_TXID[] = "fbeae5f43d76fc3035cb4190baaf8cc123dd04f11c98c8f19a8b12cb4ce90db0";
static const uint32_t PREV_VOUT = 0;

static void buildAndSign(const char * label, const ChainNetwork * net, uint32_t coinType){
  Serial.println();
  Serial.print("=== "); Serial.print(label); Serial.println(" ===");

  // 1. Derive a signing key: m/44'/coin'/0'/0/index
  HDPrivateKey root(MNEMONIC, "", net);
  String base = String("m/44'/") + String(coinType) + String("'/0'/0/");
  HDPrivateKey signKey = root.derive((base + "0/").c_str());   // receive #0
  HDPrivateKey changeKey = signKey;                            // reuse for change
  HDPrivateKey destKey  = root.derive((base + "1/").c_str());  // receive #1 (destination)

  String fromAddr = signKey.publicKey().address(net);
  String destAddr = destKey.publicKey().address(net);
  Serial.print("from address:        "); Serial.println(fromAddr);
  Serial.print("destination address: "); Serial.println(destAddr);

  // 2. Amounts (in satoshis; 1 XNA = 100,000,000 sat)
  uint64_t availableAmount = 200000000ULL; // 2 XNA UTXO (illustrative)
  uint64_t fee             = 100000ULL;    // 0.001 XNA
  uint64_t sendAmount      = 50000000ULL;  // 0.5 XNA
  uint64_t changeAmount    = availableAmount - sendAmount - fee;

  // 3. Build the transaction
  Tx tx;
  TxIn txIn(PREV_TXID, PREV_VOUT);
  tx.addInput(txIn);
  tx.addOutput(TxOut(sendAmount, destAddr.c_str()));
  tx.addOutput(TxOut(changeAmount, fromAddr.c_str()));

  Serial.println("unsigned tx:");
  Serial.println(tx);

  // 4. Sign input 0 (P2PKH, SIGHASH_ALL)
  Signature sig = tx.signInput(0, signKey);
  Serial.print("signature: "); Serial.println(sig);

  Serial.println("signed tx:");
  Serial.println(tx);
  Serial.print("txid: "); Serial.println(tx.txid());
}

void setup() {
  Serial.begin(115200);
  while(!Serial){ ; }

  buildAndSign("Neurai mainnet", &Neurai,     1900);
  buildAndSign("NeuraiTest",     &NeuraiTest,    1);

  Serial.println();
  Serial.println("Done");
}

void loop() {
  delay(1000);
}
