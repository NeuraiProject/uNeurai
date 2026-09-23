/*
 * Neurai Post-Quantum (NIP-022 / ML-DSA-44) example.
 *
 * Generates the PQ addresses of a mnemonic key and signs example transactions:
 *   - generic AuthScript witness v1 (tnc1p… / nc1p…, authType 0x01,
 *     witnessScript OP_TRUE) with Tx::signAuthScriptInputPQ — the address
 *     family the NeuraiHW firmware uses today;
 *   - strict PQ witness v2 (tpq1z… / pq1z…) with Tx::signAuthScriptInputPQStrict.
 *     The strict families are only active on regtest for now: do not pay to a
 *     pq1z… address on a chain where the node has not activated them.
 *
 * Hardware:    ESP32 (any S2/S3/C3 variant with >=320 KB RAM)
 * Dependency:  mldsa-esp32   https://github.com/NeuraiProject/mldsa-esp32
 *
 * PlatformIO setup (platformio.ini):
 *
 *   [env:esp32-s3-devkitc-1]
 *   platform   = espressif32
 *   board      = esp32-s3-devkitc-1
 *   framework  = arduino
 *   lib_deps   =
 *       https://github.com/NeuraiProject/uNeurai
 *       https://github.com/NeuraiProject/mldsa-esp32
 *   build_flags = -DUNEURAI_ENABLE_PQ
 *
 * Arduino IDE: install both libraries via the Library Manager (or via "Add .ZIP
 * library...") and add `-DUNEURAI_ENABLE_PQ` to your build flags. Without that
 * flag the PQ APIs are not compiled.
 *
 * Memory note: ML-DSA-44 keypair generation + signing needs roughly 30 KB of
 * stack. Run the workflow inside a FreeRTOS task with at least 65 KB stack
 * (see cryptoTask() below).
 */

#define UNEURAI_ENABLE_PQ  // safe to define here too; redefinition is fine if also set in build flags

#include <Arduino.h>
#include "Neurai.h"
#include "NeuraiPQ.h"

static const char MNEMONIC[] =
    "result pact model attract result puzzle final boss private educate luggage era";

static void hexPrint(const char *label, const uint8_t *data, size_t len){
    Serial.print(label);
    Serial.print(" (");
    Serial.print(len);
    Serial.print(" bytes): ");
    for(size_t i = 0; i < len; i++){
        if(data[i] < 0x10) Serial.print('0');
        Serial.print(data[i], HEX);
    }
    Serial.println();
}

static void cryptoTask(void *arg){
    (void)arg;

    Serial.println();
    Serial.println("=== Neurai PQ example (ML-DSA-44, AuthScript v1 + strict PQ v2) ===");

    /* ------------- 1. HD-PQ derivation (NIP-022, hardened-only) ------------- */
    PQHDPrivateKey master;
    if(!master.fromMnemonic(MNEMONIC, strlen(MNEMONIC), "", 0, &NeuraiPQTest)){
        Serial.println("fromMnemonic failed"); vTaskDelete(NULL); return;
    }

    PQHDPrivateKey child;
    if(!master.derive("m_pq/100'/1'/0'/0'/0'", &child)){
        Serial.println("derive failed"); vTaskDelete(NULL); return;
    }
    hexPrint("pq seed     ", child.pqSeed, 32);
    hexPrint("chain code  ", child.chainCode, 32);

    /* ------------- 2. ML-DSA-44 key pair + PQ addresses ------------- */
    static uint8_t pk[UNEURAI_PQ_PUBKEY_RAW_LEN];
    static uint8_t sk[2560];
    unsigned long t0 = millis();
    if(!child.materializeKeyPair(pk, sk)){
        Serial.println("materializeKeyPair failed"); vTaskDelete(NULL); return;
    }
    Serial.print("ml-dsa keygen took ");
    Serial.print(millis() - t0);
    Serial.println(" ms");

    char addr[UNEURAI_AUTHSCRIPT_ADDRESS_MAX] = {0};
    /* Generic AuthScript v1: tnc1pdsj0aztvgwv3rwgml360stpyp228zrggyga6n4sdenmetm6wv3tqse52vk */
    pqAddressFromPubKey(&NeuraiPQTest, pk, addr, sizeof(addr));
    Serial.print("v1 address: "); Serial.println(addr);
    /* Strict PQ v2: tpq1zxsjnzvjnwn7vt04nkx6qthvylqwej33r53duxawl0uwd3ewme4nsy38hld */
    pqAddressFromPubKey(&NeuraiPQV2Test, pk, addr, sizeof(addr));
    Serial.print("v2 address: "); Serial.println(addr);

    /* ------------- 3. Build a tiny Tx that spends one AuthScript input ------------- */
    Tx tx;
    tx.version = 2;
    tx.locktime = 0;

    /* Fake UTXO: prev txid = 0x11..11, vout = 0, amount = 1 XNA, RBF sequence. */
    uint8_t prevTxid[32];
    memset(prevTxid, 0x11, sizeof(prevTxid));
    TxIn in(prevTxid, 0, /*sequence*/ 0xfffffffdU);
    tx.addInput(in);

    /* Output: send 0.9999 XNA to a P2PKH placeholder (20 bytes 0xab). */
    uint8_t pkhScript[25] = {
        0x76, 0xa9, 0x14,
        0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,
        0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,
        0x88, 0xac
    };
    Script outScript(pkhScript, sizeof(pkhScript));
    tx.addOutput(TxOut(99990000ULL, outScript));

    /* ------------- 4. Sign with generic AuthScript witness v1 ------------- */
    uint8_t opTrue[1] = { 0x51 };
    Script witnessScript(opTrue, sizeof(opTrue));

    t0 = millis();
    int ok = tx.signAuthScriptInputPQ(0, sk, pk, /*amount*/ 100000000ULL,
                                      witnessScript, SIGHASH_ALL);
    Serial.print("ml-dsa sign took ");
    Serial.print(millis() - t0);
    Serial.println(" ms");
    if(!ok){
        Serial.println("signAuthScriptInputPQ failed"); vTaskDelete(NULL); return;
    }

    /* To spend a strict PQ v2 (tpq1z…) output instead, the witnessScript is
     * fixed (OP_TRUE) and the sighash commits to the witness version:
     *     tx.signAuthScriptInputPQStrict(0, sk, pk, 100000000ULL, SIGHASH_ALL);
     * Both produce the witness [0x01, sig||hashType, 0x05||pk, 0x51]. */

    /* ------------- 5. Emit the final transaction hex ------------- */
    static char txHex[12000];
    size_t hx = tx.serialize((uint8_t *)txHex, sizeof(txHex));
    if(hx == 0){
        Serial.println("serialize failed"); vTaskDelete(NULL); return;
    }
    Serial.print("signed tx (raw, ");
    Serial.print(hx);
    Serial.println(" bytes):");
    for(size_t i = 0; i < hx; i++){
        if(((uint8_t *)txHex)[i] < 0x10) Serial.print('0');
        Serial.print(((uint8_t *)txHex)[i], HEX);
    }
    Serial.println();

    vTaskDelete(NULL);
}

void setup(){
    Serial.begin(115200);
    delay(1500);

    /* ML-DSA-44 keygen + sign on ESP32 needs ~30 KB of stack. Use 65 KB to
     * leave plenty of headroom for our own buffers (pubkey 1312 + serialized
     * tx ~4 KB + assorted). */
    xTaskCreate(cryptoTask, "uneurai-pq", 65536, NULL, 5, NULL);
}

void loop(){
    delay(10000);
}
