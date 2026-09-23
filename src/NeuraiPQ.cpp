#include <string.h>
#include <stdlib.h>
#include "NeuraiPQ.h"
#include "Hash.h"
#include "Conversion.h"
#include "utility/segwit_addr.h"

#if defined(UNEURAI_ENABLE_PQ) && defined(ARDUINO_ARCH_ESP32)
#include <MLDSA44.h>
#endif

/* Generic AuthScript witness v1 with a PQ key (the NeuraiHW phase-1 flow).
 * HRP "nc"/"tnc" since 0.2.0 (was "nq"/"tnq", now rejected by the node). */
const ChainNetworkPQ NeuraiPQ = {
    UNEURAI_HRP_AUTHSCRIPT,              // bech32 hrp
    UNEURAI_WITVER_AUTHSCRIPT,           // witness version
    100,                                 // BIP-32 purpose (NIP-022)
    1900,                                // coin type
    { 0x04, 0x88, 0xac, 0x24 }           // xpqpriv version
};

const ChainNetworkPQ NeuraiPQTest = {
    UNEURAI_HRP_AUTHSCRIPT_TEST,         // bech32 hrp
    UNEURAI_WITVER_AUTHSCRIPT,           // witness version
    100,                                 // BIP-32 purpose (NIP-022)
    1,                                   // coin type
    { 0x04, 0x35, 0x81, 0xd5 }           // tpqpriv version
};

const ChainNetworkPQ &NeuraiPQV1 = NeuraiPQ;
const ChainNetworkPQ &NeuraiPQV1Test = NeuraiPQTest;

/* Strict PQ witness v2: same NIP-022 key tree, its own HRP and lead byte. */
const ChainNetworkPQ NeuraiPQV2 = {
    UNEURAI_HRP_PQ,                      // bech32 hrp
    UNEURAI_WITVER_PQ,                   // witness version
    100,                                 // BIP-32 purpose (NIP-022)
    1900,                                // coin type
    { 0x04, 0x88, 0xac, 0x24 }           // xpqpriv version
};

const ChainNetworkPQ NeuraiPQV2Test = {
    UNEURAI_HRP_PQ_TEST,                 // bech32 hrp
    UNEURAI_WITVER_PQ,                   // witness version
    100,                                 // BIP-32 purpose (NIP-022)
    1,                                   // coin type
    { 0x04, 0x35, 0x81, 0xd5 }           // tpqpriv version
};

const ChainNetworkPQ *const pqNetworks[] = {
    &NeuraiPQ,
    &NeuraiPQTest,
    &NeuraiPQV2,
    &NeuraiPQV2Test
};
const size_t pqNetworks_len = sizeof(pqNetworks) / sizeof(pqNetworks[0]);

/* ---------------------------- Address families ---------------------------- */

struct AuthScriptFamily {
    uint8_t     witnessVersion;
    const char *hrpMain;
    const char *hrpTest;
};

/* Canonical HRP / witness-version pairs (node base58.cpp DecodeDestination). */
static const AuthScriptFamily AUTHSCRIPT_FAMILIES[] = {
    { UNEURAI_WITVER_AUTHSCRIPT, UNEURAI_HRP_AUTHSCRIPT, UNEURAI_HRP_AUTHSCRIPT_TEST },
    { UNEURAI_WITVER_PQ,         UNEURAI_HRP_PQ,         UNEURAI_HRP_PQ_TEST         },
    { UNEURAI_WITVER_ECDSA,      UNEURAI_HRP_ECDSA,      UNEURAI_HRP_ECDSA_TEST      },
};
static const size_t AUTHSCRIPT_FAMILIES_LEN =
    sizeof(AUTHSCRIPT_FAMILIES) / sizeof(AUTHSCRIPT_FAMILIES[0]);

/* Longest Bech32 string the node's decoder accepts (bech32.cpp). */
#define UNEURAI_BECH32_MAX_LEN 90

uint8_t strictAuthScriptWitnessVersion(uint8_t authType){
    if(authType == UNEURAI_AUTHTYPE_PQ) return UNEURAI_WITVER_PQ;
    if(authType == UNEURAI_AUTHTYPE_ECDSA) return UNEURAI_WITVER_ECDSA;
    return 0;
}

uint8_t strictAuthScriptAuthType(uint8_t witnessVersion){
    if(witnessVersion == UNEURAI_WITVER_PQ) return UNEURAI_AUTHTYPE_PQ;
    if(witnessVersion == UNEURAI_WITVER_ECDSA) return UNEURAI_AUTHTYPE_ECDSA;
    return 0;
}

bool isStrictAuthScriptWitnessVersion(uint8_t witnessVersion){
    return witnessVersion == UNEURAI_WITVER_PQ || witnessVersion == UNEURAI_WITVER_ECDSA;
}

const char *authScriptHrp(uint8_t witnessVersion, bool testnet){
    for(size_t i = 0; i < AUTHSCRIPT_FAMILIES_LEN; i++){
        if(AUTHSCRIPT_FAMILIES[i].witnessVersion == witnessVersion){
            return testnet ? AUTHSCRIPT_FAMILIES[i].hrpTest : AUTHSCRIPT_FAMILIES[i].hrpMain;
        }
    }
    return NULL;
}

size_t authScriptAddressEncode(uint8_t witnessVersion, bool testnet,
                               const uint8_t program[32],
                               char *out, size_t outLen){
    if(program == NULL || out == NULL || outLen == 0) return 0;
    const char *hrp = authScriptHrp(witnessVersion, testnet);
    if(hrp == NULL) return 0;
    char addr[100] = {0};
    if(!segwit_addr_encode(addr, hrp, witnessVersion, program, 32)) return 0;
    size_t l = strlen(addr);
    if(l >= outLen) return 0;
    memcpy(out, addr, l);
    out[l] = '\0';
    return l;
}

int authScriptAddressDecode(const char *addr,
                            uint8_t *witnessVersion, bool *testnet,
                            uint8_t program[32]){
    if(addr == NULL) return 0;
    size_t len = strlen(addr);
    if(len < 8 || len > UNEURAI_BECH32_MAX_LEN) return 0;

    /* Read the (lower-cased) HRP first, then decode against it. */
    char hrp[UNEURAI_BECH32_MAX_LEN + 1];
    uint8_t data[UNEURAI_BECH32_MAX_LEN + 1];
    size_t dataLen = 0;
    enum bech32_variant variant;
    if(!bech32_decode_variant(hrp, data, &dataLen, addr, &variant)) return 0;

    for(size_t i = 0; i < AUTHSCRIPT_FAMILIES_LEN; i++){
        const AuthScriptFamily *f = &AUTHSCRIPT_FAMILIES[i];
        bool isTest;
        if(strcmp(hrp, f->hrpMain) == 0){
            isTest = false;
        }else if(strcmp(hrp, f->hrpTest) == 0){
            isTest = true;
        }else{
            continue;
        }
        int ver = -1;
        uint8_t prog[40];
        size_t progLen = 0;
        if(!segwit_addr_decode(&ver, prog, &progLen, hrp, addr)) return 0;
        /* The HRP fixes the witness version: e.g. nq1p… (v1 under "nq") is invalid. */
        if(ver != (int)f->witnessVersion || progLen != 32) return 0;
        if(witnessVersion != NULL) *witnessVersion = f->witnessVersion;
        if(testnet != NULL) *testnet = isTest;
        if(program != NULL) memcpy(program, prog, 32);
        return 1;
    }
    return 0;
}

uint8_t authScriptWitnessVersionOf(const uint8_t *script, size_t len){
    if(script == NULL || len < 34 || script[1] != 0x20) return 0;
    /* Exactly the witness program, or followed by an asset payload. */
    if(len > 34 && script[34] != 0xc0) return 0;             /* OP_XNA_ASSET */
    if(script[0] == 0x51) return UNEURAI_WITVER_AUTHSCRIPT; /* OP_1 */
    if(script[0] == 0x52) return UNEURAI_WITVER_PQ;         /* OP_2 */
    if(script[0] == 0x53) return UNEURAI_WITVER_ECDSA;      /* OP_3 */
    return 0;
}

/* ---------------------------- AuthScript primitives ---------------------------- */

void taggedHashAuthScript(const uint8_t *data, size_t len, uint8_t out[32]){
    static const char tag[] = UNEURAI_AUTHSCRIPT_TAG;
    uint8_t tagHash[32];
    sha256((const uint8_t *)tag, sizeof(tag) - 1, tagHash);

    SHA256 h;
    h.begin();
    h.write(tagHash, 32);
    h.write(tagHash, 32);
    if(data != NULL && len > 0){
        h.write(data, len);
    }
    h.end(out);
}

size_t buildAuthDescriptor(uint8_t authType,
                           const uint8_t *pubkey, size_t pkLen,
                           uint8_t *out, size_t outLen){
    if(out == NULL) return 0;
    if(authType == UNEURAI_AUTHTYPE_NOAUTH){
        if(outLen < 1) return 0;
        out[0] = UNEURAI_AUTHTYPE_NOAUTH;
        return 1;
    }
    if(authType == UNEURAI_AUTHTYPE_PQ){
        if(pubkey == NULL || pkLen != UNEURAI_PQ_PUBKEY_RAW_LEN) return 0;
        if(outLen < 21) return 0;
        /* hash160(0x05 || pubkey) without allocating the 1313-byte concat. */
        SHA256 sha;
        uint8_t prefix = UNEURAI_PQ_PUBKEY_PREFIX;
        sha.begin();
        sha.write(&prefix, 1);
        sha.write(pubkey, pkLen);
        uint8_t shaOut[32];
        sha.end(shaOut);
        out[0] = UNEURAI_AUTHTYPE_PQ;
        rmd160(shaOut, 32, out + 1);
        return 21;
    }
    if(authType == UNEURAI_AUTHTYPE_LEGACY){
        if(pubkey == NULL || pkLen == 0) return 0;
        if(outLen < 21) return 0;
        out[0] = UNEURAI_AUTHTYPE_LEGACY;
        hash160(pubkey, pkLen, out + 1);
        return 21;
    }
    return 0;
}

int buildAuthScriptCommitment(uint8_t authType,
                              const uint8_t *pubkey, size_t pkLen,
                              const uint8_t *witnessScript, size_t wsLen,
                              uint8_t out[32]){
    return buildVersionedAuthScriptCommitment(UNEURAI_WITVER_AUTHSCRIPT, authType,
                                              pubkey, pkLen, witnessScript, wsLen, out);
}

int buildVersionedAuthScriptCommitment(uint8_t witnessVersion, uint8_t authType,
                                       const uint8_t *pubkey, size_t pkLen,
                                       const uint8_t *witnessScript, size_t wsLen,
                                       uint8_t out[32]){
    if(out == NULL || witnessScript == NULL || wsLen == 0) return 0;
    if(witnessVersion != UNEURAI_WITVER_AUTHSCRIPT){
        /* Strict families: fixed authType, OP_TRUE witnessScript and key shape. */
        if(!isStrictAuthScriptWitnessVersion(witnessVersion)) return 0;
        if(authType != strictAuthScriptAuthType(witnessVersion)) return 0;
        if(wsLen != 1 || witnessScript[0] != UNEURAI_STRICT_WITNESS_SCRIPT) return 0;
        if(witnessVersion == UNEURAI_WITVER_ECDSA){
            if(pubkey == NULL || pkLen != 33 || (pubkey[0] != 0x02 && pubkey[0] != 0x03)) return 0;
        }
    }
    uint8_t descriptor[22];
    size_t descLen = buildAuthDescriptor(authType, pubkey, pkLen, descriptor, sizeof(descriptor));
    if(descLen == 0) return 0;

    uint8_t wsHash[32];
    sha256(witnessScript, wsLen, wsHash);

    /* preimage = witnessVersion || auth_descriptor || sha256(witnessScript) — at most 1 + 21 + 32 = 54 bytes */
    uint8_t preimage[1 + 21 + 32];
    preimage[0] = witnessVersion;
    memcpy(preimage + 1, descriptor, descLen);
    memcpy(preimage + 1 + descLen, wsHash, 32);
    size_t preLen = 1 + descLen + 32;

    taggedHashAuthScript(preimage, preLen, out);
    return 1;
}

size_t buildAuthScriptScriptPubKey(const uint8_t commitment[32],
                                   uint8_t *out, size_t outLen){
    return buildVersionedAuthScriptScriptPubKey(UNEURAI_WITVER_AUTHSCRIPT, commitment, out, outLen);
}

size_t buildVersionedAuthScriptScriptPubKey(uint8_t witnessVersion,
                                            const uint8_t commitment[32],
                                            uint8_t *out, size_t outLen){
    if(out == NULL || commitment == NULL || outLen < 34) return 0;
    if(authScriptHrp(witnessVersion, false) == NULL) return 0; /* only v1 / v2 / v3 */
    out[0] = (uint8_t)(0x50 + witnessVersion);  /* OP_1 / OP_2 / OP_3 */
    out[1] = 0x20;                               /* push 32 bytes */
    memcpy(out + 2, commitment, 32);
    return 34;
}

int ecdsaCommitmentFromPubKey(const uint8_t pubkey[33], uint8_t out[32]){
    const uint8_t witnessScript[1] = { UNEURAI_STRICT_WITNESS_SCRIPT };
    return buildVersionedAuthScriptCommitment(UNEURAI_WITVER_ECDSA, UNEURAI_AUTHTYPE_ECDSA,
                                              pubkey, 33, witnessScript, sizeof(witnessScript), out);
}

size_t ecdsaAddressFromPubKey(const uint8_t pubkey[33], bool testnet,
                              char *out, size_t outLen){
    uint8_t commitment[32];
    if(!ecdsaCommitmentFromPubKey(pubkey, commitment)) return 0;
    return authScriptAddressEncode(UNEURAI_WITVER_ECDSA, testnet, commitment, out, outLen);
}

int parseCovenantPQTxHashSelector(const uint8_t *script, size_t len,
                                  uint8_t *outSelector){
    if(script == NULL || outSelector == NULL) return 0;
    /* Fixed cancel-branch prefix: OP_IF OP_DUP OP_SHA256 0x20 <32> OP_EQUALVERIFY. */
    if(len < 39) return 0;                 /* prefix(37) + at least a 2-byte push */
    if(script[0]  != 0x63) return 0;       /* OP_IF        */
    if(script[1]  != 0x76) return 0;       /* OP_DUP       */
    if(script[2]  != 0xa8) return 0;       /* OP_SHA256    */
    if(script[3]  != 0x20) return 0;       /* push 32      */
    if(script[36] != 0x88) return 0;       /* OP_EQUALVERIFY */

    const uint8_t op = script[37];
    uint8_t sel;
    if(op >= 0x51 && op <= 0x60){          /* OP_1..OP_16 -> 1..16 */
        sel = (uint8_t)(op - 0x51 + 1);
    }else if(op == 0x01){                  /* 1-byte data push */
        sel = script[38];
    }else{
        return 0;
    }
    if(sel == 0) return 0;                 /* OP_TXHASH rejects selector 0 */
    *outSelector = sel;
    return 1;
}

/* ---------------------------- PQ address codec ---------------------------- */

size_t pqAddressFromPubKey(const ChainNetworkPQ *net,
                           const uint8_t pqPubKey[UNEURAI_PQ_PUBKEY_RAW_LEN],
                           char *out, size_t outLen){
    if(net == NULL || pqPubKey == NULL || out == NULL || outLen == 0) return 0;
    const uint8_t witnessScript[1] = { UNEURAI_STRICT_WITNESS_SCRIPT }; /* OP_TRUE */
    uint8_t commitment[32];
    if(!buildVersionedAuthScriptCommitment(net->witnessVersion, UNEURAI_AUTHTYPE_PQ,
                                           pqPubKey, UNEURAI_PQ_PUBKEY_RAW_LEN,
                                           witnessScript, sizeof(witnessScript),
                                           commitment)){
        return 0;
    }
    char addr[100] = {0};
    if(!segwit_addr_encode(addr, net->bech32, net->witnessVersion, commitment, 32)){
        return 0;
    }
    size_t l = strlen(addr);
    if(l >= outLen) return 0;
    memcpy(out, addr, l);
    out[l] = '\0';
    return l;
}

int pqAddressDecode(const char *addr,
                    const ChainNetworkPQ *net,
                    uint8_t commitment[32]){
    if(addr == NULL || net == NULL || commitment == NULL) return 0;
    int witver = -1;
    uint8_t prog[40];
    size_t prog_len = 0;
    if(!segwit_addr_decode(&witver, prog, &prog_len, net->bech32, addr)) return 0;
    if(witver != net->witnessVersion || prog_len != 32) return 0;
    memcpy(commitment, prog, 32);
    return 1;
}

/* ---------------------------- PQ HD key ---------------------------- */

static const char PQ_SEED_KEY[] = "Neurai PQ seed";

PQHDPrivateKey::PQHDPrivateKey()
    : depth(0), childNumber(0), network(NULL){
    memset(pqSeed, 0, sizeof(pqSeed));
    memset(chainCode, 0, sizeof(chainCode));
    memset(parentFingerprint, 0, sizeof(parentFingerprint));
}

int PQHDPrivateKey::fromMnemonic(const char *mnemonic, size_t mnemonicLen,
                                 const char *password, size_t passwordLen,
                                 const ChainNetworkPQ *net){
    if(mnemonic == NULL || net == NULL) return 0;

    uint8_t seed64[64];
    bip39SeedFromMnemonic(mnemonic, mnemonicLen,
                          password ? password : "",
                          password ? passwordLen : 0,
                          seed64, NULL);

    uint8_t I[64];
    sha512Hmac((const uint8_t *)PQ_SEED_KEY, sizeof(PQ_SEED_KEY) - 1,
               seed64, sizeof(seed64), I);
    memcpy(pqSeed,    I,      32);
    memcpy(chainCode, I + 32, 32);
    memset(parentFingerprint, 0, 4);
    depth = 0;
    childNumber = 0;
    network = net;
    return 1;
}

int PQHDPrivateKey::deriveChild(uint32_t index, PQHDPrivateKey *out) const{
    if(out == NULL) return 0;
    if((index & UNEURAI_PQ_HARDENED_OFFSET) == 0) return 0; // hardened only

    /* data = 0x00 || pqSeed(32) || ser32be(index)  -> 37 bytes */
    uint8_t data[1 + 32 + 4];
    data[0] = 0x00;
    memcpy(data + 1, pqSeed, 32);
    data[33] = (uint8_t)((index >> 24) & 0xff);
    data[34] = (uint8_t)((index >> 16) & 0xff);
    data[35] = (uint8_t)((index >>  8) & 0xff);
    data[36] = (uint8_t)((index      ) & 0xff);

    uint8_t I[64];
    sha512Hmac(chainCode, 32, data, sizeof(data), I);

    out->depth = (uint8_t)(depth + 1);
    out->childNumber = index;
    /* parentFingerprint is hash160(0x05 || pubkey).first4. We cannot compute
     * it on host without ML-DSA. Leave zeros; callers that need it must set
     * it after materializing the parent pubkey. */
    memset(out->parentFingerprint, 0, 4);
    memcpy(out->pqSeed,    I,      32);
    memcpy(out->chainCode, I + 32, 32);
    out->network = network;
    return 1;
}

void PQHDPrivateKey::fingerprintFromPubKey(const uint8_t pqPubKey[UNEURAI_PQ_PUBKEY_RAW_LEN],
                                           uint8_t out[4]) const{
    if(pqPubKey == NULL || out == NULL) return;
    SHA256 sha;
    uint8_t prefix = UNEURAI_PQ_PUBKEY_PREFIX;
    sha.begin();
    sha.write(&prefix, 1);
    sha.write(pqPubKey, UNEURAI_PQ_PUBKEY_RAW_LEN);
    uint8_t shaOut[32];
    sha.end(shaOut);
    uint8_t fp[20];
    rmd160(shaOut, 32, fp);
    memcpy(out, fp, 4);
}

int PQHDPrivateKey::derive(const char *path, PQHDPrivateKey *out) const{
    if(path == NULL || out == NULL) return 0;
    size_t n = strlen(path);
    if(n == 0) return 0;

    /* Identify root segment: "m", "M", "m_pq" or "M_pq". */
    size_t i = 0;
    if(n >= 4 && (memcmp(path, "m_pq", 4) == 0 || memcmp(path, "M_pq", 4) == 0)){
        i = 4;
    }else if(path[0] == 'm' || path[0] == 'M'){
        i = 1;
    }else{
        return 0;
    }

    PQHDPrivateKey current = *this;
    /* Path may be just "m_pq" -> return copy. */
    while(i < n){
        if(path[i] != '/') return 0;
        i++;
        /* read decimal index until "'" */
        if(i >= n) return 0;
        uint64_t v = 0;
        size_t digits = 0;
        while(i < n && path[i] >= '0' && path[i] <= '9'){
            v = v * 10 + (uint64_t)(path[i] - '0');
            if(v >= UNEURAI_PQ_HARDENED_OFFSET) return 0;
            digits++;
            i++;
        }
        if(digits == 0) return 0;
        if(i >= n || path[i] != '\'') return 0; // hardened required
        i++;

        uint32_t idx = (uint32_t)v | UNEURAI_PQ_HARDENED_OFFSET;
        PQHDPrivateKey next;
        if(!current.deriveChild(idx, &next)) return 0;
        current = next;
    }

    *out = current;
    return 1;
}

size_t PQHDPrivateKey::xpqp(char *out, size_t outLen) const{
    if(out == NULL || network == NULL) return 0;
    /* version(4) || payload(74) = 78 bytes; toBase58Check appends 4-byte checksum
     * and base58-encodes the lot. */
    uint8_t raw[4 + UNEURAI_PQ_EXTKEY_PAYLOAD_LEN];
    memcpy(raw, network->pqExtPrivVersion, 4);
    raw[4] = depth;
    memcpy(raw + 5, parentFingerprint, 4);
    raw[9]  = (uint8_t)((childNumber >> 24) & 0xff);
    raw[10] = (uint8_t)((childNumber >> 16) & 0xff);
    raw[11] = (uint8_t)((childNumber >>  8) & 0xff);
    raw[12] = (uint8_t)((childNumber      ) & 0xff);
    memcpy(raw + 13, chainCode, 32);
    raw[45] = 0x00;
    memcpy(raw + 46, pqSeed, 32);

    char buf[UNEURAI_PQ_EXTKEY_BASE58_MAX] = {0};
    size_t l = toBase58Check(raw, sizeof(raw), buf, sizeof(buf));
    if(l == 0 || l >= outLen) return 0;
    memcpy(out, buf, l);
    out[l] = '\0';
    return l;
}

#if defined(UNEURAI_ENABLE_PQ) && defined(ARDUINO_ARCH_ESP32)
int PQHDPrivateKey::materializeKeyPair(uint8_t pk[UNEURAI_PQ_PUBKEY_RAW_LEN], uint8_t sk[2560]) const{
    if(pk == NULL || sk == NULL) return 0;
    /* MLDSA44::generateKeypairFromSeed expects 32-byte seed (MLDSA_SEEDBYTES). */
    int r = MLDSA44::generateKeypairFromSeed(pk, sk, pqSeed);
    return r == 0 ? 1 : 0;
}
#endif

int PQHDPrivateKey::fromXpqp(const char *str, const ChainNetworkPQ *net){
    if(str == NULL || net == NULL) return 0;
    uint8_t raw[4 + UNEURAI_PQ_EXTKEY_PAYLOAD_LEN];
    size_t l = fromBase58Check(str, strlen(str), raw, sizeof(raw));
    if(l != sizeof(raw)) return 0;
    if(memcmp(raw, net->pqExtPrivVersion, 4) != 0) return 0;
    if(raw[45] != 0x00) return 0; // padding byte

    depth = raw[4];
    memcpy(parentFingerprint, raw + 5, 4);
    childNumber = ((uint32_t)raw[9] << 24)
                | ((uint32_t)raw[10] << 16)
                | ((uint32_t)raw[11] << 8)
                | ((uint32_t)raw[12]);
    memcpy(chainCode, raw + 13, 32);
    memcpy(pqSeed,    raw + 46, 32);
    network = net;
    return 1;
}
