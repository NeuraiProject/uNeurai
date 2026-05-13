#include <string.h>
#include <stdlib.h>
#include "NeuraiPQ.h"
#include "Hash.h"
#include "Conversion.h"
#include "utility/segwit_addr.h"

const ChainNetworkPQ NeuraiPQ = {
    "nq",                                // bech32 hrp
    1,                                   // witness version
    100,                                 // BIP-32 purpose (NIP-022)
    1900,                                // coin type
    { 0x04, 0x88, 0xac, 0x24 }           // xpqpriv version
};

const ChainNetworkPQ NeuraiPQTest = {
    "tnq",                               // bech32 hrp
    1,                                   // witness version
    100,                                 // BIP-32 purpose (NIP-022)
    1,                                   // coin type
    { 0x04, 0x35, 0x81, 0xd5 }           // tpqpriv version
};

const ChainNetworkPQ *const pqNetworks[] = {
    &NeuraiPQ,
    &NeuraiPQTest
};
const size_t pqNetworks_len = sizeof(pqNetworks) / sizeof(pqNetworks[0]);

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
    if(out == NULL || witnessScript == NULL || wsLen == 0) return 0;
    uint8_t descriptor[22];
    size_t descLen = buildAuthDescriptor(authType, pubkey, pkLen, descriptor, sizeof(descriptor));
    if(descLen == 0) return 0;

    uint8_t wsHash[32];
    sha256(witnessScript, wsLen, wsHash);

    /* preimage = [0x01] || auth_descriptor || sha256(witnessScript) — at most 1 + 21 + 32 = 54 bytes */
    uint8_t preimage[1 + 21 + 32];
    preimage[0] = UNEURAI_AUTHSCRIPT_VERSION;
    memcpy(preimage + 1, descriptor, descLen);
    memcpy(preimage + 1 + descLen, wsHash, 32);
    size_t preLen = 1 + descLen + 32;

    taggedHashAuthScript(preimage, preLen, out);
    return 1;
}

size_t buildAuthScriptScriptPubKey(const uint8_t commitment[32],
                                   uint8_t *out, size_t outLen){
    if(out == NULL || commitment == NULL || outLen < 34) return 0;
    out[0] = 0x51;       /* OP_1 */
    out[1] = 0x20;       /* push 32 bytes */
    memcpy(out + 2, commitment, 32);
    return 34;
}

/* ---------------------------- PQ address codec ---------------------------- */

size_t pqAddressFromPubKey(const ChainNetworkPQ *net,
                           const uint8_t pqPubKey[UNEURAI_PQ_PUBKEY_RAW_LEN],
                           char *out, size_t outLen){
    if(net == NULL || pqPubKey == NULL || out == NULL || outLen == 0) return 0;
    const uint8_t witnessScript[1] = { 0x51 }; /* OP_TRUE — phase 1 default */
    uint8_t commitment[32];
    if(!buildAuthScriptCommitment(UNEURAI_AUTHTYPE_PQ,
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
