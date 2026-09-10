#ifdef UXNA_TEST // only compile with test flag

/* Message signing (signmessage-compatible) against the DePIN Messaging
 * Protocol 2 vectors: Neurai/doc/depin-messaging-protocol.md §13 and
 * Neurai/contrib/depin/vectors.txt (regtest keys, never fund them). */

#include <string.h>
#include "minunit.h"
#include "Message.h"
#include "Hash.h"
#include "Conversion.h"

using std::string;

/* §13.1 keys (REGTEST ONLY) */
static const char HOLDER_WIF[]     = "cW8vy4nJbZZ4W4L8CsRZp22h3WeWrCXgNwrm1264wW8VAmzHMuJ4";
static const char HOLDER_PUBKEY[]  = "032abff8246242d5d16a80148018d683ad5415edc1164ab1c3d90e57760bc5f0f3";
static const char HOLDER_ADDRESS[] = "tRERn8G265FxuHmiWVYtZ84ntQjW56BF8n";
static const char POOL_PUBKEY[]    = "03649c7a094c76b63995e60f891c13d9440b12b65b46ad8426cb153789e816b01b";
static const char POOL_ADDRESS[]   = "tDudNSQstiVQu3Prbs7yFwbYtDrcU19eKJ";

/* §13.2 challenge request / use */
static const char REQ_PREIMAGE[]  = "DEPIN-REQ|receive|&TEST/SEC|tRERn8G265FxuHmiWVYtZ84ntQjW56BF8n|1730000000000";
static const char REQ_SIGNATURE[] = "IIMy0pTVnBwcxFYaqFsxaGbsNvXPuRbQ7Deey3kMIQ1jRhUZ+HQgoTfeDslbQ83yqyJ6vptnBa1DC31VqD74dhs=";
static const char GET_PREIMAGE[]  = "DEPIN-GET|&TEST/SEC|tRERn8G265FxuHmiWVYtZ84ntQjW56BF8n|000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static const char GET_SIGNATURE[] = "IB7YZLyXRnACLiZFCE4UIyYIfIwMsNqMLtzLuO5CdayuBZLDeXvp9PuYoBnUh84DOyuMPNt3Bvrbrb5yhlzdRd8=";

/* §13.3 plain reply: body is the ASCII hex string exactly as received */
static const char INFO_BODY[] =
    "7b22656e61626c6564223a747275652c22746f6b656e223a222654455354222c22636970686572223a224145532d3235"
    "362d47434d222c226d6178726563697069656e7473223a32302c226d61786d65737361676573697a65223a313032342c"
    "226d657373616765657870697279686f757273223a3136382c226d6178706f6f6c73697a656d62223a3130302c226d65"
    "737361676573223a302c226d656d6f72797573616765223a302c226d656d6f727975736167656d62223a302c2270726f"
    "746f636f6c223a322c22646570696e706f6f6c706b6579223a2230333634396337613039346337366236333939356536"
    "3066383931633133643934343062313262363562343661643834323663623135333738396538313662303162222c2264"
    "6570696e706f6f6c6b657961646472657373223a22744475644e53517374695651753350726273377946776259744472"
    "63553139654b4a222c22646570696e77616c6c6574223a2277616c6c65742e646174227d";
static const char INFO_POOLSIG[] = "H8MOG9VPuYvSghphjmuIns5quiTry+AMrC4kMIXEGyxXQFArA3wnsXq3C8wyNWCLOYsNNNYJXfGen269pyOqp3g=";

/* §13.4 / §13.5 bound replies: only the poolsig preimages are checked here */
static const char CHALLENGE_POOLSIG[] = "IEVB0i5eNa1/E0L7yr99MdrVbnYd21MqpemILA0NShpGXBQXSH3PobiKDo5rO6lI1PHSpzgz62/C1vw3lckcHg8=";
static const char RECEIVE_NONCE[]     = "9bbd728c3e35285321c594a6925b537d743ad11da328163715363511deeae8ef";
static const char RECEIVE_SIGNATURE[] = "IHpzi6TQUw3zps5j8BOWVegmqd/E1Atnugkto15aROxTCSIMlGFfYubkPXAUwEcuqGqgOnKADnoFxNbbvFz9Pgw=";

static string pubHex(const uint8_t pub[33]) { return toHex(pub, 33); }

/* DEPIN-RESP|method|token|address|challenge|sha256hex(bodystr) (§6.3) */
static string respPreimage(const char * method, const char * token, const char * address,
                           const char * challenge, const char * bodyStr) {
    uint8_t h[32];
    sha256((const uint8_t *)bodyStr, strlen(bodyStr), h);
    string p = "DEPIN-RESP|";
    p += method; p += "|"; p += token; p += "|"; p += address; p += "|"; p += challenge; p += "|";
    p += toHex(h, 32);
    return p;
}

MU_TEST(test_magic_hash_layout) {
    /* SHA256d( ser_string(magic) || ser_string(text) ) built by hand */
    const char text[] = "hello";
    uint8_t manual[64]; size_t n = 0;
    manual[n++] = (uint8_t)strlen(NEURAI_MESSAGE_MAGIC);
    memcpy(manual + n, NEURAI_MESSAGE_MAGIC, strlen(NEURAI_MESSAGE_MAGIC)); n += strlen(NEURAI_MESSAGE_MAGIC);
    manual[n++] = 5;
    memcpy(manual + n, text, 5); n += 5;
    uint8_t expect[32], got[32];
    doubleSha(manual, n, expect);
    messageMagicHash(text, got);
    mu_assert(memcmp(expect, got, 32) == 0, "magic hash layout");
    /* empty text is legal */
    messageMagicHash((const uint8_t *)"", 0, got);
    messageMagicHash("", expect);
    mu_assert(memcmp(expect, got, 32) == 0, "empty text overloads agree");
}

MU_TEST(test_holder_key_matches_vectors) {
    PrivateKey k(HOLDER_WIF);                       /* regtest WIF: prefix 0xef */
    uint8_t pub[33];
    mu_assert(k.publicKey().sec(pub, 33) == 33, "holder pubkey sec");
    mu_assert(pubHex(pub) == HOLDER_PUBKEY, "holder WIF -> pubkey (§13.1)");
    mu_assert(k.address() == HOLDER_ADDRESS, "holder pubkey -> address (§13.1)");
}

MU_TEST(test_sign_depin_req_vector) {
    PrivateKey k(HOLDER_WIF);
    char sig[NEURAI_MESSAGE_SIG_B64_LEN + 1];
    size_t n = signMessageBase64(k, REQ_PREIMAGE, sig, sizeof(sig));
    mu_assert(n == NEURAI_MESSAGE_SIG_B64_LEN, "DEPIN-REQ signature length");
    mu_assert_string_eq(REQ_SIGNATURE, sig);         /* deterministic: byte for byte (§13.2) */
}

MU_TEST(test_sign_depin_get_vector) {
    PrivateKey k(HOLDER_WIF);
    char sig[NEURAI_MESSAGE_SIG_B64_LEN + 1];
    mu_assert(signMessageBase64(k, GET_PREIMAGE, sig, sizeof(sig)) == NEURAI_MESSAGE_SIG_B64_LEN, "DEPIN-GET length");
    mu_assert_string_eq(GET_SIGNATURE, sig);

    /* §13.5: the DEPIN-GET over the issued challenge */
    string get = string("DEPIN-GET|&TEST/SEC|") + HOLDER_ADDRESS + "|" + RECEIVE_NONCE;
    mu_assert(signMessageBase64(k, get.c_str(), sig, sizeof(sig)) == NEURAI_MESSAGE_SIG_B64_LEN, "DEPIN-GET (13.5) length");
    mu_assert_string_eq(RECEIVE_SIGNATURE, sig);
}

MU_TEST(test_sign_raw_and_string_overloads) {
    PrivateKey k(HOLDER_WIF);
    uint8_t raw[NEURAI_MESSAGE_SIG_LEN];
    mu_assert(signMessage(k, REQ_PREIMAGE, raw) == NEURAI_MESSAGE_SIG_LEN, "raw sig length");
    mu_assert(raw[0] >= 31 && raw[0] <= 34, "compressed header 31..34");
    uint8_t dec[NEURAI_MESSAGE_SIG_LEN];
    mu_assert(fromBase64(REQ_SIGNATURE, strlen(REQ_SIGNATURE), dec, sizeof(dec)) == NEURAI_MESSAGE_SIG_LEN, "vector decodes");
    mu_assert(memcmp(raw, dec, NEURAI_MESSAGE_SIG_LEN) == 0, "raw bytes equal the vector");
    string s = signMessageBase64(k, string(REQ_PREIMAGE));
    mu_assert(s == REQ_SIGNATURE, "std::string overload");
    /* too-small buffer */
    char tiny[10];
    mu_assert(signMessageBase64(k, REQ_PREIMAGE, tiny, sizeof(tiny)) == 0, "small buffer rejected");
}

MU_TEST(test_recover_holder) {
    uint8_t pub[33];
    mu_assert(recoverMessageSigner(REQ_SIGNATURE, REQ_PREIMAGE, pub), "recover DEPIN-REQ signer");
    mu_assert(pubHex(pub) == HOLDER_PUBKEY, "recovered key == holder pubkey");
    mu_assert(recoverMessageSigner(GET_SIGNATURE, GET_PREIMAGE, pub), "recover DEPIN-GET signer");
    mu_assert(pubHex(pub) == HOLDER_PUBKEY, "recovered key == holder pubkey (GET)");
}

MU_TEST(test_verify_address_and_pubkey) {
    mu_assert(verifyMessage(HOLDER_ADDRESS, REQ_SIGNATURE, REQ_PREIMAGE), "verify against address");
    PublicKey pub(HOLDER_PUBKEY);
    mu_assert(verifyMessage(pub, REQ_SIGNATURE, REQ_PREIMAGE), "verify against pubkey");
    /* wrong text / wrong address / wrong key */
    mu_assert(!verifyMessage(HOLDER_ADDRESS, REQ_SIGNATURE, GET_PREIMAGE), "other text must fail");
    mu_assert(!verifyMessage(POOL_ADDRESS, REQ_SIGNATURE, REQ_PREIMAGE), "other address must fail");
    PublicKey poolPub(POOL_PUBKEY);
    mu_assert(!verifyMessage(poolPub, REQ_SIGNATURE, REQ_PREIMAGE), "other pubkey must fail");
    mu_assert(!verifyMessage("not-an-address", REQ_SIGNATURE, REQ_PREIMAGE), "garbage address");
    mu_assert(!verifyMessage(HOLDER_ADDRESS, "AAAA", REQ_PREIMAGE), "garbage signature");
}

MU_TEST(test_poolsig_plain_reply_vector) {
    /* §13.3: DEPIN-RESP|depingetmsginfo|&TEST|||sha256hex(body) signed by the pool key */
    string pre = respPreimage("depingetmsginfo", "&TEST", "", "", INFO_BODY);
    uint8_t pub[33];
    mu_assert(recoverMessageSigner(INFO_POOLSIG, pre.c_str(), pub), "recover poolsig signer");
    mu_assert(pubHex(pub) == POOL_PUBKEY, "poolsig signer == pool pubkey");
    mu_assert(verifyMessage(POOL_ADDRESS, INFO_POOLSIG, pre.c_str()), "poolsig verifies for pool address");

    /* hash160(pool pubkey) == pool address payload (§13.1 check) */
    PublicKey poolPub(POOL_PUBKEY);
    mu_assert(poolPub.address(&NeuraiTest) == POOL_ADDRESS, "pool pubkey -> pool address");
}

MU_TEST(test_poolsig_bound_replies_vectors) {
    /* §13.4: bound reply of depinchallenge, challenge "" in the preimage.
     * Only the preimage shape is exercised here (the encrypted blob is long);
     * the signature must NOT verify for a wrong method or a wrong challenge. */
    string good = string("DEPIN-RESP|depinchallenge|&TEST/SEC|") + HOLDER_ADDRESS + "||";
    string bad  = string("DEPIN-RESP|depinreceivemsg|&TEST/SEC|") + HOLDER_ADDRESS + "||";
    uint8_t pub[33];
    /* Without the encrypted body we can only assert that a different preimage
     * does not recover the pool key: */
    if (recoverMessageSigner(CHALLENGE_POOLSIG, bad.c_str(), pub)) {
        mu_assert(pubHex(pub) != POOL_PUBKEY, "wrong method must not recover the pool key");
    }
    if (recoverMessageSigner(CHALLENGE_POOLSIG, good.c_str(), pub)) {
        mu_assert(pubHex(pub) != POOL_PUBKEY, "preimage without sha256hex must not recover the pool key");
    }
}

MU_TEST(test_negative_n1_flipped_poolsig) {
    /* N1 (§13.7): base64-decode, XOR 0x01 into byte 40 (inside s), re-encode */
    uint8_t sig[NEURAI_MESSAGE_SIG_LEN];
    mu_assert(fromBase64(INFO_POOLSIG, strlen(INFO_POOLSIG), sig, sizeof(sig)) == NEURAI_MESSAGE_SIG_LEN, "decode poolsig");
    sig[40] ^= 0x01;
    char flipped[NEURAI_MESSAGE_SIG_B64_LEN + 1];
    size_t n = toBase64(sig, sizeof(sig), flipped, sizeof(flipped));
    flipped[n] = '\0';
    string pre = respPreimage("depingetmsginfo", "&TEST", "", "", INFO_BODY);
    uint8_t pub[33];
    if (recoverMessageSigner(flipped, pre.c_str(), pub)) {
        mu_assert(pubHex(pub) != POOL_PUBKEY, "N1: flipped poolsig must not recover the pool key");
    }
    mu_assert(!verifyMessage(POOL_ADDRESS, flipped, pre.c_str()), "N1: flipped poolsig must not verify");
}

MU_TEST(test_negative_n2_reserialized_body) {
    /* N2 (§13.7): hash the string received, never a re-serialization. A body
     * with the same JSON but different bytes changes sha256hex -> reject. */
    string body(INFO_BODY);
    /* swap two hex chars inside the body: same length, different string */
    body[10] = (body[10] == '2') ? '3' : '2';
    string pre = respPreimage("depingetmsginfo", "&TEST", "", "", body.c_str());
    mu_assert(!verifyMessage(POOL_ADDRESS, INFO_POOLSIG, pre.c_str()), "N2: altered body must not verify");
}

MU_TEST(test_uncompressed_header_roundtrip) {
    /* An uncompressed key signs with header 27..30 and verifies against its
     * uncompressed address; recoverMessageSigner still returns the compressed SEC. */
    uint8_t secret[32];
    memset(secret, 0x11, sizeof(secret));
    PrivateKey ku(secret, false, &NeuraiTest);
    uint8_t raw[NEURAI_MESSAGE_SIG_LEN];
    mu_assert(signMessage(ku, "abc", raw) == NEURAI_MESSAGE_SIG_LEN, "uncompressed sign");
    mu_assert(raw[0] >= 27 && raw[0] <= 30, "uncompressed header 27..30");
    char b64[NEURAI_MESSAGE_SIG_B64_LEN + 1];
    size_t n = toBase64(raw, sizeof(raw), b64, sizeof(b64)); b64[n] = '\0';
    mu_assert(verifyMessage(ku.address().c_str(), b64, "abc"), "verifies against uncompressed address");
    PrivateKey kc(secret, true, &NeuraiTest);
    mu_assert(!verifyMessage(kc.address().c_str(), b64, "abc"), "does not verify against the compressed address");
    uint8_t pub[33];
    mu_assert(recoverMessageSigner(b64, "abc", pub) && (pub[0] == 0x02 || pub[0] == 0x03), "recovered SEC is compressed");
}

/* ── Review findings on the first 0.0.10 draft (must stay rejected) ────────── */

/* Signature produced by the all-zero private key over "abc" (header 31, built
 * by hand from PrivateKey().sign() before signMessage() refused zero keys).
 * Recovery yields the point at infinity, i.e. 02||00*32 == PublicKey(). */
static const char ZERO_KEY_SIG_ABC[] = "Hxf6+wm7scSyEgqk5UfzIUclqVxob9zNLz1aIiJ1jqR1Fl8O9kDFUCnAEMB2Y1AVIae5nswuS2d/s0Nt4DfRVMQ=";

MU_TEST(test_p1_zero_pubkey_rejected) {
    uint8_t pub[33];
    memset(pub, 0xaa, sizeof(pub));
    mu_assert(!recoverMessageSigner(ZERO_KEY_SIG_ABC, "abc", pub), "P1: recovery of the infinity point must fail");
    mu_assert(!verifyMessage(PublicKey(), ZERO_KEY_SIG_ABC, "abc"), "P1: empty PublicKey must not verify its own zero-key signature");
    PublicKey bogus("020000000000000000000000000000000000000000000000000000000000000000");
    mu_assert(!verifyMessage(bogus, ZERO_KEY_SIG_ABC, "abc"), "P1: off-curve pubkey must not verify");
    /* the same bogus keys against a genuine signature */
    mu_assert(!verifyMessage(PublicKey(), REQ_SIGNATURE, REQ_PREIMAGE), "P1: empty PublicKey vs holder signature");
    mu_assert(!verifyMessage(bogus, REQ_SIGNATURE, REQ_PREIMAGE), "P1: off-curve pubkey vs holder signature");
    /* and no address can claim it either (hash160 of the zero point) */
    uint8_t zeroPub[33] = { 0x02 };
    uint8_t h[20];
    hash160(zeroPub, 33, h);
    uint8_t payload[21]; payload[0] = NeuraiTest.p2pkh; memcpy(payload + 1, h, 20);
    string addr = toBase58Check(payload, 21);
    mu_assert(!verifyMessage(addr.c_str(), ZERO_KEY_SIG_ABC, "abc"), "P1: address of the zero point must not verify");
}

MU_TEST(test_p2_zero_private_key_rejected) {
    char buf[NEURAI_MESSAGE_SIG_B64_LEN + 1];
    buf[0] = 'x';
    mu_assert(signMessageBase64(PrivateKey(), "abc", buf, sizeof(buf)) == 0, "P2: empty PrivateKey must not sign");
    uint8_t raw[NEURAI_MESSAGE_SIG_LEN];
    mu_assert(signMessage(PrivateKey(), "abc", raw) == 0, "P2: empty PrivateKey raw sign");
    /* Scalars >= n cannot be built through PrivateKey's constructor or
     * setSecret(): both multiply by G and trezor asserts on out-of-range
     * scalars in debug builds. RawScalarKey starts from a VALID key (so its
     * cached public key passes pub.isValid()) and then overwrites only the
     * scalar, so the only thing left to reject it is the range check inside
     * signMessage(). */
    struct RawScalarKey : public PrivateKey {
        RawScalarKey(const uint8_t valid[32]) : PrivateKey(valid, true, &NeuraiTest) {}
        void setRaw(const uint8_t a[32]) { memcpy(num, a, 32); }
    };
    uint8_t validSecret[32]; memset(validSecret, 0x11, sizeof(validSecret));
    static const uint8_t ORDER_N[32] = { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
                                         0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41 };
    RawScalarKey probe(validSecret);
    mu_assert(probe.publicKey().isValid(), "RawScalarKey starts with a valid public key");
    mu_assert(signMessage(probe, "abc", raw) == NEURAI_MESSAGE_SIG_LEN, "RawScalarKey signs before tampering");
    probe.setRaw(ORDER_N);
    mu_assert(probe.publicKey().isValid(), "public key still valid after tampering (only the range check can reject)");
    mu_assert(signMessage(probe, "abc", raw) == 0, "P2: d == n must not sign");
    uint8_t allOnes[32]; memset(allOnes, 0xff, sizeof(allOnes));
    probe.setRaw(allOnes);
    mu_assert(signMessage(probe, "abc", raw) == 0, "P2: d == 2^256-1 must not sign");
    uint8_t nPlus1[32]; memcpy(nPlus1, ORDER_N, 32); nPlus1[31] = 0x42;
    probe.setRaw(nPlus1);
    mu_assert(signMessage(probe, "abc", raw) == 0, "P2: d == n + 1 must not sign");
    uint8_t zero[32]; memset(zero, 0, sizeof(zero));
    probe.setRaw(zero);
    mu_assert(signMessage(probe, "abc", raw) == 0, "P2: d == 0 with a valid cached pubkey must not sign");

    /* n - 1 is the largest valid scalar and must still sign. */
    uint8_t nMinus1[32] = { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
                            0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x40 };
    PrivateKey maxKey(nMinus1, true, &NeuraiTest);
    mu_assert(signMessage(maxKey, "abc", raw) == NEURAI_MESSAGE_SIG_LEN, "n - 1 signs");
    char b64[NEURAI_MESSAGE_SIG_B64_LEN + 1];
    size_t n = toBase64(raw, sizeof(raw), b64, sizeof(b64)); b64[n] = '\0';
    mu_assert(verifyMessage(maxKey.address().c_str(), b64, "abc", &NeuraiTest), "n - 1 signature verifies");
}

MU_TEST(test_p3_prefix_and_network_checked) {
    /* same hash160, P2SH version byte (testnet 0xc4) and a valid checksum */
    uint8_t payload[25];
    mu_assert(fromBase58Check(HOLDER_ADDRESS, strlen(HOLDER_ADDRESS), payload, sizeof(payload)) == 21, "decode holder");
    mu_assert(payload[0] == NeuraiTest.p2pkh, "holder is a testnet/regtest P2PKH");
    payload[0] = NeuraiTest.p2sh;
    string p2sh = toBase58Check(payload, 21);
    mu_assert(!verifyMessage(p2sh.c_str(), REQ_SIGNATURE, REQ_PREIMAGE), "P3: P2SH address must not verify");
    payload[0] = 0x99;                             /* unknown prefix */
    string unknown = toBase58Check(payload, 21);
    mu_assert(!verifyMessage(unknown.c_str(), REQ_SIGNATURE, REQ_PREIMAGE), "P3: unknown prefix must not verify");
    /* explicit network: testnet accepts, mainnet rejects the same address */
    mu_assert(verifyMessage(HOLDER_ADDRESS, REQ_SIGNATURE, REQ_PREIMAGE, &NeuraiTest), "P3: testnet net accepts");
    mu_assert(!verifyMessage(HOLDER_ADDRESS, REQ_SIGNATURE, REQ_PREIMAGE, &Neurai), "P3: mainnet net rejects testnet address");
    /* mainnet address for the same key verifies only on mainnet */
    payload[0] = Neurai.p2pkh;
    string mainAddr = toBase58Check(payload, 21);
    mu_assert(verifyMessage(mainAddr.c_str(), REQ_SIGNATURE, REQ_PREIMAGE, &Neurai), "P3: mainnet address on mainnet");
    mu_assert(verifyMessage(mainAddr.c_str(), REQ_SIGNATURE, REQ_PREIMAGE), "P3: mainnet address, any network");
    mu_assert(!verifyMessage(mainAddr.c_str(), REQ_SIGNATURE, REQ_PREIMAGE, &NeuraiTest), "P3: mainnet address rejected on testnet");
}

MU_TEST(test_p4_noncanonical_base64_rejected) {
    string nc(REQ_SIGNATURE);
    nc[nc.size() - 2] = 't';                       /* "dhs=" -> "dht=": stray padding bits */
    mu_assert(!verifyMessage(HOLDER_ADDRESS, nc.c_str(), REQ_PREIMAGE), "P4: non-canonical base64 must not verify");
    uint8_t pub[33];
    mu_assert(!recoverMessageSigner(nc.c_str(), REQ_PREIMAGE, pub), "P4: non-canonical base64 must not recover");
    string noPad(REQ_SIGNATURE, 87);               /* missing '=' */
    mu_assert(!recoverMessageSigner(noPad.c_str(), REQ_PREIMAGE, pub), "P4: wrong length rejected");
    string urlSafe(REQ_SIGNATURE);
    for (char & c : urlSafe) { if (c == '+') c = '-'; else if (c == '/') c = '_'; }
    if (urlSafe != REQ_SIGNATURE)
        mu_assert(!recoverMessageSigner(urlSafe.c_str(), REQ_PREIMAGE, pub), "P4: url-safe alphabet rejected");
    /* the canonical vector still passes */
    mu_assert(verifyMessage(HOLDER_ADDRESS, REQ_SIGNATURE, REQ_PREIMAGE), "canonical vector still verifies");
}

MU_TEST_SUITE(test_message) {
    MU_RUN_TEST(test_magic_hash_layout);
    MU_RUN_TEST(test_holder_key_matches_vectors);
    MU_RUN_TEST(test_sign_depin_req_vector);
    MU_RUN_TEST(test_sign_depin_get_vector);
    MU_RUN_TEST(test_sign_raw_and_string_overloads);
    MU_RUN_TEST(test_recover_holder);
    MU_RUN_TEST(test_verify_address_and_pubkey);
    MU_RUN_TEST(test_poolsig_plain_reply_vector);
    MU_RUN_TEST(test_poolsig_bound_replies_vectors);
    MU_RUN_TEST(test_negative_n1_flipped_poolsig);
    MU_RUN_TEST(test_negative_n2_reserialized_body);
    MU_RUN_TEST(test_uncompressed_header_roundtrip);
    MU_RUN_TEST(test_p1_zero_pubkey_rejected);
    MU_RUN_TEST(test_p2_zero_private_key_rejected);
    MU_RUN_TEST(test_p3_prefix_and_network_checked);
    MU_RUN_TEST(test_p4_noncanonical_base64_rejected);
}

int main(int argc, char *argv[]) {
    MU_RUN_SUITE(test_message);
    MU_REPORT();
    return MU_EXIT_CODE;
}

#endif // UXNA_TEST
