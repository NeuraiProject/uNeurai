# Micro-Neurai

C++ Neurai library for 32-bit microcontrollers. The library supports [Arduino IDE](https://www.arduino.cc/), [ARM mbed](https://www.mbed.com/en/) and bare metal.<br>
It provides a collection of convenient classes for Neurai: private and public keys, HD wallets, generation of the recovery phrases, PSBT transaction formats, scripts and **Neurai assets** (issue, transfer and manage) — everything required for a hardware wallet or other neurai-powered device. See the [Assets](#assets-issue-transfer-and-manage) section.

It speaks every Neurai address type: Legacy Base58 P2PKH and the Bech32m AuthScript families — generic AuthScript witness v1 (`nc1p…`), strict PQ witness v2 (`pq1z…`) and strict ECDSA witness v3 (`nq1r…`) — see [Address types](#address-types). Optional **Post-Quantum** signing (ML-DSA-44, NIP-022) is available with the `mldsa-esp32` backend — see the [Post-Quantum support](#post-quantum-support-ml-dsa-44-nip-022) section.

> **0.2.0 changes the AuthScript address encoding.** Witness v1 addresses are now `nc1p…` / `tnc1p…` (they used to be `nq1p…` / `tnq1p…`, which the node now rejects), and `nq` / `tnq` belong to the strict ECDSA family. See [Upgrading from 0.0.x](#upgrading-from-00x).

The library should work on any decent 32-bit microcontroller, like esp32, riscV, stm32 series and others. It *doesn't work* on 8-bit microcontrollers like a classic Arduino as these microcontrollers are not powerful enough to run complicated crypto algorithms.

We use elliptic curve implementation from [trezor-crypto](https://github.com/trezor/trezor-firmware/tree/master/crypto). API is inspired by [Jimmy Song's](https://github.com/jimmysong/) Porgramming Blockchain class and the [book](https://github.com/jimmysong/programmingbitcoin).

## Documentation

In progress.

Pending full API docs, the host test suite under [`tests/`](tests/) is the most concise reference: every public primitive has at least one assertion that exercises it (BIP-39, BIP-32, bech32/bech32m, AuthScript primitives, NIP-022 HD-PQ, sighash, etc.), with vectors generated from the JS reference wallet so they double as worked examples.

Telegram group: https://t.me/neuraiproject

 ## Networks

 Micro-Neurai supports the following network configurations (the name in
 brackets is the equivalent [`@neuraiproject/neurai-key`](https://www.npmjs.com/package/@neuraiproject/neurai-key) 5 network):

 - **Neurai**: (Default) The mainnet network. Uses BIP-44 coin type `1900` (`xna-legacy`).
 - **NeuraiLegacy**: Mainnet network using BIP-44 coin type `0`. Compatible with legacy wallet implementations (`xna-old-legacy`).
 - **NeuraiTest**: The testnet network. Uses BIP-44 coin type `1` and WIF prefix `0xef`, as the node does (`xna-legacy-test`). Regtest uses the same prefixes.

 These describe Base58 P2PKH addresses. The Bech32m AuthScript families are
 selected by HRP (next section); `chainNetworkIsTestnet(net)` tells which HRP
 (mainnet or testnet) a `ChainNetwork` maps to.

 PQ key networks (`ChainNetworkPQ`, NIP-022 key tree `m_pq/100'/coin'/…`, extended-key version `xpqpriv` / `tpqpriv`):

 - **NeuraiPQ** / **NeuraiPQTest** (alias `NeuraiPQV1` / `NeuraiPQV1Test`): generic AuthScript witness v1 with a PQ key, HRP `nc` / `tnc` (`xna-authscript` / `xna-authscript-test`). This is the phase-1 PQ flow of the NeuraiHW firmware.
 - **NeuraiPQV2** / **NeuraiPQV2Test**: strict PQ witness v2, HRP `pq` / `tpq` (`xna-pq` / `xna-pq-test`).

## Address types

| Family | Witness | HRP (main / test) | scriptPubKey | authType | witnessScript | `ScriptType` | neurai-key 5 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Legacy P2PKH | — | Base58 `N…` / `t…` | `76a914…88ac` | — | — | `P2PKH` | `xna-legacy`, `xna-old-legacy` |
| Generic AuthScript | v1 | `nc` / `tnc` → `nc1p…` | `51 20 <C>` | any | any | `P2AUTHSCRIPT` | `xna-authscript` |
| Strict PQ (ML-DSA-44) | v2 | `pq` / `tpq` → `pq1z…` | `52 20 <C>` | `0x01` | `0x51` (fixed) | `P2AUTHSCRIPT_V2` | `xna-pq` |
| Strict ECDSA (secp256k1) | v3 | `nq` / `tnq` → `nq1r…` | `53 20 <C>` | `0x02` | `0x51` (fixed) | `P2AUTHSCRIPT_V3` | `xna` |

`C = taggedHash("NeuraiAuthScript", witnessVersion || auth_descriptor || SHA256(witnessScript))`,
with `auth_descriptor = 0x01 || HASH160(0x05 || pq_pubkey)` (PQ) or
`0x02 || HASH160(compressed_pubkey)` (ECDSA). The witness version is the first
byte of the preimage, so one key has a different program in each family.

- The node only accepts these HRP / witness-version pairs. `nq1p…` / `tnq1p…`
  (witness v1 under `nq`) is **invalid**; `Script("nq1p…")` is empty and
  `authScriptAddressDecode()` returns 0.
- Decoding follows the node: Bech32m first (any case), then Base58, so Base58
  addresses that happen to start with `NQ1` / `Nc1` still decode as P2PKH.
- **Activation:** the strict families (v2, v3) are active only on regtest for
  now. Before activation the node refuses `pq1…` / `nq1…` addresses because an
  `OP_2` / `OP_3` output is anyone-can-spend there. uNeurai cannot know the
  activation state: do not build outputs to v2/v3 addresses on a chain where
  they are not active.
- DePIN messaging is P2PKH-only in the node: keep DePIN identities on
  `m/44'/<coin>'/100'/0/0` Legacy addresses.

```cpp
#include "Neurai.h"
#include "NeuraiPQ.h"

// Any family: address -> scriptPubKey -> address
Script spk("tnq1rskqpx9d5ccaj8eplrz7rlp9ds5w9wpppmqgenvmzeflmlme8p6yqgl0c8d");
spk.type();                  // P2AUTHSCRIPT_V3
spk.authScriptVersion();     // 3
spk.address(&NeuraiTest);    // "tnq1rskqpx9…"; also works for tnc1p… and tpq1z…

// Strict ECDSA address of a secp256k1 key (neurai-key 5 "xna": m/84'/1900'/0'/0/0)
HDPrivateKey root("...mnemonic...", "");
PrivateKey key = root.derive("m/84'/1900'/0'/0/0");
key.ecdsaAddress();                      // "nq1r…"
key.publicKey().ecdsaAddress(&NeuraiTest); // "tnq1r…"
Script v3(key.publicKey(), P2AUTHSCRIPT_V3); // OP_3 0x20 <C>

// Low level
uint8_t ver; bool testnet; uint8_t program[32];
char buf[UNEURAI_AUTHSCRIPT_ADDRESS_MAX];
authScriptAddressDecode("tpq1z…", &ver, &testnet, program); // ver 2, testnet true
authScriptAddressEncode(2, true, program, buf, sizeof(buf));
```

## Installation

You can download the latest release manually from this repository.

[Download](https://github.com/NeuraiProject/uNeurai/archive/refs/heads/main.zip) the zip file from our [repository](https://github.com/NeuraiProject/uNeurai/) and select in Arduino IDE `Sketch` → `Include library` → `Add .ZIP library...`.

Or clone it into your `Documents/Arduino/libraries` folder:

```sh
git clone https://github.com/NeuraiProject/uNeurai.git
```

When installed you will also see a few examples in `File` → `Examples` → `Neurai` menu.

## Basic usage example

First, don't forget to include necessary headers:

```cpp
// we use these two in our sketch:
#include "Neurai.h"
#include "PSBT.h"       // if using PSBT functionality
// other headers of the library
#include "Conversion.h" // to get access to functions like toHex() or fromBase64()
#include "Hash.h"       // if using hashes in your code
#include "Message.h"    // signmessage-compatible message signing (DePIN auth)
```

Now we can write a simple example that does the following:

1. Creates a master private key from a recovery phrase and empty password
2. Derives account and prints master public key for a watch-only wallet (`zpub` in this case)
3. Derives and print first segwit address
4. Parses, signs and prints signed PSBT transaction

```cpp
// derive master private key
HDPrivateKey hd("add good charge eagle walk culture book inherit fan nature seek repair", "");
// derive native Neurai account (BIP-44 coin type 1900)
HDPrivateKey account = hd.derive("m/44'/1900'/0'/");
// print xpub: xpub6DBgMq857cJ4ByRimVBYqUkVqSw6MBoSrm...HDp2vfhrvRpT52HRNfFm1QE6v3Gtxu
Serial.println(account.xpub());
// or change the account type to UNKNOWN_TYPE to get tpub
HDPublicKey xpub = account.xpub();
// this time prints xpub6DBgMq857cJ4ByRimVBYqUkVqSw6MBoSrm...HDp2vfhrvRpT52HRNfFm1QE6v3Gtxu
Serial.println(xpub);
// Returns the BIP-32 fingerprint (the first 4 bytes of the key’s hash160)
Serial.println(hd.fingerprint());

// print first address: NLhNpkHibiJs3Sj9BgoUwAFJvVsuGSJp62
Serial.println(xpub.derive("m/0/0").address());

PSBT tx;
// parse unsigned transaction
tx.parseBase64("cHNidP8BAHECAAAAAUQS8FqBzYocPDpeQmXBRBH7NwZHVJF39dYJDCXxq"
"zf6AAAAAAD+////AqCGAQAAAAAAFgAUuP0WcSBmiAZYi91nX90hg/cZJ1U8AgMAAAAAABYAF"
"C1RhUR+m/nFyQkPSlP0xmZVxlOqAAAAAAABAR/gkwQAAAAAABYAFNYPuLrw6igutR+Kp7vxJ"
"QPBtdvuIgYDzkBZaAkSIz0P0BexiPYfzInxu9mMeuaOQa1fGEUXcWIYoyAeuFQAAIABAACAA"
"AAAgAAAAAAAAAAAAAAiAgMxjOiFQofq7l9q42nsLA3Ta4zKpEs5eCnAvMnQaVeqsBijIB64V"
"AAAgAEAAIAAAACAAQAAAAAAAAAA");
// sign with the root key
tx.sign(hd);
// print signed transaction
Serial.println(tx.toBase64());
```

## Post-Quantum support (ML-DSA-44, NIP-022)

uNeurai includes optional support for Neurai **Post-Quantum** keys: ML-DSA-44
signatures, NIP-022 HD derivation and the two AuthScript families that carry a
PQ key — generic AuthScript witness v1 (`nc1p…` / `tnc1p…`, authType `0x01`,
witnessScript `OP_TRUE`) and strict PQ witness v2 (`pq1z…` / `tpq1z…`).

The PQ surface is **opt-in**: the post-quantum signing backend is supplied by
the separate [`mldsa-esp32`](https://github.com/NeuraiProject/mldsa-esp32)
library and is only compiled when you define `UNEURAI_ENABLE_PQ` on an ESP32
target. Without it uNeurai builds exactly as before on every supported platform.

### What you get

- `ChainNetworkPQ` descriptors `NeuraiPQ` / `NeuraiPQTest` (v1, `nc` / `tnc`)
  and `NeuraiPQV2` / `NeuraiPQV2Test` (strict v2, `pq` / `tpq`).
- `pqAddressFromPubKey()` / `pqAddressDecode()` — address of a PQ key in the
  family of the network you pass (`&NeuraiPQTest` → `tnc1p…`,
  `&NeuraiPQV2Test` → `tpq1z…`).
- `buildAuthScriptCommitment()` / `buildAuthScriptScriptPubKey()` (v1) and
  `buildVersionedAuthScriptCommitment()` / `buildVersionedAuthScriptScriptPubKey()`
  (v1, v2, v3; the strict versions enforce the consensus template).
- `PQHDPrivateKey` — NIP-022 hardened-only HD derivation, `xpqpriv` / `tpqpriv`
  serialization.
- `Tx::sigHashAuthScript(...)` (generic v1: BIP-143-style preimage with an extra
  `authType` byte) and `Tx::sigHashAuthScriptStrict(...)` (v2 / v3: the same
  preimage with scriptCode `OP_TRUE` and `witnessVersion || authType` before
  the hashType). A v1-style signature is **not** valid for a strict input.
- `Tx::signAuthScriptInputPQ(...)` (v1) and `Tx::signAuthScriptInputPQStrict(...)`
  (v2). Both build the witness `[0x01, sig||hashType, 0x05||pk, witnessScript]`.

Everything *except* `PQHDPrivateKey::materializeKeyPair`,
`Tx::signAuthScriptInputPQ`, `Tx::signAuthScriptInputPQStrict` and
`Tx::signCovenantCancelInputPQ` compiles on every supported platform, so address
generation, HD derivation, sighash computation and the bech32m codec can be
tested in host-side CI without the `mldsa-esp32` backend.

The strict ECDSA family (v3) needs no PQ backend:
`Tx::signAuthScriptInputECDSA(index, privateKey, amount)` signs an `nq1r…`
input with the witness `[0x02, DER(sig)||hashType, compressed pubkey, 0x51]`,
and `PSBT::sign()` signs v3 inputs whose program matches the derived key.
`PSBT::sign()` never signs v1 / v2 AuthScript inputs (a legacy sighash would
be invalid for them): use the `Tx::signAuthScriptInput*` functions instead.
Transactions with version 3 (NIP-014 reference inputs) are not supported by
the AuthScript sighashes (they return 0).

### Enabling PQ in PlatformIO

```ini
[env:esp32-s3-devkitc-1]
platform   = espressif32
board      = esp32-s3-devkitc-1
framework  = arduino
lib_deps   =
    https://github.com/NeuraiProject/uNeurai
    https://github.com/NeuraiProject/mldsa-esp32
build_flags = -DUNEURAI_ENABLE_PQ
```

### Enabling PQ in Arduino IDE

1. Install both libraries via *Sketch → Include library → Add .ZIP library…*
   (or via the Library Manager once published).
2. Add `-DUNEURAI_ENABLE_PQ` to your sketch build flags
   (`platform.txt` / boards manager build options).
3. Open `File → Examples → uNeurai → neurai_pq` and flash it. The sketch runs
   inside a FreeRTOS task with a 64 KB stack — ML-DSA-44 keygen needs ~30 KB.

### PQ usage example

End-to-end flow: derive an ML-DSA-44 key via NIP-022 from a BIP-39 mnemonic, get
the corresponding `tnc1p…` (v1) and `tpq1z…` (strict v2) addresses, then sign
transaction inputs.

```cpp
#include "Neurai.h"
#include "NeuraiPQ.h"

// 1. HD-PQ derivation (NIP-022, hardened-only). Host-compilable.
PQHDPrivateKey master;
master.fromMnemonic("...12-word mnemonic...", /*mlen*/ 71, "", 0, &NeuraiPQTest);

PQHDPrivateKey child;
master.derive("m_pq/100'/1'/0'/0'/0'", &child);

// 2. ML-DSA-44 key pair + addresses (ESP32-only — needs mldsa-esp32).
uint8_t pk[UNEURAI_PQ_PUBKEY_RAW_LEN];  // 1312 bytes
uint8_t sk[2560];
child.materializeKeyPair(pk, sk);       // ~1-2 s on ESP32-S3

char addr[UNEURAI_AUTHSCRIPT_ADDRESS_MAX] = {0};
pqAddressFromPubKey(&NeuraiPQTest, pk, addr, sizeof(addr));
// addr -> "tnc1pdsj0aztvgwv3rwgml360stpyp228zrggyga6n4sdenmetm6wv3tqse52vk"
pqAddressFromPubKey(&NeuraiPQV2Test, pk, addr, sizeof(addr));
// addr -> "tpq1zxsjnzvjnwn7vt04nkx6qthvylqwej33r53duxawl0uwd3ewme4nsy38hld"

// 3a. Spend a generic v1 (tnc1p…) input (witnessScript = OP_TRUE).
Tx tx;
// ... populate tx.version, addInput(...), addOutput(...) ...
uint8_t opTrue[1] = { 0x51 };
Script witnessScript(opTrue, 1);
tx.signAuthScriptInputPQ(/*input*/ 0, sk, pk,
                         /*amount sats*/ 100000000ULL,
                         witnessScript, SIGHASH_ALL);
// tx.txIns[0].witness now carries [authType, sig||hashType, 0x05||pk, witnessScript]

// 3b. Spend a strict v2 (tpq1z…) input: fixed OP_TRUE, strict sighash.
tx.signAuthScriptInputPQStrict(/*input*/ 1, sk, pk, /*amount sats*/ 100000000ULL);
```

See [`examples/neurai_pq/neurai_pq.ino`](examples/neurai_pq/neurai_pq.ino) for a
complete sketch running inside an `xTaskCreate(..., 65536, ...)` FreeRTOS task.

### Test vectors

The host test suite under `tests/` includes vectors generated by
`tmp/oracle/dump_vectors.cjs` against the JS reference implementations
(`tmp/neurai-key`, `tmp/neurai-sign-transaction`). The address, commitment,
auth_descriptor, NIP-022 HD seed, `tpqpriv` and AuthScript sighash all match
byte-for-byte.

The address-family, strict-sighash and strict-asset vectors
(`tests/test_address_families.cpp`, `tests/test_sighash_authscript.cpp`,
`tests/test_assets.cpp`, `tests/test_pq_sign.cpp`) come from a Neurai-DePIN
regtest node: addresses and scriptPubKeys from `getnewaddress` /
`validateaddress`, and v1 / v2 / v3 spends signed by this library that the node
accepted with `testmempoolaccept`.

### Running the tests

```sh
cd tests
make run                                   # host build (g++), no PQ backend
make run MLDSA_DIR=/path/to/mldsa-esp32/src  # also builds and runs the ML-DSA signers
```

With `MLDSA_DIR` the suite is built into `tests/build/pq` with the ESP32-only
PQ code enabled; the ESP32 TRNG is replaced by `tests/pq_host/randombytes_host.c`.

## Upgrading from 0.0.x

Version 0.2.0, not 0.1.0: the PlatformIO registry already lists an older
uNeurai 0.1.0 without the PQ headers, so this release skips that number.

0.2.0 follows the address types of the Neurai node (Neurai-DePIN) and
`@neuraiproject/neurai-key` 5. Breaking changes:

- **`NeuraiPQ` / `NeuraiPQTest` HRPs are now `nc` / `tnc`.** They still describe
  the generic AuthScript witness v1 family (same key tree, same commitment,
  same `OP_1 0x20 <C>` scriptPubKey), so `pqAddressFromPubKey()` now returns
  `nc1p…` / `tnc1p…` instead of `nq1p…` / `tnq1p…`. Funds sent to an old
  address are reachable through the re-encoded address.
- **`nq1…` / `tnq1…` now means strict ECDSA witness v3.** `Script("nq1p…")`,
  `pqAddressDecode("tnq1p…", …)` and `authScriptAddressDecode()` reject the old
  v1 encoding, like the node.
- `Script::type()` returns the new `P2AUTHSCRIPT_V2` / `P2AUTHSCRIPT_V3` for
  `OP_2` / `OP_3` programs (`P2AUTHSCRIPT` stays witness v1 only).
- `Script::address(…, const ChainNetworkPQ *)` renders the family of the script
  (a v3 output with `&NeuraiPQTest` gives `tnq1r…`), and
  `Script::address(…, const ChainNetwork *)` now renders AuthScript outputs
  too (it used to return 0 for them).
- `Tx::sigHashAuthScript()` returns 0 (and signing fails) for an out-of-range
  input or a version-3 transaction instead of hashing garbage.
- `PSBT::sign()` skips AuthScript v1 / v2 and other witness-program inputs
  instead of producing an invalid legacy signature, and signs strict ECDSA v3
  inputs with the strict sighash.
- `AssetInfo` has a new `witnessVersion` field (null-asset destinations).

## Message signing (`signmessage` compatible)

`Message.h` signs and verifies text with the classic magic-hash scheme
(`"Neurai Signed Message:\n"`, compact recoverable 65-byte signature in
base64), interoperable with any wallet's `signmessage` / `verifymessage`. It is
the primitive the **DePIN Messaging Protocol 2** uses for challenge requests
(`DEPIN-REQ`), challenge use (`DEPIN-GET` / `DEPIN-CLEAR`) and reply
authentication (`poolsig`), so an ESP32 can authenticate against a DePIN pool
without exposing its key.

```cpp
#include "Message.h"

PrivateKey key("cW8vy4nJ...");                       // holder key (WIF)
char sig[NEURAI_MESSAGE_SIG_B64_LEN + 1];

// DePIN challenge request (protocol 2 §7.1): sign the preimage, send it to depinchallenge
signMessageBase64(key, "DEPIN-REQ|receive|&TEST/SEC|tRERn8G2...|1730000000000", sig, sizeof(sig));

// Verify a reply signature (poolsig) against the pinned pool key or its address
uint8_t signer[33];
recoverMessageSigner(poolSigB64, preimage, signer);             // 33-byte compressed SEC
verifyMessage("tDudNSQstiVQu3Prbs7yFwbYtDrcU19eKJ", poolSigB64, preimage, &NeuraiTest); // 1 = valid
```

A device that chats over DePIN should use the dedicated identity account
(`m/44'/<coin>'/100'/0/0`, coin `1900` on Mainnet and `1` on Testnet) rather than
its funds account: `hd.derive("m/44'/1'/100'/0/0")` on Testnet.

Signing is deterministic (RFC 6979): [`tests/test_message.cpp`](tests/test_message.cpp)
reproduces the protocol vectors of `Neurai/doc/depin-messaging-protocol.md` §13
byte for byte, including the negative cases N1/N2.

## Assets (issue, transfer and manage)

Micro-Neurai understands Neurai assets (the Ravencoin-style asset layer) on both
**Mainnet and Testnet**, for legacy (P2PKH) and AuthScript destinations
(generic v1 `nc1p…`, strict PQ v2 `pq1z…` and strict ECDSA v3 `nq1r…`; the
node accepts assets on v2/v3 only where the strict families are active). Asset support is split across four headers and is completely
allocation-free:

- **`Asset.h`** — the on-chain script codec. `assetParseScript()` decodes any
  asset script into an `AssetInfo` (operation, base destination, name, amount,
  units, …) — ideal for a hardware-wallet review screen so the device shows
  *what* asset is being moved instead of blind-signing. The `assetEncode*Script()`
  functions build transfer / issue / owner / reissue and the null-asset scripts
  (qualifier tag, freeze, verifier, global restriction).
- **`AssetConstants.h`** — per-network burn (fee) addresses and amounts, the fixed
  owner/unique amounts, and the name helpers (`assetOwnerTokenName`, …).
- **`AssetBuilder.h`** — assembles the correctly-ordered `TxOut` set for each
  operation onto a `Tx`: issue (root / sub / unique / qualifier / restricted),
  reissue, transfer, qualifier tag/untag, and freeze/unfreeze of addresses or the
  whole asset.
- **`AssetName.h`** — `assetDetectAndValidate()` validates an asset name and
  reports its type (root / sub / unique / qualifier / restricted / depin / owner)
  following the Neurai naming rules and per-network length limits (full name
  31 chars on Mainnet / 121 on Testnet; root and sub names one less so the
  owner token `NAME!` still fits — the same caps the node enforces).

### NIP-040: the `rvn` / `xna` asset marker

Every transfer / issue / owner / reissue payload starts with a 3-byte marker.
Historically it is `rvn` (inherited from Ravencoin); NIP-040 migrates it to
`xna`. From the activation height the node **rejects** new outputs that still
carry `rvn` (`bad-txns-legacy-asset-marker-after-nip040`), while legacy `rvn`
UTXOs remain valid and spendable. Status today:

| Network | Marker for new outputs |
| --- | --- |
| Mainnet | `rvn` (no activation height scheduled yet) |
| Testnet | `xna` (active since block 303000) |

uNeurai therefore exposes the marker explicitly instead of guessing it from the
network — exactly like `@neuraiproject/neurai-create-transaction`:

- `assetParseScript()` accepts **both** markers and reports the one it found in
  `AssetInfo.marker` (`ASSET_MARKER_RVN` / `ASSET_MARKER_XNA`).
- Every encoder and builder that emits a marker takes a trailing
  `AssetMarker marker` argument, defaulting to `ASSET_MARKER_RVN`. Pass the
  value the node reports in `getblockchaininfo.asset_marker` for the next block
  (the host sends it to the device); when building offline, pass the marker you
  know to be right for the target chain.
- Null-asset outputs (qualifier tag / untag, address or global freeze,
  verifier) carry no marker bytes and are unaffected.

```cpp
// Testnet today: the node reports asset_marker "xna"
assetBuildTransfer(tx, "tAddress...", "MYTOKEN", 250000000ULL, ASSET_MARKER_XNA);

// Mainnet today: "rvn" (the default, so both of these are equivalent)
assetBuildTransfer(tx, "Naddress...", "MYTOKEN", 250000000ULL);
assetBuildTransfer(tx, "Naddress...", "MYTOKEN", 250000000ULL, ASSET_MARKER_RVN);

// Low-level: the 4-byte payload prefix for a given marker / op
uint8_t pfx[4];
assetMarkerPrefix(ASSET_MARKER_XNA, ASSET_ISSUE, pfx);   // "xnaq"
```

```cpp
#include "AssetBuilder.h"   // pulls in Asset.h + AssetConstants.h
#include "AssetName.h"

// Validate a name before issuing (mainnet => testnet = false)
if (assetDetectAndValidate("MYTOKEN", false) != ASSET_NAME_ROOT) { /* reject */ }

// Build an asset transfer output (the asset amount lives in the script;
// the output value is 0). amountRaw is value * 1e8.
Tx tx;
assetBuildTransfer(tx, "Naddress...", "MYTOKEN", 250000000ULL); // 2.5 MYTOKEN

// Decode an output's script (e.g. to show it on a device before signing)
AssetInfo info;
const Script& spk = tx.txOuts[0].scriptPubkey;
if (assetParseScript(spk.scriptArray, spk.scriptLen, &info)) {
    // info.op == ASSET_TRANSFER, info.name == "MYTOKEN", info.amount == 250000000
    // info.marker == ASSET_MARKER_RVN or ASSET_MARKER_XNA (NIP-040, see below)
}
```

The encoders, builders and validator are verified byte-for-byte against the
reference JS libraries (`@neuraiproject/neurai-create-transaction` and
`@neuraiproject/neurai-assets`) in [`tests/test_assets.cpp`](tests/test_assets.cpp).

## Thanks

This project builds on the uBitcoin codebase, adapting it for Neurai hardware and tooling, and we gratefully acknowledge Stepan Snigirev for open-sourcing that work.