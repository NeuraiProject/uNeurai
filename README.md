# Micro-Neurai

C++ Neurai library for 32-bit microcontrollers. The library supports [Arduino IDE](https://www.arduino.cc/), [ARM mbed](https://www.mbed.com/en/) and bare metal.<br>
It provides a collection of convenient classes for Neurai: private and public keys, HD wallets, generation of the recovery phrases, PSBT transaction formats, scripts — everything required for a hardware wallet or other neurai-powered device.

Optional **Post-Quantum** support (ML-DSA-44, NIP-022, BIP-350 bech32m addresses, witness-v1 AuthScript transactions) is available behind the `-DUNEURAI_ENABLE_PQ` build flag — see the [Post-Quantum support](#post-quantum-support-ml-dsa-44-nip-022) section.

The library should work on any decent 32-bit microcontroller, like esp32, riscV, stm32 series and others. It *doesn't work* on 8-bit microcontrollers like a classic Arduino as these microcontrollers are not powerful enough to run complicated crypto algorithms.

We use elliptic curve implementation from [trezor-crypto](https://github.com/trezor/trezor-firmware/tree/master/crypto). API is inspired by [Jimmy Song's](https://github.com/jimmysong/) Porgramming Blockchain class and the [book](https://github.com/jimmysong/programmingbitcoin).

## Documentation

In progress.

Pending full API docs, the host test suite under [`tests/`](tests/) is the most concise reference: every public primitive has at least one assertion that exercises it (BIP-39, BIP-32, bech32/bech32m, AuthScript primitives, NIP-022 HD-PQ, sighash, etc.), with vectors generated from the JS reference wallet so they double as worked examples.

Telegram group: https://t.me/neuraiproject

 ## Networks

 Micro-Neurai supports the following network configurations:

 - **Neurai**: (Default) The mainnet network. Uses BIP-44 coin type `1900`.
 - **NeuraiLegacy**: Mainnet network using BIP-44 coin type `0`. Compatible with legacy wallet implementations.
 - **NeuraiTest**: The testnet network.

 Post-Quantum networks (only present when built with `-DUNEURAI_ENABLE_PQ`):

 - **NeuraiPQ**: Post-Quantum mainnet (HRP `nq`, BIP-32 purpose `100`, coin type `1900`, extended-key version `xpqpriv`).
 - **NeuraiPQTest**: Post-Quantum testnet (HRP `tnq`, coin type `1`, extended-key version `tpqpriv`).

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

uNeurai includes optional support for the **Neurai PQ** chain (witness v1
AuthScript with ML-DSA-44 signatures, NIP-022 HD derivation, BIP-350 bech32m
addresses with the `nq` / `tnq` HRPs).

The PQ surface is **opt-in**: the post-quantum signing backend is supplied by
the separate [`mldsa-esp32`](https://github.com/NeuraiProject/mldsa-esp32)
library and is only compiled when you define `UNEURAI_ENABLE_PQ`. Without that
flag uNeurai builds exactly as before on every supported platform.

### What you get with `-DUNEURAI_ENABLE_PQ`

- `ChainNetworkPQ`, `NeuraiPQ`, `NeuraiPQTest` network descriptors.
- `pqAddressFromPubKey()` / `pqAddressDecode()` — `nq1…` / `tnq1…` codec.
- `Script::address(buffer, len, &NeuraiPQTest)` overload to render PQ
  addresses; `Script("tnq1…")` round-trips via `P2AUTHSCRIPT`.
- `PQHDPrivateKey` — NIP-022 hardened-only HD derivation, `xpqpriv` / `tpqpriv`
  serialization.
- `Tx::sigHashAuthScript(...)` and `Tx::signAuthScriptInputPQ(...)` —
  BIP-143-style sighash with an extra `auth_type` byte, plus the witness-v1
  signing path.

Note that everything *except* `PQHDPrivateKey::materializeKeyPair` and
`Tx::signAuthScriptInputPQ` compiles on every supported platform, so address
generation, HD derivation, sighash computation and bech32m codec can be tested
in host-side CI without the `mldsa-esp32` backend.

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
the corresponding `tnq1…` address, then sign a transaction input with witness v1
AuthScript.

```cpp
#include "Neurai.h"
#include "NeuraiPQ.h"

// 1. HD-PQ derivation (NIP-022, hardened-only). Host-compilable.
PQHDPrivateKey master;
master.fromMnemonic("...12-word mnemonic...", /*mlen*/ 71, "", 0, &NeuraiPQTest);

PQHDPrivateKey child;
master.derive("m_pq/100'/1'/0'/0'/0'", &child);

// 2. ML-DSA-44 key pair + address (ESP32-only — needs mldsa-esp32).
uint8_t pk[UNEURAI_PQ_PUBKEY_RAW_LEN];  // 1312 bytes
uint8_t sk[2560];
child.materializeKeyPair(pk, sk);       // ~1-2 s on ESP32-S3

char addr[100] = {0};
pqAddressFromPubKey(&NeuraiPQTest, pk, addr, sizeof(addr));
// addr -> "tnq1pdsj0aztvgwv3rwgml360stpyp228zrggyga6n4sdenmetm6wv3tqzddk95"

// 3. Sign one AuthScript input (witnessScript = OP_TRUE for phase 1).
Tx tx;
// ... populate tx.version, addInput(...), addOutput(...) ...
uint8_t opTrue[1] = { 0x51 };
Script witnessScript(opTrue, 1);
tx.signAuthScriptInputPQ(/*input*/ 0, sk, pk,
                         /*amount sats*/ 100000000ULL,
                         witnessScript, SIGHASH_ALL);
// tx.txIns[0].witness now carries [authType, sig||hashType, 0x05||pk, witnessScript]
```

See [`examples/neurai_pq/neurai_pq.ino`](examples/neurai_pq/neurai_pq.ino) for a
complete sketch running inside an `xTaskCreate(..., 65536, ...)` FreeRTOS task.

### Test vectors

The host test suite under `tests/` includes vectors generated by
`tmp/oracle/dump_vectors.cjs` against the JS reference implementations
(`tmp/neurai-key`, `tmp/neurai-sign-transaction`). The address, commitment,
auth_descriptor, NIP-022 HD seed, `tpqpriv` and AuthScript sighash all match
byte-for-byte.

## Thanks

This project builds on the uBitcoin codebase, adapting it for Neurai hardware and tooling, and we gratefully acknowledge Stepan Snigirev for open-sourcing that work.