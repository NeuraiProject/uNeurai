# Micro-Neurai

C++ Neurai library for 32-bit microcontrollers. The library supports [Arduino IDE](https://www.arduino.cc/), [ARM mbed](https://www.mbed.com/en/) and bare metal.<br>
It provides a collection of convenient classes for Neurai: private and public keys, HD wallets, generation of the recovery phrases, PSBT transaction formats, scripts — everything required for a hardware wallet or other neurai-powered device.

The library should work on any decent 32-bit microcontroller, like esp32, riscV, stm32 series and others. It *doesn't work* on 8-bit microcontrollers like a classic Arduino as these microcontrollers are not powerful enough to run complicated crypto algorithms.

We use elliptic curve implementation from [trezor-crypto](https://github.com/trezor/trezor-firmware/tree/master/crypto). API is inspired by [Jimmy Song's](https://github.com/jimmysong/) Porgramming Blockchain class and the [book](https://github.com/jimmysong/programmingbitcoin).

## Documentation

In progress...

Telegram group: https://t.me/neuraiproject

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
// derive native Neurai account
HDPrivateKey account = hd.derive("m/44'/0'/0'/");
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

## Thanks

This project builds on the uBitcoin codebase, adapting it for Neurai hardware and tooling, and we gratefully acknowledge Stepan Snigirev for open-sourcing that work.