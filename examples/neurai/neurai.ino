/*
 * This example shows how to derive master private key from the recovery seed
 * Generate a random recovery seed i.e. on https://iancoleman.io/bip39/
 * and check the master private key, account private key, account public key
 * and first address.
 */
#include "Neurai.h"

void setup() {
  Serial.begin(115200);
  String mnemonic = "receive gym happy calm one wrong army mimic control rocket bullet muffin";
  String password = "123";

  HDPrivateKey hd(mnemonic, "123");

  Serial.println("Mnemonic:");
  Serial.println(mnemonic);
  Serial.print("Password: \"");
  Serial.println(password+"\"");

  HDPrivateKey neurai = hd.derive("m/44'/0'/0'/");
  neurai.network = &Neurai;
  neurai.type = P2PKH;

  Serial.println("Root private key:");
  Serial.println(hd);
  Serial.println("Master private key:");
  Serial.println(neurai);
  Serial.println("Master public key:");
  Serial.println(neurai.xpub());
  Serial.println("Master public key:");
  
  Serial.println("m/44'/0'/0'/0/0");
  Serial.println(neurai.derive("m/0/0/").addreses());
  Serial.println("m/44'/0'/0'/0/1");
  Serial.println(neurai.derive("m/0/1/").addreses());
  Serial.println("m/44'/0'/0'/0/2");
  Serial.println(neurai.derive("m/0/2/").addreses());
  Serial.println("m/44'/0'/0'/0/3");
  Serial.println(neurai.derive("m/0/3/").addreses());
  Serial.println("m/44'/0'/0'/0/4");
  Serial.println(neurai.derive("m/0/4/").addreses());


// BIP32 Root Key xprv9s21ZrQH143K3FjoUayaetzo2oWvPjn6t5HxNj7BKWdXitLf3jS6dpRLEuDea7SR8qQSdaTuoX5VMX1hKeuw3BdKrrCXHG7qw9f1ynQAymQ
// Account Extended Private Key xprv9z5DEjvgpY8eGEjixTQLL2EfaVvivrGheAqmwpmkvrmjBBhKhhf5e8wrhPmk3G3EooyhHA3LgbiPDvK8TqrQp4hYx7u3nESBsgBBkctSyKF
// Account Extended Public Key xpub6D4ZeFTaeugwUipC4UwLhABQ8XmDLJzZ1PmNkDBNVCJi3z2UFEyLBwGLYf7G7T394QfGjEc7ch7v2ZvjcvRRzNrke9Zf2i6ydz9TY6BmmPp

// m/44'/0'/0'/0/0	NNG4C9EaifSuLJLvzADguXQSYZSsTmxYMP
// m/44'/0'/0'/0/1	NaExCWJ1TPD7HZ1kaqW3wSCJJJMN2B6Q2K
// m/44'/0'/0'/0/2	NLzyuNNiKaVENqf1otVvtkFUjeRMx93XPj
// m/44'/0'/0'/0/3	NSX5qyPfZnfD9wEo8cKaKENbXZ6rSnqHwy
// m/44'/0'/0'/0/4	NcHkpRbvQUSXtnhQVFWYs8sftnAzcE8WqH

Serial.println("\n");
}

void loop() {
  delay(10000000);
}