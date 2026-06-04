#ifndef __UNEURAI_CONF_H__
#define __UNEURAI_CONF_H__

/* Change this if you want to have other network by default */
//#define DEFAULT_NETWORK NeuraiTest
#define DEFAULT_NETWORK Neurai

/* ---- Post-Quantum support (NIP-022 / ML-DSA-44) ----
 * Enables PQHDPrivateKey::materializeKeyPair() and Tx::signAuthScriptInputPQ().
 *
 * The flag MUST be visible to every library .cpp file. The Arduino IDE does NOT
 * propagate a #define written in your .ino to the library sources, so defining
 * it only in the sketch makes linking fail with "undefined reference to
 * PQHDPrivateKey::materializeKeyPair / Tx::signAuthScriptInputPQ". Defining it
 * here (or passing -DUNEURAI_ENABLE_PQ as a global build flag) fixes that.
 *
 * Requires the mldsa-esp32 library (https://github.com/NeuraiProject/mldsa-esp32)
 * and an ESP32 target. If you do NOT use PQ, comment the block below out so the
 * library stays independent of mldsa-esp32. */
#ifndef UNEURAI_ENABLE_PQ
#define UNEURAI_ENABLE_PQ
#endif

/* Change this config file to adjust to your framework */
#ifndef USE_STDONLY
  #ifdef ARDUINO
  #include <Arduino.h>
  #else
  #define MBED
  #include <mbed.h>
  #endif
#endif

/* If you don't have a Stream class in your framework you can implement one
 * by yourself and use it to parse transactions and hash on the fly.
 * Arduino and Mbed are using slightly different API, choose one.
 * TODO: describe the interface.
 */

/* settings for Arduino */
#ifdef ARDUINO
#define USE_ARDUINO_STRING 1 /* Arduino String implementation (WString.h) */
#define USE_ARDUINO_STREAM 1 /* Arduino Stream class */
#define USE_STD_STRING     0 /* Standard library std::string */
#define USE_MBED_STREAM    0 /* Mbed Stream class */
#endif

#ifdef MBED
#define USE_ARDUINO_STRING 0 /* Arduino String implementation (WString.h) */
#define USE_ARDUINO_STREAM 0 /* Arduino Stream class */
#define USE_STD_STRING     1 /* Standard library std::string */
#define USE_MBED_STREAM    1 /* Mbed Stream class */
#endif

#ifdef USE_STDONLY
 #ifndef USE_ARDUINO_STRING
  #define USE_ARDUINO_STRING 0 /* Arduino String implementation (WString.h) */
 #endif
 #ifndef USE_ARDUINO_STREAM
  #define USE_ARDUINO_STREAM 0 /* Arduino Stream class */
 #endif
 #ifndef USE_STD_STRING
  #define USE_STD_STRING     1 /* Standard library std::string */
 #endif
 #ifndef USE_MBED_STREAM
  #define USE_MBED_STREAM    0 /* Mbed Stream class */
 #endif
#endif

#if USE_STD_STRING
#include <string>
// using std::string;
#endif

#endif //__UNEURAI_CONF_H__
