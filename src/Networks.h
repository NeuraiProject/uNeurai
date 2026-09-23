#ifndef __UXNA_NETWORKS_H__
#define __UXNA_NETWORKS_H__

#include <stdint.h>

/** \brief Prefixes para cada red soportada por Neurai.<br>
 *  HD key prefixes are described here:<br>
 *  https://github.com/satoshilabs/slips/blob/master/slip-0132.md<br>
 *  useful tool: in https://iancoleman.io/bip39/
 */
typedef struct {
    /** \brief Pay-To-Pubkey-Hash addresses */
    uint8_t p2pkh;   
    /** \brief Pay-To-Script-Hash addresses */
    uint8_t p2sh;    
    /** \brief Prefix for segwit addreses (cadena Bech32 propia de la red) */
    char bech32[5];  
    /** \brief Wallet Import Format, used in PrivateKey */
    uint8_t wif;     
    /** \brief HD private key for legacy addresses (P2PKH) */
    uint8_t xprv[4]; 
    /** \brief HD private key for nested Segwit (P2SH-P2WPKH) */
    uint8_t yprv[4]; 
    /** \brief HD private key for native Segwit (P2WPKH) */
    uint8_t zprv[4]; 
    /** \brief HD private key for nested Segwit Multisig (P2SH-P2WSH) */
    uint8_t Yprv[4]; 
    /** \brief HD private key for native Segwit Multisig (P2WSH) */
    uint8_t Zprv[4]; 
    /** \brief HD public key for legacy addresses (P2PKH) */
    uint8_t xpub[4]; 
    /** \brief HD public key for nested Segwit (P2SH-P2WPKH) */
    uint8_t ypub[4]; 
    /** \brief HD public key for native Segwit (P2WPKH) */
    uint8_t zpub[4]; 
    /** \brief HD public key for nested Segwit Multisig (P2SH-P2WSH) */
    uint8_t Ypub[4]; 
    /** \brief HD public key for native Segwit Multisig (P2WSH) */
    uint8_t Zpub[4]; 
    /** \brief bip32 coin index */
    uint32_t bip32;
} ChainNetwork;

/*
 * Base58 P2PKH networks. Mapping to the @neuraiproject/neurai-key 5 network names:
 *   Neurai       -> "xna-legacy"      (m/44'/1900'/…)
 *   NeuraiLegacy -> "xna-old-legacy"  (m/44'/0'/…, historical coin type 0)
 *   NeuraiTest   -> "xna-legacy-test" (m/44'/1'/…, also used on regtest)
 * neurai-key 5 "xna" / "xna-test" are the strict ECDSA witness v3 addresses
 * (nq1r… / tnq1r…) of the same secp256k1 keys at m/84'/…: see
 * PublicKey::ecdsaAddress() and NeuraiPQ.h. The AuthScript families (nc/pq/nq
 * HRPs) are not described by ChainNetwork; its `bech32` field stays empty.
 */
extern const ChainNetwork Neurai;
extern const ChainNetwork NeuraiLegacy;
extern const ChainNetwork NeuraiTest;
extern const ChainNetwork * networks[];
extern const uint8_t networks_len;

/** \brief True for the testnet / regtest parameters (NeuraiTest prefixes),
 *         false for mainnet (Neurai, NeuraiLegacy). Used to pick the
 *         mainnet or testnet HRP of the AuthScript address families. */
bool chainNetworkIsTestnet(const ChainNetwork * network);

// default network for the application
#ifndef DEFAULT_NETWORK
#define DEFAULT_NETWORK Neurai
#endif

#endif // __UXNA_NETWORKS_H__