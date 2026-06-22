#ifndef __UNEURAI_ASSETNAME_H__R3NU8EN25O
#define __UNEURAI_ASSETNAME_H__R3NU8EN25O

#include <stdint.h>
#include <stddef.h>

/*
 * Neurai asset-name validation, mirroring @neuraiproject/neurai-assets
 * (validators/assetNameValidator.js) exactly — same rules, same per-type
 * dispatch, same Mainnet/Testnet length limits. Pure string logic, no regex,
 * no allocation. Use it to pre-validate names before building an asset tx (the
 * node remains authoritative).
 *
 * Length caps: Mainnet 32 / Testnet 121 (root & sub are one less). DEPIN ('&')
 * is testnet-only. Reserved: XNA / NEURAI / NEURAICOIN (and their '#' forms).
 */

enum AssetNameType {
    ASSET_NAME_INVALID = 0,
    ASSET_NAME_ROOT,
    ASSET_NAME_SUB,
    ASSET_NAME_UNIQUE,
    ASSET_NAME_QUALIFIER,
    ASSET_NAME_SUB_QUALIFIER,
    ASSET_NAME_RESTRICTED,
    ASSET_NAME_DEPIN,
    ASSET_NAME_OWNER
};

/* Detect the asset type from the name and validate it for the network.
 * Returns the type, or ASSET_NAME_INVALID if the name is not valid.
 * `testnet` selects the length limits and enables DEPIN. */
AssetNameType assetDetectAndValidate(const char * name, bool testnet);

/* Convenience: true if `name` is a valid asset name of any type. */
bool assetNameIsValid(const char * name, bool testnet);

#endif /* __UNEURAI_ASSETNAME_H__R3NU8EN25O */
