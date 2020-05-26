/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 *
 * @defgroup SEOS CryptoServer
 * @{
 *
 * @file CryptoServer.h
 *
 * @brief SEOS CryptoServer interface
 *
 */

#pragma once

#include "OS_Crypto.h"

#include <camkes.h>

/**
 * @brief Load a key from CryptoServer's KeyStore into Crypto API instance
 *
 * Every CryptoServer client has its own KeyStore instance where keys are stored
 * under a name. This function allows a client to load a key from any client
 * (identified by the client's ID) into its local Crypto API instance for use.
 *
 * The CryptoServer will internally check, whether a request can be granted based
 * on its configuration.
 *
 * Upon success, the key in \p hKey can be used like any other Crypto API key,
 * for the API instance given by \p hCrypto.
 *
 * NOTE: The key has to be freed once it is no longer used.
 *
 * @param hKey (required) pointer to handle of SEOS Crypto Key object
 * @param hCrypto (required) handle of SEOS Crypto API
 * @param ownerId (required) ID of key's owner
 * @param name (required) name of key
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_NOT_FOUND if the CryptoServer client cannot be found
 * @retval OS_ERROR_ACCESS_DENIED if the CryptoServer configuration does not allow
 *  the client to load keys owned by \p ownerId
 * @retval OS_ERROR_GENERIC is a generic error occured in the KeyStore
 */
static OS_Error_t
CryptoServer_loadKey(
    OS_CryptoKey_Handle_t* hKey,
    OS_Crypto_Handle_t     hCrypto,
    seL4_Word              ownerId,
    const char*            name)
{
    OS_Error_t err;
    CryptoLib_Object_ptr ptr;

    if (NULL == hKey || NULL == hCrypto)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    // Call function within CryptoServer component via CAmkES-generated interface
    if ((err = CryptoServer_RPC_loadKey(&ptr, ownerId, name)) == OS_SUCCESS)
    {
        err = OS_Crypto_migrateLibObject(hKey, hCrypto, ptr, false);
    }

    return err;
}

/**
 * @brief Store a "non-exportable" key in the CryptoServer's KeyStore
 *
 * The Crypto API delegates all operations (including generation, import, etc.)
 * with keys with the exportable flag set to FALSE to the CryptoServer. These keys
 * shall never leave the CryptoServer and are thus safely isolated.
 *
 * Once a key exists in the CryptoServer, it can be used via the Crypto API
 * transparently.
 *
 * Furthermore, it is desirable to persist a key given by the \p hKey handle, so
 * it can be retrieved at a later time (e.g., after a reboot). This function allows
 * to persist a CryptoServer key into the client's KeyStore under a unique \p name.
 *
 * NOTE: Due to restrictions of the underlying file systems, key names are limited
 *       to 8 characters.
 *
 * @param hKey (required) handle of SEOS Crypto Key object
 * @param name (required) name of key
 *
 * @param hCrypto (required) handle of SEOS Crypto API
 *
 * @return an error code
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_NOT_FOUND if the CryptoServer client cannot be found
 * @retval OS_ERROR_INSUFFICIENT_SPACE if the operation would exceed the
 *  storageLimit defined for it in the configuration
 * @retval OS_ERROR_GENERIC is a generic error occured in the KeyStore
 */
static OS_Error_t
CryptoServer_storeKey(
    OS_CryptoKey_Handle_t hKey,
    const char*           name)
{
    // Call function within CryptoServer component via CAmkES-generated interface
    return CryptoServer_RPC_storeKey(OS_Crypto_getLibObject(hKey), name);
}

/** @} */