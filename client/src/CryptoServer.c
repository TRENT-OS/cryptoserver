/* 
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH 
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#include "CryptoServer.h"

OS_Error_t
CryptoServer_loadKey(
    const if_CryptoServer_t* rpc,
    OS_CryptoKey_Handle_t*   pLocalKeyHandle,
    OS_Crypto_Handle_t       hCrypto,
    seL4_Word                ownerId,
    const char*              name)
{
    OS_Error_t err;
    OS_CryptoKey_Handle_t remoteKeyHandle;

    if (NULL == pLocalKeyHandle || NULL == hCrypto)
    {
        return OS_ERROR_INVALID_HANDLE;
    }
    if (NULL == rpc)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    // Load the key in the server's address space, which creates a proxy object
    // on the server side. If successful, import that underlying key object
    // into a proxy object on the client's side.
    if ((err = rpc->loadKey(
                   &remoteKeyHandle,
                   ownerId,
                   name)) == OS_SUCCESS)
    {
        err = OS_Crypto_createProxy(
                  pLocalKeyHandle,
                  hCrypto,
                  remoteKeyHandle,
                  false);
    }

    return err;
}

OS_Error_t
CryptoServer_storeKey(
    const if_CryptoServer_t* rpc,
    OS_CryptoKey_Handle_t    localKeyHandle,
    const char*              name)
{
    OS_CryptoKey_Handle_t remoteKeyHandle;

    if (NULL == rpc)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    // Get the address of the underlying key object from the client's proxy object.
    // This should be the address where the server's proxy object can be found.
    remoteKeyHandle = (OS_CryptoKey_Handle_t)OS_Crypto_getProxyPtr(localKeyHandle);
    if (NULL == remoteKeyHandle)
    {
        return OS_ERROR_INVALID_HANDLE;
    }

    return rpc->storeKey(remoteKeyHandle, name);
}