/* Copyright (C) 2019-2020, Hensoldt Cyber GmbH */

#include "OS_Crypto.h"

#include <camkes.h>

OS_Error_t
CryptoServer_loadKey(
    OS_CryptoKey_Handle_t* pLocalKeyHandle,
    OS_Crypto_Handle_t     hCrypto,
    seL4_Word              ownerId,
    const char*            name)
{
    OS_Error_t err;
    OS_CryptoKey_Handle_t remoteKeyHandle;

    if (NULL == pLocalKeyHandle || NULL == hCrypto)
    {
        return OS_ERROR_INVALID_HANDLE;
    }

    if ((err = cryptoServer_rpc_loadKey(
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
    OS_CryptoKey_Handle_t localKeyHandle,
    const char*           name)
{
    OS_CryptoKey_Handle_t remoteKeyHandle;

    // Get the address of the underlying key object from the client's proxy object.
    // This should be the address where the server's proxy object can be found.
    remoteKeyHandle = (OS_CryptoKey_Handle_t)OS_Crypto_getProxyPtr(localKeyHandle);
    if (NULL == remoteKeyHandle)
    {
        return OS_ERROR_INVALID_HANDLE;
    }

    return cryptoServer_rpc_storeKey(remoteKeyHandle, name);