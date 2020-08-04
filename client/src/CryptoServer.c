/* Copyright (C) 2019-2020, Hensoldt Cyber GmbH */

#include "OS_Crypto.h"

#include <camkes.h>

OS_Error_t
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

    if ((err = cryptoServer_rpc_loadKey(&ptr, ownerId, name)) == OS_SUCCESS)
    {
        err = OS_Crypto_migrateLibObject(hKey, hCrypto, ptr, false);
    }

    return err;
}

OS_Error_t
CryptoServer_storeKey(
    OS_CryptoKey_Handle_t hKey,
    const char*           name)
{
    return cryptoServer_rpc_storeKey(OS_Crypto_getLibObject(hKey), name);
}
