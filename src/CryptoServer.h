/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosCryptoApi.h"

#include <camkes.h>

static seos_err_t
CryptoServer_loadKey(
    SeosCryptoApi_KeyH* hKey,
    SeosCryptoApiH      hCrypto,
    seL4_Word           ownerId,
    const char*         name)
{
    seos_err_t err;
    SeosCryptoLib_Object ptr;

    if (NULL == hKey || NULL == hCrypto)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    // Call function within CryptoServer component via CAmkES-generated interface
    if ((err = CryptoServer_RPC_loadKey(&ptr, ownerId, name)) == SEOS_SUCCESS)
    {
        err = SeosCryptoApi_migrateObject(hKey, hCrypto, ptr);
    }

    return err;
}

static seos_err_t
CryptoServer_storeKey(
    SeosCryptoApi_KeyH hKey,
    const char*        name)
{
    // Call function within CryptoServer component via CAmkES-generated interface
    return CryptoServer_RPC_storeKey(SeosCryptoApi_getObject(hKey), name);
}