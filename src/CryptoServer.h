/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosCryptoApi.h"

seos_err_t
CryptoServer_loadKey(
    unsigned int                 ownerId,
    const char*                  name,
    SeosCryptoApi_Key_RemotePtr* ptr);

seos_err_t
CryptoServer_storeKey(
    const char*       name,
    SeosCryptoApi_Key key);