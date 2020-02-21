/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosCryptoApi.h"

#include <camkes.h>

seos_err_t
CryptoServer_loadKey(
    seL4_Word                    ownerId,
    const char*                  name,
    SeosCryptoApi_Key_RemotePtr* ptr);

seos_err_t
CryptoServer_storeKey(
    const char*       name,
    SeosCryptoApi_Key key);