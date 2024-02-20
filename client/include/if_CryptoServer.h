/* 
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH 
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#pragma once

#include "OS_Crypto.h"

#include <stdint.h>

#include <camkes.h>

typedef struct
{
    OS_Error_t (*storeKey)(OS_CryptoKey_Handle_t hKey, const char* name);
    OS_Error_t (*loadKey)(OS_CryptoKey_Handle_t* hKey, seL4_Word ownerId,
                          const char* name);
} if_CryptoServer_t;

#define IF_CRYPTOSERVER_ASSIGN(_rpc_)   \
{                                       \
    .storeKey   = _rpc_ ## _storeKey,   \
    .loadKey    = _rpc_ ## _loadKey,    \
}
