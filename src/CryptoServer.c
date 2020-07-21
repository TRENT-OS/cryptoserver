/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

// OS includes
#include "OS_FileSystem.h"
#include "OS_Crypto.h"
#include "OS_Keystore.h"

#include "LibDebug/Debug.h"

#include <string.h>

#include <camkes.h>

// Config for Crypto API
static const OS_Crypto_Config_t cfgCrypto =
{
    .mode = OS_Crypto_MODE_SERVER,
    .dataport = OS_DATAPORT_ASSIGN(crypto_port),
    .library.entropy = OS_CRYPTO_ASSIGN_Entropy(
        entropy_rpc,
        entropy_port),
};
// Config for FileSystem API
static const OS_FileSystem_Config_t cfgFs =
{
    .type = OS_FileSystem_Type_FATFS,
    .size = OS_FileSystem_STORAGE_MAX,
    .storage = OS_FILESYSTEM_ASSIGN_Storage(
        storage_rpc,
        storage_dp),
};

// Allow at most this amount of clients
#define CRYPTO_CLIENTS_MAX 16

// Maximum length of keynames
#define KEYSTORE_NAME_MAX 8
/*
 * These are auto-generated based on interface names; they give unique ID
 * assigned to the user of the interface.
 *
 * Sender IDs can be assigned via a configuration for each interface/user
 * individually, when following this convention:
 *   <interface_user>.<interface>_attributes = ID
 *
 * IDs must be same for each interface user on both interfaces, see also the
 * comment below.
 */
seL4_Word cryptoServer_rpc_get_sender_id(
    void);
seL4_Word crypto_rpc_get_sender_id(
    void);

typedef struct
{
    OS_Keystore_Handle_t hKeystore;
    OS_Crypto_Handle_t hCrypto;
    size_t bytesWritten;
} CryptoServer_KeyStore;

typedef struct
{
    unsigned int id;
    OS_Crypto_Handle_t hCrypto;
    CryptoServer_KeyStore keys;
} CryptoServer_Client;

typedef struct
{
    CryptoServer_Client clients[CRYPTO_CLIENTS_MAX];
    OS_FileSystem_Handle_t hFs;
} CryptoServer_State;

// Here we keep track of all the respective contexts and the list of clients
// connected to the server
static CryptoServer_State serverState;

// Clients we have based on the amount of config data
static const size_t clients = sizeof(cryptoServer_config) /
                              sizeof(struct CryptoServer_ClientConfig);


// Private Functions -----------------------------------------------------------

/*
 * Here we map the RPC client to his respective data structures. What is important
 * to understand is that the CryptoServer offers TWO interfaces:
 * 1. The cryptoServer_rpc interface, as explicitly defined in the relevant CAMKES
 *    file and as visible in CrytpoServer.h and this file.
 * 2. The crypto_rpc interface, due to the fact that this component is
 *    linked with OS_CRYPTO_WITH_RCP_SERVER and thus contains the Crypto API
 *    LIB and RPC Server code.
 * Mapping to the data structure is based on the numeric "sender ID" which each
 * CAMKES call to an interface provides. However, we need to ensure that
 * sender IDs are the same for each RPC client ON BOTH INTERFACES. If it is not
 * so, one component initializes data structures with ID=1 via the cryptoServer_rpc
 * interface, and then uses data structures with ID=2 (or whatever) via the
 * crypto_rpc interface! This mismatch leads to problems.
 *
 * The way to make sure both IDs are the same, is to explicitly assign the IDs
 * in a configuration:
 *
 *  assembly {
 *      composition {
 *          component   TestApp_1   testApp_1;
 *          component   TestApp_2   testApp_2;
 *          ...
 *      }
 *      configuration{
 *          testApp_1.cryptoServer_rpc_attributes   = 0;
 *          testApp_1.crypto_rpc_attributes         = 0;
 *          testApp_2.cryptoServer_rpc_attributes   = 1;
 *          testApp_2.crypto_rpc_attributes         = 1;
 *      }
 *  }
 */

static CryptoServer_Client*
getClient(
    seL4_Word id)
{
    CryptoServer_Client* client;

    client = (id >= clients) ? NULL :
             (serverState.clients[id].id != id) ? NULL :
             &serverState.clients[id];

    return client;
}

static CryptoServer_Client*
CryptoServer_getClient()
{
    return getClient(cryptoServer_rpc_get_sender_id());
}

static CryptoServer_Client*
crypto_rpc_getClient()
{
    return getClient(crypto_rpc_get_sender_id());
}

static OS_Error_t
initFileSystem(
    OS_FileSystem_Handle_t* hFs)
{
    OS_Error_t err;

    if ((err = OS_FileSystem_init(hFs, &cfgFs)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystem_init() failed with %d", err);
        return err;
    }

    // Try mounting, if it fails we format the disk again and try another time
    if ((err = OS_FileSystem_mount(*hFs)) != OS_SUCCESS)
    {
        Debug_LOG_INFO("Mounting fileystem failed, formatting the storage now");
        if ((err = OS_FileSystem_format(*hFs)) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_FileSystem_format() failed with %d", err);
            return err;
        }
        if ((err = OS_FileSystem_mount(*hFs)) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_FileSystem_mount() finally failed with %d", err);
            return err;
        }
    }
    else
    {
        Debug_LOG_INFO("Mounted existing fileystem");
    }

    return err;
}

static OS_Error_t
initKeyStore(
    OS_FileSystem_Handle_t hFs,
    const uint8_t          index,
    CryptoServer_KeyStore* ks)
{
    OS_Error_t err;
    char ksName[16];
    OS_Crypto_Config_t cfg =
    {
        .mode = OS_Crypto_MODE_LIBRARY_ONLY,
        .library.entropy = OS_CRYPTO_ASSIGN_Entropy(
            entropy_rpc,
            entropy_port),
    };

    // We need an instance of the Crypto API for the keystore for hashing etc..
    if ((err = OS_Crypto_init(&ks->hCrypto, &cfg)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Crypto_init() failed with %d", err);
        return err;
    }

    // Every keystore needs its own instance name
    snprintf(ksName, sizeof(ksName), "kstore%02i", index);
    if ((err = OS_Keystore_init(&ks->hKeystore, hFs, ks->hCrypto,
                                ksName)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Keystore_init() failed with %d", err);
        goto err0;
    }

    return OS_SUCCESS;

err0:
    OS_Crypto_free(ks->hCrypto);

    return err;
}

// Public Functions used only by crypto_rpc ------------------------------

/*
 * This function is called from the RPC server of the Crypto API to find the
 * correct API context, irrespective of which API context address the RPC client
 * tells it to use. This is done to prevent API clients from accessing contexts
 * that don't belong to them.
 *
 * Note that this uses crypto_rpc_getClient, which WAITs until the
 * serverState struct has been initialized!!
 */
OS_Crypto_Handle_t
crypto_rpc_getCrypto(
    void)
{
    CryptoServer_Client* client = crypto_rpc_getClient();
    return (NULL == client) ? NULL : client->hCrypto;
}

void
post_init()
{
    OS_Error_t err;
    CryptoServer_Client* client;

    // Make sure we don't exceed our limit
    Debug_ASSERT(clients <= CRYPTO_CLIENTS_MAX);
    // Make sure we have as many COLUMNS in the first row as we have clients
    Debug_ASSERT(clients == sizeof(cryptoServer_config.clients[0].allowedIds) /
                 sizeof(int));
    // Make sure we have as many ROWS as we have clients
    Debug_ASSERT(clients == sizeof(cryptoServer_config.clients) /
                 sizeof(cryptoServer_config.clients[0]));

    if ((err = initFileSystem(&serverState.hFs)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("initFileSystem() failed with %d", err);
        return;
    }

    for (size_t i = 0; i < clients; i++)
    {
        client = &serverState.clients[i];
        client->id = i;

        // Set up an instance of the Crypto API for each client which is then
        // accessed via its RPC interface
        if ((err = OS_Crypto_init(&client->hCrypto, &cfgCrypto)) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_Crypto_init() failed with %d", err);
            return;
        }

        // Set up keystore
        if ((err = initKeyStore(serverState.hFs, i, &client->keys)) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("initKeyStore() failed with %d", err);
            return;
        }
    }
}

// Public Functions ------------------------------------------------------------

OS_Error_t
cryptoServer_rpc_loadKey(
    CryptoLib_Object_ptr* ptr,
    seL4_Word             ownerId,
    const char*           name)
{
    OS_Error_t err;
    CryptoServer_Client* client, *owner;
    OS_CryptoKey_Data_t data;
    size_t dataLen = sizeof(data), i;
    bool isAllowed;
    OS_CryptoKey_Handle_t hMyKey;

    if ((owner = getClient(ownerId)) == NULL)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    else if (strlen(name) == 0 || strlen(name) > KEYSTORE_NAME_MAX)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((client = CryptoServer_getClient()) == NULL)
    {
        return OS_ERROR_NOT_FOUND;
    }

    for (i = 0, isAllowed = false; i < clients && !isAllowed; i++)
    {
        isAllowed = (cryptoServer_config.clients[owner->id].allowedIds[i] ==
                     client->id);
    }

    // Check if we have access to the key of that owner; a zero indicates NO ACCES
    // anything else allows it.
    if (!isAllowed)
    {
        Debug_LOG_WARNING("Client with ID=%u failed to access the keystore of ID=%u",
                          client->id, owner->id);
        return OS_ERROR_ACCESS_DENIED;
    }

    // Here we access the data stored for another client; however, since all
    // RPC calls are serialized, we cannot have a race-condition because there
    // is only one RPC client active at a time.
    if ((err = OS_Keystore_loadKey(owner->keys.hKeystore, name, &data,
                                   &dataLen)) != OS_SUCCESS)
    {
        return err;
    }

    // Import key data into the remote Crypto API, so it can be used there.
    if ((err = OS_CryptoKey_import(&hMyKey, client->hCrypto,
                                   &data)) != OS_SUCCESS)
    {
        return err;
    }

    // Send back only the pointer to the LIB Key object
    *ptr = OS_Crypto_getLibObject(hMyKey);

    return OS_SUCCESS;
}

OS_Error_t
cryptoServer_rpc_storeKey(
    CryptoLib_Object_ptr ptr,
    const char*          name)
{
    OS_Error_t err;
    OS_CryptoKey_Data_t data;
    OS_CryptoKey_Handle_t hMyKey;
    CryptoServer_Client* client;

    if ((client = CryptoServer_getClient()) == NULL)
    {
        return OS_ERROR_NOT_FOUND;
    }
    else if (strlen(name) == 0 || strlen(name) > KEYSTORE_NAME_MAX)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    // We get an API Key object from the RPC client, which has the API context of
    // the CLIENT attached to it. This needs to be changed to the local API context.
    if ((err = OS_Crypto_migrateLibObject(&hMyKey, client->hCrypto,
                                          ptr, true)) != OS_SUCCESS)
    {
        return err;
    }

    // Now we can use that key object and export its data; we can always do this
    // since we go through the API which uses the RPC server's LIB instance (the
    // same the RPC client refers to from afar)..
    if ((err = OS_CryptoKey_export(hMyKey, &data)) != OS_SUCCESS)
    {
        return err;
    }

    // Check if we are about to exceed the storage limit for this keystore
    if (client->keys.bytesWritten + sizeof(data) >
        cryptoServer_config.clients[client->id].storageLimit)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    // Store key in keystore
    if ((err = OS_Keystore_storeKey(client->keys.hKeystore, name, &data,
                                    sizeof(data))) == OS_SUCCESS)
    {
        client->keys.bytesWritten += sizeof(data);
    }

    return err;
}
