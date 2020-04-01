/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

// Crypto includes
#include "OS_Crypto.h"

// KeyStore includes
#include "SeosKeyStore.h"
#include "SeosKeyStoreApi.h"

// FS includes
#include "ProxyNVM.h"
#include "AesNvm.h"
#include "seos_fs_api.h"
#include "seos_pm_api.h"
#include "SeosFileStreamFactory.h"
#include "partition_io_layer.h"

#include "LibDebug/Debug.h"

#include <camkes.h>
#include <string.h>

// Defines for ChanMux
#define CHANMUX_NVM_CHANNEL 6
#define CHANMUX_NVM_DATAPORT chanMuxDataPort

#define CRYPTO_DATAPORT SeosCryptoDataport
// Allow at most this amount of clients
#define CRYPTO_CLIENTS_MAX 16

// Maximum length of keys with FAT32 as FS
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
seL4_Word CryptoServer_get_sender_id(void);
seL4_Word OS_CryptoRpcServer_get_sender_id(void);

typedef struct
{
    SeosKeyStoreCtx* context;
    SeosKeyStore store;
    OS_Crypto_Handle_t hCrypto;
    hPartition_t partition;
    SeosFileStreamFactory fileStream;
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
    struct
    {
        ProxyNVM nvm;
        char buffer[PAGE_SIZE];
    } proxy;
    ChanMuxClient chanMux;
} CryptoServer_FileSystem;

typedef struct
{
    CryptoServer_Client clients[CRYPTO_CLIENTS_MAX];
    CryptoServer_FileSystem fs;
    bool initialized;
} CryptoServer_State;

// Here we keep track of all the respective contexts and the list of clients
// connected to the server
static CryptoServer_State serverState =
{
    .clients     = {},
    .fs          = {},
    .initialized = false
};

// Private Functions -----------------------------------------------------------

static int
entropy(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}

/*
 * Here we map the RPC client to his respective data structures. What is important
 * to understand is that the CryptoServer offers TWO interfaces:
 * 1. The CryptoServer interface, as explicitly defined in the relevant CAMKES
 *    file and as visible in CrytpoServer.h and this file.
 * 2. The OS_CryptoRpcServer interface, due to the fact that this component is
 *    linked with SEOS_CRYPTO_WITH_RCP_SERVER and thus contains the Crypto API
 *    LIB and RPC Server code.
 * Mapping to the data structure is based on the numeric "sender ID" which each
 * CAMKES call to an interface provides. However, we need to ensure that
 * sender IDs are the same for each RPC client ON BOTH INTERFACES. If it is not
 * so, one component initializes data structures with ID=1 via the CryptoServer
 * interface, and then uses data structures with ID=2 (or whatever) via the
 * OS_CryptoRpcServer interface! This mismatch leads to problems.
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
 *          testApp_1.CryptoServer_attributes         = 0;
 *          testApp_1.OS_CryptoRpcServer_attributes   = 0;
 *          testApp_2.CryptoServer_attributes         = 1;
 *          testApp_2.OS_CryptoRpcServer_attributes   = 1;
 *      }
 *  }
 */

static CryptoServer_Client*
getClient(
    seL4_Word id)
{
    // Before we acces the server state, make sure it is initialized. If not, we
    // wait for the run-thread to send the initDone signal!
    if (!serverState.initialized)
    {
        initDone_wait();
    }

    return (id >= config.numClients) ? NULL :
           (serverState.clients[id].id == id) ? &serverState.clients[id] : NULL;
}

static CryptoServer_Client*
CryptoServer_getClient()
{
    return getClient(CryptoServer_get_sender_id());
}

static CryptoServer_Client*
OS_CryptoRpcServer_getClient()
{
    return getClient(OS_CryptoRpcServer_get_sender_id());
}

static seos_err_t
initFileSystem(
    CryptoServer_FileSystem* fs)
{
    pm_disk_data_t disk;

    // Setup ChanMux -> Proxy to write to QEMU host for persistence
    if (!ChanMuxClient_ctor(&fs->chanMux,
                            CHANMUX_NVM_CHANNEL,
                            CHANMUX_NVM_DATAPORT,
                            CHANMUX_NVM_DATAPORT) ||
        !ProxyNVM_ctor(&fs->proxy.nvm, &fs->chanMux, fs->proxy.buffer,
                       sizeof(fs->proxy.buffer)))
    {
        Debug_LOG_ERROR("Failed to construct ChanMux-ProxyNVM cascade");
        return SEOS_ERROR_GENERIC;
    }

    // Set up the partition manager
    if (partition_manager_init(&fs->proxy.nvm) != SEOS_SUCCESS ||
        partition_manager_get_info_disk(&disk) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("Failed to init pm");
        return SEOS_ERROR_GENERIC;
    }

    // Make sure we have as many partitions as we have clients
    Debug_ASSERT(config.numClients == disk.partition_count);

    Debug_LOG_DEBUG("initFileSystem succesful");

    return SEOS_SUCCESS;
}

static seos_err_t
initKeyStore(
    CryptoServer_FileSystem* fs,
    const uint8_t            index,
    CryptoServer_KeyStore*   ks)
{
    seos_err_t err;
    pm_partition_data_t partition;
    OS_Crypto_Config_t localCfg =
    {
        .mode = OS_Crypto_MODE_LIBRARY,
        .mem.malloc = malloc,
        .mem.free = free,
        .impl.lib.rng.entropy = entropy,
    };

    // We need an instance of the Crypto API for the keystore for hashing etc..
    if ((err = OS_Crypto_init(&ks->hCrypto, &localCfg)) != SEOS_SUCCESS)
    {
        return err;
    }

    // Read partition info to get the internal ID
    if (partition_manager_get_info_partition(index, &partition) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("Failed to get partition info.");
        return SEOS_ERROR_GENERIC;
    }

    // Initialize the partition with RW access
    if (partition_init(partition.partition_id, 0) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("Failed to init partition.");
        return SEOS_ERROR_GENERIC;
    }

    // Open the partition
    ks->partition = partition_open(partition.partition_id);
    if (!is_valid_partition_handle(ks->partition))
    {
        Debug_LOG_ERROR("Failed to open partition.");
        return SEOS_ERROR_GENERIC;
    }

    // Create FS on partition
    if (partition_fs_create(
            ks->partition,
            FS_FORMAT,
            partition.partition_size,
            0,  // default value: size of sector:   512
            0,  // default value: size of cluster:  512
            0,  // default value: reserved sectors count: FAT12/FAT16 = 1; FAT32 = 3
            0,  // default value: count file/dir entries: FAT12/FAT16 = 16; FAT32 = 0
            0,  // default value: count header sectors: 512
            FS_PARTITION_OVERWRITE_CREATE) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("Failed to create filesystem.");
        return SEOS_ERROR_GENERIC;
    }

    // Mount the FS on the partition
    if (partition_fs_mount(ks->partition) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("Failed to mount partition with filesystem.");
        return SEOS_ERROR_GENERIC;
    }

    // Open the partition and assign it to a filestream factory
    if (!SeosFileStreamFactory_ctor(&ks->fileStream, ks->partition))
    {
        Debug_LOG_ERROR("Failed to open partition or create FileStreamFactory");
        return SEOS_ERROR_GENERIC;
    }

    if ((err = SeosKeyStore_init(&ks->store, &ks->fileStream.parent, ks->hCrypto,
                                 "keystore")) != SEOS_SUCCESS)
    {
        return err;
    }
    ks->context = SeosKeyStore_TO_SEOS_KEY_STORE_CTX(&ks->store);

    return SEOS_SUCCESS;
}

// Public Functions used only by OS_CryptoRpcServer ---------------------------

/*
 * This function is called from the RPC server of the Crypto API to find the
 * correct API context, irrespective of which API context address the RPC client
 * tells it to use. This is done to prevent API clients from accessing contexts
 * that don't belong to them.
 *
 * Note that this uses OS_CryptoRpcServer_getClient, which WAITs until the
 * serverState struct has been initialized!!
 */
OS_Crypto_Handle_t
OS_CryptoRpcServer_getCrypto(
    void)
{
    CryptoServer_Client* client = OS_CryptoRpcServer_getClient();
    return (NULL == client) ? NULL : client->hCrypto;
}

// Public Functions ------------------------------------------------------------

seos_err_t
CryptoServer_RPC_loadKey(
    OS_CryptoLib_Object_ptr* ptr,
    seL4_Word                ownerId,
    const char*              name)
{
    seos_err_t err;
    CryptoServer_Client* client, *owner;
    OS_CryptoKey_Data_t data;
    size_t dataLen = sizeof(data);
    OS_CryptoKey_Handle_t hMyKey;

    if ((owner = getClient(ownerId)) == NULL)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (strlen(name) == 0 || strlen(name) > KEYSTORE_NAME_MAX)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((client = CryptoServer_getClient()) == NULL)
    {
        return SEOS_ERROR_NOT_FOUND;
    }

    // Check if we have access to the key of that owner; a zero indicates NO ACCES
    // anything else allows it.
    if (config.clients[owner->id].allowedIds[client->id] == 0)
    {
        Debug_LOG_WARNING("Client with ID=%u failed to access the keystore of ID=%u",
                          client->id, owner->id);
        return SEOS_ERROR_ACCESS_DENIED;
    }

    // Here we access the data stored for another client; however, since all
    // RPC calls are serialized, we cannot have a race-condition because there
    // is only one RPC client active at a time.
    if ((err = SeosKeyStoreApi_getKey(owner->keys.context, name, &data,
                                      &dataLen)) != SEOS_SUCCESS)
    {
        return err;
    }

    // Import key data into the remote Crypto API, so it can be used there.
    if ((err = OS_CryptoKey_import(&hMyKey, client->hCrypto,
                                        &data)) != SEOS_SUCCESS)
    {
        return err;
    }

    // Send back only the pointer to the LIB Key object
    *ptr = OS_Crypto_getObject(hMyKey);

    return SEOS_SUCCESS;
}

seos_err_t
CryptoServer_RPC_storeKey(
    OS_CryptoLib_Object_ptr ptr,
    const char*             name)
{
    seos_err_t err;
    OS_CryptoKey_Data_t data;
    OS_CryptoKey_Handle_t hMyKey;
    CryptoServer_Client* client;

    if ((client = CryptoServer_getClient()) == NULL)
    {
        return SEOS_ERROR_NOT_FOUND;
    }
    else if (strlen(name) == 0 || strlen(name) > KEYSTORE_NAME_MAX)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    // We get an API Key object from the RPC client, which has the API context of
    // the CLIENT attached to it. This needs to be changed to the local API context.
    if ((err = OS_Crypto_migrateObject(&hMyKey, client->hCrypto,
                                           ptr)) != SEOS_SUCCESS)
    {
        return err;
    }

    // Now we can use that key object and export its data; we can always do this
    // since we go through the API which uses the RPC server's LIB instance (the
    // same the RPC client refers to from afar)..
    if ((err = OS_CryptoKey_export(hMyKey, &data)) != SEOS_SUCCESS)
    {
        return err;
    }

    // Check if we are about to exceed the storage limit for this keystore
    if (client->keys.bytesWritten + sizeof(data) >
        config.clients[client->id].storageLimit)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    // Store key in keystore
    if ((err = SeosKeyStoreApi_importKey(client->keys.context, name,
                                         &data, sizeof(data))) == SEOS_SUCCESS)
    {
        client->keys.bytesWritten += sizeof(data);
    }

    return err;
}

int run()
{
    seos_err_t err;
    CryptoServer_Client* client;
    OS_Crypto_Config_t remoteCfg =
    {
        .mode = OS_Crypto_MODE_RPC_SERVER_WITH_LIBRARY,
        .mem.malloc = malloc,
        .mem.free = free,
        .impl.lib.rng.entropy = entropy,
        .server.dataPort = CRYPTO_DATAPORT
    };

    // Make sure we don't exceed our limit
    Debug_ASSERT(config.numClients <= CRYPTO_CLIENTS_MAX);
    // Make sure we have as many COLUMNS in the first row as we have clients
    Debug_ASSERT(config.numClients == sizeof(config.clients[0].allowedIds) / sizeof(
                     int));
    // Make sure we have as many ROWS in the matrix as we have clients
    Debug_ASSERT(config.numClients == sizeof(config.clients) / sizeof(
                     config.clients[0]));

    if ((err = initFileSystem(&serverState.fs)) != SEOS_SUCCESS)
    {
        return err;
    }

    for (size_t i = 0; i < config.numClients; i++)
    {
        client = &serverState.clients[i];
        client->id = i;

        // Set up an instance of the Crypto API for each client which is then
        // accessed via its RPC interface
        if ((err = OS_Crypto_init(&client->hCrypto, &remoteCfg)) != SEOS_SUCCESS)
        {
            return err;
        }

        // Set up keystore
        if ((err = initKeyStore(&serverState.fs, i, &client->keys)) != SEOS_SUCCESS)
        {
            return err;
        }
    }

    serverState.initialized = true;

    // Signal to every RPC interface thread which has potentially already clients
    // waiting to use the CryptoServer
    serverInitDone_emit();

    return SEOS_SUCCESS;
}
