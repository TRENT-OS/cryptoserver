/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

// OS includes
#include "OS_Filesystem.h"
#include "OS_Crypto.h"
#include "OS_Keystore.h"

// FS includes
#include "ChanMuxNvmDriver.h"
#include "OS_PartitionManager.h"
#include "OS_FilesystemFileStreamFactory.h"
#include "partition_io_layer.h"

#include "LibDebug/Debug.h"

#include <camkes.h>
#include <string.h>

// Defines for ChanMux
static const ChanMuxClientConfig_t chanMuxClientConfig =
{
    .port  = CHANMUX_DATAPORT_ASSIGN(chanMux_chan_portRead,
                                     chanMux_chan_portWrite),
    .wait  = chanMux_chan_EventHasData_wait,
    .write = chanMux_Rpc_write,
    .read  = chanMux_Rpc_read
};

// Config for Crypto API
static const OS_Crypto_Config_t remoteCfg =
{
    .mode = OS_Crypto_MODE_SERVER,
    .dataport = OS_DATAPORT_ASSIGN(CryptoLibDataport),
    .library.entropy = OS_CRYPTO_ASSIGN_EntropySource(entropySource_rpc_read,
                                                      entropySource_dp),
};

// Allow at most this amount of clients
#define CRYPTO_CLIENTS_MAX 16

// Maximum length of keys with FAT32 as FS
#define KEYSTORE_NAME_MAX 8

// All the FS/KeyStore stuff have an underlying "parent" pointer for the "real"
// object
#define GET_PARENT_PTR(o) (&((o).parent))

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
seL4_Word CryptoLibServer_get_sender_id(void);

typedef struct
{
    OS_Keystore_Handle_t hKeystore;
    OS_Crypto_Handle_t hCrypto;
    hPartition_t partition;
    OS_FilesystemFileStreamFactory_t fileStream;
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
    ChanMuxNvmDriver chanMuxNvmDriver;
} CryptoServer_FileSystem;

typedef struct
{
    CryptoServer_Client clients[CRYPTO_CLIENTS_MAX];
    CryptoServer_FileSystem fs;
} CryptoServer_State;

// Here we keep track of all the respective contexts and the list of clients
// connected to the server
static CryptoServer_State serverState;

// Private Functions -----------------------------------------------------------

/*
 * Here we map the RPC client to his respective data structures. What is important
 * to understand is that the CryptoServer offers TWO interfaces:
 * 1. The CryptoServer interface, as explicitly defined in the relevant CAMKES
 *    file and as visible in CrytpoServer.h and this file.
 * 2. The CryptoLibServer interface, due to the fact that this component is
 *    linked with OS_CRYPTO_WITH_RCP_SERVER and thus contains the Crypto API
 *    LIB and RPC Server code.
 * Mapping to the data structure is based on the numeric "sender ID" which each
 * CAMKES call to an interface provides. However, we need to ensure that
 * sender IDs are the same for each RPC client ON BOTH INTERFACES. If it is not
 * so, one component initializes data structures with ID=1 via the CryptoServer
 * interface, and then uses data structures with ID=2 (or whatever) via the
 * CryptoLibServer interface! This mismatch leads to problems.
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
 *          testApp_1.CryptoServer_attributes      = 0;
 *          testApp_1.CryptoLibServer_attributes   = 0;
 *          testApp_2.CryptoServer_attributes      = 1;
 *          testApp_2.CryptoLibServer_attributes   = 1;
 *      }
 *  }
 */

static CryptoServer_Client*
getClient(
    seL4_Word id)
{
    CryptoServer_Client* client;

    // Before we acces the server state, make sure it is initialized.
    Debug_ASSERT_PRINTFLN(sem_init_wait() == 0, "Failed to wait for semaphore");

    client = (id >= config.numClients) ? NULL :
             (serverState.clients[id].id != id) ? NULL :
             &serverState.clients[id];

    Debug_ASSERT_PRINTFLN(sem_init_post() == 0, "Failed to post semaphore");

    return client;
}

static CryptoServer_Client*
CryptoServer_getClient()
{
    return getClient(CryptoServer_get_sender_id());
}

static CryptoServer_Client*
CryptoLibServer_getClient()
{
    return getClient(CryptoLibServer_get_sender_id());
}

static OS_Error_t
initFileSystem(
    CryptoServer_FileSystem* fs)
{
    OS_Error_t err;
    OS_PartitionManagerDataTypes_DiskData_t disk;

    if (!ChanMuxNvmDriver_ctor(
            &(fs->chanMuxNvmDriver),
            &chanMuxClientConfig))
    {
        Debug_LOG_ERROR("ChanMuxNvmDriver_ctor() failed");
        return OS_ERROR_GENERIC;
    }

    // Set up partition manager
    if ((err = OS_PartitionManager_init(
                   ChanMuxNvmDriver_get_nvm(
                       &fs->chanMuxNvmDriver))) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_PartitionManager_init() failed with %d", err);
        goto err0;
    }
    if ((err = OS_PartitionManager_getInfoDisk(&disk)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_PartitionManager_getInfoDisk() failed with %d", err);
        goto err0;
    }

    // Make sure we have as many partitions as we have clients
    Debug_ASSERT(config.numClients == disk.partition_count);

    return OS_SUCCESS;

err0:
    ChanMuxNvmDriver_dtor(&fs->chanMuxNvmDriver);

    return err;
}

static OS_Error_t
initKeyStore(
    CryptoServer_FileSystem* fs,
    const uint8_t            index,
    CryptoServer_KeyStore*   ks)
{
    OS_Error_t err;
    OS_PartitionManagerDataTypes_PartitionData_t partition;
    OS_Crypto_Config_t localCfg =
    {
        .mode = OS_Crypto_MODE_LIBRARY_ONLY,
        .library.entropy = OS_CRYPTO_ASSIGN_EntropySource(entropySource_rpc_read,
                                                          entropySource_dp),
    };

    // We need an instance of the Crypto API for the keystore for hashing etc..
    if ((err = OS_Crypto_init(&ks->hCrypto, &localCfg)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Crypto_init() failed with %d", err);
        return err;
    }

    // Read partition info to get the internal ID
    if ((err = OS_PartitionManager_getInfoPartition(index,
                                                    &partition)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_PartitionManager_getInfoPartition() failed with %d", err);
        goto err0;
    }

    // Initialize the partition with RW access
    if ((err = OS_Filesystem_init(partition.partition_id, 0)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Filesystem_init() failed with %d", err);
        goto err0;
    }

    // Open the partition
    ks->partition = OS_Filesystem_open(partition.partition_id);
    if (!OS_Filesystem_validatePartitionHandle(ks->partition))
    {
        Debug_LOG_ERROR("Failed to open partition");
        err = OS_ERROR_GENERIC;
        goto err0;
    }

    // Create FS on partition
    if ((err = OS_Filesystem_create(
                   ks->partition,
                   FS_FORMAT,
                   partition.partition_size,
                   0,  // default value: size of sector:   512
                   0,  // default value: size of cluster:  512
                   0,  // default value: reserved sectors count: FAT12/FAT16 = 1; FAT32 = 3
                   0,  // default value: count file/dir entries: FAT12/FAT16 = 16; FAT32 = 0
                   0,  // default value: count header sectors: 512
                   FS_PARTITION_OVERWRITE_CREATE)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Filesystem_create() failed with %d", err);
        goto err1;
    }

    // Mount the FS on the partition
    if ((err = OS_Filesystem_mount(ks->partition)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("Failed to mount partition with filesystem.");
        return OS_ERROR_GENERIC;
    }

    // Open the partition and assign it to a filestream factory
    if (!OS_FilesystemFileStreamFactory_ctor(&ks->fileStream, ks->partition))
    {
        Debug_LOG_ERROR("Failed to create FileStreamFactory");
        err = OS_ERROR_GENERIC;
        goto err2;
    }

    if ((err = OS_Keystore_init(&ks->hKeystore, GET_PARENT_PTR(ks->fileStream),
                                ks->hCrypto, "keystore")) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Keystore_init() failed with %d", err);
        goto err3;
    }

    return OS_SUCCESS;

err3:
    OS_FilesystemFileStreamFactory_dtor(GET_PARENT_PTR(ks->fileStream));
err2:
    OS_Filesystem_unmount(ks->partition);
err1:
    OS_Filesystem_close(ks->partition);
err0:
    OS_Crypto_free(ks->hCrypto);

    return err;
}

// Public Functions used only by CryptoLibServer ------------------------------

/*
 * This function is called from the RPC server of the Crypto API to find the
 * correct API context, irrespective of which API context address the RPC client
 * tells it to use. This is done to prevent API clients from accessing contexts
 * that don't belong to them.
 *
 * Note that this uses CryptoLibServer_getClient, which WAITs until the
 * serverState struct has been initialized!!
 */
OS_Crypto_Handle_t
CryptoLibServer_getCrypto(
    void)
{
    CryptoServer_Client* client = CryptoLibServer_getClient();
    return (NULL == client) ? NULL : client->hCrypto;
}

/*
 * Init filesystem, keystore and crypto states for every client before allowing the
 * RPC components to access them.
 *
 * NOTE: Ideally, we would like to do this in post_init() but OS_Filesystem_return()
 *       does not return, so that needs further investigation.
 */
int run()
{
    OS_Error_t err;
    CryptoServer_Client* client;

    // Make sure we don't exceed our limit
    Debug_ASSERT(config.numClients <= CRYPTO_CLIENTS_MAX);
    // Make sure we have as many COLUMNS in the first row as we have clients
    Debug_ASSERT(config.numClients == sizeof(config.clients[0].allowedIds) /
                 sizeof(int));
    // Make sure we have as many ROWS in the matrix as we have clients
    Debug_ASSERT(config.numClients == sizeof(config.clients) /
                 sizeof(config.clients[0]));

    if ((err = initFileSystem(&serverState.fs)) != OS_SUCCESS)
    {
        return err;
    }

    for (size_t i = 0; i < config.numClients; i++)
    {
        client = &serverState.clients[i];
        client->id = i;

        // Set up an instance of the Crypto API for each client which is then
        // accessed via its RPC interface
        if ((err = OS_Crypto_init(&client->hCrypto, &remoteCfg)) != OS_SUCCESS)
        {
            return err;
        }

        // Set up keystore
        if ((err = initKeyStore(&serverState.fs, i, &client->keys)) != OS_SUCCESS)
        {
            return err;
        }
    }

    /*
     * We have to post twice, because we may have the two RPC threads for the
     * two interfaces waiting in parallel for the init to complete. The two
     * interfaces are:
     * 1. CryptoServer      (implemented here)
     * 2. CryptoLibServer   (provided via the RPC server module of the Crypto API)
     */
    Debug_ASSERT_PRINTFLN(sem_init_post() == 0, "Failed to post semaphore");
    Debug_ASSERT_PRINTFLN(sem_init_post() == 0, "Failed to post semaphore");

    return OS_SUCCESS;
}

// Public Functions ------------------------------------------------------------

OS_Error_t
CryptoServer_RPC_loadKey(
    CryptoLib_Object_ptr* ptr,
    seL4_Word             ownerId,
    const char*           name)
{
    OS_Error_t err;
    CryptoServer_Client* client, *owner;
    OS_CryptoKey_Data_t data;
    size_t dataLen = sizeof(data);
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

    // Check if we have access to the key of that owner; a zero indicates NO ACCES
    // anything else allows it.
    if (config.clients[owner->id].allowedIds[client->id] == 0)
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
CryptoServer_RPC_storeKey(
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
        config.clients[client->id].storageLimit)
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
