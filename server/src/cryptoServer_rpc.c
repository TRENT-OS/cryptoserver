/**
 * Copyright (C) 2019-2020, HENSOLDT Cyber GmbH
 */

// OS includes
#include "OS_FileSystem.h"
#include "OS_Crypto.h"
#include "OS_KeystoreFile.h"

#include "lib_debug/Debug.h"
#include "lib_server/HandleMgr.h"
#include "lib_macros/Check.h"

#include <string.h>

#include <camkes.h>

// Get a client when called via RPC
#define GET_CLIENT(cli, cid) \
    do { \
        if ((cli = getClient(cid)) == NULL) \
        { \
            Debug_LOG_ERROR("Could not get state for client with client ID " \
                            "%"SEL4_PRI_word", the badge number is most likely" \
                            " not properly configured", cid); \
            return OS_ERROR_NOT_FOUND; \
        } \
    } while(0)

// Translate between badge IDs and array index
#define CID_TO_IDX(cid) ((cid)-101)
#define IDX_TO_CID(idx) ((idx)+101)

// Config for FileSystem API
static const OS_FileSystem_Config_t cfgFs =
{
    .type = OS_FileSystem_Type_FATFS,
    .size = OS_FileSystem_USE_STORAGE_MAX,
    .storage = IF_OS_STORAGE_ASSIGN(
        storage_rpc,
        storage_port),
};
static const OS_Crypto_Config_t cfgCrypto =
{
    .mode = OS_Crypto_MODE_LIBRARY,
    .entropy = IF_OS_ENTROPY_ASSIGN(
        entropy_rpc,
        entropy_port),
};

// IDs for handle manager
enum HandleIds
{
    HND_MAC = 0,
    HND_DIGEST,
    HND_KEY,
    HND_CIPHER,
    HND_AGREEMENT,
    HND_SIGNATURE,
    HND_MAX
};

// Allow at most this amount of clients; this can be adjusted but then we have to
// also increase the amount of dataports and the number of clients supported by
// the CAmkES macros..
#define CRYPTO_CLIENTS_MAX 8

static OS_Dataport_t ports[CRYPTO_CLIENTS_MAX] =
{
    OS_DATAPORT_ASSIGN(cryptoServer_port1),
    OS_DATAPORT_ASSIGN(cryptoServer_port2),
    OS_DATAPORT_ASSIGN(cryptoServer_port3),
    OS_DATAPORT_ASSIGN(cryptoServer_port4),
    OS_DATAPORT_ASSIGN(cryptoServer_port5),
    OS_DATAPORT_ASSIGN(cryptoServer_port6),
    OS_DATAPORT_ASSIGN(cryptoServer_port7),
    OS_DATAPORT_ASSIGN(cryptoServer_port8),
};

// Maximum length of keynames (excluding null terminator).
#define KEYSTORE_NAME_MAX_LEN 8

// Identify user of interface
seL4_Word cryptoServer_rpc_get_sender_id(
    void);

typedef struct
{
    OS_Keystore_Handle_t hKeystore;
    OS_Crypto_Handle_t hCrypto;
    size_t bytesWritten;
} CryptoServer_KeyStore_t;

typedef struct
{
    unsigned int cid;
    OS_Crypto_Handle_t hCrypto;
    char* handleMgrMem[HND_MAX];
    HandleMgr_t handleMgrs[HND_MAX];
    OS_Dataport_t* dataport;
    CryptoServer_KeyStore_t keys;
} CryptoServer_Client_t;

typedef struct
{
    CryptoServer_Client_t clients[CRYPTO_CLIENTS_MAX];
    OS_FileSystem_Handle_t hFs;
} CryptoServer_State_t;

// Here we keep track of all the respective contexts and the list of clients
// connected to the server
static CryptoServer_State_t serverState;

// Clients we have based on the amount of config data
static const size_t clients = sizeof(cryptoServer_config) /
                              sizeof(struct CryptoServer_ClientConfig);

// Private Functions -----------------------------------------------------------

static CryptoServer_Client_t*
getClient(
    seL4_Word cid)
{
    const int idx = CID_TO_IDX(cid);
    CryptoServer_Client_t* client;

    client = ((idx < 0) || (idx >= clients))
             ? NULL : (serverState.clients[idx].cid != cid)
             ? NULL : &serverState.clients[idx];

    return client;
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
    OS_FileSystem_Handle_t   hFs,
    const uint8_t            index,
    CryptoServer_KeyStore_t* ks)
{
    OS_Error_t err;
    char ksName[16];

    // We need an instance of the Crypto API for the keystore for hashing etc..
    if ((err = OS_Crypto_init(&ks->hCrypto, &cfgCrypto)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Crypto_init() failed with %d", err);
        return err;
    }

    // Every keystore needs its own instance name
    snprintf(ksName, sizeof(ksName), "kstore%02i", index);

    err = OS_KeystoreFile_init(
        &ks->hKeystore,
        hFs,
        ks->hCrypto,
        ksName);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Keystore_init() failed with %d", err);
        goto err0;
    }

    return OS_SUCCESS;

err0:
    OS_Crypto_free(ks->hCrypto);

    return err;
}

static inline OS_Error_t
initCrypto(
    CryptoServer_Client_t* client)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    int i = 0;

    for (; i < HND_MAX; i++)
    {
        size_t handleMgrMemSize =
            HandleMgr_SIZE_OF_BUFFER(
                cryptoServer_config.clients[CID_TO_IDX(client->cid)].handleMgrCapacity);
        client->handleMgrMem[i] = malloc(handleMgrMemSize);

        if (client->handleMgrMem[i] != NULL)
        {
            if ((err = HandleMgr_init(&client->handleMgrs[i],
                                      client->handleMgrMem[i],
                                      handleMgrMemSize,
                                      NULL)) != OS_SUCCESS)
            {
                free(client->handleMgrMem[i]);
                goto error;
            }
        }
        else
        {
            err = OS_ERROR_INSUFFICIENT_SPACE;
            goto error;
        }
    }
    return OS_Crypto_init(&client->hCrypto, &cfgCrypto);

error:
    for (i = i - 1; i >= 0; i--)
    {
        HandleMgr_free(&client->handleMgrs[i]);
        free(client->handleMgrMem[i]);
    }
    return err;
}

// -----------------------------------------------------------------------------

void
post_init()
{
    OS_Error_t err;
    CryptoServer_Client_t* client;

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

    for (uint8_t i = 0; i < clients; i++)
    {
        client = &serverState.clients[i];
        client->cid = IDX_TO_CID(i);

        // Set up an instance of the Crypto API for each client which is then
        // accessed via its RPC interface; every client has its own dataport.
        client->dataport = &ports[i];
        if (OS_Dataport_isUnset(*client->dataport))
        {
            Debug_LOG_ERROR("Dataport of client ID %u is unset", client->cid);
            return;
        }
        // Init client's Crypto API instance and list of handles
        if ((err = initCrypto(client)) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("initCrypto() failed with %d", err);
            return;
        }
        // Init client's keystore
        if ((err = initKeyStore(serverState.hFs, i, &client->keys)) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("initKeyStore() failed with %d", err);
            return;
        }
    }
}

// Extra if_CryptoServer interface functions -----------------------------------

OS_Error_t
cryptoServer_rpc_loadKey(
    OS_CryptoKey_Handle_t* pKeyHandle,
    seL4_Word              ownerId,
    const char*            name)
{
    OS_Error_t err;
    CryptoServer_Client_t* client, *owner;
    OS_CryptoKey_Data_t data;
    size_t dataLen = sizeof(data), i;
    bool isAllowed;

    GET_CLIENT(owner,  ownerId);
    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(strnlen(name, KEYSTORE_NAME_MAX_LEN), 1,
                                   KEYSTORE_NAME_MAX_LEN);

    // Go through list of owner's allowedIDs to check if the ID that is requesting
    // access is part of his list
    for (i = 0, isAllowed = false; i < clients && !isAllowed; i++)
    {
        isAllowed = (cryptoServer_config.clients[CID_TO_IDX(owner->cid)].allowedIds[i] ==
                     client->cid);
    }
    if (!isAllowed)
    {
        Debug_LOG_WARNING("Client with client ID %u failed to access the keystore " \
                          "of client ID %u", client->cid, owner->cid);
        return OS_ERROR_ACCESS_DENIED;
    }

    // Here we access the data stored for another client; however, since all
    // RPC calls are serialized, we cannot have a race-condition because there
    // is only one RPC client active at a time.
    if ((err = OS_Keystore_loadKey(owner->keys.hKeystore, name, &data,
                                   &dataLen)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Keystore_loadKey() failed with %d", err);
        return err;
    }

    return HandleMgr_addOnSuccess(
               &client->handleMgrs[HND_KEY],
               OS_CryptoKey_import(
                   pKeyHandle,
                   client->hCrypto,
                   &data),
               (HandleMgr_Handle_t*) pKeyHandle);
}

OS_Error_t
cryptoServer_rpc_storeKey(
    OS_CryptoKey_Handle_t keyHandle,
    const char*           name)
{
    OS_Error_t err;
    OS_CryptoKey_Data_t data;
    CryptoServer_Client_t* client;
    size_t limit;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(strlen(name), 1, KEYSTORE_NAME_MAX_LEN);

    // We already get a key handle that belongs to our own proxy object,
    // so we can use it straight-forward.
    if ((err = OS_CryptoKey_export(keyHandle, &data)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_CryptoKey_export() failed with %u", err);
        return err;
    }

    // Check if we are about to exceed the storage limit for this keystore
    limit = cryptoServer_config.clients[CID_TO_IDX(client->cid)].storageLimit;
    if (client->keys.bytesWritten + sizeof(data) > limit)
    {
        Debug_LOG_ERROR("Client with client ID %u has reached storage limit of %zd "
                        "bytes", client->cid, limit);
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    // Store key in keystore
    if ((err = OS_Keystore_storeKey(client->keys.hKeystore, name, &data,
                                    sizeof(data))) == OS_SUCCESS)
    {
        client->keys.bytesWritten += sizeof(data);
    }
    else
    {
        Debug_LOG_ERROR("OS_Keystore_storeKey() failed with %u", err);
    }

    return err;
}

// if_OS_Crypto interface functions --------------------------------------------

OS_Error_t
cryptoServer_rpc_Rng_getBytes(
    unsigned int flags,
    size_t       bufSize)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(bufSize, 0,
                                   OS_Dataport_getSize(*client->dataport));

    return OS_CryptoRng_getBytes(
               client->hCrypto,
               flags,
               OS_Dataport_getBuf(*client->dataport),
               bufSize);
}

OS_Error_t
cryptoServer_rpc_Rng_reseed(
    size_t seedSize)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(seedSize, 0,
                                   OS_Dataport_getSize(*client->dataport));

    return OS_CryptoRng_reseed(
               client->hCrypto,
               OS_Dataport_getBuf(*client->dataport),
               seedSize);
}

OS_Error_t
cryptoServer_rpc_Mac_init(
    OS_CryptoMac_Handle_t* pMacHandle,
    OS_CryptoKey_Handle_t  keyHandle,
    unsigned int           algorithm)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return HandleMgr_addOnSuccess(
               &client->handleMgrs[HND_MAC],
               OS_CryptoMac_init(
                   pMacHandle,
                   client->hCrypto,
                   HandleMgr_validate(
                       &client->handleMgrs[HND_KEY],
                       keyHandle),
                   algorithm),
               (HandleMgr_Handle_t*) pMacHandle);
}

OS_Error_t
cryptoServer_rpc_Mac_free(
    OS_CryptoMac_Handle_t macHandle)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return HandleMgr_removeOnSuccess(
               &client->handleMgrs[HND_MAC],
               OS_CryptoMac_free(
                   HandleMgr_validate(
                       &client->handleMgrs[HND_MAC],
                       macHandle)),
               macHandle);
}

OS_Error_t
cryptoServer_rpc_Mac_process(
    OS_CryptoMac_Handle_t macHandle,
    size_t                dataSize)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(dataSize, 0,
                                   OS_Dataport_getSize(*client->dataport));

    return OS_CryptoMac_process(
               HandleMgr_validate(
                   &client->handleMgrs[HND_MAC],
                   macHandle),
               OS_Dataport_getBuf(*client->dataport),
               dataSize);
}

OS_Error_t
cryptoServer_rpc_Mac_finalize(
    OS_CryptoMac_Handle_t macHandle,
    size_t*               macSize)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(*macSize, 0,
                                   OS_Dataport_getSize(*client->dataport));

    return OS_CryptoMac_finalize(
               HandleMgr_validate(
                   &client->handleMgrs[HND_MAC],
                   macHandle),
               OS_Dataport_getBuf(*client->dataport),
               macSize);
}

OS_Error_t
cryptoServer_rpc_Digest_init(
    OS_CryptoDigest_Handle_t* pDigestHandle,
    unsigned int              algorithm)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return HandleMgr_addOnSuccess(
               &client->handleMgrs[HND_DIGEST],
               OS_CryptoDigest_init(
                   pDigestHandle,
                   client->hCrypto,
                   algorithm),
               (HandleMgr_Handle_t*) pDigestHandle);
}

OS_Error_t
cryptoServer_rpc_Digest_free(
    OS_CryptoDigest_Handle_t digestHandle)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return HandleMgr_removeOnSuccess(
               &client->handleMgrs[HND_DIGEST],
               OS_CryptoDigest_free(
                   HandleMgr_validate(
                       &client->handleMgrs[HND_DIGEST],
                       digestHandle)),
               digestHandle);
}

OS_Error_t
cryptoServer_rpc_Digest_clone(
    OS_CryptoDigest_Handle_t* pDigestHandle,
    OS_CryptoDigest_Handle_t  srcDigestHandle)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return HandleMgr_addOnSuccess(
               &client->handleMgrs[HND_DIGEST],
               OS_CryptoDigest_clone(
                   pDigestHandle,
                   client->hCrypto,
                   HandleMgr_validate(
                       &client->handleMgrs[HND_DIGEST],
                       srcDigestHandle)),
               (HandleMgr_Handle_t*) pDigestHandle);
}

OS_Error_t
cryptoServer_rpc_Digest_process(
    OS_CryptoDigest_Handle_t digestHandle,
    size_t                   inSize)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(inSize, 0,
                                   OS_Dataport_getSize(*client->dataport));

    return OS_CryptoDigest_process(
               HandleMgr_validate(
                   &client->handleMgrs[HND_DIGEST],
                   digestHandle),
               OS_Dataport_getBuf(*client->dataport),
               inSize);
}

OS_Error_t
cryptoServer_rpc_Digest_finalize(
    OS_CryptoDigest_Handle_t digestHandle,
    size_t*                  digestSize)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(*digestSize, 0,
                                   OS_Dataport_getSize(*client->dataport));

    return OS_CryptoDigest_finalize(
               HandleMgr_validate(
                   &client->handleMgrs[HND_DIGEST],
                   digestHandle),
               OS_Dataport_getBuf(*client->dataport),
               digestSize);
}

OS_Error_t
cryptoServer_rpc_Key_generate(
    OS_CryptoKey_Handle_t* pKeyHandle)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return HandleMgr_addOnSuccess(
               &client->handleMgrs[HND_KEY],
               OS_CryptoKey_generate(
                   pKeyHandle,
                   client->hCrypto,
                   OS_Dataport_getBuf(*client->dataport)),
               (HandleMgr_Handle_t*) pKeyHandle);
}

OS_Error_t
cryptoServer_rpc_Key_makePublic(
    OS_CryptoKey_Handle_t* pPubKeyHandle,
    OS_CryptoKey_Handle_t  prvKeyHandle)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return HandleMgr_addOnSuccess(
               &client->handleMgrs[HND_KEY],
               OS_CryptoKey_makePublic(
                   pPubKeyHandle,
                   client->hCrypto,
                   HandleMgr_validate(
                       &client->handleMgrs[HND_KEY],
                       prvKeyHandle),
                   OS_Dataport_getBuf(*client->dataport)),
               (HandleMgr_Handle_t*) pPubKeyHandle);
}

OS_Error_t
cryptoServer_rpc_Key_import(
    OS_CryptoKey_Handle_t* pKeyHandle)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return HandleMgr_addOnSuccess(
               &client->handleMgrs[HND_KEY],
               OS_CryptoKey_import(
                   pKeyHandle,
                   client->hCrypto,
                   OS_Dataport_getBuf(*client->dataport)),
               (HandleMgr_Handle_t*) pKeyHandle);
}

OS_Error_t
cryptoServer_rpc_Key_export(
    OS_CryptoKey_Handle_t keyHandle)
{
    // The CryptoServer does not allow ANY kind of export; a key that is in the
    // CryptoServer (either via import or generation) will never leave it.
    return OS_ERROR_OPERATION_DENIED;
}

OS_Error_t
cryptoServer_rpc_Key_getParams(
    OS_CryptoKey_Handle_t keyHandle,
    size_t*               paramSize)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(*paramSize, 0,
                                   OS_Dataport_getSize(*client->dataport));

    return OS_CryptoKey_getParams(
               HandleMgr_validate(
                   &client->handleMgrs[HND_KEY],
                   keyHandle),
               OS_Dataport_getBuf(*client->dataport),
               paramSize);
}

OS_Error_t
cryptoServer_rpc_Key_getAttribs(
    OS_CryptoKey_Handle_t keyHandle)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return OS_CryptoKey_getAttribs(
               HandleMgr_validate(
                   &client->handleMgrs[HND_KEY],
                   keyHandle),
               OS_Dataport_getBuf(*client->dataport));
}

OS_Error_t
cryptoServer_rpc_Key_loadParams(
    OS_CryptoKey_Param_t param,
    size_t*              paramSize)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(*paramSize, 0,
                                   OS_Dataport_getSize(*client->dataport));

    return OS_CryptoKey_loadParams(
               client->hCrypto,
               param,
               OS_Dataport_getBuf(*client->dataport),
               paramSize);
}

OS_Error_t
cryptoServer_rpc_Key_free(
    OS_CryptoKey_Handle_t keyHandle)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return HandleMgr_removeOnSuccess(
               &client->handleMgrs[HND_KEY],
               OS_CryptoKey_free(
                   HandleMgr_validate(
                       &client->handleMgrs[HND_KEY],
                       keyHandle)),
               keyHandle);
}

OS_Error_t
cryptoServer_rpc_Agreement_init(
    OS_CryptoAgreement_Handle_t* pAgrHandle,
    OS_CryptoKey_Handle_t        prvKeyHandle,
    OS_CryptoAgreement_Alg_t     algorithm)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return HandleMgr_addOnSuccess(
               &client->handleMgrs[HND_AGREEMENT],
               OS_CryptoAgreement_init(
                   pAgrHandle,
                   client->hCrypto,
                   HandleMgr_validate(
                       &client->handleMgrs[HND_KEY],
                       prvKeyHandle),
                   algorithm),
               (HandleMgr_Handle_t*) pAgrHandle);
}

OS_Error_t
cryptoServer_rpc_Agreement_agree(
    OS_CryptoAgreement_Handle_t agrHandle,
    OS_CryptoKey_Handle_t       pubKeyHandle,
    size_t*                     sharedSize)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(*sharedSize, 0,
                                   OS_Dataport_getSize(*client->dataport));

    return OS_CryptoAgreement_agree(
               HandleMgr_validate(
                   &client->handleMgrs[HND_AGREEMENT],
                   agrHandle),
               HandleMgr_validate(
                   &client->handleMgrs[HND_KEY],
                   pubKeyHandle),
               OS_Dataport_getBuf(*client->dataport),
               sharedSize);
}

OS_Error_t
cryptoServer_rpc_Agreement_free(
    OS_CryptoAgreement_Handle_t agrHandle)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return HandleMgr_removeOnSuccess(
               &client->handleMgrs[HND_AGREEMENT],
               OS_CryptoAgreement_free(
                   HandleMgr_validate(
                       &client->handleMgrs[HND_AGREEMENT],
                       agrHandle)),
               agrHandle);
}

OS_Error_t
cryptoServer_rpc_Signature_init(
    OS_CryptoSignature_Handle_t* pSigHandle,
    OS_CryptoKey_Handle_t        prvKeyHandle,
    OS_CryptoKey_Handle_t        pubKeyHandle,
    unsigned int                 algorithm,
    unsigned int                 digest)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return HandleMgr_addOnSuccess(
               &client->handleMgrs[HND_SIGNATURE],
               OS_CryptoSignature_init(
                   pSigHandle,
                   client->hCrypto,
                   HandleMgr_validate(
                       &client->handleMgrs[HND_KEY],
                       prvKeyHandle),
                   HandleMgr_validate(
                       &client->handleMgrs[HND_KEY],
                       pubKeyHandle),
                   algorithm,
                   digest),
               (HandleMgr_Handle_t*) pSigHandle);
}

OS_Error_t
cryptoServer_rpc_Signature_verify(
    OS_CryptoSignature_Handle_t sigHandle,
    size_t                      hashSize,
    size_t                      signatureSize)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(signatureSize + hashSize, 0,
                                   OS_Dataport_getSize(*client->dataport));

    return OS_CryptoSignature_verify(
               HandleMgr_validate(
                   &client->handleMgrs[HND_SIGNATURE],
                   sigHandle),
               OS_Dataport_getBuf(*client->dataport),
               hashSize,
               OS_Dataport_getBuf(*client->dataport) + hashSize,
               signatureSize);
}

OS_Error_t
cryptoServer_rpc_Signature_sign(
    OS_CryptoSignature_Handle_t sigHandle,
    size_t                      hashSize,
    size_t*                     signatureSize)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(hashSize, 0,
                                   OS_Dataport_getSize(*client->dataport));
    CHECK_VALUE_IN_CLOSED_INTERVAL(*signatureSize, 0,
                                   OS_Dataport_getSize(*client->dataport));

    return OS_CryptoSignature_sign(
               HandleMgr_validate(
                   &client->handleMgrs[HND_SIGNATURE],
                   sigHandle),
               OS_Dataport_getBuf(*client->dataport),
               hashSize,
               OS_Dataport_getBuf(*client->dataport),
               signatureSize);
}

OS_Error_t
cryptoServer_rpc_Signature_free(
    OS_CryptoSignature_Handle_t sigHandle)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return HandleMgr_removeOnSuccess(
               &client->handleMgrs[HND_SIGNATURE],
               OS_CryptoSignature_free(
                   HandleMgr_validate(
                       &client->handleMgrs[HND_SIGNATURE],
                       sigHandle)),
               sigHandle);
}

OS_Error_t
cryptoServer_rpc_Cipher_init(
    OS_CryptoCipher_Handle_t* pCipherHandle,
    OS_CryptoKey_Handle_t     keyHandle,
    unsigned int              algorithm,
    size_t                    ivSize)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(ivSize, 0,
                                   OS_Dataport_getSize(*client->dataport));

    return HandleMgr_addOnSuccess(
               &client->handleMgrs[HND_CIPHER],
               OS_CryptoCipher_init(
                   pCipherHandle,
                   client->hCrypto,
                   HandleMgr_validate(
                       &client->handleMgrs[HND_KEY],
                       keyHandle),
                   algorithm,
                   OS_Dataport_getBuf(*client->dataport),
                   ivSize),
               (HandleMgr_Handle_t*) pCipherHandle);
}

OS_Error_t
cryptoServer_rpc_Cipher_free(
    OS_CryptoCipher_Handle_t cipherHandle)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return HandleMgr_removeOnSuccess(
               &client->handleMgrs[HND_CIPHER],
               OS_CryptoCipher_free(
                   HandleMgr_validate(
                       &client->handleMgrs[HND_CIPHER],
                       cipherHandle)),
               cipherHandle);
}

OS_Error_t
cryptoServer_rpc_Cipher_process(
    OS_CryptoCipher_Handle_t cipherHandle,
    size_t                   inputSize,
    size_t*                  outputSize)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(inputSize, 0,
                                   OS_Dataport_getSize(*client->dataport));
    CHECK_VALUE_IN_CLOSED_INTERVAL(*outputSize, 0,
                                   OS_Dataport_getSize(*client->dataport));

    return OS_CryptoCipher_process(
               HandleMgr_validate(
                   &client->handleMgrs[HND_CIPHER],
                   cipherHandle),
               OS_Dataport_getBuf(*client->dataport),
               inputSize,
               OS_Dataport_getBuf(*client->dataport),
               outputSize);
}

OS_Error_t
cryptoServer_rpc_Cipher_start(
    OS_CryptoCipher_Handle_t cipherHandle,
    size_t                   len)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    return OS_CryptoCipher_start(
               HandleMgr_validate(
                   &client->handleMgrs[HND_CIPHER],
                   cipherHandle),
               OS_Dataport_getBuf(*client->dataport),
               len);
}

OS_Error_t
cryptoServer_rpc_Cipher_finalize(
    OS_CryptoCipher_Handle_t cipherHandle,
    size_t*                  tagSize)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(*tagSize, 0,
                                   OS_Dataport_getSize(*client->dataport));

    return OS_CryptoCipher_finalize(
               HandleMgr_validate(
                   &client->handleMgrs[HND_CIPHER],
                   cipherHandle),
               OS_Dataport_getBuf(*client->dataport),
               tagSize);
}
