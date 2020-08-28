/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

// OS includes
#include "OS_FileSystem.h"
#include "OS_Crypto.h"
#include "OS_Keystore.h"

#include "LibDebug/Debug.h"
#include "LibHandle/HandleMgr.h"

#include <string.h>

#include <camkes.h>

// Get a client when called via RPC
#define GET_CLIENT(cli, cid)                                            \
    if ((cli = getClient(cid)) == NULL)                                 \
    {                                                                   \
        Debug_LOG_ERROR("Could not get corresponding client state");    \
        return OS_ERROR_NOT_FOUND;                                      \
    }
// Check a buffer size against a client's dataport size
#define CHK_SIZE(cli, sz)                                       \
    if (sz > OS_Dataport_getSize(*cli->dataport)) {             \
        Debug_LOG_ERROR("Requested size too big for dataport"); \
        return OS_ERROR_INVALID_PARAMETER;                      \
    }

// Config for FileSystem API
static const OS_FileSystem_Config_t cfgFs =
{
    .type = OS_FileSystem_Type_FATFS,
    .size = OS_FileSystem_STORAGE_MAX,
    .storage = IF_OS_STORAGE_ASSIGN(
        storage_rpc,
        storage_port),
};
static const OS_Crypto_Config_t cfgCrypto =
{
    .mode = OS_Crypto_MODE_LIBRARY_ONLY,
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

// Maximum length of keynames
#define KEYSTORE_NAME_MAX 8

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
    unsigned int id;
    OS_Crypto_Handle_t hCrypto;
    HandleMgr_t* handleMgr;
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
    seL4_Word id)
{
    CryptoServer_Client_t* client;

    client = (id > clients) || (id <= 0) ? NULL :
             (serverState.clients[id - 1].id != id) ? NULL :
             &serverState.clients[id - 1];

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

static OS_Error_t
initCrypto(
    OS_Crypto_Handle_t* hCrypto,
    HandleMgr_t**       handleMgr)
{
    OS_Error_t err;

    if ((err = HandleMgr_init(handleMgr, HND_MAX)) != OS_SUCCESS)
    {
        return err;
    }

    return OS_Crypto_init(hCrypto, &cfgCrypto);
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
        client->id = i + 1;

        // Set up an instance of the Crypto API for each client which is then
        // accessed via its RPC interface; every client has its own dataport.
        client->dataport = &ports[clients - i - 1];
        if (OS_Dataport_isUnset(*client->dataport))
        {
            Debug_LOG_ERROR("Dataport %i is unset, it should be connected "
                            "to the respective client", i + 1);
            return;
        }
        // Init client's Crypto API instance and list of handles
        if ((err = initCrypto(&client->hCrypto, &client->handleMgr)) != OS_SUCCESS)
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
    CryptoLib_Object_ptr* ptr,
    seL4_Word             ownerId,
    const char*           name)
{
    OS_Error_t err;
    CryptoServer_Client_t* client, *owner;
    OS_CryptoKey_Data_t data;
    size_t dataLen = sizeof(data), i;
    bool isAllowed;
    OS_CryptoKey_Handle_t hMyKey;

    GET_CLIENT(owner,  ownerId);
    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    if (strlen(name) == 0 || strlen(name) > KEYSTORE_NAME_MAX)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    // Go through list of owner's allowedIDs to check if the ID that is requesting
    // access is part of his list
    for (i = 0, isAllowed = false; i < clients && !isAllowed; i++)
    {
        isAllowed = (cryptoServer_config.clients[owner->id - 1].allowedIds[i] ==
                     client->id);
    }
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
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());

    if (strlen(name) == 0 || strlen(name) > KEYSTORE_NAME_MAX)
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
        cryptoServer_config.clients[client->id - 1].storageLimit)
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

// if_OS_Crypto interface functions --------------------------------------------

OS_Error_t
cryptoServer_rpc_Rng_getBytes(
    unsigned int flags,
    size_t       bufSize)
{
    CryptoServer_Client_t* client;

    GET_CLIENT(client, cryptoServer_rpc_get_sender_id());
    CHK_SIZE(client, bufSize);

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
    CHK_SIZE(client, seedSize);

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
               client->handleMgr,
               HND_MAC,
               OS_CryptoMac_init(
                   pMacHandle,
                   client->hCrypto,
                   HandleMgr_validate(
                       client->handleMgr,
                       HND_KEY,
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
               client->handleMgr,
               HND_MAC,
               OS_CryptoMac_free(
                   HandleMgr_validate(
                       client->handleMgr,
                       HND_MAC,
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
    CHK_SIZE(client, dataSize);

    return OS_CryptoMac_process(
               HandleMgr_validate(
                   client->handleMgr,
                   HND_MAC,
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
    CHK_SIZE(client, *macSize);

    return OS_CryptoMac_finalize(
               HandleMgr_validate(
                   client->handleMgr,
                   HND_MAC,
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
               client->handleMgr,
               HND_DIGEST,
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
               client->handleMgr,
               HND_DIGEST,
               OS_CryptoDigest_free(
                   HandleMgr_validate(
                       client->handleMgr,
                       HND_DIGEST,
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
               client->handleMgr,
               HND_DIGEST,
               OS_CryptoDigest_clone(
                   pDigestHandle,
                   client->hCrypto,
                   HandleMgr_validate(
                       client->handleMgr,
                       HND_DIGEST,
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
    CHK_SIZE(client, inSize);

    return OS_CryptoDigest_process(
               HandleMgr_validate(
                   client->handleMgr,
                   HND_DIGEST,
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
    CHK_SIZE(client, *digestSize);

    return OS_CryptoDigest_finalize(
               HandleMgr_validate(
                   client->handleMgr,
                   HND_DIGEST,
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
               client->handleMgr,
               HND_KEY,
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
               client->handleMgr,
               HND_KEY,
               OS_CryptoKey_makePublic(
                   pPubKeyHandle,
                   client->hCrypto,
                   HandleMgr_validate(
                       client->handleMgr,
                       HND_KEY,
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
               client->handleMgr,
               HND_KEY,
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
    CHK_SIZE(client, *paramSize);

    return OS_CryptoKey_getParams(
               HandleMgr_validate(
                   client->handleMgr,
                   HND_KEY,
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
                   client->handleMgr,
                   HND_KEY,
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
    CHK_SIZE(client, *paramSize);

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
               client->handleMgr,
               HND_KEY,
               OS_CryptoKey_free(
                   HandleMgr_validate(
                       client->handleMgr,
                       HND_KEY,
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
               client->handleMgr,
               HND_AGREEMENT,
               OS_CryptoAgreement_init(
                   pAgrHandle,
                   client->hCrypto,
                   HandleMgr_validate(
                       client->handleMgr,
                       HND_KEY,
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
    CHK_SIZE(client, *sharedSize);

    return OS_CryptoAgreement_agree(
               HandleMgr_validate(
                   client->handleMgr,
                   HND_AGREEMENT,
                   agrHandle),
               HandleMgr_validate(
                   client->handleMgr,
                   HND_KEY,
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
               client->handleMgr,
               HND_AGREEMENT,
               OS_CryptoAgreement_free(
                   HandleMgr_validate(
                       client->handleMgr,
                       HND_AGREEMENT,
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
               client->handleMgr,
               HND_SIGNATURE,
               OS_CryptoSignature_init(
                   pSigHandle,
                   client->hCrypto,
                   HandleMgr_validate(
                       client->handleMgr,
                       HND_KEY,
                       prvKeyHandle),
                   HandleMgr_validate(
                       client->handleMgr,
                       HND_KEY,
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
    CHK_SIZE(client, hashSize + signatureSize);

    return OS_CryptoSignature_verify(
               HandleMgr_validate(
                   client->handleMgr,
                   HND_SIGNATURE,
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
    CHK_SIZE(client, hashSize);
    CHK_SIZE(client, *signatureSize);

    return OS_CryptoSignature_sign(
               HandleMgr_validate(
                   client->handleMgr,
                   HND_SIGNATURE,
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
               client->handleMgr,
               HND_SIGNATURE,
               OS_CryptoSignature_free(
                   HandleMgr_validate(
                       client->handleMgr,
                       HND_SIGNATURE,
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
    CHK_SIZE(client, ivSize);

    return HandleMgr_addOnSuccess(
               client->handleMgr,
               HND_CIPHER,
               OS_CryptoCipher_init(
                   pCipherHandle,
                   client->hCrypto,
                   HandleMgr_validate(
                       client->handleMgr,
                       HND_KEY,
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
               client->handleMgr,
               HND_CIPHER,
               OS_CryptoCipher_free(
                   HandleMgr_validate(
                       client->handleMgr,
                       HND_CIPHER,
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
    CHK_SIZE(client, inputSize);
    CHK_SIZE(client, *outputSize);

    return OS_CryptoCipher_process(
               HandleMgr_validate(
                   client->handleMgr,
                   HND_CIPHER,
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
                   client->handleMgr,
                   HND_CIPHER,
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
    CHK_SIZE(client, *tagSize);

    return OS_CryptoCipher_finalize(
               HandleMgr_validate(
                   client->handleMgr,
                   HND_CIPHER,
                   cipherHandle),
               OS_Dataport_getBuf(*client->dataport),
               tagSize);
}