cmake_minimum_required(VERSION 3.7.2)

seos_use_libs(
    SEOS_LIBS
    SEOS_CRYPTO_WITH_RPC_SERVER
    SEOS_CRYPTO_IMPL_MBEDTLS
    SEOS_PARTITION_MANAGER
    SEOS_FILESYSTEM_CORE
    SEOS_FILESYSTEM_FAT
    SEOS_KEYSTORE
    # TODO: SPIFFS is not used, but still this is needed to compile stuff
    #       from fs-core
    SEOS_FILESYSTEM_SPIFFS
)

set(KEYSTORE_AS_COMPONENT ON CACHE BOOL "string")

project(cryptoserver C)

DeclareCAmkESComponent(CryptoServer
    INCLUDES
        src
    SOURCES
        src/CryptoServer.c
    C_FLAGS
        -Wall -Werror
        # filesystem
        -DSEOS_FS_BUILD_AS_LIB
        # partition manager
        -DSEOS_PARTITION_MANAGER_BUILD_AS_LIB
    LIBS
        seos_core_api
        seos_libs
        seos_crypto_with_rpc_server
        seos_filesystem_fat
        seos_partition_manager
        seos_filesystem_core
        seos_keystore
        # TODO: SPIFFS is not used, but still this is needed to compile stuff
        #       from fs-core
        seos_filesystem_spiffs
)