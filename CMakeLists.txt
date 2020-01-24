cmake_minimum_required(VERSION 3.7.2)

seos_use_libs(
    SEOS_LIBS
    SEOS_LIBS_LOGGER
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

set(SEOS_FS_CONFIG_H_FILE_FAT ${CMAKE_CURRENT_LIST_DIR}/config/seos_fs_config.h)
set(SEOS_PM_CONFIG_H_FILE_FAT ${CMAKE_CURRENT_LIST_DIR}/config/seos_pm_config.h)

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
        -DSEOS_FS_CONFIG_H_FILE=${SEOS_FS_CONFIG_H_FILE_FAT}
        -DSEOS_FS_BUILD_AS_LIB
        # partition manager
        -DSEOS_PM_CONFIG_H_FILE=${SEOS_PM_CONFIG_H_FILE_FAT}
        -DSEOS_PARTITION_MANAGER_BUILD_AS_LIB
        -DFAT_FS
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