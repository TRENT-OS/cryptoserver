cmake_minimum_required(VERSION 3.7.2)

os_use_libs(
    OS_LIBS
    OS_CHANMUX
    OS_CRYPTO_WITH_RPC_SERVER
    OS_PARTITION_MANAGER
    OS_FILESYSTEM_CORE
    OS_FILESYSTEM_FAT
    OS_KEYSTORE
    # TODO: SPIFFS is not used, but still this is needed to compile stuff
    #       from fs-core
    OS_FILESYSTEM_SPIFFS
)

project(cryptoserver C)

DeclareCAmkESComponent(CryptoServer
    INCLUDES
        inc
    SOURCES
        src/CryptoServer.c
    C_FLAGS
        -Wall -Werror
        # filesystem
        -DOS_FS_BUILD_AS_LIB
        # partition manager
        -DOS_PARTITION_MANAGER_BUILD_AS_LIB
    LIBS
        seos_core_api
        seos_libs
        chanmux_client
        proxy_nvm
        seos_crypto_with_rpc_server
        seos_filesystem_fat
        seos_partition_manager
        seos_filesystem_core
        seos_keystore
        # TODO: SPIFFS is not used, but still this is needed to compile stuff
        #       from fs-core
        seos_filesystem_spiffs
)
