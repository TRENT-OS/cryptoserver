#
# Crypto Server CAmkES Component
#
# Copyright (C) 2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

#-------------------------------------------------------------------------------
# we can't use CMAKE_CURRENT_LIST_DIR in a function/macro, because that will
# give us the dir of the file that is invoking the function/macro. Until we
# have CmMake 3.17 which provides CMAKE_CURRENT_FUNCTION_LIST_DIR, the work
# around is creating a global variable here with the directory and then use
# this in the function below.
set(COMPONENT_CryptoServer_DIR ${CMAKE_CURRENT_LIST_DIR})


#-------------------------------------------------------------------------------
#
# Declare Crypto Server CAmkES Component
#
# Parameters:
#
#   <name>
#     required, component instance name
#
function(DeclareCAmkESComponent_CryptoServer name)

    os_use_libs(
        OS_LIBS
        OS_CRYPTO_WITH_RPC_SERVER
        OS_CRYPTO_WITH_RPC_CLIENT
        # all setting blow are for the keystore, there it still a lot of
        # re-work needed to streamline this. We should not need ChanMux or the
        # partition manager here, all we need is an NVM interace to access a
        # raw PARTITION
        OS_CHANMUX
        OS_PARTITION_MANAGER
        OS_FILESYSTEM_CORE
        OS_FILESYSTEM_FAT
        OS_FILESYSTEM_SPIFFS # unused, but needed by SEOS_FILESYSTEM_CORE
        OS_KEYSTORE
    )

    #---------------------------------------------------------------------------
    DeclareCAmkESComponent(${name}
        INCLUDES
            # we state this folder explicitly and don't put CryptoServer_client
            # into the libs, because it's semantically broken when the server
            # uses the client lib.
            ${COMPONENT_CryptoServer_DIR}/inc
        SOURCES
            ${COMPONENT_CryptoServer_DIR}/src/CryptoServer.c
        C_FLAGS
            -Wall -Werror
            -DOS_FS_BUILD_AS_LIB
            -DOS_PARTITION_MANAGER_BUILD_AS_LIB
        LIBS
            seos_core_api
            seos_libs
            seos_crypto_with_rpc_server
            # all setting blow are for the keystore, there it still a lot of
            # re-work needed to streamline this. We should not need ChanMux or
            # the partition manager here, all we need is an NVM interace to
            # access a raw partition
            proxy_nvm
            seos_partition_manager
            seos_filesystem_core
            seos_filesystem_fat
            seos_filesystem_spiffs # unused, but needed by seos_filesystem_core
            seos_keystore
    )

    #---------------------------------------------------------------------------
    # create the corresponding client project, which every client of this
    # Crypto server instance must include. We do not define this globally,
    # because the clients may have server specific configurations in the
    # future.
    project(${name}_client C)

    add_library(${PROJECT_NAME} INTERFACE)

    target_include_directories(${PROJECT_NAME}
        INTERFACE
            ${COMPONENT_CryptoServer_DIR}/inc
    )

    target_link_libraries(${PROJECT_NAME}
        INTERFACE
            seos_crypto_with_rpc_client
    )

endfunction()
