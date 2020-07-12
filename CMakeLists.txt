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
#     component instance name. The server will be called "<name>" and the
#     corresponding client library will be called "<name>_client"
#
function(DeclareCAmkESComponent_CryptoServer
    name
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
            os_core_api
            os_libs
            os_crypto_with_rpc_server
            # all settings blow are for the keystore, there is still a lot of
            # re-work needed to streamline this. We should not need ChanMux or
            # the partition manager here, all we need is an NVM interace to
            # access a raw partition
            proxy_nvm
            os_partition_manager
            os_filesystem_core
            os_filesystem_fat
            os_filesystem_spiffs # unused, but needed by os_filesystem_core
            os_keystore
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
            os_crypto_with_rpc_client
    )

endfunction()
