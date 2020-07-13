#
# Crypto Server CAmkES Component
#
# Copyright (C) 2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

# we cannot use CMAKE_CURRENT_LIST_DIR in a function or macro, because that
# would give us the dir of the file that is invoking the macro. The work around
# is that we create a global (ie cached and flagged as internal) variable here
# and then use it in the macro below. As a convenient side effect we don't
# require anybody else to provide any helper variables, this CMake file becomes
# fully self-contained and "copy&paste safe".
set(
    OS_COMPONENT_CryptoServer_DIR
    "${CMAKE_CURRENT_LIST_DIR}"
    CACHE INTERNAL ""
)


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
        SOURCES
            ${OS_COMPONENT_CryptoServer_DIR}/src/CryptoServer.c
        C_FLAGS
            -Wall
            -Werror
        LIBS
            os_core_api
            os_libs
            os_crypto_with_rpc_server
            os_filesystem
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
            ${OS_COMPONENT_CryptoServer_DIR}/inc
    )

    target_link_libraries(${PROJECT_NAME}
        INTERFACE
            os_crypto_with_rpc_client
    )

endfunction()
