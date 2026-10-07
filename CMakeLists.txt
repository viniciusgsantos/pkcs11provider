cmake_minimum_required (VERSION 3.18)
project (pkcs11provider)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_subdirectory(src)
include_directories(include)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -z defs")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -z defs")

set(PROJECT_SOVERSION "0")
set(PROJECT_VERSION "0.0.1")

add_library(${PROJECT_NAME} SHARED ${SRC_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION ${PROJECT_SOVERSION})
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION})
# Don't change or remove it. For total compatibility the OpenSSL standard, we must use C99.
set_target_properties(${PROJECT_NAME} PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

find_package(OpenSSL 3.0.0 REQUIRED)

target_link_libraries (${PROJECT_NAME}
    OpenSSL::SSL
    ${CMAKE_DL_LIBS}
)
