cmake_minimum_required (VERSION 3.18)
project (pkcs11provider)

find_package(OpenSSL 3.0.0 REQUIRED)

set(PROJECT_SOVERSION "0")
set(PROJECT_VERSION "0.0.1")

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -z defs")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -z defs")

add_subdirectory(src)
include_directories(include)

add_library(${PROJECT_NAME} SHARED ${SRC_FILES})

set_target_properties(${PROJECT_NAME} PROPERTIES 
    SOVERSION ${PROJECT_SOVERSION}
    VERSION ${PROJECT_VERSION}
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)

target_link_libraries (${PROJECT_NAME}
    PRIVATE
        OpenSSL::Crypto
        ${CMAKE_DL_LIBS}
)

include(GNUInstallDirs)

install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

cmake_policy(SET CMP0135 NEW)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/063de7e9578f82b369302001269680b4b1553359.zip
)

FetchContent_MakeAvailable(googletest)

enable_testing()

add_subdirectory(tests)
