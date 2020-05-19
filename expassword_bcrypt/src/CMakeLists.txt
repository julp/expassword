cmake_minimum_required(VERSION 2.8.3)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})

find_program(ERL_EXECUTABLE erl)
if(NOT ERL_EXECUTABLE)
    message(FATAL_ERROR "could not find erl program")
endif(NOT ERL_EXECUTABLE)

execute_process(
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND erl -noshell -eval "io:format(\"~s\", [code:root_dir()])" -s erlang halt
    OUTPUT_VARIABLE ERL_ROOT
)

find_path(NIF_INCLUDE_DIR "erl_nif.h"
    PATHS "${ERL_ROOT}"
    PATH_SUFFIXES "/usr/include/"
)

set(OPTIONAL_SOURCES )
include(CheckFunctionExists)
check_function_exists("explicit_bzero" HAVE_EXPLICIT_BZERO)
if(NOT HAVE_EXPLICIT_BZERO)
    list(APPEND OPTIONAL_SOURCES explicit_bzero.c)
endif(NOT HAVE_EXPLICIT_BZERO)
check_function_exists("timingsafe_bcmp" HAVE_TIMINGSAFE_BCMP)
if(NOT HAVE_TIMINGSAFE_BCMP)
    list(APPEND OPTIONAL_SOURCES timingsafe_bcmp.c)
endif(NOT HAVE_TIMINGSAFE_BCMP)

include_directories(
    ${PROJECT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${NIF_INCLUDE_DIR}
)

add_library(
    bcrypt_nif SHARED
    bcrypt_nif.c
    blowfish.c
    ${OPTIONAL_SOURCES}
)
set_target_properties(bcrypt_nif PROPERTIES
    PREFIX ""
    COMPILE_FLAGS "-fPIC"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../priv"
)

if((NOT DEFINED ENV{MIX_ENV}) OR ($ENV{MIX_ENV} STREQUAL "dev"))
    add_executable(
        test
        test.c
        bcrypt_nif.c
        blowfish.c
        ${OPTIONAL_SOURCES}
    )
    set_target_properties(test PROPERTIES
        COMPILE_DEFINITIONS "STANDALONE"
    )
endif((NOT DEFINED ENV{MIX_ENV}) OR ($ENV{MIX_ENV} STREQUAL "dev"))
