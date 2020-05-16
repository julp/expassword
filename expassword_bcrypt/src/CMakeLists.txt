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

include_directories(
    ${PROJECT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${NIF_INCLUDE_DIR}
)

add_library(
    bcrypt_nif SHARED
    bcrypt_nif.c
    blowfish.c
    timingsafe_bcmp.c
)
set_target_properties(bcrypt_nif PROPERTIES
    PREFIX ""
    COMPILE_FLAGS "-fPIC"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../priv"
)

if(NOT DEFINED ENV{MIX_ENV} OR ENV{MIX_ENV} EQUAL "dev")
    add_executable(
        test
        test.c
        bcrypt_nif.c
        blowfish.c
    )
    set_target_properties(test PROPERTIES
        COMPILE_DEFINITIONS "STANDALONE"
    )
endif(NOT DEFINED ENV{MIX_ENV} OR ENV{MIX_ENV} EQUAL "dev")
