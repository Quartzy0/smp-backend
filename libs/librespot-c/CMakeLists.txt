cmake_minimum_required(VERSION 3.22)
project(librespot_c C)

set(CMAKE_C_STANDARD 99)

find_package(CURL REQUIRED)

include_directories(.)
include_directories(src)
include_directories(src/proto)
include_directories(src/shannon)

add_library(librespot_c
        src/proto/authentication.pb-c.c
        src/proto/authentication.pb-c.h
        src/proto/keyexchange.pb-c.c
        src/proto/keyexchange.pb-c.h
        src/proto/mercury.pb-c.c
        src/proto/mercury.pb-c.h
        src/proto/metadata.pb-c.c
        src/proto/metadata.pb-c.h
        src/shannon/Shannon.h
        src/shannon/ShannonFast.c
        src/shannon/ShannonInternal.h
        src/channel.c
        src/channel.h
        src/connection.c
        src/connection.h
        src/crypto.c
        src/crypto.h
        src/librespot-c-internal.h
        src/librespot-c.c
        src/cmd.h
        librespot-c.h)

target_link_libraries(librespot_c m)
target_link_libraries(librespot_c protobuf-c)
target_link_libraries(librespot_c gcrypt)
target_link_libraries(librespot_c event)
target_link_libraries(librespot_c pthread)
