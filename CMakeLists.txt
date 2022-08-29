cmake_minimum_required(VERSION 3.22)
project(smp_backend C)

set(CMAKE_C_STANDARD 99)

add_subdirectory(libs/librespot-c)
add_subdirectory(test)

find_package(OpenSSL REQUIRED)

add_executable(smp_backend src/main.c src/librespot-util.c src/librespot-util.h src/openssl_hostname_validation.c src/openssl_hostname_validation.h src/hostcheck.c src/hostcheck.h src/cmd.h src/vec.c src/vec.h src/debug.h)

target_include_directories(smp_backend PRIVATE libs/librespot-c)

include_directories(${OPENSSL_INCLUDE_DIR})

target_link_libraries(smp_backend pthread event event_pthreads event_openssl)
target_link_libraries(smp_backend librespot_c)
target_link_libraries(smp_backend ${OPENSSL_LIBRARIES})
target_link_libraries(smp_backend rt)
#target_link_libraries(smp_backend OpenSSL::SSL)
