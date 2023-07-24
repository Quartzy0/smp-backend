cmake_minimum_required(VERSION 3.22)
project(smp_backend C)

set(CMAKE_C_STANDARD 11)

add_subdirectory(libs/librespot-c)
add_subdirectory(test)

find_package(OpenSSL REQUIRED)

file(GLOB smp_backend_SRC CONFIGURE_DEPENDS "src/*.h" "src/*.c")

add_executable(smp_backend ${smp_backend_SRC})

target_include_directories(smp_backend PRIVATE libs/librespot-c)

include_directories(${OPENSSL_INCLUDE_DIR})

target_link_libraries(smp_backend event event_openssl)
target_link_libraries(smp_backend pthread)
target_link_libraries(smp_backend librespot_c)
target_link_libraries(smp_backend ${OPENSSL_LIBRARIES})
target_link_libraries(smp_backend rt)

set(JDM_BUILD_SHARED_LIBS OFF)
add_subdirectory(libs/jdm)
target_link_libraries(smp_backend jdm)
