cmake_minimum_required(VERSION 3.22)
project(smp_backend_test C)

set(CMAKE_C_STANDARD 99)

add_executable(smp_backend_test test.c)

target_link_libraries(smp_backend_test event)