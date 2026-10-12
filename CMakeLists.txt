# Portable CMake build (Windows/MSVC, Linux, macOS, BSD).
#   cmake -S . -B build && cmake --build build --config Release
#   ctest --test-dir build -C Release
cmake_minimum_required(VERSION 3.10)
project(ram1024 C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(Threads)
option(RAM_NO_THREADS "Build without threads" OFF)

add_library(ram SHARED csrc/ram1024.c)
target_include_directories(ram PUBLIC csrc)
target_compile_definitions(ram PRIVATE RAM_BUILD_DLL)
if(RAM_NO_THREADS OR NOT Threads_FOUND)
  target_compile_definitions(ram PUBLIC RAM_NO_THREADS)
else()
  target_link_libraries(ram PRIVATE Threads::Threads)
endif()

add_library(ram_static STATIC csrc/ram1024.c)
target_include_directories(ram_static PUBLIC csrc)
if(RAM_NO_THREADS OR NOT Threads_FOUND)
  target_compile_definitions(ram_static PUBLIC RAM_NO_THREADS)
else()
  target_link_libraries(ram_static PUBLIC Threads::Threads)
endif()

add_executable(ram_test csrc/ram_test.c)
target_link_libraries(ram_test ram_static)
add_executable(ramsum csrc/ramsum.c)
target_link_libraries(ramsum ram_static)

enable_testing()
add_test(NAME conformance COMMAND ram_test ${CMAKE_CURRENT_SOURCE_DIR}/tests/kat.txt)
