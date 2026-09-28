cmake_minimum_required(VERSION 3.25)

project(RuntimeDumper LANGUAGES CXX)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED IMPORTED_TARGET capstone)

set(KVMLIB_ENABLE_MEMPROCFS ON CACHE BOOL "" FORCE)
set(MEMPROCFS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../KVM-Folders/MemProcFS" CACHE PATH "" FORCE)
set(MEMPROCFS_LIBRARY_DIR "${MEMPROCFS_ROOT}/files" CACHE PATH "" FORCE)

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../KVMLib" "${CMAKE_CURRENT_BINARY_DIR}/kvmlib")

add_executable(dump
    backing_image.cpp
    main.cpp
    pe_reconstruct.cpp
    qmp_freeze.cpp
    runtime_dump.cpp
)
target_link_libraries(dump PRIVATE kvmlib::kvmlib PkgConfig::CAPSTONE)
target_compile_features(dump PRIVATE cxx_std_23)
target_compile_options(dump PRIVATE -Wall -Wextra -Wpedantic)
set_target_properties(dump PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

add_executable(pe_probe
    backing_image.cpp
    pe_probe_main.cpp
    pe_reconstruct.cpp
    qmp_freeze.cpp
    runtime_dump.cpp
)
target_link_libraries(pe_probe PRIVATE kvmlib::kvmlib PkgConfig::CAPSTONE)
target_compile_features(pe_probe PRIVATE cxx_std_23)
target_compile_options(pe_probe PRIVATE -Wall -Wextra -Wpedantic)
set_target_properties(pe_probe PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
