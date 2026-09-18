cmake_minimum_required(VERSION 3.18)
project(duck_vdso_detector_tests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(DUCK_CPP_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../main/cpp")

add_executable(vdso_detector_test
    vdso_detector_test.cpp
    "${DUCK_CPP_ROOT}/memory/detectors/vdso_detector.cpp"
)

target_include_directories(vdso_detector_test PRIVATE
    "${DUCK_CPP_ROOT}"
)

# Hosts such as macOS do not ship <sys/auxv.h>. Provide a test-only stub so the
# detector translation unit can compile; Linux and Android NDK builds use the
# platform header instead.
include(CheckIncludeFileCXX)
check_include_file_cxx("sys/auxv.h" HAVE_SYS_AUXV_H)
if(NOT HAVE_SYS_AUXV_H)
    set(AUXV_STUB_DIR "${CMAKE_CURRENT_BINARY_DIR}/auxv_stub")
    file(MAKE_DIRECTORY "${AUXV_STUB_DIR}/sys")
    file(WRITE "${AUXV_STUB_DIR}/sys/auxv.h" [=[
#ifndef DUCK_TEST_SYS_AUXV_H
#define DUCK_TEST_SYS_AUXV_H
#define AT_SYSINFO_EHDR 33
#ifdef __cplusplus
extern "C" {
#endif
unsigned long getauxval(unsigned long type);
#ifdef __cplusplus
}
#endif
#endif
]=])
    target_include_directories(vdso_detector_test PRIVATE "${AUXV_STUB_DIR}")
endif()

enable_testing()
add_test(NAME vdso_detector_test COMMAND vdso_detector_test)
