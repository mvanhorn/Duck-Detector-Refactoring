cmake_minimum_required(VERSION 3.20)
project(vdso_detector_test LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()

set(memory_native_root "${CMAKE_CURRENT_SOURCE_DIR}/../../main/cpp")

add_executable(vdso_detector_test
        vdso_detector_test.cpp
        "${memory_native_root}/memory/detectors/vdso_detector.cpp"
)
target_include_directories(vdso_detector_test PRIVATE "${memory_native_root}")

add_test(NAME vdso_detector_test COMMAND vdso_detector_test)
