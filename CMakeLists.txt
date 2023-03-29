project(ConverterProject C CXX)

cmake_minimum_required (VERSION 3.12)

set (CMAKE_CXX_STANDARD 20)

add_subdirectory (elfio-3.11)

add_executable (converter
        src/main.cpp
        src/Utils.cpp src/Utils.h
        src/ConvertManager.cpp src/ConvertManager.h
        src/AssemblyUtils.h src/AssemblyUtils.cpp
        src/InstructionConverter.h src/InstructionConverter.cpp
        src/FunctionConverter.cpp src/FunctionConverter.h
        src/ElfStructures.h )

include(FindPkgConfig)

pkg_check_modules (CAPSTONE REQUIRED capstone)
#pkg_check_modules (KEYSTONE REQUIRED keystone)

target_link_libraries(converter capstone)
target_link_libraries(converter elfio)
target_link_libraries(converter keystone)
TARGET_LINK_LIBRARIES(converter "-L/usr/local/keystone" keystone)

 if (MSVC)
     # warning level 4 and all warnings as errors
     add_compile_options(/W4 /WX)
 else()
     # lots of warnings and all warnings as errors
     add_compile_options(-Wall -Wextra -pedantic)
 endif()
