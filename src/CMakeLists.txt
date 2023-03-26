add_executable (converter main.cpp utils.cpp utils.h ConvertManager.cpp ConvertManager.h AssemblyUtils.h InstructionConverter.h ElfStructures.h FunctionConverter.cpp FunctionConverter.h AssemblyUtils.cpp InstructionConverter.cpp)

target_link_libraries(converter PRIVATE elfio)
target_link_libraries(converter PRIVATE capstone)

if (MSVC)
    # warning level 4 and all warnings as errors
    add_compile_options(/W4 /WX)
else()
    # lots of warnings and all warnings as errors
    add_compile_options(-Wall -Wextra -pedantic)
endif()
