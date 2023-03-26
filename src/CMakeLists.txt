add_executable (converter main.cpp utils.cpp utils.h ConvertManager.cpp ConvertManager.h AssemblyUtils.h InstructionConverter.h ElfStructures.h FunctionConverter.cpp FunctionConverter.h)

target_link_libraries(converter PRIVATE elfio)
target_link_libraries(converter PRIVATE capstone)
