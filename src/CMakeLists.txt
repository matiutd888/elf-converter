add_executable (converter main.cpp function_converter.h utils.cpp utils.h function_converter.cpp ConvertManager.cpp ConvertManager.h)

target_link_libraries(converter PRIVATE elfio)
target_link_libraries(converter PRIVATE capstone)
