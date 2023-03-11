add_executable (converter main.cpp converter.cpp converter.h function_converter.h utils.cpp utils.h function_converter.cpp)

target_link_libraries(converter PRIVATE elfio::elfio)
target_link_libraries(converter PRIVATE capstone)
target_link_libraries(converter PRIVATE keystone)