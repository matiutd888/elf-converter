add_executable (converter main.cpp converter.cpp converter.h)

target_link_libraries(converter PRIVATE elfio::elfio)