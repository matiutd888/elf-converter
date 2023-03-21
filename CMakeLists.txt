project(ConverterProject)
cmake_minimum_required (VERSION 3.12)


set (CMAKE_CXX_STANDARD 20)

# Recurse into the "Hello" and "Demo" subdirectories. This does not actually
# cause another cmake executable to run. The same process will walk through
# the project's entire directory structure.
add_subdirectory (elfio-3.11)
add_subdirectory (src)
add_subdirectory (capstone)



