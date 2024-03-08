# CMakeLists.txt --- CMake settings
##############################################################################

# CMake minimum version
cmake_minimum_required(VERSION 3.5)

# project name and languages
project(ShellExecute CXX)

# ShellExecute.exe
add_executable(ShellExecute ShellExecute.cpp)
target_link_libraries(ShellExecute PRIVATE ntdll)

##############################################################################
